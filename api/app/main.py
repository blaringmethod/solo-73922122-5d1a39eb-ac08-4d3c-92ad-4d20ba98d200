"""Secure gateway API: upload -> spool to disk -> INSTREAM scan -> publish.

Single-process design: the whole process shares ONE IDSESSION TCP connection
to the scanner (see scanner.py). Run uvicorn with exactly one worker.
"""
import logging
import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, RedirectResponse

from . import config
from .db import DB
from .scanner import ScanManager, ScanUnavailable

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("api")

db: DB = None
manager: ScanManager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global db, manager
    os.makedirs(config.UPLOADS_DIR, exist_ok=True)
    db = DB(config.DB_PATH)
    swept = db.fail_interrupted()  # restart: unfinished -> failed, clean survives
    if swept:
        log.warning("restart sweep: %d unfinished file(s) marked failed", swept)
    manager = ScanManager(
        config.SCANNER_HOST,
        config.SCANNER_PORT,
        max_inflight=config.MAX_INFLIGHT,
        scan_timeout=config.SCAN_TIMEOUT,
        on_status=_on_status,
    )
    manager.start()
    yield
    await manager.stop()
    db.close()


def _on_status(file_id: str, status: str, signature=None, error=None) -> None:
    db.set_status(file_id, status, signature=signature, error=error)


app = FastAPI(
    title="Secure Gateway AV Scan API",
    version="1.0.0",
    lifespan=lifespan,
    description=(
        "Uploads are spooled to disk in chunks (max 8 MiB), scanned over a single "
        "shared IDSESSION/INSTREAM connection (max 4 in flight, 5 s total budget), "
        "and only files with a clean verdict are downloadable."
    ),
)


def _public(rec: dict) -> dict:
    return {
        "id": rec["id"],
        "filename": rec["filename"],
        "size": rec["size"],
        "status": rec["status"],
        "signature": rec["signature"],
        "error": rec["error"],
        "created_at": rec["created_at"],
        "updated_at": rec["updated_at"],
        "downloadable": rec["status"] == "clean",
    }


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/docs")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}


@app.post("/files", status_code=202, summary="Upload a file for scanning")
async def upload(file: UploadFile = File(...)):
    """Spool the upload to disk in chunks (max 8 MiB), then stream it to the
    scanner. Returns 503 when 4 scans are already in flight."""
    file_id = uuid.uuid4().hex
    path = os.path.join(config.UPLOADS_DIR, file_id)
    task = manager.admit(file_id, path)
    if task is None:
        raise HTTPException(
            status_code=503,
            detail=f"scanner busy: {config.MAX_INFLIGHT} scans already in flight, retry later",
        )
    db.insert(file_id, file.filename or "unnamed")

    size = 0
    try:
        with open(path, "wb") as out:
            while True:
                chunk = await file.read(config.UPLOAD_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > config.MAX_FILE_SIZE:
                    raise _TooLarge()
                out.write(chunk)
                if task.done:  # cancelled or failed (e.g. deadline) mid-upload
                    raise _Aborted()
    except _TooLarge:
        manager.finish(task, "failed", error="file exceeds 8 MiB limit")
        _silent_unlink(path)
        raise HTTPException(status_code=413, detail="file exceeds 8 MiB limit")
    except _Aborted:
        _silent_unlink(path)
        rec = db.get(file_id)
        if rec and rec["status"] == "cancelled":
            return _public(rec)
        raise HTTPException(status_code=503, detail="scan aborted before dispatch")
    except Exception:
        manager.finish(task, "failed", error="upload receive failed")
        _silent_unlink(path)
        raise

    db.set_size(file_id, size)
    if task.done:  # cancelled/failed between spool and dispatch
        rec = db.get(file_id)
        if rec["status"] == "cancelled":
            return _public(rec)
        raise HTTPException(status_code=503, detail=rec["error"] or "scan aborted")

    db.set_status(file_id, "scanning")
    try:
        await manager.send(task)
    except ScanUnavailable as exc:
        rec = db.get(file_id)
        if rec and rec["status"] == "cancelled":
            return _public(rec)
        raise HTTPException(status_code=503, detail=str(exc))
    return _public(db.get(file_id))


@app.get("/files", summary="List all files")
def list_files():
    return [_public(r) for r in db.list()]


@app.get("/files/{file_id}", summary="Get scan status")
def get_file(file_id: str):
    rec = db.get(file_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="unknown file id")
    return _public(rec)


@app.post("/files/{file_id}/cancel", summary="Cancel an in-progress scan")
def cancel_file(file_id: str):
    """Cancelling a scan that is already on the wire still finishes sending its
    frames; the reply is discarded and the slot is held until it arrives."""
    rec = db.get(file_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="unknown file id")
    if rec["status"] in ("clean", "infected", "failed", "cancelled"):
        raise HTTPException(status_code=409, detail=f"file already terminal: {rec['status']}")
    if not manager.cancel(file_id):
        raise HTTPException(status_code=409, detail=f"file already terminal: {rec['status']}")
    return _public(db.get(file_id))


@app.get("/files/{file_id}/download", summary="Download a clean file")
def download_file(file_id: str):
    """Only files that were fully scanned and received a clean verdict can be
    downloaded. Hits and errors are never downloadable."""
    rec = db.get(file_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="unknown file id")
    if rec["status"] == "clean":
        return FileResponse(
            os.path.join(config.UPLOADS_DIR, file_id),
            filename=rec["filename"],
            media_type="application/octet-stream",
        )
    if rec["status"] in ("uploading", "scanning"):
        raise HTTPException(status_code=409, detail=f"scan not finished: {rec['status']}")
    raise HTTPException(status_code=403, detail=f"file not downloadable: {rec['status']}")


class _TooLarge(Exception):
    pass


class _Aborted(Exception):
    pass


def _silent_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
