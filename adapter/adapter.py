#!/usr/bin/env python3
"""Controllable INSTREAM adapter sitting between the API and clamd.

API  <-->  adapter (this, TCP :3311)  <-->  clamd (TCP :3310, real ClamAV)

Wire protocol towards the API (single IDSESSION connection):
    C: zIDSESSION\\0
    S: SESSION <uuid> OK\\n
    C: zINSTREAM <reqid>\\0 <len32><payload> ... <len32=0>
    S: <reqid> stream: OK\\n | <reqid> stream: <name> FOUND\\n | <reqid> ERROR <msg>\\n
    C: zPING\\0 -> S: PONG\\n ; C: zEND\\0 -> close

Each INSTREAM request is forwarded to clamd as its own standard INSTREAM
session. Replies are tagged with the caller's reqid and may be DELAYED,
REORDERED or the whole session DROPPED, all controllable at runtime:

    GET  /config           -> current behaviour config (JSON)
    POST /config  {...}    -> update, keys:
        delay_min_ms / delay_max_ms  random per-reply delay; a wide window
                                     reorders concurrently sent replies
        drop_after_replies           close the API session after N replies (0=off)
        drop_probability             random session drop per reply, 0..1

SCAN_BACKEND=clamd (default) forwards to a real clamd; SCAN_BACKEND=mock uses
the offline demo signature DB (HDB: md5:size:name) directly, handy for local
development without Docker.
"""
import asyncio
import hashlib
import json
import os
import random
import struct
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_HOST = os.environ.get("ADAPTER_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("ADAPTER_PORT", "3311"))
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "8080"))
CLAMD_HOST = os.environ.get("CLAMD_HOST", "127.0.0.1")
CLAMD_PORT = int(os.environ.get("CLAMD_PORT", "3310"))
SCAN_BACKEND = os.environ.get("SCAN_BACKEND", "clamd")
SIG_DB = os.environ.get("SIG_DB", os.path.join(os.path.dirname(__file__), "eicar.hdb"))

DEFAULT_CONFIG = {
    "delay_min_ms": 0,
    "delay_max_ms": 300,
    "drop_after_replies": 0,
    "drop_probability": 0.0,
}


class Config:
    def __init__(self):
        self._lock = threading.Lock()
        self._cfg = dict(DEFAULT_CONFIG)

    def get(self):
        with self._lock:
            return dict(self._cfg)

    def update(self, patch: dict):
        with self._lock:
            for key, value in patch.items():
                if key not in DEFAULT_CONFIG:
                    raise ValueError(f"unknown key: {key}")
                if key == "drop_probability":
                    value = float(value)
                    if not 0.0 <= value <= 1.0:
                        raise ValueError("drop_probability must be within [0, 1]")
                elif key in ("delay_min_ms", "delay_max_ms", "drop_after_replies"):
                    value = int(value)
                    if value < 0:
                        raise ValueError(f"{key} must be >= 0")
                self._cfg[key] = value
            if self._cfg["delay_max_ms"] < self._cfg["delay_min_ms"]:
                self._cfg["delay_max_ms"] = self._cfg["delay_min_ms"]
            return dict(self._cfg)


CONFIG = Config()


def log(msg, *args):
    print(f"[adapter] {msg % args if args else msg}", flush=True)


# ------------------------------------------------------------------ backends

class MockBackend:
    """Offline demo scanner: matches file MD5 against the HDB signature DB."""

    def __init__(self, sig_db_path):
        self.sigs = {}
        with open(sig_db_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                md5, _size, name = line.split(":", 2)
                self.sigs[md5.lower()] = name
        log("mock backend loaded %d signature(s) from %s", len(self.sigs), sig_db_path)

    async def scan(self, path):
        digest = hashlib.md5(open(path, "rb").read()).hexdigest()
        await asyncio.sleep(0)
        if digest in self.sigs:
            return f"stream: {self.sigs[digest]} FOUND"
        return "stream: OK"


class ClamdBackend:
    """Forwards each request to a real clamd as a standard INSTREAM session."""

    async def scan(self, path):
        reader, writer = await self._connect_with_retry()
        try:
            writer.write(b"zINSTREAM\0")
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(256 * 1024)
                    if not chunk:
                        break
                    writer.write(struct.pack(">I", len(chunk)))
                    writer.write(chunk)
            writer.write(b"\x00\x00\x00\x00")
            await writer.drain()
            raw = await asyncio.wait_for(reader.readuntil(b"\0"), timeout=30)
            return self._parse(raw[:-1].decode("utf-8", "replace").strip())
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _connect_with_retry(attempts=30, delay=1.0):
        last = None
        for _ in range(attempts):
            try:
                return await asyncio.open_connection(CLAMD_HOST, CLAMD_PORT, limit=1 << 20)
            except OSError as exc:
                last = exc
                await asyncio.sleep(delay)
        raise ConnectionError(f"clamd unreachable at {CLAMD_HOST}:{CLAMD_PORT}: {last!r}")

    @staticmethod
    def _parse(reply: str) -> str:
        # clamd answers e.g. "stream: OK", "stream: Eicar-Test-Signature FOUND",
        # or "INSTREAM size limit exceeded. ERROR"
        if reply == "stream: OK":
            return "stream: OK"
        if reply.startswith("stream: ") and reply.endswith(" FOUND"):
            return reply
        if reply.endswith(" ERROR") or "ERROR" in reply:
            return f"ERROR {reply}"
        return f"ERROR unexpected clamd reply: {reply}"


BACKEND = MockBackend(SIG_DB) if SCAN_BACKEND == "mock" else ClamdBackend()


# ------------------------------------------------------------- TCP sessions

class Session:
    def __init__(self, writer):
        self.writer = writer
        self.replies = 0
        self.tasks = set()
        self.closed = False


async def handle_scan(reqid: str, path: str, session: Session):
    try:
        try:
            verdict = await BACKEND.scan(path)
        except Exception as exc:
            verdict = f"ERROR scan backend failure: {exc!r}"

        cfg = CONFIG.get()
        lo, hi = cfg["delay_min_ms"], cfg["delay_max_ms"]
        delay = random.uniform(lo, max(lo, hi)) / 1000.0
        if delay:
            await asyncio.sleep(delay)  # jitter reorders concurrent replies

        cfg = CONFIG.get()
        drop = False
        if cfg["drop_after_replies"] and session.replies >= cfg["drop_after_replies"]:
            drop = True
        elif cfg["drop_probability"] and random.random() < cfg["drop_probability"]:
            drop = True
        if drop:
            log("session drop injected before replying reqid=%s", reqid)
            session.writer.close()  # simulate a broken upstream link
            return

        if session.closed:
            return
        session.writer.write(f"{reqid} {verdict}\n".encode())
        await session.writer.drain()
        session.replies += 1
        log("replied reqid=%s -> %s", reqid, verdict)
    except (ConnectionError, asyncio.CancelledError, OSError):
        pass
    finally:
        session.tasks.discard(asyncio.current_task())
        try:
            os.unlink(path)
        except OSError:
            pass


async def handle_session(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    session = Session(writer)
    log("session open from %s", peer)
    try:
        while True:
            header = await reader.readuntil(b"\0")
            command = header[:-1].decode("utf-8", "replace").strip()
            if command == "zIDSESSION":
                writer.write(f"SESSION {uuid.uuid4().hex} OK\n".encode())
                await writer.drain()
            elif command == "zPING":
                writer.write(b"PONG\n")
                await writer.drain()
            elif command.startswith("zINSTREAM"):
                parts = command.split()
                if len(parts) != 2:
                    writer.write(b"ERROR malformed INSTREAM command\n")
                    await writer.drain()
                    continue
                reqid = parts[1]
                path = await spool_frames(reader)
                task = asyncio.create_task(handle_scan(reqid, path, session))
                session.tasks.add(task)
            elif command == "zEND":
                break
            else:
                writer.write(b"ERROR unknown command\n")
                await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
            ConnectionResetError, BrokenPipeError):
        pass
    finally:
        session.closed = True
        for task in list(session.tasks):
            task.cancel()
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        log("session closed for %s", peer)


async def spool_frames(reader: asyncio.StreamReader) -> str:
    """Read length-prefixed INSTREAM frames into a temp file until a zero frame."""
    fd, path = tempfile.mkstemp(prefix="instream-")
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                (size,) = struct.unpack(">I", await reader.readexactly(4))
                if size == 0:
                    return path
                out.write(await reader.readexactly(size))
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


# ------------------------------------------------------------ control plane

class ControlHandler(BaseHTTPRequestHandler):
    def _send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/config":
            self._send_json(200, CONFIG.get())
        elif self.path == "/healthz":
            self._send_json(200, {"ok": True, "backend": SCAN_BACKEND})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/config":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            patch = json.loads(self.rfile.read(length) or b"{}")
            self._send_json(200, CONFIG.update(patch))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": str(exc)})

    def log_message(self, *args):
        pass


def run_control_server():
    server = ThreadingHTTPServer(("0.0.0.0", CONTROL_PORT), ControlHandler)
    log("control endpoint on :%d (GET/POST /config)", CONTROL_PORT)
    server.serve_forever()


async def main():
    server = await asyncio.start_server(
        handle_session, LISTEN_HOST, LISTEN_PORT, limit=4 << 20
    )
    log("INSTREAM adapter on %s:%d (backend=%s -> %s:%d)",
        LISTEN_HOST, LISTEN_PORT, SCAN_BACKEND, CLAMD_HOST, CLAMD_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=run_control_server, daemon=True).start()
    asyncio.run(main())
