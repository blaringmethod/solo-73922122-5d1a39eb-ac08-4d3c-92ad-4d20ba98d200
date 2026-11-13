"""Scan manager: owns the single shared IDSESSION TCP connection to the scanner.

Protocol spoken with the adapter (one TCP connection, one IDSESSION):

    C: zIDSESSION\\0
    S: SESSION <uuid> OK\\n
    C: zINSTREAM <reqid>\\0 <len32><payload>... <len32=0>   (frames of ONE file,
       never interleaved with another file's frames - serialized by send_lock)
    S: <reqid> stream: OK\\n            (replies may arrive OUT OF ORDER and are
    S: <reqid> stream: <name> FOUND\\n   matched to scans by <reqid>)
    S: <reqid> ERROR <msg>\\n

Guarantees implemented here:
  * at most MAX_INFLIGHT scans in flight; admission fails -> API returns 503
  * every accepted file has a total SCAN_TIMEOUT budget from admission
  * cancel of an on-wire scan: frames are still fully sent, the reply is
    discarded when it arrives, and the slot is held until then
  * any timeout or connection drop fails ALL unfinished scans of the current
    connection; the connection is then recycled and reconnected automatically
    (old generation tasks can never leak into the new connection)
"""
import asyncio
import itertools
import logging
import struct
import time

from . import config

log = logging.getLogger("scanner")

CHUNK = config.SCAN_CHUNK


class ScanUnavailable(Exception):
    """Raised to the upload handler when the scan could not be dispatched."""


class ScanTask:
    __slots__ = (
        "file_id", "path", "deadline", "reqid", "gen", "state",
        "cancelled", "slot_released", "done",
    )

    def __init__(self, file_id: str, path: str, deadline: float):
        self.file_id = file_id
        self.path = path
        self.deadline = deadline
        self.reqid = None          # assigned when the INSTREAM command is sent
        self.gen = None            # connection generation the scan was sent on
        self.state = "uploading"   # uploading -> sending -> awaiting -> done
        self.cancelled = False
        self.slot_released = False
        self.done = False


class _Conn:
    __slots__ = ("reader", "writer", "gen", "send_lock")

    def __init__(self, reader, writer, gen):
        self.reader = reader
        self.writer = writer
        self.gen = gen
        self.send_lock = asyncio.Lock()  # serializes whole-file INSTREAM bursts


class ScanManager:
    def __init__(self, host, port, *, max_inflight, scan_timeout, on_status):
        self.host = host
        self.port = port
        self.max_inflight = max_inflight
        self.scan_timeout = scan_timeout
        self.on_status = on_status  # callback(file_id, status, signature, error)

        self._inflight = 0
        self._reqids = itertools.count(1)  # process-unique: no cross-generation reuse
        self._tasks = {}                   # reqid -> ScanTask (on the wire now)
        self._all = {}                     # file_id -> ScanTask (non-terminal)
        self._conn = None
        self._gen = 0
        self._ready = asyncio.Event()
        self._reset = asyncio.Event()
        self._stopped = False
        self._supervisor_task = None
        self._watchdog_task = None

    # ------------------------------------------------------------------ slots

    def admit(self, file_id: str, path: str):
        """Reserve one of the MAX_INFLIGHT slots; None means 'full' (-> 503)."""
        if self._inflight >= self.max_inflight:
            return None
        self._inflight += 1
        task = ScanTask(file_id, path, time.monotonic() + self.scan_timeout)
        self._all[file_id] = task
        log.info("admit %s (inflight=%d/%d)", file_id, self._inflight, self.max_inflight)
        return task

    def _release_slot(self, task: ScanTask) -> None:
        if not task.slot_released:
            task.slot_released = True
            self._inflight -= 1
            log.info("release %s (inflight=%d/%d)", task.file_id, self._inflight, self.max_inflight)

    # -------------------------------------------------------------- lifecycle

    def start(self) -> None:
        self._supervisor_task = asyncio.create_task(self._supervisor(), name="scan-supervisor")
        self._watchdog_task = asyncio.create_task(self._watchdog(), name="scan-watchdog")

    async def stop(self) -> None:
        self._stopped = True
        for t in (self._supervisor_task, self._watchdog_task):
            if t:
                t.cancel()
        conn, self._conn = self._conn, None
        if conn:
            try:
                conn.writer.close()
            except Exception:
                pass
        for t in (self._supervisor_task, self._watchdog_task):
            if t:
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass

    # ------------------------------------------------------- terminal handling

    def finish(self, task: ScanTask, status: str, signature=None, error=None) -> None:
        """Idempotent terminal transition; a cancelled scan stays cancelled."""
        if task.done:
            return
        task.done = True
        if task.cancelled:
            status, signature, error = "cancelled", None, None
        self._release_slot(task)
        if task.reqid is not None:
            self._tasks.pop(task.reqid, None)
        self._all.pop(task.file_id, None)
        log.info("finish %s -> %s (%s)", task.file_id, status, error or signature or "")
        self.on_status(task.file_id, status, signature, error)

    def cancel(self, file_id: str) -> bool:
        """Request cancellation. On-wire scans keep their slot until the reply
        arrives (frames are finished, the reply is discarded)."""
        task = self._all.get(file_id)
        if task is None or task.done:
            return False
        task.cancelled = True
        if task.state == "uploading":
            # never reached the scanner: release the slot immediately
            self.finish(task, "cancelled")
        else:
            # sending/awaiting: reflect the cancel now, keep the slot until the
            # reply (or a connection failure) retires the scan
            self.on_status(file_id, "cancelled", None, None)
        return True

    # ------------------------------------------------------------ sending side

    async def send(self, task: ScanTask) -> None:
        """Stream the file to the scanner as one atomic INSTREAM burst.

        Frames of a file are sent to completion even if the scan is cancelled
        mid-flight (the reply will be discarded by the reader)."""
        if task.done:
            raise ScanUnavailable("scan already finished")
        remaining = task.deadline - time.monotonic()
        if remaining <= 0:
            self.finish(task, "failed", error="scan deadline exceeded")
            raise ScanUnavailable("scan deadline exceeded")
        try:
            await asyncio.wait_for(self._ready.wait(), remaining)
        except asyncio.TimeoutError:
            self.finish(task, "failed", error="scanner not ready")
            raise ScanUnavailable("scanner not ready")

        conn = self._conn
        if conn is None:
            raise ScanUnavailable("scanner not connected")
        try:
            async with conn.send_lock:  # one file's frames on the wire at a time
                if conn is not self._conn or task.done:
                    raise ScanUnavailable("scan connection recycled")
                task.gen = conn.gen
                task.reqid = next(self._reqids)
                self._tasks[task.reqid] = task
                task.state = "sending"
                w = conn.writer
                w.write(b"zINSTREAM " + str(task.reqid).encode() + b"\0")
                with open(task.path, "rb") as fh:
                    while True:
                        chunk = fh.read(CHUNK)
                        if not chunk:
                            break
                        w.write(struct.pack(">I", len(chunk)))
                        w.write(chunk)
                        await w.drain()
                w.write(b"\x00\x00\x00\x00")  # zero-length frame terminates INSTREAM
                await w.drain()
            if not task.done:
                task.state = "awaiting"
                log.info("sent %s as reqid=%s gen=%d", task.file_id, task.reqid, conn.gen)
        except ScanUnavailable:
            raise
        except Exception as exc:
            log.warning("send failed for %s: %r", task.file_id, exc)
            if not task.done:
                self.finish(task, "failed", error="scan connection lost")
            self._reset.set()  # a broken pipe poisons the shared connection
            raise ScanUnavailable("scan connection lost") from exc

    # ----------------------------------------------------------- reading side

    def _handle_reply(self, conn: _Conn, line: bytes) -> None:
        if conn is not self._conn:
            return  # stale generation: ignore
        try:
            text = line.decode("utf-8", "replace").strip()
            reqid_s, verdict = text.split(" ", 1)
            reqid = int(reqid_s)
        except (ValueError, UnicodeDecodeError):
            log.warning("unparseable scanner reply: %r", line)
            return
        task = self._tasks.get(reqid)
        if task is None or task.done:
            log.info("reply for unknown/finished reqid=%s discarded", reqid)
            return
        if task.cancelled:
            log.info("reply for cancelled reqid=%s discarded", reqid)
            self.finish(task, "cancelled")
            return
        if verdict == "stream: OK":
            self.finish(task, "clean")
        elif verdict.startswith("stream: ") and verdict.endswith(" FOUND"):
            self.finish(task, "infected", signature=verdict[len("stream: "):-len(" FOUND")])
        else:
            self.finish(task, "failed", error=verdict)

    async def _reader_loop(self, conn: _Conn) -> None:
        while True:
            line = await conn.reader.readline()
            if not line:
                raise ConnectionError("scanner closed the connection")
            self._handle_reply(conn, line)

    # ------------------------------------------------- supervision & recovery

    async def _connect(self):
        reader, writer = await asyncio.open_connection(
            self.host, self.port, limit=1 << 20
        )
        writer.write(b"zIDSESSION\0")
        await writer.drain()
        greeting = await asyncio.wait_for(reader.readline(), timeout=5)
        if not greeting or not greeting.startswith(b"SESSION "):
            writer.close()
            raise ConnectionError(f"bad session greeting: {greeting!r}")
        return reader, writer

    async def _supervisor(self) -> None:
        backoff = 0.2
        while not self._stopped:
            try:
                reader, writer = await self._connect()
            except Exception as exc:
                log.warning("scanner connect failed: %r (retry in %.1fs)", exc, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 2.0)
                continue
            backoff = 0.2
            self._gen += 1
            conn = _Conn(reader, writer, self._gen)
            self._conn = conn
            self._reset.clear()
            self._ready.set()
            log.info("scanner connection up (gen=%d)", conn.gen)

            reader_task = asyncio.create_task(self._reader_loop(conn))
            reset_task = asyncio.create_task(self._reset.wait())
            done, pending = await asyncio.wait(
                {reader_task, reset_task}, return_when=asyncio.FIRST_COMPLETED
            )
            for p in pending:
                p.cancel()
            if pending:
                await asyncio.wait(pending)  # let cancellations settle
            reason = "connection reset requested"
            if reader_task in done and reader_task.exception():
                reason = f"connection lost: {reader_task.exception()!r}"
            log.warning("tearing down scanner connection gen=%d: %s", conn.gen, reason)

            # Cleanup: every unfinished scan of THIS connection fails; only then
            # do we reconnect, so old-generation work never touches the new link.
            self._ready.clear()
            if self._conn is conn:
                self._conn = None
            for task in list(self._tasks.values()):
                if not task.done:
                    self.finish(task, "failed", error="scan connection lost")
            self._tasks.clear()
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _watchdog(self) -> None:
        """Enforce the per-file total deadline; an on-wire timeout poisons the
        whole connection (all its unfinished scans fail, then we reconnect)."""
        while not self._stopped:
            await asyncio.sleep(0.05)
            now = time.monotonic()
            expired = [t for t in self._all.values() if not t.done and t.deadline <= now]
            if not expired:
                continue
            on_wire = any(t.state in ("sending", "awaiting") for t in expired)
            for t in expired:
                log.warning("deadline exceeded for %s (state=%s)", t.file_id, t.state)
                self.finish(t, "failed", error="scan deadline exceeded (5s total)")
            if on_wire:
                self._reset.set()
