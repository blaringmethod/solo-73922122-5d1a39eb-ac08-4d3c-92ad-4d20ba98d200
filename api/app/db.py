"""Tiny SQLite persistence layer.

Statuses: uploading -> scanning -> clean | infected | failed | cancelled
Only `clean` rows are downloadable ("published"). On service restart every
non-terminal row is swept to `failed` (see fail_interrupted).
"""
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id         TEXT PRIMARY KEY,
    filename   TEXT NOT NULL,
    size       INTEGER NOT NULL DEFAULT 0,
    status     TEXT NOT NULL,
    signature  TEXT,
    error      TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
"""

ACTIVE_STATUSES = ("uploading", "scanning")
TERMINAL_STATUSES = ("clean", "infected", "failed", "cancelled")


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class DB:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["created_at"] = _iso(d["created_at"])
        d["updated_at"] = _iso(d["updated_at"])
        return d

    def insert(self, file_id: str, filename: str, status: str = "uploading") -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO files (id, filename, size, status, created_at, updated_at)"
                " VALUES (?, ?, 0, ?, ?, ?)",
                (file_id, filename, status, now, now),
            )
            self._conn.commit()

    def set_status(self, file_id: str, status: str, signature=None, error=None) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE files SET status=?, signature=COALESCE(?, signature),"
                " error=COALESCE(?, error), updated_at=? WHERE id=?",
                (status, signature, error, time.time(), file_id),
            )
            self._conn.commit()

    def set_size(self, file_id: str, size: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE files SET size=?, updated_at=? WHERE id=?",
                (size, time.time(), file_id),
            )
            self._conn.commit()

    def get(self, file_id: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM files WHERE id=?", (file_id,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def list(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM files ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def fail_interrupted(self) -> int:
        """Sweep non-terminal rows to failed; published (clean) files survive."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE files SET status='failed', error='interrupted by service restart',"
                " updated_at=? WHERE status IN ('uploading','scanning')",
                (time.time(),),
            )
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        with self._lock:
            self._conn.close()
