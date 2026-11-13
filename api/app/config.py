"""Central configuration for the gateway API process (single process only)."""
import os

# Where uploaded blobs and the SQLite database live (mounted volume in compose).
DATA_DIR = os.environ.get("DATA_DIR", "./data")

# Scanner adapter endpoint (the single shared IDSESSION TCP connection target).
SCANNER_HOST = os.environ.get("SCANNER_HOST", "127.0.0.1")
SCANNER_PORT = int(os.environ.get("SCANNER_PORT", "3311"))

# Hard limits required by the gateway policy.
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", str(8 * 1024 * 1024)))  # 8 MiB
MAX_INFLIGHT = int(os.environ.get("MAX_INFLIGHT", "4"))                     # in-flight scans
SCAN_TIMEOUT = float(os.environ.get("SCAN_TIMEOUT_S", "5"))                 # total per-file budget

UPLOAD_CHUNK = 512 * 1024   # disk spooling chunk while receiving the upload
SCAN_CHUNK = 256 * 1024     # INSTREAM frame payload size when streaming to the scanner

UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
DB_PATH = os.path.join(DATA_DIR, "gateway.db")
