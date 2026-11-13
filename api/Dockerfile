FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV DATA_DIR=/data \
    SCANNER_HOST=adapter \
    SCANNER_PORT=3311 \
    MAX_INFLIGHT=4 \
    SCAN_TIMEOUT_S=5

EXPOSE 8000
# single process on purpose: the IDSESSION connection is per-process
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
