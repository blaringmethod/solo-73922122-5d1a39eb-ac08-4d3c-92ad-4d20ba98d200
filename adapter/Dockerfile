FROM python:3.12-slim

WORKDIR /app
COPY adapter.py .
COPY eicar.hdb /sigs/eicar.hdb

ENV ADAPTER_HOST=0.0.0.0 \
    ADAPTER_PORT=3311 \
    CONTROL_PORT=8080 \
    CLAMD_HOST=clamd \
    CLAMD_PORT=3310 \
    SCAN_BACKEND=clamd \
    SIG_DB=/sigs/eicar.hdb

EXPOSE 3311 8080
CMD ["python", "-u", "adapter.py"]
