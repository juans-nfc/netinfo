FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# nmap is the discovery engine; ca-certificates for TLS to MeshCentral.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Refresh the offline MAC/OUI vendor database at build time so lookups work
# without internet at runtime. Non-fatal if the build host has no network.
RUN python -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()" || true

COPY app ./app

# Data (SQLite DB + credential key) lives on a mounted volume.
VOLUME ["/app/data"]

EXPOSE 8850

# nmap OS detection / SYN scans need raw sockets -> run as root with NET_RAW.
CMD ["sh", "-c", "uvicorn app.main:app --host ${NETVIEW_HOST:-0.0.0.0} --port ${NETVIEW_PORT:-8850} --proxy-headers --forwarded-allow-ips '*'"]
