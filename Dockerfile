# SentinelAI network IDS: web platform + packet capture
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY config/ ./config/
COPY models/ ./models/
COPY data/processed/ ./data/processed/

RUN mkdir -p /app/logs
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fs http://127.0.0.1:5000/api/health || exit 1

# Packet capture needs root (or the NET_RAW/NET_ADMIN capabilities, see docker-compose.yml)
CMD ["python", "src/cli.py", "web", "--host", "0.0.0.0", "--port", "5000"]
