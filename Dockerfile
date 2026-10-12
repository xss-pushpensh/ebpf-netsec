FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        bpftrace libbpf1 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY ebpf/ ./ebpf/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

RUN mkdir -p /app/data
EXPOSE 8080
CMD ["ebpf-netsec", "dashboard", "--host", "0.0.0.0", "--port", "8080"]
