# ============================================================================
# soc-triage — production SOC log anomaly detector + local LLM MITRE triage agent
# ============================================================================
FROM python:3.11-slim AS base

WORKDIR /app

# 1. Install dependencies first (cached layer)
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# 2. Copy the application code
COPY . .

# 3. Non-root user for hardening
RUN useradd --create-home --uid 1000 --shell /bin/bash soc \
    && chown -R soc:soc /app && chmod -R a+rX /app
USER soc

# Persistent state mounts (see docker-compose.yml)
VOLUME ["/app/data", "/app/models", "/app/reports", "/app/logs"]

# Entrypoint: the CLI. Default prints usage.
ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
