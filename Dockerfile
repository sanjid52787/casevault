# ==============================================================================
# CaseVault Multi-Stage Hardened Dockerfile
# Organization: Northbridge Cyber Response
# Module: CYS22301 Software and Platform Security (Level 6)
# ==============================================================================

# Stage 1: Build Dependencies & Wheels
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies required for compiling cryptographic C extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /build/

# Install dependencies using cryptographic hash verification
RUN pip install --no-cache-dir --upgrade pip>=26.2.2 && \
    pip install --no-cache-dir --require-hashes -r requirements.lock

# Stage 2: Hardened Runtime Container
FROM python:3.12-slim AS runner

# Security metadata labels (OCI specification)
LABEL org.opencontainers.image.title="CaseVault Incident Response Platform" \
      org.opencontainers.image.description="Secure forensic case management and evidence vault" \
      org.opencontainers.image.vendor="Northbridge Cyber Response" \
      org.opencontainers.image.licenses="BSD-3-Clause"

# Install curl for container healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Hard Rule: Create dedicated unprivileged non-root user and group
RUN groupadd -g 10001 casevault && \
    useradd -u 10001 -g casevault -s /bin/false -M casevault

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . /app/

# Create isolated evidence storage and static directories with strict ownership
RUN mkdir -p /app/vault_storage /app/staticfiles && \
    chown -R casevault:casevault /app

# Drop root privileges permanently
USER casevault:casevault

# Environment defaults (production)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CASEVAULT_ENV=production \
    DEBUG=False

# Expose non-privileged HTTP port
EXPOSE 8000

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/auth/login/ || exit 1

# Production Entrypoint
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
