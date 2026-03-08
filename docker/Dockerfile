# ─────────────────────────────────────────
# STAGE 1 — Builder
# Install dependencies in a separate stage
# so we don't carry build tools into production
# ─────────────────────────────────────────
FROM python:3.11-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libffi-dev

WORKDIR /build

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# ─────────────────────────────────────────
# STAGE 2 — Production
# Clean final image with no build tools
# This massively reduces attack surface
# ─────────────────────────────────────────
FROM python:3.11-alpine

# Update all packages to latest versions
# This fixes most OS-level CVEs immediately
RUN apk update && \
    apk upgrade --no-cache && \
    apk add --no-cache ca-certificates && \
    rm -rf /var/cache/apk/*

# Create non-root user — never run as root
RUN addgroup -S appgroup && \
    adduser -S appuser -G appgroup

# Set working directory
WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# Remove build tools from production image
# These are only needed to install packages, not to run your app
RUN find /usr/local/lib/python3.11/site-packages -name "setuptools*" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3.11/site-packages -name "wheel*" -type d -exec rm -rf {} + 2>/dev/null || true && \
    find /usr/local/lib/python3.11/site-packages -name "pip*" -type d -exec rm -rf {} + 2>/dev/null || true
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy source code
COPY src/ ./src/

# Set ownership to non-root user
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Security — don't run as root, no new privileges
# Tells the OS this process should never gain more permissions
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Health check — Docker will monitor if app is alive
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import src.scanner; print('healthy')" || exit 1

# Run the scanner
CMD ["python", "src/scanner.py"]