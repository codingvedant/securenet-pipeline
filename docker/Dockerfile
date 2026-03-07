# Start from a minimal Python image
# alpine = tiny Linux distro, keeps image small and secure
FROM python:3.11-alpine

# Create a non-root user — NEVER run apps as root
# This is a security best practice
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set the working directory inside the container
WORKDIR /app

# Copy and install dependencies first
# (Docker caches this layer — faster rebuilds)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your source code into the container
COPY src/ ./src/

# Switch to non-root user before running
USER appuser

# Default command when container starts
CMD ["python", "src/scanner.py"]