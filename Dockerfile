# Multi-stage Dockerfile for Vaulytica
# Optimized for production deployment

# Stage 1: Builder
FROM python:3.11-slim as builder

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /root/.local /root/.local

# Copy application code
COPY vaulytica/ ./vaulytica/
COPY setup.py .
COPY README.md .

# Install application
RUN pip install --no-cache-dir -e .

# Create non-root user
RUN useradd -m -u 1000 vaulytica && \
    chown -R vaulytica:vaulytica /app

# Create directories for data
RUN mkdir -p /app/outputs/cache /app/chroma_db && \
    chown -R vaulytica:vaulytica /app/outputs /app/chroma_db

# Switch to non-root user
USER vaulytica

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH=/root/.local/bin:$PATH

# Default command
CMD ["python", "-m", "vaulytica.cli", "serve", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

