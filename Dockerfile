# Multi-stage build for Vaulytica
FROM python:3.11-slim as builder

# Install Poetry
RUN pip install poetry==1.7.1

# Set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Configure Poetry to not create virtual env (we're in a container)
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --no-dev --no-interaction --no-ansi

# Final stage
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY vaulytica ./vaulytica
COPY README.md LICENSE ./

# Create directories for config and reports
RUN mkdir -p /app/config /app/reports /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV VAULYTICA_CONFIG=/app/config/config.yaml

# Create non-root user
RUN useradd -m -u 1000 vaulytica && \
    chown -R vaulytica:vaulytica /app

USER vaulytica

# Default command
ENTRYPOINT ["vaulytica"]
CMD ["--help"]

