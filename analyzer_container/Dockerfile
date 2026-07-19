FROM python:3.12-slim

# Create non-root user
RUN groupadd -r analyzer && useradd -r -g analyzer analyzer

WORKDIR /app

# Install dependencies (none system-level needed for now, just python)

# Copy source
COPY src/ /app/src/
ENV PYTHONPATH=/app/src

USER analyzer

# Security: Set as read-only in production runs
ENTRYPOINT ["python", "-m", "pkintel.analyzer.container_main"]
