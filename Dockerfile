# Application image: API + pipeline workers. (The analyzer sandbox has its own
# hardened image in analyzer_container/Dockerfile.)
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps: docker CLI (analyzer worker launches sandbox containers).
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates docker.io \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

COPY db ./db

COPY start.sh ./
RUN chmod +x start.sh

# Run as non-root for the API/most workers.
RUN useradd --create-home --uid 10001 pkintel && chown -R pkintel:pkintel /app
USER pkintel

EXPOSE 7860
CMD ["./start.sh"]
