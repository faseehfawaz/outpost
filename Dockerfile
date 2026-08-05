# Application image: API + pipeline workers. (The analyzer sandbox has its own
# hardened image in analyzer_container/Dockerfile.)

# Stage 1: builder
FROM python:3.12-slim AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps: C++ compiler to build python-tlsh
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels .

# Stage 2: final
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

COPY db ./db
COPY frontend ./frontend

COPY start.sh ./
RUN chmod +x start.sh

# Run as non-root for the API/most workers.
RUN useradd --create-home --uid 10001 pkintel && chown -R pkintel:pkintel /app
USER pkintel

EXPOSE 7860
CMD ["./start.sh"]
