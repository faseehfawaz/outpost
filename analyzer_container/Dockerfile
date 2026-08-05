# Hardened analyzer sandbox.
#
# This image parses attacker-authored archives. It is launched per-kit by
# pkintel.analyzer.runner with --network none, --read-only, --cap-drop ALL,
# --pids-limit and memory/CPU/wall-clock bounds.
#
# Deliberately minimal: it contains ONLY the pure-Python analysis modules and
# their parsing dependencies. No psycopg, no boto3, no credentials, no DB
# driver — if this container is ever compromised there is nothing in it to
# steal and nowhere to send it.
#
#   make analyzer-image
#
# Protocol: argv[1] is a path to an archive; stdout is one AnalysisResult JSON
# document; exit code 0 on success.

FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1

# python-tlsh needs a C++ toolchain; it does not survive into the final image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Only what the static analysis path actually imports. Notably absent:
# psycopg, boto3, fastapi, playwright.
RUN pip wheel --wheel-dir /wheels \
    "pydantic>=2.7" \
    "pydantic-settings>=2.3" \
    "structlog>=24.1" \
    "python-tlsh>=4.5" \
    "mmh3>=4.1" \
    "regex>=2024.5"

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd -r analyzer && useradd -r -g analyzer -s /usr/sbin/nologin analyzer

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels \
        pydantic pydantic-settings structlog python-tlsh mmh3 regex \
    && rm -rf /wheels

# Source only — no .env, no db/, no frontend/.
COPY src/pkintel /app/src/pkintel
ENV PYTHONPATH=/app/src

# Mount point for the kit under analysis. Created at build time because the
# container runs with --read-only and cannot mkdir it at runtime.
RUN mkdir -p /in && chown analyzer:analyzer /in

USER analyzer

ENTRYPOINT ["python", "-m", "pkintel.analyzer.container_main"]
