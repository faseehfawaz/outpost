"""
FastAPI application for pkintel.
"""

import hmac
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

from pkintel.api.routes import actors, feeds, ioc
from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)

# Per-IP request counters for the rate limiter, keyed by (ip, minute-window).
_rl_counts: dict[tuple[str, int], int] = {}
_rl_lock = threading.Lock()


def _init_sentry():
    """Initialize Sentry if DSN is configured."""
    if not settings.sentry_dsn:
        return
    import sentry_sdk

    sentry_sdk.init(
        dsn=settings.sentry_dsn,
        traces_sample_rate=settings.sentry_traces_sample_rate,
        environment=settings.dd_env,
        release="outpost@0.1.0",
        send_default_pii=False,
    )
    log.info("sentry_initialized", env=settings.dd_env)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events for FastAPI."""
    _init_sentry()
    # Registers the scrape-time queue-depth collector. Without this /metrics
    # exposes only the default Python process collectors — which was the case
    # for the entire life of this endpoint.
    from pkintel.metrics import register_collectors

    register_collectors()
    log.info("Starting up pkintel API")
    yield
    log.info("Shutting down pkintel API")


app = FastAPI(title="pkintel - Phishing-Kit Intelligence API", lifespan=lifespan)

# CORS.
#
# Was: allow_origins=["*"] together with allow_credentials=True. That pairing is
# invalid per the Fetch spec — a browser refuses to honour a wildcard origin on
# a credentialed request, so this configuration was simultaneously insecure in
# intent and non-functional in practice. Origins are now explicit and
# credentials are off, since this API is read-only and unauthenticated by
# design. Add your own origins via PKINTEL_API_CORS_ORIGINS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


# Simple in-process token bucket. The API is internet-facing and had no rate
# limit at all, so a single client could trivially saturate the DB pool that the
# pipeline workers also depend on. Per-IP, resets each minute.
@app.middleware("http")
async def _rate_limit(request: Request, call_next):
    if settings.api_rate_limit_per_min <= 0:
        return await call_next(request)

    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    window = int(now // 60)
    key = (client, window)

    with _rl_lock:
        # Drop windows we've rolled past so the dict can't grow without bound.
        for k in [k for k in _rl_counts if k[1] != window]:
            del _rl_counts[k]
        _rl_counts[key] = _rl_counts.get(key, 0) + 1
        count = _rl_counts[key]

    if count > settings.api_rate_limit_per_min:
        return JSONResponse(
            status_code=429,
            content={"detail": "rate limit exceeded"},
            headers={"Retry-After": str(60 - int(now % 60))},
        )
    return await call_next(request)


def require_api_key(authorization: str = Header(default="")) -> None:
    """Dependency guarding admin/write routes. No-op when no key is configured.

    Public read routes stay open (this is a published threat-intel feed); this
    exists so operational endpoints are not world-writable the moment any are
    added.
    """
    if not settings.api_key:
        return
    expected = f"Bearer {settings.api_key}"
    # Constant-time compare: a naive == leaks the key one byte at a time.
    if not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="invalid or missing API key")


# Prometheus metrics middleware endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Include Routers
app.include_router(actors.router, prefix="/api/actors", tags=["actors"])
app.include_router(ioc.router, prefix="/api/ioc", tags=["ioc"])
app.include_router(feeds.router, prefix="/api/feeds", tags=["feeds"])


@app.get("/health", tags=["health"])
async def health_check() -> dict:
    """API health check.

    Reports queue depths alongside liveness. A queue that stops draining is the
    earliest symptom of a wedged worker, and previously nothing surfaced it —
    ``{"status": "ok"}`` stayed green while the pipeline silently died.
    """
    from pkintel.crypto import encryption_enabled
    from pkintel.db import queue_depths

    depths = queue_depths()
    return {
        "status": "ok" if depths else "degraded",
        "queues": depths,
        "indicator_encryption": encryption_enabled(),
    }


# Mount the static frontend last so it serves index.html at root '/'
from pathlib import Path
from fastapi.staticfiles import StaticFiles


class NoCacheStaticFiles(StaticFiles):
    """StaticFiles subclass that prevents stale browser/CDN caching of CSS & JS."""

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


_frontend_candidates = [
    Path("/app/frontend"),
    Path(__file__).resolve().parents[3] / "frontend",
]
for _fe_dir in _frontend_candidates:
    if _fe_dir.is_dir():
        app.mount("/", NoCacheStaticFiles(directory=str(_fe_dir), html=True), name="frontend")
        break
