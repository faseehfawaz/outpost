"""
FastAPI application for pkintel.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import make_asgi_app

from pkintel.api.routes import actors, feeds, ioc
from pkintel.logging import get_logger

log = get_logger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events for FastAPI."""
    log.info("Starting up pkintel API")
    # Insert database pool init logic here if required
    yield
    log.info("Shutting down pkintel API")
    # Insert database pool teardown logic here if required

app = FastAPI(
    title="pkintel - Phishing-Kit Intelligence API",
    lifespan=lifespan
)

# Allow all origins for dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus metrics middleware endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Include Routers
app.include_router(actors.router, prefix="/api/actors", tags=["actors"])
app.include_router(ioc.router, prefix="/api/ioc", tags=["ioc"])
app.include_router(feeds.router, prefix="/api/feeds", tags=["feeds"])

@app.get("/health", tags=["health"])
async def health_check() -> dict:
    """API Health Check."""
    return {"status": "ok"}

# Mount the static frontend last so it serves index.html at root '/'
from fastapi.staticfiles import StaticFiles

app.mount("/", StaticFiles(directory="/Users/fazee/Documents/PROJECT ONE/frontend", html=True), name="frontend")

