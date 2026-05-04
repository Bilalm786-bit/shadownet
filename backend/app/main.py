"""
ShadowNet — Main Application Entry Point
FastAPI app with full lifecycle management for all services.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog
import time

from app.core.config import settings
from app.core.database import init_db
from app.core.es_client import ESClient
from app.core.neo4j_client import Neo4jClient
from app.core.s3_client import S3Client
from app.core.cursor_client import cursor_client

# API Routers
from app.api.v1.auth import router as auth_router
from app.api.v1.cases import router as cases_router
from app.api.v1.targets import router as targets_router
from app.api.v1.osint import router as osint_router
from app.api.v1.websocket import router as ws_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.search import router as search_router
from app.api.v1.graph import router as graph_router
from app.api.v1.reports import router as reports_router
from app.api.v1.dashboard import router as dashboard_router
from app.api.v1.darkweb import router as darkweb_router
from app.api.v1.cursor_agent import router as cursor_agent_router

logger = structlog.get_logger(__name__)


# ─── Lifecycle ──────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("[*] ShadowNet starting up...", version=settings.app_version)

    # Initialize databases
    await init_db()
    logger.info("[+] Database initialized")

    try:
        await Neo4jClient.connect()
        logger.info("[+] Neo4j connected")
    except Exception as e:
        logger.warning("[-] Neo4j unavailable (non-fatal)", error=str(e))

    try:
        await ESClient.connect()
        logger.info("[+] Elasticsearch connected")
    except Exception as e:
        logger.warning("[-] Elasticsearch unavailable (non-fatal)", error=str(e))

    try:
        S3Client.connect()
        logger.info("[+] MinIO/S3 connected")
    except Exception as e:
        logger.warning("[-] MinIO unavailable (non-fatal)", error=str(e))

    # Import modules to trigger registration
    try:
        import app.modules  # noqa: F401
        logger.info("[+] OSINT modules loaded")
    except Exception as e:
        logger.warning("[-] Some OSINT modules failed to load", error=str(e))

    # Initialize Cursor Cloud Agent client
    if settings.cursor_api_key:
        cursor_client.configure(settings.cursor_api_key, settings.cursor_api_base)
        logger.info("[+] Cursor Cloud Agent API configured")
    else:
        logger.warning("[-] Cursor API key not set — agent features disabled")

    logger.info("[OK] ShadowNet is ready", app=settings.app_name)

    yield

    # Shutdown
    logger.info("[!] ShadowNet shutting down...")
    await Neo4jClient.close()
    await ESClient.close()
    logger.info("Shutdown complete")


# ─── App Factory ────────────────────────────────────────
app = FastAPI(
    title=settings.app_name,
    description="Professional OSINT Intelligence Platform — Reconnaissance, Dark Web Monitoring & Threat Analysis",
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ─── CORS ───────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request Timing Middleware ──────────────────────────
@app.middleware("http")
async def add_process_time(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start
    response.headers["X-Process-Time"] = f"{elapsed:.4f}"
    return response


# ─── Register Routers ──────────────────────────────────
API_PREFIX = "/api/v1"

app.include_router(auth_router, prefix=API_PREFIX)
app.include_router(cases_router, prefix=API_PREFIX)
app.include_router(targets_router, prefix=API_PREFIX)
app.include_router(osint_router, prefix=API_PREFIX)
app.include_router(alerts_router, prefix=API_PREFIX)
app.include_router(search_router, prefix=API_PREFIX)
app.include_router(graph_router, prefix=API_PREFIX)
app.include_router(reports_router, prefix=API_PREFIX)
app.include_router(dashboard_router, prefix=API_PREFIX)
app.include_router(darkweb_router, prefix=API_PREFIX)
app.include_router(cursor_agent_router, prefix=API_PREFIX)
app.include_router(ws_router)  # WebSocket at root


# ─── Health Check ───────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "operational",
        "app": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/", tags=["System"])
async def root():
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "message": "ShadowNet OSINT Platform — API is running",
    }
