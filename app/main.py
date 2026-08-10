"""
AI Code Security Reviewer — Application entry point.

Responsibilities (and nothing else):
- Configure logging
- Initialize database and bootstrap admin
- Create FastAPI app, mount static files, register routers
- Add request-correlation middleware
"""

import uuid
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from sqlmodel import Session, select

from app.api.routes import admin, auth, export, reviews, submissions, web
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.core.security import hash_password
from app.db.session import engine, init_db
from app.models.user import Role, User
from app.rag.setup import ensure_pgvector
from app.rag.embedder import SentenceTransformerEmbedder

# --- Logging ---
configure_logging()
logger = get_logger(__name__)

# --- Startup logic ---
def _bootstrap_admin() -> None:
    """Create the first admin if none exists. ADR-006."""
    with Session(engine) as session:
        existing = session.exec(
            select(User).where(User.role == Role.ADMIN)
        ).first()
        if existing:
            logger.info("bootstrap_skipped", reason="admin_exists", email=existing.email)
            return

        admin_user = User(
            email=settings.INITIAL_ADMIN_EMAIL,
            password_hash=hash_password(settings.INITIAL_ADMIN_PASSWORD),
            role=Role.ADMIN,
        )
        session.add(admin_user)
        session.commit()
        logger.info("bootstrap_admin_created", email=admin_user.email)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting_up")
    ensure_pgvector(engine)
    init_db()
    logger.info("database_initialized")
    _bootstrap_admin()
    logger.info("bootstrap_complete")
    app.state.embedder = SentenceTransformerEmbedder()
    logger.info("embedder_loaded")
    yield
    logger.info("shutting_down")


# --- App ---
app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
    description="Security review of code using a SAST tool and LLM",
    lifespan=lifespan,
)

# Static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# API routers
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(submissions.router)
app.include_router(reviews.router)
app.include_router(export.router)

# Web UI router
app.include_router(web.router)

# --- Middleware ---
@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Bind a unique request ID to every log emitted during this request.

    Minimal: capture request body, log a truncated view, and replay the body
    for downstream handlers so behavior is unchanged.
    """
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
    )

    # Read body and log a truncated representation (safe size)
    try:
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body_bytes = b""
        body_text = ""

    truncated = (body_text[:1000] + "...[truncated]") if len(body_text) > 1000 else body_text
    logger.info(
        "incoming_request",
        method=request.method,
        path=request.url.path,
        query=str(request.url.query),
        client=request.client.host if request.client else None,
        body=truncated,
    )

    # Replay the body for downstream handlers
    async def _receive() -> dict:
        return {"type": "http.request", "body": body_bytes, "more_body": False}

    new_request = Request(request.scope, _receive)
    response = await call_next(new_request)
    response.headers["X-Request-ID"] = request_id

    logger.info(
        "request_completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
    )
    return response

# --- Exception handler ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred. Please try again."},
    )

# --- Health / Root ---
@app.get("/health", tags=["system"])
def health():
    """Liveness check for Docker healthcheck and monitoring"""
    return {"status": "ok", "environment": settings.ENVIRONMENT}

@app.get("/", tags=["system"])
def root():
    """Landing redirect hint"""
    return {"message": "AI Code Security Reviewer", "docs": "/docs", "ui": "/web/"}