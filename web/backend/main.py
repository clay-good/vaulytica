"""Vaulytica Web Backend - FastAPI Application."""

import time
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from .config import get_settings
from .db.database import engine, get_pool_status
from .db.models import Base
from .api import auth, scans, findings, dashboards, domains, schedules, audit, users, alerts, compliance, websocket, delta
from .api.v1 import router as v1_router
from .core.logging import (
    setup_logging,
    get_logger,
    set_request_id,
    clear_context,
    log_event,
    LogEvent,
)

settings = get_settings()

# Setup structured logging
setup_logging(
    log_level=settings.log_level,
    service_name="vaulytica-api",
    environment=settings.environment,
    json_output=settings.log_json,
    log_file=settings.log_file,
)

logger = get_logger(__name__)

# Rate limiter setup
limiter = Limiter(key_func=get_remote_address)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Add security headers
        if settings.is_production():
            # HSTS - tell browsers to only use HTTPS for 1 year
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Enable XSS filter
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Content Security Policy
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"

        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all HTTP requests with structured logging."""

    async def dispatch(self, request: Request, call_next):
        # Set request ID from header or generate new one
        request_id = request.headers.get("X-Request-ID")
        request_id = set_request_id(request_id)

        # Start timer
        start_time = time.time()

        # Get client IP
        client_ip = get_remote_address(request)

        try:
            response = await call_next(request)
            duration_ms = (time.time() - start_time) * 1000

            # Log request (skip health check to reduce noise)
            if request.url.path != "/health":
                logger.info(
                    f"{request.method} {request.url.path} - {response.status_code}",
                    extra={
                        "http_method": request.method,
                        "http_path": request.url.path,
                        "http_status": response.status_code,
                        "http_duration_ms": round(duration_ms, 2),
                        "client_ip": client_ip,
                        "user_agent": request.headers.get("User-Agent", ""),
                    },
                )

            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            return response

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(
                f"{request.method} {request.url.path} - Error: {str(e)}",
                exc_info=True,
                extra={
                    "http_method": request.method,
                    "http_path": request.url.path,
                    "http_duration_ms": round(duration_ms, 2),
                    "client_ip": client_ip,
                    "error": str(e),
                },
            )
            raise
        finally:
            # Clear context after request
            clear_context()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    log_event(
        LogEvent.SYSTEM_STARTUP,
        f"Vaulytica API starting up (version {settings.app_version})",
        environment=settings.environment,
    )
    Base.metadata.create_all(bind=engine)
    logger.info(f"Database tables created/verified")
    yield
    # Shutdown
    log_event(
        LogEvent.SYSTEM_SHUTDOWN,
        "Vaulytica API shutting down",
    )


app = FastAPI(
    title=settings.app_name,
    description="Google Workspace Security & Compliance Platform API",
    version=settings.app_version,
    docs_url="/docs" if not settings.is_production() else None,  # Disable docs in production
    redoc_url="/redoc" if not settings.is_production() else None,
    lifespan=lifespan,
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Request logging middleware (runs first, logs request details)
app.add_middleware(RequestLoggingMiddleware)

# Security headers middleware (add first so it runs last)
app.add_middleware(SecurityHeadersMiddleware)

# HTTPS redirect in production
if settings.is_production():
    app.add_middleware(HTTPSRedirectMiddleware)

# CORS middleware - restrict methods based on actual needs
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin", "X-Requested-With"],
    max_age=600,  # Cache preflight requests for 10 minutes
)

# Include versioned API router (v1)
app.include_router(v1_router, prefix="/api/v1")

# Legacy routes (redirect to v1 for backwards compatibility)
# Include the same routers at /api for backwards compatibility
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication (Legacy)"], deprecated=True)
app.include_router(scans.router, prefix="/api/scans", tags=["Scans (Legacy)"], deprecated=True)
app.include_router(findings.router, prefix="/api/findings", tags=["Findings (Legacy)"], deprecated=True)
app.include_router(dashboards.router, prefix="/api/dashboards", tags=["Dashboards (Legacy)"], deprecated=True)
app.include_router(domains.router, prefix="/api/domains", tags=["Domains (Legacy)"], deprecated=True)
app.include_router(schedules.router, prefix="/api/schedules", tags=["Scheduled Scans (Legacy)"], deprecated=True)
app.include_router(audit.router, prefix="/api/audit-logs", tags=["Audit Logs (Legacy)"], deprecated=True)
app.include_router(users.router, prefix="/api/users", tags=["User Management (Legacy)"], deprecated=True)
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alert Rules (Legacy)"], deprecated=True)
app.include_router(compliance.router, prefix="/api/compliance", tags=["Compliance Reports (Legacy)"], deprecated=True)
app.include_router(delta.router, prefix="/api/delta", tags=["Delta Tracking (Legacy)"], deprecated=True)
app.include_router(websocket.router, prefix="/api", tags=["WebSocket (Legacy)"], deprecated=True)


@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs",
        "redoc": "/redoc",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint with pool status for monitoring."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": settings.app_version,
        "database_pool": get_pool_status(),
    }


@app.get("/api")
async def api_info():
    """API information endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "api_version": "v1",
        "current_version": "/api/v1",
        "legacy_notice": "Routes at /api/* are deprecated. Please use /api/v1/* for new integrations.",
        "endpoints": {
            "v1": {
                "auth": "/api/v1/auth",
                "scans": "/api/v1/scans",
                "findings": "/api/v1/findings",
                "dashboards": "/api/v1/dashboards",
                "domains": "/api/v1/domains",
                "schedules": "/api/v1/schedules",
                "audit_logs": "/api/v1/audit-logs",
                "users": "/api/v1/users",
                "alerts": "/api/v1/alerts",
                "compliance": "/api/v1/compliance",
                "delta": "/api/v1/delta",
                "websocket": "/api/v1/ws",
            },
            "legacy": {
                "auth": "/api/auth",
                "scans": "/api/scans",
                "findings": "/api/findings",
                "dashboards": "/api/dashboards",
                "domains": "/api/domains",
                "schedules": "/api/schedules",
                "audit_logs": "/api/audit-logs",
                "users": "/api/users",
                "alerts": "/api/alerts",
                "compliance": "/api/compliance",
                "delta": "/api/delta",
                "websocket": "/api/ws",
            },
        },
    }
