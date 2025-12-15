"""API v1 router - aggregates all v1 endpoints."""

from fastapi import APIRouter

from ..auth import router as auth_router
from ..scans import router as scans_router
from ..findings import router as findings_router
from ..dashboards import router as dashboards_router
from ..domains import router as domains_router
from ..schedules import router as schedules_router
from ..audit import router as audit_router
from ..users import router as users_router
from ..alerts import router as alerts_router
from ..compliance import router as compliance_router
from ..websocket import router as websocket_router
from ..delta import router as delta_router

# Create the v1 router
router = APIRouter()

# Include all API routers under v1
router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
router.include_router(scans_router, prefix="/scans", tags=["Scans"])
router.include_router(findings_router, prefix="/findings", tags=["Findings"])
router.include_router(dashboards_router, prefix="/dashboards", tags=["Dashboards"])
router.include_router(domains_router, prefix="/domains", tags=["Domains"])
router.include_router(schedules_router, prefix="/schedules", tags=["Scheduled Scans"])
router.include_router(audit_router, prefix="/audit-logs", tags=["Audit Logs"])
router.include_router(users_router, prefix="/users", tags=["User Management"])
router.include_router(alerts_router, prefix="/alerts", tags=["Alert Rules"])
router.include_router(compliance_router, prefix="/compliance", tags=["Compliance Reports"])
router.include_router(delta_router, prefix="/delta", tags=["Delta Tracking"])
router.include_router(websocket_router, tags=["WebSocket"])
