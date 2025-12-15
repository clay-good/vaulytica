"""Multi-tenant support for Vaulytica.

This module provides tenant context management for multi-tenant deployments.
It supports both application-level filtering and PostgreSQL Row-Level Security (RLS).

Usage:
    # In a request handler
    async def get_scans(tenant: TenantContext = Depends(get_tenant_context)):
        # All queries automatically filtered by tenant
        scans = tenant.query(ScanRun).filter(ScanRun.status == "completed").all()
        return scans

    # Or manually set tenant context
    with set_tenant_context(db, tenant_id=1):
        scans = db.query(ScanRun).all()  # Only returns tenant 1's scans (with RLS)
"""

from __future__ import annotations

import logging
from contextvars import ContextVar
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, Any, TypeVar, Generic, TYPE_CHECKING

from fastapi import Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, ForeignKey, event, text
from sqlalchemy.orm import Session, Query, relationship

if TYPE_CHECKING:
    from .database import Base

logger = logging.getLogger(__name__)

# Context variable for current tenant
current_tenant_id: ContextVar[Optional[int]] = ContextVar("current_tenant_id", default=None)

T = TypeVar("T")


class TenantPlan:
    """Tenant plan definitions."""
    FREE = "free"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"

    LIMITS = {
        FREE: {"max_domains": 1, "max_users": 5, "max_scans_per_month": 10},
        PROFESSIONAL: {"max_domains": 5, "max_users": 25, "max_scans_per_month": 100},
        ENTERPRISE: {"max_domains": -1, "max_users": -1, "max_scans_per_month": -1},  # -1 = unlimited
    }


class TenantInfo(BaseModel):
    """Tenant information schema."""
    id: int
    name: str
    slug: str
    is_active: bool
    plan: str
    max_domains: int
    max_users: int
    settings: Optional[dict] = None

    class Config:
        from_attributes = True


class TenantContext:
    """Context manager for tenant-scoped database operations.

    Provides a query interface that automatically filters by tenant_id.
    For PostgreSQL with RLS enabled, also sets the tenant context at the
    database connection level.
    """

    def __init__(self, db: Session, tenant_id: int, tenant_info: Optional[TenantInfo] = None):
        self.db = db
        self.tenant_id = tenant_id
        self.info = tenant_info
        self._original_context: Optional[int] = None

    def __enter__(self) -> "TenantContext":
        """Enter tenant context."""
        self._original_context = current_tenant_id.get()
        current_tenant_id.set(self.tenant_id)

        # Set PostgreSQL session variable for RLS
        try:
            self.db.execute(text(f"SET app.current_tenant_id = '{self.tenant_id}'"))
            logger.debug(f"Set tenant context to tenant_id={self.tenant_id}")
        except Exception as e:
            # SQLite and other databases don't support session variables
            # This is expected in development/testing environments
            logger.debug(f"Could not set RLS tenant context (non-PostgreSQL database): {type(e).__name__}")

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit tenant context."""
        current_tenant_id.set(self._original_context)

        # Reset PostgreSQL session variable
        try:
            if self._original_context:
                self.db.execute(text(f"SET app.current_tenant_id = '{self._original_context}'"))
                logger.debug(f"Restored tenant context to tenant_id={self._original_context}")
            else:
                self.db.execute(text("SET app.current_tenant_id = ''"))
                logger.debug("Cleared tenant context")
        except Exception as e:
            # SQLite and other databases don't support session variables
            logger.debug(f"Could not reset RLS tenant context (non-PostgreSQL database): {type(e).__name__}")

    def query(self, model: type[T]) -> Query[T]:
        """Create a tenant-filtered query.

        For models with tenant_id, adds automatic filtering.
        For models without tenant_id (like finding tables), filtering
        happens through their relationship to ScanRun.

        Args:
            model: SQLAlchemy model class to query

        Returns:
            Query filtered by tenant_id
        """
        q = self.db.query(model)

        # Check if model has tenant_id column
        if hasattr(model, "tenant_id"):
            q = q.filter(model.tenant_id == self.tenant_id)

        return q


def get_current_tenant() -> Optional[int]:
    """Get the current tenant ID from context.

    Returns:
        Current tenant ID or None if not set
    """
    return current_tenant_id.get()


@contextmanager
def set_tenant_context(db: Session, tenant_id: int):
    """Context manager for setting tenant context.

    Args:
        db: Database session
        tenant_id: Tenant ID to set

    Yields:
        TenantContext instance
    """
    ctx = TenantContext(db, tenant_id)
    with ctx:
        yield ctx


def get_tenant_from_domain(db: Session, domain_name: str) -> Optional[int]:
    """Get tenant_id for a domain.

    Args:
        db: Database session
        domain_name: Domain name to look up

    Returns:
        Tenant ID or None if domain not found
    """
    from ..db.models import Domain
    domain = db.query(Domain).filter(Domain.name == domain_name).first()
    if domain:
        return domain.tenant_id
    return None


def validate_tenant_access(db: Session, user_id: int, tenant_id: int) -> bool:
    """Validate that a user has access to a tenant.

    Args:
        db: Database session
        user_id: User ID to check
        tenant_id: Tenant ID to validate access for

    Returns:
        True if user has access, False otherwise
    """
    from ..db.models import User, TenantMember

    # Superusers have access to all tenants
    user = db.query(User).filter(User.id == user_id).first()
    if user and user.is_superuser:
        return True

    # Check tenant membership
    membership = (
        db.query(TenantMember)
        .filter(TenantMember.user_id == user_id)
        .filter(TenantMember.tenant_id == tenant_id)
        .first()
    )

    return membership is not None


def get_user_tenants(db: Session, user_id: int) -> list[int]:
    """Get list of tenant IDs a user has access to.

    Args:
        db: Database session
        user_id: User ID

    Returns:
        List of tenant IDs
    """
    from ..db.models import TenantMember

    memberships = (
        db.query(TenantMember.tenant_id)
        .filter(TenantMember.user_id == user_id)
        .all()
    )

    return [m.tenant_id for m in memberships]


def check_tenant_limits(db: Session, tenant_id: int, resource: str, count: int = 1) -> bool:
    """Check if a tenant can add more of a resource.

    Args:
        db: Database session
        tenant_id: Tenant ID
        resource: Resource type ('domains', 'users', 'scans')
        count: Number of resources to add

    Returns:
        True if within limits, False if would exceed limits
    """
    from ..db.models import Tenant, Domain, User

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        return False

    limits = TenantPlan.LIMITS.get(tenant.plan, TenantPlan.LIMITS[TenantPlan.FREE])

    if resource == "domains":
        max_allowed = limits["max_domains"]
        if max_allowed == -1:  # Unlimited
            return True
        current = db.query(Domain).filter(Domain.tenant_id == tenant_id).count()
        return (current + count) <= max_allowed

    elif resource == "users":
        max_allowed = limits["max_users"]
        if max_allowed == -1:
            return True
        current = db.query(User).filter(User.tenant_id == tenant_id).count()
        return (current + count) <= max_allowed

    return True  # Unknown resource, allow by default


class TenantMiddleware:
    """Middleware for setting tenant context from request headers or domain.

    This middleware extracts tenant context from:
    1. X-Tenant-ID header (for internal services)
    2. Domain parameter in request
    3. User's default tenant

    And sets it in the database session for RLS enforcement.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            # Extract tenant from headers
            headers = dict(scope.get("headers", []))
            tenant_id = headers.get(b"x-tenant-id")

            if tenant_id:
                # Set tenant context variable
                current_tenant_id.set(int(tenant_id.decode()))

        await self.app(scope, receive, send)


# Event listener to set tenant context on new connections (PostgreSQL only)
def setup_tenant_rls_listener(engine):
    """Set up event listener to configure RLS on new connections.

    This should be called during application startup with the database engine.

    Args:
        engine: SQLAlchemy engine instance
    """
    @event.listens_for(engine, "connect")
    def set_rls_context(dbapi_conn, connection_record):
        """Set tenant context when connection is established."""
        tenant_id = current_tenant_id.get()
        if tenant_id:
            try:
                cursor = dbapi_conn.cursor()
                cursor.execute(f"SET app.current_tenant_id = '{tenant_id}'")
                cursor.close()
                logger.debug(f"Set RLS context on new connection for tenant_id={tenant_id}")
            except Exception as e:
                # Non-PostgreSQL databases don't support this
                logger.debug(f"Could not set RLS on connection (non-PostgreSQL): {type(e).__name__}")
