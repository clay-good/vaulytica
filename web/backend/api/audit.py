"""Audit Log API routes."""

from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from ..auth.security import get_current_user
from ..db.database import get_db
from ..db.models import User, AuditLog
from .schemas import AuditLogResponse

router = APIRouter()


@router.get("/", response_model=List[AuditLogResponse])
async def get_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action type"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    days: int = Query(30, ge=1, le=365, description="Number of days to look back"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get audit logs with optional filtering.

    Only superusers can view all audit logs. Regular users can only view their own.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    query = db.query(AuditLog).filter(AuditLog.created_at >= cutoff_date)

    # Non-superusers can only see their own audit logs
    if not current_user.is_superuser:
        query = query.filter(AuditLog.user_id == current_user.id)
    elif user_id:
        # Superusers can filter by specific user
        query = query.filter(AuditLog.user_id == user_id)

    if action:
        query = query.filter(AuditLog.action == action)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)

    # Get total count for pagination
    total = query.count()
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size

    logs = query.order_by(desc(AuditLog.created_at)).offset(offset).limit(page_size).all()

    return {
        "items": [AuditLogResponse.model_validate(log) for log in logs],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


@router.get("/actions")
async def get_audit_log_actions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get list of distinct audit log actions.

    Useful for building filter dropdowns in the UI.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="Only superusers can access this endpoint"
        )

    actions = db.query(AuditLog.action).distinct().all()
    return {"actions": [a[0] for a in actions if a[0]]}


@router.get("/resource-types")
async def get_audit_log_resource_types(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get list of distinct audit log resource types.

    Useful for building filter dropdowns in the UI.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="Only superusers can access this endpoint"
        )

    resource_types = db.query(AuditLog.resource_type).distinct().all()
    return {"resource_types": [rt[0] for rt in resource_types if rt[0]]}


@router.get("/summary")
async def get_audit_log_summary(
    days: int = Query(7, ge=1, le=30, description="Number of days to summarize"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a summary of audit log activity.

    Only superusers can access the full summary.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="Only superusers can access this endpoint"
        )

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    logs = db.query(AuditLog).filter(AuditLog.created_at >= cutoff_date).all()

    # Count by action type
    action_counts = {}
    for log in logs:
        action = log.action or "unknown"
        action_counts[action] = action_counts.get(action, 0) + 1

    # Count by resource type
    resource_counts = {}
    for log in logs:
        resource = log.resource_type or "unknown"
        resource_counts[resource] = resource_counts.get(resource, 0) + 1

    # Count by day
    daily_counts = {}
    for log in logs:
        day = log.created_at.strftime("%Y-%m-%d") if log.created_at else "unknown"
        daily_counts[day] = daily_counts.get(day, 0) + 1

    return {
        "total_events": len(logs),
        "period_days": days,
        "by_action": action_counts,
        "by_resource_type": resource_counts,
        "by_day": daily_counts,
    }
