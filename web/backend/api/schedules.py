"""Scheduled scans API routes."""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import desc
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..auth.security import get_current_user, require_domain_access, require_domain_role, Role
from ..db.database import get_db
from ..db.models import User, Domain, ScheduledScan

router = APIRouter()


# Pydantic schemas for scheduled scans
class ScheduledScanBase(BaseModel):
    """Base schema for scheduled scans."""
    name: str
    scan_type: str  # files, users, oauth, posture, all
    schedule_type: str  # hourly, daily, weekly, monthly
    schedule_config: Optional[Dict[str, Any]] = None
    scan_config: Optional[Dict[str, Any]] = None
    is_active: bool = True


class ScheduledScanCreate(ScheduledScanBase):
    """Schema for creating a scheduled scan."""
    domain_name: str


class ScheduledScanUpdate(BaseModel):
    """Schema for updating a scheduled scan."""
    name: Optional[str] = None
    scan_type: Optional[str] = None
    schedule_type: Optional[str] = None
    schedule_config: Optional[Dict[str, Any]] = None
    scan_config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class ScheduledScanResponse(ScheduledScanBase):
    """Response schema for scheduled scans."""
    id: int
    domain_id: int
    domain_name: str
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_by: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


def calculate_next_run(schedule_type: str, schedule_config: Optional[Dict] = None) -> datetime:
    """Calculate the next run time based on schedule configuration."""
    now = datetime.utcnow()

    if schedule_type == "hourly":
        return now + timedelta(hours=1)
    elif schedule_type == "daily":
        hour = schedule_config.get("hour", 2) if schedule_config else 2
        next_run = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        return next_run
    elif schedule_type == "weekly":
        day_of_week = schedule_config.get("day_of_week", 0) if schedule_config else 0  # 0 = Monday
        hour = schedule_config.get("hour", 2) if schedule_config else 2
        days_ahead = day_of_week - now.weekday()
        if days_ahead <= 0:
            days_ahead += 7
        next_run = now + timedelta(days=days_ahead)
        return next_run.replace(hour=hour, minute=0, second=0, microsecond=0)
    elif schedule_type == "monthly":
        day = schedule_config.get("day", 1) if schedule_config else 1
        hour = schedule_config.get("hour", 2) if schedule_config else 2
        if now.day >= day:
            # Next month
            if now.month == 12:
                next_run = now.replace(year=now.year + 1, month=1, day=day, hour=hour, minute=0, second=0, microsecond=0)
            else:
                next_run = now.replace(month=now.month + 1, day=day, hour=hour, minute=0, second=0, microsecond=0)
        else:
            next_run = now.replace(day=day, hour=hour, minute=0, second=0, microsecond=0)
        return next_run

    return now + timedelta(days=1)


@router.get("", response_model=List[ScheduledScanResponse])
async def list_scheduled_scans(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all scheduled scans accessible to the current user."""
    query = db.query(ScheduledScan).join(Domain)

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(Domain.name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(Domain.name.in_(user_domains))

    if is_active is not None:
        query = query.filter(ScheduledScan.is_active == is_active)

    schedules = query.order_by(desc(ScheduledScan.created_at)).all()

    # Add domain_name to response
    result = []
    for schedule in schedules:
        domain_obj = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
        schedule_dict = {
            "id": schedule.id,
            "name": schedule.name,
            "domain_id": schedule.domain_id,
            "domain_name": domain_obj.name if domain_obj else "unknown",
            "scan_type": schedule.scan_type,
            "schedule_type": schedule.schedule_type,
            "schedule_config": schedule.schedule_config,
            "scan_config": schedule.scan_config,
            "is_active": schedule.is_active,
            "last_run": schedule.last_run,
            "next_run": schedule.next_run,
            "created_by": schedule.created_by,
            "created_at": schedule.created_at,
            "updated_at": schedule.updated_at,
        }
        result.append(ScheduledScanResponse(**schedule_dict))

    return result


@router.post("", response_model=ScheduledScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan(
    data: ScheduledScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new scheduled scan."""
    # Check domain access - requires EDITOR role to create schedules
    require_domain_role(current_user, data.domain_name, Role.EDITOR)

    # Get domain
    domain = db.query(Domain).filter(Domain.name == data.domain_name).first()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{data.domain_name}' not found"
        )

    # Validate schedule_type
    valid_schedule_types = ["hourly", "daily", "weekly", "monthly"]
    if data.schedule_type not in valid_schedule_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid schedule_type. Must be one of: {valid_schedule_types}"
        )

    # Validate scan_type
    valid_scan_types = ["files", "users", "oauth", "posture", "all"]
    if data.scan_type not in valid_scan_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan_type. Must be one of: {valid_scan_types}"
        )

    # Calculate next run
    next_run = calculate_next_run(data.schedule_type, data.schedule_config)

    try:
        schedule = ScheduledScan(
            name=data.name,
            domain_id=domain.id,
            scan_type=data.scan_type,
            schedule_type=data.schedule_type,
            schedule_config=data.schedule_config,
            scan_config=data.scan_config,
            is_active=data.is_active,
            next_run=next_run,
            created_by=current_user.id,
        )

        db.add(schedule)
        db.commit()
        db.refresh(schedule)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create scheduled scan. Please try again.",
        )

    return ScheduledScanResponse(
        id=schedule.id,
        name=schedule.name,
        domain_id=schedule.domain_id,
        domain_name=domain.name,
        scan_type=schedule.scan_type,
        schedule_type=schedule.schedule_type,
        schedule_config=schedule.schedule_config,
        scan_config=schedule.scan_config,
        is_active=schedule.is_active,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        created_by=schedule.created_by,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


@router.get("/{schedule_id}", response_model=ScheduledScanResponse)
async def get_scheduled_scan(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific scheduled scan."""
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found"
        )

    domain = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
    if domain:
        require_domain_access(current_user, domain.name)

    return ScheduledScanResponse(
        id=schedule.id,
        name=schedule.name,
        domain_id=schedule.domain_id,
        domain_name=domain.name if domain else "unknown",
        scan_type=schedule.scan_type,
        schedule_type=schedule.schedule_type,
        schedule_config=schedule.schedule_config,
        scan_config=schedule.scan_config,
        is_active=schedule.is_active,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        created_by=schedule.created_by,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


@router.put("/{schedule_id}", response_model=ScheduledScanResponse)
async def update_scheduled_scan(
    schedule_id: int,
    data: ScheduledScanUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a scheduled scan."""
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found"
        )

    domain = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
    if domain:
        # Requires EDITOR role to update schedules
        require_domain_role(current_user, domain.name, Role.EDITOR)

    # Update fields
    if data.name is not None:
        schedule.name = data.name
    if data.scan_type is not None:
        valid_scan_types = ["files", "users", "oauth", "posture", "all"]
        if data.scan_type not in valid_scan_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid scan_type. Must be one of: {valid_scan_types}"
            )
        schedule.scan_type = data.scan_type
    if data.schedule_type is not None:
        valid_schedule_types = ["hourly", "daily", "weekly", "monthly"]
        if data.schedule_type not in valid_schedule_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid schedule_type. Must be one of: {valid_schedule_types}"
            )
        schedule.schedule_type = data.schedule_type
    if data.schedule_config is not None:
        schedule.schedule_config = data.schedule_config
    if data.scan_config is not None:
        schedule.scan_config = data.scan_config
    if data.is_active is not None:
        schedule.is_active = data.is_active

    # Recalculate next_run if schedule changed
    if data.schedule_type is not None or data.schedule_config is not None:
        schedule.next_run = calculate_next_run(
            schedule.schedule_type,
            schedule.schedule_config
        )

    try:
        db.commit()
        db.refresh(schedule)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update scheduled scan. Please try again.",
        )

    return ScheduledScanResponse(
        id=schedule.id,
        name=schedule.name,
        domain_id=schedule.domain_id,
        domain_name=domain.name if domain else "unknown",
        scan_type=schedule.scan_type,
        schedule_type=schedule.schedule_type,
        schedule_config=schedule.schedule_config,
        scan_config=schedule.scan_config,
        is_active=schedule.is_active,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        created_by=schedule.created_by,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_scan(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a scheduled scan."""
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found"
        )

    domain = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
    if domain:
        # Requires EDITOR role to delete schedules
        require_domain_role(current_user, domain.name, Role.EDITOR)

    try:
        db.delete(schedule)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete scheduled scan. Please try again.",
        )
    return None


@router.post("/{schedule_id}/toggle", response_model=ScheduledScanResponse)
async def toggle_scheduled_scan(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Toggle a scheduled scan's active status."""
    schedule = db.query(ScheduledScan).filter(ScheduledScan.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled scan not found"
        )

    domain = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
    if domain:
        # Requires EDITOR role to toggle schedules
        require_domain_role(current_user, domain.name, Role.EDITOR)

    schedule.is_active = not schedule.is_active

    # Recalculate next_run if activating
    if schedule.is_active:
        schedule.next_run = calculate_next_run(
            schedule.schedule_type,
            schedule.schedule_config
        )

    try:
        db.commit()
        db.refresh(schedule)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle scheduled scan. Please try again.",
        )

    return ScheduledScanResponse(
        id=schedule.id,
        name=schedule.name,
        domain_id=schedule.domain_id,
        domain_name=domain.name if domain else "unknown",
        scan_type=schedule.scan_type,
        schedule_type=schedule.schedule_type,
        schedule_config=schedule.schedule_config,
        scan_config=schedule.scan_config,
        is_active=schedule.is_active,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        created_by=schedule.created_by,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )
