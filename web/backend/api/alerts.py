"""Alert rules API routes."""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..auth.security import get_current_user, require_domain_access, require_domain_role, Role
from ..db.database import get_db
from ..db.models import User, AlertRule, Domain, AuditLog

router = APIRouter()


# Pydantic Schemas
class AlertRuleBase(BaseModel):
    """Base alert rule schema."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: bool = True
    condition_type: str = Field(..., description="Type of condition: high_risk_file, public_file, inactive_user, risky_oauth, security_finding")
    condition_value: dict = Field(default_factory=dict, description="Condition parameters (e.g., {'threshold': 75})")
    notification_channels: List[str] = Field(default_factory=lambda: ["email"], description="Notification channels: email, webhook")
    notification_config: dict = Field(default_factory=dict, description="Channel configuration (e.g., {'emails': ['admin@example.com']})")


class AlertRuleCreate(AlertRuleBase):
    """Schema for creating an alert rule."""
    domain_name: str = Field(..., description="Domain this rule applies to")


class AlertRuleUpdate(BaseModel):
    """Schema for updating an alert rule."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    condition_type: Optional[str] = None
    condition_value: Optional[dict] = None
    notification_channels: Optional[List[str]] = None
    notification_config: Optional[dict] = None


class AlertRuleResponse(AlertRuleBase):
    """Alert rule response schema."""
    id: int
    domain_id: Optional[int] = None
    domain_name: Optional[str] = None
    created_by: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AlertRuleListResponse(BaseModel):
    """Paginated alert rules response."""
    items: List[AlertRuleResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# Valid condition types
VALID_CONDITION_TYPES = [
    "high_risk_file",      # Files with risk score above threshold
    "public_file",         # Public files detected
    "external_share",      # Files shared externally
    "inactive_user",       # Users inactive for X days
    "no_2fa_user",         # Users without 2FA enabled
    "risky_oauth",         # OAuth apps with high risk score
    "security_finding",    # Security posture findings by severity
    "scan_completed",      # Notify when scan completes
    "scan_failed",         # Notify when scan fails
]


@router.get("", response_model=AlertRuleListResponse)
async def list_alert_rules(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List alert rules."""
    query = db.query(AlertRule)

    # Filter by domain access
    if domain:
        require_domain_access(current_user, domain)
        domain_obj = db.query(Domain).filter(Domain.name == domain).first()
        if domain_obj:
            query = query.filter(AlertRule.domain_id == domain_obj.id)
    elif not current_user.is_superuser:
        # Only show rules for domains user has access to
        user_domains = [ud.domain for ud in current_user.domains]
        domain_ids = db.query(Domain.id).filter(Domain.name.in_(user_domains)).all()
        domain_ids = [d[0] for d in domain_ids]
        query = query.filter(AlertRule.domain_id.in_(domain_ids))

    if is_active is not None:
        query = query.filter(AlertRule.is_active == is_active)

    # Get total count
    total = query.count()

    # Paginate
    offset = (page - 1) * page_size
    rules = query.order_by(AlertRule.created_at.desc()).offset(offset).limit(page_size).all()

    # Build response with domain names
    items = []
    for rule in rules:
        domain_obj = db.query(Domain).filter(Domain.id == rule.domain_id).first() if rule.domain_id else None
        items.append(AlertRuleResponse(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            is_active=rule.is_active,
            condition_type=rule.condition_type,
            condition_value=rule.condition_value or {},
            notification_channels=rule.notification_channels or [],
            notification_config=rule.notification_config or {},
            domain_id=rule.domain_id,
            domain_name=domain_obj.name if domain_obj else None,
            created_by=rule.created_by,
            created_at=rule.created_at,
            updated_at=rule.updated_at,
        ))

    return AlertRuleListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.get("/{rule_id}", response_model=AlertRuleResponse)
async def get_alert_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific alert rule."""
    rule = db.query(AlertRule).filter(AlertRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    # Check domain access
    if rule.domain_id:
        domain = db.query(Domain).filter(Domain.id == rule.domain_id).first()
        if domain:
            require_domain_access(current_user, domain.name)

    domain_obj = db.query(Domain).filter(Domain.id == rule.domain_id).first() if rule.domain_id else None

    return AlertRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        is_active=rule.is_active,
        condition_type=rule.condition_type,
        condition_value=rule.condition_value or {},
        notification_channels=rule.notification_channels or [],
        notification_config=rule.notification_config or {},
        domain_id=rule.domain_id,
        domain_name=domain_obj.name if domain_obj else None,
        created_by=rule.created_by,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


@router.post("", response_model=AlertRuleResponse, status_code=201)
async def create_alert_rule(
    request: AlertRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new alert rule."""
    # Validate condition type
    if request.condition_type not in VALID_CONDITION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid condition_type. Must be one of: {', '.join(VALID_CONDITION_TYPES)}"
        )

    # Verify domain access and get domain ID
    require_domain_role(current_user, request.domain_name, Role.EDITOR)
    domain = db.query(Domain).filter(Domain.name == request.domain_name).first()
    if not domain:
        raise HTTPException(status_code=404, detail=f"Domain '{request.domain_name}' not found")

    try:
        rule = AlertRule(
            name=request.name,
            description=request.description,
            is_active=request.is_active,
            domain_id=domain.id,
            condition_type=request.condition_type,
            condition_value=request.condition_value,
            notification_channels=request.notification_channels,
            notification_config=request.notification_config,
            created_by=current_user.id,
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="alert_rule_created",
            resource_type="alert_rule",
            resource_id=str(rule.id),
            details={
                "name": rule.name,
                "domain": request.domain_name,
                "condition_type": rule.condition_type,
            },
        )
        db.add(audit_log)
        db.commit()

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create alert rule")

    return AlertRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        is_active=rule.is_active,
        condition_type=rule.condition_type,
        condition_value=rule.condition_value or {},
        notification_channels=rule.notification_channels or [],
        notification_config=rule.notification_config or {},
        domain_id=rule.domain_id,
        domain_name=domain.name,
        created_by=rule.created_by,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


@router.patch("/{rule_id}", response_model=AlertRuleResponse)
async def update_alert_rule(
    rule_id: int,
    request: AlertRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update an alert rule."""
    rule = db.query(AlertRule).filter(AlertRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    # Check domain access
    domain = db.query(Domain).filter(Domain.id == rule.domain_id).first() if rule.domain_id else None
    if domain:
        require_domain_role(current_user, domain.name, Role.EDITOR)

    # Validate condition type if provided
    if request.condition_type and request.condition_type not in VALID_CONDITION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid condition_type. Must be one of: {', '.join(VALID_CONDITION_TYPES)}"
        )

    try:
        if request.name is not None:
            rule.name = request.name
        if request.description is not None:
            rule.description = request.description
        if request.is_active is not None:
            rule.is_active = request.is_active
        if request.condition_type is not None:
            rule.condition_type = request.condition_type
        if request.condition_value is not None:
            rule.condition_value = request.condition_value
        if request.notification_channels is not None:
            rule.notification_channels = request.notification_channels
        if request.notification_config is not None:
            rule.notification_config = request.notification_config

        db.commit()
        db.refresh(rule)

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="alert_rule_updated",
            resource_type="alert_rule",
            resource_id=str(rule.id),
            details={"name": rule.name},
        )
        db.add(audit_log)
        db.commit()

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update alert rule")

    return AlertRuleResponse(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        is_active=rule.is_active,
        condition_type=rule.condition_type,
        condition_value=rule.condition_value or {},
        notification_channels=rule.notification_channels or [],
        notification_config=rule.notification_config or {},
        domain_id=rule.domain_id,
        domain_name=domain.name if domain else None,
        created_by=rule.created_by,
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


@router.delete("/{rule_id}", status_code=204)
async def delete_alert_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete an alert rule."""
    rule = db.query(AlertRule).filter(AlertRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    # Check domain access
    if rule.domain_id:
        domain = db.query(Domain).filter(Domain.id == rule.domain_id).first()
        if domain:
            require_domain_role(current_user, domain.name, Role.EDITOR)

    try:
        rule_name = rule.name
        db.delete(rule)
        db.commit()

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="alert_rule_deleted",
            resource_type="alert_rule",
            resource_id=str(rule_id),
            details={"name": rule_name},
        )
        db.add(audit_log)
        db.commit()

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete alert rule")


@router.get("/condition-types", response_model=List[dict])
async def get_condition_types(
    current_user: User = Depends(get_current_user),
):
    """Get list of available condition types with descriptions."""
    return [
        {"type": "high_risk_file", "description": "Files with risk score above threshold", "params": ["threshold"]},
        {"type": "public_file", "description": "Public files detected", "params": []},
        {"type": "external_share", "description": "Files shared externally", "params": ["domains"]},
        {"type": "inactive_user", "description": "Users inactive for X days", "params": ["days"]},
        {"type": "no_2fa_user", "description": "Users without 2FA enabled", "params": []},
        {"type": "risky_oauth", "description": "OAuth apps with high risk score", "params": ["threshold"]},
        {"type": "security_finding", "description": "Security posture findings by severity", "params": ["severity"]},
        {"type": "scan_completed", "description": "Notify when scan completes", "params": ["scan_type"]},
        {"type": "scan_failed", "description": "Notify when scan fails", "params": ["scan_type"]},
    ]
