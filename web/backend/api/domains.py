"""Domain management API routes."""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..auth.security import get_current_user, get_current_active_superuser
from ..db.database import get_db
from ..db.models import User, Domain
from .schemas import DomainCreate, DomainResponse

router = APIRouter()


@router.get("/", response_model=List[DomainResponse])
async def list_domains(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all domains accessible to the current user."""
    if current_user.is_superuser:
        domains = db.query(Domain).filter(Domain.is_active == True).all()
    else:
        user_domain_names = [ud.domain for ud in current_user.domains]
        domains = (
            db.query(Domain)
            .filter(
                Domain.is_active == True,
                Domain.name.in_(user_domain_names),
            )
            .all()
        )

    return [DomainResponse.model_validate(d) for d in domains]


@router.post("/", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def create_domain(
    domain_in: DomainCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser),
):
    """Create a new domain (superuser only)."""
    # Check if domain already exists
    existing = db.query(Domain).filter(Domain.name == domain_in.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain already exists",
        )

    try:
        domain = Domain(
            name=domain_in.name,
            display_name=domain_in.display_name or domain_in.name,
            admin_email=domain_in.admin_email,
            credentials_path=domain_in.credentials_path,
            is_active=True,
        )
        db.add(domain)
        db.commit()
        db.refresh(domain)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create domain. Please try again.",
        )

    return DomainResponse.model_validate(domain)


@router.get("/{domain_name}", response_model=DomainResponse)
async def get_domain(
    domain_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get domain details."""
    # Check access
    if not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        if domain_name not in user_domains:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this domain",
            )

    domain = db.query(Domain).filter(Domain.name == domain_name).first()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    return DomainResponse.model_validate(domain)


@router.put("/{domain_name}", response_model=DomainResponse)
async def update_domain(
    domain_name: str,
    domain_update: DomainCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser),
):
    """Update domain settings (superuser only)."""
    domain = db.query(Domain).filter(Domain.name == domain_name).first()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    try:
        domain.display_name = domain_update.display_name or domain.display_name
        domain.admin_email = domain_update.admin_email or domain.admin_email
        domain.credentials_path = domain_update.credentials_path or domain.credentials_path
        domain.updated_at = datetime.utcnow()

        db.commit()
        db.refresh(domain)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update domain. Please try again.",
        )

    return DomainResponse.model_validate(domain)


@router.delete("/{domain_name}")
async def delete_domain(
    domain_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser),
):
    """Delete a domain (superuser only)."""
    domain = db.query(Domain).filter(Domain.name == domain_name).first()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    try:
        # Soft delete by setting is_active to False
        domain.is_active = False
        domain.updated_at = datetime.utcnow()
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete domain. Please try again.",
        )

    return {"message": f"Domain {domain_name} deleted"}


@router.post("/{domain_name}/activate")
async def activate_domain(
    domain_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser),
):
    """Activate a domain (superuser only)."""
    domain = db.query(Domain).filter(Domain.name == domain_name).first()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    try:
        domain.is_active = True
        domain.updated_at = datetime.utcnow()
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate domain. Please try again.",
        )

    return {"message": f"Domain {domain_name} activated"}


@router.post("/{domain_name}/rotate-credentials")
async def rotate_credentials(
    domain_name: str,
    credentials_path: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser),
):
    """
    Rotate domain credentials (superuser only).

    This endpoint allows updating the service account credentials
    for a domain without changing other settings. Use this when:
    - Service account keys are rotated per security policy
    - Credentials have been compromised
    - Moving to a new service account

    Args:
        domain_name: The domain to update
        credentials_path: Path to the new credentials file
    """
    from ..db.models import AuditLog

    domain = db.query(Domain).filter(Domain.name == domain_name).first()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    old_credentials_path = domain.credentials_path

    try:
        domain.credentials_path = credentials_path
        domain.credentials_rotated_at = datetime.utcnow()
        domain.updated_at = datetime.utcnow()

        # Create audit log entry
        audit_log = AuditLog(
            user_id=current_user.id,
            action="credentials_rotated",
            resource_type="domain",
            resource_id=str(domain.id),
            details={
                "domain": domain_name,
                "old_credentials_path": old_credentials_path,
                "new_credentials_path": credentials_path,
            },
        )
        db.add(audit_log)

        db.commit()
        db.refresh(domain)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to rotate credentials. Please try again.",
        )

    return {
        "message": f"Credentials rotated for domain {domain_name}",
        "rotated_at": domain.credentials_rotated_at.isoformat(),
    }


@router.get("/{domain_name}/credentials-status")
async def get_credentials_status(
    domain_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get credentials status for a domain.

    Returns information about when credentials were last rotated
    and whether rotation is recommended.
    """
    # Check access
    if not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        if domain_name not in user_domains:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to this domain",
            )

    domain = db.query(Domain).filter(Domain.name == domain_name).first()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    # Calculate days since last rotation
    last_rotated = domain.credentials_rotated_at or domain.created_at
    days_since_rotation = (datetime.utcnow() - last_rotated).days

    # Recommend rotation after 90 days
    rotation_recommended = days_since_rotation > 90

    return {
        "domain": domain_name,
        "credentials_path": domain.credentials_path,
        "last_rotated": last_rotated.isoformat() if last_rotated else None,
        "days_since_rotation": days_since_rotation,
        "rotation_recommended": rotation_recommended,
        "recommendation_threshold_days": 90,
    }
