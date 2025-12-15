"""User management API routes for administrators."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..auth.schemas import UserResponse, UserDomainSchema
from ..auth.security import get_current_active_superuser, get_password_hash
from ..db.database import get_db
from ..db.models import User, UserDomain, AuditLog

router = APIRouter()


class AdminUserUpdate(BaseModel):
    """Schema for admin updating a user."""

    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None


class UserListResponse(BaseModel):
    """Paginated user list response."""

    items: List[UserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search by email or name"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    is_superuser: Optional[bool] = Query(None, description="Filter by superuser status"),
    current_user: User = Depends(get_current_active_superuser),
    db: Session = Depends(get_db),
):
    """List all users with pagination and filtering (superuser only)."""
    query = db.query(User)

    # Apply filters
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (User.email.ilike(search_term)) | (User.full_name.ilike(search_term))
        )
    if is_active is not None:
        query = query.filter(User.is_active == is_active)
    if is_superuser is not None:
        query = query.filter(User.is_superuser == is_superuser)

    # Get total count
    total = query.count()

    # Apply pagination
    offset = (page - 1) * page_size
    users = query.order_by(User.created_at.desc()).offset(offset).limit(page_size).all()

    total_pages = (total + page_size - 1) // page_size

    return UserListResponse(
        items=[UserResponse.model_validate(user) for user in users],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_active_superuser),
    db: Session = Depends(get_db),
):
    """Get a specific user by ID (superuser only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return UserResponse.model_validate(user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_update: AdminUserUpdate,
    current_user: User = Depends(get_current_active_superuser),
    db: Session = Depends(get_db),
):
    """Update a user (superuser only).

    Allows updating email, full_name, password, is_active, and is_superuser.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent self-demotion from superuser
    if user.id == current_user.id and user_update.is_superuser is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own superuser status",
        )

    # Prevent self-deactivation
    if user.id == current_user.id and user_update.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account",
        )

    # Track changes for audit log
    changes = {}

    if user_update.email is not None and user_update.email != user.email:
        # Check if email is already taken
        existing = db.query(User).filter(
            User.email == user_update.email,
            User.id != user_id,
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use",
            )
        changes["email"] = {"old": user.email, "new": user_update.email}
        user.email = user_update.email

    if user_update.full_name is not None and user_update.full_name != user.full_name:
        changes["full_name"] = {"old": user.full_name, "new": user_update.full_name}
        user.full_name = user_update.full_name

    if user_update.password is not None:
        user.hashed_password = get_password_hash(user_update.password)
        changes["password"] = "changed"

    if user_update.is_active is not None and user_update.is_active != user.is_active:
        changes["is_active"] = {"old": user.is_active, "new": user_update.is_active}
        user.is_active = user_update.is_active

    if user_update.is_superuser is not None and user_update.is_superuser != user.is_superuser:
        changes["is_superuser"] = {"old": user.is_superuser, "new": user_update.is_superuser}
        user.is_superuser = user_update.is_superuser

    if not changes:
        return UserResponse.model_validate(user)

    try:
        db.commit()
        db.refresh(user)

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="user_updated",
            resource_type="user",
            resource_id=str(user_id),
            details={
                "target_user": user.email,
                "changes": changes,
            },
        )
        db.add(audit_log)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user. Please try again.",
        )

    return UserResponse.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_active_superuser),
    db: Session = Depends(get_db),
):
    """Delete a user (superuser only).

    This permanently removes the user and their domain associations.
    Audit logs are preserved for compliance.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent self-deletion
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    user_email = user.email

    try:
        # Delete user domain associations first
        db.query(UserDomain).filter(UserDomain.user_id == user_id).delete()

        # Delete the user
        db.delete(user)
        db.commit()

        # Log the action (after commit to ensure user is deleted)
        audit_log = AuditLog(
            user_id=current_user.id,
            action="user_deleted",
            resource_type="user",
            resource_id=str(user_id),
            details={
                "deleted_user_email": user_email,
            },
        )
        db.add(audit_log)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user. Please try again.",
        )

    return None


@router.post("/{user_id}/activate", response_model=UserResponse)
async def activate_user(
    user_id: int,
    current_user: User = Depends(get_current_active_superuser),
    db: Session = Depends(get_db),
):
    """Activate a deactivated user (superuser only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already active",
        )

    try:
        user.is_active = True
        db.commit()
        db.refresh(user)

        audit_log = AuditLog(
            user_id=current_user.id,
            action="user_activated",
            resource_type="user",
            resource_id=str(user_id),
            details={"target_user": user.email},
        )
        db.add(audit_log)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate user. Please try again.",
        )

    return UserResponse.model_validate(user)


@router.post("/{user_id}/deactivate", response_model=UserResponse)
async def deactivate_user(
    user_id: int,
    current_user: User = Depends(get_current_active_superuser),
    db: Session = Depends(get_db),
):
    """Deactivate a user (superuser only).

    Deactivated users cannot log in but their data is preserved.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Prevent self-deactivation
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already deactivated",
        )

    try:
        user.is_active = False
        db.commit()
        db.refresh(user)

        audit_log = AuditLog(
            user_id=current_user.id,
            action="user_deactivated",
            resource_type="user",
            resource_id=str(user_id),
            details={"target_user": user.email},
        )
        db.add(audit_log)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to deactivate user. Please try again.",
        )

    return UserResponse.model_validate(user)
