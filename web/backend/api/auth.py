"""Authentication API routes."""

import secrets
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..auth.schemas import (
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
    UserUpdate,
    PasswordChange,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    UserPermissionsResponse,
    UserDomainSchema,
)
from ..auth.security import (
    authenticate_user,
    create_access_token,
    get_current_user,
    get_current_active_superuser,
    get_password_hash,
    verify_password,
    get_user_accessible_domains,
    get_user_editable_domains,
    get_user_admin_domains,
)
from ..config import get_settings
from ..db.database import get_db
from ..db.models import User, UserDomain, PasswordResetToken, AuditLog
from ..core.email import send_password_reset_email, send_password_reset_confirmation_email

# Token validity period (1 hour)
PASSWORD_RESET_TOKEN_EXPIRE_HOURS = 1

router = APIRouter()
settings = get_settings()
limiter = Limiter(key_func=get_remote_address)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")  # Prevent brute force attacks
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Authenticate user and return JWT token."""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Update last login with proper error handling
    try:
        user.last_login = datetime.utcnow()
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        # Non-critical - don't fail login if last_login update fails

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user.email, "user_id": user.id},
        expires_delta=access_token_expires,
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")  # Prevent spam registrations
async def register(
    request: Request,
    user_in: UserCreate,
    db: Session = Depends(get_db),
):
    """Register a new user."""
    # Check if user exists
    existing_user = db.query(User).filter(User.email == user_in.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Create new user with proper error handling
    try:
        user = User(
            email=user_in.email,
            hashed_password=get_password_hash(user_in.password),
            full_name=user_in.full_name,
            is_active=True,
            is_superuser=False,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user. Please try again.",
        )

    return UserResponse.model_validate(user)


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
):
    """Get current user information."""
    return UserResponse.model_validate(current_user)


@router.put("/me", response_model=UserResponse)
async def update_current_user(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update current user information."""
    if user_update.email is not None:
        # Check if email is already taken
        existing = db.query(User).filter(
            User.email == user_update.email,
            User.id != current_user.id,
        ).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use",
            )
        current_user.email = user_update.email

    if user_update.full_name is not None:
        current_user.full_name = user_update.full_name

    if user_update.password is not None:
        current_user.hashed_password = get_password_hash(user_update.password)

    try:
        db.commit()
        db.refresh(current_user)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user. Please try again.",
        )
    return UserResponse.model_validate(current_user)


@router.post("/me/change-password")
@limiter.limit("3/minute")  # Prevent brute force password guessing
async def change_password(
    request: Request,
    password_change: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Change current user's password."""
    if not verify_password(password_change.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password",
        )

    try:
        current_user.hashed_password = get_password_hash(password_change.new_password)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to change password. Please try again.",
        )

    return {"message": "Password changed successfully"}


@router.get("/me/permissions", response_model=UserPermissionsResponse)
async def get_current_user_permissions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get current user's permissions and accessible domains.

    Returns a summary of what the user can access and what roles they have.
    Useful for frontend to determine what UI elements to show/hide.
    """
    accessible = get_user_accessible_domains(current_user, db)
    editable = get_user_editable_domains(current_user, db)
    admin = get_user_admin_domains(current_user, db)

    # Build domain roles list
    domain_roles = [
        UserDomainSchema(domain=ud.domain, role=ud.role)
        for ud in current_user.domains
    ]

    return UserPermissionsResponse(
        is_superuser=current_user.is_superuser,
        accessible_domains=accessible,
        editable_domains=editable,
        admin_domains=admin,
        domain_roles=domain_roles,
    )


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_superuser),
    db: Session = Depends(get_db),
):
    """List all users (superuser only)."""
    users = db.query(User).offset(skip).limit(limit).all()
    return [UserResponse.model_validate(user) for user in users]


@router.post("/users/{user_id}/domains")
async def add_user_domain(
    user_id: int,
    domain: str,
    role: str = "viewer",
    current_user: User = Depends(get_current_active_superuser),
    db: Session = Depends(get_db),
):
    """Add domain access to a user (superuser only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    try:
        # Check if domain access already exists
        existing = db.query(UserDomain).filter(
            UserDomain.user_id == user_id,
            UserDomain.domain == domain,
        ).first()
        if existing:
            existing.role = role
        else:
            user_domain = UserDomain(user_id=user_id, domain=domain, role=role)
            db.add(user_domain)

        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to add domain access. Please try again.",
        )
    return {"message": f"Domain {domain} added to user {user.email}"}


@router.delete("/users/{user_id}/domains/{domain}")
async def remove_user_domain(
    user_id: int,
    domain: str,
    current_user: User = Depends(get_current_active_superuser),
    db: Session = Depends(get_db),
):
    """Remove domain access from a user (superuser only)."""
    user_domain = db.query(UserDomain).filter(
        UserDomain.user_id == user_id,
        UserDomain.domain == domain,
    ).first()
    if not user_domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain access not found",
        )

    try:
        db.delete(user_domain)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove domain access. Please try again.",
        )
    return {"message": f"Domain {domain} removed from user"}


@router.post("/forgot-password", response_model=ForgotPasswordResponse)
@limiter.limit("3/minute")  # Prevent enumeration and abuse
async def forgot_password(
    request: Request,
    forgot_request: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    """Request a password reset token.

    Always returns success to prevent email enumeration attacks.
    If the email exists and user is active, a reset token is created.
    In production, this would send an email with the reset link.
    """
    # Always return success message to prevent email enumeration
    success_message = (
        "If an account with that email exists, "
        "a password reset link has been sent."
    )

    user = db.query(User).filter(User.email == forgot_request.email).first()

    # If user doesn't exist or is inactive, return success without creating token
    if not user or not user.is_active:
        return ForgotPasswordResponse(message=success_message)

    try:
        # Invalidate any existing unused tokens for this user
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        ).delete(synchronize_session="fetch")

        # Create new reset token
        token = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=PASSWORD_RESET_TOKEN_EXPIRE_HOURS)

        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=expires_at,
        )
        db.add(reset_token)

        # Log the action
        audit_log = AuditLog(
            user_id=user.id,
            action="password_reset_requested",
            resource_type="user",
            resource_id=str(user.id),
            details={"email": user.email},
        )
        db.add(audit_log)
        db.commit()

        # Send password reset email (will log token if SMTP not configured)
        send_password_reset_email(user.email, token, user.full_name)

    except SQLAlchemyError:
        db.rollback()
        # Still return success to prevent enumeration
        pass

    return ForgotPasswordResponse(message=success_message)


@router.post("/reset-password", response_model=ResetPasswordResponse)
@limiter.limit("5/minute")  # Prevent brute force
async def reset_password(
    request: Request,
    reset_request: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    """Reset password using a valid reset token.

    The token must be valid (not expired, not used).
    """
    # Find the token
    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == reset_request.token,
    ).first()

    if not reset_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # Check if token is already used
    if reset_token.used_at is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset token has already been used",
        )

    # Check if token is expired
    if datetime.utcnow() > reset_token.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token has expired. Please request a new one.",
        )

    # Get the user
    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This account is deactivated. Please contact an administrator.",
        )

    try:
        # Update password
        user.hashed_password = get_password_hash(reset_request.new_password)

        # Mark token as used
        reset_token.used_at = datetime.utcnow()

        # Log the action
        audit_log = AuditLog(
            user_id=user.id,
            action="password_reset_completed",
            resource_type="user",
            resource_id=str(user.id),
            details={"email": user.email},
        )
        db.add(audit_log)
        db.commit()

        # Send confirmation email (non-blocking, failure won't affect response)
        send_password_reset_confirmation_email(user.email, user.full_name)

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset password. Please try again.",
        )

    return ResetPasswordResponse(message="Password has been reset successfully. You can now log in with your new password.")


@router.get("/reset-password/validate/{token}")
async def validate_reset_token(
    token: str,
    db: Session = Depends(get_db),
):
    """Validate a password reset token without using it.

    Useful for frontend to check if token is valid before showing reset form.
    """
    reset_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == token,
    ).first()

    if not reset_token:
        return {"valid": False, "reason": "Token not found"}

    if reset_token.used_at is not None:
        return {"valid": False, "reason": "Token already used"}

    if datetime.utcnow() > reset_token.expires_at:
        return {"valid": False, "reason": "Token expired"}

    user = db.query(User).filter(User.id == reset_token.user_id).first()
    if not user or not user.is_active:
        return {"valid": False, "reason": "Invalid token"}

    return {"valid": True, "email": user.email}
