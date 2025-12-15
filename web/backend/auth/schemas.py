"""Pydantic schemas for authentication."""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field


class UserBase(BaseModel):
    """Base user schema."""

    email: EmailStr
    full_name: Optional[str] = None


class UserCreate(UserBase):
    """Schema for creating a new user."""

    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    """Schema for updating a user."""

    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = None


class UserDomainSchema(BaseModel):
    """Schema for user domain access."""

    domain: str
    role: str = "viewer"

    class Config:
        from_attributes = True


class UserResponse(UserBase):
    """Schema for user response."""

    id: int
    is_active: bool
    is_superuser: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    domains: List[UserDomainSchema] = []

    class Config:
        from_attributes = True


class LoginRequest(BaseModel):
    """Schema for login request."""

    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Schema for token response."""

    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class PasswordChange(BaseModel):
    """Schema for password change."""

    current_password: str
    new_password: str = Field(..., min_length=8)


class ForgotPasswordRequest(BaseModel):
    """Schema for requesting a password reset."""

    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    """Schema for forgot password response."""

    message: str


class ResetPasswordRequest(BaseModel):
    """Schema for resetting password with token."""

    token: str
    new_password: str = Field(..., min_length=8)


class ResetPasswordResponse(BaseModel):
    """Schema for reset password response."""

    message: str


class UserPermissionsResponse(BaseModel):
    """Schema for user permissions response."""

    is_superuser: bool
    accessible_domains: List[str]  # All domains user can view
    editable_domains: List[str]    # Domains user can trigger scans, manage schedules
    admin_domains: List[str]       # Domains user has full admin access to
    domain_roles: List[UserDomainSchema]  # Per-domain role details
