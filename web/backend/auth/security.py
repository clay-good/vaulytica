"""Security utilities for authentication and authorization."""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db.database import get_db
from ..db.models import User

settings = get_settings()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


class Token(BaseModel):
    """Token response model."""

    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Token payload data."""

    email: Optional[str] = None
    user_id: Optional[int] = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token. Returns the payload dict or raises JWTError."""
    return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])


def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """Authenticate a user by email and password."""
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Get the current authenticated user from the JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        email: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email, user_id=user_id)
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )
    return user


async def get_current_active_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """Get the current user and verify they are a superuser."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user


from enum import Enum
from typing import List


class Role(str, Enum):
    """User roles for domain access."""
    VIEWER = "viewer"      # Read-only access to scan results and findings
    EDITOR = "editor"      # Can trigger scans, update finding statuses, manage schedules
    ADMIN = "admin"        # Full access including user management for the domain


# Role hierarchy - higher roles include all permissions of lower roles
ROLE_HIERARCHY = {
    Role.VIEWER: [Role.VIEWER],
    Role.EDITOR: [Role.VIEWER, Role.EDITOR],
    Role.ADMIN: [Role.VIEWER, Role.EDITOR, Role.ADMIN],
}


def get_user_role_for_domain(user: User, domain: str) -> Optional[Role]:
    """Get the user's role for a specific domain.

    Returns None if user has no access to the domain.
    Superusers are treated as having ADMIN role for all domains.
    """
    if user.is_superuser:
        return Role.ADMIN

    for ud in user.domains:
        if ud.domain == domain:
            try:
                return Role(ud.role)
            except ValueError:
                return Role.VIEWER  # Default to viewer for unknown roles
    return None


def check_domain_access(user: User, domain: str) -> bool:
    """Check if user has access to a specific domain."""
    return get_user_role_for_domain(user, domain) is not None


def check_domain_role(user: User, domain: str, required_role: Role) -> bool:
    """Check if user has at least the required role for a domain.

    Args:
        user: The user to check
        domain: The domain to check access for
        required_role: The minimum role required

    Returns:
        True if user has at least the required role, False otherwise
    """
    user_role = get_user_role_for_domain(user, domain)
    if user_role is None:
        return False

    # Check if required_role is in the user's role hierarchy
    return required_role in ROLE_HIERARCHY.get(user_role, [])


def require_domain_access(user: User, domain: str) -> None:
    """Raise exception if user doesn't have access to domain."""
    if not check_domain_access(user, domain):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied to domain: {domain}",
        )


def require_domain_role(user: User, domain: str, required_role: Role) -> None:
    """Raise exception if user doesn't have required role for domain.

    Args:
        user: The user to check
        domain: The domain to check access for
        required_role: The minimum role required

    Raises:
        HTTPException: 403 if user doesn't have the required role
    """
    if not check_domain_role(user, domain, required_role):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires {required_role.value} role for domain: {domain}",
        )


def get_user_accessible_domains(user: User, db: Session) -> List[str]:
    """Get list of domains the user can access.

    Superusers can access all domains.
    Regular users can only access domains explicitly assigned to them.
    """
    if user.is_superuser:
        from ..db.models import Domain
        domains = db.query(Domain.name).filter(Domain.is_active == True).all()
        return [d[0] for d in domains]

    return [ud.domain for ud in user.domains]


def get_user_editable_domains(user: User, db: Session) -> List[str]:
    """Get list of domains the user can edit (trigger scans, manage schedules, etc.).

    Superusers can edit all domains.
    Regular users need at least EDITOR role.
    """
    if user.is_superuser:
        from ..db.models import Domain
        domains = db.query(Domain.name).filter(Domain.is_active == True).all()
        return [d[0] for d in domains]

    return [ud.domain for ud in user.domains if ud.role in (Role.EDITOR.value, Role.ADMIN.value)]


def get_user_admin_domains(user: User, db: Session) -> List[str]:
    """Get list of domains the user has admin access to.

    Superusers have admin access to all domains.
    Regular users need ADMIN role for the domain.
    """
    if user.is_superuser:
        from ..db.models import Domain
        domains = db.query(Domain.name).filter(Domain.is_active == True).all()
        return [d[0] for d in domains]

    return [ud.domain for ud in user.domains if ud.role == Role.ADMIN.value]
