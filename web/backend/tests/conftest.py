"""Test configuration and fixtures for backend tests."""

import os
import pytest
from datetime import datetime, timedelta
from typing import Generator

# Set environment variables BEFORE importing the app
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "test-secret-key-for-testing-purposes-only-12345"
os.environ["ENVIRONMENT"] = "development"

from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker, Session

from backend.main import app
from backend.db.database import get_db, engine
from backend.db.models import Base, User, Domain, ScanRun, UserDomain
from backend.auth.security import get_password_hash, create_access_token
from backend.core.cache import get_cache


# Create testing session using the engine from database module (configured for SQLite via env)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db() -> Generator[Session, None, None]:
    """Create a fresh database session for each test."""
    # Clear cache before each test for isolation
    get_cache().clear()
    # Create all tables before each test
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        # Drop all tables after each test for isolation
        Base.metadata.drop_all(bind=engine)
        # Clear cache after test as well
        get_cache().clear()


@pytest.fixture(scope="function")
def client(db: Session) -> Generator[TestClient, None, None]:
    """Create a test client with database override."""

    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_user(db: Session) -> User:
    """Create a test user."""
    user = User(
        email="test@example.com",
        hashed_password=get_password_hash("testpassword"),
        full_name="Test User",
        is_active=True,
        is_superuser=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def test_superuser(db: Session) -> User:
    """Create a test superuser."""
    user = User(
        email="admin@example.com",
        hashed_password=get_password_hash("adminpassword"),
        full_name="Admin User",
        is_active=True,
        is_superuser=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture
def test_domain(db: Session) -> Domain:
    """Create a test domain."""
    domain = Domain(
        name="example.com",
        display_name="Example Company",
        admin_email="admin@example.com",
        is_active=True,
    )
    db.add(domain)
    db.commit()
    db.refresh(domain)
    return domain


@pytest.fixture
def user_with_domain(db: Session, test_user: User, test_domain: Domain) -> User:
    """Create a user with domain access."""
    user_domain = UserDomain(
        user_id=test_user.id,
        domain=test_domain.name,
        role="viewer",
    )
    db.add(user_domain)
    db.commit()
    db.refresh(test_user)
    return test_user


@pytest.fixture
def auth_headers(test_user: User) -> dict:
    """Create authentication headers for test user."""
    token = create_access_token(
        data={"sub": test_user.email, "user_id": test_user.id}
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def superuser_headers(test_superuser: User) -> dict:
    """Create authentication headers for superuser."""
    token = create_access_token(
        data={"sub": test_superuser.email, "user_id": test_superuser.id}
    )
    return {"Authorization": f"Bearer {token}"}


# Aliases for test_users.py compatibility
@pytest.fixture
def db_session(db: Session) -> Session:
    """Alias for db fixture for backward compatibility."""
    return db


@pytest.fixture
def superuser(test_superuser: User) -> User:
    """Alias for test_superuser fixture."""
    return test_superuser


@pytest.fixture
def superuser_token(test_superuser: User) -> str:
    """Create access token for superuser."""
    return create_access_token(
        data={"sub": test_superuser.email, "user_id": test_superuser.id}
    )


@pytest.fixture
def regular_user_token(test_user: User) -> str:
    """Create access token for regular user."""
    return create_access_token(
        data={"sub": test_user.email, "user_id": test_user.id}
    )


@pytest.fixture
def test_scan_run(db: Session, test_domain: Domain) -> ScanRun:
    """Create a test scan run."""
    scan = ScanRun(
        scan_type="posture",
        domain_name=test_domain.name,
        domain_id=test_domain.id,
        status="completed",
        start_time=datetime.utcnow() - timedelta(hours=1),
        end_time=datetime.utcnow(),
        total_items=100,
        issues_found=10,
        high_risk_count=2,
        medium_risk_count=5,
        low_risk_count=3,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@pytest.fixture
def authenticated_client(
    db: Session, test_user: User, test_domain: Domain
) -> Generator[TestClient, None, None]:
    """Create a test client with authenticated user who has domain access."""
    # Give user access to test domain
    user_domain = UserDomain(
        user_id=test_user.id,
        domain=test_domain.name,
        role="admin",
    )
    db.add(user_domain)
    db.commit()

    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db

    # Create token for the user
    token = create_access_token(
        data={"sub": test_user.email, "user_id": test_user.id}
    )

    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = f"Bearer {token}"
        yield test_client

    app.dependency_overrides.clear()
