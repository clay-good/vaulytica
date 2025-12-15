#!/usr/bin/env python3
"""Initialize database and create admin user.

This script should be run after starting the PostgreSQL container
but before starting the backend.

Usage:
    python scripts/init_db.py

Environment variables:
    DATABASE_URL: PostgreSQL connection string
    ADMIN_EMAIL: Admin user email (default: admin@example.com)
    ADMIN_PASSWORD: Admin user password (default: changeme)
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Get database URL from environment
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://vaulytica:changeme@localhost:5432/vaulytica"
)

# Import models and create tables
from backend.db.models import Base, User
from backend.auth.security import get_password_hash


def init_database():
    """Create all database tables."""
    print(f"Connecting to database: {DATABASE_URL.replace(DATABASE_URL.split(':')[2].split('@')[0], '***')}")

    engine = create_engine(DATABASE_URL)

    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully!")

    return engine


def create_admin_user(engine):
    """Create admin user if it doesn't exist."""
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "changeme")

    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        # Check if admin already exists
        existing = session.query(User).filter(User.email == admin_email).first()
        if existing:
            print(f"Admin user already exists: {admin_email}")
            return

        # Create admin user
        admin = User(
            email=admin_email,
            hashed_password=get_password_hash(admin_password),
            full_name="Admin User",
            is_active=True,
            is_superuser=True,
        )
        session.add(admin)
        session.commit()

        print(f"Admin user created: {admin_email}")
        print(f"Password: {admin_password}")
        print("\n*** IMPORTANT: Change this password after first login! ***\n")

    except Exception as e:
        session.rollback()
        print(f"Error creating admin user: {e}")
        raise
    finally:
        session.close()


def main():
    """Main entry point."""
    print("=" * 60)
    print("Vaulytica Database Initialization")
    print("=" * 60)
    print()

    try:
        engine = init_database()
        create_admin_user(engine)

        print()
        print("=" * 60)
        print("Database initialization complete!")
        print("=" * 60)
        print()
        print("Next steps:")
        print("1. Start the backend: uvicorn backend.main:app --host 0.0.0.0 --port 8000")
        print("2. Start the frontend: cd frontend && npm run dev")
        print("3. Open http://localhost:3000 and login")
        print()

    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
