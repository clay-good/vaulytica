"""Database integration module for saving CLI scan results to PostgreSQL.

This module provides the bridge between CLI scan results and the web dashboard's
PostgreSQL database, enabling users to view CLI scan results in the web UI.

Usage:
    # Install with database support
    pip install vaulytica[database]

    # Or: poetry install --extras database

    # Then run scans with database saving
    vaulytica --save-to-db --db-url postgresql://user:pass@host:5432/vaulytica scan files
"""

try:
    from vaulytica.core.database.saver import DatabaseSaver
    __all__ = ["DatabaseSaver"]
except ImportError:
    # SQLAlchemy not installed - database features not available
    DatabaseSaver = None  # type: ignore
    __all__ = []
