"""Base classes and mixins for Vaulytica models.

These mixins provide consistent field definitions that can be used by both
the CLI and web database models.
"""

from datetime import datetime
from typing import Optional, Dict, Any

from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer
from sqlalchemy.orm import declared_attr


class TimestampMixin:
    """Mixin that adds created_at and updated_at timestamp fields."""

    @declared_attr
    def created_at(cls) -> Column:
        return Column(DateTime, default=datetime.utcnow, nullable=False)

    @declared_attr
    def updated_at(cls) -> Column:
        return Column(
            DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
        )


class SoftDeleteMixin:
    """Mixin that adds soft delete support with audit trail.

    Instead of hard deleting records, this marks them as deleted while
    preserving the data for compliance and audit purposes.
    """

    @declared_attr
    def is_deleted(cls) -> Column:
        return Column(Boolean, default=False, nullable=False, index=True)

    @declared_attr
    def deleted_at(cls) -> Column:
        return Column(DateTime, nullable=True)

    @declared_attr
    def deleted_by(cls) -> Column:
        return Column(String(255), nullable=True)

    @declared_attr
    def deletion_reason(cls) -> Column:
        return Column(String(500), nullable=True)


class AuditMixin:
    """Mixin for audit-related fields on entities that track changes.

    Used for tracking who made changes and when.
    """

    @declared_attr
    def status_changed_at(cls) -> Column:
        return Column(DateTime, nullable=True)

    @declared_attr
    def status_changed_by(cls) -> Column:
        return Column(String(255), nullable=True)


class SharedBase:
    """Base class with common utility methods for all Vaulytica models."""

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary, handling datetime serialization."""
        result = {}
        for column in self.__table__.columns:  # type: ignore
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                value = value.isoformat()
            result[column.name] = value
        return result

    @classmethod
    def get_field_names(cls) -> list:
        """Get list of column names for this model."""
        return [column.name for column in cls.__table__.columns]  # type: ignore
