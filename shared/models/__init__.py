"""Shared models package for Vaulytica CLI and Web.

This package provides unified model definitions that can be imported by both
the CLI tool and the web backend to eliminate code duplication and ensure
consistency across the platform.

Usage in CLI:
    from shared.models import ScanRunMixin, UserRecordMixin, ScanStatus

Usage in Web:
    from shared.models import FileRecordMixin, FindingSeverity, map_cli_to_standard
"""

from shared.models.base import (
    SharedBase,
    SoftDeleteMixin,
    TimestampMixin,
    AuditMixin,
)
from shared.models.findings import (
    BaseFindingMixin,
    FileRecordMixin,
    UserRecordMixin,
    OAuthRecordMixin,
    ScanRunMixin,
    SecurityPostureMixin,
    AuditLogMixin,
    ComplianceReportMixin,
)
from shared.models.enums import (
    ScanStatus,
    FindingSeverity,
    FindingStatus,
    ScanType,
    ResourceType,
    RiskLevel,
    ComplianceFramework,
)
from shared.models.field_mappings import (
    CLI_TO_STANDARD,
    WEB_TO_STANDARD,
    STANDARD_TO_CLI,
    STANDARD_TO_WEB,
    map_cli_to_standard,
    map_web_to_standard,
    map_standard_to_cli,
    map_standard_to_web,
    USER_FINDING_FIELDS,
    FILE_FINDING_FIELDS,
    OAUTH_FINDING_FIELDS,
    SECURITY_FINDING_FIELDS,
)

__all__ = [
    # Base classes
    "SharedBase",
    "SoftDeleteMixin",
    "TimestampMixin",
    "AuditMixin",
    # Finding mixins
    "BaseFindingMixin",
    "FileRecordMixin",
    "UserRecordMixin",
    "OAuthRecordMixin",
    "ScanRunMixin",
    "SecurityPostureMixin",
    "AuditLogMixin",
    "ComplianceReportMixin",
    # Enums
    "ScanStatus",
    "FindingSeverity",
    "FindingStatus",
    "ScanType",
    "ResourceType",
    "RiskLevel",
    "ComplianceFramework",
    # Field mappings
    "CLI_TO_STANDARD",
    "WEB_TO_STANDARD",
    "STANDARD_TO_CLI",
    "STANDARD_TO_WEB",
    "map_cli_to_standard",
    "map_web_to_standard",
    "map_standard_to_cli",
    "map_standard_to_web",
    "USER_FINDING_FIELDS",
    "FILE_FINDING_FIELDS",
    "OAUTH_FINDING_FIELDS",
    "SECURITY_FINDING_FIELDS",
]
