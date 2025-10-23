"""Data parsers for various security event sources."""

from .base import BaseParser
from .guardduty import GuardDutyParser
from .gcp_scc import GCPSecurityCommandCenterParser
from .datadog import DatadogParser
from .crowdstrike import CrowdStrikeParser
from .snowflake import SnowflakeParser

# Alias for backward compatibility
GCPSCCParser = GCPSecurityCommandCenterParser

__all__ = [
    "BaseParser",
    "GuardDutyParser",
    "GCPSecurityCommandCenterParser",
    "GCPSCCParser",
    "DatadogParser",
    "CrowdStrikeParser",
    "SnowflakeParser"
]
