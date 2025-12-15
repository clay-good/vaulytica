"""
Vaulytica API Client SDK

A Python client library for interacting with the Vaulytica API.

Example usage:
    from vaulytica_client import VaulyticaClient

    client = VaulyticaClient(base_url="https://vaulytica.example.com")
    client.login("admin@example.com", "password")

    # List scans
    scans = client.scans.list()

    # Trigger a new scan
    scan = client.scans.trigger(domain_id=1, scan_type="files")

    # Get findings
    findings = client.findings.list_security()

    # Export to CSV
    csv_data = client.findings.export_security(format="csv")
"""

from .client import VaulyticaClient
from .exceptions import (
    VaulyticaError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)

__version__ = "1.0.0"
__all__ = [
    "VaulyticaClient",
    "VaulyticaError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "RateLimitError",
    "ValidationError",
]
