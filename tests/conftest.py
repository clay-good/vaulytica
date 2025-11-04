"""Pytest configuration and fixtures for Vaulytica tests."""

import pytest
from pathlib import Path
from typing import Dict, Any


@pytest.fixture
def sample_config() -> Dict[str, Any]:
    """Provide a sample configuration for testing."""
    return {
        "google_workspace": {
            "domain": "example.com",
            "credentials_file": "test-credentials.json",
            "impersonate_user": "admin@example.com",
        },
        "scanning": {
            "scan_my_drive": True,
            "scan_shared_drives": True,
            "check_pii": True,
            "pii_patterns": ["ssn", "credit_card", "phone"],
        },
        "alerts": {
            "email": {
                "enabled": False,
            }
        },
        "reporting": {
            "output_dir": "./test-reports",
            "formats": ["csv", "json"],
        },
        "storage": {
            "database_path": ":memory:",
        },
    }


@pytest.fixture
def temp_config_file(tmp_path: Path, sample_config: Dict[str, Any]) -> Path:
    """Create a temporary config file for testing."""
    import yaml
    
    config_file = tmp_path / "config.yaml"
    with open(config_file, "w") as f:
        yaml.dump(sample_config, f)
    
    return config_file


@pytest.fixture
def mock_drive_file() -> Dict[str, Any]:
    """Provide a mock Google Drive file response."""
    return {
        "id": "file123",
        "name": "Test Document.docx",
        "mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "owners": [{"emailAddress": "owner@example.com", "displayName": "Test Owner"}],
        "createdTime": "2024-01-01T00:00:00.000Z",
        "modifiedTime": "2024-01-15T00:00:00.000Z",
        "size": "12345",
        "permissions": [
            {
                "id": "perm1",
                "type": "user",
                "role": "owner",
                "emailAddress": "owner@example.com",
            },
            {
                "id": "perm2",
                "type": "user",
                "role": "reader",
                "emailAddress": "external@otherdomain.com",
            },
        ],
    }


@pytest.fixture
def mock_public_file() -> Dict[str, Any]:
    """Provide a mock publicly shared Google Drive file."""
    return {
        "id": "file456",
        "name": "Public Spreadsheet.xlsx",
        "mimeType": "application/vnd.google-apps.spreadsheet",
        "owners": [{"emailAddress": "owner@example.com", "displayName": "Test Owner"}],
        "createdTime": "2024-01-01T00:00:00.000Z",
        "modifiedTime": "2024-01-15T00:00:00.000Z",
        "permissions": [
            {
                "id": "perm1",
                "type": "user",
                "role": "owner",
                "emailAddress": "owner@example.com",
            },
            {
                "id": "perm2",
                "type": "anyone",
                "role": "reader",
            },
        ],
    }

