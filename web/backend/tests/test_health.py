"""Tests for health and root endpoints."""

import pytest
from fastapi.testclient import TestClient


class TestHealthEndpoints:
    """Test health and info endpoints."""

    def test_root_endpoint(self, client: TestClient):
        """Test root endpoint returns API info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert "docs" in data

    def test_health_endpoint(self, client: TestClient):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "version" in data

    def test_api_info_endpoint(self, client: TestClient):
        """Test API info endpoint."""
        response = client.get("/api")
        assert response.status_code == 200
        data = response.json()
        assert "endpoints" in data
        assert "api_version" in data
        assert data["api_version"] == "v1"
        # Check v1 endpoints
        assert "v1" in data["endpoints"]
        assert "auth" in data["endpoints"]["v1"]
        assert "scans" in data["endpoints"]["v1"]
        assert "findings" in data["endpoints"]["v1"]
        assert "dashboards" in data["endpoints"]["v1"]
        # Check legacy endpoints
        assert "legacy" in data["endpoints"]
        assert "auth" in data["endpoints"]["legacy"]

    def test_docs_endpoint(self, client: TestClient):
        """Test OpenAPI docs are accessible."""
        response = client.get("/docs")
        assert response.status_code == 200

    def test_openapi_json(self, client: TestClient):
        """Test OpenAPI JSON schema is accessible."""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
        assert "paths" in data
