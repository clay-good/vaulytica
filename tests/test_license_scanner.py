"""Tests for license scanner."""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from vaulytica.core.scanners.license_scanner import (
    LicenseScanner,
    LicenseAssignment,
    LicenseSKU,
    LicenseScanResult,
)


class TestLicenseAssignment:
    """Tests for LicenseAssignment dataclass."""

    def test_license_assignment_creation(self):
        """Test creating a license assignment."""
        assignment = LicenseAssignment(
            user_email="user@example.com",
            sku_id="1010020020",
            sku_name="Business Starter",
            product_id="Google-Apps",
            product_name="Google Workspace",
            assigned_date=datetime.now(timezone.utc),
            last_used=datetime.now(timezone.utc) - timedelta(days=5),
            is_active=True,
            usage_days=25,
        )

        assert assignment.user_email == "user@example.com"
        assert assignment.sku_id == "1010020020"
        assert assignment.sku_name == "Business Starter"
        assert assignment.is_active is True
        assert assignment.usage_days == 25


class TestLicenseSKU:
    """Tests for LicenseSKU dataclass."""

    def test_license_sku_creation(self):
        """Test creating a license SKU."""
        sku = LicenseSKU(
            sku_id="1010020020",
            sku_name="Business Starter",
            product_id="Google-Apps",
            product_name="Google Workspace",
            total_licenses=100,
            assigned_licenses=80,
            available_licenses=20,
            cost_per_license=6.00,
            billing_cycle="monthly",
        )

        assert sku.sku_id == "1010020020"
        assert sku.total_licenses == 100
        assert sku.assigned_licenses == 80
        assert sku.available_licenses == 20
        assert sku.cost_per_license == 6.00


class TestLicenseScanner:
    """Tests for LicenseScanner."""

    @pytest.fixture
    def mock_client(self):
        """Create a mock Google Workspace client."""
        client = Mock()
        return client

    @pytest.fixture
    def license_scanner(self, mock_client):
        """Create a license scanner instance."""
        return LicenseScanner(client=mock_client, inactive_days=30)

    def test_scanner_initialization(self, license_scanner, mock_client):
        """Test scanner initialization."""
        assert license_scanner.client == mock_client
        assert license_scanner.inactive_days == 30

    def test_identify_unused_licenses(self, license_scanner):
        """Test identifying unused licenses."""
        assignments = [
            LicenseAssignment(
                user_email="active@example.com",
                sku_id="1010020020",
                sku_name="Business Starter",
                product_id="Google-Apps",
                product_name="Google Workspace",
                is_active=True,
                usage_days=60,
            ),
            LicenseAssignment(
                user_email="inactive@example.com",
                sku_id="1010020020",
                sku_name="Business Starter",
                product_id="Google-Apps",
                product_name="Google Workspace",
                is_active=False,
                usage_days=0,
            ),
            LicenseAssignment(
                user_email="underutilized@example.com",
                sku_id="1010020020",
                sku_name="Business Starter",
                product_id="Google-Apps",
                product_name="Google Workspace",
                is_active=True,
                usage_days=15,
            ),
        ]

        unused, underutilized = license_scanner._identify_unused_licenses(assignments)

        assert len(unused) == 1
        assert unused[0].user_email == "inactive@example.com"
        assert len(underutilized) == 1
        assert underutilized[0].user_email == "underutilized@example.com"

    def test_calculate_total_cost(self, license_scanner):
        """Test calculating total cost."""
        skus = [
            LicenseSKU(
                sku_id="1010020020",
                sku_name="Business Starter",
                product_id="Google-Apps",
                product_name="Google Workspace",
                total_licenses=100,
                assigned_licenses=80,
                available_licenses=20,
                cost_per_license=6.00,
            ),
            LicenseSKU(
                sku_id="1010020025",
                sku_name="Business Standard",
                product_id="Google-Apps",
                product_name="Google Workspace",
                total_licenses=50,
                assigned_licenses=40,
                available_licenses=10,
                cost_per_license=12.00,
            ),
        ]

        total_cost = license_scanner._calculate_total_cost(skus)

        # 80 * 6.00 + 40 * 12.00 = 480 + 480 = 960
        assert total_cost == 960.00

    def test_calculate_potential_savings(self, license_scanner):
        """Test calculating potential savings."""
        unused = [
            LicenseAssignment(
                user_email="unused1@example.com",
                sku_id="1010020020",
                sku_name="Business Starter",
                product_id="Google-Apps",
                product_name="Google Workspace",
                is_active=False,
            ),
            LicenseAssignment(
                user_email="unused2@example.com",
                sku_id="1010020020",
                sku_name="Business Starter",
                product_id="Google-Apps",
                product_name="Google Workspace",
                is_active=False,
            ),
        ]

        underutilized = [
            LicenseAssignment(
                user_email="underutilized@example.com",
                sku_id="1010020025",
                sku_name="Business Standard",
                product_id="Google-Apps",
                product_name="Google Workspace",
                is_active=True,
                usage_days=15,
            ),
        ]

        savings = license_scanner._calculate_potential_savings(unused, underutilized)

        # 2 * 6.00 (unused) + 1 * 12.00 * 0.5 (underutilized) = 12 + 6 = 18
        assert savings == 18.00

    def test_generate_recommendations(self, license_scanner):
        """Test generating recommendations."""
        result = LicenseScanResult(
            total_licenses=100,
            assigned_licenses=80,
            available_licenses=20,
            unused_licenses_count=10,
            underutilized_licenses_count=5,
            total_monthly_cost=1200.00,
            potential_savings=100.00,
            skus=[Mock(), Mock(), Mock(), Mock()],  # 4 SKUs
        )

        recommendations = license_scanner._generate_recommendations(result)

        # Should have recommendations for: unused, underutilized, consolidation, cost optimization
        assert len(recommendations) >= 3
        assert any(rec["type"] == "unused_licenses" for rec in recommendations)
        assert any(rec["type"] == "underutilized_licenses" for rec in recommendations)
        assert any(rec["type"] == "consolidation" for rec in recommendations)
        assert any(rec["type"] == "cost_optimization" for rec in recommendations)

    def test_generate_issues(self, license_scanner):
        """Test generating issues."""
        result = LicenseScanResult(
            total_licenses=100,
            assigned_licenses=50,
            available_licenses=50,
            unused_licenses_count=15,
            underutilized_licenses_count=5,
            total_monthly_cost=600.00,
            potential_savings=150.00,
        )

        issues = license_scanner._generate_issues(result)

        # Should have issues for: excessive unused licenses, over-provisioned
        assert len(issues) >= 1
        assert any(issue["type"] == "excessive_unused_licenses" for issue in issues)
        assert any(issue["type"] == "over_provisioned" for issue in issues)

    @patch("vaulytica.core.scanners.license_scanner.LicenseScanner._list_all_skus")
    @patch("vaulytica.core.scanners.license_scanner.LicenseScanner._list_all_assignments")
    def test_scan_all_licenses(self, mock_list_assignments, mock_list_skus, license_scanner):
        """Test scanning all licenses."""
        # Mock SKUs
        mock_skus = [
            LicenseSKU(
                sku_id="1010020020",
                sku_name="Business Starter",
                product_id="Google-Apps",
                product_name="Google Workspace",
                total_licenses=100,
                assigned_licenses=80,
                available_licenses=20,
                cost_per_license=6.00,
            ),
        ]
        mock_list_skus.return_value = mock_skus

        # Mock assignments
        mock_assignments = [
            LicenseAssignment(
                user_email="active@example.com",
                sku_id="1010020020",
                sku_name="Business Starter",
                product_id="Google-Apps",
                product_name="Google Workspace",
                is_active=True,
                usage_days=60,
            ),
            LicenseAssignment(
                user_email="inactive@example.com",
                sku_id="1010020020",
                sku_name="Business Starter",
                product_id="Google-Apps",
                product_name="Google Workspace",
                is_active=False,
                usage_days=0,
            ),
        ]
        mock_list_assignments.return_value = mock_assignments

        result = license_scanner.scan_all_licenses()

        assert result.total_licenses == 100
        assert result.assigned_licenses == 80
        assert result.available_licenses == 20
        assert result.unused_licenses_count == 1
        assert result.total_monthly_cost == 480.00  # 80 * 6.00
        assert len(result.skus) == 1
        assert len(result.assignments) == 2
        assert len(result.unused_licenses) == 1
        assert len(result.recommendations) > 0

