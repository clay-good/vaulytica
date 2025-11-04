"""Tests for Vault scanner."""

import pytest
from unittest.mock import Mock
from vaulytica.core.scanners.vault_scanner import (
    VaultScanner,
    Matter,
    Hold,
    RetentionPolicy,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.vault = Mock()
    return client


@pytest.fixture
def vault_scanner(mock_client):
    """Create a VaultScanner instance."""
    return VaultScanner(mock_client, "example.com")


class TestVaultScanner:
    """Tests for VaultScanner class."""

    def test_init(self, vault_scanner):
        """Test scanner initialization."""
        assert vault_scanner.domain == "example.com"

    def test_scan_matters(self, vault_scanner):
        """Test scanning matters."""
        matters = vault_scanner._scan_matters()

        # Mock implementation returns empty list
        assert isinstance(matters, list)

    def test_scan_holds(self, vault_scanner):
        """Test scanning holds for a matter."""
        holds = vault_scanner._scan_holds("matter123")

        # Mock implementation returns empty list
        assert isinstance(holds, list)

    def test_scan_retention_policies(self, vault_scanner):
        """Test scanning retention policies."""
        policies = vault_scanner._scan_retention_policies()

        # Mock implementation returns empty list
        assert isinstance(policies, list)

    def test_generate_issues_matter_without_holds(self, vault_scanner):
        """Test issue generation for matter without holds."""
        from vaulytica.core.scanners.vault_scanner import VaultScanResult

        result = VaultScanResult()
        result.matters = [
            Matter(
                matter_id="matter1",
                name="Test Matter",
                state="OPEN",
                holds_count=0,
            )
        ]
        result.total_retention_policies = 1  # Set to avoid "no policies" issue

        issues = vault_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "matter_without_holds"
        assert issues[0]["severity"] == "medium"

    def test_generate_issues_hold_without_scope(self, vault_scanner):
        """Test issue generation for hold without scope."""
        from vaulytica.core.scanners.vault_scanner import VaultScanResult

        result = VaultScanResult()
        result.holds = [
            Hold(
                hold_id="hold1",
                matter_id="matter1",
                name="Test Hold",
                corpus="MAIL",
                accounts=[],
                org_unit="",
            )
        ]
        result.total_retention_policies = 1  # Set to avoid "no policies" issue

        issues = vault_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "hold_without_scope"
        assert issues[0]["severity"] == "high"

    def test_generate_issues_no_retention_policies(self, vault_scanner):
        """Test issue generation for missing retention policies."""
        from vaulytica.core.scanners.vault_scanner import VaultScanResult

        result = VaultScanResult()
        result.total_retention_policies = 0

        issues = vault_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "no_retention_policies"
        assert issues[0]["severity"] == "high"

    def test_generate_issues_multiple(self, vault_scanner):
        """Test issue generation with multiple issues."""
        from vaulytica.core.scanners.vault_scanner import VaultScanResult

        result = VaultScanResult()
        result.matters = [
            Matter(
                matter_id="matter1",
                name="Test Matter",
                state="OPEN",
                holds_count=0,
            )
        ]
        result.holds = [
            Hold(
                hold_id="hold1",
                matter_id="matter1",
                name="Test Hold",
                corpus="MAIL",
                accounts=[],
                org_unit="",
            )
        ]
        result.total_retention_policies = 0

        issues = vault_scanner._generate_issues(result)

        assert len(issues) == 3  # matter without holds + hold without scope + no policies

    def test_calculate_statistics(self, vault_scanner):
        """Test statistics calculation."""
        from vaulytica.core.scanners.vault_scanner import VaultScanResult

        result = VaultScanResult(
            total_matters=10,
            open_matters=5,
            closed_matters=5,
            total_holds=20,
            total_retention_policies=3,
        )
        result.issues = [{"type": "test"}] * 5

        stats = vault_scanner._calculate_statistics(result)

        assert stats["total_matters"] == 10
        assert stats["open_matters"] == 5
        assert stats["closed_matters"] == 5
        assert stats["total_holds"] == 20
        assert stats["total_retention_policies"] == 3
        assert stats["total_issues"] == 5

    def test_scan_all(self, vault_scanner):
        """Test scanning all Vault resources."""
        result = vault_scanner.scan_all()

        # Mock implementation returns empty results
        assert result.total_matters == 0
        assert result.total_holds == 0
        assert result.total_retention_policies == 0
        assert isinstance(result.statistics, dict)

    def test_get_matter_details(self, vault_scanner):
        """Test getting matter details."""
        matter = vault_scanner.get_matter_details("matter123")

        # Mock implementation returns None
        assert matter is None

    def test_get_hold_details(self, vault_scanner):
        """Test getting hold details."""
        hold = vault_scanner.get_hold_details("matter123", "hold456")

        # Mock implementation returns None
        assert hold is None

    def test_matter_dataclass(self):
        """Test Matter dataclass."""
        matter = Matter(
            matter_id="matter1",
            name="Test Matter",
            description="Test description",
            state="OPEN",
        )

        assert matter.matter_id == "matter1"
        assert matter.name == "Test Matter"
        assert matter.state == "OPEN"
        assert matter.holds_count == 0

    def test_hold_dataclass(self):
        """Test Hold dataclass."""
        hold = Hold(
            hold_id="hold1",
            matter_id="matter1",
            name="Test Hold",
            corpus="MAIL",
            accounts=["user@example.com"],
        )

        assert hold.hold_id == "hold1"
        assert hold.matter_id == "matter1"
        assert hold.corpus == "MAIL"
        assert len(hold.accounts) == 1

    def test_retention_policy_dataclass(self):
        """Test RetentionPolicy dataclass."""
        policy = RetentionPolicy(
            policy_id="policy1",
            name="Test Policy",
            corpus="DRIVE",
            retention_period_days=365,
        )

        assert policy.policy_id == "policy1"
        assert policy.name == "Test Policy"
        assert policy.corpus == "DRIVE"
        assert policy.retention_period_days == 365

