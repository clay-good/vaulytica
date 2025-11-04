"""Tests for Gmail security scanner."""

import pytest
from unittest.mock import Mock, MagicMock
from vaulytica.core.scanners.gmail_security_scanner import (
    GmailSecurityScanner,
    DelegateInfo,
    ForwardingRule,
    SendAsAlias,
    GmailFilter,
    GmailSecurityScanResult,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.admin = Mock()
    client.gmail = Mock()
    return client


@pytest.fixture
def gmail_security_scanner(mock_client):
    """Create a GmailSecurityScanner instance."""
    return GmailSecurityScanner(mock_client, "example.com")


class TestGmailSecurityScanner:
    """Tests for GmailSecurityScanner class."""

    def test_init(self, gmail_security_scanner):
        """Test scanner initialization."""
        assert gmail_security_scanner.domain == "example.com"
        assert gmail_security_scanner.client is not None

    def test_list_all_users(self, gmail_security_scanner, mock_client):
        """Test listing all users."""
        # Mock API response
        mock_client.admin.users().list().execute.return_value = {
            "users": [
                {"primaryEmail": "user1@example.com"},
                {"primaryEmail": "user2@example.com"},
            ]
        }

        users = gmail_security_scanner._list_all_users()

        assert len(users) == 2
        assert users[0]["primaryEmail"] == "user1@example.com"
        assert users[1]["primaryEmail"] == "user2@example.com"

    def test_scan_delegates(self, gmail_security_scanner, mock_client):
        """Test scanning for delegates."""
        # Mock API response
        mock_client.gmail.users().settings().delegates().list().execute.return_value = {
            "delegates": [
                {
                    "delegateEmail": "assistant@example.com",
                    "verificationStatus": "accepted",
                }
            ]
        }

        delegates = gmail_security_scanner._scan_delegates("user@example.com")

        assert len(delegates) == 1
        assert delegates[0].delegate_email == "assistant@example.com"
        assert delegates[0].user_email == "user@example.com"
        assert delegates[0].verification_status == "accepted"

    def test_scan_delegates_empty(self, gmail_security_scanner, mock_client):
        """Test scanning for delegates when none exist."""
        # Mock API response
        mock_client.gmail.users().settings().delegates().list().execute.return_value = {
            "delegates": []
        }

        delegates = gmail_security_scanner._scan_delegates("user@example.com")

        assert len(delegates) == 0

    def test_scan_forwarding(self, gmail_security_scanner, mock_client):
        """Test scanning for forwarding rules."""
        # Mock API response
        mock_client.gmail.users().settings().forwardingAddresses().list().execute.return_value = {
            "forwardingAddresses": [
                {
                    "forwardingEmail": "external@other.com",
                    "verificationStatus": "accepted",
                }
            ]
        }

        forwarding = gmail_security_scanner._scan_forwarding("user@example.com")

        assert len(forwarding) == 1
        assert forwarding[0].forward_to == "external@other.com"
        assert forwarding[0].user_email == "user@example.com"
        assert forwarding[0].enabled is True

    def test_scan_forwarding_unverified(self, gmail_security_scanner, mock_client):
        """Test that unverified forwarding addresses are not included."""
        # Mock API response
        mock_client.gmail.users().settings().forwardingAddresses().list().execute.return_value = {
            "forwardingAddresses": [
                {
                    "forwardingEmail": "external@other.com",
                    "verificationStatus": "pending",
                }
            ]
        }

        forwarding = gmail_security_scanner._scan_forwarding("user@example.com")

        assert len(forwarding) == 0

    def test_scan_send_as(self, gmail_security_scanner, mock_client):
        """Test scanning for send-as aliases."""
        # Mock API response
        mock_client.gmail.users().settings().sendAs().list().execute.return_value = {
            "sendAs": [
                {
                    "sendAsEmail": "user@example.com",  # Primary email (should be skipped)
                    "displayName": "User Name",
                    "isPrimary": True,
                },
                {
                    "sendAsEmail": "alias@example.com",
                    "displayName": "Alias Name",
                    "isDefault": False,
                    "verificationStatus": "accepted",
                },
            ]
        }

        send_as = gmail_security_scanner._scan_send_as("user@example.com")

        assert len(send_as) == 1  # Primary email should be excluded
        assert send_as[0].send_as_email == "alias@example.com"
        assert send_as[0].user_email == "user@example.com"
        assert send_as[0].display_name == "Alias Name"

    def test_scan_risky_filters_trash(self, gmail_security_scanner, mock_client):
        """Test scanning for risky filters (auto-delete)."""
        # Mock API response
        mock_client.gmail.users().settings().filters().list().execute.return_value = {
            "filter": [
                {
                    "id": "filter1",
                    "criteria": {"from": "spam@example.com"},
                    "action": {"trash": True},
                }
            ]
        }

        risky_filters = gmail_security_scanner._scan_risky_filters("user@example.com")

        assert len(risky_filters) == 1
        assert risky_filters[0].filter_id == "filter1"
        assert risky_filters[0].action["trash"] is True

    def test_scan_risky_filters_forward(self, gmail_security_scanner, mock_client):
        """Test scanning for risky filters (auto-forward)."""
        # Mock API response
        mock_client.gmail.users().settings().filters().list().execute.return_value = {
            "filter": [
                {
                    "id": "filter2",
                    "criteria": {"subject": "confidential"},
                    "action": {"forward": "external@other.com"},
                }
            ]
        }

        risky_filters = gmail_security_scanner._scan_risky_filters("user@example.com")

        assert len(risky_filters) == 1
        assert risky_filters[0].filter_id == "filter2"
        assert risky_filters[0].action["forward"] == "external@other.com"

    def test_scan_risky_filters_safe(self, gmail_security_scanner, mock_client):
        """Test that safe filters are not flagged."""
        # Mock API response
        mock_client.gmail.users().settings().filters().list().execute.return_value = {
            "filter": [
                {
                    "id": "filter3",
                    "criteria": {"from": "newsletter@example.com"},
                    "action": {"addLabelIds": ["Label_1"]},  # Safe action
                }
            ]
        }

        risky_filters = gmail_security_scanner._scan_risky_filters("user@example.com")

        assert len(risky_filters) == 0

    def test_generate_issues_external_delegate(self, gmail_security_scanner):
        """Test issue generation for external delegate."""
        result = GmailSecurityScanResult(
            delegates=[
                DelegateInfo(
                    delegate_email="external@other.com",
                    user_email="user@example.com",
                )
            ]
        )

        issues = gmail_security_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "gmail_delegate"
        assert issues[0]["severity"] == "high"
        assert issues[0]["is_external"] is True

    def test_generate_issues_internal_delegate(self, gmail_security_scanner):
        """Test issue generation for internal delegate."""
        result = GmailSecurityScanResult(
            delegates=[
                DelegateInfo(
                    delegate_email="assistant@example.com",
                    user_email="user@example.com",
                )
            ]
        )

        issues = gmail_security_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "gmail_delegate"
        assert issues[0]["severity"] == "medium"
        assert issues[0]["is_external"] is False

    def test_generate_issues_external_forwarding(self, gmail_security_scanner):
        """Test issue generation for external forwarding."""
        result = GmailSecurityScanResult(
            forwarding_rules=[
                ForwardingRule(
                    user_email="user@example.com",
                    forward_to="external@other.com",
                )
            ]
        )

        issues = gmail_security_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "gmail_forwarding"
        assert issues[0]["severity"] == "critical"
        assert issues[0]["is_external"] is True

    def test_generate_issues_internal_forwarding(self, gmail_security_scanner):
        """Test issue generation for internal forwarding."""
        result = GmailSecurityScanResult(
            forwarding_rules=[
                ForwardingRule(
                    user_email="user@example.com",
                    forward_to="backup@example.com",
                )
            ]
        )

        issues = gmail_security_scanner._generate_issues(result)

        assert len(issues) == 1
        assert issues[0]["type"] == "gmail_forwarding"
        assert issues[0]["severity"] == "high"
        assert issues[0]["is_external"] is False

    def test_calculate_statistics(self, gmail_security_scanner):
        """Test statistics calculation."""
        result = GmailSecurityScanResult(
            total_users_scanned=100,
            users_with_delegates=5,
            users_with_forwarding=2,
            users_with_send_as=10,
            users_with_risky_filters=3,
            delegates=[
                DelegateInfo("delegate1@example.com", "user1@example.com"),
                DelegateInfo("delegate2@example.com", "user2@example.com"),
            ],
            forwarding_rules=[
                ForwardingRule("user3@example.com", "external@other.com"),
            ],
            send_as_aliases=[
                SendAsAlias("user4@example.com", "alias@example.com"),
            ],
            risky_filters=[
                GmailFilter("user5@example.com", "filter1"),
            ],
            issues=[{"type": "test"}],
        )

        stats = gmail_security_scanner._calculate_statistics(result)

        assert stats["total_users_scanned"] == 100
        assert stats["users_with_delegates"] == 5
        assert stats["users_with_forwarding"] == 2
        assert stats["users_with_send_as"] == 10
        assert stats["users_with_risky_filters"] == 3
        assert stats["total_delegates"] == 2
        assert stats["total_forwarding_rules"] == 1
        assert stats["total_send_as_aliases"] == 1
        assert stats["total_risky_filters"] == 1
        assert stats["total_issues"] == 1

