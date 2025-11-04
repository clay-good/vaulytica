"""Tests for group scanner."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from vaulytica.core.scanners.group_scanner import (
    GroupScanner,
    GroupInfo,
    GroupMember,
    GroupScanResult,
)


@pytest.fixture
def mock_client():
    """Create a mock Google Workspace client."""
    client = Mock()
    client.admin = Mock()
    return client


@pytest.fixture
def group_scanner(mock_client):
    """Create a GroupScanner instance."""
    return GroupScanner(mock_client, "example.com")


class TestGroupScanner:
    """Tests for GroupScanner class."""

    def test_init(self, group_scanner):
        """Test scanner initialization."""
        assert group_scanner.domain == "example.com"
        assert group_scanner.client is not None

    def test_list_all_groups(self, group_scanner, mock_client):
        """Test listing all groups."""
        # Mock API response
        mock_client.admin.groups().list().execute.return_value = {
            "groups": [
                {
                    "id": "group1",
                    "email": "team@example.com",
                    "name": "Team Group",
                    "directMembersCount": 5,
                },
                {
                    "id": "group2",
                    "email": "all@example.com",
                    "name": "All Staff",
                    "directMembersCount": 100,
                },
            ]
        }

        groups = group_scanner._list_all_groups()

        assert len(groups) == 2
        assert groups[0]["email"] == "team@example.com"
        assert groups[1]["email"] == "all@example.com"

    def test_detect_external_members(self, group_scanner):
        """Test detecting external members."""
        members = [
            GroupMember(email="user1@example.com", role="MEMBER", type="USER"),
            GroupMember(email="external@other.com", role="MEMBER", type="USER"),
            GroupMember(email="user2@example.com", role="OWNER", type="USER"),
            GroupMember(email="contractor@vendor.com", role="MEMBER", type="USER"),
        ]

        external = group_scanner._detect_external_members(members)

        assert len(external) == 2
        assert external[0].email == "external@other.com"
        assert external[1].email == "contractor@vendor.com"

    def test_calculate_group_risk_score_external_members(self, group_scanner):
        """Test risk score calculation with external members."""
        group = GroupInfo(
            id="group1",
            email="team@example.com",
            name="Team",
            external_members=[
                GroupMember(email="ext1@other.com", role="MEMBER", type="USER"),
                GroupMember(email="ext2@other.com", role="MEMBER", type="USER"),
            ],
        )

        score = group_scanner._calculate_group_risk_score(group)

        assert score > 0
        assert score <= 100

    def test_calculate_group_risk_score_public_group(self, group_scanner):
        """Test risk score calculation for public group."""
        group = GroupInfo(
            id="group1",
            email="public@example.com",
            name="Public Group",
            is_public=True,
        )

        score = group_scanner._calculate_group_risk_score(group)

        assert score >= 40  # Public groups get 40 points

    def test_calculate_group_risk_score_orphaned(self, group_scanner):
        """Test risk score calculation for orphaned group."""
        group = GroupInfo(
            id="group1",
            email="orphaned@example.com",
            name="Orphaned Group",
            is_orphaned=True,
        )

        score = group_scanner._calculate_group_risk_score(group)

        assert score >= 20  # Orphaned groups get 20 points

    def test_calculate_group_risk_score_combined(self, group_scanner):
        """Test risk score calculation with multiple issues."""
        group = GroupInfo(
            id="group1",
            email="risky@example.com",
            name="Risky Group",
            external_members=[
                GroupMember(email="ext@other.com", role="MEMBER", type="USER")
            ],
            is_public=True,
            is_orphaned=True,
            nested_groups=["subgroup@example.com"],
        )

        score = group_scanner._calculate_group_risk_score(group)

        assert score >= 60  # Should have high risk score
        assert score <= 100

    def test_generate_issues_external_members(self, group_scanner):
        """Test issue generation for external members."""
        groups = [
            GroupInfo(
                id="group1",
                email="team@example.com",
                name="Team",
                external_members=[
                    GroupMember(email="ext@other.com", role="MEMBER", type="USER")
                ],
                risk_score=30,
            )
        ]

        issues = group_scanner._generate_issues(groups)

        assert len(issues) == 1
        assert issues[0]["type"] == "external_members"
        assert issues[0]["group"] == "team@example.com"
        assert "ext@other.com" in issues[0]["external_members"]

    def test_generate_issues_public_group(self, group_scanner):
        """Test issue generation for public groups."""
        groups = [
            GroupInfo(
                id="group1",
                email="public@example.com",
                name="Public",
                is_public=True,
                risk_score=40,
            )
        ]

        issues = group_scanner._generate_issues(groups)

        assert len(issues) == 1
        assert issues[0]["type"] == "public_group"
        assert issues[0]["severity"] == "critical"

    def test_generate_issues_orphaned_group(self, group_scanner):
        """Test issue generation for orphaned groups."""
        groups = [
            GroupInfo(
                id="group1",
                email="orphaned@example.com",
                name="Orphaned",
                is_orphaned=True,
                risk_score=20,
            )
        ]

        issues = group_scanner._generate_issues(groups)

        assert len(issues) == 1
        assert issues[0]["type"] == "orphaned_group"
        assert issues[0]["severity"] == "high"

    def test_generate_issues_multiple(self, group_scanner):
        """Test issue generation with multiple issues."""
        groups = [
            GroupInfo(
                id="group1",
                email="risky@example.com",
                name="Risky",
                external_members=[
                    GroupMember(email="ext@other.com", role="MEMBER", type="USER")
                ],
                is_public=True,
                is_orphaned=True,
                risk_score=75,
            )
        ]

        issues = group_scanner._generate_issues(groups)

        assert len(issues) == 3  # external_members, public_group, orphaned_group
        issue_types = [i["type"] for i in issues]
        assert "external_members" in issue_types
        assert "public_group" in issue_types
        assert "orphaned_group" in issue_types

    def test_calculate_statistics(self, group_scanner):
        """Test statistics calculation."""
        result = GroupScanResult(
            total_groups=10,
            groups_with_external_members=3,
            public_groups=1,
            orphaned_groups=2,
            issues=[
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "high"},
                {"severity": "medium"},
            ],
        )

        stats = group_scanner._calculate_statistics(result)

        assert stats["total_groups"] == 10
        assert stats["groups_with_external_members"] == 3
        assert stats["public_groups"] == 1
        assert stats["orphaned_groups"] == 2
        assert stats["total_issues"] == 4
        assert stats["critical_issues"] == 1
        assert stats["high_issues"] == 2
        assert stats["medium_issues"] == 1

    def test_get_group_members(self, group_scanner, mock_client):
        """Test getting group members."""
        # Mock API response
        mock_client.admin.members().list().execute.return_value = {
            "members": [
                {
                    "email": "user1@example.com",
                    "role": "OWNER",
                    "type": "USER",
                    "status": "ACTIVE",
                },
                {
                    "email": "user2@example.com",
                    "role": "MEMBER",
                    "type": "USER",
                    "status": "ACTIVE",
                },
            ]
        }

        members = group_scanner._get_group_members("group1")

        assert len(members) == 2
        assert members[0].email == "user1@example.com"
        assert members[0].role == "OWNER"
        assert members[1].email == "user2@example.com"
        assert members[1].role == "MEMBER"

    def test_is_group_public(self, group_scanner):
        """Test public group detection."""
        # Test public group
        settings = {"whoCanJoin": "ANYONE_CAN_JOIN"}
        assert group_scanner._is_group_public(settings) is True

        # Test domain-wide group
        settings = {"whoCanJoin": "ALL_IN_DOMAIN_CAN_JOIN"}
        assert group_scanner._is_group_public(settings) is True

        # Test private group
        settings = {"whoCanJoin": "INVITED_CAN_JOIN"}
        assert group_scanner._is_group_public(settings) is False

        # Test empty settings
        settings = {}
        assert group_scanner._is_group_public(settings) is False

