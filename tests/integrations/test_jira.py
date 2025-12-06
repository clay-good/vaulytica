"""Tests for Jira integration."""

import json
from datetime import datetime, timezone
from unittest.mock import Mock, patch, MagicMock

import pytest
import requests

from vaulytica.integrations.jira import (
    JiraClient,
    JiraConfig,
    JiraError,
    JiraCreateResult,
    JiraIssue,
    JiraSecurityReporter,
    JiraPriority,
    create_jira_client_from_config,
)


@pytest.fixture
def jira_config():
    """Sample Jira configuration."""
    return JiraConfig(
        url="https://test-org.atlassian.net",
        email="test@company.com",
        api_token="test-token",
        project_key="SEC",
        issue_type="Task",
        default_priority="Medium",
        default_labels=["vaulytica", "security"],
    )


@pytest.fixture
def jira_client(jira_config):
    """Jira client with test config."""
    return JiraClient(jira_config)


@pytest.fixture
def mock_response():
    """Create mock response."""
    def _mock_response(status_code=200, json_data=None, text=""):
        mock = Mock()
        mock.status_code = status_code
        mock.json.return_value = json_data or {}
        mock.text = text
        return mock
    return _mock_response


class TestJiraConfig:
    """Test JiraConfig dataclass."""

    def test_create_config_with_defaults(self):
        """Test creating config with default values."""
        config = JiraConfig(
            url="https://test.atlassian.net",
            email="user@test.com",
            api_token="token123",
            project_key="TEST",
        )

        assert config.url == "https://test.atlassian.net"
        assert config.email == "user@test.com"
        assert config.api_token == "token123"
        assert config.project_key == "TEST"
        assert config.issue_type == "Task"
        assert config.default_priority == "Medium"
        assert config.verify_ssl is True
        assert config.timeout == 30

    def test_create_config_with_custom_values(self):
        """Test creating config with custom values."""
        config = JiraConfig(
            url="https://custom.atlassian.net",
            email="admin@custom.com",
            api_token="custom-token",
            project_key="SEC",
            issue_type="Bug",
            default_priority="High",
            default_labels=["security", "urgent"],
            verify_ssl=False,
            timeout=60,
        )

        assert config.issue_type == "Bug"
        assert config.default_priority == "High"
        assert config.default_labels == ["security", "urgent"]
        assert config.verify_ssl is False
        assert config.timeout == 60


class TestJiraClient:
    """Test JiraClient class."""

    def test_client_initialization(self, jira_config):
        """Test client initializes correctly."""
        client = JiraClient(jira_config)

        assert client.base_url == "https://test-org.atlassian.net"
        assert client.api_url == "https://test-org.atlassian.net/rest/api/3"
        assert client.auth == ("test@company.com", "test-token")

    def test_client_strips_trailing_slash(self):
        """Test client strips trailing slash from URL."""
        config = JiraConfig(
            url="https://test.atlassian.net/",
            email="test@test.com",
            api_token="token",
            project_key="TEST",
        )
        client = JiraClient(config)

        assert client.base_url == "https://test.atlassian.net"

    @patch("requests.get")
    def test_test_connection_success(self, mock_get, jira_client, mock_response):
        """Test successful connection test."""
        mock_get.return_value = mock_response(
            status_code=200,
            json_data={"displayName": "Test User", "emailAddress": "test@company.com"},
        )

        result = jira_client.test_connection()

        assert result is True
        mock_get.assert_called_once()

    @patch("requests.get")
    def test_test_connection_failure(self, mock_get, jira_client, mock_response):
        """Test failed connection test."""
        mock_get.return_value = mock_response(
            status_code=401,
            text="Unauthorized",
        )

        with pytest.raises(JiraError):
            jira_client.test_connection()

    @patch("requests.get")
    def test_test_connection_network_error(self, mock_get, jira_client):
        """Test connection test with network error."""
        mock_get.side_effect = requests.exceptions.ConnectionError("Network error")

        with pytest.raises(JiraError):
            jira_client.test_connection()

    @patch("requests.post")
    def test_create_issue_success(self, mock_post, jira_client, mock_response):
        """Test successful issue creation."""
        mock_post.return_value = mock_response(
            status_code=201,
            json_data={"key": "SEC-123", "id": "10001"},
        )

        result = jira_client.create_issue(
            summary="Test Issue",
            description="Test description",
            priority="High",
        )

        assert result.success is True
        assert result.key == "SEC-123"
        assert result.id == "10001"
        assert result.url == "https://test-org.atlassian.net/browse/SEC-123"
        mock_post.assert_called_once()

    @patch("requests.post")
    def test_create_issue_failure(self, mock_post, jira_client, mock_response):
        """Test failed issue creation."""
        mock_post.return_value = mock_response(
            status_code=400,
            text="Invalid project key",
        )

        result = jira_client.create_issue(
            summary="Test Issue",
            description="Test description",
        )

        assert result.success is False
        assert result.error == "Invalid project key"

    @patch("requests.post")
    def test_create_issues_batch(self, mock_post, jira_client, mock_response):
        """Test batch issue creation."""
        mock_post.return_value = mock_response(
            status_code=201,
            json_data={"key": "SEC-123", "id": "10001"},
        )

        issues = [
            {"summary": "Issue 1", "description": "Desc 1"},
            {"summary": "Issue 2", "description": "Desc 2"},
        ]

        results = jira_client.create_issues_batch(issues, delay_between=0)

        assert len(results) == 2
        assert all(r.success for r in results)
        assert mock_post.call_count == 2

    @patch("requests.get")
    def test_get_issue_success(self, mock_get, jira_client, mock_response):
        """Test getting an issue."""
        mock_get.return_value = mock_response(
            status_code=200,
            json_data={
                "key": "SEC-123",
                "id": "10001",
                "fields": {
                    "summary": "Test Issue",
                    "description": None,
                    "status": {"name": "Open"},
                    "priority": {"name": "High"},
                    "issuetype": {"name": "Task"},
                    "created": "2024-01-01T00:00:00.000+0000",
                    "updated": "2024-01-02T00:00:00.000+0000",
                    "assignee": {"displayName": "Test User"},
                    "labels": ["vaulytica"],
                },
            },
        )

        issue = jira_client.get_issue("SEC-123")

        assert issue is not None
        assert issue.key == "SEC-123"
        assert issue.summary == "Test Issue"
        assert issue.status == "Open"
        assert issue.priority == "High"

    @patch("requests.get")
    def test_get_issue_not_found(self, mock_get, jira_client, mock_response):
        """Test getting non-existent issue."""
        mock_get.return_value = mock_response(status_code=404)

        issue = jira_client.get_issue("SEC-999")

        assert issue is None

    @patch("requests.post")
    def test_add_comment_success(self, mock_post, jira_client, mock_response):
        """Test adding comment to issue."""
        mock_post.return_value = mock_response(status_code=201)

        result = jira_client.add_comment("SEC-123", "Test comment")

        assert result is True
        mock_post.assert_called_once()

    @patch("requests.post")
    def test_add_comment_failure(self, mock_post, jira_client, mock_response):
        """Test failed comment addition."""
        mock_post.return_value = mock_response(status_code=404)

        result = jira_client.add_comment("SEC-999", "Test comment")

        assert result is False

    @patch("requests.get")
    @patch("requests.post")
    def test_transition_issue_success(self, mock_post, mock_get, jira_client, mock_response):
        """Test transitioning an issue."""
        mock_get.return_value = mock_response(
            status_code=200,
            json_data={
                "transitions": [
                    {"id": "31", "name": "Done"},
                    {"id": "21", "name": "In Progress"},
                ]
            },
        )
        mock_post.return_value = mock_response(status_code=204)

        result = jira_client.transition_issue("SEC-123", "Done")

        assert result is True

    @patch("requests.get")
    def test_transition_issue_not_found(self, mock_get, jira_client, mock_response):
        """Test transition with invalid transition name."""
        mock_get.return_value = mock_response(
            status_code=200,
            json_data={"transitions": [{"id": "31", "name": "Done"}]},
        )

        result = jira_client.transition_issue("SEC-123", "Invalid")

        assert result is False

    @patch("requests.get")
    def test_search_issues(self, mock_get, jira_client, mock_response):
        """Test searching for issues."""
        mock_get.return_value = mock_response(
            status_code=200,
            json_data={
                "issues": [
                    {
                        "key": "SEC-123",
                        "id": "10001",
                        "fields": {
                            "summary": "Test Issue 1",
                            "status": {"name": "Open"},
                            "priority": {"name": "High"},
                            "issuetype": {"name": "Task"},
                            "created": "2024-01-01T00:00:00.000+0000",
                            "updated": "2024-01-02T00:00:00.000+0000",
                            "labels": [],
                        },
                    },
                    {
                        "key": "SEC-124",
                        "id": "10002",
                        "fields": {
                            "summary": "Test Issue 2",
                            "status": {"name": "Done"},
                            "priority": {"name": "Low"},
                            "issuetype": {"name": "Task"},
                            "created": "2024-01-01T00:00:00.000+0000",
                            "updated": "2024-01-02T00:00:00.000+0000",
                            "labels": ["security"],
                        },
                    },
                ]
            },
        )

        issues = jira_client.search_issues("project = SEC")

        assert len(issues) == 2
        assert issues[0].key == "SEC-123"
        assert issues[1].key == "SEC-124"


class TestJiraSecurityReporter:
    """Test JiraSecurityReporter class."""

    @pytest.fixture
    def reporter(self, jira_client):
        """Create security reporter."""
        return JiraSecurityReporter(jira_client)

    @patch.object(JiraClient, "create_issues_batch")
    def test_create_issues_from_findings(self, mock_batch, reporter):
        """Test creating issues from security findings."""
        mock_batch.return_value = [
            JiraCreateResult(success=True, key="SEC-1"),
            JiraCreateResult(success=True, key="SEC-2"),
        ]

        findings = [
            {
                "type": "file",
                "name": "sensitive.xlsx",
                "severity": "high",
                "risk_score": 85,
                "description": "File with PII shared externally",
            },
            {
                "type": "oauth_app",
                "name": "Risky App",
                "severity": "critical",
                "risk_score": 95,
                "description": "Unauthorized app with admin access",
            },
        ]

        results = reporter.create_issues_from_findings(findings, scan_type="security")

        assert len(results) == 2
        assert all(r.success for r in results)
        mock_batch.assert_called_once()

    @patch.object(JiraClient, "create_issue")
    def test_create_weekly_report_issue(self, mock_create, reporter):
        """Test creating weekly report issue."""
        mock_create.return_value = JiraCreateResult(
            success=True,
            key="SEC-100",
            url="https://test.atlassian.net/browse/SEC-100",
        )

        summary_data = {
            "files": {"total": 1000, "high_risk": 10, "external_shares": 50},
            "users": {"total": 100, "without_2fa": 5, "inactive": 3},
            "oauth_apps": {"total": 25, "high_risk": 2},
        }

        result = reporter.create_weekly_report_issue(summary_data)

        assert result.success is True
        assert result.key == "SEC-100"
        mock_create.assert_called_once()

    def test_map_priority(self, reporter):
        """Test priority mapping."""
        assert reporter._map_priority("critical") == "Highest"
        assert reporter._map_priority("high") == "High"
        assert reporter._map_priority("medium") == "Medium"
        assert reporter._map_priority("low") == "Low"
        assert reporter._map_priority("unknown") == "Medium"

    def test_get_labels(self, reporter):
        """Test label generation."""
        finding = {
            "category": "data_exfiltration",
            "severity": "high",
        }

        labels = reporter._get_labels(finding, "security")

        assert "vaulytica" in labels
        assert "security" in labels
        assert "data_exfiltration" in labels or "data-exfiltration" in labels
        assert "severity-high" in labels


class TestJiraDescriptionFormatting:
    """Test ADF description formatting."""

    def test_format_simple_paragraph(self, jira_client):
        """Test formatting simple paragraph."""
        text = "This is a simple paragraph."
        result = jira_client._format_description(text)

        assert result["type"] == "doc"
        assert result["version"] == 1
        assert len(result["content"]) == 1
        assert result["content"][0]["type"] == "paragraph"

    def test_format_heading(self, jira_client):
        """Test formatting headings."""
        text = "# Heading 1"
        result = jira_client._format_description(text)

        assert result["content"][0]["type"] == "heading"
        assert result["content"][0]["attrs"]["level"] == 1

    def test_format_bullet_list(self, jira_client):
        """Test formatting bullet lists."""
        text = "- Item 1\n- Item 2\n- Item 3"
        result = jira_client._format_description(text)

        assert result["content"][0]["type"] == "bulletList"
        assert len(result["content"][0]["content"]) == 3

    def test_extract_description(self, jira_client):
        """Test extracting plain text from ADF."""
        adf = {
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": "Hello World"}],
                }
            ],
        }

        text = jira_client._extract_description(adf)
        assert text == "Hello World"


class TestCreateJiraClientFromConfig:
    """Test create_jira_client_from_config function."""

    def test_create_from_valid_config(self):
        """Test creating client from valid config."""
        config = {
            "integrations": {
                "jira": {
                    "enabled": True,
                    "url": "https://test.atlassian.net",
                    "email": "test@test.com",
                    "api_token": "token123",
                    "project_key": "SEC",
                }
            }
        }

        client = create_jira_client_from_config(config)

        assert client is not None
        assert client.base_url == "https://test.atlassian.net"

    def test_create_from_disabled_config(self):
        """Test creating client when disabled."""
        config = {
            "integrations": {
                "jira": {
                    "enabled": False,
                    "url": "https://test.atlassian.net",
                }
            }
        }

        client = create_jira_client_from_config(config)

        assert client is None

    def test_create_from_incomplete_config(self):
        """Test creating client from incomplete config."""
        config = {
            "integrations": {
                "jira": {
                    "enabled": True,
                    "url": "https://test.atlassian.net",
                    # Missing email, api_token, project_key
                }
            }
        }

        client = create_jira_client_from_config(config)

        assert client is None

    def test_create_from_empty_config(self):
        """Test creating client from empty config."""
        config = {}

        client = create_jira_client_from_config(config)

        assert client is None

    def test_create_with_custom_settings(self):
        """Test creating client with custom settings."""
        config = {
            "integrations": {
                "jira": {
                    "enabled": True,
                    "url": "https://test.atlassian.net",
                    "email": "test@test.com",
                    "api_token": "token123",
                    "project_key": "SEC",
                    "issue_type": "Bug",
                    "default_priority": "High",
                    "default_labels": ["custom", "labels"],
                    "priority_mapping": {
                        "critical": "Blocker",
                    },
                    "timeout": 60,
                }
            }
        }

        client = create_jira_client_from_config(config)

        assert client is not None
        assert client.config.issue_type == "Bug"
        assert client.config.default_priority == "High"
        assert client.config.default_labels == ["custom", "labels"]
        assert client.config.timeout == 60
