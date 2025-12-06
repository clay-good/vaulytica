"""Jira integration for creating and managing security issues."""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum

import requests
import structlog

logger = structlog.get_logger(__name__)


class JiraPriority(Enum):
    """Jira priority levels."""

    HIGHEST = "Highest"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    LOWEST = "Lowest"


class JiraIssueType(Enum):
    """Common Jira issue types."""

    TASK = "Task"
    BUG = "Bug"
    STORY = "Story"
    EPIC = "Epic"
    SUBTASK = "Sub-task"


@dataclass
class JiraConfig:
    """Jira connection configuration."""

    url: str  # e.g., "https://your-org.atlassian.net"
    email: str  # API user email
    api_token: str  # API token (not password)
    project_key: str  # e.g., "SEC"
    issue_type: str = "Task"
    default_priority: str = "Medium"
    default_labels: List[str] = field(default_factory=lambda: ["vaulytica", "security"])
    default_assignee: Optional[str] = None
    priority_mapping: Dict[str, str] = field(default_factory=lambda: {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    })
    verify_ssl: bool = True
    timeout: int = 30


@dataclass
class JiraIssue:
    """Represents a Jira issue."""

    key: str  # e.g., "SEC-123"
    id: str
    summary: str
    description: str
    status: str
    priority: str
    issue_type: str
    created: datetime
    updated: datetime
    assignee: Optional[str] = None
    labels: List[str] = field(default_factory=list)
    url: str = ""


@dataclass
class JiraCreateResult:
    """Result of creating a Jira issue."""

    success: bool
    key: Optional[str] = None
    id: Optional[str] = None
    url: Optional[str] = None
    error: Optional[str] = None


class JiraError(Exception):
    """Raised when Jira operations fail."""

    pass


class JiraClient:
    """Client for interacting with Jira REST API."""

    def __init__(self, config: JiraConfig):
        """Initialize Jira client.

        Args:
            config: Jira configuration
        """
        self.config = config
        self.base_url = config.url.rstrip("/")
        self.api_url = f"{self.base_url}/rest/api/3"
        self.auth = (config.email, config.api_token)

        logger.info(
            "jira_client_initialized",
            url=self.base_url,
            project_key=config.project_key,
        )

    def test_connection(self) -> bool:
        """Test connection to Jira.

        Returns:
            True if connection successful

        Raises:
            JiraError: If connection fails
        """
        try:
            response = requests.get(
                f"{self.api_url}/myself",
                auth=self.auth,
                headers={"Accept": "application/json"},
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )

            if response.status_code == 200:
                user = response.json()
                logger.info(
                    "jira_connection_successful",
                    user=user.get("displayName"),
                    email=user.get("emailAddress"),
                )
                return True
            else:
                raise JiraError(
                    f"Connection failed with status {response.status_code}: {response.text}"
                )

        except requests.exceptions.RequestException as e:
            logger.error("jira_connection_failed", error=str(e))
            raise JiraError(f"Failed to connect to Jira: {e}")

    def create_issue(
        self,
        summary: str,
        description: str,
        priority: Optional[str] = None,
        issue_type: Optional[str] = None,
        labels: Optional[List[str]] = None,
        assignee: Optional[str] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> JiraCreateResult:
        """Create a new Jira issue.

        Args:
            summary: Issue summary/title
            description: Issue description (supports Jira markup)
            priority: Priority level (uses default if not specified)
            issue_type: Issue type (uses default if not specified)
            labels: Labels to apply (uses default if not specified)
            assignee: Assignee account ID or email
            custom_fields: Additional custom fields

        Returns:
            JiraCreateResult with issue details
        """
        # Build issue payload
        fields = {
            "project": {"key": self.config.project_key},
            "summary": summary,
            "description": self._format_description(description),
            "issuetype": {"name": issue_type or self.config.issue_type},
            "priority": {"name": priority or self.config.default_priority},
            "labels": labels or self.config.default_labels,
        }

        # Add assignee if specified
        if assignee or self.config.default_assignee:
            fields["assignee"] = {"id": assignee or self.config.default_assignee}

        # Add custom fields
        if custom_fields:
            fields.update(custom_fields)

        payload = {"fields": fields}

        try:
            response = requests.post(
                f"{self.api_url}/issue",
                json=payload,
                auth=self.auth,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )

            if response.status_code in (200, 201):
                data = response.json()
                issue_key = data.get("key")
                issue_id = data.get("id")
                issue_url = f"{self.base_url}/browse/{issue_key}"

                logger.info(
                    "jira_issue_created",
                    key=issue_key,
                    summary=summary[:50],
                )

                return JiraCreateResult(
                    success=True,
                    key=issue_key,
                    id=issue_id,
                    url=issue_url,
                )
            else:
                error_msg = response.text
                logger.error(
                    "jira_issue_creation_failed",
                    status=response.status_code,
                    error=error_msg,
                )
                return JiraCreateResult(success=False, error=error_msg)

        except requests.exceptions.RequestException as e:
            logger.error("jira_request_failed", error=str(e))
            return JiraCreateResult(success=False, error=str(e))

    def create_issues_batch(
        self,
        issues: List[Dict[str, Any]],
        delay_between: float = 0.5,
    ) -> List[JiraCreateResult]:
        """Create multiple issues in batch.

        Args:
            issues: List of issue dictionaries with summary, description, priority, etc.
            delay_between: Delay between API calls to avoid rate limiting

        Returns:
            List of JiraCreateResult for each issue
        """
        results = []

        for i, issue in enumerate(issues):
            result = self.create_issue(
                summary=issue.get("summary", "Untitled Issue"),
                description=issue.get("description", ""),
                priority=issue.get("priority"),
                issue_type=issue.get("issue_type"),
                labels=issue.get("labels"),
                assignee=issue.get("assignee"),
                custom_fields=issue.get("custom_fields"),
            )
            results.append(result)

            # Add delay between requests to avoid rate limiting
            if i < len(issues) - 1:
                time.sleep(delay_between)

        # Log summary
        success_count = sum(1 for r in results if r.success)
        logger.info(
            "jira_batch_creation_complete",
            total=len(issues),
            success=success_count,
            failed=len(issues) - success_count,
        )

        return results

    def get_issue(self, issue_key: str) -> Optional[JiraIssue]:
        """Get a Jira issue by key.

        Args:
            issue_key: Issue key (e.g., "SEC-123")

        Returns:
            JiraIssue or None if not found
        """
        try:
            response = requests.get(
                f"{self.api_url}/issue/{issue_key}",
                auth=self.auth,
                headers={"Accept": "application/json"},
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )

            if response.status_code == 200:
                data = response.json()
                fields = data.get("fields", {})

                return JiraIssue(
                    key=data.get("key"),
                    id=data.get("id"),
                    summary=fields.get("summary", ""),
                    description=self._extract_description(fields.get("description")),
                    status=fields.get("status", {}).get("name", ""),
                    priority=fields.get("priority", {}).get("name", ""),
                    issue_type=fields.get("issuetype", {}).get("name", ""),
                    created=datetime.fromisoformat(
                        fields.get("created", "").replace("Z", "+00:00")
                    ),
                    updated=datetime.fromisoformat(
                        fields.get("updated", "").replace("Z", "+00:00")
                    ),
                    assignee=fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
                    labels=fields.get("labels", []),
                    url=f"{self.base_url}/browse/{data.get('key')}",
                )
            elif response.status_code == 404:
                return None
            else:
                logger.warning(
                    "jira_get_issue_failed",
                    key=issue_key,
                    status=response.status_code,
                )
                return None

        except requests.exceptions.RequestException as e:
            logger.error("jira_get_issue_error", key=issue_key, error=str(e))
            return None

    def add_comment(self, issue_key: str, comment: str) -> bool:
        """Add a comment to a Jira issue.

        Args:
            issue_key: Issue key (e.g., "SEC-123")
            comment: Comment text (supports Jira markup)

        Returns:
            True if successful
        """
        payload = {"body": self._format_description(comment)}

        try:
            response = requests.post(
                f"{self.api_url}/issue/{issue_key}/comment",
                json=payload,
                auth=self.auth,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )

            if response.status_code in (200, 201):
                logger.info("jira_comment_added", key=issue_key)
                return True
            else:
                logger.warning(
                    "jira_comment_failed",
                    key=issue_key,
                    status=response.status_code,
                )
                return False

        except requests.exceptions.RequestException as e:
            logger.error("jira_comment_error", key=issue_key, error=str(e))
            return False

    def transition_issue(self, issue_key: str, transition_name: str) -> bool:
        """Transition an issue to a new status.

        Args:
            issue_key: Issue key
            transition_name: Name of transition (e.g., "Done", "In Progress")

        Returns:
            True if successful
        """
        # First, get available transitions
        try:
            response = requests.get(
                f"{self.api_url}/issue/{issue_key}/transitions",
                auth=self.auth,
                headers={"Accept": "application/json"},
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )

            if response.status_code != 200:
                return False

            transitions = response.json().get("transitions", [])
            transition_id = None

            for t in transitions:
                if t.get("name", "").lower() == transition_name.lower():
                    transition_id = t.get("id")
                    break

            if not transition_id:
                logger.warning(
                    "jira_transition_not_found",
                    key=issue_key,
                    transition=transition_name,
                )
                return False

            # Perform the transition
            response = requests.post(
                f"{self.api_url}/issue/{issue_key}/transitions",
                json={"transition": {"id": transition_id}},
                auth=self.auth,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )

            if response.status_code == 204:
                logger.info(
                    "jira_issue_transitioned",
                    key=issue_key,
                    transition=transition_name,
                )
                return True
            else:
                logger.warning(
                    "jira_transition_failed",
                    key=issue_key,
                    status=response.status_code,
                )
                return False

        except requests.exceptions.RequestException as e:
            logger.error("jira_transition_error", key=issue_key, error=str(e))
            return False

    def search_issues(
        self,
        jql: str,
        max_results: int = 50,
        fields: Optional[List[str]] = None,
    ) -> List[JiraIssue]:
        """Search for issues using JQL.

        Args:
            jql: JQL query string
            max_results: Maximum number of results
            fields: Fields to return (default: summary, status, priority)

        Returns:
            List of JiraIssue objects
        """
        default_fields = ["summary", "status", "priority", "issuetype", "created", "updated", "assignee", "labels", "description"]
        params = {
            "jql": jql,
            "maxResults": max_results,
            "fields": ",".join(fields or default_fields),
        }

        try:
            response = requests.get(
                f"{self.api_url}/search",
                params=params,
                auth=self.auth,
                headers={"Accept": "application/json"},
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )

            if response.status_code == 200:
                data = response.json()
                issues = []

                for item in data.get("issues", []):
                    fields_data = item.get("fields", {})
                    issues.append(JiraIssue(
                        key=item.get("key"),
                        id=item.get("id"),
                        summary=fields_data.get("summary", ""),
                        description=self._extract_description(fields_data.get("description")),
                        status=fields_data.get("status", {}).get("name", ""),
                        priority=fields_data.get("priority", {}).get("name", ""),
                        issue_type=fields_data.get("issuetype", {}).get("name", ""),
                        created=datetime.fromisoformat(
                            fields_data.get("created", "").replace("Z", "+00:00")
                        ) if fields_data.get("created") else datetime.now(timezone.utc),
                        updated=datetime.fromisoformat(
                            fields_data.get("updated", "").replace("Z", "+00:00")
                        ) if fields_data.get("updated") else datetime.now(timezone.utc),
                        assignee=fields_data.get("assignee", {}).get("displayName") if fields_data.get("assignee") else None,
                        labels=fields_data.get("labels", []),
                        url=f"{self.base_url}/browse/{item.get('key')}",
                    ))

                logger.info("jira_search_complete", count=len(issues), jql=jql[:50])
                return issues
            else:
                logger.warning(
                    "jira_search_failed",
                    status=response.status_code,
                    jql=jql[:50],
                )
                return []

        except requests.exceptions.RequestException as e:
            logger.error("jira_search_error", error=str(e))
            return []

    def _format_description(self, text: str) -> Dict[str, Any]:
        """Format text as Atlassian Document Format (ADF).

        Args:
            text: Plain text or markdown

        Returns:
            ADF document structure
        """
        # Convert to ADF paragraph format
        paragraphs = text.split("\n\n")
        content = []

        for para in paragraphs:
            if para.strip():
                # Check if it's a heading
                if para.startswith("# "):
                    content.append({
                        "type": "heading",
                        "attrs": {"level": 1},
                        "content": [{"type": "text", "text": para[2:].strip()}],
                    })
                elif para.startswith("## "):
                    content.append({
                        "type": "heading",
                        "attrs": {"level": 2},
                        "content": [{"type": "text", "text": para[3:].strip()}],
                    })
                elif para.startswith("### "):
                    content.append({
                        "type": "heading",
                        "attrs": {"level": 3},
                        "content": [{"type": "text", "text": para[4:].strip()}],
                    })
                elif para.startswith("- ") or para.startswith("* "):
                    # Bullet list
                    items = [line.lstrip("- *").strip() for line in para.split("\n") if line.strip()]
                    list_items = []
                    for item in items:
                        list_items.append({
                            "type": "listItem",
                            "content": [{
                                "type": "paragraph",
                                "content": [{"type": "text", "text": item}],
                            }],
                        })
                    content.append({
                        "type": "bulletList",
                        "content": list_items,
                    })
                else:
                    # Regular paragraph
                    content.append({
                        "type": "paragraph",
                        "content": [{"type": "text", "text": para.strip()}],
                    })

        return {
            "type": "doc",
            "version": 1,
            "content": content,
        }

    def _extract_description(self, adf: Optional[Dict[str, Any]]) -> str:
        """Extract plain text from ADF description.

        Args:
            adf: Atlassian Document Format structure

        Returns:
            Plain text description
        """
        if not adf:
            return ""

        def extract_text(node: Dict[str, Any]) -> str:
            if node.get("type") == "text":
                return node.get("text", "")
            content = node.get("content", [])
            return "".join(extract_text(c) for c in content)

        return extract_text(adf)


class JiraSecurityReporter:
    """Creates Jira issues from security scan results."""

    def __init__(self, client: JiraClient):
        """Initialize reporter.

        Args:
            client: JiraClient instance
        """
        self.client = client

    def create_issues_from_findings(
        self,
        findings: List[Dict[str, Any]],
        scan_type: str = "security",
        scan_date: Optional[datetime] = None,
    ) -> List[JiraCreateResult]:
        """Create Jira issues from security findings.

        Args:
            findings: List of finding dictionaries
            scan_type: Type of scan (security, compliance, pii, etc.)
            scan_date: Date of scan

        Returns:
            List of JiraCreateResult
        """
        scan_date = scan_date or datetime.now(timezone.utc)
        issues = []

        for finding in findings:
            summary = self._create_summary(finding, scan_type)
            description = self._create_description(finding, scan_type, scan_date)
            priority = self._map_priority(finding.get("severity") or finding.get("risk_level", "medium"))

            issues.append({
                "summary": summary,
                "description": description,
                "priority": priority,
                "labels": self._get_labels(finding, scan_type),
            })

        return self.client.create_issues_batch(issues)

    def create_weekly_report_issue(
        self,
        summary_data: Dict[str, Any],
        report_date: Optional[datetime] = None,
    ) -> JiraCreateResult:
        """Create a weekly summary issue.

        Args:
            summary_data: Summary statistics
            report_date: Report date

        Returns:
            JiraCreateResult
        """
        report_date = report_date or datetime.now(timezone.utc)
        week_num = report_date.isocalendar()[1]

        summary = f"Weekly Security Report - Week {week_num}, {report_date.year}"
        description = self._create_weekly_report_description(summary_data, report_date)

        return self.client.create_issue(
            summary=summary,
            description=description,
            priority="Medium",
            labels=["vaulytica", "security", "weekly-report"],
        )

    def _create_summary(self, finding: Dict[str, Any], scan_type: str) -> str:
        """Create issue summary from finding."""
        finding_type = finding.get("type") or finding.get("category", "Security Finding")
        name = finding.get("name") or finding.get("app_name") or finding.get("file_name", "")

        if name:
            return f"[{scan_type.upper()}] {finding_type}: {name[:60]}"
        return f"[{scan_type.upper()}] {finding_type}"

    def _create_description(
        self,
        finding: Dict[str, Any],
        scan_type: str,
        scan_date: datetime,
    ) -> str:
        """Create issue description from finding."""
        lines = []

        lines.append(f"## {scan_type.title()} Finding")
        lines.append("")
        lines.append(f"**Scan Date:** {scan_date.strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"**Severity:** {finding.get('severity') or finding.get('risk_level', 'Unknown')}")

        if finding.get("risk_score"):
            lines.append(f"**Risk Score:** {finding.get('risk_score')}/100")

        lines.append("")
        lines.append("## Details")
        lines.append("")

        if finding.get("description"):
            lines.append(finding.get("description"))
            lines.append("")

        # Add evidence
        if finding.get("evidence"):
            lines.append("## Evidence")
            for item in finding.get("evidence", []):
                lines.append(f"- {item}")
            lines.append("")

        # Add affected items
        if finding.get("affected_users"):
            lines.append("## Affected Users")
            for user in finding.get("affected_users", [])[:10]:
                lines.append(f"- {user}")
            if len(finding.get("affected_users", [])) > 10:
                lines.append(f"- ... and {len(finding['affected_users']) - 10} more")
            lines.append("")

        # Add remediation steps
        if finding.get("remediation_steps"):
            lines.append("## Remediation Steps")
            for step in finding.get("remediation_steps", []):
                lines.append(f"- {step}")
            lines.append("")

        lines.append("---")
        lines.append("*This issue was automatically created by Vaulytica.*")

        return "\n".join(lines)

    def _create_weekly_report_description(
        self,
        summary_data: Dict[str, Any],
        report_date: datetime,
    ) -> str:
        """Create weekly report description."""
        lines = []

        lines.append("## Weekly Security Summary")
        lines.append("")
        lines.append(f"**Report Period:** Week ending {report_date.strftime('%Y-%m-%d')}")
        lines.append("")

        lines.append("## Key Metrics")
        lines.append("")

        if "files" in summary_data:
            lines.append("### File Scanning")
            files = summary_data["files"]
            lines.append(f"- Total files scanned: {files.get('total', 0)}")
            lines.append(f"- High risk files: {files.get('high_risk', 0)}")
            lines.append(f"- Files with external sharing: {files.get('external_shares', 0)}")
            lines.append(f"- Public files: {files.get('public', 0)}")
            lines.append(f"- Files with PII: {files.get('pii_files', 0)}")
            lines.append("")

        if "users" in summary_data:
            lines.append("### User Security")
            users = summary_data["users"]
            lines.append(f"- Total users: {users.get('total', 0)}")
            lines.append(f"- Users without 2FA: {users.get('without_2fa', 0)}")
            lines.append(f"- Inactive users: {users.get('inactive', 0)}")
            lines.append("")

        if "oauth_apps" in summary_data:
            lines.append("### OAuth Applications")
            apps = summary_data["oauth_apps"]
            lines.append(f"- Total OAuth apps: {apps.get('total', 0)}")
            lines.append(f"- High risk apps: {apps.get('high_risk', 0)}")
            lines.append(f"- Unverified apps: {apps.get('unverified', 0)}")
            lines.append("")

        if "compliance" in summary_data:
            lines.append("### Compliance Status")
            compliance = summary_data["compliance"]
            for framework, score in compliance.items():
                lines.append(f"- {framework}: {score}%")
            lines.append("")

        lines.append("## Action Items")
        lines.append("")
        lines.append("- [ ] Review high-risk files and update sharing settings")
        lines.append("- [ ] Follow up with users who need to enable 2FA")
        lines.append("- [ ] Review and revoke unauthorized OAuth apps")
        lines.append("- [ ] Address any compliance gaps")
        lines.append("")

        lines.append("---")
        lines.append("*This report was automatically generated by Vaulytica.*")

        return "\n".join(lines)

    def _map_priority(self, severity: str) -> str:
        """Map finding severity to Jira priority."""
        mapping = self.client.config.priority_mapping
        return mapping.get(severity.lower(), "Medium")

    def _get_labels(self, finding: Dict[str, Any], scan_type: str) -> List[str]:
        """Get labels for finding."""
        labels = ["vaulytica", "security", scan_type]

        if finding.get("category"):
            labels.append(finding["category"].lower().replace(" ", "-"))

        if finding.get("severity") or finding.get("risk_level"):
            severity = (finding.get("severity") or finding.get("risk_level", "")).lower()
            if severity:
                labels.append(f"severity-{severity}")

        return labels


def create_jira_client_from_config(config: Dict[str, Any]) -> Optional[JiraClient]:
    """Create JiraClient from configuration.

    Args:
        config: Configuration dictionary

    Returns:
        JiraClient instance or None if not configured
    """
    jira_config = config.get("integrations", {}).get("jira", {})

    if not jira_config.get("enabled", False):
        return None

    url = jira_config.get("url")
    email = jira_config.get("email")
    api_token = jira_config.get("api_token")
    project_key = jira_config.get("project_key")

    if not all([url, email, api_token, project_key]):
        logger.warning("jira_config_incomplete")
        return None

    return JiraClient(JiraConfig(
        url=url,
        email=email,
        api_token=api_token,
        project_key=project_key,
        issue_type=jira_config.get("issue_type", "Task"),
        default_priority=jira_config.get("default_priority", "Medium"),
        default_labels=jira_config.get("default_labels", ["vaulytica", "security"]),
        default_assignee=jira_config.get("default_assignee"),
        priority_mapping=jira_config.get("priority_mapping", {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
        }),
        verify_ssl=jira_config.get("verify_ssl", True),
        timeout=jira_config.get("timeout", 30),
    ))
