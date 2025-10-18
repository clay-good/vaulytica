import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from base64 import b64encode

from vaulytica.incidents import Incident, IncidentStatus, IncidentPriority, Severity
from vaulytica.models import AnalysisResult
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class JiraIssueType(str, Enum):
    """Jira issue types."""
    BUG = "Bug"
    TASK = "Task"
    STORY = "Story"
    EPIC = "Epic"
    INCIDENT = "Incident"
    SECURITY_INCIDENT = "Security Incident"


class JiraPriority(str, Enum):
    """Jira priority levels."""
    HIGHEST = "Highest"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    LOWEST = "Lowest"


class JiraStatus(str, Enum):
    """Common Jira statuses."""
    TO_DO = "To Do"
    IN_PROGRESS = "In Progress"
    IN_REVIEW = "In Review"
    DONE = "Done"
    CLOSED = "Closed"
    CANCELLED = "Cancelled"


@dataclass
class JiraIssue:
    """Jira issue model."""
    key: str
    id: str
    summary: str
    description: str
    issue_type: str
    status: str
    priority: str
    project_key: str
    assignee: Optional[str] = None
    reporter: Optional[str] = None
    created: Optional[datetime] = None
    updated: Optional[datetime] = None
    resolved: Optional[datetime] = None
    labels: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)
    fix_versions: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    comments: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class SyncMapping:
    """Mapping between Vaulytica incident and Jira issue."""
    incident_id: str
    jira_key: str
    jira_id: str
    last_synced: datetime
    sync_direction: str  # "vaulytica_to_jira", "jira_to_vaulytica", "bidirectional"
    metadata: Dict[str, Any] = field(default_factory=dict)


class JiraAPIClient:
    """
    Jira REST API client.
    
    Provides low-level API operations for Jira Cloud/Server.
    """
    
    def __init__(
        self,
        base_url: str,
        username: str,
        api_token: str,
        api_version: str = "2"
    ):
        """
        Initialize Jira API client.
        
        Args:
            base_url: Jira instance URL (e.g., 'https://company.atlassian.net')
            username: Jira username/email
            api_token: Jira API token
            api_version: API version (default: 2)
        """
        self.base_url = base_url.rstrip('/')
        self.api_url = f"{self.base_url}/rest/api/{api_version}"
        self.username = username
        self.api_token = api_token
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Statistics
        self.statistics = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "issues_created": 0,
            "issues_updated": 0,
            "issues_queried": 0
        }
        
        logger.info(f"Jira API client initialized for: {base_url}")
    
    def _get_auth_header(self) -> str:
        """Generate Basic Auth header."""
        credentials = f"{self.username}:{self.api_token}"
        encoded = b64encode(credentials.encode()).decode()
        return f"Basic {encoded}"
    
    async def _ensure_session(self):
        """Ensure aiohttp session exists."""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={
                    "Authorization": self._get_auth_header(),
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            )
    
    async def close(self):
        """Close the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def create_issue(
        self,
        project_key: str,
        summary: str,
        description: str,
        issue_type: str = "Task",
        priority: Optional[JiraPriority] = None,
        assignee: Optional[str] = None,
        labels: Optional[List[str]] = None,
        **custom_fields
    ) -> Optional[JiraIssue]:
        """Create a new Jira issue."""
        await self._ensure_session()
        
        fields = {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type}
        }
        
        if priority:
            fields["priority"] = {"name": priority.value}
        if assignee:
            fields["assignee"] = {"name": assignee}
        if labels:
            fields["labels"] = labels
        
        # Add custom fields
        fields.update(custom_fields)
        
        payload = {"fields": fields}
        
        try:
            self.statistics["total_requests"] += 1
            
            async with self.session.post(
                f"{self.api_url}/issue",
                json=payload
            ) as response:
                if response.status == 201:
                    data = await response.json()
                    
                    self.statistics["successful_requests"] += 1
                    self.statistics["issues_created"] += 1
                    
                    # Fetch full issue details
                    issue = await self.get_issue(data["key"])
                    if issue:
                        logger.info(f"Created Jira issue: {issue.key}")
                    return issue
                else:
                    self.statistics["failed_requests"] += 1
                    error_text = await response.text()
                    logger.error(f"Failed to create issue: {response.status} - {error_text}")
                    return None
                    
        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error creating issue: {e}")
            return None
    
    async def get_issue(self, issue_key: str) -> Optional[JiraIssue]:
        """Get issue by key."""
        await self._ensure_session()
        
        try:
            self.statistics["total_requests"] += 1
            
            async with self.session.get(
                f"{self.api_url}/issue/{issue_key}"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    self.statistics["successful_requests"] += 1
                    self.statistics["issues_queried"] += 1
                    
                    return self._parse_issue(data)
                else:
                    self.statistics["failed_requests"] += 1
                    logger.error(f"Failed to get issue: {response.status}")
                    return None
                    
        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error getting issue: {e}")
            return None
    
    async def update_issue(
        self,
        issue_key: str,
        **fields
    ) -> Optional[JiraIssue]:
        """Update an existing Jira issue."""
        await self._ensure_session()
        
        payload = {"fields": fields}
        
        try:
            self.statistics["total_requests"] += 1
            
            async with self.session.put(
                f"{self.api_url}/issue/{issue_key}",
                json=payload
            ) as response:
                if response.status == 204:
                    self.statistics["successful_requests"] += 1
                    self.statistics["issues_updated"] += 1
                    
                    # Fetch updated issue
                    issue = await self.get_issue(issue_key)
                    if issue:
                        logger.info(f"Updated Jira issue: {issue.key}")
                    return issue
                else:
                    self.statistics["failed_requests"] += 1
                    error_text = await response.text()
                    logger.error(f"Failed to update issue: {response.status} - {error_text}")
                    return None
                    
        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error updating issue: {e}")
            return None
    
    async def transition_issue(
        self,
        issue_key: str,
        transition_name: str
    ) -> bool:
        """Transition issue to a new status."""
        await self._ensure_session()
        
        try:
            # Get available transitions
            async with self.session.get(
                f"{self.api_url}/issue/{issue_key}/transitions"
            ) as response:
                if response.status != 200:
                    return False
                
                data = await response.json()
                transitions = data.get("transitions", [])
                
                # Find matching transition
                transition_id = None
                for t in transitions:
                    if t["name"].lower() == transition_name.lower():
                        transition_id = t["id"]
                        break
                
                if not transition_id:
                    logger.error(f"Transition '{transition_name}' not found for {issue_key}")
                    return False
            
            # Execute transition
            payload = {"transition": {"id": transition_id}}
            
            async with self.session.post(
                f"{self.api_url}/issue/{issue_key}/transitions",
                json=payload
            ) as response:
                if response.status == 204:
                    logger.info(f"Transitioned {issue_key} to {transition_name}")
                    return True
                else:
                    logger.error(f"Failed to transition issue: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error transitioning issue: {e}")
            return False
    
    def _parse_issue(self, data: Dict[str, Any]) -> JiraIssue:
        """Parse Jira API response into JiraIssue."""
        fields = data.get("fields", {})
        
        return JiraIssue(
            key=data.get("key", ""),
            id=data.get("id", ""),
            summary=fields.get("summary", ""),
            description=fields.get("description", ""),
            issue_type=fields.get("issuetype", {}).get("name", ""),
            status=fields.get("status", {}).get("name", ""),
            priority=fields.get("priority", {}).get("name", "Medium"),
            project_key=fields.get("project", {}).get("key", ""),
            assignee=fields.get("assignee", {}).get("name") if fields.get("assignee") else None,
            reporter=fields.get("reporter", {}).get("name") if fields.get("reporter") else None,
            created=self._parse_datetime(fields.get("created")),
            updated=self._parse_datetime(fields.get("updated")),
            resolved=self._parse_datetime(fields.get("resolutiondate")),
            labels=fields.get("labels", []),
            components=[c.get("name") for c in fields.get("components", [])],
            fix_versions=[v.get("name") for v in fields.get("fixVersions", [])],
            custom_fields={k: v for k, v in fields.items() if k.startswith("customfield_")},
            comments=[c for c in fields.get("comment", {}).get("comments", [])]
        )
    
    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse Jira datetime string."""
        if not dt_str:
            return None
        try:
            # Jira uses ISO 8601 format
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except:
            return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get API client statistics."""
        return self.statistics.copy()

    async def add_comment(self, issue_key: str, comment: str) -> bool:
        """Add a comment to an issue."""
        await self._ensure_session()

        payload = {"body": comment}

        try:
            async with self.session.post(
                f"{self.api_url}/issue/{issue_key}/comment",
                json=payload
            ) as response:
                if response.status == 201:
                    logger.info(f"Added comment to {issue_key}")
                    return True
                else:
                    logger.error(f"Failed to add comment: {response.status}")
                    return False
        except Exception as e:
            logger.error(f"Error adding comment: {e}")
            return False

    async def search_issues(self, jql: str, max_results: int = 100) -> List[JiraIssue]:
        """Search issues using JQL."""
        await self._ensure_session()

        payload = {
            "jql": jql,
            "maxResults": max_results
        }

        try:
            self.statistics["total_requests"] += 1

            async with self.session.post(
                f"{self.api_url}/search",
                json=payload
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    issues = data.get("issues", [])

                    self.statistics["successful_requests"] += 1
                    self.statistics["issues_queried"] += len(issues)

                    parsed_issues = [self._parse_issue(issue) for issue in issues]
                    logger.info(f"Found {len(parsed_issues)} issues matching JQL")
                    return parsed_issues
                else:
                    self.statistics["failed_requests"] += 1
                    logger.error(f"Failed to search issues: {response.status}")
                    return []

        except Exception as e:
            self.statistics["failed_requests"] += 1
            logger.error(f"Error searching issues: {e}")
            return []


class JiraIssueManager:
    """
    Jira Issue Manager.

    Provides high-level issue management with bidirectional sync.
    """

    def __init__(
        self,
        api_client: JiraAPIClient,
        project_key: str,
        auto_create_issues: bool = False,
        auto_sync: bool = False,
        sync_interval: int = 300,  # 5 minutes
        default_issue_type: str = "Task",
        default_assignee: Optional[str] = None
    ):
        """
        Initialize Jira Issue Manager.

        Args:
            api_client: Jira API client
            project_key: Default Jira project key
            auto_create_issues: Automatically create Jira issues
            auto_sync: Enable automatic bidirectional sync
            sync_interval: Sync interval in seconds
            default_issue_type: Default issue type
            default_assignee: Default assignee
        """
        self.api_client = api_client
        self.project_key = project_key
        self.auto_create_issues = auto_create_issues
        self.auto_sync = auto_sync
        self.sync_interval = sync_interval
        self.default_issue_type = default_issue_type
        self.default_assignee = default_assignee

        # Sync mappings
        self.mappings: Dict[str, SyncMapping] = {}

        # Sync task
        self.sync_task: Optional[asyncio.Task] = None

        # Callbacks
        self.on_issue_created: Optional[Callable] = None
        self.on_issue_updated: Optional[Callable] = None
        self.on_sync_error: Optional[Callable] = None

        # Statistics
        self.statistics = {
            "issues_created": 0,
            "issues_updated": 0,
            "issues_synced": 0,
            "sync_errors": 0,
            "last_sync": None
        }

        logger.info(f"Jira Issue Manager initialized for project: {project_key}")

    def _map_severity_to_priority(self, severity: Severity) -> JiraPriority:
        """Map Vaulytica severity to Jira priority."""
        mapping = {
            Severity.CRITICAL: JiraPriority.HIGHEST,
            Severity.HIGH: JiraPriority.HIGH,
            Severity.MEDIUM: JiraPriority.MEDIUM,
            Severity.LOW: JiraPriority.LOW,
            Severity.INFO: JiraPriority.LOWEST
        }
        return mapping.get(severity, JiraPriority.MEDIUM)

    def _build_issue_description(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult] = None
    ) -> str:
        """Build Jira issue description from Vaulytica incident."""
        lines = [
            f"h2. Vaulytica Incident",
            f"*Incident ID:* {incident.incident_id}",
            f"*Severity:* {incident.severity.value}",
            f"*Priority:* {incident.priority.value}",
            f"*Status:* {incident.status.value}",
            f"*Created:* {incident.created_at.isoformat()}",
            "",
            "h2. Description",
            incident.description or "No description available",
        ]

        if incident.affected_assets:
            lines.extend([
                "",
                "h2. Affected Assets",
                *[f"* {asset}" for asset in incident.affected_assets[:10]]
            ])

        if incident.source_ips:
            lines.extend([
                "",
                "h2. Source IPs",
                *[f"* {ip}" for ip in incident.source_ips[:10]]
            ])

        if incident.mitre_techniques:
            lines.extend([
                "",
                "h2. MITRE ATT&CK Techniques",
                *[f"* {technique}" for technique in incident.mitre_techniques[:10]]
            ])

        if analysis:
            lines.extend([
                "",
                "h2. AI Analysis",
                f"*What:* {analysis.what}",
                f"*Why:* {analysis.why}",
                f"*Impact:* {analysis.impact}",
                "",
                "h3. Recommended Actions",
                *[f"# {action}" for action in analysis.recommended_actions[:5]]
            ])

        return "\n".join(lines)

    async def create_issue_from_vaulytica(
        self,
        incident: Incident,
        analysis: Optional[AnalysisResult] = None
    ) -> Optional[JiraIssue]:
        """Create Jira issue from Vaulytica incident."""
        try:
            priority = self._map_severity_to_priority(incident.severity)
            description = self._build_issue_description(incident, analysis)

            labels = [
                "vaulytica",
                f"severity-{incident.severity.value.lower()}",
                f"incident-{incident.incident_id}"
            ]

            if incident.tags:
                labels.extend(incident.tags[:5])  # Limit to 5 additional tags

            jira_issue = await self.api_client.create_issue(
                project_key=self.project_key,
                summary=incident.title[:255],  # Jira limit
                description=description,
                issue_type=self.default_issue_type,
                priority=priority,
                assignee=self.default_assignee,
                labels=labels
            )

            if jira_issue:
                # Create mapping
                mapping = SyncMapping(
                    incident_id=incident.incident_id,
                    jira_key=jira_issue.key,
                    jira_id=jira_issue.id,
                    last_synced=datetime.now(),
                    sync_direction="bidirectional",
                    metadata={
                        "created_at": datetime.now().isoformat(),
                        "vaulytica_severity": incident.severity.value,
                        "jira_priority": priority.value
                    }
                )
                self.mappings[incident.incident_id] = mapping

                self.statistics["issues_created"] += 1

                if self.on_issue_created:
                    await self.on_issue_created(jira_issue, incident)

                logger.info(f"Created Jira issue {jira_issue.key} for Vaulytica incident {incident.incident_id}")

            return jira_issue

        except Exception as e:
            logger.error(f"Error creating Jira issue: {e}")
            if self.on_sync_error:
                await self.on_sync_error("create_issue", str(e))
            return None

    async def sync_incident_to_jira(
        self,
        incident: Incident,
        issue_key: str
    ) -> Optional[JiraIssue]:
        """Sync Vaulytica incident updates to Jira."""
        try:
            priority = self._map_severity_to_priority(incident.severity)

            fields = {
                "priority": {"name": priority.value}
            }

            jira_issue = await self.api_client.update_issue(issue_key, **fields)

            # Transition based on status
            status_transitions = {
                IncidentStatus.NEW: "To Do",
                IncidentStatus.ACKNOWLEDGED: "In Progress",
                IncidentStatus.INVESTIGATING: "In Progress",
                IncidentStatus.CONTAINED: "In Progress",
                IncidentStatus.RESOLVED: "Done",
                IncidentStatus.CLOSED: "Done",
                IncidentStatus.FALSE_POSITIVE: "Cancelled"
            }

            transition = status_transitions.get(incident.status)
            if transition:
                await self.api_client.transition_issue(issue_key, transition)

            if jira_issue:
                # Update mapping
                if incident.incident_id in self.mappings:
                    self.mappings[incident.incident_id].last_synced = datetime.now()

                self.statistics["issues_synced"] += 1

                if self.on_issue_updated:
                    await self.on_issue_updated(jira_issue, incident)

                logger.info(f"Synced Vaulytica incident {incident.incident_id} to Jira {jira_issue.key}")

            return jira_issue

        except Exception as e:
            self.statistics["sync_errors"] += 1
            logger.error(f"Error syncing incident to Jira: {e}")
            if self.on_sync_error:
                await self.on_sync_error("sync_incident", str(e))
            return None

    def get_mapping(self, incident_id: str) -> Optional[SyncMapping]:
        """Get sync mapping for incident."""
        return self.mappings.get(incident_id)

    def get_all_mappings(self) -> List[SyncMapping]:
        """Get all sync mappings."""
        return list(self.mappings.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics."""
        return {
            **self.statistics,
            "total_mappings": len(self.mappings),
            "api_statistics": self.api_client.get_statistics()
        }


# Global instance
_jira_manager: Optional[JiraIssueManager] = None


def get_jira_manager(
    base_url: Optional[str] = None,
    username: Optional[str] = None,
    api_token: Optional[str] = None,
    project_key: Optional[str] = None,
    **kwargs
) -> JiraIssueManager:
    """Get or create global Jira manager instance."""
    global _jira_manager

    if _jira_manager is None:
        if not all([base_url, username, api_token, project_key]):
            raise ValueError("Jira credentials and project key required for first initialization")

        api_client = JiraAPIClient(base_url, username, api_token)
        _jira_manager = JiraIssueManager(api_client, project_key, **kwargs)

    return _jira_manager

