"""
GitLab Integration

Integrates with GitLab API for:
- Merge Request (MR) creation and management
- CI/CD pipeline management
- Code review automation
- Repository analysis
- Security scanning integration
- Automated remediation workflows

Version: 1.0.0
Author: Vaulytica Team
"""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import httpx

from vaulytica.config import VaulyticaConfig, get_config
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class GitLabMRState(str, Enum):
    """GitLab MR states"""
    OPENED = "opened"
    CLOSED = "closed"
    MERGED = "merged"
    LOCKED = "locked"


class GitLabPipelineStatus(str, Enum):
    """GitLab pipeline statuses"""
    CREATED = "created"
    WAITING_FOR_RESOURCE = "waiting_for_resource"
    PREPARING = "preparing"
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELED = "canceled"
    SKIPPED = "skipped"
    MANUAL = "manual"


@dataclass
class GitLabProject:
    """GitLab project"""
    id: int
    name: str
    path: str
    namespace: str
    default_branch: str = "main"
    web_url: str = ""
    ssh_url: str = ""
    http_url: str = ""
    description: str = ""
    visibility: str = "private"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GitLabMergeRequest:
    """GitLab merge request"""
    id: int
    iid: int  # Internal ID (project-specific)
    project_id: int
    title: str
    description: str
    state: GitLabMRState
    source_branch: str
    target_branch: str
    author: str
    web_url: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    merged_at: Optional[datetime] = None
    merge_status: str = "unchecked"  # can_be_merged, cannot_be_merged, unchecked
    has_conflicts: bool = False
    approvals_required: int = 0
    approvals_count: int = 0
    pipeline_status: Optional[GitLabPipelineStatus] = None
    changes_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GitLabPipeline:
    """GitLab CI/CD pipeline"""
    id: int
    project_id: int
    status: GitLabPipelineStatus
    ref: str  # Branch or tag
    sha: str  # Commit SHA
    web_url: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration: Optional[int] = None  # Seconds
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GitLabCommit:
    """GitLab commit"""
    id: str  # SHA
    short_id: str
    title: str
    message: str
    author_name: str
    author_email: str
    created_at: Optional[datetime] = None
    web_url: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


class GitLabAPIClient:
    """GitLab API client"""

    def __init__(
        self,
        url: str,
        token: str,
        timeout: int = 30
    ):
        """
        Initialize GitLab API client.

        Args:
            url: GitLab instance URL (e.g., 'https://gitlab.example.com')
            token: Personal access token
            timeout: Request timeout in seconds
        """
        self.url = url.rstrip('/')
        self.token = token
        self.timeout = timeout
        self.api_url = f"{self.url}/api/v4"

        # Statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "mrs_created": 0,
            "mrs_merged": 0,
            "pipelines_triggered": 0
        }

        logger.info(f"GitLab API client initialized (url: {url})")

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """Make API request"""
        try:
            self.stats["total_requests"] += 1

            headers = {
                "PRIVATE-TOKEN": self.token,
                "Content-Type": "application/json"
            }

            url = f"{self.api_url}/{endpoint}"

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if method == "GET":
                    response = await client.get(url, headers=headers, params=params)
                elif method == "POST":
                    response = await client.post(url, headers=headers, json=json_data)
                elif method == "PUT":
                    response = await client.put(url, headers=headers, json=json_data)
                elif method == "DELETE":
                    response = await client.delete(url, headers=headers)
                else:
                    raise ValueError(f"Unsupported method: {method}")

                if response.status_code in [200, 201]:
                    self.stats["successful_requests"] += 1
                    return response.json()
                else:
                    logger.error(f"GitLab API error: {response.status_code} - {response.text}")
                    self.stats["failed_requests"] += 1
                    return None

        except Exception as e:
            logger.error(f"GitLab API request error: {e}")
            self.stats["failed_requests"] += 1
            return None

    async def get_project(self, project_id: str) -> Optional[GitLabProject]:
        """
        Get project by ID or path.

        Args:
            project_id: Project ID or URL-encoded path (e.g., 'namespace/project')

        Returns:
            GitLabProject or None
        """
        # URL encode the project ID if it contains slashes
        encoded_id = project_id.replace('/', '%2F')
        result = await self._make_request("GET", f"projects/{encoded_id}")

        if not result:
            return None

        project = GitLabProject(
            id=result["id"],
            name=result["name"],
            path=result["path"],
            namespace=result["namespace"]["full_path"],
            default_branch=result.get("default_branch", "main"),
            web_url=result.get("web_url", ""),
            ssh_url=result.get("ssh_url_to_repo", ""),
            http_url=result.get("http_url_to_repo", ""),
            description=result.get("description", ""),
            visibility=result.get("visibility", "private"),
            metadata=result
        )

        logger.info(f"Retrieved GitLab project: {project.namespace}/{project.name}")
        return project

    async def create_merge_request(
        self,
        project_id: str,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str,
        remove_source_branch: bool = True,
        squash: bool = False,
        labels: Optional[List[str]] = None
    ) -> Optional[GitLabMergeRequest]:
        """
        Create a merge request.

        Args:
            project_id: Project ID or path
            source_branch: Source branch name
            target_branch: Target branch name
            title: MR title
            description: MR description
            remove_source_branch: Remove source branch after merge
            squash: Squash commits on merge
            labels: List of labels

        Returns:
            GitLabMergeRequest or None
        """
        encoded_id = project_id.replace('/', '%2F')

        data = {
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title": title,
            "description": description,
            "remove_source_branch": remove_source_branch,
            "squash": squash
        }

        if labels:
            data["labels"] = ",".join(labels)

        result = await self._make_request(
            "POST",
            f"projects/{encoded_id}/merge_requests",
            json_data=data
        )

        if not result:
            return None

        mr = self._parse_merge_request(result)
        self.stats["mrs_created"] += 1

        logger.info(f"Created GitLab MR: {mr.web_url}")
        return mr

    async def get_merge_request(
        self,
        project_id: str,
        mr_iid: int
    ) -> Optional[GitLabMergeRequest]:
        """Get merge request by IID"""
        encoded_id = project_id.replace('/', '%2F')
        result = await self._make_request(
            "GET",
            f"projects/{encoded_id}/merge_requests/{mr_iid}"
        )

        if not result:
            return None

        return self._parse_merge_request(result)

    async def merge_merge_request(
        self,
        project_id: str,
        mr_iid: int,
        merge_commit_message: Optional[str] = None,
        squash: bool = False
    ) -> bool:
        """
        Merge a merge request.

        Args:
            project_id: Project ID or path
            mr_iid: MR internal ID
            merge_commit_message: Custom merge commit message
            squash: Squash commits

        Returns:
            True if successful
        """
        encoded_id = project_id.replace('/', '%2F')

        data = {
            "squash": squash
        }

        if merge_commit_message:
            data["merge_commit_message"] = merge_commit_message

        result = await self._make_request(
            "PUT",
            f"projects/{encoded_id}/merge_requests/{mr_iid}/merge",
            json_data=data
        )

        if result:
            self.stats["mrs_merged"] += 1
            logger.info(f"Merged GitLab MR !{mr_iid} in project {project_id}")
            return True

        return False

    async def get_pipeline(
        self,
        project_id: str,
        pipeline_id: int
    ) -> Optional[GitLabPipeline]:
        """Get pipeline by ID"""
        encoded_id = project_id.replace('/', '%2F')
        result = await self._make_request(
            "GET",
            f"projects/{encoded_id}/pipelines/{pipeline_id}"
        )

        if not result:
            return None

        return self._parse_pipeline(result)

    async def trigger_pipeline(
        self,
        project_id: str,
        ref: str,
        variables: Optional[Dict[str, str]] = None
    ) -> Optional[GitLabPipeline]:
        """
        Trigger a CI/CD pipeline.

        Args:
            project_id: Project ID or path
            ref: Branch or tag name
            variables: Pipeline variables

        Returns:
            GitLabPipeline or None
        """
        encoded_id = project_id.replace('/', '%2F')

        data = {
            "ref": ref
        }

        if variables:
            data["variables"] = [
                {"key": k, "value": v}
                for k, v in variables.items()
            ]

        result = await self._make_request(
            "POST",
            f"projects/{encoded_id}/pipeline",
            json_data=data
        )

        if not result:
            return None

        pipeline = self._parse_pipeline(result)
        self.stats["pipelines_triggered"] += 1

        logger.info(f"Triggered GitLab pipeline: {pipeline.web_url}")
        return pipeline

    async def create_commit(
        self,
        project_id: str,
        branch: str,
        commit_message: str,
        actions: List[Dict[str, Any]]
    ) -> Optional[GitLabCommit]:
        """
        Create a commit with file changes.

        Args:
            project_id: Project ID or path
            branch: Branch name
            commit_message: Commit message
            actions: List of file actions (create, update, delete)
                     Each action: {"action": "create|update|delete", "file_path": "...", "content": "..."}

        Returns:
            GitLabCommit or None
        """
        encoded_id = project_id.replace('/', '%2F')

        data = {
            "branch": branch,
            "commit_message": commit_message,
            "actions": actions
        }

        result = await self._make_request(
            "POST",
            f"projects/{encoded_id}/repository/commits",
            json_data=data
        )

        if not result:
            return None

        commit = GitLabCommit(
            id=result["id"],
            short_id=result["short_id"],
            title=result["title"],
            message=result["message"],
            author_name=result["author_name"],
            author_email=result["author_email"],
            created_at=self._parse_datetime(result.get("created_at")),
            web_url=result.get("web_url", ""),
            metadata=result
        )

        logger.info(f"Created GitLab commit: {commit.short_id}")
        return commit

    def _parse_merge_request(self, data: Dict[str, Any]) -> GitLabMergeRequest:
        """Parse MR data"""
        return GitLabMergeRequest(
            id=data["id"],
            iid=data["iid"],
            project_id=data["project_id"],
            title=data["title"],
            description=data.get("description", ""),
            state=GitLabMRState(data["state"]),
            source_branch=data["source_branch"],
            target_branch=data["target_branch"],
            author=data["author"]["username"],
            web_url=data["web_url"],
            created_at=self._parse_datetime(data.get("created_at")),
            updated_at=self._parse_datetime(data.get("updated_at")),
            merged_at=self._parse_datetime(data.get("merged_at")),
            merge_status=data.get("merge_status", "unchecked"),
            has_conflicts=data.get("has_conflicts", False),
            changes_count=data.get("changes_count", 0),
            metadata=data
        )

    def _parse_pipeline(self, data: Dict[str, Any]) -> GitLabPipeline:
        """Parse pipeline data"""
        return GitLabPipeline(
            id=data["id"],
            project_id=data["project_id"],
            status=GitLabPipelineStatus(data["status"]),
            ref=data["ref"],
            sha=data["sha"],
            web_url=data["web_url"],
            created_at=self._parse_datetime(data.get("created_at")),
            updated_at=self._parse_datetime(data.get("updated_at")),
            started_at=self._parse_datetime(data.get("started_at")),
            finished_at=self._parse_datetime(data.get("finished_at")),
            duration=data.get("duration"),
            metadata=data
        )

    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime string"""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except Exception:
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get integration statistics"""
        return self.stats.copy()


class GitLabIntegration:
    """High-level GitLab integration"""

    def __init__(self, config: Optional[VaulyticaConfig] = None):
        """Initialize GitLab integration"""
        if config is None:
            config = get_config()

        self.config = config
        self.client = GitLabAPIClient(
            url=config.gitlab_url,
            token=config.gitlab_token
        )

        logger.info("GitLab integration initialized")

    async def create_remediation_mr(
        self,
        project_path: str,
        vulnerability_id: str,
        file_changes: Dict[str, str],  # {file_path: new_content}
        title: str,
        description: str
    ) -> Optional[GitLabMergeRequest]:
        """
        Create MR for vulnerability remediation.

        Args:
            project_path: Project path (namespace/project)
            vulnerability_id: Vulnerability ID for branch naming
            file_changes: Dictionary of file paths to new content
            title: MR title
            description: MR description

        Returns:
            GitLabMergeRequest or None
        """
        # Get project to find default branch
        project = await self.client.get_project(project_path)
        if not project:
            logger.error(f"Project not found: {project_path}")
            return None

        # Create branch name
        branch_name = f"vaulytica/fix-{vulnerability_id}"

        # Create commit with file changes
        actions = []
        for file_path, content in file_changes.items():
            actions.append({
                "action": "update",
                "file_path": file_path,
                "content": content
            })

        commit = await self.client.create_commit(
            project_id=project_path,
            branch=branch_name,
            commit_message=f"Fix vulnerability {vulnerability_id}",
            actions=actions
        )

        if not commit:
            logger.error(f"Failed to create commit for {vulnerability_id}")
            return None

        # Create MR
        mr = await self.client.create_merge_request(
            project_id=project_path,
            source_branch=branch_name,
            target_branch=project.default_branch,
            title=title,
            description=description,
            labels=["security", "vaulytica", "automated-fix"]
        )

        return mr

    def get_statistics(self) -> Dict[str, Any]:
        """Get integration statistics"""
        return self.client.get_statistics()


# Global instance
_gitlab_integration: Optional[GitLabIntegration] = None


def get_gitlab_integration(config: Optional[VaulyticaConfig] = None) -> GitLabIntegration:
    """Get or create global GitLab integration instance"""
    global _gitlab_integration

    if _gitlab_integration is None:
        _gitlab_integration = GitLabIntegration(config)

    return _gitlab_integration

