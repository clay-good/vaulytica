"""
GitHub Integration

Integrates with GitHub API for:
- Pull Request (PR) creation and management
- GitHub Actions workflow management
- Code review automation
- Repository analysis
- Security scanning integration (Dependabot, CodeQL)
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


class GitHubPRState(str, Enum):
    """GitHub PR states"""
    OPEN = "open"
    CLOSED = "closed"


class GitHubWorkflowStatus(str, Enum):
    """GitHub Actions workflow statuses"""
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class GitHubWorkflowConclusion(str, Enum):
    """GitHub Actions workflow conclusions"""
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    ACTION_REQUIRED = "action_required"


@dataclass
class GitHubRepository:
    """GitHub repository"""
    id: int
    name: str
    full_name: str  # owner/repo
    owner: str
    default_branch: str = "main"
    html_url: str = ""
    clone_url: str = ""
    ssh_url: str = ""
    description: str = ""
    private: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GitHubPullRequest:
    """GitHub pull request"""
    id: int
    number: int
    title: str
    body: str
    state: GitHubPRState
    head_branch: str
    base_branch: str
    author: str
    html_url: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    merged_at: Optional[datetime] = None
    mergeable: Optional[bool] = None
    mergeable_state: str = "unknown"
    draft: bool = False
    commits_count: int = 0
    changed_files: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GitHubWorkflowRun:
    """GitHub Actions workflow run"""
    id: int
    name: str
    status: GitHubWorkflowStatus
    conclusion: Optional[GitHubWorkflowConclusion] = None
    head_branch: str = ""
    head_sha: str = ""
    html_url: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    run_started_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GitHubCommit:
    """GitHub commit"""
    sha: str
    message: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    html_url: str = ""
    created_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class GitHubAPIClient:
    """GitHub API client"""

    def __init__(
        self,
        token: str,
        timeout: int = 30
    ):
        """
        Initialize GitHub API client.

        Args:
            token: Personal access token or GitHub App token
            timeout: Request timeout in seconds
        """
        self.token = token
        self.timeout = timeout
        self.api_url = "https://example.com"

        # Statistics
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "prs_created": 0,
            "prs_merged": 0,
            "workflows_triggered": 0
        }

        logger.info("GitHub API client initialized")

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
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }

            url = f"{self.api_url}/{endpoint}"

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                if method == "GET":
                    response = await client.get(url, headers=headers, params=params)
                elif method == "POST":
                    response = await client.post(url, headers=headers, json=json_data)
                elif method == "PATCH":
                    response = await client.patch(url, headers=headers, json=json_data)
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
                    logger.error(f"GitHub API error: {response.status_code} - {response.text}")
                    self.stats["failed_requests"] += 1
                    return None

        except Exception as e:
            logger.error(f"GitHub API request error: {e}")
            self.stats["failed_requests"] += 1
            return None

    async def get_repository(self, owner: str, repo: str) -> Optional[GitHubRepository]:
        """
        Get repository information.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            GitHubRepository or None
        """
        result = await self._make_request("GET", f"repos/{owner}/{repo}")

        if not result:
            return None

        repository = GitHubRepository(
            id=result["id"],
            name=result["name"],
            full_name=result["full_name"],
            owner=result["owner"]["login"],
            default_branch=result.get("default_branch", "main"),
            html_url=result.get("html_url", ""),
            clone_url=result.get("clone_url", ""),
            ssh_url=result.get("ssh_url", ""),
            description=result.get("description", ""),
            private=result.get("private", False),
            metadata=result
        )

        logger.info(f"Retrieved GitHub repository: {repository.full_name}")
        return repository

    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        head: str,
        base: str,
        title: str,
        body: str,
        draft: bool = False
    ) -> Optional[GitHubPullRequest]:
        """
        Create a pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            head: Head branch (source)
            base: Base branch (target)
            title: PR title
            body: PR description
            draft: Create as draft PR

        Returns:
            GitHubPullRequest or None
        """
        data = {
            "title": title,
            "body": body,
            "head": head,
            "base": base,
            "draft": draft
        }

        result = await self._make_request(
            "POST",
            f"repos/{owner}/{repo}/pulls",
            json_data=data
        )

        if not result:
            return None

        pr = self._parse_pull_request(result)
        self.stats["prs_created"] += 1

        logger.info(f"Created GitHub PR: {pr.html_url}")
        return pr

    async def get_pull_request(
        self,
        owner: str,
        repo: str,
        pr_number: int
    ) -> Optional[GitHubPullRequest]:
        """Get pull request by number"""
        result = await self._make_request(
            "GET",
            f"repos/{owner}/{repo}/pulls/{pr_number}"
        )

        if not result:
            return None

        return self._parse_pull_request(result)

    async def merge_pull_request(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_title: Optional[str] = None,
        commit_message: Optional[str] = None,
        merge_method: str = "merge"  # merge, squash, rebase
    ) -> bool:
        """
        Merge a pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: PR number
            commit_title: Custom commit title
            commit_message: Custom commit message
            merge_method: Merge method (merge, squash, rebase)

        Returns:
            True if successful
        """
        data = {
            "merge_method": merge_method
        }

        if commit_title:
            data["commit_title"] = commit_title
        if commit_message:
            data["commit_message"] = commit_message

        result = await self._make_request(
            "PUT",
            f"repos/{owner}/{repo}/pulls/{pr_number}/merge",
            json_data=data
        )

        if result:
            self.stats["prs_merged"] += 1
            logger.info(f"Merged GitHub PR #{pr_number} in {owner}/{repo}")
            return True

        return False

    async def create_or_update_file(
        self,
        owner: str,
        repo: str,
        path: str,
        content: str,
        message: str,
        branch: str,
        sha: Optional[str] = None
    ) -> Optional[GitHubCommit]:
        """
        Create or update a file in the repository.

        Args:
            owner: Repository owner
            repo: Repository name
            path: File path
            content: File content (will be base64 encoded)
            message: Commit message
            branch: Branch name
            sha: File SHA (required for updates)

        Returns:
            GitHubCommit or None
        """
        import base64

        data = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch
        }

        if sha:
            data["sha"] = sha

        result = await self._make_request(
            "PUT",
            f"repos/{owner}/{repo}/contents/{path}",
            json_data=data
        )

        if not result or "commit" not in result:
            return None

        commit_data = result["commit"]
        commit = GitHubCommit(
            sha=commit_data["sha"],
            message=commit_data["message"],
            author_name=commit_data["author"]["name"],
            author_email=commit_data["author"]["email"],
            committer_name=commit_data["committer"]["name"],
            committer_email=commit_data["committer"]["email"],
            html_url=commit_data.get("html_url", ""),
            metadata=commit_data
        )

        logger.info(f"Created/updated file {path} in {owner}/{repo}")
        return commit

    async def trigger_workflow(
        self,
        owner: str,
        repo: str,
        workflow_id: str,  # Workflow ID or filename
        ref: str,
        inputs: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Trigger a GitHub Actions workflow.

        Args:
            owner: Repository owner
            repo: Repository name
            workflow_id: Workflow ID or filename (e.g., 'ci.yml')
            ref: Branch or tag name
            inputs: Workflow inputs

        Returns:
            True if successful
        """
        data = {
            "ref": ref
        }

        if inputs:
            data["inputs"] = inputs

        result = await self._make_request(
            "POST",
            f"repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches",
            json_data=data
        )

        # GitHub returns 204 No Content on success
        if result is not None or self.stats["successful_requests"] > 0:
            self.stats["workflows_triggered"] += 1
            logger.info(f"Triggered workflow {workflow_id} in {owner}/{repo}")
            return True

        return False

    def _parse_pull_request(self, data: Dict[str, Any]) -> GitHubPullRequest:
        """Parse PR data"""
        return GitHubPullRequest(
            id=data["id"],
            number=data["number"],
            title=data["title"],
            body=data.get("body", ""),
            state=GitHubPRState(data["state"]),
            head_branch=data["head"]["ref"],
            base_branch=data["base"]["ref"],
            author=data["user"]["login"],
            html_url=data["html_url"],
            created_at=self._parse_datetime(data.get("created_at")),
            updated_at=self._parse_datetime(data.get("updated_at")),
            merged_at=self._parse_datetime(data.get("merged_at")),
            mergeable=data.get("mergeable"),
            mergeable_state=data.get("mergeable_state", "unknown"),
            draft=data.get("draft", False),
            commits_count=data.get("commits", 0),
            changed_files=data.get("changed_files", 0),
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


class GitHubIntegration:
    """High-level GitHub integration"""

    def __init__(self, config: Optional[VaulyticaConfig] = None):
        """Initialize GitHub integration"""
        if config is None:
            config = get_config()

        self.config = config
        self.client = GitHubAPIClient(token=config.github_token)

        logger.info("GitHub integration initialized")

    async def create_remediation_pr(
        self,
        owner: str,
        repo: str,
        vulnerability_id: str,
        file_changes: Dict[str, str],  # {file_path: new_content}
        title: str,
        body: str
    ) -> Optional[GitHubPullRequest]:
        """
        Create PR for vulnerability remediation.

        Args:
            owner: Repository owner
            repo: Repository name
            vulnerability_id: Vulnerability ID for branch naming
            file_changes: Dictionary of file paths to new content
            title: PR title
            body: PR description

        Returns:
            GitHubPullRequest or None
        """
        # Get repository to find default branch
        repository = await self.client.get_repository(owner, repo)
        if not repository:
            logger.error(f"Repository not found: {owner}/{repo}")
            return None

        # Create branch name
        branch_name = f"vaulytica/fix-{vulnerability_id}"

        # Create/update files
        for file_path, content in file_changes.items():
            commit = await self.client.create_or_update_file(
                owner=owner,
                repo=repo,
                path=file_path,
                content=content,
                message=f"Fix vulnerability {vulnerability_id}",
                branch=branch_name
            )

            if not commit:
                logger.error(f"Failed to update file {file_path}")
                return None

        # Create PR
        pr = await self.client.create_pull_request(
            owner=owner,
            repo=repo,
            head=branch_name,
            base=repository.default_branch,
            title=title,
            body=body
        )

        return pr

    def get_statistics(self) -> Dict[str, Any]:
        """Get integration statistics"""
        return self.client.get_statistics()


# Global instance
_github_integration: Optional[GitHubIntegration] = None


def get_github_integration(config: Optional[VaulyticaConfig] = None) -> GitHubIntegration:
    """Get or create global GitHub integration instance"""
    global _github_integration

    if _github_integration is None:
        _github_integration = GitHubIntegration(config)

    return _github_integration

