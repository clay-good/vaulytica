"""Group scanner for detecting security issues in Google Groups."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
import time
import structlog
from googleapiclient.errors import HttpError

logger = structlog.get_logger(__name__)


@dataclass
class GroupMember:
    """Represents a group member."""

    email: str
    role: str  # OWNER, MANAGER, MEMBER
    type: str  # USER, GROUP, CUSTOMER
    status: str = "ACTIVE"


@dataclass
class GroupInfo:
    """Represents a Google Group."""

    id: str
    email: str
    name: str
    description: str = ""
    direct_members_count: int = 0
    members: List[GroupMember] = field(default_factory=list)
    settings: Dict = field(default_factory=dict)
    external_members: List[GroupMember] = field(default_factory=list)
    nested_groups: List[str] = field(default_factory=list)
    is_public: bool = False
    is_orphaned: bool = False
    risk_score: int = 0


@dataclass
class GroupScanResult:
    """Results from a group security scan."""

    total_groups: int = 0
    groups_with_external_members: int = 0
    public_groups: int = 0
    orphaned_groups: int = 0
    groups: List[GroupInfo] = field(default_factory=list)
    issues: List[Dict] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)


class GroupScanner:
    """Scanner for Google Groups security issues."""

    def __init__(self, client, domain: str):
        """Initialize the group scanner.

        Args:
            client: Authenticated Google Workspace client
            domain: Primary domain to scan
        """
        self.client = client
        self.domain = domain
        self.logger = logger.bind(scanner="group", domain=domain)

    def scan_all_groups(
        self,
        include_members: bool = True,
        max_groups: Optional[int] = None
    ) -> GroupScanResult:
        """Scan all groups in the domain with enhanced performance.

        Args:
            include_members: Whether to fetch member details for each group
            max_groups: Maximum number of groups to scan (for performance testing)

        Returns:
            GroupScanResult with all findings

        Raises:
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_groups is not None and (not isinstance(max_groups, int) or max_groups < 1):
            raise ValueError("max_groups must be a positive integer")

        self.logger.info(
            "starting_group_scan",
            include_members=include_members,
            max_groups=max_groups
        )
        scan_start_time = time.time()
        result = GroupScanResult()
        failed_groups = []

        try:
            # List all groups in the domain
            groups = self._list_all_groups()

            # Apply max_groups limit if specified
            if max_groups:
                groups = groups[:max_groups]
                self.logger.info("limiting_scan_to_max_groups", max_groups=max_groups)

            result.total_groups = len(groups)

            self.logger.info("groups_found", count=len(groups))

            # Scan each group
            scanned_count = 0
            for group_data in groups:
                try:
                    group_info = self._scan_group(group_data, include_members)
                    result.groups.append(group_info)
                    scanned_count += 1

                    # Track statistics
                    if group_info.external_members:
                        result.groups_with_external_members += 1
                    if group_info.is_public:
                        result.public_groups += 1
                    if group_info.is_orphaned:
                        result.orphaned_groups += 1

                    # Log progress every 50 groups
                    if scanned_count % 50 == 0:
                        self.logger.info(
                            "group_scan_progress",
                            scanned=scanned_count,
                            total=len(groups),
                            external_members=result.groups_with_external_members,
                            public=result.public_groups
                        )

                except Exception as e:
                    self.logger.warning(
                        "failed_to_scan_group",
                        group_email=group_data.get("email", "unknown"),
                        error=str(e)
                    )
                    failed_groups.append({
                        "email": group_data.get("email", "unknown"),
                        "error": str(e)
                    })
                    continue

            # Generate issues list
            result.issues = self._generate_issues(result.groups)

            # Calculate statistics
            result.statistics = self._calculate_statistics(result)

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            self.logger.info(
                "group_scan_complete",
                total_groups=result.total_groups,
                external_members=result.groups_with_external_members,
                public_groups=result.public_groups,
                orphaned_groups=result.orphaned_groups,
                failed_groups=len(failed_groups),
                scan_duration_seconds=round(scan_duration, 2),
            )

            # Log warning if many groups failed
            if failed_groups and len(failed_groups) > 5:
                self.logger.warning(
                    "many_groups_failed_scan",
                    failed_count=len(failed_groups),
                    sample_errors=failed_groups[:3]
                )

        except Exception as e:
            self.logger.error("group_scan_failed", error=str(e))
            raise

        return result

    def _list_all_groups(self) -> List[Dict]:
        """List all groups in the domain."""
        groups = []
        page_token = None

        try:
            while True:
                response = (
                    self.client.admin.groups()
                    .list(domain=self.domain, pageToken=page_token, maxResults=200)
                    .execute()
                )

                groups.extend(response.get("groups", []))

                page_token = response.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            self.logger.error("failed_to_list_groups", error=str(e))
            raise

        return groups

    def _scan_group(self, group_data: Dict, include_members: bool) -> GroupInfo:
        """Scan a single group for security issues."""
        group_email = group_data.get("email", "")
        group_id = group_data.get("id", "")

        self.logger.debug("scanning_group", email=group_email)

        group_info = GroupInfo(
            id=group_id,
            email=group_email,
            name=group_data.get("name", ""),
            description=group_data.get("description", ""),
            direct_members_count=group_data.get("directMembersCount", 0),
        )

        # Get group settings
        try:
            settings = self._get_group_settings(group_email)
            group_info.settings = settings
            group_info.is_public = self._is_group_public(settings)
        except Exception as e:
            self.logger.warning("failed_to_get_settings", group=group_email, error=str(e))

        # Get members if requested
        if include_members:
            try:
                members = self._get_group_members(group_id)
                group_info.members = members

                # Detect external members
                group_info.external_members = self._detect_external_members(members)

                # Detect nested groups
                group_info.nested_groups = [
                    m.email for m in members if m.type == "GROUP"
                ]

                # Check if orphaned (no owners)
                owners = [m for m in members if m.role == "OWNER"]
                group_info.is_orphaned = len(owners) == 0

            except Exception as e:
                self.logger.warning("failed_to_get_members", group=group_email, error=str(e))

        # Calculate risk score
        group_info.risk_score = self._calculate_group_risk_score(group_info)

        return group_info

    def _get_group_settings(self, group_email: str) -> Dict:
        """Get group settings (requires Groups Settings API)."""
        # Note: This requires the Groups Settings API to be enabled
        # For now, return empty dict - can be enhanced later
        return {}

    def _get_group_members(self, group_id: str) -> List[GroupMember]:
        """Get all members of a group."""
        members = []
        page_token = None

        try:
            while True:
                response = (
                    self.client.admin.members()
                    .list(groupKey=group_id, pageToken=page_token, maxResults=200)
                    .execute()
                )

                for member_data in response.get("members", []):
                    member = GroupMember(
                        email=member_data.get("email", ""),
                        role=member_data.get("role", "MEMBER"),
                        type=member_data.get("type", "USER"),
                        status=member_data.get("status", "ACTIVE"),
                    )
                    members.append(member)

                page_token = response.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            self.logger.error("failed_to_list_members", group_id=group_id, error=str(e))
            raise

        return members

    def _detect_external_members(self, members: List[GroupMember]) -> List[GroupMember]:
        """Detect members from outside the domain."""
        external = []

        for member in members:
            if member.type == "USER" and not member.email.endswith(f"@{self.domain}"):
                external.append(member)

        return external

    def _is_group_public(self, settings: Dict) -> bool:
        """Check if group allows anyone to join."""
        # Check common settings that indicate public access
        who_can_join = settings.get("whoCanJoin", "")
        return who_can_join in ["ANYONE_CAN_JOIN", "ALL_IN_DOMAIN_CAN_JOIN"]

    def _calculate_group_risk_score(self, group: GroupInfo) -> int:
        """Calculate risk score for a group (0-100)."""
        score = 0

        # External members add risk
        if group.external_members:
            score += min(30, len(group.external_members) * 5)

        # Public groups are high risk
        if group.is_public:
            score += 40

        # Orphaned groups are risky
        if group.is_orphaned:
            score += 20

        # Nested groups add complexity
        if group.nested_groups:
            score += min(10, len(group.nested_groups) * 2)

        return min(100, score)

    def _generate_issues(self, groups: List[GroupInfo]) -> List[Dict]:
        """Generate list of security issues found."""
        issues = []

        for group in groups:
            if group.external_members:
                issues.append(
                    {
                        "type": "external_members",
                        "severity": "high" if len(group.external_members) > 5 else "medium",
                        "group": group.email,
                        "description": f"Group has {len(group.external_members)} external members",
                        "external_members": [m.email for m in group.external_members],
                        "risk_score": group.risk_score,
                    }
                )

            if group.is_public:
                issues.append(
                    {
                        "type": "public_group",
                        "severity": "critical",
                        "group": group.email,
                        "description": "Group allows anyone to join",
                        "risk_score": group.risk_score,
                    }
                )

            if group.is_orphaned:
                issues.append(
                    {
                        "type": "orphaned_group",
                        "severity": "high",
                        "group": group.email,
                        "description": "Group has no owners",
                        "risk_score": group.risk_score,
                    }
                )

        return issues

    def _calculate_statistics(self, result: GroupScanResult) -> Dict:
        """Calculate summary statistics."""
        return {
            "total_groups": result.total_groups,
            "groups_with_external_members": result.groups_with_external_members,
            "public_groups": result.public_groups,
            "orphaned_groups": result.orphaned_groups,
            "total_issues": len(result.issues),
            "critical_issues": len([i for i in result.issues if i["severity"] == "critical"]),
            "high_issues": len([i for i in result.issues if i["severity"] == "high"]),
            "medium_issues": len([i for i in result.issues if i["severity"] == "medium"]),
        }

