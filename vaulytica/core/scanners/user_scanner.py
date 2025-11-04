"""Google Workspace user scanner for detecting inactive users and security issues."""

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any, Iterator

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient

logger = structlog.get_logger(__name__)


@dataclass
class UserInfo:
    """Represents a Google Workspace user."""

    id: str
    email: str
    full_name: str
    is_admin: bool
    is_suspended: bool
    is_archived: bool
    creation_time: datetime
    last_login_time: Optional[datetime] = None
    org_unit_path: str = "/"
    manager_email: Optional[str] = None
    is_delegated_admin: bool = False
    two_factor_enabled: bool = False
    days_since_last_login: Optional[int] = None
    is_inactive: bool = False


@dataclass
class UserScanResult:
    """Results from user scanning."""

    total_users: int = 0
    active_users: int = 0
    inactive_users: int = 0
    suspended_users: int = 0
    admin_users: int = 0
    users: List[UserInfo] = field(default_factory=list)


class UserScannerError(Exception):
    """Raised when user scanning fails."""

    pass


class UserScanner:
    """Scans Google Workspace users for security and lifecycle issues."""

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        domain: str,
        inactive_threshold_days: int = 90,
    ):
        """Initialize user scanner.

        Args:
            client: GoogleWorkspaceClient instance
            domain: Organization domain
            inactive_threshold_days: Days of inactivity to consider user inactive
        """
        self.client = client
        self.domain = domain
        self.inactive_threshold_days = inactive_threshold_days

        logger.info(
            "user_scanner_initialized",
            domain=domain,
            inactive_threshold_days=inactive_threshold_days,
        )

    def scan_all_users(
        self,
        max_users: Optional[int] = None,
        org_unit: Optional[str] = None
    ) -> UserScanResult:
        """Scan all users in the domain with enhanced filtering and performance.

        Args:
            max_users: Maximum number of users to scan (for performance testing)
            org_unit: Filter by organizational unit path

        Returns:
            UserScanResult with all users

        Raises:
            UserScannerError: If scanning fails
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_users is not None and (not isinstance(max_users, int) or max_users < 1):
            raise ValueError("max_users must be a positive integer")
        if org_unit and not isinstance(org_unit, str):
            raise ValueError("org_unit must be a string")

        logger.info(
            "starting_user_scan",
            max_users=max_users,
            org_unit=org_unit
        )
        scan_start_time = time.time()

        result = UserScanResult()
        failed_users = []
        scanned_count = 0

        try:
            page_token = None

            while True:
                try:
                    # Build request parameters
                    request_params = {
                        "domain": self.domain,
                        "maxResults": 500,
                        "pageToken": page_token,
                        "projection": "full",
                        "orderBy": "email",
                    }

                    # Add org unit filter if specified
                    if org_unit:
                        request_params["query"] = f"orgUnitPath='{org_unit}'"

                    # Fetch users
                    response = (
                        self.client.admin.users()
                        .list(**request_params)
                        .execute()
                    )

                    users = response.get("users", [])

                    for user_data in users:
                        try:
                            user_info = self._process_user(user_data)
                            result.users.append(user_info)
                            result.total_users += 1
                            scanned_count += 1

                            if user_info.is_suspended:
                                result.suspended_users += 1
                            elif user_info.is_inactive:
                                result.inactive_users += 1
                            else:
                                result.active_users += 1

                            if user_info.is_admin:
                                result.admin_users += 1

                            # Log progress every 100 users
                            if scanned_count % 100 == 0:
                                logger.info(
                                    "user_scan_progress",
                                    scanned=scanned_count,
                                    active=result.active_users,
                                    inactive=result.inactive_users,
                                    suspended=result.suspended_users
                                )

                            # Check max_users limit
                            if max_users and scanned_count >= max_users:
                                logger.info("max_users_limit_reached", max_users=max_users)
                                break

                        except Exception as e:
                            logger.warning(
                                "failed_to_process_user",
                                user_email=user_data.get("primaryEmail", "unknown"),
                                error=str(e)
                            )
                            failed_users.append({
                                "email": user_data.get("primaryEmail", "unknown"),
                                "error": str(e)
                            })
                            continue

                    # Check if we hit max_users limit
                    if max_users and scanned_count >= max_users:
                        break

                    page_token = response.get("nextPageToken")
                    if not page_token:
                        break

                    time.sleep(0.1)  # Rate limiting

                except HttpError as e:
                    if e.resp.status == 429:  # Rate limit
                        logger.warning("rate_limit_hit_retrying")
                        time.sleep(5)
                        continue
                    elif e.resp.status == 403:
                        logger.error("insufficient_permissions_to_list_users", error=str(e))
                        raise UserScannerError(f"Insufficient permissions: {e}")
                    else:
                        logger.error("http_error_listing_users", error=str(e))
                        raise UserScannerError(f"Failed to list users: {e}")

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            logger.info(
                "user_scan_complete",
                total_users=result.total_users,
                active=result.active_users,
                inactive=result.inactive_users,
                suspended=result.suspended_users,
                admins=result.admin_users,
                failed_users=len(failed_users),
                scan_duration_seconds=round(scan_duration, 2),
            )

            # Log warning if many users failed
            if failed_users and len(failed_users) > 10:
                logger.warning(
                    "many_users_failed_processing",
                    failed_count=len(failed_users),
                    sample_errors=failed_users[:5]
                )

            return result

        except Exception as e:
            logger.error("user_scan_failed", error=str(e))
            raise UserScannerError(f"User scan failed: {e}")

    def get_suspended_users(self) -> List[UserInfo]:
        """Get all suspended users.

        Returns:
            List of suspended UserInfo objects
        """
        logger.info("fetching_suspended_users")

        try:
            response = (
                self.client.admin.users()
                .list(
                    domain=self.domain,
                    maxResults=500,
                    query="isSuspended=true",
                    projection="full",
                )
                .execute()
            )

            users = response.get("users", [])
            suspended_users = [self._process_user(user_data) for user_data in users]

            logger.info("suspended_users_fetched", count=len(suspended_users))
            return suspended_users

        except Exception as e:
            logger.error("failed_to_fetch_suspended_users", error=str(e))
            raise UserScannerError(f"Failed to fetch suspended users: {e}")

    def get_user_by_email(self, email: str) -> Optional[UserInfo]:
        """Get user information by email.

        Args:
            email: User email address

        Returns:
            UserInfo object or None if not found
        """
        try:
            user_data = self.client.admin.users().get(userKey=email).execute()
            return self._process_user(user_data)

        except HttpError as e:
            if e.resp.status == 404:
                logger.warning("user_not_found", email=email)
                return None
            raise

    def _process_user(self, user_data: Dict[str, Any]) -> UserInfo:
        """Process raw user data into UserInfo object.

        Args:
            user_data: Raw user data from Admin SDK

        Returns:
            UserInfo object
        """
        # Parse timestamps
        creation_time = datetime.fromisoformat(
            user_data.get("creationTime", "").replace("Z", "+00:00")
        )

        last_login_time = None
        last_login_str = user_data.get("lastLoginTime")
        if last_login_str:
            last_login_time = datetime.fromisoformat(last_login_str.replace("Z", "+00:00"))

        # Calculate days since last login
        days_since_last_login = None
        is_inactive = False

        if last_login_time:
            days_since_last_login = (datetime.now(timezone.utc) - last_login_time).days
            is_inactive = days_since_last_login >= self.inactive_threshold_days

        # Get manager email (if available)
        manager_email = None
        relations = user_data.get("relations", [])
        for relation in relations:
            if relation.get("type") == "manager":
                manager_email = relation.get("value")
                break

        # Check 2FA status
        two_factor_enabled = user_data.get("isEnrolledIn2Sv", False)

        user_info = UserInfo(
            id=user_data.get("id", ""),
            email=user_data.get("primaryEmail", ""),
            full_name=user_data.get("name", {}).get("fullName", ""),
            is_admin=user_data.get("isAdmin", False),
            is_suspended=user_data.get("suspended", False),
            is_archived=user_data.get("archived", False),
            creation_time=creation_time,
            last_login_time=last_login_time,
            org_unit_path=user_data.get("orgUnitPath", "/"),
            manager_email=manager_email,
            is_delegated_admin=user_data.get("isDelegatedAdmin", False),
            two_factor_enabled=two_factor_enabled,
            days_since_last_login=days_since_last_login,
            is_inactive=is_inactive,
        )

        return user_info

