"""Auto-expire external sharing policies."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict, Any

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.scanners.file_scanner import FileInfo, FilePermission

logger = structlog.get_logger(__name__)


@dataclass
class ExpirationPolicy:
    """Policy for auto-expiring external shares."""

    name: str
    expiration_days: int
    grace_period_days: int = 7
    notify_before_expiry: bool = True
    exempted_domains: List[str] = field(default_factory=list)
    exempted_users: List[str] = field(default_factory=list)
    exempted_files: List[str] = field(default_factory=list)


@dataclass
class ExpirationAction:
    """Action taken for expiring a share."""

    file_id: str
    file_name: str
    permission_id: str
    permission_email: str
    permission_type: str
    shared_date: datetime
    days_shared: int
    action: str  # notify, expire, exempt
    status: str = "pending"  # pending, success, failed
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ExpirationReport:
    """Report of expiration actions."""

    policy_name: str
    scan_time: datetime
    files_scanned: int = 0
    shares_expired: int = 0
    shares_notified: int = 0
    shares_exempted: int = 0
    actions: List[ExpirationAction] = field(default_factory=list)


class ExpirationError(Exception):
    """Raised when expiration processing fails."""

    pass


class ExpirationManager:
    """Manages auto-expiration of external shares."""

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        domain: str,
        dry_run: bool = True,
    ):
        """Initialize expiration manager.

        Args:
            client: GoogleWorkspaceClient instance
            domain: Organization domain
            dry_run: If True, don't make actual changes (default: True for safety)
        """
        self.client = client
        self.domain = domain
        self.dry_run = dry_run

        logger.info(
            "expiration_manager_initialized",
            domain=domain,
            dry_run=dry_run,
        )

    def apply_policy(
        self,
        policy: ExpirationPolicy,
        files: List[FileInfo],
    ) -> ExpirationReport:
        """Apply expiration policy to files.

        Args:
            policy: ExpirationPolicy to apply
            files: List of FileInfo objects to process

        Returns:
            ExpirationReport with actions taken
        """
        logger.info(
            "applying_expiration_policy",
            policy_name=policy.name,
            file_count=len(files),
        )

        report = ExpirationReport(
            policy_name=policy.name,
            scan_time=datetime.now(timezone.utc),
            files_scanned=len(files),
        )

        now = datetime.now(timezone.utc)
        expiration_threshold = now - timedelta(days=policy.expiration_days)
        notification_threshold = now - timedelta(
            days=policy.expiration_days - policy.grace_period_days
        )

        for file_info in files:
            # Skip files without external shares
            if not file_info.is_shared_externally:
                continue

            # Process each external permission
            for permission in file_info.permissions:
                # Skip owner permissions
                if permission.role == "owner":
                    continue

                # Check if external
                is_external = self._is_external_permission(permission)
                if not is_external:
                    continue

                # Check if exempted
                if self._is_exempted(file_info, permission, policy):
                    action = ExpirationAction(
                        file_id=file_info.id,
                        file_name=file_info.name,
                        permission_id=permission.id,
                        permission_email=permission.email_address or permission.domain or "anyone",
                        permission_type=permission.type,
                        shared_date=file_info.modified_time,  # Approximation
                        days_shared=(now - file_info.modified_time).days,
                        action="exempt",
                        status="success",
                    )
                    report.actions.append(action)
                    report.shares_exempted += 1
                    continue

                # Calculate days shared (using modified time as approximation)
                days_shared = (now - file_info.modified_time).days

                # Determine action
                if file_info.modified_time <= expiration_threshold:
                    # Expire the share
                    action = self._expire_permission(file_info, permission, days_shared)
                    report.actions.append(action)
                    if action.status == "success":
                        report.shares_expired += 1

                elif (
                    policy.notify_before_expiry
                    and file_info.modified_time <= notification_threshold
                ):
                    # Notify about upcoming expiration
                    action = self._notify_expiration(file_info, permission, days_shared, policy)
                    report.actions.append(action)
                    if action.status == "success":
                        report.shares_notified += 1

        logger.info(
            "expiration_policy_applied",
            policy_name=policy.name,
            shares_expired=report.shares_expired,
            shares_notified=report.shares_notified,
            shares_exempted=report.shares_exempted,
        )

        return report

    def _is_external_permission(self, permission: FilePermission) -> bool:
        """Check if permission is external.

        Args:
            permission: FilePermission to check

        Returns:
            True if external, False otherwise
        """
        if permission.type == "anyone":
            return True

        if permission.type == "user" and permission.email_address:
            email_domain = permission.email_address.split("@")[-1]
            return email_domain != self.domain

        if permission.type == "domain" and permission.domain:
            return permission.domain != self.domain

        return False

    def _is_exempted(
        self,
        file_info: FileInfo,
        permission: FilePermission,
        policy: ExpirationPolicy,
    ) -> bool:
        """Check if file/permission is exempted from policy.

        Args:
            file_info: FileInfo object
            permission: FilePermission object
            policy: ExpirationPolicy

        Returns:
            True if exempted, False otherwise
        """
        # Check file exemption
        if file_info.id in policy.exempted_files:
            return True

        # Check user exemption
        if permission.email_address and permission.email_address in policy.exempted_users:
            return True

        # Check domain exemption
        if permission.email_address:
            email_domain = permission.email_address.split("@")[-1]
            if email_domain in policy.exempted_domains:
                return True

        if permission.domain and permission.domain in policy.exempted_domains:
            return True

        return False

    def _expire_permission(
        self,
        file_info: FileInfo,
        permission: FilePermission,
        days_shared: int,
    ) -> ExpirationAction:
        """Expire a permission.

        Args:
            file_info: FileInfo object
            permission: FilePermission to expire
            days_shared: Number of days the file has been shared

        Returns:
            ExpirationAction with result
        """
        action = ExpirationAction(
            file_id=file_info.id,
            file_name=file_info.name,
            permission_id=permission.id,
            permission_email=permission.email_address or permission.domain or "anyone",
            permission_type=permission.type,
            shared_date=file_info.modified_time,
            days_shared=days_shared,
            action="expire",
        )

        if self.dry_run:
            action.status = "success"
            logger.info(
                "dry_run_expire_permission",
                file_id=file_info.id,
                permission_id=permission.id,
            )
            return action

        try:
            self.client.drive.permissions().delete(
                fileId=file_info.id,
                permissionId=permission.id,
            ).execute()

            action.status = "success"
            logger.info(
                "permission_expired",
                file_id=file_info.id,
                permission_id=permission.id,
            )

        except Exception as e:
            action.status = "failed"
            action.error_message = str(e)
            logger.error(
                "expire_permission_failed",
                file_id=file_info.id,
                permission_id=permission.id,
                error=str(e),
            )

        return action

    def _notify_expiration(
        self,
        file_info: FileInfo,
        permission: FilePermission,
        days_shared: int,
        policy: ExpirationPolicy,
    ) -> ExpirationAction:
        """Notify about upcoming expiration.

        Args:
            file_info: FileInfo object
            permission: FilePermission
            days_shared: Number of days shared
            policy: ExpirationPolicy

        Returns:
            ExpirationAction with result
        """
        action = ExpirationAction(
            file_id=file_info.id,
            file_name=file_info.name,
            permission_id=permission.id,
            permission_email=permission.email_address or permission.domain or "anyone",
            permission_type=permission.type,
            shared_date=file_info.modified_time,
            days_shared=days_shared,
            action="notify",
        )

        # Implement notification via Drive API comment
        # Add a comment to the file notifying about upcoming expiration
        try:
            days_until_expiry = policy.expiration_days - days_shared
            comment_text = (
                f"⚠️ External Sharing Expiration Notice\n\n"
                f"This file is shared with {action.permission_email} and will expire in {days_until_expiry} days "
                f"according to the '{policy.name}' policy.\n\n"
                f"If you need to extend this sharing, please contact your administrator."
            )

            # Add comment to file using Drive API
            self.client.drive_service.comments().create(
                fileId=file_info.id,
                body={
                    "content": comment_text,
                },
                fields="id,content,createdTime",
            ).execute()

            action.status = "success"
            logger.info(
                "expiration_notification_sent",
                file_id=file_info.id,
                permission_email=action.permission_email,
                days_until_expiry=days_until_expiry,
            )
        except Exception as e:
            action.status = "failed"
            action.error_message = str(e)
            logger.error(
                "expiration_notification_failed",
                file_id=file_info.id,
                error=str(e),
            )

        return action

