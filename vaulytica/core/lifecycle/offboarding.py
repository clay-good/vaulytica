"""Employee offboarding automation."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.scanners.user_scanner import UserInfo
from vaulytica.core.scanners.file_scanner import FileInfo

logger = structlog.get_logger(__name__)


@dataclass
class OffboardingAction:
    """Represents an action taken during offboarding."""

    action_type: str  # transfer_ownership, revoke_share, delete_file
    file_id: str
    file_name: str
    from_user: str
    to_user: Optional[str] = None
    status: str = "pending"  # pending, success, failed
    error_message: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class OffboardingReport:
    """Report of offboarding actions."""

    user_email: str
    user_name: str
    manager_email: Optional[str]
    offboarding_time: datetime
    files_found: int = 0
    files_transferred: int = 0
    shares_revoked: int = 0
    actions: List[OffboardingAction] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class OffboardingError(Exception):
    """Raised when offboarding fails."""

    pass


class OffboardingManager:
    """Manages employee offboarding automation."""

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        domain: str,
        dry_run: bool = True,
    ):
        """Initialize offboarding manager.

        Args:
            client: GoogleWorkspaceClient instance
            domain: Organization domain
            dry_run: If True, don't make actual changes (default: True for safety)
        """
        self.client = client
        self.domain = domain
        self.dry_run = dry_run

        logger.info(
            "offboarding_manager_initialized",
            domain=domain,
            dry_run=dry_run,
        )

    def offboard_user(
        self,
        user_email: str,
        transfer_to: Optional[str] = None,
        revoke_external_shares: bool = True,
        transfer_ownership: bool = True,
    ) -> OffboardingReport:
        """Offboard a user.

        Args:
            user_email: Email of user to offboard
            transfer_to: Email to transfer files to (defaults to manager)
            revoke_external_shares: Whether to revoke external shares
            transfer_ownership: Whether to transfer file ownership

        Returns:
            OffboardingReport with actions taken

        Raises:
            OffboardingError: If offboarding fails
        """
        logger.info(
            "starting_offboarding",
            user_email=user_email,
            transfer_to=transfer_to,
            dry_run=self.dry_run,
        )

        # Get user info
        from vaulytica.core.scanners.user_scanner import UserScanner

        user_scanner = UserScanner(self.client, self.domain)
        user_info = user_scanner.get_user_by_email(user_email)

        if not user_info:
            raise OffboardingError(f"User not found: {user_email}")

        # Determine transfer recipient
        if not transfer_to:
            transfer_to = user_info.manager_email

        if not transfer_to:
            raise OffboardingError(
                f"No transfer recipient specified and no manager found for {user_email}"
            )

        # Create report
        report = OffboardingReport(
            user_email=user_email,
            user_name=user_info.full_name,
            manager_email=user_info.manager_email,
            offboarding_time=datetime.now(timezone.utc),
        )

        # Get all files owned by user
        files = self._get_user_files(user_email)
        report.files_found = len(files)

        logger.info("files_found", user_email=user_email, file_count=len(files))

        # Process each file
        for file_info in files:
            # Revoke external shares if requested
            if revoke_external_shares and file_info.is_shared_externally:
                action = self._revoke_external_shares(file_info)
                report.actions.append(action)
                if action.status == "success":
                    report.shares_revoked += 1

            # Transfer ownership if requested
            if transfer_ownership:
                action = self._transfer_file_ownership(file_info, user_email, transfer_to)
                report.actions.append(action)
                if action.status == "success":
                    report.files_transferred += 1

        logger.info(
            "offboarding_complete",
            user_email=user_email,
            files_transferred=report.files_transferred,
            shares_revoked=report.shares_revoked,
        )

        return report

    def _get_user_files(self, user_email: str) -> List[FileInfo]:
        """Get all files owned by a user.

        Args:
            user_email: User email

        Returns:
            List of FileInfo objects
        """
        from vaulytica.core.scanners.file_scanner import FileScanner

        scanner = FileScanner(self.client, self.domain)

        # Query for files owned by user
        files = []
        page_token = None

        try:
            while True:
                results = (
                    self.client.drive.files()
                    .list(
                        q=f"'{user_email}' in owners and trashed=false",
                        pageSize=100,
                        pageToken=page_token,
                        fields="nextPageToken, files(id, name, mimeType, owners, createdTime, modifiedTime, permissions)",
                        supportsAllDrives=True,
                        includeItemsFromAllDrives=True,
                    )
                    .execute()
                )

                for file_data in results.get("files", []):
                    file_info = scanner._process_file(file_data)
                    files.append(file_info)

                page_token = results.get("nextPageToken")
                if not page_token:
                    break

        except Exception as e:
            logger.error("failed_to_get_user_files", user_email=user_email, error=str(e))
            raise OffboardingError(f"Failed to get user files: {e}")

        return files

    def _transfer_file_ownership(
        self, file_info: FileInfo, from_user: str, to_user: str
    ) -> OffboardingAction:
        """Transfer file ownership.

        Args:
            file_info: FileInfo object
            from_user: Current owner email
            to_user: New owner email

        Returns:
            OffboardingAction with result
        """
        action = OffboardingAction(
            action_type="transfer_ownership",
            file_id=file_info.id,
            file_name=file_info.name,
            from_user=from_user,
            to_user=to_user,
        )

        if self.dry_run:
            action.status = "success"
            logger.info(
                "dry_run_transfer_ownership",
                file_id=file_info.id,
                from_user=from_user,
                to_user=to_user,
            )
            return action

        try:
            # Add new owner as writer first
            self.client.drive.permissions().create(
                fileId=file_info.id,
                body={
                    "type": "user",
                    "role": "writer",
                    "emailAddress": to_user,
                },
                transferOwnership=False,
            ).execute()

            # Transfer ownership
            self.client.drive.permissions().create(
                fileId=file_info.id,
                body={
                    "type": "user",
                    "role": "owner",
                    "emailAddress": to_user,
                },
                transferOwnership=True,
            ).execute()

            action.status = "success"
            logger.info(
                "ownership_transferred",
                file_id=file_info.id,
                from_user=from_user,
                to_user=to_user,
            )

        except Exception as e:
            action.status = "failed"
            action.error_message = str(e)
            logger.error(
                "ownership_transfer_failed",
                file_id=file_info.id,
                error=str(e),
            )

        return action

    def _revoke_external_shares(self, file_info: FileInfo) -> OffboardingAction:
        """Revoke external shares on a file.

        Args:
            file_info: FileInfo object

        Returns:
            OffboardingAction with result
        """
        action = OffboardingAction(
            action_type="revoke_share",
            file_id=file_info.id,
            file_name=file_info.name,
            from_user=file_info.owner_email,
        )

        if self.dry_run:
            action.status = "success"
            logger.info("dry_run_revoke_shares", file_id=file_info.id)
            return action

        try:
            # Revoke external permissions
            for permission in file_info.permissions:
                # Skip owner permissions
                if permission.role == "owner":
                    continue

                # Check if external
                is_external = False
                if permission.type == "anyone":
                    is_external = True
                elif permission.type == "user" and permission.email_address:
                    email_domain = permission.email_address.split("@")[-1]
                    if email_domain != self.domain:
                        is_external = True
                elif permission.type == "domain" and permission.domain:
                    if permission.domain != self.domain:
                        is_external = True

                if is_external:
                    self.client.drive.permissions().delete(
                        fileId=file_info.id,
                        permissionId=permission.id,
                    ).execute()

                    logger.info(
                        "permission_revoked",
                        file_id=file_info.id,
                        permission_id=permission.id,
                    )

            action.status = "success"

        except Exception as e:
            action.status = "failed"
            action.error_message = str(e)
            logger.error("revoke_shares_failed", file_id=file_info.id, error=str(e))

        return action

