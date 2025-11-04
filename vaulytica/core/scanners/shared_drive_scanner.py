"""Shared Drive scanner for Google Workspace."""

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Iterator

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.scanners.file_scanner import FileInfo, FileScanner

logger = structlog.get_logger(__name__)


@dataclass
class SharedDriveInfo:
    """Represents a Shared Drive."""

    id: str
    name: str
    created_time: datetime
    hidden: bool = False
    restrictions: Dict[str, Any] = field(default_factory=dict)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    member_count: int = 0
    file_count: int = 0
    external_member_count: int = 0


@dataclass
class SharedDriveScanResult:
    """Results from Shared Drive scanning."""

    total_drives: int = 0
    drives_with_external_members: int = 0
    drives_with_external_files: int = 0
    total_files_scanned: int = 0
    files_with_issues: int = 0
    drives: List[SharedDriveInfo] = field(default_factory=list)
    files: List[FileInfo] = field(default_factory=list)


class SharedDriveScannerError(Exception):
    """Raised when Shared Drive scanning fails."""

    pass


class SharedDriveScanner:
    """Scans Shared Drives for security issues."""

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        domain: str,
    ):
        """Initialize Shared Drive scanner.

        Args:
            client: GoogleWorkspaceClient instance
            domain: Organization domain
        """
        self.client = client
        self.domain = domain
        self.file_scanner = FileScanner(client, domain)

        logger.info("shared_drive_scanner_initialized", domain=domain)

    def scan_all_shared_drives(
        self,
        scan_files: bool = True,
        external_only: bool = False,
        max_drives: Optional[int] = None,
    ) -> SharedDriveScanResult:
        """Scan all Shared Drives with enhanced performance.

        Args:
            scan_files: Whether to scan files within Shared Drives
            external_only: Only scan files shared externally
            max_drives: Maximum number of drives to scan (for performance testing)

        Returns:
            SharedDriveScanResult with scan results

        Raises:
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_drives is not None and (not isinstance(max_drives, int) or max_drives < 1):
            raise ValueError("max_drives must be a positive integer")

        logger.info(
            "starting_shared_drive_scan",
            scan_files=scan_files,
            external_only=external_only,
            max_drives=max_drives,
        )
        scan_start_time = time.time()

        result = SharedDriveScanResult()
        failed_drives = []

        # Get all Shared Drives
        drives = list(self._list_shared_drives(max_drives=max_drives))
        result.total_drives = len(drives)
        result.drives = drives

        logger.info("shared_drives_found", count=len(drives))

        # Scan files in each drive if requested
        if scan_files:
            drive_count = 0
            for drive in drives:
                try:
                    logger.info("scanning_shared_drive", drive_name=drive.name, drive_id=drive.id)

                    # Scan files in this drive
                    files = list(
                        self._scan_drive_files(
                            drive.id,
                            external_only=external_only,
                        )
                    )

                    result.total_files_scanned += len(files)

                    # Check for issues
                    files_with_issues = [
                        f for f in files if f.is_shared_externally or f.is_public
                    ]

                    if files_with_issues:
                        result.drives_with_external_files += 1
                        result.files_with_issues += len(files_with_issues)
                        result.files.extend(files_with_issues)

                    drive_count += 1

                    # Log progress every 5 drives
                    if drive_count % 5 == 0:
                        logger.info(
                            "shared_drive_progress",
                            scanned=drive_count,
                            total_files=result.total_files_scanned,
                            files_with_issues=result.files_with_issues,
                        )

                except Exception as e:
                    logger.warning(
                        "failed_to_scan_drive",
                        drive_id=drive.id,
                        drive_name=drive.name,
                        error=str(e)
                    )
                    failed_drives.append({
                        "drive_id": drive.id,
                        "drive_name": drive.name,
                        "error": str(e)
                    })
                    continue

        # Calculate scan duration
        scan_duration = time.time() - scan_start_time

        logger.info(
            "shared_drive_scan_complete",
            total_drives=result.total_drives,
            files_scanned=result.total_files_scanned,
            files_with_issues=result.files_with_issues,
            failed_drives=len(failed_drives),
            scan_duration_seconds=round(scan_duration, 2),
        )

        # Log warning if many drives failed
        if failed_drives and len(failed_drives) > 3:
            logger.warning(
                "many_drives_failed_scan",
                failed_count=len(failed_drives),
                sample_errors=failed_drives[:3]
            )

        return result

    def get_shared_drive(self, drive_id: str) -> SharedDriveInfo:
        """Get information about a specific Shared Drive.

        Args:
            drive_id: Shared Drive ID

        Returns:
            SharedDriveInfo object
        """
        try:
            drive_data = (
                self.client.drive.drives()
                .get(driveId=drive_id, fields="*")
                .execute()
            )

            return self._process_drive(drive_data)

        except HttpError as e:
            if e.resp.status == 404:
                raise SharedDriveScannerError(f"Shared Drive not found: {drive_id}")
            raise SharedDriveScannerError(f"Failed to get Shared Drive: {e}")

    def _list_shared_drives(self, max_drives: Optional[int] = None) -> Iterator[SharedDriveInfo]:
        """List all Shared Drives with optional limit.

        Args:
            max_drives: Maximum number of drives to fetch

        Yields:
            SharedDriveInfo objects
        """
        page_token = None
        drive_count = 0

        try:
            while True:
                try:
                    response = (
                        self.client.drive.drives()
                        .list(
                            pageSize=100,
                            pageToken=page_token,
                            fields="nextPageToken, drives(id, name, createdTime, hidden, restrictions, capabilities)",
                        )
                        .execute()
                    )

                    drives = response.get("drives", [])

                    for drive_data in drives:
                        drive_info = self._process_drive(drive_data)
                        yield drive_info
                        drive_count += 1

                        # Check max_drives limit
                        if max_drives and drive_count >= max_drives:
                            logger.info("max_drives_limit_reached", max_drives=max_drives)
                            return

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
                        logger.error("insufficient_permissions_to_list_drives", error=str(e))
                        raise SharedDriveScannerError(f"Insufficient permissions: {e}")
                    else:
                        raise

        except SharedDriveScannerError:
            raise
        except Exception as e:
            logger.error("failed_to_list_shared_drives", error=str(e))
            raise SharedDriveScannerError(f"Failed to list Shared Drives: {e}")

    def _scan_drive_files(
        self,
        drive_id: str,
        external_only: bool = False,
    ) -> Iterator[FileInfo]:
        """Scan files in a Shared Drive.

        Args:
            drive_id: Shared Drive ID
            external_only: Only return externally shared files

        Yields:
            FileInfo objects
        """
        page_token = None

        try:
            while True:
                try:
                    # Build query
                    query = f"'{drive_id}' in parents and trashed=false"

                    response = (
                        self.client.drive.files()
                        .list(
                            q=query,
                            pageSize=100,
                            pageToken=page_token,
                            fields="nextPageToken, files(id, name, mimeType, owners, createdTime, modifiedTime, size, webViewLink, permissions)",
                            supportsAllDrives=True,
                            includeItemsFromAllDrives=True,
                            corpora="drive",
                            driveId=drive_id,
                        )
                        .execute()
                    )

                    files = response.get("files", [])

                    for file_data in files:
                        file_info = self.file_scanner._process_file(file_data)

                        # Filter if requested
                        if external_only and not file_info.is_shared_externally:
                            continue

                        yield file_info

                    page_token = response.get("nextPageToken")
                    if not page_token:
                        break

                    time.sleep(0.1)  # Rate limiting

                except HttpError as e:
                    if e.resp.status == 429:  # Rate limit
                        logger.warning("rate_limit_hit_retrying")
                        time.sleep(5)
                        continue
                    else:
                        raise

        except Exception as e:
            logger.error(
                "failed_to_scan_drive_files",
                drive_id=drive_id,
                error=str(e),
            )
            raise SharedDriveScannerError(f"Failed to scan drive files: {e}")

    def _process_drive(self, drive_data: Dict[str, Any]) -> SharedDriveInfo:
        """Process raw drive data into SharedDriveInfo.

        Args:
            drive_data: Raw drive data from API

        Returns:
            SharedDriveInfo object
        """
        created_time = datetime.fromisoformat(
            drive_data.get("createdTime", "").replace("Z", "+00:00")
        )

        drive_info = SharedDriveInfo(
            id=drive_data.get("id", ""),
            name=drive_data.get("name", ""),
            created_time=created_time,
            hidden=drive_data.get("hidden", False),
            restrictions=drive_data.get("restrictions", {}),
            capabilities=drive_data.get("capabilities", {}),
        )

        return drive_info

