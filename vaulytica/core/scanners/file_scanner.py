"""Google Drive file scanner for detecting sharing issues."""

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Iterator

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.utils.cache import Cache
from vaulytica.storage.state import StateManager
from vaulytica.core.scanners.exceptions import (
    NetworkError,
    AuthenticationError,
    PermissionError as ScannerPermissionError,
    RateLimitError,
    APIError,
)

logger = structlog.get_logger(__name__)


@dataclass
class FilePermission:
    """Represents a file permission."""

    id: str
    type: str  # user, group, domain, anyone
    role: str  # owner, organizer, fileOrganizer, writer, commenter, reader
    email_address: Optional[str] = None
    domain: Optional[str] = None
    display_name: Optional[str] = None
    deleted: bool = False


@dataclass
class FileInfo:
    """Represents a Google Drive file with sharing information."""

    id: str
    name: str
    mime_type: str
    owner_email: str
    owner_name: str
    created_time: datetime
    modified_time: datetime
    size: Optional[int] = None
    web_view_link: Optional[str] = None
    permissions: List[FilePermission] = field(default_factory=list)
    is_shared_externally: bool = False
    is_public: bool = False
    external_domains: List[str] = field(default_factory=list)
    external_emails: List[str] = field(default_factory=list)
    risk_score: int = 0
    # Phase 2: Last accessed tracking
    last_accessed_time: Optional[datetime] = None
    days_since_last_access: Optional[int] = None
    is_stale: bool = False
    # Phase 2: External ownership tracking
    is_externally_owned: bool = False
    owner_domain: Optional[str] = None
    organization_access: List[str] = field(default_factory=list)


class FileScannerError(Exception):
    """Raised when file scanning fails."""

    pass


class FileScanner:
    """Scans Google Drive files for sharing and security issues."""

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        domain: str,
        batch_size: int = 100,
        rate_limit_delay: float = 0.1,
        enable_cache: bool = True,
        cache_ttl: int = 3600,
        state_manager: Optional[StateManager] = None,
        incremental: bool = False,
    ):
        """Initialize file scanner.

        Args:
            client: GoogleWorkspaceClient instance
            domain: Organization domain
            batch_size: Number of files to fetch per API call
            rate_limit_delay: Delay between API calls in seconds
            enable_cache: Whether to enable caching
            cache_ttl: Cache time-to-live in seconds
            state_manager: Optional StateManager for incremental scanning
            incremental: Whether to use incremental scanning
        """
        self.client = client
        self.domain = domain
        self.batch_size = batch_size
        self.rate_limit_delay = rate_limit_delay
        self.cache = Cache(default_ttl=cache_ttl) if enable_cache else None
        self.state_manager = state_manager
        self.incremental = incremental

        logger.info(
            "file_scanner_initialized",
            domain=domain,
            batch_size=batch_size,
            cache_enabled=enable_cache,
            incremental=incremental,
        )

    def scan_all_files(
        self,
        external_only: bool = False,
        public_only: bool = False,
        user_email: Optional[str] = None,
        max_files: Optional[int] = None,
    ) -> Iterator[FileInfo]:
        """Scan all files in the domain with enhanced performance.

        Args:
            external_only: Only return files shared externally
            public_only: Only return publicly shared files
            user_email: Scan specific user's files only
            max_files: Maximum number of files to scan (for performance testing)

        Yields:
            FileInfo objects for each file found

        Raises:
            FileScannerError: If scanning fails
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_files is not None and (not isinstance(max_files, int) or max_files < 1):
            raise ValueError("max_files must be a positive integer")
        if user_email and not isinstance(user_email, str):
            raise ValueError("user_email must be a string")

        logger.info(
            "starting_file_scan",
            external_only=external_only,
            public_only=public_only,
            user_email=user_email,
            max_files=max_files,
            incremental=self.incremental,
        )
        scan_start_time = time.time()

        # Get last scan time for incremental scanning
        last_scan_time = None
        if self.incremental and self.state_manager:
            last_scan_time = self.state_manager.get_last_scan_time("file_scan", self.domain)
            if last_scan_time:
                logger.info("incremental_scan", last_scan_time=last_scan_time.isoformat())

        try:
            # Build query
            query_parts = []

            if public_only:
                query_parts.append("visibility='anyoneWithLink' or visibility='anyoneCanFind'")
            elif external_only:
                # We'll filter externally shared files after fetching
                pass

            # Exclude trashed files
            query_parts.append("trashed=false")

            # Add incremental filter
            if last_scan_time:
                # Only scan files modified since last scan
                query_parts.append(f"modifiedTime > '{last_scan_time.isoformat()}'")

            query = " and ".join(query_parts) if query_parts else "trashed=false"

            # Scan files
            page_token = None
            file_count = 0

            while True:
                try:
                    # Fetch files
                    results = (
                        self.client.drive.files()
                        .list(
                            q=query,
                            pageSize=self.batch_size,
                            pageToken=page_token,
                            fields="nextPageToken, files(id, name, mimeType, owners, createdTime, modifiedTime, viewedByMeTime, size, webViewLink, permissions)",
                            supportsAllDrives=True,
                            includeItemsFromAllDrives=True,
                        )
                        .execute()
                    )

                    files = results.get("files", [])

                    for file_data in files:
                        file_info = self._process_file(file_data)

                        # Apply filters
                        if external_only and not file_info.is_shared_externally:
                            continue
                        if public_only and not file_info.is_public:
                            continue

                        # Update state for incremental scanning
                        if self.state_manager:
                            self.state_manager.update_file_state(
                                file_id=file_info.id,
                                file_name=file_info.name,
                                owner_email=file_info.owner_email,
                                modified_time=file_info.modified_time,
                                is_shared_externally=file_info.is_shared_externally,
                                risk_score=file_info.risk_score,
                            )

                        file_count += 1

                        # Log progress every 500 files
                        if file_count % 500 == 0:
                            logger.info(
                                "file_scan_progress",
                                scanned=file_count,
                                external_shared=sum(1 for f in [file_info] if f.is_shared_externally),
                            )

                        yield file_info

                        # Check max_files limit
                        if max_files and file_count >= max_files:
                            logger.info("max_files_limit_reached", max_files=max_files)
                            break

                    # Check if we hit max_files limit
                    if max_files and file_count >= max_files:
                        break

                    page_token = results.get("nextPageToken")
                    if not page_token:
                        break

                    # Rate limiting
                    time.sleep(self.rate_limit_delay)

                except HttpError as e:
                    if e.resp.status == 429:  # Rate limit
                        logger.warning("rate_limit_hit_retrying")
                        time.sleep(5)
                        continue
                    elif e.resp.status == 403:
                        logger.error("insufficient_permissions_to_list_files", error=str(e))
                        raise FileScannerError(f"Insufficient permissions: {e}")
                    else:
                        logger.error("http_error_listing_files", error=str(e))
                        raise FileScannerError(f"Failed to list files: {e}")

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            logger.info(
                "file_scan_complete",
                file_count=file_count,
                scan_duration_seconds=round(scan_duration, 2)
            )

        except FileScannerError:
            # Re-raise scanner-specific errors
            raise
        except HttpError as e:
            # Categorize HTTP errors
            logger.error("file_scan_http_error", error=str(e), status=e.resp.status)
            if e.resp.status == 401:
                raise AuthenticationError(f"Authentication failed during file scan: {e}")
            elif e.resp.status == 403:
                raise ScannerPermissionError(f"Permission denied during file scan: {e}")
            elif e.resp.status == 429:
                raise RateLimitError(f"Rate limit exceeded during file scan: {e}")
            elif e.resp.status >= 500:
                raise NetworkError(f"Server error during file scan: {e}")
            else:
                raise APIError(f"API error during file scan: {e}", status_code=e.resp.status)
        except ConnectionError as e:
            logger.error("file_scan_connection_error", error=str(e))
            raise NetworkError(f"Connection error during file scan: {e}")
        except TimeoutError as e:
            logger.error("file_scan_timeout", error=str(e))
            raise NetworkError(f"Timeout during file scan: {e}")
        except Exception as e:
            logger.error("file_scan_failed", error=str(e), error_type=type(e).__name__)
            raise FileScannerError(f"File scan failed with unexpected error: {type(e).__name__}: {e}")

    def _process_file(self, file_data: Dict[str, Any], stale_days: Optional[int] = None) -> FileInfo:
        """Process raw file data into FileInfo object.

        Args:
            file_data: Raw file data from Drive API
            stale_days: Optional threshold for marking files as stale

        Returns:
            FileInfo object with processed data
        """
        # Extract owner information
        owners = file_data.get("owners", [])
        owner = owners[0] if owners else {}
        owner_email = owner.get("emailAddress", "unknown")
        owner_name = owner.get("displayName", "Unknown")

        # Extract owner domain
        owner_domain = owner_email.split("@")[-1] if "@" in owner_email else None

        # Determine if file is externally owned
        is_externally_owned = owner_domain is not None and owner_domain != self.domain

        # Parse timestamps
        created_time = datetime.fromisoformat(
            file_data.get("createdTime", "").replace("Z", "+00:00")
        )
        modified_time = datetime.fromisoformat(
            file_data.get("modifiedTime", "").replace("Z", "+00:00")
        )

        # Parse last accessed time (viewedByMeTime)
        last_accessed_time = None
        days_since_last_access = None
        is_stale = False
        viewed_by_me_time = file_data.get("viewedByMeTime")
        if viewed_by_me_time:
            last_accessed_time = datetime.fromisoformat(
                viewed_by_me_time.replace("Z", "+00:00")
            )
            days_since_last_access = (datetime.now(last_accessed_time.tzinfo) - last_accessed_time).days
            if stale_days is not None and days_since_last_access >= stale_days:
                is_stale = True

        # Process permissions
        permissions = []
        is_public = False
        is_shared_externally = False
        external_domains = set()
        external_emails = set()
        organization_access = set()

        for perm_data in file_data.get("permissions", []):
            perm = FilePermission(
                id=perm_data.get("id", ""),
                type=perm_data.get("type", ""),
                role=perm_data.get("role", ""),
                email_address=perm_data.get("emailAddress"),
                domain=perm_data.get("domain"),
                display_name=perm_data.get("displayName"),
                deleted=perm_data.get("deleted", False),
            )
            permissions.append(perm)

            # Check for public sharing
            if perm.type == "anyone":
                is_public = True

            # Check for external sharing and track organization access
            if perm.type == "user" and perm.email_address:
                email_domain = perm.email_address.split("@")[-1]
                if email_domain != self.domain:
                    is_shared_externally = True
                    external_emails.add(perm.email_address)
                    external_domains.add(email_domain)
                else:
                    # Internal user with access to this file
                    organization_access.add(perm.email_address)

            elif perm.type == "domain" and perm.domain:
                if perm.domain != self.domain:
                    is_shared_externally = True
                    external_domains.add(perm.domain)

        # Create FileInfo object
        file_info = FileInfo(
            id=file_data.get("id", ""),
            name=file_data.get("name", ""),
            mime_type=file_data.get("mimeType", ""),
            owner_email=owner_email,
            owner_name=owner_name,
            created_time=created_time,
            modified_time=modified_time,
            size=int(file_data.get("size", 0)) if file_data.get("size") else None,
            web_view_link=file_data.get("webViewLink"),
            permissions=permissions,
            is_shared_externally=is_shared_externally,
            is_public=is_public,
            external_domains=list(external_domains),
            external_emails=list(external_emails),
            # Phase 2 fields
            last_accessed_time=last_accessed_time,
            days_since_last_access=days_since_last_access,
            is_stale=is_stale,
            is_externally_owned=is_externally_owned,
            owner_domain=owner_domain,
            organization_access=list(organization_access),
        )

        # Calculate risk score
        file_info.risk_score = self._calculate_risk_score(file_info)

        return file_info

    def _calculate_risk_score(self, file_info: FileInfo) -> int:
        """Calculate risk score for a file.

        Args:
            file_info: FileInfo object

        Returns:
            Risk score (0-100)
        """
        score = 0

        # Public sharing is highest risk
        if file_info.is_public:
            score += 100
            return min(score, 100)  # Cap at 100

        # External sharing
        if file_info.is_shared_externally:
            score += 50

            # Additional points for multiple external domains
            if len(file_info.external_domains) > 1:
                score += min(len(file_info.external_domains) * 5, 25)

        # Large files are higher risk
        if file_info.size and file_info.size > 100 * 1024 * 1024:  # > 100MB
            score += 10

        # Old shares are higher risk
        days_since_modified = (datetime.now(file_info.modified_time.tzinfo) - file_info.modified_time).days
        if days_since_modified > 90:
            score += 15
        elif days_since_modified > 30:
            score += 5

        return min(score, 100)  # Cap at 100

    def scan_stale_content(
        self,
        stale_days: int = 180,
        folders_only: bool = False,
        max_files: Optional[int] = None,
    ) -> Iterator[FileInfo]:
        """Scan for stale files and folders not accessed in N days.

        Args:
            stale_days: Number of days threshold for marking content as stale
            folders_only: Only scan folders, not individual files
            max_files: Maximum number of files to scan

        Yields:
            FileInfo objects for stale files/folders

        Raises:
            FileScannerError: If scanning fails
        """
        logger.info(
            "starting_stale_content_scan",
            stale_days=stale_days,
            folders_only=folders_only,
            max_files=max_files,
        )

        try:
            # Build query
            query_parts = ["trashed=false"]

            if folders_only:
                query_parts.append("mimeType='application/vnd.google-apps.folder'")

            query = " and ".join(query_parts)

            page_token = None
            file_count = 0
            stale_count = 0

            while True:
                try:
                    results = (
                        self.client.drive.files()
                        .list(
                            q=query,
                            pageSize=self.batch_size,
                            pageToken=page_token,
                            fields="nextPageToken, files(id, name, mimeType, owners, createdTime, modifiedTime, viewedByMeTime, size, webViewLink, permissions)",
                            supportsAllDrives=True,
                            includeItemsFromAllDrives=True,
                        )
                        .execute()
                    )

                    files = results.get("files", [])

                    for file_data in files:
                        file_info = self._process_file(file_data, stale_days=stale_days)

                        # Only yield stale files
                        if file_info.is_stale:
                            stale_count += 1
                            yield file_info

                        file_count += 1

                        # Check max_files limit
                        if max_files and file_count >= max_files:
                            break

                    if max_files and file_count >= max_files:
                        break

                    page_token = results.get("nextPageToken")
                    if not page_token:
                        break

                    time.sleep(self.rate_limit_delay)

                except HttpError as e:
                    if e.resp.status == 429:
                        logger.warning("rate_limit_hit_retrying")
                        time.sleep(5)
                        continue
                    else:
                        raise FileScannerError(f"Failed to scan stale content: {e}")

            logger.info(
                "stale_content_scan_complete",
                total_scanned=file_count,
                stale_found=stale_count,
            )

        except FileScannerError:
            raise
        except HttpError as e:
            logger.error("stale_content_scan_http_error", error=str(e), status=e.resp.status)
            if e.resp.status == 401:
                raise AuthenticationError(f"Authentication failed during stale content scan: {e}")
            elif e.resp.status == 403:
                raise ScannerPermissionError(f"Permission denied during stale content scan: {e}")
            elif e.resp.status >= 500:
                raise NetworkError(f"Server error during stale content scan: {e}")
            else:
                raise APIError(f"API error during stale content scan: {e}", status_code=e.resp.status)
        except (ConnectionError, TimeoutError) as e:
            logger.error("stale_content_scan_network_error", error=str(e))
            raise NetworkError(f"Network error during stale content scan: {e}")
        except Exception as e:
            logger.error("stale_content_scan_failed", error=str(e), error_type=type(e).__name__)
            raise FileScannerError(f"Stale content scan failed with unexpected error: {type(e).__name__}: {e}")

    def scan_external_owned(
        self,
        min_size: Optional[int] = None,
        max_files: Optional[int] = None,
    ) -> Iterator[FileInfo]:
        """Scan for files owned by external users (outside the organization domain).

        This identifies files shared INTO the domain but owned by external parties,
        which is valuable for:
        - Audit preparation
        - Data sovereignty compliance
        - Storage cleanup and cost management
        - Security posture assessment

        Args:
            min_size: Minimum file size in bytes to include
            max_files: Maximum number of files to scan

        Yields:
            FileInfo objects for externally owned files

        Raises:
            FileScannerError: If scanning fails
        """
        logger.info(
            "starting_external_owned_scan",
            domain=self.domain,
            min_size=min_size,
            max_files=max_files,
        )

        try:
            # Build query - we need to scan all accessible files
            query = "trashed=false"

            page_token = None
            file_count = 0
            external_owned_count = 0

            while True:
                try:
                    results = (
                        self.client.drive.files()
                        .list(
                            q=query,
                            pageSize=self.batch_size,
                            pageToken=page_token,
                            fields="nextPageToken, files(id, name, mimeType, owners, createdTime, modifiedTime, viewedByMeTime, size, webViewLink, permissions)",
                            supportsAllDrives=True,
                            includeItemsFromAllDrives=True,
                        )
                        .execute()
                    )

                    files = results.get("files", [])

                    for file_data in files:
                        file_info = self._process_file(file_data)

                        # Only yield externally owned files
                        if file_info.is_externally_owned:
                            # Apply size filter if specified
                            if min_size and file_info.size and file_info.size < min_size:
                                continue

                            external_owned_count += 1
                            yield file_info

                        file_count += 1

                        # Check max_files limit
                        if max_files and file_count >= max_files:
                            break

                    if max_files and file_count >= max_files:
                        break

                    page_token = results.get("nextPageToken")
                    if not page_token:
                        break

                    time.sleep(self.rate_limit_delay)

                except HttpError as e:
                    if e.resp.status == 429:
                        logger.warning("rate_limit_hit_retrying")
                        time.sleep(5)
                        continue
                    else:
                        raise FileScannerError(f"Failed to scan external owned files: {e}")

            logger.info(
                "external_owned_scan_complete",
                total_scanned=file_count,
                external_owned_found=external_owned_count,
            )

        except FileScannerError:
            raise
        except HttpError as e:
            logger.error("external_owned_scan_http_error", error=str(e), status=e.resp.status)
            if e.resp.status == 401:
                raise AuthenticationError(f"Authentication failed during external owned scan: {e}")
            elif e.resp.status == 403:
                raise ScannerPermissionError(f"Permission denied during external owned scan: {e}")
            elif e.resp.status >= 500:
                raise NetworkError(f"Server error during external owned scan: {e}")
            else:
                raise APIError(f"API error during external owned scan: {e}", status_code=e.resp.status)
        except (ConnectionError, TimeoutError) as e:
            logger.error("external_owned_scan_network_error", error=str(e))
            raise NetworkError(f"Network error during external owned scan: {e}")
        except Exception as e:
            logger.error("external_owned_scan_failed", error=str(e), error_type=type(e).__name__)
            raise FileScannerError(f"External owned scan failed with unexpected error: {type(e).__name__}: {e}")

