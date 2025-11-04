"""Vault scanner for Google Vault legal holds and retention policies."""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime
import structlog
from googleapiclient.errors import HttpError

logger = structlog.get_logger(__name__)


@dataclass
class Matter:
    """Represents a Google Vault matter."""

    matter_id: str
    name: str
    description: str = ""
    state: str = "OPEN"  # OPEN, CLOSED, DELETED
    created_time: Optional[datetime] = None
    holds_count: int = 0
    exports_count: int = 0


@dataclass
class Hold:
    """Represents a legal hold."""

    hold_id: str
    matter_id: str
    name: str
    corpus: str  # MAIL, DRIVE, GROUPS, HANGOUTS_CHAT
    accounts: List[str] = field(default_factory=list)
    org_unit: str = ""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    query: str = ""


@dataclass
class RetentionPolicy:
    """Represents a retention policy."""

    policy_id: str
    name: str
    corpus: str  # MAIL, DRIVE, GROUPS, HANGOUTS_CHAT
    retention_period_days: int = 0
    org_units: List[str] = field(default_factory=list)
    is_default: bool = False


@dataclass
class VaultScanResult:
    """Results from a Vault scan."""

    total_matters: int = 0
    open_matters: int = 0
    closed_matters: int = 0
    total_holds: int = 0
    total_retention_policies: int = 0
    matters: List[Matter] = field(default_factory=list)
    holds: List[Hold] = field(default_factory=list)
    retention_policies: List[RetentionPolicy] = field(default_factory=list)
    issues: List[Dict] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)


class VaultScanner:
    """Scanner for Google Vault."""

    def __init__(self, client, domain: str):
        """Initialize the Vault scanner.

        Args:
            client: Authenticated Google Workspace client
            domain: Primary domain to scan
        """
        self.client = client
        self.domain = domain
        self.logger = logger.bind(scanner="vault", domain=domain)

    def scan_all(self, max_matters: Optional[int] = None) -> VaultScanResult:
        """Scan all Vault matters, holds, and retention policies with enhanced performance.

        Args:
            max_matters: Maximum number of matters to scan (for performance testing)

        Returns:
            VaultScanResult with all findings

        Raises:
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_matters is not None and (not isinstance(max_matters, int) or max_matters < 1):
            raise ValueError("max_matters must be a positive integer")

        self.logger.info("starting_vault_scan", max_matters=max_matters)
        scan_start_time = time.time()

        result = VaultScanResult()
        failed_matters = []

        try:
            # Scan matters
            self.logger.info("fetching_vault_matters")
            result.matters = self._scan_matters(max_matters=max_matters)
            result.total_matters = len(result.matters)
            self.logger.info("vault_matters_fetched", count=result.total_matters)

            matter_count = 0
            for matter in result.matters:
                try:
                    if matter.state == "OPEN":
                        result.open_matters += 1
                    elif matter.state == "CLOSED":
                        result.closed_matters += 1

                    # Scan holds for each matter
                    holds = self._scan_holds(matter.matter_id)
                    result.holds.extend(holds)
                    matter.holds_count = len(holds)

                    matter_count += 1

                    # Log progress every 10 matters
                    if matter_count % 10 == 0:
                        self.logger.info(
                            "vault_matter_progress",
                            scanned=matter_count,
                            total_holds=len(result.holds),
                        )

                except Exception as e:
                    self.logger.warning(
                        "failed_to_process_matter",
                        matter_id=matter.matter_id,
                        matter_name=matter.name,
                        error=str(e)
                    )
                    failed_matters.append({
                        "matter_id": matter.matter_id,
                        "matter_name": matter.name,
                        "error": str(e)
                    })
                    continue

            result.total_holds = len(result.holds)

            # Scan retention policies
            self.logger.info("fetching_retention_policies")
            result.retention_policies = self._scan_retention_policies()
            result.total_retention_policies = len(result.retention_policies)
            self.logger.info("retention_policies_fetched", count=result.total_retention_policies)

            # Generate issues
            result.issues = self._generate_issues(result)

            # Calculate statistics
            result.statistics = self._calculate_statistics(result)

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            self.logger.info(
                "vault_scan_complete",
                total_matters=result.total_matters,
                total_holds=result.total_holds,
                total_policies=result.total_retention_policies,
                failed_matters=len(failed_matters),
                scan_duration_seconds=round(scan_duration, 2),
            )

            # Log warning if many matters failed
            if failed_matters and len(failed_matters) > 3:
                self.logger.warning(
                    "many_matters_failed_processing",
                    failed_count=len(failed_matters),
                    sample_errors=failed_matters[:3]
                )

        except HttpError as e:
            if e.resp.status == 403:
                self.logger.error("insufficient_permissions_to_scan_vault", error=str(e))
                raise
            else:
                self.logger.error("vault_scan_failed", error=str(e))
                raise
        except Exception as e:
            self.logger.error("vault_scan_failed", error=str(e))
            raise

        return result

    def _scan_matters(self, max_matters: Optional[int] = None) -> List[Matter]:
        """Scan all matters with optional limit.

        Args:
            max_matters: Maximum number of matters to fetch

        Returns:
            List of Matter objects
        """
        matters = []
        matter_count = 0

        try:
            # Note: In a real implementation, this would use the Vault API
            # For now, we'll return a mock implementation
            # vault_service = self.client.vault
            # response = vault_service.matters().list().execute()
            #
            # for matter_data in response.get('matters', []):
            #     matter = Matter(
            #         matter_id=matter_data.get('matterId'),
            #         name=matter_data.get('name'),
            #         description=matter_data.get('description', ''),
            #         state=matter_data.get('state', 'OPEN')
            #     )
            #     matters.append(matter)
            #     matter_count += 1
            #
            #     # Check max_matters limit
            #     if max_matters and matter_count >= max_matters:
            #         self.logger.info("max_matters_limit_reached", max_matters=max_matters)
            #         break

            # Mock implementation for testing
            self.logger.debug("scanning_matters", max_matters=max_matters)

        except HttpError as e:
            if e.resp.status == 403:
                self.logger.error("insufficient_permissions_to_list_matters", error=str(e))
            else:
                self.logger.error("failed_to_scan_matters", error=str(e))
            raise

        return matters

    def _scan_holds(self, matter_id: str) -> List[Hold]:
        """Scan holds for a specific matter."""
        holds = []

        try:
            # Note: In a real implementation, this would use the Vault API
            # vault_service = self.client.vault
            # response = vault_service.matters().holds().list(matterId=matter_id).execute()

            # Mock implementation for testing
            self.logger.debug("scanning_holds", matter_id=matter_id)

        except HttpError as e:
            self.logger.error("failed_to_scan_holds", matter_id=matter_id, error=str(e))

        return holds

    def _scan_retention_policies(self) -> List[RetentionPolicy]:
        """Scan retention policies."""
        policies = []

        try:
            # Note: In a real implementation, this would use the Vault API
            # This is a mock implementation for testing
            self.logger.debug("scanning_retention_policies")

        except HttpError as e:
            self.logger.error("failed_to_scan_retention_policies", error=str(e))

        return policies

    def _generate_issues(self, result: VaultScanResult) -> List[Dict]:
        """Generate list of compliance issues found."""
        issues = []

        # Check for matters without holds
        for matter in result.matters:
            if matter.state == "OPEN" and matter.holds_count == 0:
                issues.append(
                    {
                        "type": "matter_without_holds",
                        "severity": "medium",
                        "matter": matter.name,
                        "description": "Open matter has no active holds",
                    }
                )

        # Check for old open matters (mock - would need actual date comparison)
        for matter in result.matters:
            if matter.state == "OPEN":
                # In real implementation, check if matter is older than threshold
                pass

        # Check for holds without accounts
        for hold in result.holds:
            if not hold.accounts and not hold.org_unit:
                issues.append(
                    {
                        "type": "hold_without_scope",
                        "severity": "high",
                        "hold": hold.name,
                        "matter_id": hold.matter_id,
                        "description": "Hold has no accounts or org units specified",
                    }
                )

        # Check for missing retention policies
        if result.total_retention_policies == 0:
            issues.append(
                {
                    "type": "no_retention_policies",
                    "severity": "high",
                    "description": "No retention policies configured",
                }
            )

        return issues

    def _calculate_statistics(self, result: VaultScanResult) -> Dict:
        """Calculate summary statistics."""
        return {
            "total_matters": result.total_matters,
            "open_matters": result.open_matters,
            "closed_matters": result.closed_matters,
            "total_holds": result.total_holds,
            "total_retention_policies": result.total_retention_policies,
            "total_issues": len(result.issues),
        }

    def get_matter_details(self, matter_id: str) -> Optional[Matter]:
        """Get detailed information about a specific matter.

        Args:
            matter_id: The matter ID to retrieve

        Returns:
            Matter object or None if not found
        """
        try:
            # Note: In a real implementation, this would use the Vault API
            # vault_service = self.client.vault
            # response = vault_service.matters().get(matterId=matter_id).execute()

            self.logger.debug("getting_matter_details", matter_id=matter_id)
            return None

        except HttpError as e:
            self.logger.error("failed_to_get_matter", matter_id=matter_id, error=str(e))
            return None

    def get_hold_details(self, matter_id: str, hold_id: str) -> Optional[Hold]:
        """Get detailed information about a specific hold.

        Args:
            matter_id: The matter ID
            hold_id: The hold ID to retrieve

        Returns:
            Hold object or None if not found
        """
        try:
            # Note: In a real implementation, this would use the Vault API
            # vault_service = self.client.vault
            # response = vault_service.matters().holds().get(
            #     matterId=matter_id, holdId=hold_id
            # ).execute()

            self.logger.debug("getting_hold_details", matter_id=matter_id, hold_id=hold_id)
            return None

        except HttpError as e:
            self.logger.error(
                "failed_to_get_hold",
                matter_id=matter_id,
                hold_id=hold_id,
                error=str(e),
            )
            return None

