"""Google Workspace license management and optimization scanner."""

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import structlog
from googleapiclient.errors import HttpError

logger = structlog.get_logger(__name__)


@dataclass
class LicenseAssignment:
    """Google Workspace license assignment."""

    user_email: str
    sku_id: str
    sku_name: str
    product_id: str
    product_name: str
    assigned_date: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_active: bool = True
    usage_days: int = 0


@dataclass
class LicenseSKU:
    """Google Workspace license SKU information."""

    sku_id: str
    sku_name: str
    product_id: str
    product_name: str
    total_licenses: int
    assigned_licenses: int
    available_licenses: int
    cost_per_license: float = 0.0
    billing_cycle: str = "monthly"


@dataclass
class LicenseScanResult:
    """Results from license scanning."""

    total_licenses: int = 0
    assigned_licenses: int = 0
    available_licenses: int = 0
    unused_licenses_count: int = 0
    underutilized_licenses_count: int = 0
    total_monthly_cost: float = 0.0
    potential_savings: float = 0.0
    skus: List[LicenseSKU] = field(default_factory=list)
    assignments: List[LicenseAssignment] = field(default_factory=list)
    unused_licenses: List[LicenseAssignment] = field(default_factory=list)
    underutilized_licenses: List[LicenseAssignment] = field(default_factory=list)
    recommendations: List[Dict] = field(default_factory=list)
    issues: List[Dict] = field(default_factory=list)
    scan_timestamp: datetime = field(default_factory=datetime.now)


class LicenseScanner:
    """Scanner for Google Workspace license management."""

    # License SKU pricing (approximate monthly costs in USD)
    LICENSE_PRICING = {
        "Google-Apps-For-Business": 6.00,  # Business Starter
        "Google-Apps-Unlimited": 12.00,  # Business Standard
        "Google-Apps-For-Postini": 18.00,  # Business Plus
        "1010020020": 6.00,  # Business Starter
        "1010020025": 12.00,  # Business Standard
        "1010020026": 18.00,  # Business Plus
        "1010020027": 18.00,  # Enterprise Essentials
        "1010020028": 20.00,  # Enterprise Standard
        "1010020029": 30.00,  # Enterprise Plus
        "1010310002": 8.00,  # Frontline Starter
        "1010310003": 10.00,  # Frontline Standard
        "Google-Vault": 5.00,  # Google Vault
        "Google-Vault-Former-Employee": 5.00,  # Vault Former Employee
    }

    def __init__(self, client, inactive_days: int = 30):
        """
        Initialize the license scanner.

        Args:
            client: Google Workspace Admin SDK client
            inactive_days: Days of inactivity to consider license underutilized
        """
        self.client = client
        self.inactive_days = inactive_days

    def scan_all_licenses(self, max_assignments: Optional[int] = None) -> LicenseScanResult:
        """
        Scan all Google Workspace licenses with enhanced performance.

        Args:
            max_assignments: Maximum number of assignments to scan (for performance testing)

        Returns:
            LicenseScanResult with license information and recommendations

        Raises:
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_assignments is not None and (not isinstance(max_assignments, int) or max_assignments < 1):
            raise ValueError("max_assignments must be a positive integer")

        logger.info("starting_license_scan", max_assignments=max_assignments)
        scan_start_time = time.time()

        result = LicenseScanResult()

        try:
            # Get all license SKUs
            logger.info("fetching_license_skus")
            skus = self._list_all_skus()
            result.skus = skus
            logger.info("license_skus_fetched", count=len(skus))

            # Get all license assignments
            logger.info("fetching_license_assignments")
            assignments = self._list_all_assignments(max_assignments=max_assignments)
            result.assignments = assignments
            logger.info("license_assignments_fetched", count=len(assignments))

            # Calculate statistics
            result.total_licenses = sum(sku.total_licenses for sku in skus)
            result.assigned_licenses = sum(sku.assigned_licenses for sku in skus)
            result.available_licenses = sum(sku.available_licenses for sku in skus)

            # Calculate costs
            result.total_monthly_cost = self._calculate_total_cost(skus)

            # Identify unused and underutilized licenses
            logger.info("analyzing_license_usage")
            unused, underutilized = self._identify_unused_licenses(assignments)
            result.unused_licenses = unused
            result.underutilized_licenses = underutilized
            result.unused_licenses_count = len(unused)
            result.underutilized_licenses_count = len(underutilized)

            # Calculate potential savings
            result.potential_savings = self._calculate_potential_savings(unused, underutilized)

            # Generate recommendations
            result.recommendations = self._generate_recommendations(result)

            # Generate issues
            result.issues = self._generate_issues(result)

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            logger.info(
                "license_scan_complete",
                total_licenses=result.total_licenses,
                assigned=result.assigned_licenses,
                unused=result.unused_licenses_count,
                potential_savings=result.potential_savings,
                scan_duration_seconds=round(scan_duration, 2),
            )

        except HttpError as e:
            if e.resp.status == 403:
                logger.error("insufficient_permissions_to_scan_licenses", error=str(e))
                raise
            else:
                logger.error("license_scan_failed", error=str(e))
                raise
        except Exception as e:
            logger.error("license_scan_failed", error=str(e))
            raise

        return result

    def _list_all_skus(self) -> List[LicenseSKU]:
        """List all available license SKUs."""
        skus = []

        try:
            # Get customer ID
            customer_id = "my_customer"

            # List all subscriptions
            subscriptions = (
                self.client.service.subscriptions()
                .list(customerId=customer_id)
                .execute()
            )

            for sub in subscriptions.get("subscriptions", []):
                sku = LicenseSKU(
                    sku_id=sub.get("skuId", ""),
                    sku_name=sub.get("skuName", "Unknown"),
                    product_id=sub.get("productId", ""),
                    product_name=sub.get("productName", "Unknown"),
                    total_licenses=int(sub.get("seats", {}).get("numberOfSeats", 0)),
                    assigned_licenses=int(sub.get("seats", {}).get("licensedNumberOfSeats", 0)),
                    available_licenses=int(sub.get("seats", {}).get("numberOfSeats", 0))
                    - int(sub.get("seats", {}).get("licensedNumberOfSeats", 0)),
                    cost_per_license=self.LICENSE_PRICING.get(sub.get("skuId", ""), 0.0),
                )
                skus.append(sku)

        except Exception as e:
            logger.error("failed_to_list_skus", error=str(e))

        return skus

    def _list_all_assignments(self, max_assignments: Optional[int] = None) -> List[LicenseAssignment]:
        """List all license assignments with optional limit.

        Args:
            max_assignments: Maximum number of assignments to fetch

        Returns:
            List of LicenseAssignment objects
        """
        assignments = []
        assignment_count = 0

        try:
            customer_id = "my_customer"

            # Get all products
            products = (
                self.client.service.licensing()
                .listForProduct(productId="Google-Apps", customerId=customer_id)
                .execute()
            )

            for item in products.get("items", []):
                assignment = LicenseAssignment(
                    user_email=item.get("userId", ""),
                    sku_id=item.get("skuId", ""),
                    sku_name=item.get("skuName", "Unknown"),
                    product_id=item.get("productId", ""),
                    product_name=item.get("productName", "Unknown"),
                )
                assignments.append(assignment)
                assignment_count += 1

                # Log progress every 100 assignments
                if assignment_count % 100 == 0:
                    logger.info("license_assignment_progress", scanned=assignment_count)

                # Check max_assignments limit
                if max_assignments and assignment_count >= max_assignments:
                    logger.info("max_assignments_limit_reached", max_assignments=max_assignments)
                    break

        except HttpError as e:
            if e.resp.status == 403:
                logger.error("insufficient_permissions_to_list_assignments", error=str(e))
            else:
                logger.error("failed_to_list_assignments", error=str(e))
        except Exception as e:
            logger.error("failed_to_list_assignments", error=str(e))

        return assignments

    def _identify_unused_licenses(
        self, assignments: List[LicenseAssignment]
    ) -> tuple[List[LicenseAssignment], List[LicenseAssignment]]:
        """
        Identify unused and underutilized licenses.

        Returns:
            Tuple of (unused_licenses, underutilized_licenses)
        """
        unused = []
        underutilized = []

        for assignment in assignments:
            if not assignment.is_active:
                unused.append(assignment)
            elif assignment.usage_days < self.inactive_days:
                underutilized.append(assignment)

        return unused, underutilized

    def _calculate_total_cost(self, skus: List[LicenseSKU]) -> float:
        """Calculate total monthly cost of all licenses."""
        total = 0.0
        for sku in skus:
            total += sku.assigned_licenses * sku.cost_per_license
        return total

    def _calculate_potential_savings(
        self, unused: List[LicenseAssignment], underutilized: List[LicenseAssignment]
    ) -> float:
        """Calculate potential monthly savings from unused licenses."""
        savings = 0.0

        # Calculate savings from unused licenses
        for assignment in unused:
            cost = self.LICENSE_PRICING.get(assignment.sku_id, 0.0)
            savings += cost

        # Calculate partial savings from underutilized licenses (50% of cost)
        for assignment in underutilized:
            cost = self.LICENSE_PRICING.get(assignment.sku_id, 0.0)
            savings += cost * 0.5

        return savings

    def _generate_recommendations(self, result: LicenseScanResult) -> List[Dict]:
        """Generate license optimization recommendations."""
        recommendations = []

        # Unused licenses
        if result.unused_licenses_count > 0:
            recommendations.append(
                {
                    "type": "unused_licenses",
                    "severity": "high",
                    "title": f"Remove {result.unused_licenses_count} Unused Licenses",
                    "description": f"Found {result.unused_licenses_count} licenses assigned to inactive users. "
                    f"Removing these could save ${result.potential_savings:.2f}/month.",
                    "action": "Review and remove licenses from inactive users",
                }
            )

        # Underutilized licenses
        if result.underutilized_licenses_count > 0:
            recommendations.append(
                {
                    "type": "underutilized_licenses",
                    "severity": "medium",
                    "title": f"Review {result.underutilized_licenses_count} Underutilized Licenses",
                    "description": f"Found {result.underutilized_licenses_count} licenses with low usage. "
                    "Consider downgrading or removing.",
                    "action": "Contact users to verify if they need their licenses",
                }
            )

        # License consolidation
        if len(result.skus) > 3:
            recommendations.append(
                {
                    "type": "consolidation",
                    "severity": "low",
                    "title": "Consolidate License Types",
                    "description": f"You have {len(result.skus)} different license types. "
                    "Consolidating could simplify management.",
                    "action": "Review if all license types are necessary",
                }
            )

        # Cost optimization
        if result.total_monthly_cost > 1000:
            recommendations.append(
                {
                    "type": "cost_optimization",
                    "severity": "medium",
                    "title": "Consider Annual Billing",
                    "description": f"Current monthly cost: ${result.total_monthly_cost:.2f}. "
                    "Annual billing could save 10-20%.",
                    "action": "Contact Google Workspace sales for annual pricing",
                }
            )

        return recommendations

    def _generate_issues(self, result: LicenseScanResult) -> List[Dict]:
        """Generate issues from license scan."""
        issues = []

        # High unused license count
        if result.unused_licenses_count > 10:
            issues.append(
                {
                    "severity": "high",
                    "type": "excessive_unused_licenses",
                    "description": f"{result.unused_licenses_count} unused licenses detected",
                    "recommendation": "Remove licenses from inactive users immediately",
                    "potential_savings": f"${result.potential_savings:.2f}/month",
                }
            )

        # Over-provisioned
        utilization_rate = (
            result.assigned_licenses / result.total_licenses if result.total_licenses > 0 else 0
        )
        if utilization_rate < 0.7:
            issues.append(
                {
                    "severity": "medium",
                    "type": "over_provisioned",
                    "description": f"License utilization is only {utilization_rate*100:.1f}%",
                    "recommendation": "Reduce total license count to match actual usage",
                }
            )

        return issues

