"""Gmail security scanner for detecting delegates, forwarding, and other security issues."""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import structlog
from googleapiclient.errors import HttpError

logger = structlog.get_logger(__name__)


@dataclass
class DelegateInfo:
    """Represents a Gmail delegate."""

    delegate_email: str
    user_email: str
    verification_status: str = "accepted"


@dataclass
class ForwardingRule:
    """Represents a Gmail forwarding rule."""

    user_email: str
    forward_to: str
    enabled: bool = True
    disposition: str = "leaveInInbox"  # leaveInInbox, archive, trash, markRead


@dataclass
class SendAsAlias:
    """Represents a Gmail send-as alias."""

    user_email: str
    send_as_email: str
    display_name: str = ""
    is_default: bool = False
    is_primary: bool = False
    verification_status: str = "accepted"


@dataclass
class GmailFilter:
    """Represents a Gmail filter."""

    user_email: str
    filter_id: str
    criteria: Dict = field(default_factory=dict)
    action: Dict = field(default_factory=dict)


@dataclass
class GmailSecurityScanResult:
    """Results from a Gmail security scan."""

    total_users_scanned: int = 0
    users_with_delegates: int = 0
    users_with_forwarding: int = 0
    users_with_send_as: int = 0
    users_with_risky_filters: int = 0
    delegates: List[DelegateInfo] = field(default_factory=list)
    forwarding_rules: List[ForwardingRule] = field(default_factory=list)
    send_as_aliases: List[SendAsAlias] = field(default_factory=list)
    risky_filters: List[GmailFilter] = field(default_factory=list)
    issues: List[Dict] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)


class GmailSecurityScanner:
    """Scanner for Gmail security issues."""

    def __init__(self, client, domain: str):
        """Initialize the Gmail security scanner.

        Args:
            client: Authenticated Google Workspace client
            domain: Primary domain to scan
        """
        self.client = client
        self.domain = domain
        self.logger = logger.bind(scanner="gmail_security", domain=domain)

    def scan_all_users(
        self,
        check_delegates: bool = True,
        check_forwarding: bool = True,
        check_send_as: bool = True,
        check_filters: bool = True,
        max_users: Optional[int] = None,
    ) -> GmailSecurityScanResult:
        """Scan all users for Gmail security issues with enhanced performance.

        Args:
            check_delegates: Check for Gmail delegates
            check_forwarding: Check for auto-forwarding rules
            check_send_as: Check for send-as aliases
            check_filters: Check for risky filters
            max_users: Maximum number of users to scan (for performance testing)

        Returns:
            GmailSecurityScanResult with all findings

        Raises:
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_users is not None and (not isinstance(max_users, int) or max_users < 1):
            raise ValueError("max_users must be a positive integer")

        self.logger.info(
            "starting_gmail_security_scan",
            delegates=check_delegates,
            forwarding=check_forwarding,
            send_as=check_send_as,
            filters=check_filters,
            max_users=max_users,
        )
        scan_start_time = time.time()

        result = GmailSecurityScanResult()
        failed_users = []

        try:
            # Get all users in the domain
            self.logger.info("fetching_users")
            users = self._list_all_users(max_users=max_users)
            result.total_users_scanned = len(users)

            self.logger.info("users_found", count=len(users))

            # Scan each user
            user_count = 0
            for user in users:
                user_email = user.get("primaryEmail", "")

                try:
                    if check_delegates:
                        delegates = self._scan_delegates(user_email)
                        if delegates:
                            result.delegates.extend(delegates)
                            result.users_with_delegates += 1

                    if check_forwarding:
                        forwarding = self._scan_forwarding(user_email)
                        if forwarding:
                            result.forwarding_rules.extend(forwarding)
                            result.users_with_forwarding += 1

                    if check_send_as:
                        send_as = self._scan_send_as(user_email)
                        if send_as:
                            result.send_as_aliases.extend(send_as)
                            result.users_with_send_as += 1

                    if check_filters:
                        risky_filters = self._scan_risky_filters(user_email)
                        if risky_filters:
                            result.risky_filters.extend(risky_filters)
                            result.users_with_risky_filters += 1

                    user_count += 1

                    # Log progress every 50 users
                    if user_count % 50 == 0:
                        self.logger.info(
                            "gmail_security_scan_progress",
                            scanned=user_count,
                            with_delegates=result.users_with_delegates,
                            with_forwarding=result.users_with_forwarding,
                            with_risky_filters=result.users_with_risky_filters,
                        )

                except Exception as e:
                    self.logger.warning(
                        "failed_to_scan_user",
                        user_email=user_email,
                        error=str(e)
                    )
                    failed_users.append({
                        "user_email": user_email,
                        "error": str(e)
                    })
                    continue

            # Generate issues
            result.issues = self._generate_issues(result)

            # Calculate statistics
            result.statistics = self._calculate_statistics(result)

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            self.logger.info(
                "gmail_security_scan_complete",
                total_users=result.total_users_scanned,
                delegates=result.users_with_delegates,
                forwarding=result.users_with_forwarding,
                send_as=result.users_with_send_as,
                risky_filters=result.users_with_risky_filters,
                failed_users=len(failed_users),
                scan_duration_seconds=round(scan_duration, 2),
            )

            # Log warning if many users failed
            if failed_users and len(failed_users) > 10:
                self.logger.warning(
                    "many_users_failed_scan",
                    failed_count=len(failed_users),
                    sample_errors=failed_users[:3]
                )

        except HttpError as e:
            if e.resp.status == 403:
                self.logger.error("insufficient_permissions_to_scan_gmail_security", error=str(e))
                raise
            else:
                self.logger.error("gmail_security_scan_failed", error=str(e))
                raise
        except Exception as e:
            self.logger.error("gmail_security_scan_failed", error=str(e))
            raise

        return result

    def _list_all_users(self, max_users: Optional[int] = None) -> List[Dict]:
        """List all users in the domain with optional limit.

        Args:
            max_users: Maximum number of users to fetch

        Returns:
            List of user dictionaries
        """
        users = []
        page_token = None

        try:
            while True:
                response = (
                    self.client.admin.users()
                    .list(domain=self.domain, pageToken=page_token, maxResults=500)
                    .execute()
                )

                users.extend(response.get("users", []))

                # Check max_users limit
                if max_users and len(users) >= max_users:
                    self.logger.info("max_users_limit_reached", max_users=max_users)
                    return users[:max_users]

                page_token = response.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            if e.resp.status == 403:
                self.logger.error("insufficient_permissions_to_list_users", error=str(e))
            else:
                self.logger.error("failed_to_list_users", error=str(e))
            raise

        return users

    def _scan_delegates(self, user_email: str) -> List[DelegateInfo]:
        """Scan for Gmail delegates for a user."""
        delegates = []

        try:
            # Get delegates using Gmail API
            response = (
                self.client.gmail.users()
                .settings()
                .delegates()
                .list(userId=user_email)
                .execute()
            )

            for delegate_data in response.get("delegates", []):
                delegate = DelegateInfo(
                    delegate_email=delegate_data.get("delegateEmail", ""),
                    user_email=user_email,
                    verification_status=delegate_data.get("verificationStatus", "accepted"),
                )
                delegates.append(delegate)

        except HttpError as e:
            # User might not have Gmail enabled or API access denied
            self.logger.debug("failed_to_get_delegates", user=user_email, error=str(e))

        return delegates

    def _scan_forwarding(self, user_email: str) -> List[ForwardingRule]:
        """Scan for auto-forwarding rules for a user."""
        forwarding_rules = []

        try:
            # Get forwarding addresses
            response = (
                self.client.gmail.users()
                .settings()
                .forwardingAddresses()
                .list(userId=user_email)
                .execute()
            )

            for forward_data in response.get("forwardingAddresses", []):
                # Only include verified forwarding addresses
                if forward_data.get("verificationStatus") == "accepted":
                    rule = ForwardingRule(
                        user_email=user_email,
                        forward_to=forward_data.get("forwardingEmail", ""),
                        enabled=True,
                    )
                    forwarding_rules.append(rule)

        except HttpError as e:
            self.logger.debug("failed_to_get_forwarding", user=user_email, error=str(e))

        return forwarding_rules

    def _scan_send_as(self, user_email: str) -> List[SendAsAlias]:
        """Scan for send-as aliases for a user."""
        send_as_aliases = []

        try:
            # Get send-as aliases
            response = (
                self.client.gmail.users()
                .settings()
                .sendAs()
                .list(userId=user_email)
                .execute()
            )

            for alias_data in response.get("sendAs", []):
                # Skip the primary email address
                alias_email = alias_data.get("sendAsEmail", "")
                if alias_email != user_email:
                    alias = SendAsAlias(
                        user_email=user_email,
                        send_as_email=alias_email,
                        display_name=alias_data.get("displayName", ""),
                        is_default=alias_data.get("isDefault", False),
                        is_primary=alias_data.get("isPrimary", False),
                        verification_status=alias_data.get("verificationStatus", "accepted"),
                    )
                    send_as_aliases.append(alias)

        except HttpError as e:
            self.logger.debug("failed_to_get_send_as", user=user_email, error=str(e))

        return send_as_aliases

    def _scan_risky_filters(self, user_email: str) -> List[GmailFilter]:
        """Scan for risky Gmail filters (auto-delete, auto-forward, etc.)."""
        risky_filters = []

        try:
            # Get filters
            response = (
                self.client.gmail.users()
                .settings()
                .filters()
                .list(userId=user_email)
                .execute()
            )

            for filter_data in response.get("filter", []):
                action = filter_data.get("action", {})

                # Check for risky actions
                is_risky = (
                    action.get("trash", False)  # Auto-delete
                    or action.get("forward")  # Auto-forward
                    or action.get("removeLabelIds")  # Remove labels (hide emails)
                )

                if is_risky:
                    gmail_filter = GmailFilter(
                        user_email=user_email,
                        filter_id=filter_data.get("id", ""),
                        criteria=filter_data.get("criteria", {}),
                        action=action,
                    )
                    risky_filters.append(gmail_filter)

        except HttpError as e:
            self.logger.debug("failed_to_get_filters", user=user_email, error=str(e))

        return risky_filters

    def _generate_issues(self, result: GmailSecurityScanResult) -> List[Dict]:
        """Generate list of security issues found."""
        issues = []

        # Delegates issues
        for delegate in result.delegates:
            # Check if delegate is external
            is_external = not delegate.delegate_email.endswith(f"@{self.domain}")

            issues.append(
                {
                    "type": "gmail_delegate",
                    "severity": "high" if is_external else "medium",
                    "user": delegate.user_email,
                    "delegate": delegate.delegate_email,
                    "description": f"User has granted delegate access to {delegate.delegate_email}",
                    "is_external": is_external,
                }
            )

        # Forwarding issues
        for rule in result.forwarding_rules:
            is_external = not rule.forward_to.endswith(f"@{self.domain}")

            issues.append(
                {
                    "type": "gmail_forwarding",
                    "severity": "critical" if is_external else "high",
                    "user": rule.user_email,
                    "forward_to": rule.forward_to,
                    "description": f"User has auto-forwarding enabled to {rule.forward_to}",
                    "is_external": is_external,
                }
            )

        return issues

    def _calculate_statistics(self, result: GmailSecurityScanResult) -> Dict:
        """Calculate summary statistics."""
        return {
            "total_users_scanned": result.total_users_scanned,
            "users_with_delegates": result.users_with_delegates,
            "users_with_forwarding": result.users_with_forwarding,
            "users_with_send_as": result.users_with_send_as,
            "users_with_risky_filters": result.users_with_risky_filters,
            "total_delegates": len(result.delegates),
            "total_forwarding_rules": len(result.forwarding_rules),
            "total_send_as_aliases": len(result.send_as_aliases),
            "total_risky_filters": len(result.risky_filters),
            "total_issues": len(result.issues),
        }

