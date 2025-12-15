"""
Vaulytica API Resource Handlers

This module provides resource classes for each API endpoint group.
"""

from typing import Any, Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from .client import VaulyticaClient, AsyncVaulyticaClient


class BaseResource:
    """Base class for API resources."""

    def __init__(self, client: "VaulyticaClient"):
        self._client = client

    def _request(self, method: str, endpoint: str, **kwargs) -> Any:
        return self._client._request(method, endpoint, **kwargs)


class AsyncBaseResource:
    """Base class for async API resources."""

    def __init__(self, client: "AsyncVaulyticaClient"):
        self._client = client

    async def _request(self, method: str, endpoint: str, **kwargs) -> Any:
        return await self._client._request(method, endpoint, **kwargs)


# ============================================================================
# Scans Resource
# ============================================================================


class ScansResource(BaseResource):
    """
    Scans API resource.

    Example:
        client.scans.list()
        client.scans.trigger(domain_id=1, scan_type="files")
        client.scans.get(scan_id=123)
        client.scans.cancel(scan_id=123)
    """

    def list(
        self,
        page: int = 1,
        page_size: int = 20,
        domain_id: Optional[int] = None,
        scan_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> dict:
        """
        List scans with pagination and filtering.

        Args:
            page: Page number (default: 1)
            page_size: Items per page (default: 20)
            domain_id: Filter by domain ID
            scan_type: Filter by scan type (files, users, oauth, posture, all)
            status: Filter by status (pending, running, completed, failed, cancelled)

        Returns:
            Paginated list of scans
        """
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        if scan_type:
            params["scan_type"] = scan_type
        if status:
            params["status"] = status
        return self._request("GET", "/scans", params=params)

    def get(self, scan_id: int) -> dict:
        """
        Get a specific scan by ID.

        Args:
            scan_id: Scan ID

        Returns:
            Scan details
        """
        return self._request("GET", f"/scans/{scan_id}")

    def trigger(
        self,
        domain_id: int,
        scan_type: str = "all",
    ) -> dict:
        """
        Trigger a new scan.

        Args:
            domain_id: Domain to scan
            scan_type: Type of scan (files, users, oauth, posture, all)

        Returns:
            Created scan details
        """
        return self._request(
            "POST",
            "/scans/trigger",
            json={"domain_id": domain_id, "scan_type": scan_type},
        )

    def cancel(self, scan_id: int, reason: Optional[str] = None) -> dict:
        """
        Cancel a running scan.

        Args:
            scan_id: Scan ID to cancel
            reason: Optional cancellation reason

        Returns:
            Updated scan details
        """
        json_data = {}
        if reason:
            json_data["reason"] = reason
        return self._request("POST", f"/scans/{scan_id}/cancel", json=json_data or None)

    def compare(self, scan_id_1: int, scan_id_2: int) -> dict:
        """
        Compare two scans.

        Args:
            scan_id_1: First scan ID
            scan_id_2: Second scan ID

        Returns:
            Comparison results with new/resolved issues
        """
        return self._request(
            "GET",
            "/scans/compare",
            params={"scan_id_1": scan_id_1, "scan_id_2": scan_id_2},
        )

    def get_stats(self) -> dict:
        """
        Get scan statistics.

        Returns:
            Scan statistics summary
        """
        return self._request("GET", "/scans/stats")


class AsyncScansResource(AsyncBaseResource):
    """Async version of ScansResource."""

    async def list(self, **kwargs) -> dict:
        params = {"page": kwargs.get("page", 1), "page_size": kwargs.get("page_size", 20)}
        for key in ["domain_id", "scan_type", "status"]:
            if kwargs.get(key):
                params[key] = kwargs[key]
        return await self._request("GET", "/scans", params=params)

    async def get(self, scan_id: int) -> dict:
        return await self._request("GET", f"/scans/{scan_id}")

    async def trigger(self, domain_id: int, scan_type: str = "all") -> dict:
        return await self._request(
            "POST", "/scans/trigger", json={"domain_id": domain_id, "scan_type": scan_type}
        )

    async def cancel(self, scan_id: int, reason: Optional[str] = None) -> dict:
        json_data = {"reason": reason} if reason else None
        return await self._request("POST", f"/scans/{scan_id}/cancel", json=json_data)

    async def compare(self, scan_id_1: int, scan_id_2: int) -> dict:
        return await self._request(
            "GET", "/scans/compare", params={"scan_id_1": scan_id_1, "scan_id_2": scan_id_2}
        )

    async def get_stats(self) -> dict:
        return await self._request("GET", "/scans/stats")


# ============================================================================
# Findings Resource
# ============================================================================


class FindingsResource(BaseResource):
    """
    Findings API resource.

    Example:
        client.findings.list_security()
        client.findings.list_files(domain_id=1)
        client.findings.update_status(finding_id=123, status="resolved")
        client.findings.export_security(format="csv")
    """

    def list_security(
        self,
        page: int = 1,
        page_size: int = 20,
        domain_id: Optional[int] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> dict:
        """List security findings."""
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        return self._request("GET", "/findings/security", params=params)

    def list_files(
        self,
        page: int = 1,
        page_size: int = 20,
        domain_id: Optional[int] = None,
        high_risk: Optional[bool] = None,
        public: Optional[bool] = None,
    ) -> dict:
        """List file findings."""
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        if high_risk is not None:
            params["high_risk"] = high_risk
        if public is not None:
            params["public"] = public
        return self._request("GET", "/findings/files", params=params)

    def list_users(
        self,
        page: int = 1,
        page_size: int = 20,
        domain_id: Optional[int] = None,
        inactive: Optional[bool] = None,
        no_2fa: Optional[bool] = None,
    ) -> dict:
        """List user findings."""
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        if inactive is not None:
            params["inactive"] = inactive
        if no_2fa is not None:
            params["no_2fa"] = no_2fa
        return self._request("GET", "/findings/users", params=params)

    def list_oauth(
        self,
        page: int = 1,
        page_size: int = 20,
        domain_id: Optional[int] = None,
        risky: Optional[bool] = None,
    ) -> dict:
        """List OAuth app findings."""
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        if risky is not None:
            params["risky"] = risky
        return self._request("GET", "/findings/oauth", params=params)

    def get_security(self, finding_id: int) -> dict:
        """Get a specific security finding."""
        return self._request("GET", f"/findings/security/{finding_id}")

    def get_file(self, finding_id: int) -> dict:
        """Get a specific file finding."""
        return self._request("GET", f"/findings/files/{finding_id}")

    def get_user(self, finding_id: int) -> dict:
        """Get a specific user finding."""
        return self._request("GET", f"/findings/users/{finding_id}")

    def get_oauth(self, finding_id: int) -> dict:
        """Get a specific OAuth finding."""
        return self._request("GET", f"/findings/oauth/{finding_id}")

    def update_status(
        self,
        finding_id: int,
        status: str,
        notes: Optional[str] = None,
    ) -> dict:
        """
        Update finding status.

        Args:
            finding_id: Finding ID
            status: New status (open, acknowledged, resolved, false_positive)
            notes: Optional notes about the status change

        Returns:
            Updated finding details
        """
        json_data = {"status": status}
        if notes:
            json_data["notes"] = notes
        return self._request("PATCH", f"/findings/{finding_id}/status", json=json_data)

    def get_summary(self, domain_id: Optional[int] = None) -> dict:
        """Get findings summary."""
        params = {}
        if domain_id:
            params["domain_id"] = domain_id
        return self._request("GET", "/findings/security/summary", params=params)

    def export_security(self, format: str = "csv", domain_id: Optional[int] = None) -> bytes:
        """Export security findings."""
        params = {"format": format}
        if domain_id:
            params["domain_id"] = domain_id
        return self._request(
            "GET", "/findings/export/security", params=params, raw_response=True
        )

    def export_files(self, format: str = "csv", domain_id: Optional[int] = None) -> bytes:
        """Export file findings."""
        params = {"format": format}
        if domain_id:
            params["domain_id"] = domain_id
        return self._request(
            "GET", "/findings/export/files", params=params, raw_response=True
        )

    def export_users(self, format: str = "csv", domain_id: Optional[int] = None) -> bytes:
        """Export user findings."""
        params = {"format": format}
        if domain_id:
            params["domain_id"] = domain_id
        return self._request(
            "GET", "/findings/export/users", params=params, raw_response=True
        )

    def export_oauth(self, format: str = "csv", domain_id: Optional[int] = None) -> bytes:
        """Export OAuth findings."""
        params = {"format": format}
        if domain_id:
            params["domain_id"] = domain_id
        return self._request(
            "GET", "/findings/export/oauth", params=params, raw_response=True
        )


class AsyncFindingsResource(AsyncBaseResource):
    """Async version of FindingsResource."""

    async def list_security(self, **kwargs) -> dict:
        params = {"page": kwargs.get("page", 1), "page_size": kwargs.get("page_size", 20)}
        for key in ["domain_id", "severity", "status"]:
            if kwargs.get(key):
                params[key] = kwargs[key]
        return await self._request("GET", "/findings/security", params=params)

    async def list_files(self, **kwargs) -> dict:
        params = {"page": kwargs.get("page", 1), "page_size": kwargs.get("page_size", 20)}
        for key in ["domain_id", "high_risk", "public"]:
            if key in kwargs and kwargs[key] is not None:
                params[key] = kwargs[key]
        return await self._request("GET", "/findings/files", params=params)

    async def list_users(self, **kwargs) -> dict:
        params = {"page": kwargs.get("page", 1), "page_size": kwargs.get("page_size", 20)}
        for key in ["domain_id", "inactive", "no_2fa"]:
            if key in kwargs and kwargs[key] is not None:
                params[key] = kwargs[key]
        return await self._request("GET", "/findings/users", params=params)

    async def list_oauth(self, **kwargs) -> dict:
        params = {"page": kwargs.get("page", 1), "page_size": kwargs.get("page_size", 20)}
        for key in ["domain_id", "risky"]:
            if key in kwargs and kwargs[key] is not None:
                params[key] = kwargs[key]
        return await self._request("GET", "/findings/oauth", params=params)

    async def get_security(self, finding_id: int) -> dict:
        return await self._request("GET", f"/findings/security/{finding_id}")

    async def get_file(self, finding_id: int) -> dict:
        return await self._request("GET", f"/findings/files/{finding_id}")

    async def get_user(self, finding_id: int) -> dict:
        return await self._request("GET", f"/findings/users/{finding_id}")

    async def get_oauth(self, finding_id: int) -> dict:
        return await self._request("GET", f"/findings/oauth/{finding_id}")

    async def update_status(self, finding_id: int, status: str, notes: Optional[str] = None) -> dict:
        json_data = {"status": status}
        if notes:
            json_data["notes"] = notes
        return await self._request("PATCH", f"/findings/{finding_id}/status", json=json_data)

    async def get_summary(self, domain_id: Optional[int] = None) -> dict:
        params = {"domain_id": domain_id} if domain_id else {}
        return await self._request("GET", "/findings/security/summary", params=params)

    async def export_security(self, format: str = "csv", domain_id: Optional[int] = None) -> bytes:
        params = {"format": format}
        if domain_id:
            params["domain_id"] = domain_id
        return await self._request("GET", "/findings/export/security", params=params, raw_response=True)


# ============================================================================
# Domains Resource
# ============================================================================


class DomainsResource(BaseResource):
    """
    Domains API resource.

    Example:
        client.domains.list()
        client.domains.create(name="example.com", credentials={...})
        client.domains.get(domain_id=1)
    """

    def list(self, page: int = 1, page_size: int = 20) -> dict:
        """List domains."""
        return self._request("GET", "/domains", params={"page": page, "page_size": page_size})

    def get(self, domain_id: int) -> dict:
        """Get a specific domain."""
        return self._request("GET", f"/domains/{domain_id}")

    def create(
        self,
        name: str,
        credentials: dict,
        admin_email: Optional[str] = None,
    ) -> dict:
        """
        Create a new domain.

        Args:
            name: Domain name (e.g., "example.com")
            credentials: Google service account credentials (JSON)
            admin_email: Admin email for impersonation

        Returns:
            Created domain details
        """
        json_data = {"name": name, "credentials": credentials}
        if admin_email:
            json_data["admin_email"] = admin_email
        return self._request("POST", "/domains", json=json_data)

    def update(
        self,
        domain_id: int,
        name: Optional[str] = None,
        credentials: Optional[dict] = None,
        admin_email: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> dict:
        """Update a domain."""
        json_data = {}
        if name is not None:
            json_data["name"] = name
        if credentials is not None:
            json_data["credentials"] = credentials
        if admin_email is not None:
            json_data["admin_email"] = admin_email
        if is_active is not None:
            json_data["is_active"] = is_active
        return self._request("PATCH", f"/domains/{domain_id}", json=json_data)

    def delete(self, domain_id: int) -> None:
        """Delete a domain."""
        self._request("DELETE", f"/domains/{domain_id}")


class AsyncDomainsResource(AsyncBaseResource):
    """Async version of DomainsResource."""

    async def list(self, page: int = 1, page_size: int = 20) -> dict:
        return await self._request("GET", "/domains", params={"page": page, "page_size": page_size})

    async def get(self, domain_id: int) -> dict:
        return await self._request("GET", f"/domains/{domain_id}")

    async def create(self, name: str, credentials: dict, admin_email: Optional[str] = None) -> dict:
        json_data = {"name": name, "credentials": credentials}
        if admin_email:
            json_data["admin_email"] = admin_email
        return await self._request("POST", "/domains", json=json_data)

    async def update(self, domain_id: int, **kwargs) -> dict:
        json_data = {k: v for k, v in kwargs.items() if v is not None}
        return await self._request("PATCH", f"/domains/{domain_id}", json=json_data)

    async def delete(self, domain_id: int) -> None:
        await self._request("DELETE", f"/domains/{domain_id}")


# ============================================================================
# Schedules Resource
# ============================================================================


class SchedulesResource(BaseResource):
    """
    Schedules API resource.

    Example:
        client.schedules.list()
        client.schedules.create(name="Daily Scan", domain_id=1, scan_type="files", schedule_type="daily")
    """

    def list(self, page: int = 1, page_size: int = 20, domain_id: Optional[int] = None) -> dict:
        """List schedules."""
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        return self._request("GET", "/schedules", params=params)

    def get(self, schedule_id: int) -> dict:
        """Get a specific schedule."""
        return self._request("GET", f"/schedules/{schedule_id}")

    def create(
        self,
        name: str,
        domain_id: int,
        scan_type: str,
        schedule_type: str,
        hour: int = 2,
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None,
    ) -> dict:
        """
        Create a new schedule.

        Args:
            name: Schedule name
            domain_id: Domain to scan
            scan_type: Type of scan (files, users, oauth, posture, all)
            schedule_type: Schedule frequency (daily, weekly, monthly)
            hour: Hour to run (0-23, default: 2)
            day_of_week: Day of week for weekly (0=Monday, 6=Sunday)
            day_of_month: Day of month for monthly (1-31)

        Returns:
            Created schedule details
        """
        json_data = {
            "name": name,
            "domain_id": domain_id,
            "scan_type": scan_type,
            "schedule_type": schedule_type,
            "hour": hour,
        }
        if day_of_week is not None:
            json_data["day_of_week"] = day_of_week
        if day_of_month is not None:
            json_data["day_of_month"] = day_of_month
        return self._request("POST", "/schedules", json=json_data)

    def update(self, schedule_id: int, **kwargs) -> dict:
        """Update a schedule."""
        json_data = {k: v for k, v in kwargs.items() if v is not None}
        return self._request("PATCH", f"/schedules/{schedule_id}", json=json_data)

    def delete(self, schedule_id: int) -> None:
        """Delete a schedule."""
        self._request("DELETE", f"/schedules/{schedule_id}")

    def toggle(self, schedule_id: int) -> dict:
        """Toggle schedule active/paused state."""
        return self._request("POST", f"/schedules/{schedule_id}/toggle")


class AsyncSchedulesResource(AsyncBaseResource):
    """Async version of SchedulesResource."""

    async def list(self, page: int = 1, page_size: int = 20, domain_id: Optional[int] = None) -> dict:
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        return await self._request("GET", "/schedules", params=params)

    async def get(self, schedule_id: int) -> dict:
        return await self._request("GET", f"/schedules/{schedule_id}")

    async def create(self, **kwargs) -> dict:
        return await self._request("POST", "/schedules", json=kwargs)

    async def update(self, schedule_id: int, **kwargs) -> dict:
        json_data = {k: v for k, v in kwargs.items() if v is not None}
        return await self._request("PATCH", f"/schedules/{schedule_id}", json=json_data)

    async def delete(self, schedule_id: int) -> None:
        await self._request("DELETE", f"/schedules/{schedule_id}")

    async def toggle(self, schedule_id: int) -> dict:
        return await self._request("POST", f"/schedules/{schedule_id}/toggle")


# ============================================================================
# Alerts Resource
# ============================================================================


class AlertsResource(BaseResource):
    """
    Alerts API resource.

    Example:
        client.alerts.list()
        client.alerts.create(name="High Risk Alert", domain_id=1, condition_type="high_risk_file")
    """

    def list(self, page: int = 1, page_size: int = 20, domain_id: Optional[int] = None) -> dict:
        """List alert rules."""
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        return self._request("GET", "/alerts", params=params)

    def get(self, alert_id: int) -> dict:
        """Get a specific alert rule."""
        return self._request("GET", f"/alerts/{alert_id}")

    def create(
        self,
        name: str,
        domain_id: int,
        condition_type: str,
        threshold: int = 1,
        email_recipients: Optional[List[str]] = None,
        webhook_url: Optional[str] = None,
    ) -> dict:
        """
        Create a new alert rule.

        Args:
            name: Alert name
            domain_id: Domain to monitor
            condition_type: Condition type (high_risk_file, public_file, etc.)
            threshold: Threshold count to trigger (default: 1)
            email_recipients: List of email addresses to notify
            webhook_url: Webhook URL to call

        Returns:
            Created alert details
        """
        json_data = {
            "name": name,
            "domain_id": domain_id,
            "condition_type": condition_type,
            "threshold": threshold,
        }
        if email_recipients:
            json_data["email_recipients"] = email_recipients
        if webhook_url:
            json_data["webhook_url"] = webhook_url
        return self._request("POST", "/alerts", json=json_data)

    def update(self, alert_id: int, **kwargs) -> dict:
        """Update an alert rule."""
        json_data = {k: v for k, v in kwargs.items() if v is not None}
        return self._request("PATCH", f"/alerts/{alert_id}", json=json_data)

    def delete(self, alert_id: int) -> None:
        """Delete an alert rule."""
        self._request("DELETE", f"/alerts/{alert_id}")

    def get_condition_types(self) -> List[dict]:
        """Get available condition types."""
        return self._request("GET", "/alerts/condition-types")


class AsyncAlertsResource(AsyncBaseResource):
    """Async version of AlertsResource."""

    async def list(self, page: int = 1, page_size: int = 20, domain_id: Optional[int] = None) -> dict:
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        return await self._request("GET", "/alerts", params=params)

    async def get(self, alert_id: int) -> dict:
        return await self._request("GET", f"/alerts/{alert_id}")

    async def create(self, **kwargs) -> dict:
        return await self._request("POST", "/alerts", json=kwargs)

    async def update(self, alert_id: int, **kwargs) -> dict:
        json_data = {k: v for k, v in kwargs.items() if v is not None}
        return await self._request("PATCH", f"/alerts/{alert_id}", json=json_data)

    async def delete(self, alert_id: int) -> None:
        await self._request("DELETE", f"/alerts/{alert_id}")

    async def get_condition_types(self) -> List[dict]:
        return await self._request("GET", "/alerts/condition-types")


# ============================================================================
# Compliance Resource
# ============================================================================


class ComplianceResource(BaseResource):
    """
    Compliance API resource.

    Example:
        client.compliance.list()
        client.compliance.generate(domain_id=1, framework="hipaa")
        client.compliance.get(report_id=1)
    """

    def list(
        self,
        page: int = 1,
        page_size: int = 20,
        domain_id: Optional[int] = None,
        framework: Optional[str] = None,
    ) -> dict:
        """List compliance reports."""
        params = {"page": page, "page_size": page_size}
        if domain_id:
            params["domain_id"] = domain_id
        if framework:
            params["framework"] = framework
        return self._request("GET", "/compliance", params=params)

    def get(self, report_id: int) -> dict:
        """Get a specific compliance report."""
        return self._request("GET", f"/compliance/{report_id}")

    def generate(self, domain_id: int, framework: str) -> dict:
        """
        Generate a new compliance report.

        Args:
            domain_id: Domain to assess
            framework: Compliance framework (gdpr, hipaa, soc2, pci_dss, ferpa, fedramp)

        Returns:
            Generated report details
        """
        return self._request(
            "POST",
            "/compliance",
            json={"domain_id": domain_id, "framework": framework},
        )

    def delete(self, report_id: int) -> None:
        """Delete a compliance report."""
        self._request("DELETE", f"/compliance/{report_id}")

    def get_frameworks(self) -> List[dict]:
        """Get available compliance frameworks."""
        return self._request("GET", "/compliance/frameworks")

    def list_schedules(self, page: int = 1, page_size: int = 20) -> dict:
        """List compliance report schedules."""
        return self._request(
            "GET", "/compliance/schedules", params={"page": page, "page_size": page_size}
        )

    def create_schedule(
        self,
        name: str,
        domain_id: int,
        framework: str,
        schedule_type: str,
        recipients: List[str],
        hour: int = 2,
        day_of_week: Optional[int] = None,
        day_of_month: Optional[int] = None,
    ) -> dict:
        """Create a compliance report schedule."""
        json_data = {
            "name": name,
            "domain_id": domain_id,
            "framework": framework,
            "schedule_type": schedule_type,
            "recipients": recipients,
            "hour": hour,
        }
        if day_of_week is not None:
            json_data["day_of_week"] = day_of_week
        if day_of_month is not None:
            json_data["day_of_month"] = day_of_month
        return self._request("POST", "/compliance/schedules", json=json_data)


class AsyncComplianceResource(AsyncBaseResource):
    """Async version of ComplianceResource."""

    async def list(self, **kwargs) -> dict:
        params = {"page": kwargs.get("page", 1), "page_size": kwargs.get("page_size", 20)}
        for key in ["domain_id", "framework"]:
            if kwargs.get(key):
                params[key] = kwargs[key]
        return await self._request("GET", "/compliance", params=params)

    async def get(self, report_id: int) -> dict:
        return await self._request("GET", f"/compliance/{report_id}")

    async def generate(self, domain_id: int, framework: str) -> dict:
        return await self._request(
            "POST", "/compliance", json={"domain_id": domain_id, "framework": framework}
        )

    async def delete(self, report_id: int) -> None:
        await self._request("DELETE", f"/compliance/{report_id}")

    async def get_frameworks(self) -> List[dict]:
        return await self._request("GET", "/compliance/frameworks")


# ============================================================================
# Users Resource
# ============================================================================


class UsersResource(BaseResource):
    """
    Users API resource (admin only).

    Example:
        client.users.list()
        client.users.get(user_id=1)
        client.users.update(user_id=1, name="New Name")
    """

    def list(
        self,
        page: int = 1,
        page_size: int = 20,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_superuser: Optional[bool] = None,
    ) -> dict:
        """List users (admin only)."""
        params = {"page": page, "page_size": page_size}
        if search:
            params["search"] = search
        if is_active is not None:
            params["is_active"] = is_active
        if is_superuser is not None:
            params["is_superuser"] = is_superuser
        return self._request("GET", "/users", params=params)

    def get(self, user_id: int) -> dict:
        """Get a specific user."""
        return self._request("GET", f"/users/{user_id}")

    def update(
        self,
        user_id: int,
        email: Optional[str] = None,
        name: Optional[str] = None,
        password: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_superuser: Optional[bool] = None,
    ) -> dict:
        """Update a user."""
        json_data = {}
        if email is not None:
            json_data["email"] = email
        if name is not None:
            json_data["name"] = name
        if password is not None:
            json_data["password"] = password
        if is_active is not None:
            json_data["is_active"] = is_active
        if is_superuser is not None:
            json_data["is_superuser"] = is_superuser
        return self._request("PATCH", f"/users/{user_id}", json=json_data)

    def delete(self, user_id: int) -> None:
        """Delete a user."""
        self._request("DELETE", f"/users/{user_id}")

    def activate(self, user_id: int) -> dict:
        """Activate a user."""
        return self._request("POST", f"/users/{user_id}/activate")

    def deactivate(self, user_id: int) -> dict:
        """Deactivate a user."""
        return self._request("POST", f"/users/{user_id}/deactivate")


class AsyncUsersResource(AsyncBaseResource):
    """Async version of UsersResource."""

    async def list(self, **kwargs) -> dict:
        params = {"page": kwargs.get("page", 1), "page_size": kwargs.get("page_size", 20)}
        for key in ["search", "is_active", "is_superuser"]:
            if key in kwargs and kwargs[key] is not None:
                params[key] = kwargs[key]
        return await self._request("GET", "/users", params=params)

    async def get(self, user_id: int) -> dict:
        return await self._request("GET", f"/users/{user_id}")

    async def update(self, user_id: int, **kwargs) -> dict:
        json_data = {k: v for k, v in kwargs.items() if v is not None}
        return await self._request("PATCH", f"/users/{user_id}", json=json_data)

    async def delete(self, user_id: int) -> None:
        await self._request("DELETE", f"/users/{user_id}")

    async def activate(self, user_id: int) -> dict:
        return await self._request("POST", f"/users/{user_id}/activate")

    async def deactivate(self, user_id: int) -> dict:
        return await self._request("POST", f"/users/{user_id}/deactivate")


# ============================================================================
# Audit Resource
# ============================================================================


class AuditResource(BaseResource):
    """
    Audit logs API resource.

    Example:
        client.audit.list()
        client.audit.get_summary()
    """

    def list(
        self,
        page: int = 1,
        page_size: int = 20,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        user_id: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> dict:
        """List audit logs."""
        params = {"page": page, "page_size": page_size}
        if action:
            params["action"] = action
        if resource_type:
            params["resource_type"] = resource_type
        if user_id:
            params["user_id"] = user_id
        if start_date:
            params["start_date"] = start_date
        if end_date:
            params["end_date"] = end_date
        return self._request("GET", "/audit-logs", params=params)

    def get_summary(self) -> dict:
        """Get audit activity summary."""
        return self._request("GET", "/audit-logs/summary")


class AsyncAuditResource(AsyncBaseResource):
    """Async version of AuditResource."""

    async def list(self, **kwargs) -> dict:
        params = {"page": kwargs.get("page", 1), "page_size": kwargs.get("page_size", 20)}
        for key in ["action", "resource_type", "user_id", "start_date", "end_date"]:
            if kwargs.get(key):
                params[key] = kwargs[key]
        return await self._request("GET", "/audit-logs", params=params)

    async def get_summary(self) -> dict:
        return await self._request("GET", "/audit-logs/summary")


# ============================================================================
# Delta Tracking Resource
# ============================================================================


class DeltaResource(BaseResource):
    """
    Delta tracking and deduplication API resource.

    Provides functionality for:
    - Comparing findings between scans to identify new, resolved, and changed issues
    - Tracking finding history across multiple scans using fingerprints
    - Analyzing trends in findings over time
    - Identifying duplicate/recurring findings

    Example:
        # Compare two scans
        delta = client.delta.compare(scan_id_1=10, scan_id_2=20, finding_type="security")

        # Get latest delta (between last two scans)
        delta = client.delta.get_latest(domain="example.com", finding_type="files")

        # Get trend data
        trend = client.delta.get_trend(domain="example.com", finding_type="users")

        # Find duplicate findings
        duplicates = client.delta.get_duplicates(domain="example.com", finding_type="oauth")

        # Get finding history by fingerprint
        history = client.delta.get_history(fingerprint="abc123", domain="example.com", finding_type="security")
    """

    def compare(
        self,
        scan_id_1: int,
        scan_id_2: int,
        finding_type: str,
    ) -> dict:
        """
        Compare findings between two scans.

        Args:
            scan_id_1: First (older) scan ID
            scan_id_2: Second (newer) scan ID
            finding_type: Type of findings (security, file, user, oauth)

        Returns:
            Delta comparison with new, resolved, unchanged, and changed findings
        """
        return self._request(
            "GET",
            "/delta/compare",
            params={
                "scan_id_1": scan_id_1,
                "scan_id_2": scan_id_2,
                "finding_type": finding_type,
            },
        )

    def get_latest(self, domain: str, finding_type: str) -> Optional[dict]:
        """
        Get delta between the two most recent scans for a domain.

        Args:
            domain: Domain name
            finding_type: Type of findings (security, file, user, oauth)

        Returns:
            Delta comparison or None if fewer than 2 scans exist
        """
        return self._request(
            "GET",
            "/delta/latest",
            params={"domain": domain, "finding_type": finding_type},
        )

    def get_trend(
        self,
        domain: str,
        finding_type: str,
        num_scans: int = 10,
    ) -> dict:
        """
        Get trend data showing how findings changed over multiple scans.

        Args:
            domain: Domain name
            finding_type: Type of findings (security, file, user, oauth)
            num_scans: Number of scans to include (default: 10, max: 50)

        Returns:
            Trend data with data points for each scan
        """
        return self._request(
            "GET",
            "/delta/trend",
            params={
                "domain": domain,
                "finding_type": finding_type,
                "num_scans": num_scans,
            },
        )

    def get_duplicates(
        self,
        domain: str,
        finding_type: str,
        lookback_scans: int = 5,
    ) -> dict:
        """
        Find duplicate findings across recent scans.

        Args:
            domain: Domain name
            finding_type: Type of findings (security, file, user, oauth)
            lookback_scans: Number of scans to check (default: 5, max: 20)

        Returns:
            Findings that appear in multiple scans, grouped by fingerprint
        """
        return self._request(
            "GET",
            "/delta/duplicates",
            params={
                "domain": domain,
                "finding_type": finding_type,
                "lookback_scans": lookback_scans,
            },
        )

    def get_history(
        self,
        fingerprint: str,
        domain: str,
        finding_type: str,
        max_scans: int = 10,
    ) -> dict:
        """
        Get the history of a specific finding across scans.

        Args:
            fingerprint: Finding fingerprint (unique identifier)
            domain: Domain name
            finding_type: Type of finding (security, file, user, oauth)
            max_scans: Maximum scans to look back (default: 10, max: 50)

        Returns:
            History showing when the finding appeared/disappeared
        """
        return self._request(
            "GET",
            f"/delta/history/{fingerprint}",
            params={
                "domain": domain,
                "finding_type": finding_type,
                "max_scans": max_scans,
            },
        )

    def analyze(self, scan_id: int, finding_type: str) -> dict:
        """
        Analyze a scan to identify new vs recurring findings.

        Args:
            scan_id: Scan ID to analyze
            finding_type: Type of findings (security, file, user, oauth)

        Returns:
            Analysis with counts of new vs recurring findings
        """
        return self._request(
            "POST",
            f"/delta/analyze/{scan_id}",
            params={"finding_type": finding_type},
        )


class AsyncDeltaResource(AsyncBaseResource):
    """Async version of DeltaResource."""

    async def compare(
        self,
        scan_id_1: int,
        scan_id_2: int,
        finding_type: str,
    ) -> dict:
        return await self._request(
            "GET",
            "/delta/compare",
            params={
                "scan_id_1": scan_id_1,
                "scan_id_2": scan_id_2,
                "finding_type": finding_type,
            },
        )

    async def get_latest(self, domain: str, finding_type: str) -> Optional[dict]:
        return await self._request(
            "GET",
            "/delta/latest",
            params={"domain": domain, "finding_type": finding_type},
        )

    async def get_trend(
        self,
        domain: str,
        finding_type: str,
        num_scans: int = 10,
    ) -> dict:
        return await self._request(
            "GET",
            "/delta/trend",
            params={
                "domain": domain,
                "finding_type": finding_type,
                "num_scans": num_scans,
            },
        )

    async def get_duplicates(
        self,
        domain: str,
        finding_type: str,
        lookback_scans: int = 5,
    ) -> dict:
        return await self._request(
            "GET",
            "/delta/duplicates",
            params={
                "domain": domain,
                "finding_type": finding_type,
                "lookback_scans": lookback_scans,
            },
        )

    async def get_history(
        self,
        fingerprint: str,
        domain: str,
        finding_type: str,
        max_scans: int = 10,
    ) -> dict:
        return await self._request(
            "GET",
            f"/delta/history/{fingerprint}",
            params={
                "domain": domain,
                "finding_type": finding_type,
                "max_scans": max_scans,
            },
        )

    async def analyze(self, scan_id: int, finding_type: str) -> dict:
        return await self._request(
            "POST",
            f"/delta/analyze/{scan_id}",
            params={"finding_type": finding_type},
        )
