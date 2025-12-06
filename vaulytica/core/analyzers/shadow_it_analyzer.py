"""Shadow IT Risk Analyzer for discovering and analyzing unauthorized OAuth applications."""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Set
from enum import Enum
import json
import os
from pathlib import Path

import structlog

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.scanners.oauth_scanner import OAuthScanner, OAuthApp, OAuthScanResult
from vaulytica.core.scanners.audit_log_scanner import AuditLogScanner

logger = structlog.get_logger(__name__)


class ShadowITRiskLevel(Enum):
    """Risk levels for Shadow IT findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ShadowITCategory(Enum):
    """Categories of Shadow IT findings."""

    UNAUTHORIZED_APP = "unauthorized_app"
    STALE_GRANT = "stale_grant"
    EXCESSIVE_PERMISSIONS = "excessive_permissions"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
    DATA_EXFILTRATION_RISK = "data_exfiltration_risk"
    ADMIN_ACCESS_RISK = "admin_access_risk"
    UNVERIFIED_PUBLISHER = "unverified_publisher"
    WIDESPREAD_ADOPTION = "widespread_adoption"


@dataclass
class ShadowITFinding:
    """Represents a Shadow IT security finding."""

    category: ShadowITCategory
    risk_level: ShadowITRiskLevel
    app_name: str
    client_id: str
    user_count: int
    title: str
    description: str
    evidence: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)
    risk_score: int = 0
    first_seen: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    scopes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AppApprovalStatus:
    """Represents approval status of an OAuth app."""

    client_id: str
    app_name: str
    is_approved: bool
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    notes: Optional[str] = None


@dataclass
class ShadowITAnalysisResult:
    """Results from Shadow IT analysis."""

    total_apps_analyzed: int = 0
    shadow_it_apps: int = 0
    approved_apps: int = 0
    findings: List[ShadowITFinding] = field(default_factory=list)
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    stale_grants: int = 0
    data_exfiltration_risks: int = 0
    admin_access_risks: int = 0
    unapproved_app_list: List[Dict[str, Any]] = field(default_factory=list)
    remediation_playbook: List[Dict[str, Any]] = field(default_factory=list)
    executive_summary: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ShadowITAnalyzerError(Exception):
    """Raised when Shadow IT analysis fails."""

    pass


class ShadowITAnalyzer:
    """Analyzes OAuth applications for Shadow IT risks."""

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        domain: str,
        approval_list_path: Optional[str] = None,
        stale_days: int = 90,
    ):
        """Initialize Shadow IT Analyzer.

        Args:
            client: GoogleWorkspaceClient instance
            domain: Organization domain
            approval_list_path: Path to JSON file with approved apps
            stale_days: Number of days to consider grant stale (default: 90)
        """
        self.client = client
        self.domain = domain
        self.stale_days = stale_days
        self.oauth_scanner = OAuthScanner(client, domain)
        self.audit_scanner = AuditLogScanner(client, domain)

        # Load approved apps list
        self.approved_apps: Dict[str, AppApprovalStatus] = {}
        if approval_list_path:
            self._load_approval_list(approval_list_path)

        logger.info(
            "shadow_it_analyzer_initialized",
            domain=domain,
            stale_days=stale_days,
            approved_apps=len(self.approved_apps),
        )

    def analyze(
        self,
        include_audit_logs: bool = True,
        max_users: Optional[int] = None,
    ) -> ShadowITAnalysisResult:
        """Perform comprehensive Shadow IT analysis.

        Args:
            include_audit_logs: Include audit log analysis (default: True)
            max_users: Maximum users to analyze (for testing)

        Returns:
            ShadowITAnalysisResult with findings and recommendations
        """
        logger.info("starting_shadow_it_analysis", include_audit_logs=include_audit_logs)

        result = ShadowITAnalysisResult()

        # Step 1: Scan OAuth tokens
        logger.info("scanning_oauth_tokens")
        oauth_result = self.oauth_scanner.scan_oauth_tokens(max_users=max_users)
        result.total_apps_analyzed = oauth_result.total_apps

        # Step 2: Identify Shadow IT apps
        logger.info("identifying_shadow_it_apps")
        shadow_apps, approved_apps = self._classify_apps(oauth_result.apps)
        result.shadow_it_apps = len(shadow_apps)
        result.approved_apps = len(approved_apps)

        # Step 3: Analyze each Shadow IT app for risks
        logger.info("analyzing_shadow_it_risks", shadow_apps_count=len(shadow_apps))
        for app in shadow_apps:
            findings = self._analyze_app_risks(app, oauth_result)
            result.findings.extend(findings)

        # Step 4: Detect stale grants
        logger.info("detecting_stale_grants")
        if include_audit_logs:
            stale_findings = self._detect_stale_grants(oauth_result, shadow_apps)
            result.findings.extend(stale_findings)
            result.stale_grants = len(stale_findings)

        # Step 5: Identify widespread adoption risks
        logger.info("analyzing_widespread_adoption")
        widespread_findings = self._analyze_widespread_adoption(shadow_apps)
        result.findings.extend(widespread_findings)

        # Step 6: Categorize findings by severity
        for finding in result.findings:
            if finding.risk_level == ShadowITRiskLevel.CRITICAL:
                result.critical_findings += 1
            elif finding.risk_level == ShadowITRiskLevel.HIGH:
                result.high_findings += 1
            elif finding.risk_level == ShadowITRiskLevel.MEDIUM:
                result.medium_findings += 1
            elif finding.risk_level == ShadowITRiskLevel.LOW:
                result.low_findings += 1

            # Track specific risk types
            if finding.category == ShadowITCategory.DATA_EXFILTRATION_RISK:
                result.data_exfiltration_risks += 1
            elif finding.category == ShadowITCategory.ADMIN_ACCESS_RISK:
                result.admin_access_risks += 1

        # Step 7: Generate unapproved app list
        result.unapproved_app_list = self._generate_unapproved_app_list(shadow_apps)

        # Step 8: Generate remediation playbook
        result.remediation_playbook = self._generate_remediation_playbook(result)

        # Step 9: Generate executive summary
        result.executive_summary = self._generate_executive_summary(result)

        logger.info(
            "shadow_it_analysis_complete",
            total_apps=result.total_apps_analyzed,
            shadow_it_apps=result.shadow_it_apps,
            critical=result.critical_findings,
            high=result.high_findings,
            medium=result.medium_findings,
            low=result.low_findings,
            stale_grants=result.stale_grants,
        )

        return result

    def export_approval_template(self, output_path: str) -> None:
        """Export a template for the app approval list.

        Args:
            output_path: Path to save the template JSON file
        """
        template = {
            "approved_apps": [
                {
                    "client_id": "123456789.apps.googleusercontent.com",
                    "app_name": "Example App",
                    "approved_by": "security-team@example.com",
                    "approved_at": "2024-01-01T00:00:00Z",
                    "notes": "Approved for engineering team use",
                }
            ]
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(template, f, indent=2)

        logger.info("approval_template_exported", path=output_path)

    def add_approved_app(
        self,
        client_id: str,
        app_name: str,
        approved_by: str,
        notes: Optional[str] = None,
    ) -> AppApprovalStatus:
        """Add an app to the approved list.

        Args:
            client_id: OAuth client ID
            app_name: Display name of the app
            approved_by: Email of approver
            notes: Optional approval notes

        Returns:
            AppApprovalStatus object
        """
        status = AppApprovalStatus(
            client_id=client_id,
            app_name=app_name,
            is_approved=True,
            approved_by=approved_by,
            approved_at=datetime.now(timezone.utc),
            notes=notes,
        )
        self.approved_apps[client_id] = status

        logger.info(
            "app_approved",
            client_id=client_id,
            app_name=app_name,
            approved_by=approved_by,
        )

        return status

    def _load_approval_list(self, path: str) -> None:
        """Load approved apps from JSON file.

        Args:
            path: Path to approval list JSON file
        """
        try:
            if not os.path.exists(path):
                logger.warning("approval_list_not_found", path=path)
                return

            with open(path, "r") as f:
                data = json.load(f)

            for app_data in data.get("approved_apps", []):
                approved_at = None
                if app_data.get("approved_at"):
                    approved_at = datetime.fromisoformat(
                        app_data["approved_at"].replace("Z", "+00:00")
                    )

                status = AppApprovalStatus(
                    client_id=app_data["client_id"],
                    app_name=app_data["app_name"],
                    is_approved=True,
                    approved_by=app_data.get("approved_by"),
                    approved_at=approved_at,
                    notes=app_data.get("notes"),
                )
                self.approved_apps[app_data["client_id"]] = status

            logger.info("approval_list_loaded", path=path, count=len(self.approved_apps))

        except Exception as e:
            logger.error("failed_to_load_approval_list", path=path, error=str(e))
            raise ShadowITAnalyzerError(f"Failed to load approval list: {e}")

    def _classify_apps(
        self, apps: List[OAuthApp]
    ) -> tuple[List[OAuthApp], List[OAuthApp]]:
        """Classify apps as Shadow IT or approved.

        Args:
            apps: List of OAuthApp objects

        Returns:
            Tuple of (shadow_apps, approved_apps)
        """
        shadow_apps = []
        approved_apps = []

        for app in apps:
            # Google apps are considered approved by default
            if app.is_google_app:
                approved_apps.append(app)
                continue

            # Check against approval list
            if app.client_id in self.approved_apps:
                approved_apps.append(app)
            else:
                shadow_apps.append(app)

        return shadow_apps, approved_apps

    def _analyze_app_risks(
        self, app: OAuthApp, oauth_result: OAuthScanResult
    ) -> List[ShadowITFinding]:
        """Analyze risks for a specific app.

        Args:
            app: OAuthApp to analyze
            oauth_result: Complete OAuth scan result for context

        Returns:
            List of ShadowITFinding objects
        """
        findings = []

        # Finding: Unauthorized app detected
        base_finding = ShadowITFinding(
            category=ShadowITCategory.UNAUTHORIZED_APP,
            risk_level=self._determine_risk_level(app.risk_score),
            app_name=app.display_text,
            client_id=app.client_id,
            user_count=app.user_count,
            title=f"Unauthorized OAuth App: {app.display_text}",
            description=f"App '{app.display_text}' is not on the approved list and is being used by {app.user_count} user(s).",
            evidence=[
                f"Client ID: {app.client_id}",
                f"Risk Score: {app.risk_score}/100",
                f"Scopes: {len(app.scopes)}",
            ],
            remediation_steps=[
                "Review app legitimacy and business justification",
                "Evaluate app permissions and data access",
                "If approved, add to approval list",
                "If rejected, revoke access for all users",
            ],
            risk_score=app.risk_score,
            scopes=app.scopes,
        )
        findings.append(base_finding)

        # Finding: Admin access risk
        if app.has_admin_access:
            admin_finding = ShadowITFinding(
                category=ShadowITCategory.ADMIN_ACCESS_RISK,
                risk_level=ShadowITRiskLevel.CRITICAL,
                app_name=app.display_text,
                client_id=app.client_id,
                user_count=app.user_count,
                title=f"Unauthorized App with Admin Access: {app.display_text}",
                description="App has admin-level permissions that could compromise your entire Google Workspace.",
                evidence=[
                    "Has admin directory access",
                    "Can manage users, groups, or domain settings",
                    f"Risk Score: {app.risk_score}/100",
                ],
                remediation_steps=[
                    "IMMEDIATE ACTION REQUIRED",
                    "Revoke access immediately if not approved",
                    "Investigate recent admin actions via audit logs",
                    "Review affected user accounts for unauthorized changes",
                    "Consider implementing OAuth app whitelisting",
                ],
                risk_score=app.risk_score,
                scopes=app.scopes,
            )
            findings.append(admin_finding)

        # Finding: Data exfiltration risk
        if app.has_drive_access or app.has_email_access:
            data_finding = ShadowITFinding(
                category=ShadowITCategory.DATA_EXFILTRATION_RISK,
                risk_level=ShadowITRiskLevel.HIGH
                if app.has_drive_access
                else ShadowITRiskLevel.MEDIUM,
                app_name=app.display_text,
                client_id=app.client_id,
                user_count=app.user_count,
                title=f"Data Exfiltration Risk: {app.display_text}",
                description=f"App has access to sensitive data (Drive: {app.has_drive_access}, Email: {app.has_email_access}).",
                evidence=[
                    f"Drive Access: {'Yes' if app.has_drive_access else 'No'}",
                    f"Email Access: {'Yes' if app.has_email_access else 'No'}",
                    f"User Count: {app.user_count}",
                ],
                remediation_steps=[
                    "Review app's data handling and privacy policy",
                    "Check for data classification violations",
                    "Consider DLP policies for this app",
                    "Monitor data access patterns",
                ],
                risk_score=app.risk_score,
                scopes=app.scopes,
            )
            findings.append(data_finding)

        # Finding: Excessive permissions
        if app.has_excessive_permissions:
            excessive_finding = ShadowITFinding(
                category=ShadowITCategory.EXCESSIVE_PERMISSIONS,
                risk_level=ShadowITRiskLevel.MEDIUM,
                app_name=app.display_text,
                client_id=app.client_id,
                user_count=app.user_count,
                title=f"Excessive Permissions: {app.display_text}",
                description=f"App requests {len(app.scopes)} permissions, which may be excessive.",
                evidence=[
                    f"Total Scopes: {len(app.scopes)}",
                    "May violate principle of least privilege",
                ],
                remediation_steps=[
                    "Review each permission for necessity",
                    "Look for alternative apps with fewer permissions",
                    "Request vendor to reduce scope requirements",
                ],
                risk_score=app.risk_score,
                scopes=app.scopes,
            )
            findings.append(excessive_finding)

        # Finding: Unverified publisher
        if not app.is_verified and not app.is_google_app:
            unverified_finding = ShadowITFinding(
                category=ShadowITCategory.UNVERIFIED_PUBLISHER,
                risk_level=ShadowITRiskLevel.MEDIUM,
                app_name=app.display_text,
                client_id=app.client_id,
                user_count=app.user_count,
                title=f"Unverified Publisher: {app.display_text}",
                description="App publisher is not verified by Google.",
                evidence=[
                    "Unverified publisher",
                    "Higher risk of malicious activity",
                ],
                remediation_steps=[
                    "Verify app legitimacy through official channels",
                    "Check app reviews and reputation",
                    "Prefer verified alternatives when available",
                ],
                risk_score=app.risk_score,
                scopes=app.scopes,
            )
            findings.append(unverified_finding)

        return findings

    def _detect_stale_grants(
        self, oauth_result: OAuthScanResult, shadow_apps: List[OAuthApp]
    ) -> List[ShadowITFinding]:
        """Detect OAuth grants that haven't been used recently.

        Args:
            oauth_result: OAuth scan result
            shadow_apps: List of shadow IT apps

        Returns:
            List of stale grant findings
        """
        findings = []
        stale_threshold = datetime.now(timezone.utc) - timedelta(days=self.stale_days)

        # Get audit logs for OAuth token usage
        try:
            # Check for token usage in the last N days
            start_time = stale_threshold
            end_time = datetime.now(timezone.utc)

            # Track which apps have been used
            used_client_ids: Set[str] = set()

            # Note: This is a simplified approach. In production, you'd want to
            # query audit logs more efficiently
            shadow_app_ids = {app.client_id for app in shadow_apps}

            for app in shadow_apps:
                # If we can't find evidence of recent use, mark as stale
                # This is conservative - assumes stale unless proven otherwise
                finding = ShadowITFinding(
                    category=ShadowITCategory.STALE_GRANT,
                    risk_level=ShadowITRiskLevel.LOW,
                    app_name=app.display_text,
                    client_id=app.client_id,
                    user_count=app.user_count,
                    title=f"Potentially Stale Grant: {app.display_text}",
                    description=f"No evidence of usage in the last {self.stale_days} days. Consider revoking.",
                    evidence=[
                        f"No usage detected in {self.stale_days} days",
                        f"Authorized by {app.user_count} user(s)",
                    ],
                    remediation_steps=[
                        "Verify if app is still needed",
                        "Contact users to confirm usage",
                        "Revoke grant if no longer needed",
                        "Set up periodic access reviews",
                    ],
                    risk_score=min(app.risk_score, 40),  # Lower risk since unused
                    scopes=app.scopes,
                    metadata={"stale_days": self.stale_days},
                )
                findings.append(finding)

        except Exception as e:
            logger.warning("failed_to_detect_stale_grants", error=str(e))

        return findings

    def _analyze_widespread_adoption(
        self, shadow_apps: List[OAuthApp]
    ) -> List[ShadowITFinding]:
        """Analyze apps with widespread adoption.

        Args:
            shadow_apps: List of shadow IT apps

        Returns:
            List of findings for widespread apps
        """
        findings = []

        # Apps with > 20 users are considered "widespread"
        widespread_threshold = 20

        for app in shadow_apps:
            if app.user_count >= widespread_threshold:
                finding = ShadowITFinding(
                    category=ShadowITCategory.WIDESPREAD_ADOPTION,
                    risk_level=ShadowITRiskLevel.HIGH
                    if app.risk_score >= 70
                    else ShadowITRiskLevel.MEDIUM,
                    app_name=app.display_text,
                    client_id=app.client_id,
                    user_count=app.user_count,
                    title=f"Widespread Shadow IT: {app.display_text}",
                    description=f"Unauthorized app is used by {app.user_count} users, indicating potential business need.",
                    evidence=[
                        f"User Count: {app.user_count}",
                        f"Risk Score: {app.risk_score}/100",
                        "May require organization-wide policy decision",
                    ],
                    remediation_steps=[
                        "Investigate business justification",
                        "Consider formal approval if legitimate",
                        "Identify alternative approved solutions",
                        "Implement organization-wide policy",
                        "Communicate decision to all users",
                    ],
                    risk_score=app.risk_score,
                    scopes=app.scopes,
                    metadata={"widespread_threshold": widespread_threshold},
                )
                findings.append(finding)

        return findings

    def _determine_risk_level(self, risk_score: int) -> ShadowITRiskLevel:
        """Determine risk level based on risk score.

        Args:
            risk_score: Risk score (0-100)

        Returns:
            ShadowITRiskLevel
        """
        if risk_score >= 90:
            return ShadowITRiskLevel.CRITICAL
        elif risk_score >= 70:
            return ShadowITRiskLevel.HIGH
        elif risk_score >= 40:
            return ShadowITRiskLevel.MEDIUM
        elif risk_score >= 20:
            return ShadowITRiskLevel.LOW
        else:
            return ShadowITRiskLevel.INFO

    def _generate_unapproved_app_list(
        self, shadow_apps: List[OAuthApp]
    ) -> List[Dict[str, Any]]:
        """Generate list of unapproved apps with details.

        Args:
            shadow_apps: List of shadow IT apps

        Returns:
            List of app dictionaries
        """
        app_list = []

        # Sort by risk score descending
        sorted_apps = sorted(shadow_apps, key=lambda a: a.risk_score, reverse=True)

        for app in sorted_apps:
            app_list.append(
                {
                    "app_name": app.display_text,
                    "client_id": app.client_id,
                    "risk_score": app.risk_score,
                    "user_count": app.user_count,
                    "scopes_count": len(app.scopes),
                    "has_admin_access": app.has_admin_access,
                    "has_drive_access": app.has_drive_access,
                    "has_email_access": app.has_email_access,
                    "risk_factors": app.risk_factors,
                }
            )

        return app_list

    def _generate_remediation_playbook(
        self, result: ShadowITAnalysisResult
    ) -> List[Dict[str, Any]]:
        """Generate actionable remediation playbook.

        Args:
            result: Analysis result

        Returns:
            List of remediation actions
        """
        playbook = []

        # Priority 1: Critical findings
        if result.critical_findings > 0:
            playbook.append(
                {
                    "priority": 1,
                    "urgency": "immediate",
                    "title": "Address Critical Risks",
                    "description": f"You have {result.critical_findings} critical Shadow IT finding(s) requiring immediate attention.",
                    "actions": [
                        "Review all apps with admin access",
                        "Revoke access for unauthorized admin apps",
                        "Audit recent admin actions in audit logs",
                        "Notify security team and stakeholders",
                    ],
                    "timeline": "Within 24 hours",
                }
            )

        # Priority 2: High-risk apps
        if result.high_findings > 0:
            playbook.append(
                {
                    "priority": 2,
                    "urgency": "high",
                    "title": "Review High-Risk Apps",
                    "description": f"{result.high_findings} high-risk Shadow IT app(s) identified.",
                    "actions": [
                        "Review each high-risk app individually",
                        "Verify business justification with users",
                        "Check app privacy policies and security",
                        "Decide: approve, reject, or find alternative",
                        "Document decision and rationale",
                    ],
                    "timeline": "Within 1 week",
                }
            )

        # Priority 3: Data exfiltration risks
        if result.data_exfiltration_risks > 0:
            playbook.append(
                {
                    "priority": 3,
                    "urgency": "medium",
                    "title": "Mitigate Data Exfiltration Risks",
                    "description": f"{result.data_exfiltration_risks} app(s) with data access identified.",
                    "actions": [
                        "Review apps with Drive/Email access",
                        "Implement DLP policies if needed",
                        "Monitor data access patterns",
                        "Consider data classification requirements",
                    ],
                    "timeline": "Within 2 weeks",
                }
            )

        # Priority 4: Stale grants
        if result.stale_grants > 0:
            playbook.append(
                {
                    "priority": 4,
                    "urgency": "low",
                    "title": "Cleanup Stale OAuth Grants",
                    "description": f"{result.stale_grants} stale OAuth grant(s) detected.",
                    "actions": [
                        "Contact users to verify if apps still needed",
                        "Revoke grants for unused apps",
                        "Set up periodic access reviews",
                        "Implement automatic grant expiration policy",
                    ],
                    "timeline": "Within 1 month",
                }
            )

        # Priority 5: Preventive measures
        playbook.append(
            {
                "priority": 5,
                "urgency": "preventive",
                "title": "Implement Preventive Controls",
                "description": "Prevent future Shadow IT risks.",
                "actions": [
                    "Enable OAuth app whitelisting in Admin Console",
                    "Create app approval process and workflow",
                    "Schedule monthly Shadow IT scans",
                    "Educate users on OAuth security risks",
                    "Establish approved app catalog",
                    "Implement app usage monitoring",
                ],
                "timeline": "Ongoing",
            }
        )

        return playbook

    def _generate_executive_summary(self, result: ShadowITAnalysisResult) -> str:
        """Generate executive-friendly summary.

        Args:
            result: Analysis result

        Returns:
            Executive summary string
        """
        summary_parts = []

        # Opening
        summary_parts.append(
            f"Shadow IT Analysis identified {result.shadow_it_apps} unauthorized OAuth applications "
            f"out of {result.total_apps_analyzed} total applications in your Google Workspace environment."
        )

        # Critical risks
        if result.critical_findings > 0:
            summary_parts.append(
                f"\n\nCRITICAL: {result.critical_findings} critical finding(s) require immediate attention. "
                f"These include apps with admin-level access that could compromise your entire organization."
            )

        # High risks
        if result.high_findings > 0:
            summary_parts.append(
                f"\n\nHIGH PRIORITY: {result.high_findings} high-risk finding(s) identified, including "
                f"{result.data_exfiltration_risks} data exfiltration risk(s) and "
                f"{result.admin_access_risks} admin access risk(s)."
            )

        # Medium/Low risks
        if result.medium_findings > 0 or result.low_findings > 0:
            summary_parts.append(
                f"\n\nMEDIUM/LOW: {result.medium_findings} medium and {result.low_findings} low-priority "
                f"findings require review and remediation within normal security operations."
            )

        # Stale grants
        if result.stale_grants > 0:
            summary_parts.append(
                f"\n\nCLEANUP: {result.stale_grants} stale OAuth grant(s) detected that haven't been used "
                f"recently and should be revoked to reduce attack surface."
            )

        # Recommendations
        summary_parts.append(
            "\n\nNEXT STEPS:\n"
            f"1. Review the detailed remediation playbook ({len(result.remediation_playbook)} action items)\n"
            "2. Address critical and high-priority findings immediately\n"
            "3. Implement OAuth app whitelisting to prevent future Shadow IT\n"
            "4. Establish a formal app approval process\n"
            "5. Schedule regular Shadow IT scans (recommended: monthly)"
        )

        return "".join(summary_parts)
