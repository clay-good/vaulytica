"""OAuth app and third-party integration scanner."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
import time

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient

logger = structlog.get_logger(__name__)


@dataclass
class OAuthApp:
    """Represents an OAuth application."""

    client_id: str
    display_text: str
    scopes: List[str] = field(default_factory=list)
    user_count: int = 0
    risk_score: int = 0
    is_verified: bool = False
    is_google_app: bool = False
    # Enhanced security fields
    has_excessive_permissions: bool = False
    has_data_access: bool = False
    has_admin_access: bool = False
    has_email_access: bool = False
    has_drive_access: bool = False
    risk_factors: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_used: Optional[datetime] = None


@dataclass
class OAuthToken:
    """Represents an OAuth token grant."""

    client_id: str
    display_text: str
    scopes: List[str]
    user_email: str
    user_name: str
    anonymous: bool = False


@dataclass
class OAuthScanResult:
    """Results from OAuth scanning."""

    total_apps: int = 0
    high_risk_apps: int = 0
    total_tokens: int = 0
    apps: List[OAuthApp] = field(default_factory=list)
    tokens: List[OAuthToken] = field(default_factory=list)
    # Enhanced security metrics
    apps_with_excessive_permissions: int = 0
    apps_with_data_access: int = 0
    apps_with_admin_access: int = 0
    unverified_apps: int = 0
    issues: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[Dict[str, Any]] = field(default_factory=list)


class OAuthScannerError(Exception):
    """Raised when OAuth scanning fails."""

    pass


class OAuthScanner:
    """Scans OAuth apps and tokens for security issues."""

    # High-risk scopes that grant broad access
    HIGH_RISK_SCOPES = [
        "https://www.googleapis.com/auth/drive",  # Full Drive access
        "https://www.googleapis.com/auth/gmail.modify",  # Modify Gmail
        "https://www.googleapis.com/auth/gmail.compose",  # Send emails
        "https://www.googleapis.com/auth/admin.directory.user",  # User management
        "https://www.googleapis.com/auth/admin.directory.group",  # Group management
        "https://mail.google.com/",  # Full Gmail access
    ]

    # Critical scopes that should trigger immediate review
    CRITICAL_SCOPES = [
        "https://www.googleapis.com/auth/admin.directory.user",  # User management
        "https://www.googleapis.com/auth/admin.directory.group",  # Group management
        "https://www.googleapis.com/auth/admin.directory.domain",  # Domain management
        "https://www.googleapis.com/auth/admin.directory.orgunit",  # OU management
        "https://www.googleapis.com/auth/admin.directory.rolemanagement",  # Role management
        "https://www.googleapis.com/auth/apps.groups.settings",  # Group settings
    ]

    # Data access scopes
    DATA_ACCESS_SCOPES = [
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/drive.file",
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/calendar.readonly",
    ]

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        domain: str,
    ):
        """Initialize OAuth scanner.

        Args:
            client: GoogleWorkspaceClient instance
            domain: Organization domain
        """
        self.client = client
        self.domain = domain

        logger.info("oauth_scanner_initialized", domain=domain)

    def scan_oauth_tokens(
        self,
        user_email: Optional[str] = None,
        max_users: Optional[int] = None,
        skip_suspended: bool = True
    ) -> OAuthScanResult:
        """Scan OAuth tokens for users with enhanced performance and error handling.

        Args:
            user_email: Specific user to scan (None for all users)
            max_users: Maximum number of users to scan (for performance testing)
            skip_suspended: Skip suspended users (default: True)

        Returns:
            OAuthScanResult with scan results

        Raises:
            OAuthScannerError: If scanning fails critically
            ValueError: If invalid parameters provided
        """
        # Input validation
        if user_email and not isinstance(user_email, str):
            raise ValueError("user_email must be a string")
        if max_users is not None and (not isinstance(max_users, int) or max_users < 1):
            raise ValueError("max_users must be a positive integer")

        logger.info(
            "starting_oauth_scan",
            user_email=user_email,
            max_users=max_users,
            skip_suspended=skip_suspended
        )
        scan_start_time = time.time()

        result = OAuthScanResult()
        failed_users = []

        if user_email:
            # Scan specific user
            try:
                tokens = self._get_user_tokens(user_email)
                result.tokens.extend(tokens)
            except Exception as e:
                logger.error(
                    "failed_to_get_tokens_for_user",
                    user_email=user_email,
                    error=str(e),
                )
                failed_users.append({"email": user_email, "error": str(e)})
        else:
            # Scan all users
            from vaulytica.core.scanners.user_scanner import UserScanner

            user_scanner = UserScanner(self.client, self.domain)
            user_result = user_scanner.scan_all_users()

            users_to_scan = user_result.users
            if max_users:
                users_to_scan = users_to_scan[:max_users]
                logger.info("limiting_scan_to_max_users", max_users=max_users)

            scanned_count = 0
            for user in users_to_scan:
                if skip_suspended and user.is_suspended:
                    continue

                try:
                    tokens = self._get_user_tokens(user.email)
                    result.tokens.extend(tokens)
                    scanned_count += 1

                    # Log progress every 100 users
                    if scanned_count % 100 == 0:
                        logger.info(
                            "oauth_scan_progress",
                            scanned=scanned_count,
                            total=len(users_to_scan),
                            tokens_found=len(result.tokens)
                        )
                except HttpError as e:
                    if e.resp.status == 403:
                        logger.warning(
                            "insufficient_permissions_for_user",
                            user_email=user.email,
                            error=str(e),
                        )
                    else:
                        logger.warning(
                            "failed_to_get_tokens_for_user",
                            user_email=user.email,
                            error=str(e),
                        )
                    failed_users.append({"email": user.email, "error": str(e)})
                except Exception as e:
                    logger.warning(
                        "unexpected_error_for_user",
                        user_email=user.email,
                        error=str(e),
                    )
                    failed_users.append({"email": user.email, "error": str(e)})

        result.total_tokens = len(result.tokens)

        # Aggregate by app
        app_map: Dict[str, OAuthApp] = {}

        for token in result.tokens:
            if token.client_id not in app_map:
                app_map[token.client_id] = OAuthApp(
                    client_id=token.client_id,
                    display_text=token.display_text,
                    scopes=token.scopes,
                    user_count=0,
                    is_google_app=self._is_google_app(token.client_id),
                )

            app_map[token.client_id].user_count += 1

            # Merge scopes
            for scope in token.scopes:
                if scope not in app_map[token.client_id].scopes:
                    app_map[token.client_id].scopes.append(scope)

        # Calculate risk scores and analyze security
        for app in app_map.values():
            app.risk_score = self._calculate_app_risk_score(app)

        result.apps = list(app_map.values())
        result.total_apps = len(result.apps)
        result.high_risk_apps = len([a for a in result.apps if a.risk_score >= 75])

        # Calculate enhanced security metrics
        result.apps_with_excessive_permissions = len([a for a in result.apps if a.has_excessive_permissions])
        result.apps_with_data_access = len([a for a in result.apps if a.has_data_access])
        result.apps_with_admin_access = len([a for a in result.apps if a.has_admin_access])
        result.unverified_apps = len([a for a in result.apps if not a.is_verified and not a.is_google_app])

        # Generate security issues and recommendations
        result.issues = self._generate_security_issues(result)
        result.recommendations = self._generate_recommendations(result)

        # Calculate scan duration
        scan_duration = time.time() - scan_start_time

        logger.info(
            "oauth_scan_complete",
            total_apps=result.total_apps,
            total_tokens=result.total_tokens,
            high_risk_apps=result.high_risk_apps,
            admin_access_apps=result.apps_with_admin_access,
            excessive_permissions=result.apps_with_excessive_permissions,
            issues=len(result.issues),
            recommendations=len(result.recommendations),
            failed_users=len(failed_users),
            scan_duration_seconds=round(scan_duration, 2),
        )

        # Log warning if many users failed
        if failed_users and len(failed_users) > 10:
            logger.warning(
                "many_users_failed_oauth_scan",
                failed_count=len(failed_users),
                sample_errors=failed_users[:5]
            )

        return result

    def revoke_token(self, user_email: str, client_id: str) -> bool:
        """Revoke an OAuth token for a user.

        Args:
            user_email: User email
            client_id: OAuth client ID

        Returns:
            True if successful

        Raises:
            OAuthScannerError: If revocation fails
        """
        logger.info("revoking_oauth_token", user_email=user_email, client_id=client_id)

        try:
            self.client.admin.tokens().delete(
                userKey=user_email,
                clientId=client_id,
            ).execute()

            logger.info("oauth_token_revoked", user_email=user_email, client_id=client_id)
            return True

        except HttpError as e:
            if e.resp.status == 404:
                logger.warning("oauth_token_not_found", user_email=user_email)
                return False
            raise OAuthScannerError(f"Failed to revoke token: {e}")

    def _get_user_tokens(self, user_email: str) -> List[OAuthToken]:
        """Get OAuth tokens for a user.

        Args:
            user_email: User email

        Returns:
            List of OAuthToken objects
        """
        try:
            response = (
                self.client.admin.tokens()
                .list(userKey=user_email)
                .execute()
            )

            tokens = []
            for item in response.get("items", []):
                token = OAuthToken(
                    client_id=item.get("clientId", ""),
                    display_text=item.get("displayText", "Unknown App"),
                    scopes=item.get("scopes", []),
                    user_email=user_email,
                    user_name=item.get("userKey", ""),
                    anonymous=item.get("anonymous", False),
                )
                tokens.append(token)

            return tokens

        except HttpError as e:
            if e.resp.status == 404:
                # User has no tokens
                return []
            raise OAuthScannerError(f"Failed to get tokens for {user_email}: {e}")

    def _is_google_app(self, client_id: str) -> bool:
        """Check if app is a Google app.

        Args:
            client_id: OAuth client ID

        Returns:
            True if Google app
        """
        # Google apps typically end with .apps.googleusercontent.com
        return client_id.endswith(".apps.googleusercontent.com")

    def _calculate_app_risk_score(self, app: OAuthApp) -> int:
        """Calculate enhanced risk score for an OAuth app.

        Args:
            app: OAuthApp object

        Returns:
            Risk score (0-100)
        """
        score = 0
        app.risk_factors = []

        # Check for CRITICAL scopes (highest priority)
        critical_scope_count = 0
        for scope in app.scopes:
            if any(cs in scope for cs in self.CRITICAL_SCOPES):
                critical_scope_count += 1
                app.has_admin_access = True
                app.risk_factors.append(f"Critical admin scope: {scope}")

        if critical_scope_count > 0:
            score += min(60, critical_scope_count * 20)

        # Check for high-risk scopes
        high_risk_scope_count = 0
        for scope in app.scopes:
            if any(hrs in scope for hrs in self.HIGH_RISK_SCOPES):
                high_risk_scope_count += 1
                if "drive" in scope.lower():
                    app.has_drive_access = True
                    app.risk_factors.append("Full Drive access")
                if "gmail" in scope.lower() or "mail" in scope.lower():
                    app.has_email_access = True
                    app.risk_factors.append("Email access")

        if high_risk_scope_count > 0:
            score += min(40, high_risk_scope_count * 10)

        # Check for data access scopes
        data_scope_count = 0
        for scope in app.scopes:
            if any(das in scope for das in self.DATA_ACCESS_SCOPES):
                data_scope_count += 1
                app.has_data_access = True

        if data_scope_count > 0:
            score += min(20, data_scope_count * 5)

        # Excessive permissions (too many scopes)
        if len(app.scopes) > 15:
            score += 25
            app.has_excessive_permissions = True
            app.risk_factors.append(f"Excessive permissions ({len(app.scopes)} scopes)")
        elif len(app.scopes) > 10:
            score += 15
            app.has_excessive_permissions = True
            app.risk_factors.append(f"Many permissions ({len(app.scopes)} scopes)")
        elif len(app.scopes) > 5:
            score += 5

        # Number of users (more users = higher impact)
        if app.user_count > 100:
            score += 20
            app.risk_factors.append(f"Wide adoption ({app.user_count} users)")
        elif app.user_count > 50:
            score += 15
            app.risk_factors.append(f"High adoption ({app.user_count} users)")
        elif app.user_count > 10:
            score += 10
        elif app.user_count > 5:
            score += 5

        # Non-Google, unverified apps are riskier
        if not app.is_google_app:
            score += 15
            app.risk_factors.append("Third-party app (not Google)")
            if not app.is_verified:
                score += 10
                app.risk_factors.append("Unverified app")
        else:
            # Google apps are generally lower risk
            score = int(score * 0.5)

        # Cap at 100
        return min(100, score)

    def _generate_security_issues(self, result: OAuthScanResult) -> List[Dict[str, Any]]:
        """Generate security issues from OAuth scan results.

        Args:
            result: OAuthScanResult object

        Returns:
            List of security issues
        """
        issues = []

        # Critical: Apps with admin access
        admin_apps = [app for app in result.apps if app.has_admin_access]
        if admin_apps:
            for app in admin_apps:
                issues.append({
                    "severity": "critical",
                    "type": "admin_access_app",
                    "app_name": app.display_text,
                    "client_id": app.client_id,
                    "user_count": app.user_count,
                    "risk_score": app.risk_score,
                    "description": f"App '{app.display_text}' has admin-level access to your Google Workspace",
                    "recommendation": "Review this app immediately. Revoke access if not essential.",
                    "risk_factors": app.risk_factors,
                })

        # High: Unverified apps with high risk scores
        unverified_high_risk = [
            app for app in result.apps
            if not app.is_verified and not app.is_google_app and app.risk_score >= 70
        ]
        if unverified_high_risk:
            for app in unverified_high_risk:
                issues.append({
                    "severity": "high",
                    "type": "unverified_high_risk_app",
                    "app_name": app.display_text,
                    "client_id": app.client_id,
                    "user_count": app.user_count,
                    "risk_score": app.risk_score,
                    "description": f"Unverified app '{app.display_text}' has high-risk permissions",
                    "recommendation": "Verify app legitimacy and review permissions. Consider blocking.",
                    "risk_factors": app.risk_factors,
                })

        # High: Apps with excessive permissions
        excessive_perm_apps = [app for app in result.apps if app.has_excessive_permissions]
        if len(excessive_perm_apps) > 5:
            issues.append({
                "severity": "high",
                "type": "excessive_permissions",
                "count": len(excessive_perm_apps),
                "description": f"{len(excessive_perm_apps)} apps have excessive permissions",
                "recommendation": "Review apps and revoke unnecessary permissions",
                "apps": [{"name": app.display_text, "scopes": len(app.scopes)} for app in excessive_perm_apps[:10]],
            })

        # Medium: Apps with data access
        data_access_apps = [app for app in result.apps if app.has_data_access and not app.is_google_app]
        if len(data_access_apps) > 10:
            issues.append({
                "severity": "medium",
                "type": "many_data_access_apps",
                "count": len(data_access_apps),
                "description": f"{len(data_access_apps)} third-party apps have access to user data",
                "recommendation": "Audit data access permissions regularly",
            })

        # Medium: Wide adoption of risky apps
        wide_adoption_risky = [
            app for app in result.apps
            if app.user_count > 50 and app.risk_score >= 60 and not app.is_google_app
        ]
        if wide_adoption_risky:
            for app in wide_adoption_risky:
                issues.append({
                    "severity": "medium",
                    "type": "wide_adoption_risky_app",
                    "app_name": app.display_text,
                    "user_count": app.user_count,
                    "risk_score": app.risk_score,
                    "description": f"Risky app '{app.display_text}' is used by {app.user_count} users",
                    "recommendation": "Consider organization-wide policy or alternative solution",
                })

        return issues

    def _generate_recommendations(self, result: OAuthScanResult) -> List[Dict[str, Any]]:
        """Generate security recommendations from OAuth scan results.

        Args:
            result: OAuthScanResult object

        Returns:
            List of recommendations
        """
        recommendations = []

        # Recommendation: Enable OAuth app whitelisting
        if result.total_apps > 20:
            recommendations.append({
                "priority": "high",
                "title": "Enable OAuth App Whitelisting",
                "description": f"You have {result.total_apps} OAuth apps. Consider enabling app whitelisting.",
                "action": "Go to Admin Console > Security > API Controls > App access control",
                "benefit": "Prevent users from installing unauthorized apps",
            })

        # Recommendation: Review high-risk apps
        if result.high_risk_apps > 0:
            recommendations.append({
                "priority": "high",
                "title": f"Review {result.high_risk_apps} High-Risk Apps",
                "description": "Several apps have high-risk permissions that could compromise security",
                "action": "Review each app's permissions and revoke access if not essential",
                "benefit": "Reduce attack surface and data exposure risk",
            })

        # Recommendation: Audit admin access apps
        admin_apps = [app for app in result.apps if app.has_admin_access]
        if admin_apps:
            recommendations.append({
                "priority": "critical",
                "title": f"Audit {len(admin_apps)} Apps with Admin Access",
                "description": "Apps with admin access can make organization-wide changes",
                "action": "Review admin access apps immediately and revoke if not essential",
                "benefit": "Prevent unauthorized admin actions and privilege escalation",
                "apps": [app.display_text for app in admin_apps],
            })

        # Recommendation: Regular OAuth audits
        recommendations.append({
            "priority": "medium",
            "title": "Schedule Regular OAuth Audits",
            "description": "OAuth permissions can change over time as apps update",
            "action": "Run OAuth scans monthly and review new apps",
            "benefit": "Stay ahead of security risks from third-party apps",
        })

        # Recommendation: User education
        if result.apps_with_data_access > 10:
            recommendations.append({
                "priority": "medium",
                "title": "Educate Users on OAuth Permissions",
                "description": f"{result.apps_with_data_access} apps have data access",
                "action": "Train users to review permissions before granting access",
                "benefit": "Reduce risk of users granting excessive permissions",
            })

        return recommendations

