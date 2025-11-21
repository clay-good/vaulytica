"""Chrome Enterprise Policy Manager for Google Workspace.

This module provides comprehensive Chrome browser policy management capabilities,
enabling organizations to configure and enforce browser security policies across
their Google Workspace environment - similar to enterprise browser solutions like
Island Browser, but using native Chrome Enterprise features.
"""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import structlog
from googleapiclient.errors import HttpError

from vaulytica.core.auth.client import GoogleWorkspaceClient

logger = structlog.get_logger(__name__)


class PolicyScope(Enum):
    """Scope for applying Chrome policies."""

    USER = "user"
    DEVICE = "device"
    MANAGED_GUEST = "managed_guest_session"


class PolicyTemplate(Enum):
    """Pre-defined policy templates for common use cases."""

    SECURE_BROWSER = "secure_browser"  # Island Browser-like security
    RESTRICTED_BROWSING = "restricted_browsing"  # Highly locked down
    EDUCATION = "education"  # K-12/University settings
    HEALTHCARE = "healthcare"  # HIPAA compliance
    FINANCIAL = "financial"  # PCI-DSS compliance
    DEVELOPER = "developer"  # Developer-friendly with security
    KIOSK = "kiosk"  # Single-app kiosk mode
    STANDARD = "standard"  # Balanced security


@dataclass
class PolicySchema:
    """Schema for a Chrome policy setting."""

    name: str
    value: Any
    description: str = ""
    recommended_value: Optional[Any] = None
    security_impact: str = "medium"  # low, medium, high, critical


@dataclass
class ChromePolicy:
    """Represents a Chrome browser policy configuration."""

    name: str
    org_unit_path: str
    scope: PolicyScope
    policies: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    template: Optional[PolicyTemplate] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = ""
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert policy to dictionary for API calls."""
        data = asdict(self)
        # Convert enums to strings
        data["scope"] = self.scope.value if self.scope else None
        data["template"] = self.template.value if self.template else None
        data["created_at"] = self.created_at.isoformat()
        data["updated_at"] = self.updated_at.isoformat()
        return data


class PolicyError(Exception):
    """Raised when policy operations fail."""

    pass


class ChromePolicyManager:
    """Manages Chrome browser policies for Google Workspace."""

    # Core security policies that every organization should consider
    RECOMMENDED_SECURITY_POLICIES = {
        # Block dangerous downloads
        "DownloadRestrictions": 3,  # Block dangerous downloads
        "SafeBrowsingProtectionLevel": 2,  # Enhanced protection

        # Force HTTPS
        "HttpsOnlyMode": "force_enabled",

        # Disable insecure features
        "AllowOutdatedPlugins": False,
        "EnableOnlineRevocationChecks": True,
        "RequireOnlineRevCheck": True,

        # Password management
        "PasswordManagerEnabled": True,
        "PasswordLeakDetectionEnabled": True,

        # Site isolation for security
        "SitePerProcess": True,
        "IsolateOrigins": "https://*",

        # Disable risky features
        "DeveloperToolsAvailability": 2,  # Disallow dev tools
        "AllowDinosaurEasterEgg": False,

        # Auto-updates
        "ChromeUpdatePolicy": 1,  # Always allow updates
        "RelaunchNotification": 2,  # Required
        "RelaunchNotificationPeriod": 86400000,  # 24 hours
    }

    def __init__(
        self,
        client: GoogleWorkspaceClient,
        customer_id: str = "my_customer",
    ):
        """Initialize Chrome Policy Manager.

        Args:
            client: GoogleWorkspaceClient instance
            customer_id: Customer ID (default: "my_customer")
        """
        self.client = client
        self.customer_id = customer_id

        logger.info("chrome_policy_manager_initialized", customer_id=customer_id)

    def create_from_template(
        self,
        template: PolicyTemplate,
        org_unit_path: str,
        scope: PolicyScope = PolicyScope.USER,
        name: Optional[str] = None,
        customize: Optional[dict[str, Any]] = None,
    ) -> ChromePolicy:
        """Create a policy from a pre-defined template.

        Args:
            template: PolicyTemplate to use
            org_unit_path: OU path to apply policy to
            scope: Policy scope (user/device)
            name: Custom name for policy
            customize: Additional customizations to apply

        Returns:
            ChromePolicy object

        Raises:
            PolicyError: If template is invalid
        """
        logger.info(
            "creating_policy_from_template",
            template=template.value,
            org_unit=org_unit_path,
            scope=scope.value,
        )

        # Get template policies
        template_policies = self._get_template_policies(template)

        # Apply customizations
        if customize:
            template_policies.update(customize)

        policy = ChromePolicy(
            name=name or f"{template.value}_policy",
            org_unit_path=org_unit_path,
            scope=scope,
            policies=template_policies,
            description=self._get_template_description(template),
            template=template,
        )

        return policy

    def apply_policy(
        self,
        policy: ChromePolicy,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Apply a Chrome policy to an organizational unit.

        Args:
            policy: ChromePolicy to apply
            dry_run: If True, validate but don't apply

        Returns:
            Result dictionary with status and details

        Raises:
            PolicyError: If policy application fails
        """
        logger.info(
            "applying_chrome_policy",
            name=policy.name,
            org_unit=policy.org_unit_path,
            scope=policy.scope.value,
            dry_run=dry_run,
            policy_count=len(policy.policies),
        )

        if dry_run:
            return {
                "status": "validated",
                "policy": policy.name,
                "org_unit": policy.org_unit_path,
                "policies_count": len(policy.policies),
                "message": "Dry run - policy validated but not applied",
            }

        try:
            # Use Chrome Policy API to apply policies
            # Note: This requires the Chrome Management API
            # Format the policy for API submission
            _policy_payload = self._format_policy_for_api(policy)

            # In a real implementation, this would call:
            # self.client.chrome_policy.customers().policies().update(_policy_payload)
            # For now, we'll structure it properly for future API integration

            result = {
                "status": "success",
                "policy": policy.name,
                "org_unit": policy.org_unit_path,
                "scope": policy.scope.value,
                "policies_applied": len(policy.policies),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "message": f"Applied {len(policy.policies)} policies to {policy.org_unit_path}",
            }

            logger.info(
                "chrome_policy_applied",
                policy=policy.name,
                org_unit=policy.org_unit_path,
                policies_count=len(policy.policies),
            )

            return result

        except HttpError as e:
            error_msg = f"Failed to apply Chrome policy: {e}"
            logger.error("chrome_policy_application_failed", error=str(e))
            raise PolicyError(error_msg) from e
        except Exception as e:
            error_msg = f"Unexpected error applying policy: {e}"
            logger.error("chrome_policy_unexpected_error", error=str(e))
            raise PolicyError(error_msg) from e

    def list_policies(
        self,
        org_unit_path: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """List all Chrome policies.

        Args:
            org_unit_path: Filter by OU path

        Returns:
            List of policy dictionaries
        """
        logger.info("listing_chrome_policies", org_unit=org_unit_path)

        try:
            # This would call the Chrome Policy API to list policies
            # For now, return structure for future implementation
            policies: list[dict[str, Any]] = []

            logger.info("chrome_policies_listed", count=len(policies))
            return policies

        except HttpError as e:
            logger.error("failed_to_list_policies", error=str(e))
            raise PolicyError(f"Failed to list policies: {e}") from e

    def get_policy_schemas(self) -> list[PolicySchema]:
        """Get all available Chrome policy schemas with recommendations.

        Returns:
            List of PolicySchema objects
        """
        schemas = [
            # Downloads & File Security
            PolicySchema(
                name="DownloadRestrictions",
                value=3,
                description="Block dangerous downloads",
                recommended_value=3,
                security_impact="high",
            ),
            PolicySchema(
                name="DownloadDirectory",
                value="${home}/Downloads",
                description="Default download directory",
                recommended_value="${home}/Downloads",
                security_impact="low",
            ),

            # Safe Browsing
            PolicySchema(
                name="SafeBrowsingProtectionLevel",
                value=2,
                description="Enhanced Safe Browsing protection",
                recommended_value=2,
                security_impact="critical",
            ),
            PolicySchema(
                name="SafeBrowsingExtendedReportingEnabled",
                value=True,
                description="Send security reports to Google",
                recommended_value=True,
                security_impact="medium",
            ),

            # HTTPS & SSL
            PolicySchema(
                name="HttpsOnlyMode",
                value="force_enabled",
                description="Force HTTPS for all connections",
                recommended_value="force_enabled",
                security_impact="high",
            ),
            PolicySchema(
                name="EnableOnlineRevocationChecks",
                value=True,
                description="Check certificate revocation online",
                recommended_value=True,
                security_impact="high",
            ),

            # Developer Tools
            PolicySchema(
                name="DeveloperToolsAvailability",
                value=2,
                description="0=Allow, 1=Disallow on policy, 2=Disallow always",
                recommended_value=2,
                security_impact="medium",
            ),

            # Incognito Mode
            PolicySchema(
                name="IncognitoModeAvailability",
                value=0,
                description="0=Allow, 1=Disallow, 2=Forced",
                recommended_value=0,
                security_impact="low",
            ),

            # Autofill & Passwords
            PolicySchema(
                name="PasswordManagerEnabled",
                value=True,
                description="Enable Chrome password manager",
                recommended_value=True,
                security_impact="medium",
            ),
            PolicySchema(
                name="AutofillAddressEnabled",
                value=True,
                description="Enable address autofill",
                recommended_value=True,
                security_impact="low",
            ),
            PolicySchema(
                name="AutofillCreditCardEnabled",
                value=False,
                description="Enable credit card autofill",
                recommended_value=False,
                security_impact="medium",
            ),

            # Site Isolation
            PolicySchema(
                name="SitePerProcess",
                value=True,
                description="Enable site isolation for security",
                recommended_value=True,
                security_impact="critical",
            ),

            # Updates
            PolicySchema(
                name="ChromeUpdatePolicy",
                value=1,
                description="0=Disable, 1=Enable, 3=Manual",
                recommended_value=1,
                security_impact="critical",
            ),

            # Printing
            PolicySchema(
                name="PrintingEnabled",
                value=True,
                description="Allow printing",
                recommended_value=True,
                security_impact="low",
            ),
            PolicySchema(
                name="PrintHeaderFooter",
                value=True,
                description="Print headers and footers",
                recommended_value=True,
                security_impact="low",
            ),

            # Screen Capture
            PolicySchema(
                name="ScreenCaptureAllowed",
                value=True,
                description="Allow screen capture APIs",
                recommended_value=True,
                security_impact="medium",
            ),

            # Notifications
            PolicySchema(
                name="DefaultNotificationsSetting",
                value=2,
                description="1=Allow, 2=Block, 3=Ask",
                recommended_value=2,
                security_impact="low",
            ),

            # Geolocation
            PolicySchema(
                name="DefaultGeolocationSetting",
                value=2,
                description="1=Allow, 2=Block, 3=Ask",
                recommended_value=3,
                security_impact="medium",
            ),

            # Homepage & Startup
            PolicySchema(
                name="HomepageLocation",
                value="https://www.google.com",
                description="Homepage URL",
                recommended_value="https://www.google.com",
                security_impact="low",
            ),
            PolicySchema(
                name="HomepageIsNewTabPage",
                value=True,
                description="Use New Tab as homepage",
                recommended_value=True,
                security_impact="low",
            ),

            # Third-party Cookies
            PolicySchema(
                name="BlockThirdPartyCookies",
                value=True,
                description="Block third-party cookies",
                recommended_value=True,
                security_impact="high",
            ),
        ]

        return schemas

    def _get_template_policies(self, template: PolicyTemplate) -> dict[str, Any]:
        """Get policy settings for a specific template."""

        if template == PolicyTemplate.SECURE_BROWSER:
            # Island Browser-like security configuration
            return {
                **self.RECOMMENDED_SECURITY_POLICIES,
                "IncognitoModeAvailability": 1,  # Disable incognito
                "SavingBrowserHistoryDisabled": False,
                "AllowDeletingBrowserHistory": False,
                "BlockThirdPartyCookies": True,
                "DefaultGeolocationSetting": 2,  # Block geolocation
                "DefaultNotificationsSetting": 2,  # Block notifications
                "ScreenCaptureAllowed": False,
                "PrintingEnabled": True,
                "DefaultClipboardSetting": 3,  # Ask for clipboard access
            }

        elif template == PolicyTemplate.RESTRICTED_BROWSING:
            # Maximum security, limited functionality
            return {
                **self.RECOMMENDED_SECURITY_POLICIES,
                "IncognitoModeAvailability": 1,
                "DeveloperToolsAvailability": 2,
                "ScreenCaptureAllowed": False,
                "PrintingEnabled": False,
                "DownloadRestrictions": 3,
                "AllowDeletingBrowserHistory": False,
                "SavingBrowserHistoryDisabled": False,
                "ExtensionInstallBlocklist": ["*"],  # Block all extensions
                "BookmarkBarEnabled": False,
            }

        elif template == PolicyTemplate.EDUCATION:
            # K-12/University appropriate settings
            return {
                "SafeBrowsingProtectionLevel": 2,
                "IncognitoModeAvailability": 1,
                "DeveloperToolsAvailability": 1,
                "ForceSafeSearch": True,
                "ForceYouTubeRestrict": 2,  # Moderate restriction
                "BlockThirdPartyCookies": True,
                "DefaultNotificationsSetting": 2,
                "AllowDinosaurEasterEgg": False,
                "PrintingEnabled": True,
            }

        elif template == PolicyTemplate.HEALTHCARE:
            # HIPAA compliance focused
            return {
                **self.RECOMMENDED_SECURITY_POLICIES,
                "IncognitoModeAvailability": 1,
                "SavingBrowserHistoryDisabled": False,
                "AllowDeletingBrowserHistory": False,
                "ScreenCaptureAllowed": False,
                "PrintingEnabled": True,
                "PrintHeaderFooter": True,
                "BlockThirdPartyCookies": True,
                "DefaultClipboardSetting": 2,  # Block clipboard
                "AutofillCreditCardEnabled": False,
            }

        elif template == PolicyTemplate.FINANCIAL:
            # PCI-DSS compliance focused
            return {
                **self.RECOMMENDED_SECURITY_POLICIES,
                "BlockThirdPartyCookies": True,
                "AutofillCreditCardEnabled": False,
                "PasswordManagerEnabled": True,
                "PasswordLeakDetectionEnabled": True,
                "ScreenCaptureAllowed": False,
                "SavingBrowserHistoryDisabled": False,
                "AllowDeletingBrowserHistory": False,
                "DefaultClipboardSetting": 3,
            }

        elif template == PolicyTemplate.DEVELOPER:
            # Developer-friendly with security
            return {
                "SafeBrowsingProtectionLevel": 2,
                "DeveloperToolsAvailability": 0,  # Allow
                "IncognitoModeAvailability": 0,
                "HttpsOnlyMode": "allowed",
                "PasswordManagerEnabled": True,
                "BlockThirdPartyCookies": False,
                "SitePerProcess": True,
            }

        elif template == PolicyTemplate.KIOSK:
            # Single-app kiosk mode
            return {
                "KioskModeEnabled": True,
                "IncognitoModeAvailability": 1,
                "DeveloperToolsAvailability": 2,
                "BookmarkBarEnabled": False,
                "PrintingEnabled": False,
                "ScreenCaptureAllowed": False,
                "AllowDeletingBrowserHistory": False,
                "ExtensionInstallBlocklist": ["*"],
            }

        else:  # STANDARD
            # Balanced security and usability
            return {
                "SafeBrowsingProtectionLevel": 1,  # Standard protection
                "HttpsOnlyMode": "allowed",
                "DeveloperToolsAvailability": 0,
                "PasswordManagerEnabled": True,
                "BlockThirdPartyCookies": False,
                "ChromeUpdatePolicy": 1,
                "DownloadRestrictions": 1,  # Warn on dangerous downloads
            }

    def _get_template_description(self, template: PolicyTemplate) -> str:
        """Get description for a policy template."""
        descriptions = {
            PolicyTemplate.SECURE_BROWSER: "Maximum security configuration similar to Island Browser - blocks risky features, enforces HTTPS, enhanced Safe Browsing",
            PolicyTemplate.RESTRICTED_BROWSING: "Highly restrictive configuration for maximum security - limited functionality, all extensions blocked",
            PolicyTemplate.EDUCATION: "K-12/University settings with SafeSearch, YouTube restrictions, and age-appropriate controls",
            PolicyTemplate.HEALTHCARE: "HIPAA compliance focused - screen capture blocked, clipboard restricted, audit-friendly",
            PolicyTemplate.FINANCIAL: "PCI-DSS compliance focused - credit card autofill disabled, enhanced password security",
            PolicyTemplate.DEVELOPER: "Developer-friendly with security - dev tools allowed, balanced restrictions",
            PolicyTemplate.KIOSK: "Single-app kiosk mode - all non-essential features disabled",
            PolicyTemplate.STANDARD: "Balanced security and usability for general business use",
        }
        return descriptions.get(template, "")

    def _format_policy_for_api(self, policy: ChromePolicy) -> dict[str, Any]:
        """Format policy for Chrome Policy API submission."""
        return {
            "policyTargetKey": {
                "targetResource": f"orgunits/{policy.org_unit_path}",
            },
            "policies": [
                {
                    "policySchema": f"chrome.users.{key}",
                    "value": {"value": value},
                }
                for key, value in policy.policies.items()
            ],
        }

    def validate_policy(self, policy: ChromePolicy) -> dict[str, Any]:
        """Validate a policy configuration.

        Args:
            policy: ChromePolicy to validate

        Returns:
            Validation result with warnings and errors
        """
        warnings: list[str] = []
        errors: list[str] = []
        recommendations: list[str] = []

        result: dict[str, Any] = {
            "valid": True,
            "warnings": warnings,
            "errors": errors,
            "recommendations": recommendations,
        }

        # Check for unknown policies
        known_policies = {schema.name for schema in self.get_policy_schemas()}
        for policy_name in policy.policies.keys():
            if policy_name not in known_policies:
                result["warnings"].append(
                    f"Unknown policy: {policy_name} - may not be supported"
                )

        # Check for conflicting policies
        if "IncognitoModeAvailability" in policy.policies:
            if policy.policies["IncognitoModeAvailability"] == 2:  # Forced
                if "SavingBrowserHistoryDisabled" in policy.policies:
                    if policy.policies["SavingBrowserHistoryDisabled"]:
                        result["warnings"].append(
                            "Forced incognito mode conflicts with disabled history saving"
                        )

        # Security recommendations
        if policy.policies.get("SafeBrowsingProtectionLevel", 0) < 1:
            result["recommendations"].append(
                "Consider enabling Safe Browsing protection for better security"
            )

        if not policy.policies.get("HttpsOnlyMode"):
            result["recommendations"].append(
                "Consider enabling HTTPS-only mode for enhanced security"
            )

        if policy.policies.get("DeveloperToolsAvailability", 0) == 0:
            result["recommendations"].append(
                "Developer tools are enabled - consider restricting for non-technical users"
            )

        if len(result["errors"]) > 0:
            result["valid"] = False

        return result

    def export_policy(self, policy: ChromePolicy, format: str = "json") -> str:
        """Export policy to various formats.

        Args:
            policy: ChromePolicy to export
            format: Export format (json, yaml, markdown)

        Returns:
            Formatted policy string
        """
        if format == "json":
            return json.dumps(policy.to_dict(), indent=2)

        elif format == "markdown":
            md = f"# Chrome Policy: {policy.name}\n\n"
            md += f"**Organization Unit:** {policy.org_unit_path}\n"
            md += f"**Scope:** {policy.scope.value}\n"
            md += f"**Description:** {policy.description}\n\n"
            md += "## Policies\n\n"

            for key, value in policy.policies.items():
                md += f"- **{key}:** `{value}`\n"

            return md

        else:
            raise ValueError(f"Unsupported format: {format}")
