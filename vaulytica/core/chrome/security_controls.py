"""Chrome Security Controls and URL Filtering for Google Workspace.

Provides advanced security controls including URL filtering, content controls,
and safe browsing policies - similar to secure browser solutions.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class SecurityLevel(Enum):
    """Overall security level presets."""

    MINIMAL = "minimal"  # Basic security only
    STANDARD = "standard"  # Balanced security
    ENHANCED = "enhanced"  # Strong security
    MAXIMUM = "maximum"  # Maximum security (may impact usability)


class URLFilterAction(Enum):
    """Actions for URL filtering."""

    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"


class ContentCategory(Enum):
    """Categories for content filtering."""

    ADULT_CONTENT = "adult_content"
    GAMBLING = "gambling"
    VIOLENCE = "violence"
    ILLEGAL_ACTIVITY = "illegal_activity"
    MALWARE = "malware"
    PHISHING = "phishing"
    SOCIAL_MEDIA = "social_media"
    STREAMING_MEDIA = "streaming_media"
    GAMES = "games"
    SHOPPING = "shopping"
    PRODUCTIVITY_BLOCKERS = "productivity_blockers"
    ANONYMIZERS = "anonymizers"
    FILE_SHARING = "file_sharing"


@dataclass
class URLFilteringPolicy:
    """URL filtering and blocklist/allowlist policy."""

    name: str
    org_unit_path: str

    # URL allowlist/blocklist
    url_allowlist: list[str] = field(default_factory=list)
    url_blocklist: list[str] = field(default_factory=list)

    # Content categories
    blocked_categories: list[ContentCategory] = field(default_factory=list)

    # Safe Search
    force_safe_search: bool = False
    force_youtube_restrict: int = 0  # 0=off, 1=moderate, 2=strict

    # HTTPS enforcement
    force_https_only: bool = False

    # Cookie policies
    block_third_party_cookies: bool = True

    # JavaScript restrictions
    default_javascript_setting: int = 1  # 1=allow, 2=block
    javascript_blocklist: list[str] = field(default_factory=list)

    # Popup blocking
    default_popups_setting: int = 2  # 1=allow, 2=block

    # File download restrictions
    download_restrictions: int = 1  # 0=none, 1=dangerous, 2=potentially dangerous, 3=all
    dangerous_download_blocklist: list[str] = field(default_factory=list)

    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SafeBrowsingPolicy:
    """Safe Browsing and phishing protection policy."""

    name: str
    org_unit_path: str

    # Safe Browsing level
    protection_level: int = 2  # 0=disabled, 1=standard, 2=enhanced

    # Extended reporting
    extended_reporting: bool = True

    # Real-time URL checks
    real_time_url_checks: bool = True

    # Download protection
    download_protection_enabled: bool = True
    deep_scanning_enabled: bool = True

    # Password protection
    password_leak_detection: bool = True
    password_alert_enabled: bool = True

    # Certificate checking
    enable_certificate_transparency: bool = True
    enable_symantec_legacy_enforcement: bool = True

    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DataLossPrevention:
    """Data Loss Prevention policies for Chrome."""

    name: str
    org_unit_path: str

    # Clipboard restrictions
    default_clipboard_setting: int = 3  # 1=allow, 2=block, 3=ask
    clipboard_allowed_sites: list[str] = field(default_factory=list)
    clipboard_blocked_sites: list[str] = field(default_factory=list)

    # Screen capture
    screen_capture_allowed: bool = True
    screen_capture_allowed_sites: list[str] = field(default_factory=list)

    # Printing restrictions
    printing_enabled: bool = True
    print_to_pdf_allowed: bool = True
    printing_allowed_sites: list[str] = field(default_factory=list)

    # File selection dialogs
    file_selection_dialogs_allowed: bool = True

    # Data upload restrictions
    data_upload_blocklist: list[str] = field(default_factory=list)

    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SecurityControlsManager:
    """Manages Chrome security controls and URL filtering."""

    # Common malicious/risky domains
    COMMON_BLOCKLIST = [
        "*.bit",  # Blockchain domains (often malicious)
        "*.onion",  # Tor hidden services
        "*.tk",  # Free TLD (high abuse)
        "*.ml",  # Free TLD (high abuse)
        "*.ga",  # Free TLD (high abuse)
        "*.cf",  # Free TLD (high abuse)
        "*.gq",  # Free TLD (high abuse)
    ]

    # Common productivity blockers
    PRODUCTIVITY_BLOCKLIST = [
        "facebook.com",
        "twitter.com",
        "instagram.com",
        "tiktok.com",
        "reddit.com",
        "9gag.com",
        "twitch.tv",
    ]

    # Anonymizer/VPN services
    ANONYMIZER_BLOCKLIST = [
        "*.vpn",
        "hidemyass.com",
        "nordvpn.com",
        "expressvpn.com",
        "protonvpn.com",
        "hide.me",
        "anonymouse.org",
    ]

    # File sharing sites
    FILE_SHARING_BLOCKLIST = [
        "wetransfer.com",
        "sendspace.com",
        "rapidshare.com",
        "megaupload.com",
        "mediafire.com",
    ]

    def __init__(self, customer_id: str = "my_customer"):
        """Initialize Security Controls Manager.

        Args:
            customer_id: Google Workspace customer ID
        """
        self.customer_id = customer_id
        logger.info("security_controls_manager_initialized", customer_id=customer_id)

    def create_url_filtering_policy(
        self,
        name: str,
        org_unit_path: str,
        security_level: SecurityLevel = SecurityLevel.STANDARD,
        block_productivity: bool = False,
        block_anonymizers: bool = True,
        block_file_sharing: bool = False,
        custom_blocklist: Optional[list[str]] = None,
        custom_allowlist: Optional[list[str]] = None,
    ) -> URLFilteringPolicy:
        """Create a URL filtering policy.

        Args:
            name: Policy name
            org_unit_path: OU path to apply to
            security_level: Overall security level
            block_productivity: Block social media and productivity blockers
            block_anonymizers: Block VPN and anonymizer sites
            block_file_sharing: Block file sharing sites
            custom_blocklist: Additional URLs to block
            custom_allowlist: URLs to explicitly allow

        Returns:
            URLFilteringPolicy object
        """
        policy = URLFilteringPolicy(
            name=name,
            org_unit_path=org_unit_path,
        )

        # Base blocklist
        policy.url_blocklist.extend(self.COMMON_BLOCKLIST)

        # Security level adjustments
        if security_level in [SecurityLevel.ENHANCED, SecurityLevel.MAXIMUM]:
            policy.force_safe_search = True
            policy.force_youtube_restrict = 2 if security_level == SecurityLevel.MAXIMUM else 1
            policy.block_third_party_cookies = True
            policy.download_restrictions = 3 if security_level == SecurityLevel.MAXIMUM else 2
            policy.blocked_categories = [
                ContentCategory.ADULT_CONTENT,
                ContentCategory.GAMBLING,
                ContentCategory.VIOLENCE,
                ContentCategory.ILLEGAL_ACTIVITY,
                ContentCategory.MALWARE,
                ContentCategory.PHISHING,
                ContentCategory.ANONYMIZERS,
            ]

        elif security_level == SecurityLevel.STANDARD:
            policy.download_restrictions = 1
            policy.block_third_party_cookies = True
            policy.blocked_categories = [
                ContentCategory.ADULT_CONTENT,
                ContentCategory.MALWARE,
                ContentCategory.PHISHING,
            ]

        # Additional options
        if block_productivity:
            policy.url_blocklist.extend(self.PRODUCTIVITY_BLOCKLIST)
            policy.blocked_categories.append(ContentCategory.SOCIAL_MEDIA)
            policy.blocked_categories.append(ContentCategory.GAMES)

        if block_anonymizers:
            policy.url_blocklist.extend(self.ANONYMIZER_BLOCKLIST)

        if block_file_sharing:
            policy.url_blocklist.extend(self.FILE_SHARING_BLOCKLIST)
            policy.blocked_categories.append(ContentCategory.FILE_SHARING)

        # Custom lists
        if custom_blocklist:
            policy.url_blocklist.extend(custom_blocklist)

        if custom_allowlist:
            policy.url_allowlist.extend(custom_allowlist)

        # Force HTTPS for enhanced/maximum security
        if security_level in [SecurityLevel.ENHANCED, SecurityLevel.MAXIMUM]:
            policy.force_https_only = True

        policy.description = f"{security_level.value.title()} security URL filtering policy"

        logger.info(
            "created_url_filtering_policy",
            name=name,
            security_level=security_level.value,
            blocklist_count=len(policy.url_blocklist),
            allowlist_count=len(policy.url_allowlist),
        )

        return policy

    def create_safe_browsing_policy(
        self,
        name: str,
        org_unit_path: str,
        security_level: SecurityLevel = SecurityLevel.ENHANCED,
    ) -> SafeBrowsingPolicy:
        """Create a Safe Browsing policy.

        Args:
            name: Policy name
            org_unit_path: OU path to apply to
            security_level: Overall security level

        Returns:
            SafeBrowsingPolicy object
        """
        policy = SafeBrowsingPolicy(
            name=name,
            org_unit_path=org_unit_path,
        )

        if security_level == SecurityLevel.MINIMAL:
            policy.protection_level = 1  # Standard
            policy.extended_reporting = False
            policy.real_time_url_checks = False
            policy.deep_scanning_enabled = False

        elif security_level == SecurityLevel.STANDARD:
            policy.protection_level = 1  # Standard
            policy.extended_reporting = True
            policy.real_time_url_checks = True
            policy.deep_scanning_enabled = False

        elif security_level in [SecurityLevel.ENHANCED, SecurityLevel.MAXIMUM]:
            policy.protection_level = 2  # Enhanced
            policy.extended_reporting = True
            policy.real_time_url_checks = True
            policy.deep_scanning_enabled = True
            policy.password_leak_detection = True
            policy.password_alert_enabled = True
            policy.enable_certificate_transparency = True

        policy.description = f"{security_level.value.title()} Safe Browsing policy"

        logger.info(
            "created_safe_browsing_policy",
            name=name,
            protection_level=policy.protection_level,
        )

        return policy

    def create_dlp_policy(
        self,
        name: str,
        org_unit_path: str,
        security_level: SecurityLevel = SecurityLevel.STANDARD,
        allow_printing: bool = True,
        allow_screen_capture: bool = True,
    ) -> DataLossPrevention:
        """Create a Data Loss Prevention policy.

        Args:
            name: Policy name
            org_unit_path: OU path to apply to
            security_level: Overall security level
            allow_printing: Allow printing
            allow_screen_capture: Allow screen capture

        Returns:
            DataLossPrevention object
        """
        policy = DataLossPrevention(
            name=name,
            org_unit_path=org_unit_path,
        )

        if security_level == SecurityLevel.MAXIMUM:
            policy.default_clipboard_setting = 2  # Block
            policy.screen_capture_allowed = False
            policy.printing_enabled = False
            policy.file_selection_dialogs_allowed = False

        elif security_level == SecurityLevel.ENHANCED:
            policy.default_clipboard_setting = 3  # Ask
            policy.screen_capture_allowed = allow_screen_capture
            policy.printing_enabled = allow_printing

        else:  # STANDARD or MINIMAL
            policy.default_clipboard_setting = 1  # Allow
            policy.screen_capture_allowed = True
            policy.printing_enabled = True

        policy.description = f"{security_level.value.title()} DLP policy"

        logger.info(
            "created_dlp_policy",
            name=name,
            clipboard=policy.default_clipboard_setting,
            screen_capture=policy.screen_capture_allowed,
        )

        return policy

    def create_secure_browser_profile(
        self,
        name: str,
        org_unit_path: str,
    ) -> dict[str, Any]:
        """Create a complete secure browser profile (Island Browser-like).

        Args:
            name: Profile name
            org_unit_path: OU path to apply to

        Returns:
            Complete security profile with all policies
        """
        profile = {
            "name": name,
            "org_unit_path": org_unit_path,
            "description": "Complete secure browser profile with Island Browser-like security",
            "url_filtering": self.create_url_filtering_policy(
                name=f"{name}_url_filtering",
                org_unit_path=org_unit_path,
                security_level=SecurityLevel.ENHANCED,
                block_anonymizers=True,
            ),
            "safe_browsing": self.create_safe_browsing_policy(
                name=f"{name}_safe_browsing",
                org_unit_path=org_unit_path,
                security_level=SecurityLevel.ENHANCED,
            ),
            "dlp": self.create_dlp_policy(
                name=f"{name}_dlp",
                org_unit_path=org_unit_path,
                security_level=SecurityLevel.ENHANCED,
            ),
        }

        logger.info("created_secure_browser_profile", name=name, org_unit=org_unit_path)

        return profile

    def validate_url_pattern(self, pattern: str) -> dict[str, Any]:
        """Validate a URL pattern for blocklist/allowlist.

        Args:
            pattern: URL pattern to validate

        Returns:
            Validation result
        """
        errors: list[str] = []
        warnings: list[str] = []

        result: dict[str, Any] = {
            "valid": False,
            "pattern": pattern,
            "errors": errors,
            "warnings": warnings,
        }

        # Check for valid URL pattern
        if not pattern:
            result["errors"].append("Empty pattern")
            return result

        # Check wildcard usage
        if pattern.count("*") > 2:
            result["warnings"].append("Multiple wildcards may be too broad")

        # Check for scheme
        if not any(pattern.startswith(scheme) for scheme in ["http://", "https://", "*://"]):
            if not pattern.startswith("*."):
                result["warnings"].append("Pattern should include scheme or start with *.")

        # Check for dangerous wildcards
        if pattern == "*":
            result["errors"].append("Wildcard * would block/allow everything")
            return result

        if pattern == "*://*":
            result["errors"].append("Pattern *://* would block/allow everything")
            return result

        # Validate domain format
        domain_pattern = r"^(\*\.)?([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$"
        if pattern.startswith("*.") or ("://" not in pattern):
            test_domain = pattern.replace("*.", "")
            if not re.match(domain_pattern, test_domain):
                result["errors"].append("Invalid domain format")

        if len(result["errors"]) == 0:
            result["valid"] = True

        return result

    def export_security_policies(
        self,
        profile: dict[str, Any],
    ) -> dict[str, Any]:
        """Export security policies in Chrome Policy API format.

        Args:
            profile: Security profile dictionary

        Returns:
            Policies formatted for Chrome Policy API
        """
        policies = {}

        # URL Filtering policies
        if "url_filtering" in profile:
            url_policy = profile["url_filtering"]
            policies.update({
                "URLBlocklist": url_policy.url_blocklist,
                "URLAllowlist": url_policy.url_allowlist,
                "ForceSafeSearch": url_policy.force_safe_search,
                "ForceYouTubeRestrict": url_policy.force_youtube_restrict,
                "HttpsOnlyMode": "force_enabled" if url_policy.force_https_only else "allowed",
                "BlockThirdPartyCookies": url_policy.block_third_party_cookies,
                "DefaultJavaScriptSetting": url_policy.default_javascript_setting,
                "DefaultPopupsSetting": url_policy.default_popups_setting,
                "DownloadRestrictions": url_policy.download_restrictions,
            })

        # Safe Browsing policies
        if "safe_browsing" in profile:
            sb_policy = profile["safe_browsing"]
            policies.update({
                "SafeBrowsingProtectionLevel": sb_policy.protection_level,
                "SafeBrowsingExtendedReportingEnabled": sb_policy.extended_reporting,
                "SafeBrowsingRealTimeLookupEnabled": sb_policy.real_time_url_checks,
                "DownloadRestrictions": 3 if sb_policy.download_protection_enabled else 0,
                "PasswordLeakDetectionEnabled": sb_policy.password_leak_detection,
                "EnableOnlineRevocationChecks": sb_policy.enable_certificate_transparency,
            })

        # DLP policies
        if "dlp" in profile:
            dlp_policy = profile["dlp"]
            policies.update({
                "DefaultClipboardSetting": dlp_policy.default_clipboard_setting,
                "ScreenCaptureAllowed": dlp_policy.screen_capture_allowed,
                "PrintingEnabled": dlp_policy.printing_enabled,
                "PrintPdfAsImageEnabled": dlp_policy.print_to_pdf_allowed,
            })

        return policies

    def get_security_recommendations(
        self,
        current_policies: dict[str, Any],
    ) -> list[dict[str, str]]:
        """Get security recommendations based on current policies.

        Args:
            current_policies: Current policy settings

        Returns:
            List of recommendation dictionaries
        """
        recommendations: list[dict[str, str]] = []

        # Check Safe Browsing
        if current_policies.get("SafeBrowsingProtectionLevel", 0) < 2:
            recommendations.append({
                "priority": "high",
                "category": "security",
                "policy": "SafeBrowsingProtectionLevel",
                "recommendation": "Enable Enhanced Safe Browsing (level 2) for better protection",
                "current_value": str(current_policies.get("SafeBrowsingProtectionLevel", 0)),
                "recommended_value": "2",
            })

        # Check HTTPS
        if current_policies.get("HttpsOnlyMode") != "force_enabled":
            recommendations.append({
                "priority": "high",
                "category": "security",
                "policy": "HttpsOnlyMode",
                "recommendation": "Force HTTPS-only mode for all connections",
                "current_value": current_policies.get("HttpsOnlyMode", "allowed"),
                "recommended_value": "force_enabled",
            })

        # Check third-party cookies
        if not current_policies.get("BlockThirdPartyCookies", False):
            recommendations.append({
                "priority": "medium",
                "category": "privacy",
                "policy": "BlockThirdPartyCookies",
                "recommendation": "Block third-party cookies for better privacy",
                "current_value": "false",
                "recommended_value": "true",
            })

        # Check download restrictions
        if current_policies.get("DownloadRestrictions", 0) < 1:
            recommendations.append({
                "priority": "high",
                "category": "security",
                "policy": "DownloadRestrictions",
                "recommendation": "Enable download restrictions (at least level 1 - dangerous files)",
                "current_value": str(current_policies.get("DownloadRestrictions", 0)),
                "recommended_value": "1",
            })

        # Check developer tools
        if current_policies.get("DeveloperToolsAvailability", 0) == 0:
            recommendations.append({
                "priority": "low",
                "category": "security",
                "policy": "DeveloperToolsAvailability",
                "recommendation": "Consider restricting developer tools for non-technical users",
                "current_value": "0 (allowed)",
                "recommended_value": "2 (disallowed)",
            })

        return recommendations
