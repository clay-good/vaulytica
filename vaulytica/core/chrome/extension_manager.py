"""Chrome Extension Management for Google Workspace.

Provides comprehensive control over Chrome extensions - allowlisting, blocklisting,
force-installation, and security policies for extensions.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class ExtensionInstallType(Enum):
    """Types of extension installation policies."""

    ALLOWED = "allowed"  # Extension can be installed by users
    BLOCKED = "blocked"  # Extension is blocked
    FORCE_INSTALLED = "force_installed"  # Auto-installed, cannot be removed
    NORMAL_INSTALLED = "normal_installed"  # Auto-installed, can be removed
    ALLOWED_FOR_SPECIFIC = "allowed_for_specific"  # Only for specific users/groups


class ExtensionUpdatePolicy(Enum):
    """Extension update policies."""

    AUTOMATIC = "automatic"  # Auto-update (recommended)
    MANUAL = "manual"  # User controls updates
    DISABLED = "disabled"  # No updates


@dataclass
class Extension:
    """Represents a Chrome extension."""

    extension_id: str
    name: str
    install_type: ExtensionInstallType
    version: Optional[str] = None
    update_url: Optional[str] = None
    minimum_version: Optional[str] = None
    description: str = ""
    vendor: str = ""
    category: str = ""  # productivity, security, development, etc.
    risk_level: str = "unknown"  # low, medium, high, critical
    permissions_required: list[str] = field(default_factory=list)
    data_access: list[str] = field(default_factory=list)
    homepage_url: Optional[str] = None
    support_url: Optional[str] = None
    allowed_org_units: list[str] = field(default_factory=list)
    blocked_org_units: list[str] = field(default_factory=list)
    notes: str = ""
    added_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified: bool = False

    def to_policy_dict(self) -> dict[str, Any]:
        """Convert extension to Chrome policy format."""
        return {
            "id": self.extension_id,
            "installation_mode": self.install_type.value,
            "update_url": self.update_url or "https://clients2.google.com/service/update2/crx",
            "minimum_version_required": self.minimum_version,
        }


@dataclass
class ExtensionPolicy:
    """Extension policy configuration."""

    name: str
    org_unit_path: str
    force_installed: list[Extension] = field(default_factory=list)
    allowed: list[Extension] = field(default_factory=list)
    blocked: list[Extension] = field(default_factory=list)
    block_all_except_allowed: bool = False
    allow_external_extensions: bool = True
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ExtensionManagerError(Exception):
    """Raised when extension operations fail."""

    pass


class ChromeExtensionManager:
    """Manages Chrome extensions for Google Workspace."""

    # Well-known Chrome extensions (verified and commonly used)
    VERIFIED_EXTENSIONS = {
        # Google Official Extensions
        "gighmmpiobklfepjocnamgkkbiglidom": {
            "name": "Google Docs Offline",
            "vendor": "Google",
            "category": "productivity",
            "risk_level": "low",
        },
        "aapbdbdomjkkjkaonfhkkikfgjllcleb": {
            "name": "Google Translate",
            "vendor": "Google",
            "category": "productivity",
            "risk_level": "low",
        },

        # Security Extensions
        "gcbommkclmclpchllfjekcdonpmejbdp": {
            "name": "HTTPS Everywhere",
            "vendor": "EFF",
            "category": "security",
            "risk_level": "low",
        },
        "cjpalhdlnbpafiamejdnhcphjbkeiagm": {
            "name": "uBlock Origin",
            "vendor": "Raymond Hill",
            "category": "security",
            "risk_level": "low",
        },

        # Password Managers
        "nngceckbapebfimnlniiiahkandclblb": {
            "name": "Bitwarden",
            "vendor": "Bitwarden",
            "category": "security",
            "risk_level": "medium",
        },
        "hdokiejnpimakedhajhdlcegeplioahd": {
            "name": "LastPass",
            "vendor": "LastPass",
            "category": "security",
            "risk_level": "medium",
        },
        "pnlccmojcmeohlpggmfnbbiapkmbliob": {
            "name": "1Password",
            "vendor": "1Password",
            "category": "security",
            "risk_level": "medium",
        },

        # Productivity
        "klbibkeccnjlkjkiokjodocebajanakg": {
            "name": "Grammarly",
            "vendor": "Grammarly",
            "category": "productivity",
            "risk_level": "medium",
        },
        "hdflkhlnmibedjgmcjhibhdkobioejlm": {
            "name": "Zoom Scheduler",
            "vendor": "Zoom",
            "category": "productivity",
            "risk_level": "low",
        },

        # Development
        "fmkadmapgofadopljbjfkapdkoienihi": {
            "name": "React Developer Tools",
            "vendor": "Facebook",
            "category": "development",
            "risk_level": "low",
        },
        "nkbihfbeogaeaoehlefnkodbefgpgknn": {
            "name": "Metamask",
            "vendor": "ConsenSys",
            "category": "development",
            "risk_level": "high",
        },
    }

    # Common risky extension patterns
    RISKY_PATTERNS = {
        "screen_recorder": "high",
        "vpn": "high",
        "ad_injection": "critical",
        "data_scraper": "critical",
        "remote_desktop": "critical",
    }

    def __init__(self, customer_id: str = "my_customer"):
        """Initialize Extension Manager.

        Args:
            customer_id: Google Workspace customer ID
        """
        self.customer_id = customer_id
        logger.info("extension_manager_initialized", customer_id=customer_id)

    def create_secure_allowlist(
        self,
        include_google_official: bool = True,
        include_security: bool = True,
        include_productivity: bool = False,
        include_password_managers: bool = True,
        custom_extensions: Optional[list[str]] = None,
    ) -> list[Extension]:
        """Create a secure extension allowlist.

        Args:
            include_google_official: Include Google official extensions
            include_security: Include security extensions
            include_productivity: Include productivity extensions
            include_password_managers: Include password manager extensions
            custom_extensions: List of custom extension IDs to include

        Returns:
            List of Extension objects
        """
        allowlist = []

        for ext_id, ext_info in self.VERIFIED_EXTENSIONS.items():
            should_include = False

            if include_google_official and ext_info["vendor"] == "Google":
                should_include = True
            elif include_security and ext_info["category"] == "security":
                if ext_info["name"] in ["Bitwarden", "LastPass", "1Password"]:
                    should_include = include_password_managers
                else:
                    should_include = True
            elif include_productivity and ext_info["category"] == "productivity":
                should_include = True

            if should_include:
                extension = Extension(
                    extension_id=ext_id,
                    name=ext_info["name"],
                    install_type=ExtensionInstallType.ALLOWED,
                    vendor=ext_info["vendor"],
                    category=ext_info["category"],
                    risk_level=ext_info["risk_level"],
                    verified=True,
                )
                allowlist.append(extension)

        # Add custom extensions
        if custom_extensions:
            for ext_id in custom_extensions:
                if not any(e.extension_id == ext_id for e in allowlist):
                    extension = Extension(
                        extension_id=ext_id,
                        name=f"Custom Extension {ext_id[:8]}",
                        install_type=ExtensionInstallType.ALLOWED,
                        category="custom",
                        risk_level="unknown",
                        verified=False,
                    )
                    allowlist.append(extension)

        logger.info("created_extension_allowlist", count=len(allowlist))
        return allowlist

    def create_security_extension_bundle(self) -> list[Extension]:
        """Create a bundle of force-installed security extensions.

        Returns:
            List of security extensions to force-install
        """
        security_bundle = [
            Extension(
                extension_id="gcbommkclmclpchllfjekcdonpmejbdp",
                name="HTTPS Everywhere",
                install_type=ExtensionInstallType.FORCE_INSTALLED,
                vendor="EFF",
                category="security",
                risk_level="low",
                description="Force HTTPS connections for better security",
                verified=True,
            ),
            Extension(
                extension_id="cjpalhdlnbpafiamejdnhcphjbkeiagm",
                name="uBlock Origin",
                install_type=ExtensionInstallType.FORCE_INSTALLED,
                vendor="Raymond Hill",
                category="security",
                risk_level="low",
                description="Block ads and trackers",
                verified=True,
            ),
        ]

        logger.info("created_security_bundle", count=len(security_bundle))
        return security_bundle

    def analyze_extension_risk(
        self,
        extension_id: str,
        name: str,
        permissions: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Analyze risk level of an extension.

        Args:
            extension_id: Chrome extension ID
            name: Extension name
            permissions: List of requested permissions

        Returns:
            Risk analysis dictionary
        """
        risk_factors: list[str] = []
        recommendations: list[str] = []
        risk_score = 0

        analysis: dict[str, Any] = {
            "extension_id": extension_id,
            "name": name,
            "risk_level": "unknown",
            "risk_score": risk_score,
            "risk_factors": risk_factors,
            "recommendations": recommendations,
        }

        # Check if verified
        if extension_id in self.VERIFIED_EXTENSIONS:
            verified_info = self.VERIFIED_EXTENSIONS[extension_id]
            analysis["risk_level"] = verified_info["risk_level"]
            analysis["verified"] = True
            analysis["vendor"] = verified_info["vendor"]
            recommendations.append("Verified extension - safe to use")
        else:
            analysis["verified"] = False
            risk_score += 20
            risk_factors.append("Unverified extension")

        # Analyze permissions
        if permissions:
            high_risk_permissions = [
                "webRequest",
                "webRequestBlocking",
                "proxy",
                "debugger",
                "management",
                "<all_urls>",
                "tabs",
                "history",
            ]

            for permission in permissions:
                if permission in high_risk_permissions:
                    risk_score += 15
                    risk_factors.append(f"High-risk permission: {permission}")

            if len(permissions) > 10:
                risk_score += 10
                risk_factors.append(f"Excessive permissions ({len(permissions)})")

        # Check name for risky patterns
        name_lower = name.lower()
        for pattern, risk in self.RISKY_PATTERNS.items():
            if pattern.replace("_", " ") in name_lower:
                if risk == "critical":
                    risk_score += 40
                elif risk == "high":
                    risk_score += 25
                risk_factors.append(f"Risky category: {pattern}")

        # Update analysis with final score
        analysis["risk_score"] = risk_score

        # Determine overall risk level
        if risk_score >= 70:
            analysis["risk_level"] = "critical"
            recommendations.append("BLOCK: This extension poses critical security risks")
        elif risk_score >= 50:
            analysis["risk_level"] = "high"
            recommendations.append("HIGH RISK: Review carefully before allowing")
        elif risk_score >= 30:
            analysis["risk_level"] = "medium"
            recommendations.append("MEDIUM RISK: Allow only if business justification exists")
        elif risk_score >= 10:
            analysis["risk_level"] = "low"
            recommendations.append("LOW RISK: Generally safe to allow")
        else:
            analysis["risk_level"] = "minimal"
            recommendations.append("MINIMAL RISK: Safe to allow")

        return analysis

    def create_extension_policy(
        self,
        name: str,
        org_unit_path: str,
        policy_type: str = "allowlist",
    ) -> ExtensionPolicy:
        """Create an extension policy for an organizational unit.

        Args:
            name: Policy name
            org_unit_path: OU path to apply to
            policy_type: Type of policy (allowlist, blocklist, security_focused)

        Returns:
            ExtensionPolicy object
        """
        policy = ExtensionPolicy(
            name=name,
            org_unit_path=org_unit_path,
        )

        if policy_type == "allowlist":
            policy.allowed = self.create_secure_allowlist()
            policy.block_all_except_allowed = True
            policy.description = "Secure allowlist policy - only approved extensions allowed"

        elif policy_type == "blocklist":
            # Block high-risk extensions only
            policy.block_all_except_allowed = False
            policy.allow_external_extensions = True
            policy.description = "Blocklist policy - blocks known malicious extensions"

        elif policy_type == "security_focused":
            policy.force_installed = self.create_security_extension_bundle()
            policy.allowed = self.create_secure_allowlist(include_productivity=True)
            policy.block_all_except_allowed = True
            policy.description = "Security-focused policy - force-installs security extensions, allows productivity apps"

        logger.info(
            "created_extension_policy",
            name=name,
            type=policy_type,
            force_installed=len(policy.force_installed),
            allowed=len(policy.allowed),
            blocked=len(policy.blocked),
        )

        return policy

    def validate_extension_id(self, extension_id: str) -> bool:
        """Validate Chrome extension ID format.

        Args:
            extension_id: Extension ID to validate

        Returns:
            True if valid format
        """
        # Chrome extension IDs are 32 lowercase letters (a-p)
        pattern = r"^[a-p]{32}$"
        return bool(re.match(pattern, extension_id))

    def export_policy_json(self, policy: ExtensionPolicy) -> dict[str, Any]:
        """Export extension policy as JSON for Chrome Policy API.

        Args:
            policy: ExtensionPolicy to export

        Returns:
            Policy dictionary ready for API submission
        """
        extension_settings = {}

        # Force-installed extensions
        for ext in policy.force_installed:
            extension_settings[ext.extension_id] = ext.to_policy_dict()

        # Allowed extensions
        for ext in policy.allowed:
            if ext.extension_id not in extension_settings:
                extension_settings[ext.extension_id] = ext.to_policy_dict()

        # Blocked extensions
        for ext in policy.blocked:
            extension_settings[ext.extension_id] = {
                "id": ext.extension_id,
                "installation_mode": "blocked",
            }

        # Block all except allowed
        if policy.block_all_except_allowed:
            extension_settings["*"] = {
                "installation_mode": "blocked",
            }

        return {
            "ExtensionSettings": extension_settings,
            "ExtensionInstallBlocklist": ["*"] if policy.block_all_except_allowed else [],
            "ExtensionInstallAllowlist": [e.extension_id for e in policy.allowed] if policy.block_all_except_allowed else [],
            "ExtensionInstallForcelist": [f"{e.extension_id};{e.update_url or 'https://clients2.google.com/service/update2/crx'}" for e in policy.force_installed],
        }

    def get_extension_catalog(self) -> list[dict[str, Any]]:
        """Get catalog of verified extensions with metadata.

        Returns:
            List of extension information dictionaries
        """
        catalog = []
        for ext_id, info in self.VERIFIED_EXTENSIONS.items():
            catalog.append({
                "extension_id": ext_id,
                "name": info["name"],
                "vendor": info["vendor"],
                "category": info["category"],
                "risk_level": info["risk_level"],
                "verified": True,
                "chrome_web_store_url": f"https://chrome.google.com/webstore/detail/{ext_id}",
            })
        return sorted(catalog, key=lambda x: (x["category"], x["name"]))
