"""Tests for Chrome Security Controls Manager."""


import pytest

from vaulytica.core.chrome.security_controls import (
    ContentCategory,
    DataLossPrevention,
    SafeBrowsingPolicy,
    SecurityControlsManager,
    SecurityLevel,
    URLFilteringPolicy,
)


@pytest.fixture
def security_manager() -> SecurityControlsManager:
    """Create SecurityControlsManager instance."""
    return SecurityControlsManager(customer_id="test_customer")


class TestSecurityControlsManager:
    """Test SecurityControlsManager class."""

    def test_initialization(self) -> None:
        """Test manager initialization."""
        manager = SecurityControlsManager(customer_id="test_id")
        assert manager.customer_id == "test_id"

    def test_create_url_filtering_policy_standard(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test creating standard URL filtering policy."""
        policy = security_manager.create_url_filtering_policy(
            name="Standard Policy",
            org_unit_path="/",
            security_level=SecurityLevel.STANDARD,
        )

        assert policy.name == "Standard Policy"
        assert policy.org_unit_path == "/"
        assert policy.download_restrictions == 1
        assert policy.block_third_party_cookies is True
        assert len(policy.url_blocklist) > 0

    def test_create_url_filtering_policy_enhanced(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test creating enhanced URL filtering policy."""
        policy = security_manager.create_url_filtering_policy(
            name="Enhanced Policy",
            org_unit_path="/",
            security_level=SecurityLevel.ENHANCED,
        )

        assert policy.force_safe_search is True
        assert policy.force_youtube_restrict == 1
        assert policy.force_https_only is True
        assert policy.download_restrictions == 2
        assert ContentCategory.MALWARE in policy.blocked_categories

    def test_create_url_filtering_policy_maximum(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test creating maximum security URL filtering policy."""
        policy = security_manager.create_url_filtering_policy(
            name="Maximum Policy",
            org_unit_path="/",
            security_level=SecurityLevel.MAXIMUM,
        )

        assert policy.force_safe_search is True
        assert policy.force_youtube_restrict == 2  # Strict
        assert policy.download_restrictions == 3  # Block all
        assert policy.force_https_only is True

    def test_create_url_filtering_with_productivity_blocking(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test URL filtering with productivity blocking enabled."""
        policy = security_manager.create_url_filtering_policy(
            name="Restricted Policy",
            org_unit_path="/Contractors",
            security_level=SecurityLevel.ENHANCED,
            block_productivity=True,
        )

        assert any("facebook.com" in url for url in policy.url_blocklist)
        assert ContentCategory.SOCIAL_MEDIA in policy.blocked_categories

    def test_create_url_filtering_with_anonymizer_blocking(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test URL filtering with anonymizer blocking."""
        policy = security_manager.create_url_filtering_policy(
            name="No VPN Policy",
            org_unit_path="/",
            security_level=SecurityLevel.STANDARD,
            block_anonymizers=True,
        )

        # Should include VPN-related blocks
        assert any("vpn" in url.lower() for url in policy.url_blocklist)

    def test_create_url_filtering_with_file_sharing_blocking(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test URL filtering with file sharing blocking."""
        policy = security_manager.create_url_filtering_policy(
            name="No File Sharing",
            org_unit_path="/",
            security_level=SecurityLevel.STANDARD,
            block_file_sharing=True,
        )

        assert ContentCategory.FILE_SHARING in policy.blocked_categories
        assert any("wetransfer" in url.lower() for url in policy.url_blocklist)

    def test_create_url_filtering_with_custom_lists(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test URL filtering with custom blocklist and allowlist."""
        custom_block = ["*.badsite.com", "evil.org"]
        custom_allow = ["*.trusted.com", "safe.net"]

        policy = security_manager.create_url_filtering_policy(
            name="Custom Policy",
            org_unit_path="/",
            security_level=SecurityLevel.STANDARD,
            custom_blocklist=custom_block,
            custom_allowlist=custom_allow,
        )

        assert all(url in policy.url_blocklist for url in custom_block)
        assert all(url in policy.url_allowlist for url in custom_allow)

    def test_create_safe_browsing_policy_minimal(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test creating minimal Safe Browsing policy."""
        policy = security_manager.create_safe_browsing_policy(
            name="Minimal SB",
            org_unit_path="/",
            security_level=SecurityLevel.MINIMAL,
        )

        assert policy.protection_level == 1  # Standard
        assert policy.extended_reporting is False
        assert policy.real_time_url_checks is False
        assert policy.deep_scanning_enabled is False

    def test_create_safe_browsing_policy_enhanced(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test creating enhanced Safe Browsing policy."""
        policy = security_manager.create_safe_browsing_policy(
            name="Enhanced SB",
            org_unit_path="/",
            security_level=SecurityLevel.ENHANCED,
        )

        assert policy.protection_level == 2  # Enhanced
        assert policy.extended_reporting is True
        assert policy.real_time_url_checks is True
        assert policy.deep_scanning_enabled is True
        assert policy.password_leak_detection is True
        assert policy.enable_certificate_transparency is True

    def test_create_dlp_policy_standard(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test creating standard DLP policy."""
        policy = security_manager.create_dlp_policy(
            name="Standard DLP",
            org_unit_path="/",
            security_level=SecurityLevel.STANDARD,
        )

        assert policy.default_clipboard_setting == 1  # Allow
        assert policy.screen_capture_allowed is True
        assert policy.printing_enabled is True

    def test_create_dlp_policy_maximum(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test creating maximum security DLP policy."""
        policy = security_manager.create_dlp_policy(
            name="Maximum DLP",
            org_unit_path="/Finance",
            security_level=SecurityLevel.MAXIMUM,
        )

        assert policy.default_clipboard_setting == 2  # Block
        assert policy.screen_capture_allowed is False
        assert policy.printing_enabled is False
        assert policy.file_selection_dialogs_allowed is False

    def test_create_dlp_policy_with_overrides(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test DLP policy with custom overrides."""
        policy = security_manager.create_dlp_policy(
            name="Custom DLP",
            org_unit_path="/",
            security_level=SecurityLevel.ENHANCED,
            allow_printing=False,
            allow_screen_capture=False,
        )

        assert policy.printing_enabled is False
        assert policy.screen_capture_allowed is False

    def test_create_secure_browser_profile(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test creating complete secure browser profile."""
        profile = security_manager.create_secure_browser_profile(
            name="Secure Profile",
            org_unit_path="/Engineering",
        )

        assert profile["name"] == "Secure Profile"
        assert profile["org_unit_path"] == "/Engineering"
        assert "url_filtering" in profile
        assert "safe_browsing" in profile
        assert "dlp" in profile

        # Check each component
        assert isinstance(profile["url_filtering"], URLFilteringPolicy)
        assert isinstance(profile["safe_browsing"], SafeBrowsingPolicy)
        assert isinstance(profile["dlp"], DataLossPrevention)

    def test_validate_url_pattern_valid(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test validating valid URL patterns."""
        valid_patterns = [
            "*.example.com",
            "https://example.com",
            "*://example.com",
            "*.google.com",
        ]

        for pattern in valid_patterns:
            result = security_manager.validate_url_pattern(pattern)
            assert result["valid"] is True, f"Pattern {pattern} should be valid"

    def test_validate_url_pattern_invalid(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test validating invalid URL patterns."""
        invalid_patterns = [
            "",  # Empty
            "*",  # Too broad
            "*://*",  # Block everything
        ]

        for pattern in invalid_patterns:
            result = security_manager.validate_url_pattern(pattern)
            assert result["valid"] is False, f"Pattern {pattern} should be invalid"
            assert len(result["errors"]) > 0

    def test_validate_url_pattern_warnings(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test URL pattern validation generates warnings."""
        pattern = "*://*.*.*.*"  # Multiple wildcards

        result = security_manager.validate_url_pattern(pattern)
        assert len(result["warnings"]) > 0

    def test_export_security_policies(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test exporting security policies."""
        profile = security_manager.create_secure_browser_profile(
            name="Test Profile",
            org_unit_path="/",
        )

        policies = security_manager.export_security_policies(profile)

        # Should have URL filtering policies
        assert "URLBlocklist" in policies
        assert "URLAllowlist" in policies
        assert "ForceSafeSearch" in policies

        # Should have Safe Browsing policies
        assert "SafeBrowsingProtectionLevel" in policies

        # Should have DLP policies
        assert "DefaultClipboardSetting" in policies
        assert "ScreenCaptureAllowed" in policies

    def test_get_security_recommendations(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test getting security recommendations."""
        current_policies = {
            "SafeBrowsingProtectionLevel": 0,  # Disabled
            "HttpsOnlyMode": "allowed",  # Not forced
            "BlockThirdPartyCookies": False,
        }

        recommendations = security_manager.get_security_recommendations(
            current_policies
        )

        assert len(recommendations) > 0
        assert all("priority" in rec for rec in recommendations)
        assert all("category" in rec for rec in recommendations)
        assert all("recommendation" in rec for rec in recommendations)

        # Should recommend enabling Safe Browsing
        assert any(
            "Safe Browsing" in rec["recommendation"] for rec in recommendations
        )

    def test_common_blocklists_exist(
        self, security_manager: SecurityControlsManager
    ) -> None:
        """Test that common blocklists are defined."""
        assert len(security_manager.COMMON_BLOCKLIST) > 0
        assert len(security_manager.PRODUCTIVITY_BLOCKLIST) > 0
        assert len(security_manager.ANONYMIZER_BLOCKLIST) > 0
        assert len(security_manager.FILE_SHARING_BLOCKLIST) > 0

    def test_url_filtering_policy_dataclass(self) -> None:
        """Test URLFilteringPolicy dataclass."""
        policy = URLFilteringPolicy(
            name="Test Policy",
            org_unit_path="/Test",
            url_blocklist=["*.bad.com"],
            url_allowlist=["*.good.com"],
            force_safe_search=True,
            block_third_party_cookies=True,
        )

        assert policy.name == "Test Policy"
        assert policy.org_unit_path == "/Test"
        assert "*.bad.com" in policy.url_blocklist
        assert "*.good.com" in policy.url_allowlist
        assert policy.force_safe_search is True

    def test_safe_browsing_policy_dataclass(self) -> None:
        """Test SafeBrowsingPolicy dataclass."""
        policy = SafeBrowsingPolicy(
            name="Test SB",
            org_unit_path="/",
            protection_level=2,
            extended_reporting=True,
            password_leak_detection=True,
        )

        assert policy.name == "Test SB"
        assert policy.protection_level == 2
        assert policy.extended_reporting is True
        assert policy.password_leak_detection is True

    def test_dlp_policy_dataclass(self) -> None:
        """Test DataLossPrevention dataclass."""
        policy = DataLossPrevention(
            name="Test DLP",
            org_unit_path="/",
            default_clipboard_setting=3,
            screen_capture_allowed=False,
            printing_enabled=True,
        )

        assert policy.name == "Test DLP"
        assert policy.default_clipboard_setting == 3
        assert policy.screen_capture_allowed is False
        assert policy.printing_enabled is True

    def test_security_level_enum(self) -> None:
        """Test SecurityLevel enum."""
        assert SecurityLevel.MINIMAL.value == "minimal"
        assert SecurityLevel.STANDARD.value == "standard"
        assert SecurityLevel.ENHANCED.value == "enhanced"
        assert SecurityLevel.MAXIMUM.value == "maximum"

    def test_content_category_enum(self) -> None:
        """Test ContentCategory enum."""
        assert ContentCategory.ADULT_CONTENT.value == "adult_content"
        assert ContentCategory.MALWARE.value == "malware"
        assert ContentCategory.PHISHING.value == "phishing"
        assert ContentCategory.SOCIAL_MEDIA.value == "social_media"
