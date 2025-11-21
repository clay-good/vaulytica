"""Tests for Chrome Extension Manager."""


import pytest

from vaulytica.core.chrome.extension_manager import (
    ChromeExtensionManager,
    Extension,
    ExtensionInstallType,
    ExtensionPolicy,
)


@pytest.fixture
def extension_manager() -> ChromeExtensionManager:
    """Create ChromeExtensionManager instance."""
    return ChromeExtensionManager(customer_id="test_customer")


class TestChromeExtensionManager:
    """Test ChromeExtensionManager class."""

    def test_initialization(self) -> None:
        """Test manager initialization."""
        manager = ChromeExtensionManager(customer_id="test_id")
        assert manager.customer_id == "test_id"

    def test_create_secure_allowlist_default(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test creating default secure allowlist."""
        allowlist = extension_manager.create_secure_allowlist()

        assert len(allowlist) > 0
        assert all(isinstance(e, Extension) for e in allowlist)
        assert all(e.install_type == ExtensionInstallType.ALLOWED for e in allowlist)

        # Should include Google official and security extensions by default
        google_exts = [e for e in allowlist if e.vendor == "Google"]
        assert len(google_exts) > 0

    def test_create_secure_allowlist_custom(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test creating allowlist with custom extensions."""
        custom_ids = ["abcdefghijklmnopqrstuvwxyzabcdef"]
        allowlist = extension_manager.create_secure_allowlist(
            include_google_official=False,
            include_security=False,
            include_productivity=False,
            custom_extensions=custom_ids,
        )

        assert len(allowlist) == 1
        assert allowlist[0].extension_id == custom_ids[0]
        assert allowlist[0].verified is False

    def test_create_secure_allowlist_with_productivity(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test creating allowlist including productivity extensions."""
        allowlist = extension_manager.create_secure_allowlist(
            include_productivity=True
        )

        productivity_exts = [e for e in allowlist if e.category == "productivity"]
        assert len(productivity_exts) > 0

    def test_create_security_extension_bundle(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test creating security extension bundle."""
        bundle = extension_manager.create_security_extension_bundle()

        assert len(bundle) > 0
        assert all(e.category == "security" for e in bundle)
        assert all(
            e.install_type == ExtensionInstallType.FORCE_INSTALLED for e in bundle
        )

        # Should include HTTPS Everywhere and uBlock Origin
        names = [e.name for e in bundle]
        assert "HTTPS Everywhere" in names or "uBlock Origin" in names

    def test_analyze_extension_risk_verified(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test risk analysis for verified extension."""
        # Use Google Docs Offline extension ID
        analysis = extension_manager.analyze_extension_risk(
            extension_id="gighmmpiobklfepjocnamgkkbiglidom",
            name="Google Docs Offline",
            permissions=["storage"],
        )

        assert analysis["verified"] is True
        assert analysis["risk_level"] in ["low", "minimal"]
        assert analysis["vendor"] == "Google"

    def test_analyze_extension_risk_unverified(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test risk analysis for unverified extension."""
        analysis = extension_manager.analyze_extension_risk(
            extension_id="aaaabbbbccccddddeeeeffffgggghhhh",
            name="Unknown Extension",
            permissions=[],
        )

        assert analysis["verified"] is False
        assert analysis["risk_score"] >= 20  # Unverified = +20 points

    def test_analyze_extension_risk_high_risk_permissions(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test risk analysis with high-risk permissions."""
        analysis = extension_manager.analyze_extension_risk(
            extension_id="aaaabbbbccccddddeeeeffffgggghhhh",
            name="Test Extension",
            permissions=["webRequest", "webRequestBlocking", "<all_urls>", "tabs"],
        )

        assert analysis["risk_score"] > 50
        assert analysis["risk_level"] in ["high", "critical"]
        assert len(analysis["risk_factors"]) > 0

    def test_analyze_extension_risk_excessive_permissions(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test risk analysis with excessive permissions."""
        many_permissions = [f"permission_{i}" for i in range(15)]
        analysis = extension_manager.analyze_extension_risk(
            extension_id="aaaabbbbccccddddeeeeffffgggghhhh",
            name="Test Extension",
            permissions=many_permissions,
        )

        assert "Excessive permissions" in str(analysis["risk_factors"])

    def test_create_extension_policy_allowlist(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test creating allowlist extension policy."""
        policy = extension_manager.create_extension_policy(
            name="Test Allowlist",
            org_unit_path="/Test",
            policy_type="allowlist",
        )

        assert policy.name == "Test Allowlist"
        assert policy.org_unit_path == "/Test"
        assert policy.block_all_except_allowed is True
        assert len(policy.allowed) > 0

    def test_create_extension_policy_security_focused(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test creating security-focused policy."""
        policy = extension_manager.create_extension_policy(
            name="Security Policy",
            org_unit_path="/",
            policy_type="security_focused",
        )

        assert len(policy.force_installed) > 0
        assert len(policy.allowed) > 0
        assert policy.block_all_except_allowed is True

    def test_validate_extension_id_valid(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test validating valid extension ID."""
        valid_id = "abcdefghijklmnopqrstuvwxyzabcdef"
        assert extension_manager.validate_extension_id(valid_id) is False  # Uses a-p only

        valid_id = "gighmmpiobklfepjocnamgkkbiglidom"  # Real Google Docs ID
        assert extension_manager.validate_extension_id(valid_id) is True

    def test_validate_extension_id_invalid(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test validating invalid extension IDs."""
        # Too short
        assert extension_manager.validate_extension_id("short") is False

        # Contains invalid characters
        assert extension_manager.validate_extension_id("xyz" * 10 + "12") is False

        # Wrong length
        assert extension_manager.validate_extension_id("a" * 31) is False

    def test_export_policy_json(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test exporting extension policy as JSON."""
        policy = extension_manager.create_extension_policy(
            name="Test Policy",
            org_unit_path="/",
            policy_type="allowlist",
        )

        json_policy = extension_manager.export_policy_json(policy)

        assert "ExtensionSettings" in json_policy
        assert isinstance(json_policy["ExtensionSettings"], dict)

        if policy.block_all_except_allowed:
            assert "*" in json_policy["ExtensionSettings"]

    def test_get_extension_catalog(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test getting extension catalog."""
        catalog = extension_manager.get_extension_catalog()

        assert len(catalog) > 0
        assert all("extension_id" in ext for ext in catalog)
        assert all("name" in ext for ext in catalog)
        assert all("category" in ext for ext in catalog)
        assert all("verified" in ext for ext in catalog)

    def test_extension_to_policy_dict(self) -> None:
        """Test Extension to_policy_dict method."""
        ext = Extension(
            extension_id="test123",
            name="Test Extension",
            install_type=ExtensionInstallType.FORCE_INSTALLED,
            minimum_version="1.0.0",
        )

        policy_dict = ext.to_policy_dict()

        assert policy_dict["id"] == "test123"
        assert policy_dict["installation_mode"] == "force_installed"
        assert policy_dict["minimum_version_required"] == "1.0.0"

    def test_extension_policy_dataclass(self) -> None:
        """Test ExtensionPolicy dataclass."""
        ext1 = Extension(
            extension_id="ext1",
            name="Extension 1",
            install_type=ExtensionInstallType.ALLOWED,
        )
        ext2 = Extension(
            extension_id="ext2",
            name="Extension 2",
            install_type=ExtensionInstallType.BLOCKED,
        )

        policy = ExtensionPolicy(
            name="Test Policy",
            org_unit_path="/Test",
            allowed=[ext1],
            blocked=[ext2],
            block_all_except_allowed=True,
        )

        assert policy.name == "Test Policy"
        assert len(policy.allowed) == 1
        assert len(policy.blocked) == 1
        assert policy.block_all_except_allowed is True

    def test_risky_extension_patterns(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test detection of risky extension patterns."""
        risky_names = [
            "Screen Recorder Pro",
            "VPN Extension",
            "Data Scraper Tool",
        ]

        for name in risky_names:
            analysis = extension_manager.analyze_extension_risk(
                extension_id="aaaabbbbccccddddeeeeffffgggghhhh",
                name=name,
                permissions=[],
            )

            # Should have higher risk score due to pattern
            assert analysis["risk_score"] > 20

    def test_verified_extensions_catalog_complete(
        self, extension_manager: ChromeExtensionManager
    ) -> None:
        """Test that verified extensions catalog is complete."""
        verified = extension_manager.VERIFIED_EXTENSIONS

        # Should have entries for major categories
        categories = {info["category"] for info in verified.values()}
        assert "security" in categories
        assert "productivity" in categories

        # Each entry should have required fields
        for info in verified.values():
            assert "name" in info
            assert "vendor" in info
            assert "category" in info
            assert "risk_level" in info
