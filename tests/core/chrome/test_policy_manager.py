"""Tests for Chrome Policy Manager."""

from unittest.mock import Mock

import pytest

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.chrome.policy_manager import (
    ChromePolicy,
    ChromePolicyManager,
    PolicySchema,
    PolicyScope,
    PolicyTemplate,
)


@pytest.fixture
def mock_client() -> Mock:
    """Create a mock GoogleWorkspaceClient."""
    client = Mock(spec=GoogleWorkspaceClient)
    return client


@pytest.fixture
def policy_manager(mock_client: Mock) -> ChromePolicyManager:
    """Create ChromePolicyManager instance."""
    return ChromePolicyManager(client=mock_client, customer_id="test_customer")


class TestChromePolicyManager:
    """Test ChromePolicyManager class."""

    def test_initialization(self, mock_client: Mock) -> None:
        """Test manager initialization."""
        manager = ChromePolicyManager(client=mock_client, customer_id="test_id")
        assert manager.client == mock_client
        assert manager.customer_id == "test_id"

    def test_create_from_template_secure_browser(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test creating policy from secure_browser template."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.SECURE_BROWSER,
            org_unit_path="/Engineering",
            scope=PolicyScope.USER,
        )

        assert policy.name == "secure_browser_policy"
        assert policy.org_unit_path == "/Engineering"
        assert policy.scope == PolicyScope.USER
        assert policy.template == PolicyTemplate.SECURE_BROWSER
        assert len(policy.policies) > 0

        # Check for key security policies
        assert policy.policies.get("SafeBrowsingProtectionLevel") == 2
        assert policy.policies.get("HttpsOnlyMode") == "force_enabled"
        assert policy.policies.get("IncognitoModeAvailability") == 1
        assert policy.policies.get("BlockThirdPartyCookies") is True

    def test_create_from_template_education(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test creating policy from education template."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.EDUCATION,
            org_unit_path="/Students",
            scope=PolicyScope.USER,
            name="Student Policy",
        )

        assert policy.name == "Student Policy"
        assert policy.policies.get("ForceSafeSearch") is True
        assert policy.policies.get("ForceYouTubeRestrict") == 2
        assert policy.policies.get("IncognitoModeAvailability") == 1

    def test_create_from_template_healthcare(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test creating policy from healthcare template."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.HEALTHCARE,
            org_unit_path="/Clinical",
        )

        assert policy.policies.get("ScreenCaptureAllowed") is False
        assert policy.policies.get("DefaultClipboardSetting") == 2
        assert policy.policies.get("AllowDeletingBrowserHistory") is False

    def test_create_from_template_financial(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test creating policy from financial template."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.FINANCIAL,
            org_unit_path="/Finance",
        )

        assert policy.policies.get("AutofillCreditCardEnabled") is False
        assert policy.policies.get("PasswordLeakDetectionEnabled") is True
        assert policy.policies.get("BlockThirdPartyCookies") is True

    def test_create_from_template_with_customization(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test creating policy with custom overrides."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.STANDARD,
            org_unit_path="/",
            customize={
                "DownloadRestrictions": 3,
                "CustomPolicy": "custom_value",
            },
        )

        assert policy.policies.get("DownloadRestrictions") == 3
        assert policy.policies.get("CustomPolicy") == "custom_value"

    def test_apply_policy_dry_run(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test applying policy in dry-run mode."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.STANDARD,
            org_unit_path="/Test",
        )

        result = policy_manager.apply_policy(policy, dry_run=True)

        assert result["status"] == "validated"
        assert result["policy"] == policy.name
        assert result["org_unit"] == "/Test"
        assert "validated but not applied" in result["message"]

    def test_validate_policy_success(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test policy validation with valid policy."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.SECURE_BROWSER,
            org_unit_path="/",
        )

        validation = policy_manager.validate_policy(policy)

        assert validation["valid"] is True
        assert isinstance(validation["warnings"], list)
        assert isinstance(validation["errors"], list)
        assert isinstance(validation["recommendations"], list)

    def test_validate_policy_with_recommendations(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test policy validation generates recommendations."""
        policy = ChromePolicy(
            name="test_policy",
            org_unit_path="/",
            scope=PolicyScope.USER,
            policies={
                "DeveloperToolsAvailability": 0,  # Enabled
                "SafeBrowsingProtectionLevel": 0,  # Disabled
            },
        )

        validation = policy_manager.validate_policy(policy)

        assert len(validation["recommendations"]) > 0
        # Should recommend enabling Safe Browsing
        assert any("Safe Browsing" in rec for rec in validation["recommendations"])

    def test_get_policy_schemas(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test getting policy schemas."""
        schemas = policy_manager.get_policy_schemas()

        assert len(schemas) > 0
        assert all(isinstance(s, PolicySchema) for s in schemas)

        # Check for key schemas
        schema_names = [s.name for s in schemas]
        assert "DownloadRestrictions" in schema_names
        assert "SafeBrowsingProtectionLevel" in schema_names
        assert "HttpsOnlyMode" in schema_names

    def test_export_policy_json(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test exporting policy as JSON."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.STANDARD,
            org_unit_path="/",
        )

        json_export = policy_manager.export_policy(policy, format="json")

        assert isinstance(json_export, str)
        assert policy.name in json_export
        assert "\n" in json_export  # JSON formatting

    def test_export_policy_markdown(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test exporting policy as Markdown."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.STANDARD,
            org_unit_path="/",
        )

        md_export = policy_manager.export_policy(policy, format="markdown")

        assert isinstance(md_export, str)
        assert f"# Chrome Policy: {policy.name}" in md_export
        assert "## Policies" in md_export

    def test_export_policy_invalid_format(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test exporting policy with invalid format raises error."""
        policy = policy_manager.create_from_template(
            template=PolicyTemplate.STANDARD,
            org_unit_path="/",
        )

        with pytest.raises(ValueError, match="Unsupported format"):
            policy_manager.export_policy(policy, format="xml")

    def test_format_policy_for_api(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test formatting policy for Chrome Policy API."""
        policy = ChromePolicy(
            name="test",
            org_unit_path="/Test",
            scope=PolicyScope.USER,
            policies={
                "DownloadRestrictions": 3,
                "SafeBrowsingProtectionLevel": 2,
            },
        )

        api_payload = policy_manager._format_policy_for_api(policy)

        assert "policyTargetKey" in api_payload
        assert "policies" in api_payload
        assert api_payload["policyTargetKey"]["targetResource"] == "orgunits//Test"
        assert len(api_payload["policies"]) == 2

    def test_chrome_policy_to_dict(self) -> None:
        """Test ChromePolicy to_dict method."""
        policy = ChromePolicy(
            name="test_policy",
            org_unit_path="/",
            scope=PolicyScope.USER,
            policies={"test": "value"},
            template=PolicyTemplate.STANDARD,
        )

        policy_dict = policy.to_dict()

        assert policy_dict["name"] == "test_policy"
        assert policy_dict["org_unit_path"] == "/"
        assert policy_dict["scope"] == "user"
        assert policy_dict["template"] == "standard"
        assert policy_dict["policies"] == {"test": "value"}

    def test_all_templates_work(
        self, policy_manager: ChromePolicyManager
    ) -> None:
        """Test that all policy templates can be created."""
        for template in PolicyTemplate:
            policy = policy_manager.create_from_template(
                template=template,
                org_unit_path="/",
            )

            assert policy is not None
            assert len(policy.policies) > 0
            assert policy.template == template

    def test_policy_schema_dataclass(self) -> None:
        """Test PolicySchema dataclass."""
        schema = PolicySchema(
            name="TestPolicy",
            value=True,
            description="Test description",
            recommended_value=False,
            security_impact="high",
        )

        assert schema.name == "TestPolicy"
        assert schema.value is True
        assert schema.security_impact == "high"
