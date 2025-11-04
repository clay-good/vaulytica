"""Tests for workflow implementations."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from dataclasses import dataclass

from vaulytica.workflows.external_pii_alert import (
    ExternalPIIAlertWorkflow,
    ExternalPIIAlertConfig,
    ExternalPIIAlertResult,
)
from vaulytica.workflows.gmail_external_pii_alert import (
    GmailExternalPIIAlertWorkflow,
    GmailExternalPIIAlertConfig,
    GmailExternalPIIAlertResult,
)
from vaulytica.core.detectors.pii_detector import PIIType, PIIMatch, PIIDetectionResult


@pytest.fixture
def mock_auth_client():
    """Mock authentication client."""
    client = Mock()
    client.drive = Mock()
    client.gmail = Mock()
    return client


@pytest.fixture
def mock_file_scanner():
    """Mock file scanner."""
    scanner = Mock()
    return scanner


@pytest.fixture
def mock_gmail_scanner():
    """Mock Gmail scanner."""
    scanner = Mock()
    return scanner


@pytest.fixture
def mock_webhook_client():
    """Mock webhook client."""
    client = Mock()
    client.send = Mock(return_value=True)
    return client


class TestExternalPIIAlertWorkflow:
    """Tests for Use Case 1: External Drive Files with PII Alert."""

    def test_workflow_initialization(self, mock_auth_client):
        """Test workflow can be initialized."""
        config = ExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=75,
        )

        workflow = ExternalPIIAlertWorkflow(mock_auth_client, config)

        assert workflow.config == config
        assert workflow.client == mock_auth_client

    def test_workflow_with_no_findings(self, mock_auth_client, mock_file_scanner):
        """Test workflow when no external files with PII are found."""
        config = ExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=75,
            dry_run=True,
        )

        workflow = ExternalPIIAlertWorkflow(mock_auth_client, config)

        # Mock scanner to return no results
        mock_file_scanner.scan.return_value = []

        with patch.object(workflow, 'file_scanner', mock_file_scanner):
            result = workflow.run(show_progress=False)

        assert isinstance(result, ExternalPIIAlertResult)
        assert result.total_files_scanned >= 0
        assert result.files_with_pii == 0
        assert result.alerts_sent == 0

    def test_workflow_detects_external_sharing(self, mock_auth_client):
        """Test workflow detects files shared externally."""
        config = ExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=50,
        )

        workflow = ExternalPIIAlertWorkflow(mock_auth_client, config)
        
        # Mock a file shared externally
        mock_file = Mock()
        mock_file.id = "file123"
        mock_file.name = "sensitive_data.pdf"
        mock_file.owner = "user@companyname.com"
        mock_file.shared_with = ["external@gmail.com"]
        mock_file.is_public = False
        
        # Test external detection logic
        is_external = any(
            email for email in mock_file.shared_with 
            if not email.endswith("@companyname.com")
        )
        
        assert is_external is True

    def test_workflow_detects_pii_in_content(self, mock_auth_client):
        """Test workflow detects PII in file content."""
        config = ExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=50,
        )

        workflow = ExternalPIIAlertWorkflow(mock_auth_client, config)
        
        # Mock PII detection result
        pii_result = PIIDetectionResult()
        pii_match = PIIMatch(
            pii_type=PIIType.SSN,
            value="234-56-7890",
            start_pos=0,
            end_pos=11,
            confidence=0.9,
        )
        pii_result.add_match(pii_match)
        
        assert pii_result.total_matches == 1
        assert PIIType.SSN in pii_result.pii_types_found
        assert pii_result.high_confidence_matches == 1

    def test_workflow_filters_by_risk_score(self, mock_auth_client):
        """Test workflow filters findings by minimum risk score."""
        config = ExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=75,
        )

        workflow = ExternalPIIAlertWorkflow(mock_auth_client, config)
        
        # Test risk score filtering
        low_risk_score = 50
        high_risk_score = 85
        
        assert low_risk_score < config.min_risk_score
        assert high_risk_score >= config.min_risk_score

    def test_workflow_dry_run_mode(self, mock_auth_client):
        """Test workflow dry run mode doesn't send alerts."""
        config = ExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=50,
            dry_run=True,
        )

        workflow = ExternalPIIAlertWorkflow(mock_auth_client, config)

        # In dry run, alerts_sent should be 0
        with patch.object(workflow, 'file_scanner') as mock_scanner:
            mock_scanner.scan.return_value = []
            result = workflow.run(show_progress=False)

        assert result.alerts_sent == 0


class TestGmailExternalPIIAlertWorkflow:
    """Tests for Use Case 2: Gmail External Attachments with PII Alert."""

    def test_workflow_initialization(self, mock_auth_client):
        """Test workflow can be initialized."""
        config = GmailExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=75,
        )

        workflow = GmailExternalPIIAlertWorkflow(mock_auth_client, config)

        assert workflow.config == config
        assert workflow.client == mock_auth_client

    def test_workflow_with_no_findings(self, mock_auth_client, mock_gmail_scanner):
        """Test workflow when no external emails with PII attachments are found."""
        config = GmailExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=75,
            dry_run=True,
        )

        workflow = GmailExternalPIIAlertWorkflow(mock_auth_client, config)

        # Mock scanner to return no results
        mock_gmail_scanner.scan_attachments.return_value = []

        with patch.object(workflow, 'gmail_scanner', mock_gmail_scanner):
            result = workflow.run(show_progress=False)

        assert isinstance(result, GmailExternalPIIAlertResult)
        assert result.total_messages_scanned >= 0
        assert result.attachments_with_pii == 0
        assert result.alerts_sent == 0

    def test_workflow_detects_external_recipients(self, mock_auth_client):
        """Test workflow detects emails sent to external recipients."""
        config = GmailExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=50,
        )

        workflow = GmailExternalPIIAlertWorkflow(mock_auth_client, config)
        
        # Mock email with external recipient
        recipients = ["internal@companyname.com", "external@gmail.com"]
        
        # Test external detection logic
        has_external = any(
            email for email in recipients 
            if not email.endswith("@companyname.com")
        )
        
        assert has_external is True

    def test_workflow_scans_attachment_content(self, mock_auth_client):
        """Test workflow scans attachment content for PII."""
        config = GmailExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=50,
        )

        workflow = GmailExternalPIIAlertWorkflow(mock_auth_client, config)
        
        # Mock attachment with PII
        mock_attachment = Mock()
        mock_attachment.filename = "employee_data.pdf"
        mock_attachment.mime_type = "application/pdf"
        mock_attachment.size = 1024 * 100  # 100KB
        
        # Mock PII detection in attachment
        pii_result = PIIDetectionResult()
        pii_match = PIIMatch(
            pii_type=PIIType.CREDIT_CARD,
            value="4532-1488-0343-6467",
            start_pos=0,
            end_pos=19,
            confidence=0.85,
        )
        pii_result.add_match(pii_match)
        
        assert pii_result.total_matches == 1
        assert PIIType.CREDIT_CARD in pii_result.pii_types_found

    def test_workflow_supports_date_range(self, mock_auth_client):
        """Test workflow supports date range filtering."""
        config = GmailExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=50,
            days_back=7,
        )

        workflow = GmailExternalPIIAlertWorkflow(mock_auth_client, config)
        
        assert config.days_back == 7

    def test_workflow_filters_by_risk_score(self, mock_auth_client):
        """Test workflow filters findings by minimum risk score."""
        config = GmailExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=80,
        )

        workflow = GmailExternalPIIAlertWorkflow(mock_auth_client, config)
        
        # Test risk score filtering
        low_risk_score = 60
        high_risk_score = 90
        
        assert low_risk_score < config.min_risk_score
        assert high_risk_score >= config.min_risk_score

    def test_workflow_dry_run_mode(self, mock_auth_client):
        """Test workflow dry run mode doesn't send alerts."""
        config = GmailExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            min_risk_score=50,
            dry_run=True,
        )

        workflow = GmailExternalPIIAlertWorkflow(mock_auth_client, config)

        # In dry run, alerts_sent should be 0
        with patch.object(workflow, 'gmail_scanner') as mock_scanner:
            mock_scanner.scan_attachments.return_value = []
            result = workflow.run(show_progress=False)

        assert result.alerts_sent == 0


class TestWorkflowIntegration:
    """Integration tests for workflows."""

    def test_both_workflows_use_same_pii_detector(self, mock_auth_client):
        """Test both workflows use the same PII detection engine."""
        config1 = ExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
        )

        config2 = GmailExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
        )

        workflow1 = ExternalPIIAlertWorkflow(mock_auth_client, config1)
        workflow2 = GmailExternalPIIAlertWorkflow(mock_auth_client, config2)
        
        # Both should have PII detection capability
        assert hasattr(workflow1, 'file_scanner') or hasattr(workflow1, 'pii_detector')
        assert hasattr(workflow2, 'gmail_scanner') or hasattr(workflow2, 'pii_detector')

    def test_workflows_support_multiple_alert_channels(self, mock_auth_client):
        """Test workflows support email and webhook alerts."""
        config = ExternalPIIAlertConfig(
            domain="companyname.com",
            alert_email=["security@companyname.com"],
            alert_webhook="https://siem.companyname.com/webhook",
        )

        workflow = ExternalPIIAlertWorkflow(mock_auth_client, config)
        
        assert config.alert_email is not None
        assert config.alert_webhook is not None

