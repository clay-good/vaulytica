"""Tests for authentication module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from vaulytica.core.auth.credentials import (
    CredentialManager,
    AuthenticationError,
    create_credential_manager_from_config,
)
from vaulytica.core.auth.client import GoogleWorkspaceClient, APIError


class TestCredentialManager:
    """Tests for CredentialManager."""

    def test_init(self):
        """Test CredentialManager initialization."""
        manager = CredentialManager(credentials_file="test.json")
        assert manager.credentials_file == "test.json"
        assert manager.scopes == CredentialManager.SCOPES

    def test_init_with_custom_scopes(self):
        """Test CredentialManager with custom scopes."""
        custom_scopes = ["https://www.googleapis.com/auth/drive.readonly"]
        manager = CredentialManager(credentials_file="test.json", scopes=custom_scopes)
        assert manager.scopes == custom_scopes

    def test_no_credentials_raises_error(self):
        """Test that missing credentials raises error."""
        manager = CredentialManager()
        with pytest.raises(AuthenticationError, match="No credentials provided"):
            manager.get_credentials()

    @patch("vaulytica.core.auth.credentials.service_account")
    @patch("os.path.exists")
    def test_service_account_authentication(self, mock_exists, mock_sa):
        """Test service account authentication."""
        mock_exists.return_value = True
        mock_creds = Mock()
        mock_sa.Credentials.from_service_account_file.return_value = mock_creds

        manager = CredentialManager(credentials_file="service-account.json")
        creds = manager.get_credentials()

        assert creds == mock_creds
        mock_sa.Credentials.from_service_account_file.assert_called_once()

    @patch("vaulytica.core.auth.credentials.service_account")
    @patch("os.path.exists")
    def test_service_account_with_impersonation(self, mock_exists, mock_sa):
        """Test service account with user impersonation."""
        mock_exists.return_value = True
        mock_creds = Mock()
        mock_impersonated_creds = Mock()
        mock_creds.with_subject.return_value = mock_impersonated_creds
        mock_sa.Credentials.from_service_account_file.return_value = mock_creds

        manager = CredentialManager(credentials_file="service-account.json")
        creds = manager.get_credentials(impersonate_user="admin@example.com")

        assert creds == mock_impersonated_creds
        mock_creds.with_subject.assert_called_once_with("admin@example.com")

    @patch("os.path.exists")
    def test_service_account_file_not_found(self, mock_exists):
        """Test error when service account file doesn't exist."""
        mock_exists.return_value = False

        manager = CredentialManager(credentials_file="missing.json")
        with pytest.raises(AuthenticationError, match="not found"):
            manager.get_credentials()

    @patch("vaulytica.core.auth.credentials.Credentials")
    @patch("os.path.exists")
    def test_oauth_with_existing_token(self, mock_exists, mock_creds_class):
        """Test OAuth with existing valid token."""
        mock_exists.return_value = True
        mock_creds = Mock()
        mock_creds.valid = True
        mock_creds_class.from_authorized_user_file.return_value = mock_creds

        manager = CredentialManager(oauth_credentials_file="oauth.json", token_file="token.json")
        creds = manager.get_credentials()

        assert creds == mock_creds
        mock_creds_class.from_authorized_user_file.assert_called_once()

    @patch("vaulytica.core.auth.credentials.Credentials")
    @patch("vaulytica.core.auth.credentials.Request")
    @patch("os.path.exists")
    def test_oauth_with_expired_token_refresh(self, mock_exists, mock_request, mock_creds_class):
        """Test OAuth with expired token that gets refreshed."""
        mock_exists.return_value = True
        mock_creds = Mock()
        mock_creds.valid = False
        mock_creds.expired = True
        mock_creds.refresh_token = "refresh_token"
        mock_creds_class.from_authorized_user_file.return_value = mock_creds

        manager = CredentialManager(oauth_credentials_file="oauth.json", token_file="token.json")

        with patch("builtins.open", MagicMock()):
            creds = manager.get_credentials()

        assert creds == mock_creds
        mock_creds.refresh.assert_called_once()

    @patch("vaulytica.core.auth.credentials.InstalledAppFlow")
    @patch("vaulytica.core.auth.credentials.Credentials")
    @patch("os.path.exists")
    def test_oauth_new_flow(self, mock_exists, mock_creds_class, mock_flow_class):
        """Test OAuth with new authorization flow."""
        def exists_side_effect(path):
            if "oauth.json" in path:
                return True
            return False

        mock_exists.side_effect = exists_side_effect

        mock_creds = Mock()
        mock_creds.valid = False
        mock_creds.expired = False
        mock_creds_class.from_authorized_user_file.return_value = mock_creds

        mock_new_creds = Mock()
        mock_flow = Mock()
        mock_flow.run_local_server.return_value = mock_new_creds
        mock_flow_class.from_client_secrets_file.return_value = mock_flow

        manager = CredentialManager(oauth_credentials_file="oauth.json", token_file="token.json")

        with patch("builtins.open", MagicMock()):
            creds = manager.get_credentials()

        assert creds == mock_new_creds
        mock_flow.run_local_server.assert_called_once()

    @patch("os.path.exists")
    def test_oauth_missing_credentials_file(self, mock_exists):
        """Test OAuth with missing credentials file."""
        def exists_side_effect(path):
            if "token.json" in path:
                return False
            if "oauth.json" in path:
                return False
            return False

        mock_exists.side_effect = exists_side_effect

        manager = CredentialManager(oauth_credentials_file="oauth.json", token_file="token.json")

        with pytest.raises(AuthenticationError, match="OAuth credentials file not found"):
            manager.get_credentials()

    @patch("vaulytica.core.auth.credentials.Credentials")
    @patch("os.path.exists")
    def test_oauth_authentication_failure(self, mock_exists, mock_creds_class):
        """Test OAuth authentication failure."""
        mock_exists.return_value = True
        mock_creds_class.from_authorized_user_file.side_effect = Exception("Invalid token")

        manager = CredentialManager(oauth_credentials_file="oauth.json", token_file="token.json")

        with pytest.raises(AuthenticationError, match="OAuth authentication failed"):
            manager.get_credentials()

    def test_validate_credentials_success(self):
        """Test credential validation success."""
        manager = CredentialManager(credentials_file="test.json")
        mock_creds = Mock()
        mock_creds.valid = True
        manager._credentials = mock_creds

        assert manager.validate_credentials() is True

    def test_validate_credentials_failure(self):
        """Test credential validation failure."""
        manager = CredentialManager()
        assert manager.validate_credentials() is False

    @patch("os.path.exists")
    @patch("os.remove")
    def test_revoke_credentials(self, mock_remove, mock_exists):
        """Test credential revocation."""
        mock_exists.return_value = True
        manager = CredentialManager(token_file="token.json")
        manager._credentials = Mock()

        manager.revoke_credentials()

        mock_remove.assert_called_once_with("token.json")
        assert manager._credentials is None

    def test_create_from_config_with_service_account(self):
        """Test creating credential manager from config."""
        config = {
            "google_workspace": {
                "credentials_file": "service-account.json",
            }
        }

        manager = create_credential_manager_from_config(config)
        assert manager.credentials_file == "service-account.json"

    def test_create_from_config_with_oauth(self):
        """Test creating credential manager from config with OAuth."""
        config = {
            "google_workspace": {
                "oauth_credentials": "oauth.json",
            }
        }

        manager = create_credential_manager_from_config(config)
        assert manager.oauth_credentials_file == "oauth.json"

    def test_create_from_config_missing_credentials(self):
        """Test error when config has no credentials."""
        config = {"google_workspace": {}}

        with pytest.raises(ValueError, match="must include either"):
            create_credential_manager_from_config(config)


class TestGoogleWorkspaceClient:
    """Tests for GoogleWorkspaceClient."""

    def test_init(self):
        """Test GoogleWorkspaceClient initialization."""
        manager = Mock()
        client = GoogleWorkspaceClient(manager, impersonate_user="admin@example.com")

        assert client.credential_manager == manager
        assert client.impersonate_user == "admin@example.com"

    @patch("vaulytica.core.auth.client.build")
    def test_drive_service_property(self, mock_build):
        """Test Drive service property."""
        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)
        service = client.drive

        assert service == mock_service
        mock_build.assert_called_once_with("drive", "v3", credentials=mock_creds)

    @patch("vaulytica.core.auth.client.build")
    def test_admin_service_property(self, mock_build):
        """Test Admin service property."""
        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)
        service = client.admin

        assert service == mock_service
        mock_build.assert_called_once_with("admin", "directory_v1", credentials=mock_creds)

    @patch("vaulytica.core.auth.client.build")
    def test_service_caching(self, mock_build):
        """Test that services are cached after first access."""
        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)
        service1 = client.drive
        service2 = client.drive

        assert service1 == service2
        mock_build.assert_called_once()  # Should only be called once

    @patch("vaulytica.core.auth.client.build")
    def test_test_connection_success(self, mock_build):
        """Test successful connection test."""
        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds

        mock_users = Mock()
        mock_list = Mock()
        mock_execute = Mock(return_value={"users": []})
        mock_list.execute = mock_execute
        mock_users.list.return_value = mock_list

        mock_service = Mock()
        mock_service.users.return_value = mock_users
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)
        result = client.test_connection()

        assert result is True

    @patch("vaulytica.core.auth.client.build")
    def test_test_connection_failure(self, mock_build):
        """Test connection test failure."""
        from googleapiclient.errors import HttpError

        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds

        mock_service = Mock()
        mock_service.users().list().execute.side_effect = HttpError(
            Mock(status=403), b"Forbidden"
        )
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)

        with pytest.raises(APIError, match="Connection test failed"):
            client.test_connection()

    @patch("vaulytica.core.auth.client.build")
    def test_test_connection_unexpected_error(self, mock_build):
        """Test connection test with unexpected error."""
        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds

        mock_service = Mock()
        mock_service.users().list().execute.side_effect = RuntimeError("Unexpected error")
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)

        with pytest.raises(APIError, match="Unexpected error during connection test"):
            client.test_connection()

    @patch("vaulytica.core.auth.client.build")
    def test_drive_service_initialization_error(self, mock_build):
        """Test Drive service initialization error."""
        manager = Mock()
        manager.get_credentials.side_effect = Exception("Auth failed")

        client = GoogleWorkspaceClient(manager)

        with pytest.raises(AuthenticationError, match="Failed to initialize Drive service"):
            _ = client.drive

    @patch("vaulytica.core.auth.client.build")
    def test_admin_service_initialization_error(self, mock_build):
        """Test Admin service initialization error."""
        manager = Mock()
        manager.get_credentials.side_effect = Exception("Auth failed")

        client = GoogleWorkspaceClient(manager)

        with pytest.raises(AuthenticationError, match="Failed to initialize Admin service"):
            _ = client.admin

    @patch("vaulytica.core.auth.client.build")
    def test_reports_service_property(self, mock_build):
        """Test Reports service property."""
        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)
        service = client.reports

        assert service == mock_service
        mock_build.assert_called_once_with("admin", "reports_v1", credentials=mock_creds)

    @patch("vaulytica.core.auth.client.build")
    def test_reports_service_initialization_error(self, mock_build):
        """Test Reports service initialization error."""
        manager = Mock()
        manager.get_credentials.side_effect = Exception("Auth failed")

        client = GoogleWorkspaceClient(manager)

        with pytest.raises(AuthenticationError, match="Failed to initialize Reports service"):
            _ = client.reports

    @patch("vaulytica.core.auth.client.build")
    def test_gmail_service_property(self, mock_build):
        """Test Gmail service property."""
        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)
        service = client.gmail

        assert service == mock_service
        mock_build.assert_called_once_with("gmail", "v1", credentials=mock_creds)

    @patch("vaulytica.core.auth.client.build")
    def test_gmail_service_initialization_error(self, mock_build):
        """Test Gmail service initialization error."""
        manager = Mock()
        manager.get_credentials.side_effect = Exception("Auth failed")

        client = GoogleWorkspaceClient(manager)

        with pytest.raises(AuthenticationError, match="Failed to initialize Gmail service"):
            _ = client.gmail

    @patch("vaulytica.core.auth.client.build")
    def test_calendar_service_property(self, mock_build):
        """Test Calendar service property."""
        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)
        service = client.calendar

        assert service == mock_service
        mock_build.assert_called_once_with("calendar", "v3", credentials=mock_creds)

    @patch("vaulytica.core.auth.client.build")
    def test_calendar_service_initialization_error(self, mock_build):
        """Test Calendar service initialization error."""
        manager = Mock()
        manager.get_credentials.side_effect = Exception("Auth failed")

        client = GoogleWorkspaceClient(manager)

        with pytest.raises(AuthenticationError, match="Failed to initialize Calendar service"):
            _ = client.calendar

    @patch("vaulytica.core.auth.client.build")
    def test_vault_service_property(self, mock_build):
        """Test Vault service property."""
        manager = Mock()
        mock_creds = Mock()
        manager.get_credentials.return_value = mock_creds
        mock_service = Mock()
        mock_build.return_value = mock_service

        client = GoogleWorkspaceClient(manager)
        service = client.vault

        assert service == mock_service
        mock_build.assert_called_once_with("vault", "v1", credentials=mock_creds)

    @patch("vaulytica.core.auth.client.build")
    def test_vault_service_initialization_error(self, mock_build):
        """Test Vault service initialization error."""
        manager = Mock()
        manager.get_credentials.side_effect = Exception("Auth failed")

        client = GoogleWorkspaceClient(manager)

        with pytest.raises(AuthenticationError, match="Failed to initialize Vault service"):
            _ = client.vault

    def test_create_client_from_config(self):
        """Test creating client from config."""
        from vaulytica.core.auth.client import create_client_from_config

        config = {
            "google_workspace": {
                "credentials_file": "service-account.json",
                "impersonate_user": "admin@example.com",
            }
        }

        with patch("os.path.exists", return_value=True):
            with patch("vaulytica.core.auth.credentials.service_account"):
                client = create_client_from_config(config)
                assert client.impersonate_user == "admin@example.com"

