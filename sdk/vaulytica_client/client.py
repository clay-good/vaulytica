"""
Vaulytica API Client

Main client class for interacting with the Vaulytica API.
"""

from typing import Any, Optional
from urllib.parse import urljoin

import httpx

from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    NotFoundError,
    RateLimitError,
    TimeoutError,
    ValidationError,
    VaulyticaError,
)
from .resources import (
    AlertsResource,
    AuditResource,
    ComplianceResource,
    DeltaResource,
    DomainsResource,
    FindingsResource,
    ScansResource,
    SchedulesResource,
    UsersResource,
)


class VaulyticaClient:
    """
    Vaulytica API Client

    A comprehensive client for interacting with the Vaulytica API.

    Example:
        client = VaulyticaClient(base_url="https://vaulytica.example.com")
        client.login("admin@example.com", "password")

        # Access resources
        scans = client.scans.list()
        findings = client.findings.list_security()
    """

    DEFAULT_TIMEOUT = 30.0
    API_VERSION = "v1"

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT,
        verify_ssl: bool = True,
    ):
        """
        Initialize the Vaulytica API client.

        Args:
            base_url: The base URL of the Vaulytica API (e.g., "https://vaulytica.example.com")
            api_key: Optional API key for authentication (alternative to login)
            timeout: Request timeout in seconds (default: 30)
            verify_ssl: Whether to verify SSL certificates (default: True)
        """
        self.base_url = base_url.rstrip("/")
        self.api_url = f"{self.base_url}/api/{self.API_VERSION}"
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._token: Optional[str] = None
        self._refresh_token: Optional[str] = None

        # Initialize HTTP client
        self._client = httpx.Client(
            timeout=timeout,
            verify=verify_ssl,
            headers=self._get_default_headers(),
        )

        # Set API key if provided
        if api_key:
            self._token = api_key

        # Initialize resource handlers
        self._init_resources()

    def _init_resources(self) -> None:
        """Initialize resource handlers."""
        self.scans = ScansResource(self)
        self.findings = FindingsResource(self)
        self.domains = DomainsResource(self)
        self.schedules = SchedulesResource(self)
        self.alerts = AlertsResource(self)
        self.compliance = ComplianceResource(self)
        self.users = UsersResource(self)
        self.audit = AuditResource(self)
        self.delta = DeltaResource(self)

    def _get_default_headers(self) -> dict:
        """Get default request headers."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "vaulytica-client/1.0.0",
        }

    def _get_auth_headers(self) -> dict:
        """Get authentication headers."""
        headers = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def login(self, email: str, password: str) -> dict:
        """
        Authenticate with email and password.

        Args:
            email: User email address
            password: User password

        Returns:
            dict: Authentication response with user info

        Raises:
            AuthenticationError: If credentials are invalid
        """
        response = self._request(
            "POST",
            "/auth/login",
            json={"email": email, "password": password},
            authenticate=False,
        )
        self._token = response.get("access_token")
        self._refresh_token = response.get("refresh_token")
        return response

    def logout(self) -> None:
        """
        Log out and clear authentication tokens.
        """
        if self._token:
            try:
                self._request("POST", "/auth/logout")
            except VaulyticaError:
                pass  # Ignore logout errors
        self._token = None
        self._refresh_token = None

    def refresh(self) -> dict:
        """
        Refresh the authentication token.

        Returns:
            dict: New authentication tokens

        Raises:
            AuthenticationError: If refresh token is invalid
        """
        if not self._refresh_token:
            raise AuthenticationError("No refresh token available")

        response = self._request(
            "POST",
            "/auth/refresh",
            json={"refresh_token": self._refresh_token},
            authenticate=False,
        )
        self._token = response.get("access_token")
        self._refresh_token = response.get("refresh_token", self._refresh_token)
        return response

    def get_current_user(self) -> dict:
        """
        Get the current authenticated user.

        Returns:
            dict: Current user information
        """
        return self._request("GET", "/auth/me")

    def get_permissions(self) -> dict:
        """
        Get current user's permissions.

        Returns:
            dict: User permissions including domain access
        """
        return self._request("GET", "/auth/me/permissions")

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
        data: Optional[dict] = None,
        authenticate: bool = True,
        raw_response: bool = False,
    ) -> Any:
        """
        Make an API request.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            endpoint: API endpoint (e.g., "/scans")
            params: Query parameters
            json: JSON body data
            data: Form data
            authenticate: Whether to include auth headers
            raw_response: Return raw response instead of JSON

        Returns:
            API response data

        Raises:
            VaulyticaError: On API errors
        """
        url = urljoin(self.api_url + "/", endpoint.lstrip("/"))

        headers = self._get_default_headers()
        if authenticate:
            headers.update(self._get_auth_headers())

        try:
            response = self._client.request(
                method=method,
                url=url,
                params=params,
                json=json,
                data=data,
                headers=headers,
            )
        except httpx.ConnectError as e:
            raise ConnectionError(f"Failed to connect to {self.base_url}: {e}")
        except httpx.TimeoutException as e:
            raise TimeoutError(f"Request timed out: {e}")

        return self._handle_response(response, raw_response)

    def _handle_response(self, response: httpx.Response, raw_response: bool = False) -> Any:
        """
        Handle API response.

        Args:
            response: HTTP response object
            raw_response: Return raw response content

        Returns:
            Parsed response data

        Raises:
            VaulyticaError: On error responses
        """
        if raw_response:
            if response.status_code >= 400:
                self._raise_error(response)
            return response.content

        # Handle successful responses
        if response.status_code == 204:
            return None

        if response.status_code >= 400:
            self._raise_error(response)

        try:
            return response.json()
        except Exception:
            return response.text

    def _raise_error(self, response: httpx.Response) -> None:
        """
        Raise appropriate exception for error response.

        Args:
            response: HTTP response object

        Raises:
            VaulyticaError: Appropriate exception type
        """
        try:
            data = response.json()
            message = data.get("detail", str(data))
        except Exception:
            message = response.text or f"HTTP {response.status_code}"

        kwargs = {
            "message": message,
            "status_code": response.status_code,
            "response": data if "data" in dir() else {},
        }

        if response.status_code == 401:
            raise AuthenticationError(**kwargs)
        elif response.status_code == 403:
            raise AuthorizationError(**kwargs)
        elif response.status_code == 404:
            raise NotFoundError(**kwargs)
        elif response.status_code == 422:
            errors = data.get("detail", []) if isinstance(data, dict) else []
            raise ValidationError(errors=errors, **kwargs)
        elif response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                retry_after=int(retry_after) if retry_after else None,
                **kwargs,
            )
        else:
            raise VaulyticaError(**kwargs)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "VaulyticaClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()


class AsyncVaulyticaClient(VaulyticaClient):
    """
    Async version of the Vaulytica API Client.

    Example:
        async with AsyncVaulyticaClient(base_url="https://vaulytica.example.com") as client:
            await client.login("admin@example.com", "password")
            scans = await client.scans.list()
    """

    def __init__(self, *args, **kwargs):
        # Don't call parent __init__ yet
        self.base_url = kwargs.get("base_url", args[0] if args else "").rstrip("/")
        self.api_url = f"{self.base_url}/api/{self.API_VERSION}"
        self.timeout = kwargs.get("timeout", self.DEFAULT_TIMEOUT)
        self.verify_ssl = kwargs.get("verify_ssl", True)
        self._token: Optional[str] = None
        self._refresh_token: Optional[str] = None

        # Initialize async HTTP client
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            headers=self._get_default_headers(),
        )

        # Set API key if provided
        if kwargs.get("api_key"):
            self._token = kwargs["api_key"]

        # Initialize async resource handlers
        from .resources import (
            AsyncScansResource,
            AsyncFindingsResource,
            AsyncDomainsResource,
            AsyncSchedulesResource,
            AsyncAlertsResource,
            AsyncComplianceResource,
            AsyncUsersResource,
            AsyncAuditResource,
            AsyncDeltaResource,
        )

        self.scans = AsyncScansResource(self)
        self.findings = AsyncFindingsResource(self)
        self.domains = AsyncDomainsResource(self)
        self.schedules = AsyncSchedulesResource(self)
        self.alerts = AsyncAlertsResource(self)
        self.compliance = AsyncComplianceResource(self)
        self.users = AsyncUsersResource(self)
        self.audit = AsyncAuditResource(self)
        self.delta = AsyncDeltaResource(self)

    async def login(self, email: str, password: str) -> dict:
        """Authenticate with email and password (async)."""
        response = await self._request(
            "POST",
            "/auth/login",
            json={"email": email, "password": password},
            authenticate=False,
        )
        self._token = response.get("access_token")
        self._refresh_token = response.get("refresh_token")
        return response

    async def logout(self) -> None:
        """Log out and clear authentication tokens (async)."""
        if self._token:
            try:
                await self._request("POST", "/auth/logout")
            except VaulyticaError:
                pass
        self._token = None
        self._refresh_token = None

    async def refresh(self) -> dict:
        """Refresh the authentication token (async)."""
        if not self._refresh_token:
            raise AuthenticationError("No refresh token available")

        response = await self._request(
            "POST",
            "/auth/refresh",
            json={"refresh_token": self._refresh_token},
            authenticate=False,
        )
        self._token = response.get("access_token")
        self._refresh_token = response.get("refresh_token", self._refresh_token)
        return response

    async def get_current_user(self) -> dict:
        """Get the current authenticated user (async)."""
        return await self._request("GET", "/auth/me")

    async def get_permissions(self) -> dict:
        """Get current user's permissions (async)."""
        return await self._request("GET", "/auth/me/permissions")

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[dict] = None,
        json: Optional[dict] = None,
        data: Optional[dict] = None,
        authenticate: bool = True,
        raw_response: bool = False,
    ) -> Any:
        """Make an async API request."""
        url = urljoin(self.api_url + "/", endpoint.lstrip("/"))

        headers = self._get_default_headers()
        if authenticate:
            headers.update(self._get_auth_headers())

        try:
            response = await self._client.request(
                method=method,
                url=url,
                params=params,
                json=json,
                data=data,
                headers=headers,
            )
        except httpx.ConnectError as e:
            raise ConnectionError(f"Failed to connect to {self.base_url}: {e}")
        except httpx.TimeoutException as e:
            raise TimeoutError(f"Request timed out: {e}")

        return self._handle_response(response, raw_response)

    async def close(self) -> None:
        """Close the async HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncVaulyticaClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()
