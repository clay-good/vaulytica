"""Multi-domain support for scanning multiple Google Workspace domains."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

import structlog

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.config.loader import Config

logger = structlog.get_logger(__name__)


@dataclass
class DomainConfig:
    """Configuration for a single domain."""

    domain: str
    credentials_file: Optional[str] = None
    oauth_credentials: Optional[str] = None
    impersonate_user: Optional[str] = None
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DomainScanResult:
    """Result from scanning a single domain."""

    domain: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    duration: float = 0.0


class MultiDomainManager:
    """Manages scanning across multiple Google Workspace domains."""

    def __init__(self, domains: List[DomainConfig]):
        """Initialize multi-domain manager.

        Args:
            domains: List of domain configurations
        """
        self.domains = [d for d in domains if d.enabled]
        self.clients: Dict[str, GoogleWorkspaceClient] = {}

        logger.info("multi_domain_manager_initialized", domain_count=len(self.domains))

    def get_client(self, domain_config: DomainConfig) -> GoogleWorkspaceClient:
        """Get or create client for a domain.

        Args:
            domain_config: Domain configuration

        Returns:
            GoogleWorkspaceClient instance
        """
        if domain_config.domain in self.clients:
            return self.clients[domain_config.domain]

        # Create config for this domain
        config = Config(
            google_workspace={
                "domain": domain_config.domain,
                "credentials_file": domain_config.credentials_file,
                "oauth_credentials": domain_config.oauth_credentials,
                "impersonate_user": domain_config.impersonate_user,
            }
        )

        client = GoogleWorkspaceClient.from_config(config)
        self.clients[domain_config.domain] = client

        logger.info("client_created_for_domain", domain=domain_config.domain)

        return client

    def scan_all_domains(
        self,
        scan_func: Callable[[GoogleWorkspaceClient, str], Any],
        parallel: bool = True,
        max_workers: int = 5,
    ) -> List[DomainScanResult]:
        """Scan all domains with a given function.

        Args:
            scan_func: Function to call for each domain (client, domain) -> result
            parallel: Whether to scan domains in parallel
            max_workers: Maximum number of parallel workers

        Returns:
            List of DomainScanResult
        """
        if parallel:
            return self._scan_parallel(scan_func, max_workers)
        else:
            return self._scan_sequential(scan_func)

    def _scan_sequential(
        self,
        scan_func: Callable[[GoogleWorkspaceClient, str], Any],
    ) -> List[DomainScanResult]:
        """Scan domains sequentially.

        Args:
            scan_func: Function to call for each domain

        Returns:
            List of DomainScanResult
        """
        results = []

        for domain_config in self.domains:
            result = self._scan_domain(domain_config, scan_func)
            results.append(result)

        return results

    def _scan_parallel(
        self,
        scan_func: Callable[[GoogleWorkspaceClient, str], Any],
        max_workers: int,
    ) -> List[DomainScanResult]:
        """Scan domains in parallel.

        Args:
            scan_func: Function to call for each domain
            max_workers: Maximum number of parallel workers

        Returns:
            List of DomainScanResult
        """
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_domain = {
                executor.submit(self._scan_domain, domain_config, scan_func): domain_config
                for domain_config in self.domains
            }

            # Collect results as they complete
            for future in as_completed(future_to_domain):
                domain_config = future_to_domain[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(
                        "domain_scan_failed",
                        domain=domain_config.domain,
                        error=str(e),
                    )
                    results.append(
                        DomainScanResult(
                            domain=domain_config.domain,
                            success=False,
                            error=str(e),
                        )
                    )

        return results

    def _scan_domain(
        self,
        domain_config: DomainConfig,
        scan_func: Callable[[GoogleWorkspaceClient, str], Any],
    ) -> DomainScanResult:
        """Scan a single domain.

        Args:
            domain_config: Domain configuration
            scan_func: Function to call

        Returns:
            DomainScanResult
        """
        import time

        start_time = time.time()

        logger.info("scanning_domain", domain=domain_config.domain)

        try:
            client = self.get_client(domain_config)
            result = scan_func(client, domain_config.domain)

            duration = time.time() - start_time

            logger.info(
                "domain_scan_complete",
                domain=domain_config.domain,
                duration=duration,
            )

            return DomainScanResult(
                domain=domain_config.domain,
                success=True,
                result=result,
                duration=duration,
            )

        except Exception as e:
            duration = time.time() - start_time

            logger.error(
                "domain_scan_failed",
                domain=domain_config.domain,
                error=str(e),
                duration=duration,
            )

            return DomainScanResult(
                domain=domain_config.domain,
                success=False,
                error=str(e),
                duration=duration,
            )

    def get_domains_by_tag(self, tag: str) -> List[DomainConfig]:
        """Get domains with a specific tag.

        Args:
            tag: Tag to filter by

        Returns:
            List of matching domain configurations
        """
        return [d for d in self.domains if tag in d.tags]

    def get_domain_count(self) -> int:
        """Get number of enabled domains.

        Returns:
            Number of domains
        """
        return len(self.domains)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of multi-domain configuration.

        Returns:
            Summary dictionary
        """
        return {
            "total_domains": len(self.domains),
            "domains": [
                {
                    "domain": d.domain,
                    "enabled": d.enabled,
                    "tags": d.tags,
                }
                for d in self.domains
            ],
        }


def create_multi_domain_manager_from_config(config: Config) -> MultiDomainManager:
    """Create multi-domain manager from configuration.

    Args:
        config: Configuration object

    Returns:
        MultiDomainManager instance
    """
    # Check if multi-domain is configured
    if "domains" in config.data:
        # Multi-domain configuration
        domain_configs = []

        for domain_data in config.data["domains"]:
            domain_config = DomainConfig(
                domain=domain_data["domain"],
                credentials_file=domain_data.get("credentials_file"),
                oauth_credentials=domain_data.get("oauth_credentials"),
                impersonate_user=domain_data.get("impersonate_user"),
                enabled=domain_data.get("enabled", True),
                tags=domain_data.get("tags", []),
                metadata=domain_data.get("metadata", {}),
            )
            domain_configs.append(domain_config)

        return MultiDomainManager(domain_configs)

    else:
        # Single domain configuration - convert to multi-domain
        gws_config = config.data.get("google_workspace", {})

        domain_config = DomainConfig(
            domain=gws_config.get("domain", ""),
            credentials_file=gws_config.get("credentials_file"),
            oauth_credentials=gws_config.get("oauth_credentials"),
            impersonate_user=gws_config.get("impersonate_user"),
            enabled=True,
        )

        return MultiDomainManager([domain_config])

