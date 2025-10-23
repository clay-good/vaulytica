"""
WHOIS Integration Module

Provides domain registration information, registrar details,
and domain age analysis for threat intelligence.
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import httpx

from vaulytica.logger import get_logger

logger = get_logger(__name__)


@dataclass
class WHOISResult:
    """WHOIS lookup result."""
    domain: str
    registrar: Optional[str] = None
    registration_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    age_days: Optional[int] = None
    is_recently_registered: bool = False
    registrant_name: Optional[str] = None
    registrant_organization: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    risk_indicators: List[str] = field(default_factory=list)
    raw_whois: Optional[str] = None


class WHOISIntegration:
    """
    WHOIS lookup integration for domain analysis.

    Features:
    - Domain registration date lookup
    - Registrar information
    - Registrant details (if not privacy-protected)
    - Domain age calculation
    - Recently registered domain detection
    - Risk indicator identification
    """

    def __init__(
        self,
        timeout: int = 10,
        recently_registered_threshold_days: int = 30,
        use_rdap: bool = True
    ):
        """
        Initialize WHOIS integration.

        Args:
            timeout: HTTP request timeout in seconds
            recently_registered_threshold_days: Days threshold for "recently registered"
            use_rdap: Use RDAP API (more reliable than traditional WHOIS)
        """
        self.timeout = timeout
        self.recently_registered_threshold_days = recently_registered_threshold_days
        self.use_rdap = use_rdap

        # Statistics
        self.stats = {
            "lookups_performed": 0,
            "lookups_successful": 0,
            "lookups_failed": 0,
            "recently_registered_detected": 0,
            "cache_hits": 0
        }

        # Cache
        self.cache: Dict[str, WHOISResult] = {}

        logger.info(f"WHOIS integration initialized (RDAP: {use_rdap})")

    async def lookup(
        self,
        domain: str,
        use_cache: bool = True
    ) -> Optional[WHOISResult]:
        """
        Perform WHOIS lookup for a domain.

        Args:
            domain: Domain name to lookup
            use_cache: Use cached results if available

        Returns:
            WHOISResult or None if lookup failed
        """
        # Normalize domain
        domain = domain.lower().strip()
        if domain.startswith("http://") or domain.startswith("https://"):
            domain = domain.split("://")[1].split("/")[0]

        # Check cache
        if use_cache and domain in self.cache:
            self.stats["cache_hits"] += 1
            logger.debug(f"WHOIS cache hit for {domain}")
            return self.cache[domain]

        self.stats["lookups_performed"] += 1

        try:
            if self.use_rdap:
                result = await self._rdap_lookup(domain)
            else:
                result = await self._whois_lookup(domain)

            if result:
                # Calculate age
                if result.registration_date:
                    age = datetime.utcnow() - result.registration_date
                    result.age_days = age.days
                    result.is_recently_registered = (
                        age.days <= self.recently_registered_threshold_days
                    )

                    if result.is_recently_registered:
                        self.stats["recently_registered_detected"] += 1

                # Identify risk indicators
                result.risk_indicators = self._identify_risk_indicators(result)

                # Cache result
                self.cache[domain] = result
                self.stats["lookups_successful"] += 1

                logger.info(f"WHOIS lookup successful for {domain} (age: {result.age_days} days)")
            else:
                self.stats["lookups_failed"] += 1

            return result

        except Exception as e:
            logger.error(f"WHOIS lookup error for {domain}: {e}")
            self.stats["lookups_failed"] += 1
            return None

    async def _rdap_lookup(self, domain: str) -> Optional[WHOISResult]:
        """Perform RDAP lookup (more reliable than traditional WHOIS)."""
        try:
            # Use RDAP bootstrap service
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"https://example.com"
                )

                if response.status_code == 200:
                    data = response.json()
                    return self._parse_rdap_response(domain, data)
                else:
                    logger.warning(f"RDAP lookup failed for {domain}: {response.status_code}")
                    return None

        except Exception as e:
            logger.error(f"RDAP lookup error for {domain}: {e}")
            return None

    def _parse_rdap_response(self, domain: str, data: Dict[str, Any]) -> WHOISResult:
        """Parse RDAP response."""
        result = WHOISResult(domain=domain)

        # Extract events
        events = data.get("events", [])
        for event in events:
            event_action = event.get("eventAction", "")
            event_date_str = event.get("eventDate", "")

            if event_date_str:
                try:
                    event_date = datetime.fromisoformat(event_date_str.replace("Z", "+00:00"))

                    if event_action == "registration":
                        result.registration_date = event_date
                    elif event_action == "expiration":
                        result.expiration_date = event_date
                    elif event_action == "last changed":
                        result.updated_date = event_date
                except Exception as e:
                    logger.debug(f"Error parsing date {event_date_str}: {e}")

        # Extract entities (registrar, registrant)
        entities = data.get("entities", [])
        for entity in entities:
            roles = entity.get("roles", [])

            if "registrar" in roles:
                vcards = entity.get("vcardArray", [[]])
                if len(vcards) > 1:
                    for vcard in vcards[1]:
                        if isinstance(vcard, list) and len(vcard) > 3:
                            if vcard[0] == "fn":
                                result.registrar = vcard[3]

            if "registrant" in roles:
                vcards = entity.get("vcardArray", [[]])
                if len(vcards) > 1:
                    for vcard in vcards[1]:
                        if isinstance(vcard, list) and len(vcard) > 3:
                            if vcard[0] == "fn":
                                result.registrant_name = vcard[3]
                            elif vcard[0] == "org":
                                result.registrant_organization = vcard[3]
                            elif vcard[0] == "email":
                                result.registrant_email = vcard[3]

        # Extract name servers
        nameservers = data.get("nameservers", [])
        for ns in nameservers:
            ns_name = ns.get("ldhName")
            if ns_name:
                result.name_servers.append(ns_name)

        # Extract status
        status = data.get("status", [])
        result.status = status

        return result

    async def _whois_lookup(self, domain: str) -> Optional[WHOISResult]:
        """Perform traditional WHOIS lookup (fallback)."""
        try:
            # Use whois.com API or similar service
            # For now, return None and rely on RDAP
            logger.warning(f"Traditional WHOIS not implemented, use RDAP for {domain}")
            return None

        except Exception as e:
            logger.error(f"WHOIS lookup error for {domain}: {e}")
            return None

    def _identify_risk_indicators(self, result: WHOISResult) -> List[str]:
        """Identify risk indicators from WHOIS data."""
        indicators = []

        # Recently registered
        if result.is_recently_registered:
            indicators.append(
                f"Recently registered ({result.age_days} days old, threshold: {self.recently_registered_threshold_days} days)"
            )

        # Privacy protection
        if result.registrant_name and any(
            keyword in result.registrant_name.lower()
            for keyword in ["privacy", "protect", "redacted", "whoisguard", "proxy"]
        ):
            indicators.append("Privacy protection enabled")

        if result.registrant_email and any(
            keyword in result.registrant_email.lower()
            for keyword in ["privacy", "protect", "abuse", "whoisguard"]
        ):
            indicators.append("Privacy-protected email")

        # Short expiration
        if result.expiration_date:
            days_until_expiration = (result.expiration_date - datetime.utcnow()).days
            if days_until_expiration < 90:
                indicators.append(f"Short expiration period ({days_until_expiration} days)")

        # Suspicious registrar
        if result.registrar:
            suspicious_registrars = [
                "namecheap",  # Often used for malicious domains
                "godaddy",    # High volume, mixed reputation
                "tucows"      # Often used for malicious domains
            ]
            if any(sr in result.registrar.lower() for sr in suspicious_registrars):
                indicators.append(f"Registrar associated with malicious activity: {result.registrar}")

        # Suspicious name servers
        if result.name_servers:
            for ns in result.name_servers:
                if any(
                    keyword in ns.lower()
                    for keyword in ["cloudflare", "parking", "suspended"]
                ):
                    indicators.append(f"Suspicious name server: {ns}")

        # Status indicators
        if result.status:
            suspicious_statuses = ["clientHold", "serverHold", "pendingDelete"]
            for status in result.status:
                if any(ss in status for ss in suspicious_statuses):
                    indicators.append(f"Suspicious status: {status}")

        return indicators

    def get_stats(self) -> Dict[str, int]:
        """Get integration statistics."""
        return self.stats.copy()


# Global instance
_whois_integration: Optional[WHOISIntegration] = None


def get_whois_integration(
    timeout: int = 10,
    recently_registered_threshold_days: int = 30
) -> WHOISIntegration:
    """Get or create global WHOIS integration instance."""
    global _whois_integration

    if _whois_integration is None:
        _whois_integration = WHOISIntegration(
            timeout=timeout,
            recently_registered_threshold_days=recently_registered_threshold_days
        )

    return _whois_integration

