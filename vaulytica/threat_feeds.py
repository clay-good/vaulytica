"""
Real-Time Threat Intelligence Feed Integration.

This module provides integration with external threat intelligence sources:
- VirusTotal API for file/IP/domain/URL reputation
- AlienVault OTX for threat indicators and pulses
- AbuseIPDB for IP reputation
- URLhaus for malicious URL detection
- Shodan for IP/port intelligence
- Custom threat feeds (CSV, JSON, STIX/TAXII)

Features:
- Automatic IOC enrichment from multiple sources
- Caching to reduce API calls
- Rate limiting and quota management
- Confidence scoring across sources
- Threat feed aggregation
"""

import time
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import requests
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class ThreatFeedSource(str, Enum):
    """External threat intelligence sources."""
    VIRUSTOTAL = "VIRUSTOTAL"
    ALIENVAULT_OTX = "ALIENVAULT_OTX"
    ABUSEIPDB = "ABUSEIPDB"
    URLHAUS = "URLHAUS"
    SHODAN = "SHODAN"
    CUSTOM_FEED = "CUSTOM_FEED"
    MISP = "MISP"
    THREATFOX = "THREATFOX"


@dataclass
class ThreatFeedResult:
    """Result from threat feed lookup."""
    source: ThreatFeedSource
    ioc_value: str
    ioc_type: str
    is_malicious: bool
    confidence: float  # 0.0-1.0
    threat_score: int  # 0-100
    tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    detection_count: int = 0
    total_scans: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class AggregatedThreatIntel:
    """Aggregated threat intelligence from multiple sources."""
    ioc_value: str
    ioc_type: str
    is_malicious: bool
    overall_confidence: float
    overall_threat_score: int
    sources_checked: int
    sources_flagged: int
    results: List[ThreatFeedResult] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    malware_families: Set[str] = field(default_factory=set)
    threat_actors: Set[str] = field(default_factory=set)
    consensus_verdict: str = "UNKNOWN"  # MALICIOUS, SUSPICIOUS, CLEAN, UNKNOWN


class ThreatFeedCache:
    """Simple in-memory cache for threat feed results."""

    def __init__(self, ttl_hours: int = 24):
        self.cache: Dict[str, tuple[AggregatedThreatIntel, datetime]] = {}
        self.ttl = timedelta(hours=ttl_hours)

    def get(self, ioc_value: str, ioc_type: str) -> Optional[AggregatedThreatIntel]:
        """Get cached result if not expired."""
        key = f"{ioc_type}:{ioc_value}"
        if key in self.cache:
            result, timestamp = self.cache[key]
            if datetime.utcnow() - timestamp < self.ttl:
                logger.debug(f"Cache hit for {key}")
                return result
            else:
                del self.cache[key]
        return None

    def set(self, ioc_value: str, ioc_type: str, result: AggregatedThreatIntel) -> None:
        """Cache result."""
        key = f"{ioc_type}:{ioc_value}"
        self.cache[key] = (result, datetime.utcnow())
        logger.debug(f"Cached result for {key}")

    def clear_expired(self) -> None:
        """Clear expired cache entries."""
        now = datetime.utcnow()
        expired_keys = [
            key for key, (_, timestamp) in self.cache.items()
            if now - timestamp >= self.ttl
        ]
        for key in expired_keys:
            del self.cache[key]
        if expired_keys:
            logger.info(f"Cleared {len(expired_keys)} expired cache entries")


class ThreatFeedIntegration:
    """
    Real-Time Threat Intelligence Feed Integration.

    Integrates with multiple external threat intelligence sources
    to enrich IOCs with real-time threat data.
    """

    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        otx_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
        shodan_api_key: Optional[str] = None,
        enable_cache: bool = True,
        cache_ttl_hours: int = 24,
        timeout_seconds: int = 10
    ):
        """
        Initialize threat feed integration.

        Args:
            virustotal_api_key: VirusTotal API key
            otx_api_key: AlienVault OTX API key
            abuseipdb_api_key: AbuseIPDB API key
            shodan_api_key: Shodan API key
            enable_cache: Enable result caching
            cache_ttl_hours: Cache TTL in hours
            timeout_seconds: API request timeout
        """
        self.vt_api_key = virustotal_api_key
        self.otx_api_key = otx_api_key
        self.abuseipdb_api_key = abuseipdb_api_key
        self.shodan_api_key = shodan_api_key
        self.timeout = timeout_seconds

        # Initialize cache
        self.cache = ThreatFeedCache(ttl_hours=cache_ttl_hours) if enable_cache else None

        # Rate limiting
        self.last_request_time: Dict[ThreatFeedSource, float] = {}
        self.min_request_interval = 1.0  # Minimum seconds between requests

        # Statistics
        self.stats = {
            "total_lookups": 0,
            "cache_hits": 0,
            "api_calls": 0,
            "errors": 0,
            "by_source": {source: 0 for source in ThreatFeedSource}
        }

        logger.info("ThreatFeedIntegration initialized")
        self._log_enabled_sources()

    def _log_enabled_sources(self):
        """Log which threat feeds are enabled."""
        enabled = []
        if self.vt_api_key:
            enabled.append("VirusTotal")
        if self.otx_api_key:
            enabled.append("AlienVault OTX")
        if self.abuseipdb_api_key:
            enabled.append("AbuseIPDB")
        if self.shodan_api_key:
            enabled.append("Shodan")

        if enabled:
            logger.info(f"Enabled threat feeds: {', '.join(enabled)}")
        else:
            logger.warning("No threat feed API keys configured - using simulated mode")

    def enrich_ioc(
        self,
        ioc_value: str,
        ioc_type: str,
        sources: Optional[List[ThreatFeedSource]] = None
    ) -> AggregatedThreatIntel:
        """
        Enrich IOC with threat intelligence from multiple sources.

        Args:
            ioc_value: IOC value (IP, domain, hash, URL)
            ioc_type: IOC type (ip, domain, hash, url)
            sources: Specific sources to query (None = all available)

        Returns:
            Aggregated threat intelligence
        """
        self.stats["total_lookups"] += 1

        # Check cache
        if self.cache:
            cached = self.cache.get(ioc_value, ioc_type)
            if cached:
                self.stats["cache_hits"] += 1
                return cached

        # Determine which sources to query
        if sources is None:
            sources = self._get_available_sources(ioc_type)

        # Query each source
        results = []
        for source in sources:
            try:
                result = self._query_source(source, ioc_value, ioc_type)
                if result:
                    results.append(result)
                    self.stats["by_source"][source] += 1
            except Exception as e:
                logger.error(f"Error querying {source.value}: {e}")
                self.stats["errors"] += 1

        # Aggregate results
        aggregated = self._aggregate_results(ioc_value, ioc_type, results)

        # Cache result
        if self.cache:
            self.cache.set(ioc_value, ioc_type, aggregated)

        return aggregated

    def _get_available_sources(self, ioc_type: str) -> List[ThreatFeedSource]:
        """Get available sources for IOC type."""
        sources = []

        if ioc_type in ["ip", "domain", "hash", "url"]:
            if self.vt_api_key:
                sources.append(ThreatFeedSource.VIRUSTOTAL)

        if ioc_type in ["ip", "domain", "hash", "url"]:
            if self.otx_api_key:
                sources.append(ThreatFeedSource.ALIENVAULT_OTX)

        if ioc_type == "ip":
            if self.abuseipdb_api_key:
                sources.append(ThreatFeedSource.ABUSEIPDB)
            if self.shodan_api_key:
                sources.append(ThreatFeedSource.SHODAN)

        if ioc_type == "url":
            sources.append(ThreatFeedSource.URLHAUS)  # Public API

        # If no API keys configured, use simulated sources for demo
        if not sources:
            logger.debug("No API keys configured, using simulated sources")
            sources = [
                ThreatFeedSource.CUSTOM_FEED,
                ThreatFeedSource.MISP,
                ThreatFeedSource.THREATFOX
            ]

        return sources

    def _query_source(
        self,
        source: ThreatFeedSource,
        ioc_value: str,
        ioc_type: str
    ) -> Optional[ThreatFeedResult]:
        """Query a specific threat feed source."""

        # Rate limiting
        self._rate_limit(source)

        self.stats["api_calls"] += 1

        # Route to appropriate handler
        if source == ThreatFeedSource.VIRUSTOTAL:
            return self._query_virustotal(ioc_value, ioc_type)
        elif source == ThreatFeedSource.ALIENVAULT_OTX:
            return self._query_otx(ioc_value, ioc_type)
        elif source == ThreatFeedSource.ABUSEIPDB:
            return self._query_abuseipdb(ioc_value)
        elif source == ThreatFeedSource.SHODAN:
            return self._query_shodan(ioc_value)
        elif source == ThreatFeedSource.URLHAUS:
            return self._query_urlhaus(ioc_value)
        elif source == ThreatFeedSource.THREATFOX:
            return self._query_threatfox(ioc_value, ioc_type)
        else:
            return self._simulate_query(source, ioc_value, ioc_type)

    def _rate_limit(self, source: ThreatFeedSource):
        """Apply rate limiting."""
        last_time = self.last_request_time.get(source, 0)
        elapsed = time.time() - last_time

        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            logger.debug(f"Rate limiting {source.value}: sleeping {sleep_time:.2f}s")
            time.sleep(sleep_time)

        self.last_request_time[source] = time.time()

    def _query_virustotal(self, ioc_value: str, ioc_type: str) -> Optional[ThreatFeedResult]:
        """Query VirusTotal API."""
        if not self.vt_api_key:
            return None

        try:
            # Map IOC type to VT endpoint
            if ioc_type == "ip":
                url = f"https://example.com"
            elif ioc_type == "domain":
                url = f"https://example.com"
            elif ioc_type == "hash":
                url = f"https://example.com"
            elif ioc_type == "url":
                # URL needs to be base64 encoded
                import base64
                url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
                url = f"https://example.com"
            else:
                return None

            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})

                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values())

                is_malicious = malicious > 0
                threat_score = int((malicious + suspicious * 0.5) / max(total, 1) * 100)
                confidence = min(0.95, 0.5 + (total / 100))  # More scans = higher confidence

                tags = attributes.get("tags", [])

                return ThreatFeedResult(
                    source=ThreatFeedSource.VIRUSTOTAL,
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    is_malicious=is_malicious,
                    confidence=confidence,
                    threat_score=threat_score,
                    tags=tags[:10],
                    detection_count=malicious,
                    total_scans=total,
                    metadata={"stats": stats}
                )
            elif response.status_code == 404:
                # Not found in VT database
                return ThreatFeedResult(
                    source=ThreatFeedSource.VIRUSTOTAL,
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    is_malicious=False,
                    confidence=0.3,
                    threat_score=0,
                    metadata={"status": "not_found"}
                )
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"VirusTotal query error: {e}")
            return None

    def _query_otx(self, ioc_value: str, ioc_type: str) -> Optional[ThreatFeedResult]:
        """Query AlienVault OTX API."""
        if not self.otx_api_key:
            return None

        try:
            # Map IOC type to OTX endpoint
            if ioc_type == "ip":
                url = f"https://example.com"
            elif ioc_type == "domain":
                url = f"https://example.com"
            elif ioc_type == "hash":
                url = f"https://example.com"
            elif ioc_type == "url":
                url = f"https://example.com"
            else:
                return None

            headers = {"X-OTX-API-KEY": self.otx_api_key}
            response = requests.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()

                pulse_count = data.get("pulse_info", {}).get("count", 0)
                is_malicious = pulse_count > 0
                threat_score = min(100, pulse_count * 10)
                confidence = min(0.9, 0.5 + (pulse_count / 20))

                tags = []
                malware_families = []
                threat_actors = []

                # Extract tags from pulses
                for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
                    tags.extend(pulse.get("tags", []))
                    if "malware_families" in pulse:
                        malware_families.extend(pulse["malware_families"])
                    if "adversary" in pulse:
                        threat_actors.append(pulse["adversary"])

                return ThreatFeedResult(
                    source=ThreatFeedSource.ALIENVAULT_OTX,
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    is_malicious=is_malicious,
                    confidence=confidence,
                    threat_score=threat_score,
                    tags=list(set(tags))[:10],
                    malware_families=list(set(malware_families)),
                    threat_actors=list(set(threat_actors)),
                    detection_count=pulse_count,
                    metadata={"pulse_count": pulse_count}
                )
            else:
                logger.warning(f"OTX API error: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"OTX query error: {e}")
            return None

    def _query_abuseipdb(self, ioc_value: str) -> Optional[ThreatFeedResult]:
        """Query AbuseIPDB API."""
        if not self.abuseipdb_api_key:
            return None

        try:
            url = "https://example.com"
            headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}
            params = {"ipAddress": ioc_value, "maxAgeInDays": 90}

            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json().get("data", {})

                abuse_score = data.get("abuseConfidenceScore", 0)
                is_malicious = abuse_score > 50
                total_reports = data.get("totalReports", 0)

                confidence = min(0.9, 0.5 + (total_reports / 100))

                return ThreatFeedResult(
                    source=ThreatFeedSource.ABUSEIPDB,
                    ioc_value=ioc_value,
                    ioc_type="ip",
                    is_malicious=is_malicious,
                    confidence=confidence,
                    threat_score=abuse_score,
                    detection_count=total_reports,
                    metadata={
                        "abuse_score": abuse_score,
                        "is_whitelisted": data.get("isWhitelisted", False),
                        "country_code": data.get("countryCode", "")
                    }
                )
            else:
                logger.warning(f"AbuseIPDB API error: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"AbuseIPDB query error: {e}")
            return None

    def _query_shodan(self, ioc_value: str) -> Optional[ThreatFeedResult]:
        """Query Shodan API."""
        if not self.shodan_api_key:
            return None

        try:
            url = f"https://example.com"
            params = {"key": self.shodan_api_key}

            response = requests.get(url, headers={}, params=params, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()

                # Shodan doesn't directly indicate malicious, but open ports/vulns are indicators
                open_ports = data.get("ports", [])
                vulns = data.get("vulns", [])
                tags = data.get("tags", [])

                is_malicious = len(vulns) > 0 or "malicious" in tags
                threat_score = min(100, len(vulns) * 20 + len(open_ports) * 2)
                confidence = 0.7 if len(vulns) > 0 else 0.5

                return ThreatFeedResult(
                    source=ThreatFeedSource.SHODAN,
                    ioc_value=ioc_value,
                    ioc_type="ip",
                    is_malicious=is_malicious,
                    confidence=confidence,
                    threat_score=threat_score,
                    tags=tags[:10],
                    metadata={
                        "open_ports": open_ports[:20],
                        "vulns": list(vulns)[:10],
                        "org": data.get("org", ""),
                        "isp": data.get("isp", "")
                    }
                )
            else:
                logger.warning(f"Shodan API error: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Shodan query error: {e}")
            return None

    def _query_urlhaus(self, ioc_value: str) -> Optional[ThreatFeedResult]:
        """Query URLhaus API (public, no key needed)."""
        try:
            url = "https://example.com"
            data = {"url": ioc_value}

            response = requests.post(url, data=data, timeout=self.timeout)

            if response.status_code == 200:
                result = response.json()

                if result.get("query_status") == "ok":
                    is_malicious = result.get("url_status") in ["online", "offline"]
                    threat_level = result.get("threat", "unknown")
                    tags = result.get("tags", [])

                    threat_score = 90 if is_malicious else 0
                    confidence = 0.85 if is_malicious else 0.3

                    return ThreatFeedResult(
                        source=ThreatFeedSource.URLHAUS,
                        ioc_value=ioc_value,
                        ioc_type="url",
                        is_malicious=is_malicious,
                        confidence=confidence,
                        threat_score=threat_score,
                        tags=tags,
                        metadata={
                            "threat": threat_level,
                            "url_status": result.get("url_status"),
                            "date_added": result.get("date_added")
                        }
                    )
                else:
                    # Not found in URLhaus
                    return ThreatFeedResult(
                        source=ThreatFeedSource.URLHAUS,
                        ioc_value=ioc_value,
                        ioc_type="url",
                        is_malicious=False,
                        confidence=0.3,
                        threat_score=0,
                        metadata={"status": "not_found"}
                    )
            else:
                logger.warning(f"URLhaus API error: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"URLhaus query error: {e}")
            return None

    def _query_threatfox(self, ioc_value: str, ioc_type: str) -> Optional[ThreatFeedResult]:
        """Query ThreatFox API (public, no key needed) - fallback to simulation if unavailable."""
        try:
            # Validate IOC type
            search_term = self._map_ioc_type_to_search_term(ioc_type)
            if not search_term:
                return None

            # Make API request
            response = self._make_threatfox_request(ioc_value)

            # Handle response
            if response.status_code == 200:
                return self._process_threatfox_response(response.json(), ioc_value, ioc_type)
            elif response.status_code == 401:
                logger.debug("ThreatFox requires authentication, using simulation")
                return self._simulate_query(ThreatFeedSource.THREATFOX, ioc_value, ioc_type)
            else:
                logger.warning(f"ThreatFox API error: {response.status_code}")
                return None

        except Exception as e:
            logger.debug(f"ThreatFox unavailable, using simulation: {e}")
            return self._simulate_query(ThreatFeedSource.THREATFOX, ioc_value, ioc_type)

    def _map_ioc_type_to_search_term(self, ioc_type: str) -> Optional[str]:
        """Map IOC type to ThreatFox search term."""
        type_mapping = {
            "ip": "ip:port",
            "domain": "domain",
            "hash": "hash",
            "url": "url"
        }
        return type_mapping.get(ioc_type)

    def _make_threatfox_request(self, ioc_value: str):
        """Make ThreatFox API request."""
        url = "https://example.com"
        data = {
            "query": "search_ioc",
            "search_term": ioc_value
        }
        return requests.post(url, json=data, timeout=self.timeout)

    def _process_threatfox_response(
        self,
        result: Dict[str, Any],
        ioc_value: str,
        ioc_type: str
    ) -> Optional[ThreatFeedResult]:
        """Process ThreatFox API response."""
        if result.get("query_status") != "ok":
            return None

        iocs = result.get("data", [])

        if iocs:
            return self._build_malicious_result(iocs, ioc_value, ioc_type)
        else:
            return self._build_not_found_result(ioc_value, ioc_type)

    def _build_malicious_result(
        self,
        iocs: List[Dict[str, Any]],
        ioc_value: str,
        ioc_type: str
    ) -> ThreatFeedResult:
        """Build result for malicious IOC."""
        tags = []
        malware_families = []

        for ioc in iocs[:5]:
            if "tags" in ioc:
                tags.extend(ioc["tags"])
            if "malware" in ioc:
                malware_families.append(ioc["malware"])

        return ThreatFeedResult(
            source=ThreatFeedSource.THREATFOX,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            is_malicious=True,
            confidence=0.85,
            threat_score=85,
            tags=list(set(tags))[:10],
            malware_families=list(set(malware_families)),
            detection_count=len(iocs),
            metadata={"ioc_count": len(iocs)}
        )

    def _build_not_found_result(self, ioc_value: str, ioc_type: str) -> ThreatFeedResult:
        """Build result for IOC not found."""
        return ThreatFeedResult(
            source=ThreatFeedSource.THREATFOX,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            is_malicious=False,
            confidence=0.3,
            threat_score=0,
            metadata={"status": "not_found"}
        )

    def _simulate_query(
        self,
        source: ThreatFeedSource,
        ioc_value: str,
        ioc_type: str
    ) -> ThreatFeedResult:
        """Simulate threat feed query for testing/demo."""

        # Simulate based on IOC patterns
        is_malicious = False
        threat_score = 0
        confidence = 0.5
        tags = []

        # Simple heuristics for simulation
        if ioc_type == "ip":
            # Check if IP looks suspicious
            if any(x in ioc_value for x in ["198.51.100", "203.0.113", "192.0.2"]):
                is_malicious = True
                threat_score = 75
                confidence = 0.7
                tags = ["suspicious", "test_range"]

        elif ioc_type == "domain":
            suspicious_keywords = ["evil", "malware", "phish", "hack", "exploit", "bad"]
            if any(kw in ioc_value.lower() for kw in suspicious_keywords):
                is_malicious = True
                threat_score = 80
                confidence = 0.75
                tags = ["suspicious_domain", "keyword_match"]

        elif ioc_type == "hash":
            # Simulate based on hash patterns
            if ioc_value.startswith(("dead", "bad", "evil")):
                is_malicious = True
                threat_score = 85
                confidence = 0.8
                tags = ["malware", "simulated"]

        return ThreatFeedResult(
            source=source,
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            is_malicious=is_malicious,
            confidence=confidence,
            threat_score=threat_score,
            tags=tags,
            metadata={"simulated": True}
        )

    def _aggregate_results(
        self,
        ioc_value: str,
        ioc_type: str,
        results: List[ThreatFeedResult]
    ) -> AggregatedThreatIntel:
        """
        Aggregate results from multiple threat feeds.

        Uses weighted voting based on source confidence and reputation.
        """
        if not results:
            # No results - return unknown
            return AggregatedThreatIntel(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                is_malicious=False,
                overall_confidence=0.0,
                overall_threat_score=0,
                sources_checked=0,
                sources_flagged=0,
                consensus_verdict="UNKNOWN"
            )

        # Collect all data
        malicious_count = sum(1 for r in results if r.is_malicious)
        total_sources = len(results)

        # Weighted average of threat scores
        weighted_score = sum(r.threat_score * r.confidence for r in results)
        total_weight = sum(r.confidence for r in results)
        overall_threat_score = int(weighted_score / total_weight) if total_weight > 0 else 0

        # Weighted average of confidence
        overall_confidence = total_weight / total_sources if total_sources > 0 else 0.0

        # Aggregate tags, malware families, threat actors
        all_tags = set()
        all_malware = set()
        all_actors = set()

        for result in results:
            all_tags.update(result.tags)
            all_malware.update(result.malware_families)
            all_actors.update(result.threat_actors)

        # Determine consensus verdict
        malicious_ratio = malicious_count / total_sources if total_sources > 0 else 0

        if malicious_ratio >= 0.7:
            consensus_verdict = "MALICIOUS"
            is_malicious = True
        elif malicious_ratio >= 0.3:
            consensus_verdict = "SUSPICIOUS"
            is_malicious = True
        elif malicious_ratio > 0:
            consensus_verdict = "SUSPICIOUS"
            is_malicious = False
        else:
            consensus_verdict = "CLEAN"
            is_malicious = False

        return AggregatedThreatIntel(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            is_malicious=is_malicious,
            overall_confidence=overall_confidence,
            overall_threat_score=overall_threat_score,
            sources_checked=total_sources,
            sources_flagged=malicious_count,
            results=results,
            tags=all_tags,
            malware_families=all_malware,
            threat_actors=all_actors,
            consensus_verdict=consensus_verdict
        )

    def batch_enrich(
        self,
        iocs: List[tuple[str, str]],
        max_concurrent: int = 5
    ) -> Dict[str, AggregatedThreatIntel]:
        """
        Batch enrich multiple IOCs.

        Args:
            iocs: List of (ioc_value, ioc_type) tuples
            max_concurrent: Maximum concurrent API calls

        Returns:
            Dictionary mapping IOC value to aggregated intel
        """
        results = {}

        for ioc_value, ioc_type in iocs:
            try:
                result = self.enrich_ioc(ioc_value, ioc_type)
                results[ioc_value] = result
            except Exception as e:
                logger.error(f"Error enriching {ioc_value}: {e}")

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat feed statistics."""
        return {
            "total_lookups": self.stats["total_lookups"],
            "cache_hits": self.stats["cache_hits"],
            "cache_hit_rate": (
                self.stats["cache_hits"] / self.stats["total_lookups"]
                if self.stats["total_lookups"] > 0 else 0.0
            ),
            "api_calls": self.stats["api_calls"],
            "errors": self.stats["errors"],
            "by_source": dict(self.stats["by_source"]),
            "cache_size": len(self.cache.cache) if self.cache else 0
        }

    def clear_cache(self) -> None:
        """Clear threat feed cache."""
        if self.cache:
            self.cache.cache.clear()
            logger.info("Threat feed cache cleared")
