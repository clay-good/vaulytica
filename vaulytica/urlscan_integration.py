"""
URLScan.io Integration Module

Provides screenshot capture, DOM analysis, and phishing detection
for suspicious URLs and domains.
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import httpx

from vaulytica.logger import get_logger

logger = get_logger(__name__)


class URLScanVerdict(str, Enum):
    """URLScan.io verdict types."""
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


@dataclass
class URLScanResult:
    """URLScan.io scan result."""
    url: str
    scan_id: str
    screenshot_url: Optional[str] = None
    verdict: URLScanVerdict = URLScanVerdict.UNKNOWN
    brands_detected: List[str] = field(default_factory=list)
    is_phishing: bool = False
    technologies: List[str] = field(default_factory=list)
    redirects: List[str] = field(default_factory=list)
    http_transactions: int = 0
    resources_loaded: int = 0
    malicious_indicators: List[str] = field(default_factory=list)
    ip_address: Optional[str] = None
    asn: Optional[str] = None
    country: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    page_title: Optional[str] = None
    meta_description: Optional[str] = None
    scan_time: Optional[datetime] = None
    raw_result: Dict[str, Any] = field(default_factory=dict)


class URLScanIntegration:
    """
    URLScan.io API integration for URL analysis and screenshot capture.

    Features:
    - Submit URLs for scanning
    - Retrieve scan results with screenshots
    - Phishing detection
    - Brand impersonation detection
    - Technology stack identification
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: int = 60,
        max_wait_seconds: int = 60,
        visibility: str = "public"
    ):
        """
        Initialize URLScan.io integration.

        Args:
            api_key: URLScan.io API key (optional for public scans)
            timeout: HTTP request timeout in seconds
            max_wait_seconds: Maximum time to wait for scan completion
            visibility: Scan visibility (public, unlisted, private)
        """
        self.api_key = api_key
        self.timeout = timeout
        self.max_wait_seconds = max_wait_seconds
        self.visibility = visibility
        self.base_url = "https://example.com"

        # Statistics
        self.stats = {
            "scans_submitted": 0,
            "scans_completed": 0,
            "scans_failed": 0,
            "phishing_detected": 0,
            "cache_hits": 0
        }

        # Cache
        self.cache: Dict[str, URLScanResult] = {}

        logger.info(f"URLScan.io integration initialized (visibility: {visibility})")

    async def scan_url(
        self,
        url: str,
        use_cache: bool = True
    ) -> Optional[URLScanResult]:
        """
        Scan a URL with URLScan.io.

        Args:
            url: URL to scan
            use_cache: Use cached results if available

        Returns:
            URLScanResult or None if scan failed
        """
        # Check cache
        if use_cache and url in self.cache:
            self.stats["cache_hits"] += 1
            logger.debug(f"URLScan cache hit for {url}")
            return self.cache[url]

        try:
            # Submit scan
            scan_id = await self._submit_scan(url)
            if not scan_id:
                return None

            # Wait for scan to complete
            result = await self._wait_for_result(scan_id, url)

            if result:
                self.cache[url] = result
                self.stats["scans_completed"] += 1

                if result.is_phishing:
                    self.stats["phishing_detected"] += 1

                logger.info(f"URLScan completed for {url}: {result.verdict}")
            else:
                self.stats["scans_failed"] += 1

            return result

        except Exception as e:
            logger.error(f"URLScan error for {url}: {e}")
            self.stats["scans_failed"] += 1
            return None

    async def _submit_scan(self, url: str) -> Optional[str]:
        """Submit URL for scanning."""
        try:
            headers = {}
            if self.api_key:
                headers["API-Key"] = self.api_key

            data = {
                "url": url,
                "visibility": self.visibility
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/scan/",
                    headers=headers,
                    json=data
                )

                if response.status_code == 200:
                    result = response.json()
                    scan_id = result.get("uuid")
                    self.stats["scans_submitted"] += 1
                    logger.debug(f"URLScan submitted: {scan_id}")
                    return scan_id
                elif response.status_code == 429:
                    logger.warning("URLScan rate limit exceeded")
                    return None
                else:
                    logger.warning(f"URLScan submission failed: {response.status_code}")
                    return None

        except Exception as e:
            logger.error(f"URLScan submission error: {e}")
            return None

    async def _wait_for_result(
        self,
        scan_id: str,
        url: str
    ) -> Optional[URLScanResult]:
        """Wait for scan to complete and retrieve results."""
        start_time = time.time()

        while time.time() - start_time < self.max_wait_seconds:
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(
                        f"{self.base_url}/result/{scan_id}/"
                    )

                    if response.status_code == 200:
                        data = response.json()
                        return self._parse_result(url, scan_id, data)
                    elif response.status_code == 404:
                        # Scan not ready yet, wait and retry
                        await asyncio.sleep(2)
                        continue
                    else:
                        logger.warning(f"URLScan result error: {response.status_code}")
                        return None

            except Exception as e:
                logger.error(f"URLScan result retrieval error: {e}")
                return None

        logger.warning(f"URLScan timeout for {url} after {self.max_wait_seconds}s")
        return None

    def _parse_result(
        self,
        url: str,
        scan_id: str,
        data: Dict[str, Any]
    ) -> URLScanResult:
        """Parse URLScan.io result."""
        page = data.get("page", {})
        lists = data.get("lists", {})
        verdicts = data.get("verdicts", {})
        meta = data.get("meta", {})
        task = data.get("task", {})

        # Extract verdict
        overall_verdict = verdicts.get("overall", {})
        verdict_score = overall_verdict.get("score", 0)
        verdict_malicious = overall_verdict.get("malicious", False)

        if verdict_malicious or verdict_score >= 50:
            verdict = URLScanVerdict.MALICIOUS
        elif verdict_score >= 20:
            verdict = URLScanVerdict.SUSPICIOUS
        elif verdict_score == 0:
            verdict = URLScanVerdict.CLEAN
        else:
            verdict = URLScanVerdict.UNKNOWN

        # Extract brands
        brands = verdicts.get("brands", {}).get("brands", [])
        brand_names = [b.get("name") for b in brands if b.get("name")]

        # Phishing detection
        is_phishing = (
            verdict == URLScanVerdict.MALICIOUS and
            len(brand_names) > 0 and
            "phishing" in str(verdicts).lower()
        )

        # Extract technologies
        technologies = []
        for tech in meta.get("processors", {}).get("wappa", {}).get("data", []):
            if isinstance(tech, dict) and "app" in tech:
                technologies.append(tech["app"])

        # Extract redirects
        redirects = []
        for request in data.get("data", {}).get("requests", []):
            if request.get("response", {}).get("response", {}).get("redirectResponse"):
                redirects.append(request.get("request", {}).get("request", {}).get("url", ""))

        # Extract malicious indicators
        malicious_indicators = []
        if verdict_malicious:
            malicious_indicators.append(f"Malicious verdict (score: {verdict_score})")
        if is_phishing:
            malicious_indicators.append(f"Phishing detected (brands: {', '.join(brand_names)})")
        if lists.get("ips"):
            malicious_indicators.append(f"Suspicious IPs detected: {len(lists['ips'])}")
        if lists.get("urls"):
            malicious_indicators.append(f"Suspicious URLs detected: {len(lists['urls'])}")

        # Screenshot URL
        screenshot_url = task.get("screenshotURL")

        return URLScanResult(
            url=url,
            scan_id=scan_id,
            screenshot_url=screenshot_url,
            verdict=verdict,
            brands_detected=brand_names,
            is_phishing=is_phishing,
            technologies=technologies,
            redirects=redirects[:10],  # Limit to first 10
            http_transactions=len(data.get("data", {}).get("requests", [])),
            resources_loaded=len(data.get("data", {}).get("requests", [])),
            malicious_indicators=malicious_indicators,
            ip_address=page.get("ip"),
            asn=page.get("asn"),
            country=page.get("country"),
            server=page.get("server"),
            content_type=page.get("mimeType"),
            status_code=task.get("reportURL"),  # Status code not directly available
            page_title=page.get("title"),
            meta_description=meta.get("description"),
            scan_time=datetime.utcnow(),
            raw_result=data
        )

    def get_stats(self) -> Dict[str, int]:
        """Get integration statistics."""
        return self.stats.copy()


# Global instance
_urlscan_integration: Optional[URLScanIntegration] = None


def get_urlscan_integration(
    api_key: Optional[str] = None,
    timeout: int = 60,
    max_wait_seconds: int = 60
) -> URLScanIntegration:
    """Get or create global URLScan.io integration instance."""
    global _urlscan_integration

    if _urlscan_integration is None:
        _urlscan_integration = URLScanIntegration(
            api_key=api_key,
            timeout=timeout,
            max_wait_seconds=max_wait_seconds
        )

    return _urlscan_integration

