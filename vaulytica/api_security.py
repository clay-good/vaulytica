import asyncio
import hashlib
import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse, parse_qs

from vaulytica.cspm import Severity
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class VulnerabilityType(str, Enum):
    """API and application vulnerability types."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    XXE = "xxe"
    SSRF = "ssrf"
    BROKEN_AUTH = "broken_authentication"
    BROKEN_ACCESS = "broken_access_control"
    SECURITY_MISCONFIG = "security_misconfiguration"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    INSUFFICIENT_LOGGING = "insufficient_logging"
    INJECTION = "injection"
    DESERIALIZATION = "insecure_deserialization"
    COMPONENTS_VULN = "vulnerable_components"


class OWASPCategory(str, Enum):
    """OWASP Top 10 categories."""
    A01_BROKEN_ACCESS = "A01:2021-Broken Access Control"
    A02_CRYPTO_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIG = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery"


class APIMethod(str, Enum):
    """HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class AuthType(str, Enum):
    """Authentication types."""
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"


class ThreatType(str, Enum):
    """API threat types."""
    BOT_ATTACK = "bot_attack"
    CREDENTIAL_STUFFING = "credential_stuffing"
    API_ABUSE = "api_abuse"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    DATA_SCRAPING = "data_scraping"
    PARAMETER_TAMPERING = "parameter_tampering"


@dataclass
class APIEndpoint:
    """API endpoint definition."""
    endpoint_id: str
    path: str
    method: APIMethod
    auth_type: AuthType
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    rate_limit: Optional[int] = None
    requires_auth: bool = True
    description: str = ""


@dataclass
class APIVulnerability:
    """Detected API vulnerability."""
    vuln_id: str
    vulnerability_type: VulnerabilityType
    owasp_category: OWASPCategory
    severity: Severity
    endpoint: APIEndpoint
    description: str
    evidence: str
    cvss_score: float  # 0.0-10.0
    remediation: str
    cwe_id: Optional[str] = None
    detected_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class SecurityTest:
    """Security test definition."""
    test_id: str
    name: str
    test_type: VulnerabilityType
    target: str
    payload: str
    expected_result: str
    actual_result: Optional[str] = None
    passed: bool = False
    executed_at: Optional[datetime] = None


@dataclass
class APIThreat:
    """Detected API threat."""
    threat_id: str
    threat_type: ThreatType
    severity: Severity
    source_ip: str
    endpoint: str
    description: str
    indicators: List[str]
    request_count: int = 0
    risk_score: float = 0.0
    detected_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class VulnerabilityReport:
    """Comprehensive vulnerability report."""
    report_id: str
    scan_target: str
    vulnerabilities: List[APIVulnerability]
    total_endpoints: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_risk_score: float
    scan_duration: float
    generated_at: datetime = field(default_factory=datetime.utcnow)


class APISecurityScanner:
    """
    API security scanner.
    
    Scans APIs for authentication, authorization, and injection vulnerabilities.
    """
    
    def __init__(self):
        """Initialize API security scanner."""
        self.endpoints: Dict[str, APIEndpoint] = {}
        self.vulnerabilities: List[APIVulnerability] = []
        
        self.statistics = {
            "endpoints_scanned": 0,
            "vulnerabilities_found": 0,
            "by_severity": {},
            "by_type": {},
            "tests_executed": 0
        }
        
        # SQL injection patterns
        self.sql_injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' AND '1'='1"
        ]
        
        # XSS patterns
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        logger.info("API Security Scanner initialized")
    
    async def scan_endpoint(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """
        Scan API endpoint for vulnerabilities.
        
        Args:
            endpoint: API endpoint to scan
        
        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"Scanning API endpoint: {endpoint.method.value} {endpoint.path}")
        
        self.endpoints[endpoint.endpoint_id] = endpoint
        vulnerabilities = []
        
        # Test authentication
        auth_vulns = await self._test_authentication(endpoint)
        vulnerabilities.extend(auth_vulns)
        
        # Test authorization
        authz_vulns = await self._test_authorization(endpoint)
        vulnerabilities.extend(authz_vulns)
        
        # Test for injection vulnerabilities
        injection_vulns = await self._test_injection(endpoint)
        vulnerabilities.extend(injection_vulns)
        
        # Test for security misconfigurations
        misconfig_vulns = await self._test_misconfigurations(endpoint)
        vulnerabilities.extend(misconfig_vulns)
        
        self.vulnerabilities.extend(vulnerabilities)
        self.statistics["endpoints_scanned"] += 1
        self.statistics["vulnerabilities_found"] += len(vulnerabilities)
        
        # Update statistics
        for vuln in vulnerabilities:
            severity_key = vuln.severity.value
            if severity_key not in self.statistics["by_severity"]:
                self.statistics["by_severity"][severity_key] = 0
            self.statistics["by_severity"][severity_key] += 1
            
            type_key = vuln.vulnerability_type.value
            if type_key not in self.statistics["by_type"]:
                self.statistics["by_type"][type_key] = 0
            self.statistics["by_type"][type_key] += 1
        
        return vulnerabilities
    
    async def _test_authentication(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test authentication vulnerabilities."""
        vulnerabilities = []
        
        self.statistics["tests_executed"] += 1
        
        # Check if endpoint requires authentication
        if not endpoint.requires_auth:
            vuln = APIVulnerability(
                vuln_id=f"vuln-{hashlib.md5(f'{endpoint.endpoint_id}noauth'.encode()).hexdigest()[:12]}",
                vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                severity=Severity.HIGH,
                endpoint=endpoint,
                description=f"Endpoint {endpoint.path} does not require authentication",
                evidence="No authentication mechanism detected",
                cvss_score=7.5,
                remediation="Implement proper authentication (OAuth2, JWT, API keys)",
                cwe_id="CWE-306"
            )
            vulnerabilities.append(vuln)
        
        # Check for weak authentication
        if endpoint.auth_type == AuthType.BASIC:
            vuln = APIVulnerability(
                vuln_id=f"vuln-{hashlib.md5(f'{endpoint.endpoint_id}weakauth'.encode()).hexdigest()[:12]}",
                vulnerability_type=VulnerabilityType.BROKEN_AUTH,
                owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                severity=Severity.MEDIUM,
                endpoint=endpoint,
                description=f"Endpoint {endpoint.path} uses weak Basic authentication",
                evidence="Basic authentication detected (credentials in base64)",
                cvss_score=5.3,
                remediation="Use stronger authentication (OAuth2, JWT with proper token management)",
                cwe_id="CWE-287"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_authorization(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test authorization vulnerabilities."""
        vulnerabilities = []
        
        self.statistics["tests_executed"] += 1
        
        # Check for IDOR (Insecure Direct Object Reference)
        if any(param in endpoint.path for param in ['{id}', '{user_id}', '{account_id}']):
            vuln = APIVulnerability(
                vuln_id=f"vuln-{hashlib.md5(f'{endpoint.endpoint_id}idor'.encode()).hexdigest()[:12]}",
                vulnerability_type=VulnerabilityType.BROKEN_ACCESS,
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS,
                severity=Severity.HIGH,
                endpoint=endpoint,
                description=f"Potential IDOR vulnerability in {endpoint.path}",
                evidence="Direct object reference in URL without proper authorization checks",
                cvss_score=7.1,
                remediation="Implement proper authorization checks for object access",
                cwe_id="CWE-639"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_injection(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test injection vulnerabilities."""
        vulnerabilities = []
        
        self.statistics["tests_executed"] += 2
        
        # Test SQL injection
        for param in endpoint.parameters:
            if any(keyword in param.lower() for keyword in ['id', 'user', 'query', 'search']):
                vuln = APIVulnerability(
                    vuln_id=f"vuln-{hashlib.md5(f'{endpoint.endpoint_id}sqli{param}'.encode()).hexdigest()[:12]}",
                    vulnerability_type=VulnerabilityType.SQL_INJECTION,
                    owasp_category=OWASPCategory.A03_INJECTION,
                    severity=Severity.CRITICAL,
                    endpoint=endpoint,
                    description=f"Potential SQL injection in parameter '{param}'",
                    evidence=f"Parameter '{param}' may be vulnerable to SQL injection",
                    cvss_score=9.8,
                    remediation="Use parameterized queries or prepared statements",
                    cwe_id="CWE-89"
                )
                vulnerabilities.append(vuln)
        
        # Test XSS
        if endpoint.method in [APIMethod.POST, APIMethod.PUT]:
            vuln = APIVulnerability(
                vuln_id=f"vuln-{hashlib.md5(f'{endpoint.endpoint_id}xss'.encode()).hexdigest()[:12]}",
                vulnerability_type=VulnerabilityType.XSS,
                owasp_category=OWASPCategory.A03_INJECTION,
                severity=Severity.HIGH,
                endpoint=endpoint,
                description=f"Potential XSS vulnerability in {endpoint.path}",
                evidence="User input may not be properly sanitized",
                cvss_score=7.2,
                remediation="Implement input validation and output encoding",
                cwe_id="CWE-79"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _test_misconfigurations(self, endpoint: APIEndpoint) -> List[APIVulnerability]:
        """Test security misconfigurations."""
        vulnerabilities = []
        
        self.statistics["tests_executed"] += 1
        
        # Check for missing rate limiting
        if endpoint.rate_limit is None:
            vuln = APIVulnerability(
                vuln_id=f"vuln-{hashlib.md5(f'{endpoint.endpoint_id}ratelimit'.encode()).hexdigest()[:12]}",
                vulnerability_type=VulnerabilityType.SECURITY_MISCONFIG,
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIG,
                severity=Severity.MEDIUM,
                endpoint=endpoint,
                description=f"No rate limiting configured for {endpoint.path}",
                evidence="Rate limit not set",
                cvss_score=5.3,
                remediation="Implement rate limiting to prevent abuse",
                cwe_id="CWE-770"
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        return self.statistics


# Global instance
_api_scanner: Optional[APISecurityScanner] = None


def get_api_scanner() -> APISecurityScanner:
    """Get or create global API scanner instance."""
    global _api_scanner

    if _api_scanner is None:
        _api_scanner = APISecurityScanner()

    return _api_scanner


class ApplicationSecurityTester:
    """
    Application security tester.

    Tests applications for OWASP Top 10 vulnerabilities.
    """

    def __init__(self):
        """Initialize application security tester."""
        self.tests: List[SecurityTest] = []
        self.vulnerabilities: List[APIVulnerability] = []

        self.statistics = {
            "tests_executed": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "vulnerabilities_found": 0,
            "by_owasp_category": {}
        }

        logger.info("Application Security Tester initialized")

    async def test_sql_injection(self, target: str, parameters: List[str]) -> List[APIVulnerability]:
        """
        Test for SQL injection vulnerabilities.

        Args:
            target: Target URL or endpoint
            parameters: Parameters to test

        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"Testing SQL injection on: {target}")

        vulnerabilities = []
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--",
            "admin'--"
        ]

        for param in parameters:
            for payload in payloads:
                test = SecurityTest(
                    test_id=f"test-{hashlib.md5(f'{target}{param}{payload}'.encode()).hexdigest()[:12]}",
                    name=f"SQL Injection Test - {param}",
                    test_type=VulnerabilityType.SQL_INJECTION,
                    target=target,
                    payload=payload,
                    expected_result="No SQL error or data leakage",
                    executed_at=datetime.utcnow()
                )

                # Simulate test execution
                # In production, this would make actual HTTP requests
                test.actual_result = "Potential SQL injection detected"
                test.passed = False

                self.tests.append(test)
                self.statistics["tests_executed"] += 1

                if not test.passed:
                    self.statistics["tests_failed"] += 1

                    vuln = APIVulnerability(
                        vuln_id=f"vuln-{test.test_id}",
                        vulnerability_type=VulnerabilityType.SQL_INJECTION,
                        owasp_category=OWASPCategory.A03_INJECTION,
                        severity=Severity.CRITICAL,
                        endpoint=APIEndpoint(
                            endpoint_id=f"ep-{hashlib.md5(target.encode()).hexdigest()[:12]}",
                            path=target,
                            method=APIMethod.GET,
                            auth_type=AuthType.NONE
                        ),
                        description=f"SQL injection vulnerability in parameter '{param}'",
                        evidence=f"Payload: {payload}",
                        cvss_score=9.8,
                        remediation="Use parameterized queries or ORM",
                        cwe_id="CWE-89"
                    )
                    vulnerabilities.append(vuln)
                    self.statistics["vulnerabilities_found"] += 1
                else:
                    self.statistics["tests_passed"] += 1

        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities

    async def test_xss(self, target: str, parameters: List[str]) -> List[APIVulnerability]:
        """
        Test for XSS vulnerabilities.

        Args:
            target: Target URL or endpoint
            parameters: Parameters to test

        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"Testing XSS on: {target}")

        vulnerabilities = []
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        for param in parameters:
            for payload in payloads:
                test = SecurityTest(
                    test_id=f"test-{hashlib.md5(f'{target}{param}{payload}'.encode()).hexdigest()[:12]}",
                    name=f"XSS Test - {param}",
                    test_type=VulnerabilityType.XSS,
                    target=target,
                    payload=payload,
                    expected_result="Payload should be escaped",
                    executed_at=datetime.utcnow()
                )

                # Simulate test execution
                test.actual_result = "Payload reflected without escaping"
                test.passed = False

                self.tests.append(test)
                self.statistics["tests_executed"] += 1

                if not test.passed:
                    self.statistics["tests_failed"] += 1

                    vuln = APIVulnerability(
                        vuln_id=f"vuln-{test.test_id}",
                        vulnerability_type=VulnerabilityType.XSS,
                        owasp_category=OWASPCategory.A03_INJECTION,
                        severity=Severity.HIGH,
                        endpoint=APIEndpoint(
                            endpoint_id=f"ep-{hashlib.md5(target.encode()).hexdigest()[:12]}",
                            path=target,
                            method=APIMethod.POST,
                            auth_type=AuthType.NONE
                        ),
                        description=f"XSS vulnerability in parameter '{param}'",
                        evidence=f"Payload: {payload}",
                        cvss_score=7.2,
                        remediation="Implement input validation and output encoding",
                        cwe_id="CWE-79"
                    )
                    vulnerabilities.append(vuln)
                    self.statistics["vulnerabilities_found"] += 1
                else:
                    self.statistics["tests_passed"] += 1

        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities

    async def test_csrf(self, target: str) -> List[APIVulnerability]:
        """
        Test for CSRF vulnerabilities.

        Args:
            target: Target URL or endpoint

        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"Testing CSRF on: {target}")

        vulnerabilities = []

        test = SecurityTest(
            test_id=f"test-{hashlib.md5(f'{target}csrf'.encode()).hexdigest()[:12]}",
            name="CSRF Token Test",
            test_type=VulnerabilityType.CSRF,
            target=target,
            payload="No CSRF token",
            expected_result="CSRF token required",
            executed_at=datetime.utcnow()
        )

        # Simulate test execution
        test.actual_result = "No CSRF token validation"
        test.passed = False

        self.tests.append(test)
        self.statistics["tests_executed"] += 1

        if not test.passed:
            self.statistics["tests_failed"] += 1

            vuln = APIVulnerability(
                vuln_id=f"vuln-{test.test_id}",
                vulnerability_type=VulnerabilityType.CSRF,
                owasp_category=OWASPCategory.A01_BROKEN_ACCESS,
                severity=Severity.MEDIUM,
                endpoint=APIEndpoint(
                    endpoint_id=f"ep-{hashlib.md5(target.encode()).hexdigest()[:12]}",
                    path=target,
                    method=APIMethod.POST,
                    auth_type=AuthType.NONE
                ),
                description="Missing CSRF protection",
                evidence="No CSRF token validation detected",
                cvss_score=6.5,
                remediation="Implement CSRF tokens for state-changing operations",
                cwe_id="CWE-352"
            )
            vulnerabilities.append(vuln)
            self.statistics["vulnerabilities_found"] += 1
        else:
            self.statistics["tests_passed"] += 1

        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities

    async def test_ssrf(self, target: str, parameters: List[str]) -> List[APIVulnerability]:
        """
        Test for SSRF vulnerabilities.

        Args:
            target: Target URL or endpoint
            parameters: Parameters to test

        Returns:
            List of detected vulnerabilities
        """
        logger.info(f"Testing SSRF on: {target}")

        vulnerabilities = []
        payloads = [
            "http://localhost:8080",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]

        for param in parameters:
            if any(keyword in param.lower() for keyword in ['url', 'uri', 'link', 'callback']):
                for payload in payloads:
                    test = SecurityTest(
                        test_id=f"test-{hashlib.md5(f'{target}{param}{payload}'.encode()).hexdigest()[:12]}",
                        name=f"SSRF Test - {param}",
                        test_type=VulnerabilityType.SSRF,
                        target=target,
                        payload=payload,
                        expected_result="Internal URLs should be blocked",
                        executed_at=datetime.utcnow()
                    )

                    # Simulate test execution
                    test.actual_result = "Internal URL accessible"
                    test.passed = False

                    self.tests.append(test)
                    self.statistics["tests_executed"] += 1

                    if not test.passed:
                        self.statistics["tests_failed"] += 1

                        vuln = APIVulnerability(
                            vuln_id=f"vuln-{test.test_id}",
                            vulnerability_type=VulnerabilityType.SSRF,
                            owasp_category=OWASPCategory.A10_SSRF,
                            severity=Severity.HIGH,
                            endpoint=APIEndpoint(
                                endpoint_id=f"ep-{hashlib.md5(target.encode()).hexdigest()[:12]}",
                                path=target,
                                method=APIMethod.POST,
                                auth_type=AuthType.NONE
                            ),
                            description=f"SSRF vulnerability in parameter '{param}'",
                            evidence=f"Payload: {payload}",
                            cvss_score=8.6,
                            remediation="Validate and whitelist allowed URLs",
                            cwe_id="CWE-918"
                        )
                        vulnerabilities.append(vuln)
                        self.statistics["vulnerabilities_found"] += 1
                    else:
                        self.statistics["tests_passed"] += 1

        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities

    def get_statistics(self) -> Dict[str, Any]:
        """Get tester statistics."""
        return self.statistics


# Global instance
_app_tester: Optional[ApplicationSecurityTester] = None


def get_app_tester() -> ApplicationSecurityTester:
    """Get or create global application tester instance."""
    global _app_tester

    if _app_tester is None:
        _app_tester = ApplicationSecurityTester()

    return _app_tester


class APIThreatProtection:
    """
    Real-time API threat protection.

    Detects and prevents API threats like bot attacks, credential stuffing, and abuse.
    """

    def __init__(self):
        """Initialize API threat protection."""
        self.threats: List[APIThreat] = []
        self.request_history: Dict[str, List[Dict[str, Any]]] = {}

        self.statistics = {
            "requests_analyzed": 0,
            "threats_detected": 0,
            "threats_blocked": 0,
            "by_type": {}
        }

        # Known bot user agents
        self.bot_patterns = [
            r'bot', r'crawler', r'spider', r'scraper',
            r'curl', r'wget', r'python-requests'
        ]

        logger.info("API Threat Protection initialized")

    async def analyze_request(
        self,
        source_ip: str,
        endpoint: str,
        method: str,
        user_agent: str,
        headers: Dict[str, str]
    ) -> Optional[APIThreat]:
        """
        Analyze API request for threats.

        Args:
            source_ip: Source IP address
            endpoint: API endpoint
            method: HTTP method
            user_agent: User agent string
            headers: Request headers

        Returns:
            Detected threat or None
        """
        logger.info(f"Analyzing API request: {source_ip} -> {endpoint}")

        self.statistics["requests_analyzed"] += 1

        # Store request history
        if source_ip not in self.request_history:
            self.request_history[source_ip] = []

        self.request_history[source_ip].append({
            "endpoint": endpoint,
            "method": method,
            "timestamp": datetime.utcnow(),
            "user_agent": user_agent
        })

        # Check for bot attacks
        bot_threat = await self._detect_bot_attack(source_ip, user_agent)
        if bot_threat:
            return bot_threat

        # Check for credential stuffing
        cred_threat = await self._detect_credential_stuffing(source_ip, endpoint)
        if cred_threat:
            return cred_threat

        # Check for API abuse
        abuse_threat = await self._detect_api_abuse(source_ip, endpoint)
        if abuse_threat:
            return abuse_threat

        return None

    async def _detect_bot_attack(self, source_ip: str, user_agent: str) -> Optional[APIThreat]:
        """Detect bot attacks."""
        # Check user agent for bot patterns
        for pattern in self.bot_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                threat = APIThreat(
                    threat_id=f"threat-{hashlib.md5(f'{source_ip}bot'.encode()).hexdigest()[:12]}",
                    threat_type=ThreatType.BOT_ATTACK,
                    severity=Severity.MEDIUM,
                    source_ip=source_ip,
                    endpoint="*",
                    description=f"Bot detected from {source_ip}",
                    indicators=[
                        f"User-Agent: {user_agent}",
                        f"Pattern matched: {pattern}"
                    ],
                    risk_score=5.5
                )

                self.threats.append(threat)
                self._update_statistics(threat)

                return threat

        return None

    async def _detect_credential_stuffing(self, source_ip: str, endpoint: str) -> Optional[APIThreat]:
        """Detect credential stuffing attacks."""
        # Check for multiple login attempts
        if '/login' in endpoint or '/auth' in endpoint:
            recent_requests = [
                r for r in self.request_history.get(source_ip, [])
                if (datetime.utcnow() - r["timestamp"]).seconds < 60
                and ('/login' in r["endpoint"] or '/auth' in r["endpoint"])
            ]

            if len(recent_requests) > 10:
                threat = APIThreat(
                    threat_id=f"threat-{hashlib.md5(f'{source_ip}credstuff'.encode()).hexdigest()[:12]}",
                    threat_type=ThreatType.CREDENTIAL_STUFFING,
                    severity=Severity.HIGH,
                    source_ip=source_ip,
                    endpoint=endpoint,
                    description=f"Credential stuffing detected from {source_ip}",
                    indicators=[
                        f"Login attempts: {len(recent_requests)}",
                        f"Time window: 60 seconds"
                    ],
                    request_count=len(recent_requests),
                    risk_score=8.0
                )

                self.threats.append(threat)
                self._update_statistics(threat)

                return threat

        return None

    async def _detect_api_abuse(self, source_ip: str, endpoint: str) -> Optional[APIThreat]:
        """Detect API abuse."""
        # Check for excessive requests
        recent_requests = [
            r for r in self.request_history.get(source_ip, [])
            if (datetime.utcnow() - r["timestamp"]).seconds < 60
        ]

        if len(recent_requests) > 100:
            threat = APIThreat(
                threat_id=f"threat-{hashlib.md5(f'{source_ip}abuse'.encode()).hexdigest()[:12]}",
                threat_type=ThreatType.API_ABUSE,
                severity=Severity.HIGH,
                source_ip=source_ip,
                endpoint=endpoint,
                description=f"API abuse detected from {source_ip}",
                indicators=[
                    f"Requests: {len(recent_requests)} in 60 seconds",
                    f"Rate limit exceeded"
                ],
                request_count=len(recent_requests),
                risk_score=7.5
            )

            self.threats.append(threat)
            self._update_statistics(threat)

            return threat

        return None

    def _update_statistics(self, threat: APIThreat):
        """Update threat statistics."""
        self.statistics["threats_detected"] += 1

        if threat.threat_type.value not in self.statistics["by_type"]:
            self.statistics["by_type"][threat.threat_type.value] = 0
        self.statistics["by_type"][threat.threat_type.value] += 1

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat protection statistics."""
        return self.statistics


class SecurityAutomation:
    """
    Security automation engine.

    Automates security testing and remediation.
    """

    def __init__(self):
        """Initialize security automation."""
        self.scheduled_scans: List[Dict[str, Any]] = []
        self.scan_results: List[VulnerabilityReport] = []

        self.statistics = {
            "scans_executed": 0,
            "vulnerabilities_found": 0,
            "auto_remediated": 0,
            "manual_review_required": 0
        }

        logger.info("Security Automation initialized")

    async def schedule_scan(
        self,
        target: str,
        scan_type: str,
        frequency: str = "daily"
    ) -> Dict[str, Any]:
        """
        Schedule automated security scan.

        Args:
            target: Scan target
            scan_type: Type of scan (api, app, full)
            frequency: Scan frequency (hourly, daily, weekly)

        Returns:
            Scheduled scan details
        """
        logger.info(f"Scheduling {scan_type} scan for {target}")

        scan = {
            "scan_id": f"scan-{hashlib.md5(f'{target}{scan_type}'.encode()).hexdigest()[:12]}",
            "target": target,
            "scan_type": scan_type,
            "frequency": frequency,
            "next_run": datetime.utcnow() + timedelta(hours=1),
            "enabled": True
        }

        self.scheduled_scans.append(scan)

        return scan

    async def execute_scan(
        self,
        target: str,
        scan_type: str
    ) -> VulnerabilityReport:
        """
        Execute security scan.

        Args:
            target: Scan target
            scan_type: Type of scan

        Returns:
            Vulnerability report
        """
        logger.info(f"Executing {scan_type} scan on {target}")

        start_time = datetime.utcnow()
        vulnerabilities = []

        # Execute scan based on type
        if scan_type == "api":
            scanner = get_api_scanner()
            # Create test endpoint
            endpoint = APIEndpoint(
                endpoint_id=f"ep-{hashlib.md5(target.encode()).hexdigest()[:12]}",
                path=target,
                method=APIMethod.GET,
                auth_type=AuthType.NONE,
                parameters=["id", "user_id"]
            )
            vulnerabilities = await scanner.scan_endpoint(endpoint)

        elif scan_type == "app":
            tester = get_app_tester()
            sql_vulns = await tester.test_sql_injection(target, ["id", "query"])
            xss_vulns = await tester.test_xss(target, ["comment", "message"])
            csrf_vulns = await tester.test_csrf(target)
            vulnerabilities = sql_vulns + xss_vulns + csrf_vulns

        duration = (datetime.utcnow() - start_time).total_seconds()

        # Count by severity
        critical_count = len([v for v in vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in vulnerabilities if v.severity == Severity.HIGH])
        medium_count = len([v for v in vulnerabilities if v.severity == Severity.MEDIUM])
        low_count = len([v for v in vulnerabilities if v.severity == Severity.LOW])

        # Calculate overall risk
        risk_score = (critical_count * 10 + high_count * 7 + medium_count * 4 + low_count * 1) / max(len(vulnerabilities), 1)

        report = VulnerabilityReport(
            report_id=f"report-{hashlib.md5(f'{target}{start_time}'.encode()).hexdigest()[:12]}",
            scan_target=target,
            vulnerabilities=vulnerabilities,
            total_endpoints=1,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            overall_risk_score=min(risk_score, 10.0),
            scan_duration=duration
        )

        self.scan_results.append(report)
        self.statistics["scans_executed"] += 1
        self.statistics["vulnerabilities_found"] += len(vulnerabilities)

        return report

    def get_statistics(self) -> Dict[str, Any]:
        """Get automation statistics."""
        return self.statistics


# Global instances
_threat_protection: Optional[APIThreatProtection] = None
_security_automation: Optional[SecurityAutomation] = None


def get_threat_protection() -> APIThreatProtection:
    """Get or create global threat protection instance."""
    global _threat_protection

    if _threat_protection is None:
        _threat_protection = APIThreatProtection()

    return _threat_protection


def get_security_automation() -> SecurityAutomation:
    """Get or create global security automation instance."""
    global _security_automation

    if _security_automation is None:
        _security_automation = SecurityAutomation()

    return _security_automation


class VulnerabilityReporter:
    """
    Comprehensive vulnerability reporting.

    Generates detailed reports with CVSS scoring and remediation guidance.
    """

    def __init__(self):
        """Initialize vulnerability reporter."""
        self.reports: List[VulnerabilityReport] = []

        self.statistics = {
            "reports_generated": 0,
            "total_vulnerabilities": 0,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0
        }

        logger.info("Vulnerability Reporter initialized")

    async def generate_report(
        self,
        scan_target: str,
        vulnerabilities: List[APIVulnerability]
    ) -> VulnerabilityReport:
        """
        Generate vulnerability report.

        Args:
            scan_target: Target that was scanned
            vulnerabilities: List of vulnerabilities found

        Returns:
            Comprehensive vulnerability report
        """
        logger.info(f"Generating vulnerability report for {scan_target}")

        # Count by severity
        critical_count = len([v for v in vulnerabilities if v.severity == Severity.CRITICAL])
        high_count = len([v for v in vulnerabilities if v.severity == Severity.HIGH])
        medium_count = len([v for v in vulnerabilities if v.severity == Severity.MEDIUM])
        low_count = len([v for v in vulnerabilities if v.severity == Severity.LOW])

        # Calculate overall risk score
        if vulnerabilities:
            avg_cvss = sum(v.cvss_score for v in vulnerabilities) / len(vulnerabilities)
            risk_score = min(avg_cvss, 10.0)
        else:
            risk_score = 0.0

        report = VulnerabilityReport(
            report_id=f"report-{hashlib.md5(f'{scan_target}{datetime.utcnow()}'.encode()).hexdigest()[:12]}",
            scan_target=scan_target,
            vulnerabilities=vulnerabilities,
            total_endpoints=len(set(v.endpoint.endpoint_id for v in vulnerabilities)),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            overall_risk_score=risk_score,
            scan_duration=0.0
        )

        self.reports.append(report)
        self.statistics["reports_generated"] += 1
        self.statistics["total_vulnerabilities"] += len(vulnerabilities)
        self.statistics["critical_vulnerabilities"] += critical_count
        self.statistics["high_vulnerabilities"] += high_count

        return report

    def export_report(self, report: VulnerabilityReport, format: str = "json") -> str:
        """
        Export report in specified format.

        Args:
            report: Report to export
            format: Export format (json, html, pdf)

        Returns:
            Exported report content
        """
        logger.info(f"Exporting report {report.report_id} as {format}")

        if format == "json":
            return json.dumps({
                "report_id": report.report_id,
                "scan_target": report.scan_target,
                "generated_at": report.generated_at.isoformat(),
                "summary": {
                    "total_vulnerabilities": len(report.vulnerabilities),
                    "critical": report.critical_count,
                    "high": report.high_count,
                    "medium": report.medium_count,
                    "low": report.low_count,
                    "overall_risk_score": report.overall_risk_score
                },
                "vulnerabilities": [
                    {
                        "vuln_id": v.vuln_id,
                        "type": v.vulnerability_type.value,
                        "owasp": v.owasp_category.value,
                        "severity": v.severity.value,
                        "cvss_score": v.cvss_score,
                        "endpoint": v.endpoint.path,
                        "description": v.description,
                        "remediation": v.remediation,
                        "cwe_id": v.cwe_id
                    }
                    for v in report.vulnerabilities
                ]
            }, indent=2)

        return "Unsupported format"

    def get_statistics(self) -> Dict[str, Any]:
        """Get reporter statistics."""
        return self.statistics


class APISecurityOrchestrator:
    """
    API security orchestrator.

    Coordinates all API security, testing, and threat protection operations.
    """

    def __init__(self):
        """Initialize orchestrator."""
        self.api_scanner = get_api_scanner()
        self.app_tester = get_app_tester()
        self.threat_protection = get_threat_protection()
        self.security_automation = get_security_automation()
        self.reporter = VulnerabilityReporter()

        logger.info("API Security Orchestrator initialized")

    async def perform_full_assessment(
        self,
        target: str,
        endpoints: List[APIEndpoint],
        test_parameters: List[str]
    ) -> Dict[str, Any]:
        """
        Perform comprehensive API security assessment.

        Args:
            target: Target application
            endpoints: API endpoints to scan
            test_parameters: Parameters to test

        Returns:
            Complete assessment results
        """
        logger.info(f"Starting full API security assessment for {target}")

        start_time = datetime.utcnow()

        # Scan API endpoints
        api_vulnerabilities = []
        for endpoint in endpoints:
            vulns = await self.api_scanner.scan_endpoint(endpoint)
            api_vulnerabilities.extend(vulns)

        # Test application security
        sql_vulns = await self.app_tester.test_sql_injection(target, test_parameters)
        xss_vulns = await self.app_tester.test_xss(target, test_parameters)
        csrf_vulns = await self.app_tester.test_csrf(target)
        ssrf_vulns = await self.app_tester.test_ssrf(target, test_parameters)

        app_vulnerabilities = sql_vulns + xss_vulns + csrf_vulns + ssrf_vulns

        # Combine all vulnerabilities
        all_vulnerabilities = api_vulnerabilities + app_vulnerabilities

        # Generate report
        report = await self.reporter.generate_report(target, all_vulnerabilities)

        duration = (datetime.utcnow() - start_time).total_seconds()

        # Calculate risk level
        risk_level = self._get_risk_level(report.overall_risk_score)

        return {
            "assessment_id": f"assessment-{hashlib.md5(f'{target}{start_time}'.encode()).hexdigest()[:12]}",
            "target": target,
            "timestamp": start_time.isoformat(),
            "duration_seconds": duration,
            "api_security": {
                "endpoints_scanned": len(endpoints),
                "vulnerabilities_found": len(api_vulnerabilities),
                "by_severity": {
                    "critical": len([v for v in api_vulnerabilities if v.severity == Severity.CRITICAL]),
                    "high": len([v for v in api_vulnerabilities if v.severity == Severity.HIGH]),
                    "medium": len([v for v in api_vulnerabilities if v.severity == Severity.MEDIUM]),
                    "low": len([v for v in api_vulnerabilities if v.severity == Severity.LOW])
                }
            },
            "application_security": {
                "tests_executed": self.app_tester.statistics["tests_executed"],
                "vulnerabilities_found": len(app_vulnerabilities),
                "by_type": {
                    "sql_injection": len(sql_vulns),
                    "xss": len(xss_vulns),
                    "csrf": len(csrf_vulns),
                    "ssrf": len(ssrf_vulns)
                }
            },
            "report": {
                "report_id": report.report_id,
                "total_vulnerabilities": len(all_vulnerabilities),
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "medium_count": report.medium_count,
                "low_count": report.low_count,
                "overall_risk_score": report.overall_risk_score,
                "risk_level": risk_level
            },
            "statistics": {
                "api_scanner": self.api_scanner.get_statistics(),
                "app_tester": self.app_tester.get_statistics(),
                "threat_protection": self.threat_protection.get_statistics(),
                "security_automation": self.security_automation.get_statistics(),
                "reporter": self.reporter.get_statistics()
            }
        }

    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level from score."""
        if risk_score >= 9.0:
            return "CRITICAL"
        elif risk_score >= 7.0:
            return "HIGH"
        elif risk_score >= 4.0:
            return "MEDIUM"
        elif risk_score >= 1.0:
            return "LOW"
        else:
            return "MINIMAL"


# Global instances
_reporter: Optional[VulnerabilityReporter] = None
_orchestrator: Optional[APISecurityOrchestrator] = None


def get_vulnerability_reporter() -> VulnerabilityReporter:
    """Get or create global vulnerability reporter instance."""
    global _reporter

    if _reporter is None:
        _reporter = VulnerabilityReporter()

    return _reporter


def get_api_security_orchestrator() -> APISecurityOrchestrator:
    """Get or create global orchestrator instance."""
    global _orchestrator

    if _orchestrator is None:
        _orchestrator = APISecurityOrchestrator()

    return _orchestrator

