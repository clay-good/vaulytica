"""
Threat Intelligence Extractor for Vaulytica AI Agent Framework

Extracts threat intelligence from incidents and generates:
- IOCs (Indicators of Compromise)
- YARA rules for malware detection
- Sigma rules for SIEM detection
- SIEM rules (Splunk, Elastic, etc.)
- Defense-in-depth recommendations

Version: 0.31.0
"""

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class IOCType(str, Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"


class RuleType(str, Enum):
    """Types of detection rules"""
    YARA = "yara"
    SIGMA = "sigma"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    SURICATA = "suricata"


@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_type: IOCType
    value: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    context: str
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionRule:
    """Detection rule (YARA, Sigma, SIEM)"""
    rule_id: str
    rule_type: RuleType
    name: str
    description: str
    rule_content: str
    severity: str
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DefenseRecommendation:
    """Defense-in-depth recommendation"""
    category: str  # e.g., "network", "endpoint", "identity"
    control: str
    description: str
    priority: str  # "critical", "high", "medium", "low"
    implementation_guidance: str
    mitre_techniques: List[str] = field(default_factory=list)


class ThreatIntelExtractor:
    """
    Extracts threat intelligence from incident data and generates
    detection rules and defense recommendations.
    """

    def __init__(self):
        self.iocs: Dict[str, IOC] = {}
        self.rules: Dict[str, DetectionRule] = {}
        logger.info("ThreatIntelExtractor initialized")

    def extract_iocs_from_incident(
        self,
        incident_data: Dict[str, Any]
    ) -> List[IOC]:
        """
        Extract IOCs from incident data.

        Args:
            incident_data: Incident data containing logs, events, findings

        Returns:
            List of extracted IOCs
        """
        iocs = []

        # Extract from various data sources
        data_sources = incident_data.get("data_sources", {})
        findings = incident_data.get("findings", [])
        timeline = incident_data.get("timeline", [])

        # Extract IP addresses
        iocs.extend(self._extract_ip_addresses(data_sources, findings, timeline))

        # Extract domains
        iocs.extend(self._extract_domains(data_sources, findings, timeline))

        # Extract file hashes
        iocs.extend(self._extract_file_hashes(data_sources, findings, timeline))

        # Extract URLs
        iocs.extend(self._extract_urls(data_sources, findings, timeline))

        # Extract email addresses
        iocs.extend(self._extract_emails(data_sources, findings, timeline))

        # Store IOCs
        for ioc in iocs:
            ioc_key = f"{ioc.ioc_type.value}:{ioc.value}"
            self.iocs[ioc_key] = ioc

        logger.info(f"Extracted {len(iocs)} IOCs from incident")
        return iocs

    def generate_yara_rule(
        self,
        incident_data: Dict[str, Any],
        rule_name: str
    ) -> DetectionRule:
        """
        Generate YARA rule for malware detection.

        Args:
            incident_data: Incident data
            rule_name: Name for the rule

        Returns:
            DetectionRule with YARA content
        """
        # Extract malware indicators
        file_hashes = self._extract_file_hashes(
            incident_data.get("data_sources", {}),
            incident_data.get("findings", []),
            incident_data.get("timeline", [])
        )

        # Extract strings from malware analysis
        strings = self._extract_malware_strings(incident_data)

        # Generate YARA rule
        rule_content = '''rule {rule_name.replace("-", "_")} {{
    meta:
        description = "Detects malware from incident {incident_data.get('incident_id', 'unknown')}"
        author = "Vaulytica AI Agent"
        date = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        severity = "high"

    strings:
'''

        # Add string patterns
        for i, string in enumerate(strings[:10]):  # Limit to 10 strings
            rule_content += f'        $s{i} = "{string}" ascii wide\n'

        # Add hash conditions if available
        if file_hashes:
            rule_content += '\n    condition:\n'
            rule_content += '        any of ($s*)'
        else:
            rule_content += '\n    condition:\n'
            rule_content += '        3 of ($s*)\n'

        rule_content += '}\n'

        rule = DetectionRule(
            rule_id=f"yara-{rule_name}",
            rule_type=RuleType.YARA,
            name=rule_name,
            description=f"YARA rule for detecting malware from incident {incident_data.get('incident_id')}",
            rule_content=rule_content,
            severity="high",
            tags=["malware", "auto_generated"]
        )

        self.rules[rule.rule_id] = rule
        logger.info(f"Generated YARA rule: {rule_name}")
        return rule

    def generate_sigma_rule(
        self,
        incident_data: Dict[str, Any],
        rule_name: str
    ) -> DetectionRule:
        """
        Generate Sigma rule for SIEM detection.

        Args:
            incident_data: Incident data
            rule_name: Name for the rule

        Returns:
            DetectionRule with Sigma content
        """
        # Extract detection patterns
        timeline = incident_data.get("timeline", [])
        findings = incident_data.get("findings", [])

        # Identify key detection criteria
        process_names = set()
        command_lines = set()
        network_connections = set()

        for event in timeline:
            if "process_name" in event:
                process_names.add(event["process_name"])
            if "command_line" in event:
                command_lines.add(event["command_line"])
            if "remote_ip" in event:
                network_connections.add(event["remote_ip"])

        # Generate Sigma rule in YAML format
        rule_content = '''title: {rule_name}
id: {hashlib.md5(rule_name.encode()).hexdigest()}
status: experimental
description: Detects suspicious activity from incident {incident_data.get('incident_id', 'unknown')}
author: Vaulytica AI Agent
date: {datetime.utcnow().strftime('%Y/%m/%d')}
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
'''

        if process_names:
            rule_content += '        Image|endswith:\n'
            for proc in list(process_names)[:5]:
                rule_content += f'            - "{proc}"\n'

        if command_lines:
            rule_content += '        CommandLine|contains:\n'
            for cmd in list(command_lines)[:3]:
                # Sanitize command line
                cmd_sanitized = cmd[:100] if len(cmd) > 100 else cmd
                rule_content += f'            - "{cmd_sanitized}"\n'

        rule_content += '''    condition: selection
falsepositives:
    - Unknown
level: high
'''

        rule = DetectionRule(
            rule_id=f"sigma-{rule_name}",
            rule_type=RuleType.SIGMA,
            name=rule_name,
            description=f"Sigma rule for detecting activity from incident {incident_data.get('incident_id')}",
            rule_content=rule_content,
            severity="high",
            tags=["sigma", "auto_generated"]
        )

        self.rules[rule.rule_id] = rule
        logger.info(f"Generated Sigma rule: {rule_name}")
        return rule

    def generate_splunk_rule(
        self,
        incident_data: Dict[str, Any],
        rule_name: str
    ) -> DetectionRule:
        """
        Generate Splunk search query for detection.

        Args:
            incident_data: Incident data
            rule_name: Name for the rule

        Returns:
            DetectionRule with Splunk SPL content
        """
        # Extract IOCs
        iocs = self.extract_iocs_from_incident(incident_data)

        # Build Splunk search query
        search_parts = []

        # Add IP addresses
        ip_iocs = [ioc for ioc in iocs if ioc.ioc_type == IOCType.IP_ADDRESS]
        if ip_iocs:
            ips = ' OR '.join([f'"{ioc.value}"' for ioc in ip_iocs[:10]])
            search_parts.append(f'(src_ip IN ({ips}) OR dest_ip IN ({ips}))')

        # Add domains
        domain_iocs = [ioc for ioc in iocs if ioc.ioc_type == IOCType.DOMAIN]
        if domain_iocs:
            domains = ' OR '.join([f'"{ioc.value}"' for ioc in domain_iocs[:10]])
            search_parts.append(f'(domain IN ({domains}) OR query IN ({domains}))')

        # Add file hashes
        hash_iocs = [ioc for ioc in iocs if ioc.ioc_type == IOCType.FILE_HASH]
        if hash_iocs:
            hashes = ' OR '.join([f'"{ioc.value}"' for ioc in hash_iocs[:10]])
            search_parts.append(f'(file_hash IN ({hashes}) OR md5 IN ({hashes}) OR sha256 IN ({hashes}))')

        search_query = 'index=* (' + ' OR '.join(search_parts) + ')' if search_parts else 'index=*'
        search_query += '\n| stats count by _time, src_ip, dest_ip, user, action'
        search_query += '\n| where count > 0'

        rule = DetectionRule(
            rule_id=f"splunk-{rule_name}",
            rule_type=RuleType.SPLUNK,
            name=rule_name,
            description=f"Splunk detection query for incident {incident_data.get('incident_id')}",
            rule_content=search_query,
            severity="high",
            tags=["splunk", "auto_generated"]
        )

        self.rules[rule.rule_id] = rule
        logger.info(f"Generated Splunk rule: {rule_name}")
        return rule

    def generate_defense_recommendations(
        self,
        incident_data: Dict[str, Any]
    ) -> List[DefenseRecommendation]:
        """
        Generate defense-in-depth recommendations based on incident.

        Args:
            incident_data: Incident data

        Returns:
            List of defense recommendations
        """
        recommendations = []

        # Analyze attack vectors
        root_cause = incident_data.get("incident_metadata", {}).get("root_cause", {})
        attack_chain = []

        for finding in incident_data.get("findings", []):
            if "attack_chain" in finding.get("results", {}):
                attack_chain.extend(finding["results"]["attack_chain"])

        # Network-based recommendations
        if any("network" in str(event).lower() for event in incident_data.get("timeline", [])):
            recommendations.append(DefenseRecommendation(
                category="network",
                control="Network Segmentation",
                description="Implement network segmentation to limit lateral movement",
                priority="high",
                implementation_guidance="Deploy VLANs and firewall rules to segment critical assets",
                mitre_techniques=["T1021", "T1210"]
            ))

        # Endpoint-based recommendations
        if any("malware" in str(finding).lower() for finding in incident_data.get("findings", [])):
            recommendations.append(DefenseRecommendation(
                category="endpoint",
                control="Enhanced Endpoint Detection",
                description="Deploy advanced EDR capabilities with behavioral analysis",
                priority="critical",
                implementation_guidance="Enable EDR behavioral monitoring and automated response",
                mitre_techniques=["T1059", "T1055", "T1106"]
            ))

        # Identity-based recommendations
        if "credential" in str(root_cause).lower():
            recommendations.append(DefenseRecommendation(
                category="identity",
                control="Multi-Factor Authentication",
                description="Enforce MFA for all privileged accounts",
                priority="critical",
                implementation_guidance="Deploy MFA solution and enforce for admin accounts",
                mitre_techniques=["T1078", "T1110"]
            ))

        logger.info(f"Generated {len(recommendations)} defense recommendations")
        return recommendations

    # ========================================================================
    # Helper Methods for IOC Extraction
    # ========================================================================

    def _extract_ip_addresses(
        self,
        data_sources: Dict[str, Any],
        findings: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]]
    ) -> List[IOC]:
        """Extract IP address IOCs"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = set()

        # Extract from all data
        all_data = json.dumps(data_sources) + json.dumps(findings) + json.dumps(timeline)
        matches = re.findall(ip_pattern, all_data)

        iocs = []
        for ip in matches:
            # Basic validation
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                # Skip private IPs for external threat intel
                if not (parts[0] == '10' or
                       (parts[0] == '172' and 16 <= int(parts[1]) <= 31) or
                       (parts[0] == '192' and parts[1] == '168')):
                    ips.add(ip)

        for ip in ips:
            iocs.append(IOC(
                ioc_type=IOCType.IP_ADDRESS,
                value=ip,
                confidence=0.8,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                context="Extracted from incident data",
                tags=["network", "auto_extracted"]
            ))

        return iocs

    def _extract_domains(
        self,
        data_sources: Dict[str, Any],
        findings: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]]
    ) -> List[IOC]:
        """Extract domain IOCs"""
        domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'

        all_data = json.dumps(data_sources) + json.dumps(findings) + json.dumps(timeline)
        matches = re.findall(domain_pattern, all_data.lower())

        # Filter out common legitimate domains
        exclude_domains = {'microsoft.com', 'google.com', 'amazon.com', 'apple.com'}
        domains = set(matches) - exclude_domains

        iocs = []
        for domain in domains:
            iocs.append(IOC(
                ioc_type=IOCType.DOMAIN,
                value=domain,
                confidence=0.7,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                context="Extracted from incident data",
                tags=["network", "auto_extracted"]
            ))

        return iocs

    def _extract_file_hashes(
        self,
        data_sources: Dict[str, Any],
        findings: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]]
    ) -> List[IOC]:
        """Extract file hash IOCs"""
        # MD5, SHA1, SHA256 patterns
        md5_pattern = r'\b[a-f0-9]{32}\b'
        sha1_pattern = r'\b[a-f0-9]{40}\b'
        sha256_pattern = r'\b[a-f0-9]{64}\b'

        all_data = json.dumps(data_sources) + json.dumps(findings) + json.dumps(timeline)
        all_data = all_data.lower()

        hashes = set()
        hashes.update(re.findall(md5_pattern, all_data))
        hashes.update(re.findall(sha1_pattern, all_data))
        hashes.update(re.findall(sha256_pattern, all_data))

        iocs = []
        for hash_value in hashes:
            iocs.append(IOC(
                ioc_type=IOCType.FILE_HASH,
                value=hash_value,
                confidence=0.95,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                context="Extracted from incident data",
                tags=["malware", "auto_extracted"]
            ))

        return iocs

    def _extract_urls(
        self,
        data_sources: Dict[str, Any],
        findings: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]]
    ) -> List[IOC]:
        """Extract URL IOCs"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'

        all_data = json.dumps(data_sources) + json.dumps(findings) + json.dumps(timeline)
        matches = re.findall(url_pattern, all_data)

        iocs = []
        for url in set(matches):
            iocs.append(IOC(
                ioc_type=IOCType.URL,
                value=url,
                confidence=0.8,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                context="Extracted from incident data",
                tags=["network", "auto_extracted"]
            ))

        return iocs

    def _extract_emails(
        self,
        data_sources: Dict[str, Any],
        findings: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]]
    ) -> List[IOC]:
        """Extract email address IOCs"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        all_data = json.dumps(data_sources) + json.dumps(findings) + json.dumps(timeline)
        matches = re.findall(email_pattern, all_data)

        iocs = []
        for email in set(matches):
            iocs.append(IOC(
                ioc_type=IOCType.EMAIL,
                value=email,
                confidence=0.7,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                context="Extracted from incident data",
                tags=["phishing", "auto_extracted"]
            ))

        return iocs

    def _extract_malware_strings(self, incident_data: Dict[str, Any]) -> List[str]:
        """Extract characteristic strings from malware analysis"""
        strings = []

        # Look for malware-related strings in findings
        for finding in incident_data.get("findings", []):
            results = finding.get("results", {})

            # Extract from IOCs
            if "iocs" in results:
                for ioc in results["iocs"]:
                    if "value" in ioc:
                        strings.append(ioc["value"])

            # Extract from attack patterns
            if "attack_patterns" in results:
                strings.extend(results["attack_patterns"])

        # Extract from timeline events
        for event in incident_data.get("timeline", []):
            if "command_line" in event:
                # Extract distinctive parts of command lines
                cmd = event["command_line"]
                if len(cmd) > 10:
                    strings.append(cmd[:50])

        return list(set(strings))[:20]  # Return unique strings, max 20


# Global singleton instance
_threat_intel_extractor: Optional[ThreatIntelExtractor] = None


def get_threat_intel_extractor() -> ThreatIntelExtractor:
    """Get the global threat intelligence extractor instance"""
    global _threat_intel_extractor
    if _threat_intel_extractor is None:
        _threat_intel_extractor = ThreatIntelExtractor()
    return _threat_intel_extractor
