"""Advanced threat intelligence enrichment and correlation engine."""

import hashlib
import ipaddress
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class ThreatLevel(str, Enum):
    """Threat level classification."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


@dataclass
class IOCEnrichment:
    """Enriched IOC information."""
    ioc_value: str
    ioc_type: str
    threat_level: ThreatLevel
    reputation_score: float  # 0.0 (benign) to 1.0 (malicious)
    confidence: float
    tags: List[str]
    associated_malware: List[str]
    associated_actors: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    sources: List[str] = None
    context: Optional[str] = None

    def __post_init__(self):
        if self.sources is None:
            self.sources = []


class ThreatIntelligenceEngine:
    """Advanced threat intelligence correlation and enrichment engine."""

    def __init__(self):
        self.apt_database = self._load_apt_database()
        self.malware_database = self._load_malware_database()
        self.attack_patterns = self._load_attack_patterns()
        self.known_bad_ips = self._load_known_bad_ips()
        self.known_bad_domains = self._load_known_bad_domains()
        self.c2_infrastructure = self._load_c2_infrastructure()

    def _load_apt_database(self) -> Dict:
        """Load comprehensive APT group database."""
        return {
            "APT28": {
                "aliases": ["Fancy Bear", "Sofacy", "Sednit", "Pawn Storm", "STRONTIUM"],
                "origin": "Russia",
                "motivation": "Espionage, Political",
                "targets": ["Government", "Military", "Media", "Critical Infrastructure"],
                "ttps": ["T1566.001", "T1078", "T1059.001", "T1071.001", "T1027"],
                "tools": ["X-Agent", "Sofacy", "Zebrocy", "Cannon"],
                "sophistication": "Advanced"
            },
            "APT29": {
                "aliases": ["Cozy Bear", "The Dukes", "CozyDuke", "YTTRIUM"],
                "origin": "Russia",
                "motivation": "Espionage, Intelligence Gathering",
                "targets": ["Government", "Think Tanks", "Healthcare", "Energy"],
                "ttps": ["T1566.002", "T1059.001", "T1071.001", "T1027.002", "T1055"],
                "tools": ["WellMess", "WellMail", "CozyDuke", "SeaDuke"],
                "sophistication": "Advanced"
            },
            "Lazarus": {
                "aliases": ["Hidden Cobra", "Guardians of Peace", "ZINC", "Labyrinth Chollima"],
                "origin": "North Korea",
                "motivation": "Financial Gain, Espionage, Disruption",
                "targets": ["Financial", "Cryptocurrency", "Defense", "Media"],
                "ttps": ["T1566.001", "T1204.002", "T1059.003", "T1486", "T1490"],
                "tools": ["BLINDINGCAN", "COPPERHEDGE", "ECCENTRICBANDWAGON"],
                "sophistication": "Advanced"
            },
            "APT41": {
                "aliases": ["Winnti", "Barium", "Wicked Panda", "Double Dragon"],
                "origin": "China",
                "motivation": "Espionage, Financial Gain",
                "targets": ["Gaming", "Healthcare", "Telecom", "Technology"],
                "ttps": ["T1195.002", "T1078", "T1059.001", "T1027", "T1071.001"],
                "tools": ["Winnti", "PlugX", "Cobalt Strike", "Crosswalk"],
                "sophistication": "Advanced"
            },
            "FIN7": {
                "aliases": ["Carbanak Group", "Navigator Group"],
                "origin": "Unknown (Eastern Europe suspected)",
                "motivation": "Financial Gain",
                "targets": ["Retail", "Hospitality", "Financial Services"],
                "ttps": ["T1566.001", "T1204.002", "T1059.003", "T1003.001", "T1041"],
                "tools": ["Carbanak", "GRIFFON", "POWERSOURCE", "BOOSTWRITE"],
                "sophistication": "Advanced"
            },
            "APT33": {
                "aliases": ["Elfin", "Holmium", "Refined Kitten"],
                "origin": "Iran",
                "motivation": "Espionage, Disruption",
                "targets": ["Aviation", "Energy", "Government", "Defense"],
                "ttps": ["T1566.001", "T1059.001", "T1003.001", "T1071.001", "T1027"],
                "tools": ["SHAPESHIFT", "DROPSHOT", "TURNEDUP", "NANOCORE"],
                "sophistication": "Moderate to Advanced"
            },
            "APT34": {
                "aliases": ["OilRig", "Helix Kitten", "Cobalt Gypsy"],
                "origin": "Iran",
                "motivation": "Espionage",
                "targets": ["Financial", "Government", "Energy", "Chemical"],
                "ttps": ["T1566.001", "T1059.001", "T1071.001", "T1027", "T1003"],
                "tools": ["POWBAT", "BONDUPDATER", "QUADAGENT", "RDAT"],
                "sophistication": "Moderate"
            }
        }

    def _load_malware_database(self) -> Dict:
        """Load comprehensive malware family database."""
        return {
            "cryptominer": {
                "families": ["XMRig", "Minergate", "Coinhive", "CoinHive", "JSEcoin", "CryptoLoot"],
                "indicators": ["xmrig", "minergate", "coinhive", "cryptonight", "monero", "stratum+tcp"],
                "behaviors": ["High CPU usage", "Network connections to mining pools", "Process injection"],
                "mitre_ttps": ["T1496", "T1059", "T1053", "T1027"],
                "severity": "MEDIUM"
            },
            "ransomware": {
                "families": ["Ryuk", "Conti", "LockBit", "BlackCat", "REvil", "DarkSide", "Hive", "BlackMatter"],
                "indicators": [".ryuk", ".conti", ".lockbit", "ransom", "decrypt", "payment"],
                "behaviors": ["File encryption", "Shadow copy deletion", "Backup deletion", "Lateral movement"],
                "mitre_ttps": ["T1486", "T1490", "T1489", "T1083", "T1082"],
                "severity": "CRITICAL"
            },
            "backdoor": {
                "families": ["Cobalt Strike", "Meterpreter", "Empire", "Covenant", "Sliver", "Mythic"],
                "indicators": ["beacon", "meterpreter", "empire", "covenant", "sliver", "C2"],
                "behaviors": ["Command execution", "Persistence", "Credential dumping", "Lateral movement"],
                "mitre_ttps": ["T1071", "T1059", "T1003", "T1021", "T1547"],
                "severity": "HIGH"
            },
            "trojan": {
                "families": ["Emotet", "TrickBot", "Qakbot", "IcedID", "BazarLoader", "Dridex"],
                "indicators": ["emotet", "trickbot", "qakbot", "icedid", "bazar", "dridex"],
                "behaviors": ["Email spreading", "Credential theft", "Banking fraud", "Payload delivery"],
                "mitre_ttps": ["T1566.001", "T1204.002", "T1003", "T1071.001", "T1027"],
                "severity": "HIGH"
            },
            "infostealer": {
                "families": ["RedLine", "Raccoon", "Vidar", "AZORult", "Formbook", "AgentTesla"],
                "indicators": ["redline", "raccoon", "vidar", "azorult", "formbook", "agenttesla"],
                "behaviors": ["Credential harvesting", "Browser data theft", "Keylogging", "Screenshot capture"],
                "mitre_ttps": ["T1555", "T1056.001", "T1113", "T1005", "T1041"],
                "severity": "HIGH"
            },
            "webshell": {
                "families": ["China Chopper", "WSO", "C99", "R57", "B374k", "JspSpy"],
                "indicators": ["chopper", "wso", "c99", "r57", "b374k", "jspspy", "eval", "base64_decode"],
                "behaviors": ["Remote command execution", "File upload", "Database access", "Privilege escalation"],
                "mitre_ttps": ["T1505.003", "T1059", "T1083", "T1005", "T1071.001"],
                "severity": "HIGH"
            }
        }

    def _load_attack_patterns(self) -> Dict:
        """Load attack pattern signatures."""
        return {
            "cryptojacking": {
                "ttps": ["T1496", "T1059", "T1053", "T1027", "T1071"],
                "indicators": ["mining pool", "stratum", "xmrig", "high cpu", "cryptonight"],
                "confidence_threshold": 0.7
            },
            "ransomware": {
                "ttps": ["T1486", "T1490", "T1489", "T1083", "T1082", "T1047"],
                "indicators": ["encrypt", "ransom", "shadow copy", "vssadmin", "bcdedit"],
                "confidence_threshold": 0.8
            },
            "data_exfiltration": {
                "ttps": ["T1048", "T1041", "T1567", "T1020", "T1030", "T1537"],
                "indicators": ["large upload", "cloud storage", "ftp", "sftp", "exfil"],
                "confidence_threshold": 0.75
            },
            "lateral_movement": {
                "ttps": ["T1021.001", "T1021.002", "T1021.006", "T1570", "T1080"],
                "indicators": ["psexec", "wmi", "rdp", "smb", "admin$", "c$"],
                "confidence_threshold": 0.7
            },
            "credential_access": {
                "ttps": ["T1003.001", "T1003.002", "T1003.003", "T1555", "T1056.001"],
                "indicators": ["lsass", "sam", "mimikatz", "procdump", "keylog"],
                "confidence_threshold": 0.8
            },
            "persistence": {
                "ttps": ["T1547.001", "T1053.005", "T1543.003", "T1136", "T1098"],
                "indicators": ["registry run", "scheduled task", "service", "account creation"],
                "confidence_threshold": 0.7
            }
        }

    def _load_known_bad_ips(self) -> Dict:
        """Load known malicious IP addresses (sample data)."""
        return {
            "198.51.100.0/24": {"type": "C2", "malware": ["Cobalt Strike"], "severity": "HIGH"},
            "203.0.113.0/24": {"type": "Scanning", "malware": ["Mirai"], "severity": "MEDIUM"},
            "192.0.2.0/24": {"type": "Phishing", "malware": ["Emotet"], "severity": "HIGH"},
        }

    def _load_known_bad_domains(self) -> Dict:
        """Load known malicious domains (sample data)."""
        return {
            "evil-c2.example.com": {"type": "C2", "malware": ["APT28"], "severity": "CRITICAL"},
            "phishing-site.example.com": {"type": "Phishing", "malware": ["Emotet"], "severity": "HIGH"},
            "mining-pool.example.com": {"type": "Mining", "malware": ["XMRig"], "severity": "MEDIUM"},
        }

    def _load_c2_infrastructure(self) -> Dict:
        """Load known C2 infrastructure patterns."""
        return {
            "cobalt_strike": {
                "patterns": ["beacon", "malleable", "stager"],
                "ports": [80, 443, 8080, 8443, 50050],
                "user_agents": ["Mozilla/5.0 (compatible; MSIE"]
            },
            "metasploit": {
                "patterns": ["meterpreter", "reverse_tcp", "reverse_https"],
                "ports": [4444, 4445, 8080, 443],
                "user_agents": []
            }
        }

    def enrich_ioc(self, ioc_value: str, ioc_type: str) -> IOCEnrichment:
        """
        Enrich an IOC with threat intelligence.

        Args:
            ioc_value: The IOC value (IP, domain, hash, etc.)
            ioc_type: Type of IOC (ip, domain, hash, url, etc.)

        Returns:
            IOCEnrichment object with threat intelligence
        """
        logger.debug(f"Enriching IOC: {ioc_type}={ioc_value}")

        if ioc_type == "ip":
            return self._enrich_ip(ioc_value)
        elif ioc_type == "domain":
            return self._enrich_domain(ioc_value)
        elif ioc_type == "hash":
            return self._enrich_hash(ioc_value)
        elif ioc_type == "url":
            return self._enrich_url(ioc_value)
        else:
            return IOCEnrichment(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                threat_level=ThreatLevel.UNKNOWN,
                reputation_score=0.5,
                confidence=0.3,
                tags=[],
                associated_malware=[],
                associated_actors=[],
                sources=["local"]
            )

    def _enrich_ip(self, ip: str) -> IOCEnrichment:
        """Enrich IP address with threat intelligence."""
        tags = []
        malware = []
        actors = []
        reputation = 0.5  # Neutral
        threat_level = ThreatLevel.UNKNOWN
        confidence = 0.5

        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check if private IP
            if ip_obj.is_private:
                tags.append("private")
                reputation = 0.3
                threat_level = ThreatLevel.LOW
                confidence = 0.9

            # Check against known bad IPs
            for bad_network, info in self.known_bad_ips.items():
                if ip_obj in ipaddress.ip_network(bad_network):
                    tags.append(info["type"])
                    malware.extend(info["malware"])
                    reputation = 0.9
                    threat_level = ThreatLevel(info["severity"])
                    confidence = 0.85
                    break

            # Check for cloud provider IPs (AWS, GCP, Azure)
            if self._is_cloud_ip(ip):
                tags.append("cloud_provider")
                reputation = 0.4

        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            confidence = 0.2

        return IOCEnrichment(
            ioc_value=ip,
            ioc_type="ip",
            threat_level=threat_level,
            reputation_score=reputation,
            confidence=confidence,
            tags=tags,
            associated_malware=malware,
            associated_actors=actors,
            sources=["local_db", "pattern_matching"]
        )

    def _enrich_domain(self, domain: str) -> IOCEnrichment:
        """Enrich domain with threat intelligence."""
        tags = []
        malware = []
        actors = []
        reputation = 0.5
        threat_level = ThreatLevel.UNKNOWN
        confidence = 0.5

        # Check against known bad domains
        if domain in self.known_bad_domains:
            info = self.known_bad_domains[domain]
            tags.append(info["type"])
            malware.extend(info["malware"])
            reputation = 0.95
            threat_level = ThreatLevel(info["severity"])
            confidence = 0.9

        # Check for suspicious patterns
        suspicious_keywords = ["evil", "malware", "phish", "hack", "exploit", "payload"]
        if any(keyword in domain.lower() for keyword in suspicious_keywords):
            tags.append("suspicious_keyword")
            reputation = min(reputation + 0.2, 1.0)
            confidence = 0.6

        # Check for DGA-like patterns (Domain Generation Algorithm)
        if self._is_dga_domain(domain):
            tags.append("possible_dga")
            reputation = min(reputation + 0.3, 1.0)
            threat_level = ThreatLevel.MEDIUM
            confidence = 0.7

        return IOCEnrichment(
            ioc_value=domain,
            ioc_type="domain",
            threat_level=threat_level,
            reputation_score=reputation,
            confidence=confidence,
            tags=tags,
            associated_malware=malware,
            associated_actors=actors,
            sources=["local_db", "pattern_analysis"]
        )

    def _enrich_hash(self, file_hash: str) -> IOCEnrichment:
        """Enrich file hash with threat intelligence."""
        # In production, this would query VirusTotal, MalwareBazaar, etc.
        return IOCEnrichment(
            ioc_value=file_hash,
            ioc_type="hash",
            threat_level=ThreatLevel.UNKNOWN,
            reputation_score=0.5,
            confidence=0.3,
            tags=["needs_external_lookup"],
            associated_malware=[],
            associated_actors=[],
            sources=["local"]
        )

    def _enrich_url(self, url: str) -> IOCEnrichment:
        """Enrich URL with threat intelligence."""
        # Extract domain from URL
        domain_match = re.search(r'://([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            domain_enrichment = self._enrich_domain(domain)
            return IOCEnrichment(
                ioc_value=url,
                ioc_type="url",
                threat_level=domain_enrichment.threat_level,
                reputation_score=domain_enrichment.reputation_score,
                confidence=domain_enrichment.confidence,
                tags=domain_enrichment.tags + ["url"],
                associated_malware=domain_enrichment.associated_malware,
                associated_actors=domain_enrichment.associated_actors,
                sources=domain_enrichment.sources
            )

        return IOCEnrichment(
            ioc_value=url,
            ioc_type="url",
            threat_level=ThreatLevel.UNKNOWN,
            reputation_score=0.5,
            confidence=0.3,
            tags=[],
            associated_malware=[],
            associated_actors=[],
            sources=["local"]
        )

    def _is_cloud_ip(self, ip: str) -> bool:
        """Check if IP belongs to major cloud providers."""
        # Simplified check - in production, use official IP ranges
        cloud_ranges = [
            "3.0.0.0/8",      # AWS (partial)
            "34.0.0.0/8",     # GCP (partial)
            "13.64.0.0/11",   # Azure (partial)
        ]

        try:
            ip_obj = ipaddress.ip_address(ip)
            for cloud_range in cloud_ranges:
                if ip_obj in ipaddress.ip_network(cloud_range):
                    return True
        except ValueError:
            pass

        return False

    def _is_dga_domain(self, domain: str) -> bool:
        """Detect potential DGA (Domain Generation Algorithm) domains."""
        # Remove TLD
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return False

        subdomain = domain_parts[0]

        # DGA characteristics
        if len(subdomain) > 15:  # Long random strings
            vowels = sum(1 for c in subdomain if c in 'aeiou')
            consonants = len(subdomain) - vowels

            # Low vowel ratio
            if vowels / len(subdomain) < 0.2:
                return True

            # High consonant clusters
            consonant_clusters = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', subdomain)
            if len(consonant_clusters) > 0:
                return True

        return False

    def correlate_apt_group(self, ttps: List[str], tools: List[str], targets: List[str]) -> List[Tuple[str, float]]:
        """
        Correlate observed TTPs, tools, and targets with known APT groups.

        Returns:
            List of (apt_group_name, confidence_score) tuples
        """
        matches = []

        for apt_name, apt_data in self.apt_database.items():
            score = 0.0
            max_score = 0.0

            # TTP matching (weight: 0.5)
            if ttps:
                ttp_matches = len(set(ttps) & set(apt_data["ttps"]))
                ttp_score = ttp_matches / len(apt_data["ttps"]) if apt_data["ttps"] else 0
                score += ttp_score * 0.5
                max_score += 0.5

            # Tool matching (weight: 0.3)
            if tools:
                tool_matches = sum(1 for tool in tools if any(apt_tool.lower() in tool.lower() for apt_tool in apt_data["tools"]))
                tool_score = tool_matches / len(apt_data["tools"]) if apt_data["tools"] else 0
                score += tool_score * 0.3
                max_score += 0.3

            # Target matching (weight: 0.2)
            if targets:
                target_matches = sum(1 for target in targets if any(apt_target.lower() in target.lower() for apt_target in apt_data["targets"]))
                target_score = target_matches / len(apt_data["targets"]) if apt_data["targets"] else 0
                score += target_score * 0.2
                max_score += 0.2

            if max_score > 0:
                confidence = score / max_score
                if confidence > 0.3:  # Threshold for inclusion
                    matches.append((apt_name, confidence))

        # Sort by confidence descending
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[:5]  # Top 5 matches
