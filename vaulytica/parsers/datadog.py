"""Datadog Security Monitoring parser."""

from datetime import datetime
from typing import Any, Dict
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo, TechnicalIndicator, MitreAttack
)
from .base import BaseParser


class DatadogParser(BaseParser):
    """Parser for Datadog Security Monitoring signals."""
    
    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    
    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Validate Datadog signal structure."""
        required_fields = ["id", "type", "attributes"]
        if not all(field in raw_event for field in required_fields):
            return False
        
        if raw_event.get("type") != "signal":
            return False
        
        attrs = raw_event.get("attributes", {})
        return "message" in attrs and "timestamp" in attrs
    
    def parse(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Parse Datadog signal into SecurityEvent."""
        
        if not self.validate(raw_event):
            raise ValueError("Invalid Datadog signal structure")
        
        attrs = raw_event["attributes"]
        
        severity = self._parse_severity(attrs.get("severity", "medium"))
        category = self._parse_category(attrs.get("rule", {}).get("name", ""))
        
        assets = self._extract_assets(attrs)
        indicators = self._extract_indicators(attrs)
        mitre = self._extract_mitre(attrs)
        
        return SecurityEvent(
            event_id=raw_event["id"],
            source_system="Datadog Security Monitoring",
            timestamp=datetime.fromtimestamp(attrs["timestamp"] / 1000),
            severity=severity,
            category=category,
            title=attrs.get("rule", {}).get("name", "Unknown Signal"),
            description=attrs.get("message", ""),
            affected_assets=assets,
            technical_indicators=indicators,
            mitre_attack=mitre,
            raw_event=raw_event,
            confidence_score=1.0,
        )
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Convert Datadog severity to normalized severity."""
        return self.SEVERITY_MAP.get(severity_str.lower(), Severity.MEDIUM)
    
    def _parse_category(self, rule_name: str) -> EventCategory:
        """Extract category from rule name."""
        rule_lower = rule_name.lower()
        
        if "unauthorized" in rule_lower or "access" in rule_lower:
            return EventCategory.UNAUTHORIZED_ACCESS
        elif "malware" in rule_lower or "virus" in rule_lower:
            return EventCategory.MALWARE
        elif "exfiltration" in rule_lower or "data leak" in rule_lower:
            return EventCategory.DATA_EXFILTRATION
        elif "policy" in rule_lower or "compliance" in rule_lower:
            return EventCategory.POLICY_VIOLATION
        elif "vulnerability" in rule_lower or "cve" in rule_lower:
            return EventCategory.VULNERABILITY
        elif "recon" in rule_lower or "scan" in rule_lower:
            return EventCategory.RECONNAISSANCE
        elif "lateral" in rule_lower:
            return EventCategory.LATERAL_MOVEMENT
        elif "persistence" in rule_lower:
            return EventCategory.PERSISTENCE
        elif "privilege" in rule_lower or "escalation" in rule_lower:
            return EventCategory.PRIVILEGE_ESCALATION
        else:
            return EventCategory.UNKNOWN
    
    def _extract_assets(self, attrs: Dict[str, Any]) -> list[AssetInfo]:
        """Extract affected assets from Datadog signal."""
        assets = []
        
        tags = attrs.get("tags", [])
        custom_attrs = attrs.get("custom", {})
        
        hostname = None
        ip_addresses = []
        environment = "unknown"
        asset_tags = {}
        
        for tag in tags:
            if tag.startswith("host:"):
                hostname = tag.split(":", 1)[1]
            elif tag.startswith("ip:"):
                ip_addresses.append(tag.split(":", 1)[1])
            elif tag.startswith("env:"):
                environment = tag.split(":", 1)[1]
            else:
                parts = tag.split(":", 1)
                if len(parts) == 2:
                    asset_tags[parts[0]] = parts[1]
        
        if hostname or ip_addresses:
            assets.append(AssetInfo(
                hostname=hostname,
                ip_addresses=ip_addresses,
                environment=environment,
                tags=asset_tags,
            ))
        
        return assets
    
    def _extract_indicators(self, attrs: Dict[str, Any]) -> list[TechnicalIndicator]:
        """Extract technical indicators from Datadog signal."""
        indicators = []
        
        custom = attrs.get("custom", {})
        
        if "source_ip" in custom:
            indicators.append(TechnicalIndicator(
                indicator_type="ip_address",
                value=custom["source_ip"],
                context="Source IP from signal"
            ))
        
        if "destination_ip" in custom:
            indicators.append(TechnicalIndicator(
                indicator_type="ip_address",
                value=custom["destination_ip"],
                context="Destination IP from signal"
            ))
        
        if "domain" in custom:
            indicators.append(TechnicalIndicator(
                indicator_type="domain",
                value=custom["domain"],
                context="Domain from signal"
            ))
        
        if "file_hash" in custom:
            indicators.append(TechnicalIndicator(
                indicator_type="file_hash",
                value=custom["file_hash"],
                context="File hash from signal"
            ))
        
        if "process_name" in custom:
            indicators.append(TechnicalIndicator(
                indicator_type="process",
                value=custom["process_name"],
                context="Process name from signal"
            ))
        
        return indicators
    
    def _extract_mitre(self, attrs: Dict[str, Any]) -> list[MitreAttack]:
        """Map Datadog signal to MITRE ATT&CK."""
        mitre_mappings = []
        
        rule_name = attrs.get("rule", {}).get("name", "").lower()
        
        if "brute force" in rule_name or "password spray" in rule_name:
            mitre_mappings.append(MitreAttack(
                technique_id="T1110",
                technique_name="Brute Force",
                tactic="Credential Access",
                confidence=0.8
            ))
        elif "privilege escalation" in rule_name:
            mitre_mappings.append(MitreAttack(
                technique_id="T1068",
                technique_name="Exploitation for Privilege Escalation",
                tactic="Privilege Escalation",
                confidence=0.7
            ))
        elif "lateral movement" in rule_name:
            mitre_mappings.append(MitreAttack(
                technique_id="T1021",
                technique_name="Remote Services",
                tactic="Lateral Movement",
                confidence=0.7
            ))
        elif "data exfiltration" in rule_name:
            mitre_mappings.append(MitreAttack(
                technique_id="T1048",
                technique_name="Exfiltration Over Alternative Protocol",
                tactic="Exfiltration",
                confidence=0.8
            ))
        
        return mitre_mappings

