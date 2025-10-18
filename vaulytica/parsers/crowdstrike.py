from datetime import datetime
from typing import Any, Dict
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo, TechnicalIndicator, MitreAttack
)
from .base import BaseParser


class CrowdStrikeParser(BaseParser):
    """Parser for CrowdStrike Falcon detections."""
    
    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFO,
    }
    
    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Validate CrowdStrike detection structure."""
        required_fields = ["detection_id", "severity", "created_timestamp"]
        return all(field in raw_event for field in required_fields)
    
    def parse(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Parse CrowdStrike detection into SecurityEvent."""
        
        if not self.validate(raw_event):
            raise ValueError("Invalid CrowdStrike detection structure")
        
        severity = self._parse_severity(raw_event.get("severity", "medium"))
        category = self._parse_category(raw_event)
        
        assets = self._extract_assets(raw_event)
        indicators = self._extract_indicators(raw_event)
        mitre = self._extract_mitre(raw_event)
        
        return SecurityEvent(
            event_id=raw_event["detection_id"],
            source_system="CrowdStrike Falcon",
            timestamp=datetime.fromtimestamp(raw_event["created_timestamp"]),
            severity=severity,
            category=category,
            title=raw_event.get("tactic", "Unknown Detection"),
            description=raw_event.get("description", raw_event.get("tactic", "")),
            affected_assets=assets,
            technical_indicators=indicators,
            mitre_attack=mitre,
            raw_event=raw_event,
            confidence_score=raw_event.get("confidence", 100) / 100.0,
        )
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Convert CrowdStrike severity to normalized severity."""
        return self.SEVERITY_MAP.get(severity_str.lower(), Severity.MEDIUM)
    
    def _parse_category(self, raw_event: Dict[str, Any]) -> EventCategory:
        """Extract category from CrowdStrike detection."""
        tactic = raw_event.get("tactic", "").lower()
        technique = raw_event.get("technique", "").lower()
        
        if "malware" in tactic or "malware" in technique:
            return EventCategory.MALWARE
        elif "unauthorized" in tactic or "initial access" in tactic:
            return EventCategory.UNAUTHORIZED_ACCESS
        elif "exfiltration" in tactic:
            return EventCategory.DATA_EXFILTRATION
        elif "reconnaissance" in tactic or "discovery" in tactic:
            return EventCategory.RECONNAISSANCE
        elif "lateral movement" in tactic:
            return EventCategory.LATERAL_MOVEMENT
        elif "persistence" in tactic:
            return EventCategory.PERSISTENCE
        elif "privilege escalation" in tactic:
            return EventCategory.PRIVILEGE_ESCALATION
        elif "defense evasion" in tactic:
            return EventCategory.DEFENSE_EVASION
        else:
            return EventCategory.UNKNOWN
    
    def _extract_assets(self, raw_event: Dict[str, Any]) -> list[AssetInfo]:
        """Extract affected assets from CrowdStrike detection."""
        assets = []
        
        device = raw_event.get("device", {})
        
        if device:
            assets.append(AssetInfo(
                hostname=device.get("hostname"),
                ip_addresses=[device.get("local_ip")] if device.get("local_ip") else [],
                cloud_resource_id=device.get("device_id"),
                environment=device.get("tags", {}).get("environment", "unknown"),
                tags=device.get("tags", {}),
            ))
        
        return assets
    
    def _extract_indicators(self, raw_event: Dict[str, Any]) -> list[TechnicalIndicator]:
        """Extract technical indicators from CrowdStrike detection."""
        indicators = []
        
        behaviors = raw_event.get("behaviors", [])
        
        for behavior in behaviors:
            if "filename" in behavior:
                indicators.append(TechnicalIndicator(
                    indicator_type="file",
                    value=behavior["filename"],
                    context=f"File from behavior: {behavior.get('scenario', '')}"
                ))
            
            if "sha256" in behavior:
                indicators.append(TechnicalIndicator(
                    indicator_type="file_hash",
                    value=behavior["sha256"],
                    context="SHA256 hash"
                ))
            
            if "md5" in behavior:
                indicators.append(TechnicalIndicator(
                    indicator_type="file_hash",
                    value=behavior["md5"],
                    context="MD5 hash"
                ))
            
            if "cmdline" in behavior:
                indicators.append(TechnicalIndicator(
                    indicator_type="command_line",
                    value=behavior["cmdline"],
                    context="Command line execution"
                ))
            
            if "parent_cmdline" in behavior:
                indicators.append(TechnicalIndicator(
                    indicator_type="command_line",
                    value=behavior["parent_cmdline"],
                    context="Parent process command line"
                ))
        
        if "network" in raw_event:
            network = raw_event["network"]
            if "remote_ip" in network:
                indicators.append(TechnicalIndicator(
                    indicator_type="ip_address",
                    value=network["remote_ip"],
                    context=f"Remote connection on port {network.get('remote_port', 'unknown')}"
                ))
            
            if "domain" in network:
                indicators.append(TechnicalIndicator(
                    indicator_type="domain",
                    value=network["domain"],
                    context="Network connection"
                ))
        
        return indicators
    
    def _extract_mitre(self, raw_event: Dict[str, Any]) -> list[MitreAttack]:
        """Map CrowdStrike detection to MITRE ATT&CK."""
        mitre_mappings = []
        
        tactic = raw_event.get("tactic", "")
        technique = raw_event.get("technique", "")
        technique_id = raw_event.get("technique_id", "")
        
        if technique_id and technique:
            mitre_mappings.append(MitreAttack(
                technique_id=technique_id,
                technique_name=technique,
                tactic=tactic,
                confidence=0.9
            ))
        else:
            tactic_lower = tactic.lower()
            
            if "malware" in tactic_lower:
                mitre_mappings.append(MitreAttack(
                    technique_id="T1204",
                    technique_name="User Execution",
                    tactic="Execution",
                    confidence=0.7
                ))
            elif "credential" in tactic_lower:
                mitre_mappings.append(MitreAttack(
                    technique_id="T1003",
                    technique_name="OS Credential Dumping",
                    tactic="Credential Access",
                    confidence=0.7
                ))
            elif "persistence" in tactic_lower:
                mitre_mappings.append(MitreAttack(
                    technique_id="T1547",
                    technique_name="Boot or Logon Autostart Execution",
                    tactic="Persistence",
                    confidence=0.7
                ))
        
        return mitre_mappings

