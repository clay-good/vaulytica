"""AWS GuardDuty parser."""

from datetime import datetime
from typing import Any, Dict
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo, TechnicalIndicator, MitreAttack
)
from .base import BaseParser


class GuardDutyParser(BaseParser):
    """Parser for AWS GuardDuty findings."""
    
    SEVERITY_MAP = {
        "LOW": Severity.LOW,
        "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH,
        "CRITICAL": Severity.CRITICAL,
    }
    
    CATEGORY_MAP = {
        "UnauthorizedAccess": EventCategory.UNAUTHORIZED_ACCESS,
        "Recon": EventCategory.RECONNAISSANCE,
        "Trojan": EventCategory.MALWARE,
        "Backdoor": EventCategory.PERSISTENCE,
        "CryptoCurrency": EventCategory.MALWARE,
        "Exfiltration": EventCategory.DATA_EXFILTRATION,
        "Impact": EventCategory.MALWARE,
        "PrivilegeEscalation": EventCategory.PRIVILEGE_ESCALATION,
        "DefenseEvasion": EventCategory.DEFENSE_EVASION,
        "Policy": EventCategory.POLICY_VIOLATION,
    }
    
    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Validate GuardDuty finding structure."""
        required_fields = ["Id", "Type", "Severity", "CreatedAt", "Description"]
        return all(field in raw_event for field in required_fields)
    
    def parse(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Parse GuardDuty finding into SecurityEvent."""
        
        if not self.validate(raw_event):
            raise ValueError("Invalid GuardDuty finding structure")
        
        severity = self._parse_severity(raw_event.get("Severity", 0))
        category = self._parse_category(raw_event.get("Type", ""))
        
        assets = self._extract_assets(raw_event)
        indicators = self._extract_indicators(raw_event)
        mitre = self._extract_mitre(raw_event)
        
        return SecurityEvent(
            event_id=raw_event["Id"],
            source_system="AWS GuardDuty",
            timestamp=datetime.fromisoformat(raw_event["CreatedAt"].replace("Z", "+00:00")),
            severity=severity,
            category=category,
            title=raw_event["Type"],
            description=raw_event["Description"],
            affected_assets=assets,
            technical_indicators=indicators,
            mitre_attack=mitre,
            raw_event=raw_event,
            confidence_score=raw_event.get("Confidence", 100) / 100.0,
        )
    
    def _parse_severity(self, severity_value: float) -> Severity:
        """Convert GuardDuty severity score to normalized severity."""
        if severity_value >= 7.0:
            return Severity.HIGH
        elif severity_value >= 4.0:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _parse_category(self, finding_type: str) -> EventCategory:
        """Extract category from GuardDuty finding type."""
        for key, category in self.CATEGORY_MAP.items():
            if key in finding_type:
                return category
        return EventCategory.UNKNOWN
    
    def _extract_assets(self, raw_event: Dict[str, Any]) -> list[AssetInfo]:
        """Extract affected assets from GuardDuty finding."""
        assets = []
        
        resource = raw_event.get("Resource", {})
        instance_details = resource.get("InstanceDetails", {})
        
        if instance_details:
            ip_addresses = []
            for iface in instance_details.get("NetworkInterfaces", []):
                if private_ip := iface.get("PrivateIpAddress"):
                    ip_addresses.append(private_ip)
                if public_ip := iface.get("PublicIp"):
                    ip_addresses.append(public_ip)
            
            tags = {tag["Key"]: tag["Value"] for tag in instance_details.get("Tags", [])}
            
            assets.append(AssetInfo(
                hostname=instance_details.get("InstanceId"),
                ip_addresses=ip_addresses,
                cloud_resource_id=resource.get("ResourceType"),
                environment=tags.get("Environment", "unknown"),
                tags=tags,
            ))
        
        return assets
    
    def _extract_indicators(self, raw_event: Dict[str, Any]) -> list[TechnicalIndicator]:
        """Extract technical indicators from GuardDuty finding."""
        indicators = []
        
        service = raw_event.get("Service", {})
        action = service.get("Action", {})
        
        if action_type := action.get("ActionType"):
            if action_type == "NETWORK_CONNECTION":
                network = action.get("NetworkConnectionAction", {})
                if remote_ip := network.get("RemoteIpDetails", {}).get("IpAddressV4"):
                    indicators.append(TechnicalIndicator(
                        indicator_type="ip_address",
                        value=remote_ip,
                        context=f"Remote connection on port {network.get('RemotePortDetails', {}).get('Port')}"
                    ))
            elif action_type == "DNS_REQUEST":
                dns = action.get("DnsRequestAction", {})
                if domain := dns.get("Domain"):
                    indicators.append(TechnicalIndicator(
                        indicator_type="domain",
                        value=domain,
                        context="DNS query"
                    ))
        
        return indicators
    
    def _extract_mitre(self, raw_event: Dict[str, Any]) -> list[MitreAttack]:
        """Map GuardDuty finding to MITRE ATT&CK."""
        mitre_mappings = []
        finding_type = raw_event.get("Type", "")
        
        if "Recon" in finding_type:
            mitre_mappings.append(MitreAttack(
                technique_id="T1595",
                technique_name="Active Scanning",
                tactic="Reconnaissance",
                confidence=0.8
            ))
        elif "UnauthorizedAccess" in finding_type:
            mitre_mappings.append(MitreAttack(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Initial Access",
                confidence=0.7
            ))
        elif "Backdoor" in finding_type:
            mitre_mappings.append(MitreAttack(
                technique_id="T1071",
                technique_name="Application Layer Protocol",
                tactic="Command and Control",
                confidence=0.8
            ))
        
        return mitre_mappings

