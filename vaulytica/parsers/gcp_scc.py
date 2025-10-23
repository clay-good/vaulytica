"""GCP Security Command Center parser."""

from datetime import datetime
from typing import Any, Dict
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo, TechnicalIndicator, MitreAttack
)
from .base import BaseParser


class GCPSecurityCommandCenterParser(BaseParser):
    """Parser for GCP Security Command Center findings."""

    SEVERITY_MAP = {
        "LOW": Severity.LOW,
        "MEDIUM": Severity.MEDIUM,
        "HIGH": Severity.HIGH,
        "CRITICAL": Severity.CRITICAL,
    }

    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Validate GCP SCC finding structure."""
        required_fields = ["name", "category", "severity", "eventTime"]
        return all(field in raw_event for field in required_fields)

    def parse(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Parse GCP SCC finding into SecurityEvent."""

        if not self.validate(raw_event):
            raise ValueError("Invalid GCP SCC finding structure")

        severity = self.SEVERITY_MAP.get(raw_event.get("severity", "LOW"), Severity.LOW)
        category = self._parse_category(raw_event.get("category", ""))

        assets = self._extract_assets(raw_event)
        indicators = self._extract_indicators(raw_event)
        mitre = self._extract_mitre(raw_event)

        return SecurityEvent(
            event_id=raw_event["name"].split("/")[-1],
            source_system="GCP Security Command Center",
            timestamp=datetime.fromisoformat(raw_event["eventTime"].replace("Z", "+00:00")),
            severity=severity,
            category=category,
            title=raw_event["category"],
            description=raw_event.get("description", raw_event["category"]),
            affected_assets=assets,
            technical_indicators=indicators,
            mitre_attack=mitre,
            raw_event=raw_event,
            confidence_score=1.0,
        )

    def _parse_category(self, category: str) -> EventCategory:
        """Map GCP SCC category to normalized category."""
        category_lower = category.lower()

        if "unauthorized" in category_lower or "access" in category_lower:
            return EventCategory.UNAUTHORIZED_ACCESS
        elif "malware" in category_lower:
            return EventCategory.MALWARE
        elif "exfiltration" in category_lower:
            return EventCategory.DATA_EXFILTRATION
        elif "vulnerability" in category_lower or "misconfiguration" in category_lower:
            return EventCategory.VULNERABILITY
        elif "persistence" in category_lower:
            return EventCategory.PERSISTENCE
        else:
            return EventCategory.UNKNOWN

    def _extract_assets(self, raw_event: Dict[str, Any]) -> list[AssetInfo]:
        """Extract affected assets from GCP SCC finding."""
        assets = []

        resource = raw_event.get("resource", {})
        if resource:
            assets.append(AssetInfo(
                hostname=resource.get("displayName"),
                cloud_resource_id=resource.get("name"),
                environment=resource.get("projectDisplayName", "unknown"),
                tags=resource.get("labels", {}),
            ))

        return assets

    def _extract_indicators(self, raw_event: Dict[str, Any]) -> list[TechnicalIndicator]:
        """Extract technical indicators from GCP SCC finding."""
        indicators = []

        source_properties = raw_event.get("sourceProperties", {})

        if ip_addresses := source_properties.get("ipAddresses"):
            for ip in ip_addresses:
                indicators.append(TechnicalIndicator(
                    indicator_type="ip_address",
                    value=ip,
                    context="Associated IP address"
                ))

        if domains := source_properties.get("domains"):
            for domain in domains:
                indicators.append(TechnicalIndicator(
                    indicator_type="domain",
                    value=domain,
                    context="Associated domain"
                ))

        return indicators

    def _extract_mitre(self, raw_event: Dict[str, Any]) -> list[MitreAttack]:
        """Map GCP SCC finding to MITRE ATT&CK."""
        mitre_mappings = []
        category = raw_event.get("category", "").lower()

        if "persistence" in category:
            mitre_mappings.append(MitreAttack(
                technique_id="T1098",
                technique_name="Account Manipulation",
                tactic="Persistence",
                confidence=0.7
            ))
        elif "privilege" in category:
            mitre_mappings.append(MitreAttack(
                technique_id="T1068",
                technique_name="Exploitation for Privilege Escalation",
                tactic="Privilege Escalation",
                confidence=0.7
            ))

        return mitre_mappings
