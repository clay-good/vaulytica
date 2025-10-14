"""Snowflake security event parser."""

from datetime import datetime
from typing import Any, Dict
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo, TechnicalIndicator, MitreAttack
)
from .base import BaseParser


class SnowflakeParser(BaseParser):
    """Parser for Snowflake security and audit events."""
    
    SEVERITY_MAP = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }
    
    def validate(self, raw_event: Dict[str, Any]) -> bool:
        """Validate Snowflake event structure."""
        required_fields = ["EVENT_ID", "EVENT_TYPE", "EVENT_TIMESTAMP"]
        return all(field in raw_event for field in required_fields)
    
    def parse(self, raw_event: Dict[str, Any]) -> SecurityEvent:
        """Parse Snowflake event into SecurityEvent."""
        
        if not self.validate(raw_event):
            raise ValueError("Invalid Snowflake event structure")
        
        severity = self._parse_severity(raw_event)
        category = self._parse_category(raw_event)
        
        assets = self._extract_assets(raw_event)
        indicators = self._extract_indicators(raw_event)
        mitre = self._extract_mitre(raw_event)
        
        title = self._generate_title(raw_event)
        description = self._generate_description(raw_event)
        
        return SecurityEvent(
            event_id=raw_event["EVENT_ID"],
            source_system="Snowflake",
            timestamp=datetime.fromisoformat(raw_event["EVENT_TIMESTAMP"].replace('Z', '+00:00')),
            severity=severity,
            category=category,
            title=title,
            description=description,
            affected_assets=assets,
            technical_indicators=indicators,
            mitre_attack=mitre,
            raw_event=raw_event,
            confidence_score=raw_event.get("CONFIDENCE_SCORE", 1.0),
        )
    
    def _parse_severity(self, raw_event: Dict[str, Any]) -> Severity:
        """Determine severity from event type and attributes."""
        
        event_type = raw_event.get("EVENT_TYPE", "").upper()
        severity_str = raw_event.get("SEVERITY", "").upper()
        
        if severity_str in self.SEVERITY_MAP:
            return self.SEVERITY_MAP[severity_str]
        
        if "UNAUTHORIZED" in event_type or "BREACH" in event_type:
            return Severity.CRITICAL
        elif "SUSPICIOUS" in event_type or "ANOMALY" in event_type:
            return Severity.HIGH
        elif "POLICY_VIOLATION" in event_type:
            return Severity.MEDIUM
        else:
            return Severity.LOW
    
    def _parse_category(self, raw_event: Dict[str, Any]) -> EventCategory:
        """Extract category from event type."""
        
        event_type = raw_event.get("EVENT_TYPE", "").upper()
        
        if "UNAUTHORIZED_ACCESS" in event_type or "LOGIN_FAILURE" in event_type:
            return EventCategory.UNAUTHORIZED_ACCESS
        elif "DATA_EXFILTRATION" in event_type or "LARGE_EXPORT" in event_type:
            return EventCategory.DATA_EXFILTRATION
        elif "PRIVILEGE_ESCALATION" in event_type or "ROLE_GRANT" in event_type:
            return EventCategory.PRIVILEGE_ESCALATION
        elif "POLICY_VIOLATION" in event_type:
            return EventCategory.POLICY_VIOLATION
        elif "RECONNAISSANCE" in event_type or "ENUMERATION" in event_type:
            return EventCategory.RECONNAISSANCE
        else:
            return EventCategory.UNKNOWN
    
    def _extract_assets(self, raw_event: Dict[str, Any]) -> list[AssetInfo]:
        """Extract affected assets from Snowflake event."""
        
        assets = []
        
        user_name = raw_event.get("USER_NAME")
        client_ip = raw_event.get("CLIENT_IP")
        database_name = raw_event.get("DATABASE_NAME")
        schema_name = raw_event.get("SCHEMA_NAME")
        warehouse_name = raw_event.get("WAREHOUSE_NAME")
        
        tags = {}
        if database_name:
            tags["database"] = database_name
        if schema_name:
            tags["schema"] = schema_name
        if warehouse_name:
            tags["warehouse"] = warehouse_name
        if raw_event.get("ROLE_NAME"):
            tags["role"] = raw_event["ROLE_NAME"]
        
        if user_name or client_ip:
            assets.append(AssetInfo(
                hostname=user_name,
                ip_addresses=[client_ip] if client_ip else [],
                environment=raw_event.get("ACCOUNT_NAME", "unknown"),
                tags=tags,
            ))
        
        return assets
    
    def _extract_indicators(self, raw_event: Dict[str, Any]) -> list[TechnicalIndicator]:
        """Extract technical indicators from Snowflake event."""
        
        indicators = []
        
        if raw_event.get("CLIENT_IP"):
            indicators.append(TechnicalIndicator(
                indicator_type="ip_address",
                value=raw_event["CLIENT_IP"],
                context=f"Client IP for user {raw_event.get('USER_NAME', 'unknown')}"
            ))
        
        if raw_event.get("USER_NAME"):
            indicators.append(TechnicalIndicator(
                indicator_type="user_account",
                value=raw_event["USER_NAME"],
                context=f"User account involved in {raw_event.get('EVENT_TYPE', 'event')}"
            ))
        
        if raw_event.get("QUERY_TEXT"):
            indicators.append(TechnicalIndicator(
                indicator_type="query",
                value=raw_event["QUERY_TEXT"][:500],
                context="SQL query executed"
            ))
        
        if raw_event.get("SESSION_ID"):
            indicators.append(TechnicalIndicator(
                indicator_type="session_id",
                value=str(raw_event["SESSION_ID"]),
                context="Snowflake session identifier"
            ))
        
        if raw_event.get("BYTES_TRANSFERRED"):
            indicators.append(TechnicalIndicator(
                indicator_type="data_volume",
                value=str(raw_event["BYTES_TRANSFERRED"]),
                context=f"Bytes transferred: {raw_event['BYTES_TRANSFERRED']:,}"
            ))
        
        return indicators
    
    def _extract_mitre(self, raw_event: Dict[str, Any]) -> list[MitreAttack]:
        """Map Snowflake event to MITRE ATT&CK."""
        
        mitre_mappings = []
        event_type = raw_event.get("EVENT_TYPE", "").upper()
        
        if "UNAUTHORIZED_ACCESS" in event_type or "LOGIN_FAILURE" in event_type:
            mitre_mappings.append(MitreAttack(
                technique_id="T1078",
                technique_name="Valid Accounts",
                tactic="Initial Access",
                confidence=0.8
            ))
        
        if "DATA_EXFILTRATION" in event_type or "LARGE_EXPORT" in event_type:
            mitre_mappings.append(MitreAttack(
                technique_id="T1567",
                technique_name="Exfiltration Over Web Service",
                tactic="Exfiltration",
                confidence=0.9
            ))
        
        if "PRIVILEGE_ESCALATION" in event_type or "ROLE_GRANT" in event_type:
            mitre_mappings.append(MitreAttack(
                technique_id="T1098",
                technique_name="Account Manipulation",
                tactic="Privilege Escalation",
                confidence=0.85
            ))
        
        if "RECONNAISSANCE" in event_type or "ENUMERATION" in event_type:
            mitre_mappings.append(MitreAttack(
                technique_id="T1087",
                technique_name="Account Discovery",
                tactic="Discovery",
                confidence=0.75
            ))
        
        if "POLICY_VIOLATION" in event_type:
            mitre_mappings.append(MitreAttack(
                technique_id="T1530",
                technique_name="Data from Cloud Storage Object",
                tactic="Collection",
                confidence=0.7
            ))
        
        return mitre_mappings
    
    def _generate_title(self, raw_event: Dict[str, Any]) -> str:
        """Generate human-readable title."""
        
        event_type = raw_event.get("EVENT_TYPE", "Unknown Event")
        user = raw_event.get("USER_NAME", "Unknown User")
        
        return f"Snowflake {event_type.replace('_', ' ').title()}: {user}"
    
    def _generate_description(self, raw_event: Dict[str, Any]) -> str:
        """Generate detailed description."""
        
        parts = []
        
        event_type = raw_event.get("EVENT_TYPE", "Unknown")
        parts.append(f"Event Type: {event_type}")
        
        if raw_event.get("USER_NAME"):
            parts.append(f"User: {raw_event['USER_NAME']}")
        
        if raw_event.get("CLIENT_IP"):
            parts.append(f"Source IP: {raw_event['CLIENT_IP']}")
        
        if raw_event.get("DATABASE_NAME"):
            parts.append(f"Database: {raw_event['DATABASE_NAME']}")
        
        if raw_event.get("BYTES_TRANSFERRED"):
            bytes_val = raw_event['BYTES_TRANSFERRED']
            parts.append(f"Data Volume: {bytes_val:,} bytes ({bytes_val / (1024**3):.2f} GB)")
        
        if raw_event.get("ERROR_MESSAGE"):
            parts.append(f"Error: {raw_event['ERROR_MESSAGE']}")
        
        return " | ".join(parts)

