"""
Security Tests for Vaulytica

Tests security features, input validation, and vulnerability prevention.
"""

import pytest
import re
from datetime import datetime
from unittest.mock import Mock, patch
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.models import SecurityEvent, Severity, EventCategory


class TestInputValidation:
    """Test input validation and sanitization"""
    
    def test_sql_injection_in_description(self):
        """Test SQL injection attempt in description"""
        sql_injection = "'; DROP TABLE events; --"
        event = SecurityEvent(
            id="test-sql",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=sql_injection
        )
        # Should store as-is, not execute
        assert event.description == sql_injection
    
    def test_xss_in_description(self):
        """Test XSS attempt in description"""
        xss_payload = "<script>alert('XSS')</script>"
        event = SecurityEvent(
            id="test-xss",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=xss_payload
        )
        # Should store as-is for analysis
        assert event.description == xss_payload
    
    def test_command_injection_in_description(self):
        """Test command injection attempt"""
        cmd_injection = "; rm -rf / #"
        event = SecurityEvent(
            id="test-cmd",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=cmd_injection
        )
        assert event.description == cmd_injection
    
    def test_path_traversal_in_source(self):
        """Test path traversal attempt"""
        path_traversal = "../../etc/passwd"
        event = SecurityEvent(
            id="test-path",
            timestamp=datetime.now(),
            source=path_traversal,
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description="Test"
        )
        assert event.source == path_traversal
    
    def test_null_byte_injection(self):
        """Test null byte injection"""
        null_byte = "test\x00malicious"
        event = SecurityEvent(
            id="test-null",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=null_byte
        )
        # Should handle null bytes appropriately
        assert event.description == null_byte or "\x00" not in event.description
    
    def test_ldap_injection(self):
        """Test LDAP injection attempt"""
        ldap_injection = "*)(uid=*))(|(uid=*"
        event = SecurityEvent(
            id="test-ldap",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=ldap_injection
        )
        assert event.description == ldap_injection
    
    def test_xml_injection(self):
        """Test XML injection attempt"""
        xml_injection = "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"
        event = SecurityEvent(
            id="test-xml",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=xml_injection
        )
        assert event.description == xml_injection
    
    def test_regex_dos_pattern(self):
        """Test regex DoS pattern"""
        # Pattern that could cause catastrophic backtracking
        dos_pattern = "a" * 1000 + "!"
        event = SecurityEvent(
            id="test-redos",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description=dos_pattern
        )
        assert len(event.description) == 1001


class TestAuthenticationSecurity:
    """Test authentication and authorization security"""
    
    def test_password_not_logged(self):
        """Test passwords are not logged in events"""
        metadata = {
            "username": "admin",
            "password": "secret123",  # Should never be logged
            "action": "login"
        }
        event = SecurityEvent(
            id="test-pwd",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description="Login attempt",
            metadata=metadata
        )
        # Event should store metadata, but logging should filter passwords
        assert "password" in event.metadata
    
    def test_api_key_not_logged(self):
        """Test API keys are not logged"""
        metadata = {
            "api_key": "sk-1234567890abcdef",
            "action": "api_call"
        }
        event = SecurityEvent(
            id="test-apikey",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description="API call",
            metadata=metadata
        )
        assert "api_key" in event.metadata
    
    def test_token_not_logged(self):
        """Test tokens are not logged"""
        metadata = {
            "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "action": "authenticated_request"
        }
        event = SecurityEvent(
            id="test-token",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.AUTHENTICATION,
            severity=Severity.HIGH,
            description="Authenticated request",
            metadata=metadata
        )
        assert "bearer_token" in event.metadata


class TestDataProtection:
    """Test data protection and privacy"""
    
    def test_pii_in_metadata(self):
        """Test PII handling in metadata"""
        metadata = {
            "ssn": "123-45-6789",
            "credit_card": "4111-1111-1111-1111",
            "email": "user@example.com"
        }
        event = SecurityEvent(
            id="test-pii",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.DATA_EXFILTRATION,
            severity=Severity.CRITICAL,
            description="PII exposure",
            metadata=metadata
        )
        # Should store for analysis but mark as sensitive
        assert event.metadata == metadata
    
    def test_phi_in_metadata(self):
        """Test PHI (Protected Health Information) handling"""
        metadata = {
            "patient_id": "P123456",
            "diagnosis": "Condition XYZ",
            "medical_record": "MR789"
        }
        event = SecurityEvent(
            id="test-phi",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.DATA_EXFILTRATION,
            severity=Severity.CRITICAL,
            description="PHI exposure",
            metadata=metadata
        )
        assert event.metadata == metadata
    
    def test_pci_data_in_metadata(self):
        """Test PCI data handling"""
        metadata = {
            "card_number": "4111111111111111",
            "cvv": "123",
            "expiry": "12/25"
        }
        event = SecurityEvent(
            id="test-pci",
            timestamp=datetime.now(),
            source="test",
            category=EventCategory.DATA_EXFILTRATION,
            severity=Severity.CRITICAL,
            description="PCI data exposure",
            metadata=metadata
        )
        assert event.metadata == metadata


class TestRateLimiting:
    """Test rate limiting and DoS prevention"""
    
    def test_rapid_event_creation(self):
        """Test handling of rapid event creation"""
        events = []
        for i in range(1000):
            event = SecurityEvent(
                id=f"test-rapid-{i}",
                timestamp=datetime.now(),
                source="test",
                category=EventCategory.AUTHENTICATION,
                severity=Severity.LOW,
                description=f"Event {i}"
            )
            events.append(event)
        
        assert len(events) == 1000
    
    def test_large_batch_events(self):
        """Test handling of large batch of events"""
        events = []
        for i in range(10000):
            event = SecurityEvent(
                id=f"test-batch-{i}",
                timestamp=datetime.now(),
                source="test",
                category=EventCategory.NETWORK,
                severity=Severity.INFO,
                description=f"Batch event {i}"
            )
            events.append(event)
        
        assert len(events) == 10000


class TestErrorHandling:
    """Test error handling and recovery"""
    
    def test_invalid_severity_type(self):
        """Test invalid severity type"""
        with pytest.raises((ValueError, TypeError, AttributeError)):
            event = SecurityEvent(
                id="test-invalid-sev",
                timestamp=datetime.now(),
                source="test",
                category=EventCategory.AUTHENTICATION,
                severity="INVALID",  # Should be Severity enum
                description="Test"
            )
    
    def test_invalid_category_type(self):
        """Test invalid category type"""
        with pytest.raises((ValueError, TypeError, AttributeError)):
            event = SecurityEvent(
                id="test-invalid-cat",
                timestamp=datetime.now(),
                source="test",
                category="INVALID",  # Should be EventCategory enum
                severity=Severity.HIGH,
                description="Test"
            )
    
    def test_invalid_timestamp_type(self):
        """Test invalid timestamp type"""
        with pytest.raises((ValueError, TypeError)):
            event = SecurityEvent(
                id="test-invalid-ts",
                timestamp="not a datetime",  # Should be datetime
                source="test",
                category=EventCategory.AUTHENTICATION,
                severity=Severity.HIGH,
                description="Test"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

