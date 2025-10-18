"""
Comprehensive tests for Network Security, DLP & Encryption Management (v0.25.0).

Tests all network security, data loss prevention, and encryption management features.
"""

import asyncio
import sys
from datetime import datetime, timedelta


def print_test_header(test_name: str):
    """Print test header."""
    print(f"\n{'='*80}")
    print(f"🧪 TEST: {test_name}")
    print(f"{'='*80}\n")


def print_success(message: str):
    """Print success message."""
    print(f"✅ {message}")


def print_error(message: str):
    """Print error message."""
    print(f"❌ {message}")


async def test_network_security_analyzer():
    """Test network security analyzer."""
    print_test_header("Network Security Analyzer")
    
    try:
        from vaulytica.network_security import (
            get_network_analyzer,
            FirewallRule,
            FirewallAction,
            NetworkProtocol,
            NetworkFlow
        )
        
        analyzer = get_network_analyzer()
        
        # Test 1: Analyze secure firewall rule
        print("Test 1: Analyzing secure firewall rule...")
        secure_rule = FirewallRule(
            rule_id="rule-001",
            name="Allow HTTPS from specific IP",
            action=FirewallAction.ALLOW,
            protocol=NetworkProtocol.HTTPS,
            source_ip="10.0.1.0/24",
            destination_ip="10.0.2.100",
            destination_port="443"
        )
        
        result = await analyzer.analyze_firewall_rule(secure_rule)
        assert result["is_secure"] == True, "Secure rule should be marked as secure"
        print_success(f"Secure rule analyzed: {result['name']}, Risk Score: {result['risk_score']}")
        
        # Test 2: Analyze insecure firewall rule (allow all)
        print("\nTest 2: Analyzing insecure firewall rule...")
        insecure_rule = FirewallRule(
            rule_id="rule-002",
            name="Allow all traffic",
            action=FirewallAction.ALLOW,
            protocol=NetworkProtocol.TCP,
            source_ip="0.0.0.0/0",
            destination_ip="*",
            destination_port="*"
        )
        
        result = await analyzer.analyze_firewall_rule(insecure_rule)
        assert result["is_secure"] == False, "Insecure rule should be detected"
        assert result["risk_score"] > 5.0, "Insecure rule should have high risk score"
        print_success(f"Insecure rule detected: {len(result['issues'])} issues, Risk Score: {result['risk_score']}")
        
        # Test 3: Analyze network flow to malicious IP
        print("\nTest 3: Analyzing network flow to malicious IP...")
        malicious_flow = NetworkFlow(
            flow_id="flow-001",
            source_ip="10.0.1.50",
            source_port=54321,
            destination_ip="192.0.2.1",  # Known malicious IP in test data
            destination_port=443,
            protocol=NetworkProtocol.HTTPS,
            bytes_sent=1024,
            bytes_received=2048,
            packets_sent=10,
            packets_received=15,
            duration_seconds=5.0
        )
        
        threat = await analyzer.analyze_network_flow(malicious_flow)
        assert threat is not None, "Threat should be detected for malicious IP"
        assert threat.threat_type.value == "c2_communication", "Should detect C2 communication"
        print_success(f"Threat detected: {threat.threat_type.value}, Severity: {threat.severity.value}, Risk: {threat.risk_score}")
        
        # Test 4: Simulate port scanning
        print("\nTest 4: Simulating port scanning detection...")
        for port in range(1, 25):
            flow = NetworkFlow(
                flow_id=f"flow-scan-{port}",
                source_ip="10.0.1.100",
                source_port=54321 + port,
                destination_ip="10.0.2.50",
                destination_port=port,
                protocol=NetworkProtocol.TCP,
                bytes_sent=64,
                bytes_received=0,
                packets_sent=1,
                packets_received=0,
                duration_seconds=0.1
            )
            await analyzer.analyze_network_flow(flow)
        
        # Get statistics
        stats = analyzer.get_statistics()
        assert stats["flows_analyzed"] >= 25, "Should have analyzed multiple flows"
        print_success(f"Port scanning simulation complete: {stats['flows_analyzed']} flows analyzed, {stats['threats_detected']} threats detected")
        
        print_success("✅ Network Security Analyzer: ALL TESTS PASSED")
        return True
        
    except Exception as e:
        print_error(f"Network Security Analyzer test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_data_classifier():
    """Test data classifier."""
    print_test_header("Data Classifier")
    
    try:
        from vaulytica.network_security import get_data_classifier
        
        classifier = get_data_classifier()
        
        # Test 1: Classify content with SSN
        print("Test 1: Classifying content with SSN...")
        content_ssn = """
        Employee Record:
        Name: John Doe
        SSN: 123-45-6789
        Email: john.doe@example.com
        """
        
        sensitive_data = await classifier.classify_data(content_ssn, "employee_records.txt")
        assert len(sensitive_data) > 0, "Should detect sensitive data"
        
        ssn_detected = any(d.data_type.value == "ssn" for d in sensitive_data)
        email_detected = any(d.data_type.value == "email" for d in sensitive_data)
        
        assert ssn_detected, "Should detect SSN"
        assert email_detected, "Should detect email"
        print_success(f"Detected {len(sensitive_data)} sensitive data items (SSN, Email)")
        
        # Test 2: Classify content with credit card
        print("\nTest 2: Classifying content with credit card...")
        content_cc = """
        Payment Information:
        Card Number: 4532-1234-5678-9010
        Expiry: 12/25
        """
        
        sensitive_data = await classifier.classify_data(content_cc, "payment_info.txt")
        cc_detected = any(d.data_type.value == "credit_card" for d in sensitive_data)
        assert cc_detected, "Should detect credit card"
        
        # Check masking
        for data in sensitive_data:
            if data.data_type.value == "credit_card":
                assert "****" in data.matched_value, "Credit card should be masked"
                print_success(f"Credit card detected and masked: {data.matched_value}")
        
        # Test 3: Classify content with phone numbers
        print("\nTest 3: Classifying content with phone numbers...")
        content_phone = """
        Contact: 555-123-4567
        Mobile: (555) 987-6543
        """
        
        sensitive_data = await classifier.classify_data(content_phone, "contacts.txt")
        phone_detected = any(d.data_type.value == "phone" for d in sensitive_data)
        assert phone_detected, "Should detect phone numbers"
        print_success(f"Detected {len(sensitive_data)} phone numbers")
        
        # Get statistics
        stats = classifier.get_statistics()
        assert stats["data_classified"] > 0, "Should have classified data"
        print_success(f"Classification statistics: {stats['data_classified']} items classified")
        
        print_success("✅ Data Classifier: ALL TESTS PASSED")
        return True
        
    except Exception as e:
        print_error(f"Data Classifier test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_dlp_engine():
    """Test DLP engine."""
    print_test_header("DLP Engine")
    
    try:
        from vaulytica.network_security import (
            get_dlp_engine,
            SensitiveDataType,
            DLPAction,
            DataClassification
        )
        
        engine = get_dlp_engine()
        
        # Test 1: Create DLP policy to block SSN
        print("Test 1: Creating DLP policy to block SSN...")
        policy = await engine.create_policy(
            name="Block SSN Transfer",
            data_types=[SensitiveDataType.SSN, SensitiveDataType.CREDIT_CARD],
            action=DLPAction.BLOCK,
            classification_level=DataClassification.RESTRICTED
        )
        
        assert policy.policy_id is not None, "Policy should have ID"
        assert policy.enabled == True, "Policy should be enabled"
        print_success(f"DLP policy created: {policy.name} (ID: {policy.policy_id})")
        
        # Test 2: Enforce policy on content with SSN (should block)
        print("\nTest 2: Enforcing policy on content with SSN...")
        content_with_ssn = "Employee SSN: 123-45-6789"
        
        result = await engine.enforce_policy(content_with_ssn, "email_attachment.txt", "email_send")
        assert result["allowed"] == False, "Should block content with SSN"
        assert result["action"] == "block", "Action should be block"
        print_success(f"Content blocked: {result['reason']}")
        
        # Test 3: Enforce policy on safe content (should allow)
        print("\nTest 3: Enforcing policy on safe content...")
        safe_content = "This is a regular business document with no sensitive data."
        
        result = await engine.enforce_policy(safe_content, "document.txt", "file_transfer")
        assert result["allowed"] == True, "Should allow safe content"
        print_success(f"Safe content allowed: {result['reason']}")
        
        # Test 4: Create alert-only policy
        print("\nTest 4: Creating alert-only policy...")
        alert_policy = await engine.create_policy(
            name="Alert on Email Transfer",
            data_types=[SensitiveDataType.EMAIL],
            action=DLPAction.ALERT,
            classification_level=DataClassification.INTERNAL
        )
        
        content_with_email = "Contact: john.doe@example.com"
        result = await engine.enforce_policy(content_with_email, "contacts.csv", "export")
        assert result["allowed"] == True, "Alert policy should allow but alert"
        assert result["action"] == "alert", "Action should be alert"
        print_success(f"Alert triggered: {result['reason']}")
        
        # Get statistics
        stats = engine.get_statistics()
        assert stats["policies_enforced"] > 0, "Should have enforced policies"
        assert stats["violations_detected"] > 0, "Should have detected violations"
        print_success(f"DLP statistics: {stats['policies_enforced']} policies enforced, {stats['violations_detected']} violations")
        
        print_success("✅ DLP Engine: ALL TESTS PASSED")
        return True
        
    except Exception as e:
        print_error(f"DLP Engine test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_encryption_manager():
    """Test encryption manager."""
    print_test_header("Encryption Manager")
    
    try:
        from vaulytica.network_security import (
            get_encryption_manager,
            EncryptionAlgorithm
        )
        
        manager = get_encryption_manager()
        
        # Test 1: Register encryption key
        print("Test 1: Registering encryption key...")
        key = await manager.register_key(
            name="Database Encryption Key",
            algorithm=EncryptionAlgorithm.AES_256,
            key_size=256,
            purpose="database_encryption",
            rotation_policy_days=90
        )
        
        assert key.key_id is not None, "Key should have ID"
        assert key.is_active == True, "Key should be active"
        assert key.algorithm == EncryptionAlgorithm.AES_256, "Algorithm should match"
        print_success(f"Key registered: {key.name} (ID: {key.key_id}, Algorithm: {key.algorithm.value})")
        
        # Test 2: Rotate encryption key
        print("\nTest 2: Rotating encryption key...")
        new_key = await manager.rotate_key(key.key_id)
        
        assert new_key.key_id != key.key_id, "New key should have different ID"
        assert new_key.is_active == True, "New key should be active"
        assert new_key.last_rotated is not None, "New key should have rotation timestamp"
        print_success(f"Key rotated: New ID: {new_key.key_id}, Last rotated: {new_key.last_rotated}")
        
        # Test 3: Register TLS certificate
        print("\nTest 3: Registering TLS certificate...")
        cert = await manager.register_certificate(
            common_name="api.example.com",
            issuer="Let's Encrypt",
            valid_from=datetime.utcnow() - timedelta(days=30),
            valid_until=datetime.utcnow() + timedelta(days=60),
            key_algorithm="RSA",
            key_size=2048
        )
        
        assert cert.cert_id is not None, "Certificate should have ID"
        assert cert.days_until_expiry > 0, "Certificate should not be expired"
        print_success(f"Certificate registered: {cert.common_name}, Expires in {cert.days_until_expiry} days")
        
        # Test 4: Check expiring certificates
        print("\nTest 4: Checking for expiring certificates...")
        expiring_certs = await manager.check_expiring_certificates(days_threshold=90)
        
        assert len(expiring_certs) > 0, "Should find expiring certificate"
        print_success(f"Found {len(expiring_certs)} expiring certificates")
        
        # Get statistics
        stats = manager.get_statistics()
        assert stats["keys_managed"] > 0, "Should have managed keys"
        assert stats["keys_rotated"] > 0, "Should have rotated keys"
        print_success(f"Encryption statistics: {stats['keys_managed']} keys, {stats['keys_rotated']} rotations, {stats['certificates_monitored']} certificates")
        
        print_success("✅ Encryption Manager: ALL TESTS PASSED")
        return True

    except Exception as e:
        print_error(f"Encryption Manager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_network_threat_detector():
    """Test network threat detector."""
    print_test_header("Network Threat Detector")

    try:
        from vaulytica.network_security import (
            get_network_threat_detector,
            NetworkFlow,
            NetworkProtocol
        )

        detector = get_network_threat_detector()

        # Test 1: Detect DDoS attack
        print("Test 1: Detecting DDoS attack...")
        flows = []

        # Simulate DDoS: Many sources attacking one target
        target_ip = "10.0.2.100"
        for i in range(120):
            flow = NetworkFlow(
                flow_id=f"ddos-flow-{i}",
                source_ip=f"192.168.{i // 256}.{i % 256}",
                source_port=50000 + i,
                destination_ip=target_ip,
                destination_port=80,
                protocol=NetworkProtocol.HTTP,
                bytes_sent=512,
                bytes_received=0,
                packets_sent=5,
                packets_received=0,
                duration_seconds=0.5
            )
            flows.append(flow)

        threat = await detector.detect_ddos(flows)
        assert threat is not None, "Should detect DDoS attack"
        assert threat.threat_type.value == "ddos", "Should identify as DDoS"
        assert threat.severity.value == "critical", "DDoS should be critical severity"
        print_success(f"DDoS detected: {threat.description}, Risk Score: {threat.risk_score}")

        # Test 2: Detect lateral movement
        print("\nTest 2: Detecting lateral movement...")
        lateral_flows = []

        # Simulate lateral movement: One source connecting to many internal hosts on admin ports
        attacker_ip = "10.0.1.50"
        for i in range(15):
            # SSH connections
            flow = NetworkFlow(
                flow_id=f"lateral-ssh-{i}",
                source_ip=attacker_ip,
                source_port=50000 + i,
                destination_ip=f"10.0.2.{100 + i}",
                destination_port=22,
                protocol=NetworkProtocol.SSH,
                bytes_sent=1024,
                bytes_received=2048,
                packets_sent=10,
                packets_received=15,
                duration_seconds=2.0
            )
            lateral_flows.append(flow)

        threat = await detector.detect_lateral_movement(lateral_flows)
        assert threat is not None, "Should detect lateral movement"
        assert threat.threat_type.value == "lateral_movement", "Should identify as lateral movement"
        print_success(f"Lateral movement detected: {threat.description}, Risk Score: {threat.risk_score}")

        # Get statistics
        stats = detector.get_statistics()
        assert stats["threats_detected"] > 0, "Should have detected threats"
        assert stats["critical_threats"] > 0, "Should have critical threats"
        print_success(f"Threat detection statistics: {stats['threats_detected']} threats, {stats['critical_threats']} critical")

        print_success("✅ Network Threat Detector: ALL TESTS PASSED")
        return True

    except Exception as e:
        print_error(f"Network Threat Detector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_full_assessment():
    """Test full network security assessment."""
    print_test_header("Full Network Security Assessment")

    try:
        from vaulytica.network_security import (
            get_network_security_orchestrator,
            FirewallRule,
            FirewallAction,
            NetworkProtocol,
            NetworkFlow
        )

        orchestrator = get_network_security_orchestrator()

        # Prepare test data
        print("Preparing test data...")

        # Firewall rules
        firewall_rules = [
            FirewallRule(
                rule_id="rule-001",
                name="Allow HTTPS",
                action=FirewallAction.ALLOW,
                protocol=NetworkProtocol.HTTPS,
                source_ip="10.0.1.0/24",
                destination_ip="10.0.2.100",
                destination_port="443"
            ),
            FirewallRule(
                rule_id="rule-002",
                name="Insecure SSH rule",
                action=FirewallAction.ALLOW,
                protocol=NetworkProtocol.SSH,
                source_ip="0.0.0.0/0",
                destination_ip="*",
                destination_port="22"
            )
        ]

        # Network flows
        network_flows = [
            NetworkFlow(
                flow_id="flow-001",
                source_ip="10.0.1.50",
                source_port=54321,
                destination_ip="192.0.2.1",  # Malicious IP
                destination_port=443,
                protocol=NetworkProtocol.HTTPS,
                bytes_sent=1024,
                bytes_received=2048,
                packets_sent=10,
                packets_received=15,
                duration_seconds=5.0
            ),
            NetworkFlow(
                flow_id="flow-002",
                source_ip="10.0.1.100",
                source_port=55000,
                destination_ip="10.0.2.50",
                destination_port=80,
                protocol=NetworkProtocol.HTTP,
                bytes_sent=512,
                bytes_received=1024,
                packets_sent=5,
                packets_received=8,
                duration_seconds=2.0
            )
        ]

        # Data locations
        data_locations = [
            {
                "path": "employee_data.csv",
                "content": "Name,SSN,Email\nJohn Doe,123-45-6789,john@example.com"
            },
            {
                "path": "payment_info.txt",
                "content": "Card: 4532-1234-5678-9010"
            }
        ]

        # Perform full assessment
        print("\nPerforming full network security assessment...")
        assessment = await orchestrator.perform_full_assessment(
            firewall_rules=firewall_rules,
            network_flows=network_flows,
            data_locations=data_locations
        )

        # Validate assessment results
        assert assessment["assessment_id"] is not None, "Assessment should have ID"
        assert "firewall" in assessment, "Should have firewall analysis"
        assert "network_threats" in assessment, "Should have threat analysis"
        assert "data_classification" in assessment, "Should have data classification"
        assert "encryption" in assessment, "Should have encryption analysis"
        assert "risk_assessment" in assessment, "Should have risk assessment"

        # Check firewall analysis
        assert assessment["firewall"]["rules_analyzed"] == 2, "Should analyze 2 rules"
        assert assessment["firewall"]["insecure_rules"] > 0, "Should detect insecure rules"
        print_success(f"Firewall: {assessment['firewall']['rules_analyzed']} rules analyzed, {assessment['firewall']['insecure_rules']} insecure")

        # Check threat detection
        assert assessment["network_threats"]["flow_threats"] > 0, "Should detect threats"
        print_success(f"Threats: {assessment['network_threats']['flow_threats']} detected")

        # Check data classification
        assert assessment["data_classification"]["total_classified"] > 0, "Should classify data"
        print_success(f"Data: {assessment['data_classification']['total_classified']} sensitive items classified")

        # Check risk assessment
        risk_score = assessment["risk_assessment"]["overall_risk_score"]
        risk_level = assessment["risk_assessment"]["risk_level"]
        assert 0 <= risk_score <= 10, "Risk score should be 0-10"
        print_success(f"Risk Assessment: Score {risk_score:.2f}/10, Level: {risk_level}")

        # Print summary
        print("\n" + "="*80)
        print("📊 ASSESSMENT SUMMARY")
        print("="*80)
        print(f"Duration: {assessment['duration_seconds']:.2f}s")
        print(f"Firewall Rules: {assessment['firewall']['rules_analyzed']} analyzed, {assessment['firewall']['insecure_rules']} insecure")
        print(f"Network Threats: {assessment['network_threats']['flow_threats']} detected")
        print(f"Sensitive Data: {assessment['data_classification']['total_classified']} items")
        print(f"Overall Risk: {risk_score:.2f}/10 ({risk_level})")
        print("="*80)

        print_success("✅ Full Network Security Assessment: ALL TESTS PASSED")
        return True

    except Exception as e:
        print_error(f"Full assessment test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all tests."""
    print("\n" + "="*80)
    print("🚀 VAULYTICA v0.25.0 - NETWORK SECURITY & DLP TEST SUITE")
    print("="*80)

    results = []

    # Run all tests
    results.append(("Network Security Analyzer", await test_network_security_analyzer()))
    results.append(("Data Classifier", await test_data_classifier()))
    results.append(("DLP Engine", await test_dlp_engine()))
    results.append(("Encryption Manager", await test_encryption_manager()))
    results.append(("Network Threat Detector", await test_network_threat_detector()))
    results.append(("Full Assessment", await test_full_assessment()))

    # Print summary
    print("\n" + "="*80)
    print("📊 TEST SUMMARY")
    print("="*80)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{status}: {test_name}")

    print("="*80)
    print(f"Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print("="*80)

    if passed == total:
        print("\n✅ ALL TESTS PASSED!")
        print("🎉 Vaulytica v0.25.0 Network Security & DLP is PRODUCTION READY! 🚀\n")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

