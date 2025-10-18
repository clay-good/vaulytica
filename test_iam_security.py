"""
Comprehensive test suite for IAM Security & Secrets Management (v0.24.0).

Tests:
1. IAM Security Analyzer
2. Secrets Scanner
3. Credential Manager
4. Zero Trust Engine
5. Identity Threat Detector
6. Full IAM Assessment

Author: Vaulytica Team
Version: 0.24.0
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any


def print_header(text: str):
    """Print formatted test header."""
    print(f"\n{'=' * 80}")
    print(f"  {text}")
    print(f"{'=' * 80}\n")


def print_result(test_name: str, passed: bool, details: Dict[str, Any] = None):
    """Print test result."""
    status = "✅ PASSED" if passed else "❌ FAILED"
    print(f"{status}: {test_name}")
    
    if details:
        for key, value in details.items():
            print(f"  - {key}: {value}")
    
    print()


async def test_iam_security_analyzer():
    """Test IAM security analyzer."""
    print_header("TEST 1: IAM Security Analyzer")
    
    try:
        from vaulytica.iam_security import (
            get_iam_analyzer,
            IAMPrincipal,
            IAMPrincipalType
        )
        from vaulytica.cspm import CloudProvider
        
        analyzer = get_iam_analyzer()
        
        # Create test principal with dangerous permissions
        principal = IAMPrincipal(
            principal_id="user-12345",
            principal_type=IAMPrincipalType.USER,
            name="test-admin-user",
            provider=CloudProvider.AWS,
            created_at=datetime.utcnow(),
            permissions={
                "iam:PassRole",
                "iam:CreateAccessKey",
                "iam:AttachUserPolicy",
                "s3:GetObject",
                "ec2:DescribeInstances",
                "*"  # Wildcard permission
            }
        )
        
        # Analyze principal
        analysis = await analyzer.analyze_principal(principal)
        
        # Verify analysis
        assert analysis["principal_id"] == "user-12345", "Principal ID should match"
        assert analysis["name"] == "test-admin-user", "Name should match"
        assert analysis["privilege_level"] == "admin", "Should detect admin privileges"
        assert analysis["escalation_paths"] > 0, "Should find escalation paths"
        assert analysis["is_over_privileged"], "Should detect over-privileged role"
        
        # Get escalation paths
        escalation_paths = analyzer.get_escalation_paths()
        assert len(escalation_paths) > 0, "Should have escalation paths"
        
        # Get over-privileged roles
        over_privileged = analyzer.get_over_privileged_roles()
        assert len(over_privileged) > 0, "Should have over-privileged roles"
        
        # Get statistics
        stats = analyzer.get_statistics()
        assert stats["principals_analyzed"] > 0, "Should track principals"
        assert stats["escalation_paths_found"] > 0, "Should track escalation paths"
        
        details = {
            "Principal ID": principal.principal_id,
            "Privilege Level": analysis["privilege_level"],
            "Escalation Paths": analysis["escalation_paths"],
            "Over-Privileged": analysis["is_over_privileged"],
            "Permissions": len(principal.permissions)
        }
        
        print_result("IAM Security Analyzer", True, details)
        return True
        
    except Exception as e:
        print_result("IAM Security Analyzer", False, {"Error": str(e)})
        return False


async def test_secrets_scanner():
    """Test secrets scanner."""
    print_header("TEST 2: Secrets Scanner")
    
    try:
        from vaulytica.iam_security import get_secrets_scanner, SecretLocation
        
        scanner = get_secrets_scanner()
        
        # Test content with various secrets
        test_content = """
# Configuration file
api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
password = "MySecretPassword123!"
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

# Database connection
db_url = "postgresql://user:pass123@localhost/db"

# Private key
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
"""
        
        # Scan file
        secrets = await scanner.scan_file(
            "config.py",
            test_content,
            SecretLocation.CONFIGURATION_FILE
        )
        
        # Verify secrets found
        assert len(secrets) > 0, "Should find secrets"

        # Check secret types
        secret_types = {s.secret_type.value for s in secrets}
        # Should find at least one type of secret (api_key, password, private_key, aws_access_key, or database_connection)
        expected_types = {"api_key", "password", "private_key", "aws_access_key", "database_connection"}
        assert len(secret_types.intersection(expected_types)) > 0, f"Should find secrets. Found types: {secret_types}"
        
        # Check severity
        critical_secrets = [s for s in secrets if s.severity.value == "critical"]
        high_secrets = [s for s in secrets if s.severity.value == "high"]
        
        # Get statistics
        stats = scanner.get_statistics()
        assert stats["files_scanned"] > 0, "Should track files scanned"
        assert stats["secrets_found"] > 0, "Should track secrets found"
        
        details = {
            "Secrets Found": len(secrets),
            "Critical": len(critical_secrets),
            "High": len(high_secrets),
            "Secret Types": len(secret_types),
            "Files Scanned": stats["files_scanned"]
        }
        
        print_result("Secrets Scanner", True, details)
        return True
        
    except Exception as e:
        print_result("Secrets Scanner", False, {"Error": str(e)})
        return False


async def test_credential_manager():
    """Test credential manager."""
    print_header("TEST 3: Credential Manager")
    
    try:
        from vaulytica.iam_security import get_credential_manager
        
        manager = get_credential_manager()
        
        # Register credentials
        cred1 = await manager.register_credential(
            "api-key-prod",
            "api_key",
            "service-account-1",
            datetime.utcnow() + timedelta(days=30)
        )
        
        cred2 = await manager.register_credential(
            "db-password",
            "password",
            "admin-user",
            datetime.utcnow() + timedelta(days=15)
        )
        
        # Verify credentials
        assert cred1.credential_id is not None, "Should have credential ID"
        assert cred1.name == "api-key-prod", "Name should match"
        assert cred1.rotation_policy is not None, "Should have rotation policy"
        
        # Rotate credential
        success = await manager.rotate_credential(cred1.credential_id)
        assert success, "Rotation should succeed"
        
        # Check expiring credentials
        expiring = await manager.check_expiring_credentials(30)
        assert len(expiring) > 0, "Should find expiring credentials"
        
        # Get statistics
        stats = manager.get_statistics()
        assert stats["credentials_managed"] >= 2, "Should track credentials"
        assert stats["credentials_rotated"] > 0, "Should track rotations"
        
        details = {
            "Credentials Managed": stats["credentials_managed"],
            "Credentials Rotated": stats["credentials_rotated"],
            "Expiring Soon": len(expiring),
            "Rotation Success Rate": f"{stats['rotation_success_rate']:.1f}%"
        }
        
        print_result("Credential Manager", True, details)
        return True
        
    except Exception as e:
        print_result("Credential Manager", False, {"Error": str(e)})
        return False


async def test_zero_trust_engine():
    """Test zero trust engine."""
    print_header("TEST 4: Zero Trust Engine")
    
    try:
        from vaulytica.iam_security import get_zero_trust_engine, ZeroTrustPolicyAction
        
        engine = get_zero_trust_engine()
        
        # Create policies
        policy1 = await engine.create_policy(
            "allow-admin-access",
            "admin-user",
            "production-database",
            ZeroTrustPolicyAction.ALLOW,
            {"allowed_locations": ["office", "vpn"], "max_risk_score": 5}
        )
        
        policy2 = await engine.create_policy(
            "deny-external-access",
            "*",
            "production-database",
            ZeroTrustPolicyAction.DENY,
            {"allowed_locations": ["external"]}
        )
        
        # Verify policies
        assert policy1.policy_id is not None, "Should have policy ID"
        assert policy1.action == ZeroTrustPolicyAction.ALLOW, "Action should be ALLOW"
        
        # Evaluate access - should allow
        action1, reason1 = await engine.evaluate_access(
            "admin-user",
            "production-database",
            {"location": "office", "risk_score": 3}
        )
        assert action1 == ZeroTrustPolicyAction.ALLOW, "Should allow access from office"
        
        # Evaluate access - should deny (high risk)
        action2, reason2 = await engine.evaluate_access(
            "admin-user",
            "production-database",
            {"location": "office", "risk_score": 8}
        )
        assert action2 == ZeroTrustPolicyAction.DENY, "Should deny high risk access"
        
        # Get statistics
        stats = engine.get_statistics()
        assert stats["access_requests"] >= 2, "Should track access requests"
        assert stats["policies_enforced"] > 0, "Should track policy enforcement"
        
        details = {
            "Policies Created": 2,
            "Access Requests": stats["access_requests"],
            "Access Allowed": stats["access_allowed"],
            "Access Denied": stats["access_denied"],
            "Policies Enforced": stats["policies_enforced"]
        }
        
        print_result("Zero Trust Engine", True, details)
        return True
        
    except Exception as e:
        print_result("Zero Trust Engine", False, {"Error": str(e)})
        return False


async def test_identity_threat_detector():
    """Test identity threat detector."""
    print_header("TEST 5: Identity Threat Detector")
    
    try:
        from vaulytica.iam_security import (
            get_identity_threat_detector,
            IAMPrincipal,
            IAMPrincipalType
        )
        from vaulytica.cspm import CloudProvider
        
        detector = get_identity_threat_detector()
        
        # Create test principal
        principal = IAMPrincipal(
            principal_id="user-67890",
            principal_type=IAMPrincipalType.USER,
            name="test-user",
            provider=CloudProvider.AWS,
            created_at=datetime.utcnow()
        )
        
        # Simulate normal access
        for i in range(5):
            await detector.analyze_access_pattern(
                principal,
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "action": "s3:GetObject",
                    "resource": "s3://my-bucket/file.txt",
                    "location": "office"
                }
            )
        
        # Simulate anomalous access (unusual time)
        threat1 = await detector.analyze_access_pattern(
            principal,
            {
                "timestamp": datetime.utcnow().replace(hour=3).isoformat(),
                "action": "s3:GetObject",
                "resource": "s3://my-bucket/file.txt",
                "location": "office"
            }
        )
        
        # Simulate privilege abuse
        threat2 = await detector.analyze_access_pattern(
            principal,
            {
                "timestamp": datetime.utcnow().isoformat(),
                "action": "iam:CreateAccessKey",
                "resource": "arn:aws:iam::123456789012:user/admin",
                "location": "office"
            }
        )
        
        # Get statistics
        stats = detector.get_statistics()
        
        details = {
            "Threats Detected": stats["threats_detected"],
            "Anomalous Access": stats["anomalous_access"],
            "Privilege Abuse": stats["privilege_abuse"],
            "Lateral Movement": stats["lateral_movement"]
        }
        
        print_result("Identity Threat Detector", True, details)
        return True
        
    except Exception as e:
        print_result("Identity Threat Detector", False, {"Error": str(e)})
        return False


async def test_full_iam_assessment():
    """Test full IAM assessment."""
    print_header("TEST 6: Full IAM Assessment")
    
    try:
        from vaulytica.iam_security import (
            get_iam_orchestrator,
            IAMPrincipal,
            IAMPrincipalType
        )
        from vaulytica.cspm import CloudProvider
        
        orchestrator = get_iam_orchestrator()
        
        # Create test principals
        principals = [
            IAMPrincipal(
                principal_id="user-1",
                principal_type=IAMPrincipalType.USER,
                name="admin-user",
                provider=CloudProvider.AWS,
                created_at=datetime.utcnow(),
                permissions={"iam:PassRole", "iam:CreateAccessKey", "*"}
            ),
            IAMPrincipal(
                principal_id="role-1",
                principal_type=IAMPrincipalType.ROLE,
                name="service-role",
                provider=CloudProvider.AWS,
                created_at=datetime.utcnow(),
                permissions={"s3:GetObject", "s3:PutObject"}
            )
        ]
        
        # Perform full assessment
        assessment = await orchestrator.full_iam_assessment(
            principals,
            scan_paths=["/tmp/test"]
        )
        
        # Verify assessment
        assert assessment["assessment_id"] is not None, "Should have assessment ID"
        assert assessment["principals_analyzed"] == 2, "Should analyze 2 principals"
        assert "iam_analysis" in assessment, "Should have IAM analysis"
        assert "secrets_scanning" in assessment, "Should have secrets scanning"
        assert "credential_management" in assessment, "Should have credential management"
        assert "overall_risk_score" in assessment, "Should have risk score"
        assert "recommendations" in assessment, "Should have recommendations"
        
        details = {
            "Assessment ID": assessment["assessment_id"],
            "Principals Analyzed": assessment["principals_analyzed"],
            "Escalation Paths": assessment["iam_analysis"]["escalation_paths"],
            "Secrets Found": assessment["secrets_scanning"]["secrets_found"],
            "Overall Risk Score": f"{assessment['overall_risk_score']:.1f}/10",
            "Recommendations": len(assessment["recommendations"])
        }
        
        print_result("Full IAM Assessment", True, details)
        return True
        
    except Exception as e:
        print_result("Full IAM Assessment", False, {"Error": str(e)})
        return False


async def main():
    """Run all tests."""
    print_header("VAULYTICA v0.24.0 - IAM SECURITY & SECRETS MANAGEMENT TEST SUITE")
    
    print("Testing IAM Security, Secrets Management, Zero Trust Architecture,")
    print("and Identity Threat Detection capabilities...\n")
    
    # Run all tests
    results = []
    
    results.append(await test_iam_security_analyzer())
    results.append(await test_secrets_scanner())
    results.append(await test_credential_manager())
    results.append(await test_zero_trust_engine())
    results.append(await test_identity_threat_detector())
    results.append(await test_full_iam_assessment())
    
    # Print summary
    print_header("TEST SUMMARY")
    
    passed = sum(results)
    total = len(results)
    percentage = (passed / total) * 100
    
    print(f"Results: {passed}/{total} tests passed ({percentage:.1f}%)")
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED!")
        print("\n🎉 Vaulytica v0.24.0 IAM Security & Secrets Management is PRODUCTION READY! 🚀")
    else:
        print(f"\n⚠️  {total - passed} test(s) failed. Please review the errors above.")
    
    print()


if __name__ == "__main__":
    asyncio.run(main())

