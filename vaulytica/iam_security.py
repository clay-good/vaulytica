import asyncio
import hashlib
import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from vaulytica.cspm import CloudProvider, Severity
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class IAMPrincipalType(str, Enum):
    """IAM principal types."""
    USER = "user"
    ROLE = "role"
    SERVICE_ACCOUNT = "service_account"
    GROUP = "group"
    FEDERATED = "federated"


class PrivilegeLevel(str, Enum):
    """Privilege level classification."""
    ADMIN = "admin"  # Full administrative access
    ELEVATED = "elevated"  # High privileges
    STANDARD = "standard"  # Normal user privileges
    LIMITED = "limited"  # Restricted access
    READ_ONLY = "read_only"  # Read-only access


class SecretType(str, Enum):
    """Types of secrets that can be detected."""
    API_KEY = "api_key"
    PASSWORD = "password"
    PRIVATE_KEY = "private_key"
    AWS_ACCESS_KEY = "aws_access_key"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    AZURE_CLIENT_SECRET = "azure_client_secret"
    DATABASE_CONNECTION = "database_connection"
    JWT_TOKEN = "jwt_token"
    OAUTH_TOKEN = "oauth_token"
    ENCRYPTION_KEY = "encryption_key"
    CERTIFICATE = "certificate"


class SecretLocation(str, Enum):
    """Where secrets can be found."""
    SOURCE_CODE = "source_code"
    CONFIGURATION_FILE = "configuration_file"
    ENVIRONMENT_VARIABLE = "environment_variable"
    CONTAINER_IMAGE = "container_image"
    KUBERNETES_SECRET = "kubernetes_secret"
    CLOUD_STORAGE = "cloud_storage"
    VERSION_CONTROL = "version_control"


class ZeroTrustPolicyAction(str, Enum):
    """Zero trust policy actions."""
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"  # Require additional verification
    AUDIT = "audit"  # Allow but log for review


@dataclass
class IAMPrincipal:
    """IAM principal (user, role, service account)."""
    principal_id: str
    principal_type: IAMPrincipalType
    name: str
    provider: CloudProvider
    created_at: datetime
    last_used: Optional[datetime] = None
    policies: List[str] = field(default_factory=list)
    permissions: Set[str] = field(default_factory=set)
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IAMPolicy:
    """IAM policy document."""
    policy_id: str
    name: str
    provider: CloudProvider
    document: Dict[str, Any]
    attached_to: List[str] = field(default_factory=list)
    is_managed: bool = False
    created_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None


@dataclass
class PrivilegeEscalationPath:
    """Potential privilege escalation path."""
    path_id: str
    principal: IAMPrincipal
    escalation_type: str  # e.g., "iam:PassRole", "iam:CreateAccessKey"
    severity: Severity
    description: str
    attack_steps: List[str]
    mitigation: str
    risk_score: float


@dataclass
class OverPrivilegedRole:
    """Over-privileged role or user."""
    principal: IAMPrincipal
    privilege_level: PrivilegeLevel
    unused_permissions: Set[str]
    excessive_permissions: Set[str]
    last_activity: Optional[datetime]
    recommendation: str
    risk_score: float


@dataclass
class DetectedSecret:
    """Detected secret in code or configuration."""
    secret_id: str
    secret_type: SecretType
    location: SecretLocation
    file_path: str
    line_number: int
    matched_pattern: str
    entropy_score: float  # High entropy indicates likely secret
    severity: Severity
    exposed_since: Optional[datetime] = None
    remediation: str = ""


@dataclass
class Credential:
    """Managed credential."""
    credential_id: str
    name: str
    credential_type: str  # password, api_key, certificate, etc.
    owner: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_rotated: Optional[datetime] = None
    rotation_policy: Optional[str] = None
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ZeroTrustPolicy:
    """Zero trust access policy."""
    policy_id: str
    name: str
    principal: str
    resource: str
    action: ZeroTrustPolicyAction
    conditions: Dict[str, Any] = field(default_factory=dict)
    # Conditions can include: time_of_day, location, device_trust, risk_score
    priority: int = 100
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class IdentityThreat:
    """Identity-based security threat."""
    threat_id: str
    principal: IAMPrincipal
    threat_type: str  # anomalous_access, privilege_abuse, lateral_movement
    severity: Severity
    description: str
    indicators: List[str]
    timeline: List[Dict[str, Any]]
    risk_score: float
    detected_at: datetime = field(default_factory=datetime.utcnow)


class IAMSecurityAnalyzer:
    """
    IAM security analyzer for cloud platforms.
    
    Analyzes IAM policies, detects privilege escalation paths,
    identifies over-privileged roles, and provides recommendations.
    """
    
    def __init__(self):
        """Initialize IAM security analyzer."""
        self.principals: Dict[str, IAMPrincipal] = {}
        self.policies: Dict[str, IAMPolicy] = {}
        self.escalation_paths: List[PrivilegeEscalationPath] = []
        self.over_privileged: List[OverPrivilegedRole] = []
        
        self.statistics = {
            "principals_analyzed": 0,
            "policies_analyzed": 0,
            "escalation_paths_found": 0,
            "over_privileged_found": 0,
            "findings_by_severity": {s.value: 0 for s in Severity},
            "last_analysis": None
        }
        
        # Dangerous permissions that can lead to privilege escalation
        self.dangerous_permissions = {
            "aws": [
                "iam:PassRole",
                "iam:CreateAccessKey",
                "iam:CreateLoginProfile",
                "iam:UpdateAssumeRolePolicy",
                "iam:AttachUserPolicy",
                "iam:AttachRolePolicy",
                "iam:PutUserPolicy",
                "iam:PutRolePolicy",
                "sts:AssumeRole",
                "lambda:CreateFunction",
                "lambda:UpdateFunctionCode",
                "ec2:RunInstances",
                "iam:CreatePolicyVersion"
            ],
            "azure": [
                "Microsoft.Authorization/roleAssignments/write",
                "Microsoft.Authorization/roleDefinitions/write",
                "Microsoft.Compute/virtualMachines/extensions/write",
                "Microsoft.KeyVault/vaults/secrets/write"
            ],
            "gcp": [
                "iam.serviceAccounts.actAs",
                "iam.serviceAccountKeys.create",
                "iam.roles.update",
                "resourcemanager.projects.setIamPolicy",
                "compute.instances.setMetadata"
            ]
        }
        
        logger.info("IAM Security Analyzer initialized")
    
    async def analyze_principal(
        self,
        principal: IAMPrincipal
    ) -> Dict[str, Any]:
        """
        Analyze IAM principal for security issues.
        
        Args:
            principal: IAM principal to analyze
        
        Returns:
            Analysis results
        """
        logger.info(f"Analyzing IAM principal: {principal.name}")
        
        self.principals[principal.principal_id] = principal
        
        # Check for privilege escalation paths
        escalation_paths = await self._check_privilege_escalation(principal)
        
        # Check if over-privileged
        over_privileged = await self._check_over_privileged(principal)
        
        # Calculate privilege level
        privilege_level = self._calculate_privilege_level(principal)
        
        # Check for inactive principals
        is_inactive = self._check_inactive(principal)
        
        self.statistics["principals_analyzed"] += 1
        self.statistics["last_analysis"] = datetime.utcnow().isoformat()
        
        return {
            "principal_id": principal.principal_id,
            "name": principal.name,
            "type": principal.principal_type.value,
            "privilege_level": privilege_level.value,
            "escalation_paths": len(escalation_paths),
            "is_over_privileged": over_privileged is not None,
            "is_inactive": is_inactive,
            "permissions_count": len(principal.permissions),
            "policies_count": len(principal.policies)
        }
    
    async def _check_privilege_escalation(
        self,
        principal: IAMPrincipal
    ) -> List[PrivilegeEscalationPath]:
        """Check for privilege escalation paths."""
        paths = []
        
        dangerous_perms = self.dangerous_permissions.get(
            principal.provider.value.lower(),
            []
        )
        
        for perm in principal.permissions:
            if perm in dangerous_perms:
                path = PrivilegeEscalationPath(
                    path_id=f"esc-{principal.principal_id}-{hashlib.md5(perm.encode()).hexdigest()[:8]}",
                    principal=principal,
                    escalation_type=perm,
                    severity=Severity.HIGH,
                    description=f"Principal has dangerous permission: {perm}",
                    attack_steps=[
                        f"1. Use {perm} permission",
                        "2. Escalate privileges",
                        "3. Gain administrative access"
                    ],
                    mitigation=f"Remove {perm} permission or add strict conditions",
                    risk_score=8.0
                )
                paths.append(path)
                self.escalation_paths.append(path)
                self.statistics["escalation_paths_found"] += 1
                self.statistics["findings_by_severity"][Severity.HIGH.value] += 1
        
        return paths
    
    async def _check_over_privileged(
        self,
        principal: IAMPrincipal
    ) -> Optional[OverPrivilegedRole]:
        """Check if principal is over-privileged."""
        # Check for wildcard permissions
        wildcard_perms = {p for p in principal.permissions if '*' in p}
        
        if wildcard_perms or len(principal.permissions) > 50:
            over_priv = OverPrivilegedRole(
                principal=principal,
                privilege_level=PrivilegeLevel.ADMIN if wildcard_perms else PrivilegeLevel.ELEVATED,
                unused_permissions=set(),  # Would need usage data
                excessive_permissions=wildcard_perms,
                last_activity=principal.last_used,
                recommendation="Apply principle of least privilege. Remove wildcard permissions.",
                risk_score=7.0 if wildcard_perms else 5.0
            )
            self.over_privileged.append(over_priv)
            self.statistics["over_privileged_found"] += 1
            return over_priv
        
        return None
    
    def _calculate_privilege_level(self, principal: IAMPrincipal) -> PrivilegeLevel:
        """Calculate privilege level of principal."""
        # Check for admin permissions
        admin_indicators = ['*', 'admin', 'full', 'poweruser']
        
        for perm in principal.permissions:
            perm_lower = perm.lower()
            if any(indicator in perm_lower for indicator in admin_indicators):
                return PrivilegeLevel.ADMIN
        
        # Check permission count
        if len(principal.permissions) > 50:
            return PrivilegeLevel.ELEVATED
        elif len(principal.permissions) > 20:
            return PrivilegeLevel.STANDARD
        elif len(principal.permissions) > 5:
            return PrivilegeLevel.LIMITED
        else:
            return PrivilegeLevel.READ_ONLY
    
    def _check_inactive(self, principal: IAMPrincipal) -> bool:
        """Check if principal is inactive."""
        if principal.last_used is None:
            return True
        
        inactive_threshold = datetime.utcnow() - timedelta(days=90)
        return principal.last_used < inactive_threshold
    
    def get_escalation_paths(self) -> List[PrivilegeEscalationPath]:
        """Get all detected privilege escalation paths."""
        return self.escalation_paths
    
    def get_over_privileged_roles(self) -> List[OverPrivilegedRole]:
        """Get all over-privileged roles."""
        return self.over_privileged
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        return self.statistics


# Global instance
_iam_analyzer: Optional[IAMSecurityAnalyzer] = None


def get_iam_analyzer() -> IAMSecurityAnalyzer:
    """Get or create global IAM analyzer instance."""
    global _iam_analyzer

    if _iam_analyzer is None:
        _iam_analyzer = IAMSecurityAnalyzer()

    return _iam_analyzer


class SecretsScanner:
    """
    Secrets scanner for detecting hardcoded secrets.

    Scans code, configuration files, containers, and Kubernetes
    for exposed secrets using pattern matching and entropy analysis.
    """

    def __init__(self):
        """Initialize secrets scanner."""
        self.detected_secrets: List[DetectedSecret] = []

        self.statistics = {
            "files_scanned": 0,
            "secrets_found": 0,
            "secrets_by_type": {},
            "secrets_by_location": {},
            "high_entropy_matches": 0,
            "last_scan": None
        }

        # Secret patterns (regex)
        self.secret_patterns = {
            SecretType.AWS_ACCESS_KEY: [
                (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
                (r'aws_access_key_id\s*=\s*["\']?([A-Z0-9]{20})["\']?', "AWS Access Key")
            ],
            SecretType.PRIVATE_KEY: [
                (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Private Key"),
                (r'-----BEGIN OPENSSH PRIVATE KEY-----', "OpenSSH Private Key")
            ],
            SecretType.API_KEY: [
                (r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "Generic API Key"),
                (r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API Key")
            ],
            SecretType.PASSWORD: [
                (r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "Password"),
                (r'passwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "Password")
            ],
            SecretType.JWT_TOKEN: [
                (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', "JWT Token")
            ],
            SecretType.GCP_SERVICE_ACCOUNT: [
                (r'"type":\s*"service_account"', "GCP Service Account Key")
            ],
            SecretType.AZURE_CLIENT_SECRET: [
                (r'client_secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-~.]{32,})["\']', "Azure Client Secret")
            ],
            SecretType.DATABASE_CONNECTION: [
                (r'(?:mysql|postgresql|mongodb)://[^:]+:[^@]+@', "Database Connection String")
            ]
        }

        logger.info("Secrets Scanner initialized")

    async def scan_file(
        self,
        file_path: str,
        content: str,
        location: SecretLocation = SecretLocation.SOURCE_CODE
    ) -> List[DetectedSecret]:
        """
        Scan file content for secrets.

        Args:
            file_path: Path to file
            content: File content
            location: Where the file is located

        Returns:
            List of detected secrets
        """
        logger.info(f"Scanning file for secrets: {file_path}")

        secrets = []
        lines = content.split('\n')

        for secret_type, patterns in self.secret_patterns.items():
            for pattern, description in patterns:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)

                    for match in matches:
                        matched_text = match.group(0)

                        # Calculate entropy
                        entropy = self._calculate_entropy(matched_text)

                        # High entropy indicates likely secret
                        if entropy > 3.5 or secret_type in [
                            SecretType.PRIVATE_KEY,
                            SecretType.JWT_TOKEN,
                            SecretType.GCP_SERVICE_ACCOUNT
                        ]:
                            severity = self._determine_severity(secret_type, entropy)

                            secret = DetectedSecret(
                                secret_id=f"secret-{hashlib.md5(f'{file_path}{line_num}{matched_text}'.encode()).hexdigest()[:12]}",
                                secret_type=secret_type,
                                location=location,
                                file_path=file_path,
                                line_number=line_num,
                                matched_pattern=description,
                                entropy_score=entropy,
                                severity=severity,
                                remediation=self._get_remediation(secret_type)
                            )

                            secrets.append(secret)
                            self.detected_secrets.append(secret)

                            # Update statistics
                            self.statistics["secrets_found"] += 1

                            if secret_type.value not in self.statistics["secrets_by_type"]:
                                self.statistics["secrets_by_type"][secret_type.value] = 0
                            self.statistics["secrets_by_type"][secret_type.value] += 1

                            if location.value not in self.statistics["secrets_by_location"]:
                                self.statistics["secrets_by_location"][location.value] = 0
                            self.statistics["secrets_by_location"][location.value] += 1

                            if entropy > 4.0:
                                self.statistics["high_entropy_matches"] += 1

        self.statistics["files_scanned"] += 1
        self.statistics["last_scan"] = datetime.utcnow().isoformat()

        logger.info(f"Found {len(secrets)} secrets in {file_path}")

        return secrets

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        # Calculate character frequency
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        text_len = len(text)

        for count in freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * (probability ** 0.5)  # Simplified entropy

        return entropy

    def _determine_severity(self, secret_type: SecretType, entropy: float) -> Severity:
        """Determine severity based on secret type and entropy."""
        # Critical secrets
        if secret_type in [
            SecretType.PRIVATE_KEY,
            SecretType.AWS_ACCESS_KEY,
            SecretType.GCP_SERVICE_ACCOUNT
        ]:
            return Severity.CRITICAL

        # High severity
        if secret_type in [
            SecretType.API_KEY,
            SecretType.DATABASE_CONNECTION,
            SecretType.AZURE_CLIENT_SECRET
        ] or entropy > 4.5:
            return Severity.HIGH

        # Medium severity
        if entropy > 3.5:
            return Severity.MEDIUM

        return Severity.LOW

    def _get_remediation(self, secret_type: SecretType) -> str:
        """Get remediation advice for secret type."""
        remediations = {
            SecretType.AWS_ACCESS_KEY: "Rotate AWS access keys immediately. Use AWS Secrets Manager or IAM roles.",
            SecretType.PRIVATE_KEY: "Remove private key from code. Use key management service (KMS).",
            SecretType.API_KEY: "Rotate API key. Store in secrets manager or environment variables.",
            SecretType.PASSWORD: "Remove password from code. Use secrets manager or vault.",
            SecretType.JWT_TOKEN: "Revoke token. Implement proper token management.",
            SecretType.GCP_SERVICE_ACCOUNT: "Rotate service account key. Use Workload Identity.",
            SecretType.AZURE_CLIENT_SECRET: "Rotate client secret. Use Azure Key Vault.",
            SecretType.DATABASE_CONNECTION: "Remove connection string. Use managed identities or secrets manager."
        }

        return remediations.get(
            secret_type,
            "Remove secret from code. Use secrets management solution."
        )

    async def scan_directory(
        self,
        directory_path: str,
        file_extensions: Optional[List[str]] = None
    ) -> List[DetectedSecret]:
        """
        Scan directory for secrets.

        Args:
            directory_path: Directory to scan
            file_extensions: File extensions to scan (None = all)

        Returns:
            List of detected secrets
        """
        # Mock implementation - would use os.walk in production
        logger.info(f"Scanning directory: {directory_path}")

        # Simulate scanning a few files
        mock_files = [
            ("config.py", "api_key = 'sk-1234567890abcdefghijklmnopqrstuvwxyz'"),
            ("secrets.yaml", "password: 'MySecretPassword123!'"),
            (".env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
        ]

        all_secrets = []
        for filename, content in mock_files:
            secrets = await self.scan_file(
                f"{directory_path}/{filename}",
                content,
                SecretLocation.CONFIGURATION_FILE
            )
            all_secrets.extend(secrets)

        return all_secrets

    def get_secrets_by_severity(self, severity: Severity) -> List[DetectedSecret]:
        """Get secrets by severity."""
        return [s for s in self.detected_secrets if s.severity == severity]

    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics."""
        return self.statistics


# Global instance
_secrets_scanner: Optional[SecretsScanner] = None


def get_secrets_scanner() -> SecretsScanner:
    """Get or create global secrets scanner instance."""
    global _secrets_scanner

    if _secrets_scanner is None:
        _secrets_scanner = SecretsScanner()

    return _secrets_scanner


class CredentialManager:
    """
    Credential lifecycle management.

    Manages credential rotation, expiration tracking, and vault integration.
    """

    def __init__(self):
        """Initialize credential manager."""
        self.credentials: Dict[str, Credential] = {}

        self.statistics = {
            "credentials_managed": 0,
            "credentials_rotated": 0,
            "credentials_expired": 0,
            "rotation_success_rate": 0.0,
            "last_rotation": None
        }

        # Rotation policies (days)
        self.rotation_policies = {
            "password": 90,
            "api_key": 180,
            "certificate": 365,
            "service_account_key": 90,
            "access_token": 30
        }

        logger.info("Credential Manager initialized")

    async def register_credential(
        self,
        name: str,
        credential_type: str,
        owner: str,
        expires_at: Optional[datetime] = None
    ) -> Credential:
        """
        Register a new credential for management.

        Args:
            name: Credential name
            credential_type: Type of credential
            owner: Owner/principal
            expires_at: Expiration date

        Returns:
            Registered credential
        """
        logger.info(f"Registering credential: {name}")

        # Get rotation policy
        rotation_days = self.rotation_policies.get(credential_type, 90)
        rotation_policy = f"Rotate every {rotation_days} days"

        # Calculate expiration if not provided
        if expires_at is None:
            expires_at = datetime.utcnow() + timedelta(days=rotation_days)

        credential = Credential(
            credential_id=f"cred-{hashlib.md5(f'{name}{owner}'.encode()).hexdigest()[:12]}",
            name=name,
            credential_type=credential_type,
            owner=owner,
            created_at=datetime.utcnow(),
            expires_at=expires_at,
            last_rotated=datetime.utcnow(),
            rotation_policy=rotation_policy,
            is_active=True
        )

        self.credentials[credential.credential_id] = credential
        self.statistics["credentials_managed"] += 1

        return credential

    async def rotate_credential(self, credential_id: str) -> bool:
        """
        Rotate a credential.

        Args:
            credential_id: Credential to rotate

        Returns:
            True if rotation successful
        """
        credential = self.credentials.get(credential_id)
        if not credential:
            logger.error(f"Credential not found: {credential_id}")
            return False

        logger.info(f"Rotating credential: {credential.name}")

        # Simulate rotation
        # In production, this would call cloud provider APIs
        await asyncio.sleep(0.1)

        # Update credential
        credential.last_rotated = datetime.utcnow()

        # Extend expiration
        rotation_days = self.rotation_policies.get(credential.credential_type, 90)
        credential.expires_at = datetime.utcnow() + timedelta(days=rotation_days)

        self.statistics["credentials_rotated"] += 1
        self.statistics["last_rotation"] = datetime.utcnow().isoformat()

        # Update success rate
        total_rotations = self.statistics["credentials_rotated"]
        self.statistics["rotation_success_rate"] = (total_rotations / (total_rotations + 1)) * 100

        logger.info(f"Credential rotated successfully: {credential.name}")

        return True

    async def check_expiring_credentials(
        self,
        days_threshold: int = 30
    ) -> List[Credential]:
        """
        Check for credentials expiring soon.

        Args:
            days_threshold: Days until expiration to check

        Returns:
            List of expiring credentials
        """
        expiring = []
        threshold_date = datetime.utcnow() + timedelta(days=days_threshold)

        for credential in self.credentials.values():
            if credential.expires_at and credential.expires_at <= threshold_date:
                expiring.append(credential)

                if credential.expires_at <= datetime.utcnow():
                    self.statistics["credentials_expired"] += 1

        return expiring

    async def auto_rotate_credentials(self) -> Dict[str, Any]:
        """
        Automatically rotate credentials based on policy.

        Returns:
            Rotation results
        """
        logger.info("Starting automatic credential rotation")

        rotated = []
        failed = []

        for credential in self.credentials.values():
            if not credential.is_active:
                continue

            # Check if rotation needed
            if credential.last_rotated:
                rotation_days = self.rotation_policies.get(credential.credential_type, 90)
                next_rotation = credential.last_rotated + timedelta(days=rotation_days)

                if datetime.utcnow() >= next_rotation:
                    success = await self.rotate_credential(credential.credential_id)

                    if success:
                        rotated.append(credential.name)
                    else:
                        failed.append(credential.name)

        return {
            "rotated": rotated,
            "failed": failed,
            "total": len(rotated) + len(failed)
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get credential manager statistics."""
        return self.statistics


class ZeroTrustEngine:
    """
    Zero trust policy engine.

    Implements continuous verification, least privilege enforcement,
    and micro-segmentation.
    """

    def __init__(self):
        """Initialize zero trust engine."""
        self.policies: Dict[str, ZeroTrustPolicy] = {}

        self.statistics = {
            "policies_enforced": 0,
            "access_requests": 0,
            "access_allowed": 0,
            "access_denied": 0,
            "access_challenged": 0,
            "policy_violations": 0
        }

        logger.info("Zero Trust Engine initialized")

    async def create_policy(
        self,
        name: str,
        principal: str,
        resource: str,
        action: ZeroTrustPolicyAction,
        conditions: Optional[Dict[str, Any]] = None
    ) -> ZeroTrustPolicy:
        """
        Create zero trust policy.

        Args:
            name: Policy name
            principal: Principal (user, role, service)
            resource: Resource to access
            action: Policy action
            conditions: Access conditions

        Returns:
            Created policy
        """
        logger.info(f"Creating zero trust policy: {name}")

        policy = ZeroTrustPolicy(
            policy_id=f"zt-{hashlib.md5(f'{name}{principal}{resource}'.encode()).hexdigest()[:12]}",
            name=name,
            principal=principal,
            resource=resource,
            action=action,
            conditions=conditions or {},
            priority=100,
            enabled=True
        )

        self.policies[policy.policy_id] = policy

        return policy

    async def evaluate_access(
        self,
        principal: str,
        resource: str,
        context: Dict[str, Any]
    ) -> Tuple[ZeroTrustPolicyAction, str]:
        """
        Evaluate access request against zero trust policies.

        Args:
            principal: Requesting principal
            resource: Requested resource
            context: Request context (time, location, device, etc.)

        Returns:
            Tuple of (action, reason)
        """
        logger.info(f"Evaluating access: {principal} -> {resource}")

        self.statistics["access_requests"] += 1

        # Find matching policies (sorted by priority)
        matching_policies = [
            p for p in self.policies.values()
            if p.enabled and (p.principal == principal or p.principal == "*")
            and (p.resource == resource or p.resource == "*")
        ]

        matching_policies.sort(key=lambda p: p.priority)

        # Evaluate policies
        for policy in matching_policies:
            # Check conditions
            if self._check_conditions(policy.conditions, context):
                self.statistics["policies_enforced"] += 1

                if policy.action == ZeroTrustPolicyAction.ALLOW:
                    self.statistics["access_allowed"] += 1
                    return (policy.action, f"Allowed by policy: {policy.name}")

                elif policy.action == ZeroTrustPolicyAction.DENY:
                    self.statistics["access_denied"] += 1
                    self.statistics["policy_violations"] += 1
                    return (policy.action, f"Denied by policy: {policy.name}")

                elif policy.action == ZeroTrustPolicyAction.CHALLENGE:
                    self.statistics["access_challenged"] += 1
                    return (policy.action, f"Additional verification required: {policy.name}")

        # Default deny
        self.statistics["access_denied"] += 1
        return (ZeroTrustPolicyAction.DENY, "No matching policy found (default deny)")

    def _check_conditions(
        self,
        conditions: Dict[str, Any],
        context: Dict[str, Any]
    ) -> bool:
        """Check if context meets policy conditions."""
        if not conditions:
            return True

        # Check time-based conditions
        if "time_of_day" in conditions:
            # Would check current time against allowed hours
            pass

        # Check location-based conditions
        if "allowed_locations" in conditions:
            user_location = context.get("location")
            if user_location not in conditions["allowed_locations"]:
                return False

        # Check device trust
        if "device_trust_required" in conditions:
            device_trust = context.get("device_trust_score", 0)
            if device_trust < conditions["device_trust_required"]:
                return False

        # Check risk score
        if "max_risk_score" in conditions:
            risk_score = context.get("risk_score", 10)
            if risk_score > conditions["max_risk_score"]:
                return False

        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Get zero trust engine statistics."""
        stats = self.statistics.copy()

        # Calculate rates
        if stats["access_requests"] > 0:
            stats["allow_rate"] = (stats["access_allowed"] / stats["access_requests"]) * 100
            stats["deny_rate"] = (stats["access_denied"] / stats["access_requests"]) * 100
            stats["challenge_rate"] = (stats["access_challenged"] / stats["access_requests"]) * 100

        return stats


# Global instances
_credential_manager: Optional[CredentialManager] = None
_zero_trust_engine: Optional[ZeroTrustEngine] = None


def get_credential_manager() -> CredentialManager:
    """Get or create global credential manager instance."""
    global _credential_manager

    if _credential_manager is None:
        _credential_manager = CredentialManager()

    return _credential_manager


def get_zero_trust_engine() -> ZeroTrustEngine:
    """Get or create global zero trust engine instance."""
    global _zero_trust_engine

    if _zero_trust_engine is None:
        _zero_trust_engine = ZeroTrustEngine()

    return _zero_trust_engine


class IdentityThreatDetector:
    """
    Identity-based threat detection.

    Detects anomalous access patterns, privilege abuse,
    and lateral movement attempts.
    """

    def __init__(self):
        """Initialize identity threat detector."""
        self.threats: List[IdentityThreat] = []
        self.access_history: Dict[str, List[Dict[str, Any]]] = {}

        self.statistics = {
            "threats_detected": 0,
            "anomalous_access": 0,
            "privilege_abuse": 0,
            "lateral_movement": 0,
            "threats_by_severity": {s.value: 0 for s in Severity}
        }

        logger.info("Identity Threat Detector initialized")

    async def analyze_access_pattern(
        self,
        principal: IAMPrincipal,
        access_event: Dict[str, Any]
    ) -> Optional[IdentityThreat]:
        """
        Analyze access pattern for threats.

        Args:
            principal: IAM principal
            access_event: Access event details

        Returns:
            Detected threat or None
        """
        logger.info(f"Analyzing access pattern for: {principal.name}")

        # Store access history
        if principal.principal_id not in self.access_history:
            self.access_history[principal.principal_id] = []

        self.access_history[principal.principal_id].append(access_event)

        # Check for anomalous access
        threat = await self._check_anomalous_access(principal, access_event)
        if threat:
            return threat

        # Check for privilege abuse
        threat = await self._check_privilege_abuse(principal, access_event)
        if threat:
            return threat

        # Check for lateral movement
        threat = await self._check_lateral_movement(principal, access_event)
        if threat:
            return threat

        return None

    async def _check_anomalous_access(
        self,
        principal: IAMPrincipal,
        access_event: Dict[str, Any]
    ) -> Optional[IdentityThreat]:
        """Check for anomalous access patterns."""
        history = self.access_history.get(principal.principal_id, [])

        # Check for unusual time
        event_time = access_event.get("timestamp", datetime.utcnow())
        if isinstance(event_time, str):
            event_time = datetime.fromisoformat(event_time.replace('Z', '+00:00'))

        hour = event_time.hour

        # Unusual hours (2 AM - 5 AM)
        if 2 <= hour <= 5 and len(history) > 5:
            # Check if this is unusual for this principal
            normal_hours = [
                datetime.fromisoformat(h["timestamp"].replace('Z', '+00:00')).hour
                for h in history[-10:]
                if "timestamp" in h
            ]

            if normal_hours and all(h < 2 or h > 5 for h in normal_hours):
                threat = IdentityThreat(
                    threat_id=f"threat-{hashlib.md5(f'{principal.principal_id}{event_time}'.encode()).hexdigest()[:12]}",
                    principal=principal,
                    threat_type="anomalous_access",
                    severity=Severity.MEDIUM,
                    description=f"Unusual access time detected for {principal.name} at {hour}:00",
                    indicators=[
                        f"Access at {hour}:00 (unusual for this principal)",
                        f"Normal access hours: {min(normal_hours)}-{max(normal_hours)}"
                    ],
                    timeline=[access_event],
                    risk_score=6.0
                )

                self.threats.append(threat)
                self.statistics["threats_detected"] += 1
                self.statistics["anomalous_access"] += 1
                self.statistics["threats_by_severity"][Severity.MEDIUM.value] += 1

                return threat

        # Check for unusual location
        location = access_event.get("location")
        if location:
            recent_locations = [
                h.get("location")
                for h in history[-10:]
                if h.get("location")
            ]

            if recent_locations and location not in recent_locations:
                threat = IdentityThreat(
                    threat_id=f"threat-{hashlib.md5(f'{principal.principal_id}{location}'.encode()).hexdigest()[:12]}",
                    principal=principal,
                    threat_type="anomalous_access",
                    severity=Severity.HIGH,
                    description=f"Access from unusual location: {location}",
                    indicators=[
                        f"New location: {location}",
                        f"Recent locations: {', '.join(set(recent_locations))}"
                    ],
                    timeline=[access_event],
                    risk_score=7.5
                )

                self.threats.append(threat)
                self.statistics["threats_detected"] += 1
                self.statistics["anomalous_access"] += 1
                self.statistics["threats_by_severity"][Severity.HIGH.value] += 1

                return threat

        return None

    async def _check_privilege_abuse(
        self,
        principal: IAMPrincipal,
        access_event: Dict[str, Any]
    ) -> Optional[IdentityThreat]:
        """Check for privilege abuse."""
        action = access_event.get("action", "")

        # Check for sensitive actions
        sensitive_actions = [
            "iam:CreateAccessKey",
            "iam:AttachUserPolicy",
            "iam:PutUserPolicy",
            "sts:AssumeRole",
            "secretsmanager:GetSecretValue",
            "kms:Decrypt"
        ]

        if any(sensitive in action for sensitive in sensitive_actions):
            # Check if this is unusual for this principal
            history = self.access_history.get(principal.principal_id, [])
            recent_actions = [h.get("action", "") for h in history[-20:]]

            # If this sensitive action hasn't been used recently
            if action not in recent_actions:
                threat = IdentityThreat(
                    threat_id=f"threat-{hashlib.md5(f'{principal.principal_id}{action}'.encode()).hexdigest()[:12]}",
                    principal=principal,
                    threat_type="privilege_abuse",
                    severity=Severity.HIGH,
                    description=f"Unusual sensitive action: {action}",
                    indicators=[
                        f"Sensitive action: {action}",
                        "Action not seen in recent history",
                        f"Principal: {principal.name}"
                    ],
                    timeline=[access_event],
                    risk_score=8.0
                )

                self.threats.append(threat)
                self.statistics["threats_detected"] += 1
                self.statistics["privilege_abuse"] += 1
                self.statistics["threats_by_severity"][Severity.HIGH.value] += 1

                return threat

        return None

    async def _check_lateral_movement(
        self,
        principal: IAMPrincipal,
        access_event: Dict[str, Any]
    ) -> Optional[IdentityThreat]:
        """Check for lateral movement attempts."""
        action = access_event.get("action", "")
        resource = access_event.get("resource", "")

        # Lateral movement indicators
        lateral_indicators = [
            "sts:AssumeRole",
            "iam:PassRole",
            "ec2:RunInstances",
            "lambda:CreateFunction",
            "ecs:RunTask"
        ]

        if any(indicator in action for indicator in lateral_indicators):
            # Check for rapid role switching or resource creation
            history = self.access_history.get(principal.principal_id, [])
            recent_events = history[-5:] if len(history) >= 5 else history

            # Count similar actions in short time
            similar_actions = sum(
                1 for e in recent_events
                if any(ind in e.get("action", "") for ind in lateral_indicators)
            )

            if similar_actions >= 2:
                threat = IdentityThreat(
                    threat_id=f"threat-{hashlib.md5(f'{principal.principal_id}lateral'.encode()).hexdigest()[:12]}",
                    principal=principal,
                    threat_type="lateral_movement",
                    severity=Severity.CRITICAL,
                    description=f"Potential lateral movement detected for {principal.name}",
                    indicators=[
                        f"Multiple lateral movement actions: {similar_actions}",
                        f"Recent action: {action}",
                        f"Target resource: {resource}"
                    ],
                    timeline=recent_events + [access_event],
                    risk_score=9.0
                )

                self.threats.append(threat)
                self.statistics["threats_detected"] += 1
                self.statistics["lateral_movement"] += 1
                self.statistics["threats_by_severity"][Severity.CRITICAL.value] += 1

                return threat

        return None

    def get_threats_by_severity(self, severity: Severity) -> List[IdentityThreat]:
        """Get threats by severity."""
        return [t for t in self.threats if t.severity == severity]

    def get_threats_by_principal(self, principal_id: str) -> List[IdentityThreat]:
        """Get threats for specific principal."""
        return [t for t in self.threats if t.principal.principal_id == principal_id]

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat detector statistics."""
        return self.statistics


class IAMSecurityOrchestrator:
    """
    Orchestrator for IAM security operations.

    Coordinates IAM analysis, secrets scanning, credential management,
    zero trust enforcement, and threat detection.
    """

    def __init__(self):
        """Initialize IAM security orchestrator."""
        self.iam_analyzer = get_iam_analyzer()
        self.secrets_scanner = get_secrets_scanner()
        self.credential_manager = get_credential_manager()
        self.zero_trust_engine = get_zero_trust_engine()
        self.threat_detector = IdentityThreatDetector()

        logger.info("IAM Security Orchestrator initialized")

    async def full_iam_assessment(
        self,
        principals: List[IAMPrincipal],
        scan_paths: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Perform full IAM security assessment.

        Args:
            principals: IAM principals to analyze
            scan_paths: Paths to scan for secrets

        Returns:
            Complete assessment results
        """
        logger.info("Starting full IAM security assessment")

        start_time = datetime.utcnow()

        # Analyze IAM principals
        principal_analyses = []
        for principal in principals:
            analysis = await self.iam_analyzer.analyze_principal(principal)
            principal_analyses.append(analysis)

        # Scan for secrets
        detected_secrets = []
        if scan_paths:
            for path in scan_paths:
                secrets = await self.secrets_scanner.scan_directory(path)
                detected_secrets.extend(secrets)

        # Check credential expiration
        expiring_credentials = await self.credential_manager.check_expiring_credentials(30)

        # Get escalation paths
        escalation_paths = self.iam_analyzer.get_escalation_paths()

        # Get over-privileged roles
        over_privileged = self.iam_analyzer.get_over_privileged_roles()

        # Calculate overall risk score
        risk_score = self._calculate_overall_risk(
            escalation_paths,
            over_privileged,
            detected_secrets
        )

        duration = (datetime.utcnow() - start_time).total_seconds()

        assessment = {
            "assessment_id": f"iam-assess-{int(datetime.utcnow().timestamp())}",
            "timestamp": datetime.utcnow().isoformat(),
            "duration_seconds": duration,
            "principals_analyzed": len(principals),
            "iam_analysis": {
                "principals": principal_analyses,
                "escalation_paths": len(escalation_paths),
                "over_privileged_roles": len(over_privileged)
            },
            "secrets_scanning": {
                "secrets_found": len(detected_secrets),
                "critical_secrets": len([s for s in detected_secrets if s.severity == Severity.CRITICAL]),
                "high_severity": len([s for s in detected_secrets if s.severity == Severity.HIGH])
            },
            "credential_management": {
                "expiring_soon": len(expiring_credentials),
                "expired": len([c for c in expiring_credentials if c.expires_at and c.expires_at <= datetime.utcnow()])
            },
            "overall_risk_score": risk_score,
            "recommendations": self._generate_recommendations(
                escalation_paths,
                over_privileged,
                detected_secrets,
                expiring_credentials
            )
        }

        logger.info(f"IAM assessment complete. Risk score: {risk_score}")

        return assessment

    def _calculate_overall_risk(
        self,
        escalation_paths: List[PrivilegeEscalationPath],
        over_privileged: List[OverPrivilegedRole],
        secrets: List[DetectedSecret]
    ) -> float:
        """Calculate overall IAM risk score."""
        risk = 0.0

        # Escalation paths (high impact)
        risk += len(escalation_paths) * 2.0

        # Over-privileged roles
        risk += len(over_privileged) * 1.5

        # Critical secrets
        critical_secrets = [s for s in secrets if s.severity == Severity.CRITICAL]
        risk += len(critical_secrets) * 3.0

        # High severity secrets
        high_secrets = [s for s in secrets if s.severity == Severity.HIGH]
        risk += len(high_secrets) * 1.5

        # Normalize to 0-10 scale
        return min(risk, 10.0)

    def _generate_recommendations(
        self,
        escalation_paths: List[PrivilegeEscalationPath],
        over_privileged: List[OverPrivilegedRole],
        secrets: List[DetectedSecret],
        expiring_credentials: List[Credential]
    ) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        if escalation_paths:
            recommendations.append(
                f"CRITICAL: {len(escalation_paths)} privilege escalation paths detected. "
                "Review and restrict dangerous permissions immediately."
            )

        if over_privileged:
            recommendations.append(
                f"HIGH: {len(over_privileged)} over-privileged roles found. "
                "Apply principle of least privilege."
            )

        critical_secrets = [s for s in secrets if s.severity == Severity.CRITICAL]
        if critical_secrets:
            recommendations.append(
                f"CRITICAL: {len(critical_secrets)} critical secrets exposed. "
                "Rotate immediately and remove from code."
            )

        if expiring_credentials:
            recommendations.append(
                f"MEDIUM: {len(expiring_credentials)} credentials expiring soon. "
                "Schedule rotation to prevent service disruption."
            )

        if not recommendations:
            recommendations.append("No critical issues found. Continue monitoring.")

        return recommendations


# Global instances
_identity_threat_detector: Optional[IdentityThreatDetector] = None
_iam_orchestrator: Optional[IAMSecurityOrchestrator] = None


def get_identity_threat_detector() -> IdentityThreatDetector:
    """Get or create global identity threat detector instance."""
    global _identity_threat_detector

    if _identity_threat_detector is None:
        _identity_threat_detector = IdentityThreatDetector()

    return _identity_threat_detector


def get_iam_orchestrator() -> IAMSecurityOrchestrator:
    """Get or create global IAM orchestrator instance."""
    global _iam_orchestrator

    if _iam_orchestrator is None:
        _iam_orchestrator = IAMSecurityOrchestrator()

    return _iam_orchestrator

