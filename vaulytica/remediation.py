import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from vaulytica.cspm import CloudResource, Finding, CloudProvider, ResourceType
from vaulytica.vulnerability_management import VulnerabilityAssessment, CVEDetails
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class RemediationType(str, Enum):
    """Types of remediation actions."""
    CONFIGURATION_CHANGE = "configuration_change"
    PATCH_DEPLOYMENT = "patch_deployment"
    RESOURCE_REPLACEMENT = "resource_replacement"
    POLICY_UPDATE = "policy_update"
    ACCESS_CONTROL = "access_control"
    ENCRYPTION_ENABLE = "encryption_enable"
    LOGGING_ENABLE = "logging_enable"
    MONITORING_ENABLE = "monitoring_enable"


class RemediationStatus(str, Enum):
    """Remediation status."""
    PENDING = "pending"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class IaCFormat(str, Enum):
    """Infrastructure as Code formats."""
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    AZURE_ARM = "azure_arm"
    PULUMI = "pulumi"


@dataclass
class RemediationPlan:
    """Remediation plan for a finding or vulnerability."""
    plan_id: str
    title: str
    description: str
    remediation_type: RemediationType
    resource: CloudResource
    
    # Actions
    steps: List[str] = field(default_factory=list)
    iac_template: Optional[str] = None
    iac_format: Optional[IaCFormat] = None
    
    # Risk assessment
    estimated_effort: str = "medium"  # low, medium, high
    risk_of_change: str = "medium"  # low, medium, high
    requires_downtime: bool = False
    requires_approval: bool = True
    
    # Execution
    status: RemediationStatus = RemediationStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    approved_by: Optional[str] = None
    
    # Results
    success: bool = False
    error_message: Optional[str] = None
    rollback_available: bool = True
    
    # Related items
    finding_id: Optional[str] = None
    vulnerability_id: Optional[str] = None


class RemediationEngine:
    """
    Automated remediation engine.
    
    Generates and executes remediation plans with IaC templates.
    """
    
    def __init__(self):
        """Initialize remediation engine."""
        self.plans: Dict[str, RemediationPlan] = {}
        
        self.statistics = {
            "total_plans_created": 0,
            "plans_executed": 0,
            "plans_successful": 0,
            "plans_failed": 0,
            "plans_rolled_back": 0,
            "plans_by_type": {t.value: 0 for t in RemediationType}
        }
        
        logger.info("Remediation Engine initialized")
    
    async def create_remediation_plan(
        self,
        resource: CloudResource,
        finding: Optional[Finding] = None,
        vulnerability: Optional[VulnerabilityAssessment] = None
    ) -> RemediationPlan:
        """
        Create remediation plan for a finding or vulnerability.
        
        Args:
            resource: Resource to remediate
            finding: Compliance finding (optional)
            vulnerability: Vulnerability assessment (optional)
        
        Returns:
            Remediation plan
        """
        logger.info(f"Creating remediation plan for {resource.resource_id}")
        
        # Determine remediation type and steps
        if finding:
            plan = await self._create_plan_from_finding(resource, finding)
        elif vulnerability:
            plan = await self._create_plan_from_vulnerability(resource, vulnerability)
        else:
            raise ValueError("Either finding or vulnerability must be provided")
        
        self.plans[plan.plan_id] = plan
        self.statistics["total_plans_created"] += 1
        self.statistics["plans_by_type"][plan.remediation_type.value] += 1
        
        logger.info(f"Created remediation plan {plan.plan_id}")
        
        return plan
    
    async def _create_plan_from_finding(self, resource: CloudResource, finding: Finding) -> RemediationPlan:
        """Create remediation plan from compliance finding."""
        plan_id = f"plan-{finding.finding_id}"
        
        # Determine remediation based on check ID
        if "s3" in finding.check.check_id.lower() and "encryption" in finding.check.check_id.lower():
            return await self._create_s3_encryption_plan(resource, finding, plan_id)
        
        elif "s3" in finding.check.check_id.lower() and "logging" in finding.check.check_id.lower():
            return await self._create_s3_logging_plan(resource, finding, plan_id)
        
        elif "sg" in finding.check.check_id.lower() or "security_group" in finding.check.check_id.lower():
            return await self._create_security_group_plan(resource, finding, plan_id)
        
        else:
            # Generic plan
            return RemediationPlan(
                plan_id=plan_id,
                title=f"Remediate: {finding.title}",
                description=finding.remediation,
                remediation_type=RemediationType.CONFIGURATION_CHANGE,
                resource=resource,
                steps=[finding.remediation],
                finding_id=finding.finding_id
            )
    
    async def _create_s3_encryption_plan(
        self,
        resource: CloudResource,
        finding: Finding,
        plan_id: str
    ) -> RemediationPlan:
        """Create plan to enable S3 bucket encryption."""
        # Generate Terraform template
        terraform_template = f"""
resource "aws_s3_bucket_server_side_encryption_configuration" "{resource.name}_encryption" {{
  bucket = "{resource.name}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm     = "AES256"
    }}
  }}
}}
"""
        
        # Generate CloudFormation template
        cloudformation_template = f"""
Resources:
  {resource.name}Encryption:
    Type: AWS::S3::BucketEncryption
    Properties:
      BucketName: {resource.name}
      ServerSideEncryptionConfiguration:
        - ServerSideEncryptionByDefault:
            SSEAlgorithm: AES256
"""
        
        return RemediationPlan(
            plan_id=plan_id,
            title="Enable S3 Bucket Encryption",
            description=f"Enable default encryption for S3 bucket {resource.name}",
            remediation_type=RemediationType.ENCRYPTION_ENABLE,
            resource=resource,
            steps=[
                "1. Review current bucket configuration",
                "2. Apply encryption configuration",
                "3. Verify encryption is enabled",
                "4. Test bucket access"
            ],
            iac_template=terraform_template,
            iac_format=IaCFormat.TERRAFORM,
            estimated_effort="low",
            risk_of_change="low",
            requires_downtime=False,
            finding_id=finding.finding_id
        )
    
    async def _create_s3_logging_plan(
        self,
        resource: CloudResource,
        finding: Finding,
        plan_id: str
    ) -> RemediationPlan:
        """Create plan to enable S3 bucket logging."""
        terraform_template = f"""
resource "aws_s3_bucket_logging" "{resource.name}_logging" {{
  bucket = "{resource.name}"

  target_bucket = "${{var.logging_bucket}}"
  target_prefix = "s3-access-logs/{resource.name}/"
}}
"""
        
        return RemediationPlan(
            plan_id=plan_id,
            title="Enable S3 Bucket Logging",
            description=f"Enable access logging for S3 bucket {resource.name}",
            remediation_type=RemediationType.LOGGING_ENABLE,
            resource=resource,
            steps=[
                "1. Create or identify logging bucket",
                "2. Configure bucket logging",
                "3. Verify logs are being generated",
                "4. Set up log analysis"
            ],
            iac_template=terraform_template,
            iac_format=IaCFormat.TERRAFORM,
            estimated_effort="low",
            risk_of_change="low",
            requires_downtime=False,
            finding_id=finding.finding_id
        )
    
    async def _create_security_group_plan(
        self,
        resource: CloudResource,
        finding: Finding,
        plan_id: str
    ) -> RemediationPlan:
        """Create plan to fix security group rules."""
        # Determine which port to restrict
        port = 22 if "ssh" in finding.check.check_id.lower() else 3389
        protocol = "SSH" if port == 22 else "RDP"
        
        terraform_template = f"""
resource "aws_security_group_rule" "{resource.name}_restrict_{port}" {{
  type              = "ingress"
  from_port         = {port}
  to_port           = {port}
  protocol          = "tcp"
  cidr_blocks       = ["${{var.admin_cidr}}"]  # Replace with your admin IP range
  security_group_id = "{resource.resource_id}"
  description       = "Restrict {protocol} access to admin IPs only"
}}
"""
        
        return RemediationPlan(
            plan_id=plan_id,
            title=f"Restrict {protocol} Access",
            description=f"Remove unrestricted {protocol} access from security group {resource.name}",
            remediation_type=RemediationType.ACCESS_CONTROL,
            resource=resource,
            steps=[
                f"1. Identify legitimate {protocol} users",
                f"2. Remove 0.0.0.0/0 rule for port {port}",
                f"3. Add restricted rule with specific IP ranges",
                "4. Verify connectivity for authorized users",
                "5. Monitor for access issues"
            ],
            iac_template=terraform_template,
            iac_format=IaCFormat.TERRAFORM,
            estimated_effort="medium",
            risk_of_change="medium",
            requires_downtime=False,
            requires_approval=True,
            finding_id=finding.finding_id
        )
    
    async def _create_plan_from_vulnerability(
        self,
        resource: CloudResource,
        vulnerability: VulnerabilityAssessment
    ) -> RemediationPlan:
        """Create remediation plan from vulnerability assessment."""
        plan_id = f"plan-vuln-{vulnerability.assessment_id}"
        
        # Get highest severity vulnerability
        if vulnerability.vulnerabilities:
            highest_vuln = max(vulnerability.vulnerabilities, key=lambda v: v.cvss_v3_score)
            
            return RemediationPlan(
                plan_id=plan_id,
                title=f"Patch Vulnerability: {highest_vuln.cve_id}",
                description=highest_vuln.description,
                remediation_type=RemediationType.PATCH_DEPLOYMENT,
                resource=resource,
                steps=[
                    "1. Review vulnerability details and impact",
                    "2. Test patch in non-production environment",
                    "3. Schedule maintenance window",
                    "4. Deploy patch",
                    "5. Verify vulnerability is resolved",
                    "6. Monitor for issues"
                ],
                estimated_effort="high",
                risk_of_change="medium",
                requires_downtime=True,
                requires_approval=True,
                vulnerability_id=vulnerability.assessment_id
            )
        
        return RemediationPlan(
            plan_id=plan_id,
            title="No Vulnerabilities Found",
            description="No remediation needed",
            remediation_type=RemediationType.CONFIGURATION_CHANGE,
            resource=resource,
            vulnerability_id=vulnerability.assessment_id
        )
    
    async def execute_plan(self, plan_id: str, dry_run: bool = True) -> Dict[str, Any]:
        """
        Execute a remediation plan.
        
        Args:
            plan_id: Plan ID to execute
            dry_run: If True, simulate execution without making changes
        
        Returns:
            Execution results
        """
        plan = self.plans.get(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")
        
        if plan.requires_approval and plan.status != RemediationStatus.APPROVED:
            raise ValueError(f"Plan {plan_id} requires approval before execution")
        
        logger.info(f"Executing remediation plan {plan_id} (dry_run={dry_run})")
        
        plan.status = RemediationStatus.IN_PROGRESS
        plan.executed_at = datetime.utcnow()
        
        try:
            if dry_run:
                # Simulate execution
                result = {
                    "status": "success",
                    "dry_run": True,
                    "message": "Dry run completed successfully",
                    "changes": plan.steps
                }
                plan.success = True
            else:
                # Execute actual remediation
                result = await self._execute_remediation(plan)
                plan.success = result["status"] == "success"
            
            if plan.success:
                plan.status = RemediationStatus.COMPLETED
                plan.completed_at = datetime.utcnow()
                self.statistics["plans_successful"] += 1
            else:
                plan.status = RemediationStatus.FAILED
                plan.error_message = result.get("error")
                self.statistics["plans_failed"] += 1
            
            self.statistics["plans_executed"] += 1
            
            logger.info(f"Plan {plan_id} execution completed: {plan.status}")
            
            return result
            
        except Exception as e:
            plan.status = RemediationStatus.FAILED
            plan.error_message = str(e)
            self.statistics["plans_failed"] += 1
            logger.error(f"Plan {plan_id} execution failed: {e}")
            raise
    
    async def _execute_remediation(self, plan: RemediationPlan) -> Dict[str, Any]:
        """Execute actual remediation."""
        # In production, integrate with cloud provider APIs
        # For now, return mock success
        return {
            "status": "success",
            "message": f"Remediation completed for {plan.resource.resource_id}",
            "changes_applied": plan.steps
        }
    
    def approve_plan(self, plan_id: str, approved_by: str):
        """Approve a remediation plan."""
        plan = self.plans.get(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")
        
        plan.status = RemediationStatus.APPROVED
        plan.approved_at = datetime.utcnow()
        plan.approved_by = approved_by
        
        logger.info(f"Plan {plan_id} approved by {approved_by}")
    
    def get_plan(self, plan_id: str) -> Optional[RemediationPlan]:
        """Get remediation plan by ID."""
        return self.plans.get(plan_id)
    
    def get_plans_by_status(self, status: RemediationStatus) -> List[RemediationPlan]:
        """Get plans by status."""
        return [p for p in self.plans.values() if p.status == status]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get remediation engine statistics."""
        return self.statistics


# Global instance
_remediation_engine: Optional[RemediationEngine] = None


def get_remediation_engine() -> RemediationEngine:
    """Get or create global remediation engine instance."""
    global _remediation_engine
    
    if _remediation_engine is None:
        _remediation_engine = RemediationEngine()
    
    return _remediation_engine

