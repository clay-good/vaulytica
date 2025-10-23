"""
Automated Threat Response System

Provides automated threat containment, isolation, and remediation capabilities.
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional, Set


class ThreatSeverity(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ResponseAction(str, Enum):
    """Available response actions."""
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    DISABLE_USER = "disable_user"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    REVOKE_CREDENTIALS = "revoke_credentials"
    BLOCK_PORT = "block_port"
    ENABLE_MFA = "enable_mfa"
    RESET_PASSWORD = "reset_password"
    SNAPSHOT_SYSTEM = "snapshot_system"
    COLLECT_EVIDENCE = "collect_evidence"
    NOTIFY_TEAM = "notify_team"
    CREATE_TICKET = "create_ticket"
    ESCALATE = "escalate"


class ResponseStatus(str, Enum):
    """Response execution status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    REQUIRES_APPROVAL = "requires_approval"


class AutomationMode(str, Enum):
    """Automation modes."""
    FULLY_AUTOMATED = "fully_automated"
    SEMI_AUTOMATED = "semi_automated"  # Requires approval
    MANUAL = "manual"  # Suggest only


@dataclass
class ThreatContext:
    """Context about a detected threat."""
    threat_id: str
    threat_type: str
    severity: ThreatSeverity
    confidence: float
    affected_assets: List[str]
    indicators: Dict[str, Any]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ResponsePlan:
    """Automated response plan."""
    plan_id: str
    threat_id: str
    actions: List[ResponseAction]
    automation_mode: AutomationMode
    estimated_impact: str
    rollback_plan: List[Dict[str, Any]]
    requires_approval: bool
    approval_timeout_seconds: int = 300
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ResponseExecution:
    """Response execution tracking."""
    execution_id: str
    plan_id: str
    action: ResponseAction
    status: ResponseStatus
    target: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    rollback_data: Optional[Dict[str, Any]] = None


@dataclass
class ContainmentPolicy:
    """Containment policy definition."""
    policy_id: str
    name: str
    description: str
    threat_types: List[str]
    min_severity: ThreatSeverity
    min_confidence: float
    actions: List[ResponseAction]
    automation_mode: AutomationMode
    enabled: bool = True


class AutomatedThreatResponseSystem:
    """Automated threat response and containment system."""

    def __init__(self):
        self.policies: Dict[str, ContainmentPolicy] = {}
        self.response_plans: Dict[str, ResponsePlan] = {}
        self.executions: Dict[str, ResponseExecution] = {}
        self.pending_approvals: Set[str] = set()

        # Initialize default policies
        self._initialize_default_policies()

    def _initialize_default_policies(self):
        """Initialize default containment policies."""
        # Critical malware policy
        self.add_policy(ContainmentPolicy(
            policy_id="policy-malware-critical",
            name="Critical Malware Response",
            description="Automated response for critical malware detections",
            threat_types=["malware", "ransomware", "trojan"],
            min_severity=ThreatSeverity.CRITICAL,
            min_confidence=0.9,
            actions=[
                ResponseAction.ISOLATE_HOST,
                ResponseAction.QUARANTINE_FILE,
                ResponseAction.KILL_PROCESS,
                ResponseAction.SNAPSHOT_SYSTEM,
                ResponseAction.COLLECT_EVIDENCE,
                ResponseAction.NOTIFY_TEAM
            ],
            automation_mode=AutomationMode.FULLY_AUTOMATED
        ))

        # Compromised account policy
        self.add_policy(ContainmentPolicy(
            policy_id="policy-account-compromise",
            name="Account Compromise Response",
            description="Response for compromised user accounts",
            threat_types=["account_compromise", "credential_theft"],
            min_severity=ThreatSeverity.HIGH,
            min_confidence=0.8,
            actions=[
                ResponseAction.DISABLE_USER,
                ResponseAction.REVOKE_CREDENTIALS,
                ResponseAction.RESET_PASSWORD,
                ResponseAction.ENABLE_MFA,
                ResponseAction.NOTIFY_TEAM
            ],
            automation_mode=AutomationMode.SEMI_AUTOMATED
        ))

        # Network threat policy
        self.add_policy(ContainmentPolicy(
            policy_id="policy-network-threat",
            name="Network Threat Response",
            description="Response for network-based threats",
            threat_types=["c2_communication", "data_exfiltration", "lateral_movement"],
            min_severity=ThreatSeverity.HIGH,
            min_confidence=0.85,
            actions=[
                ResponseAction.BLOCK_IP,
                ResponseAction.BLOCK_DOMAIN,
                ResponseAction.BLOCK_PORT,
                ResponseAction.ISOLATE_HOST,
                ResponseAction.COLLECT_EVIDENCE
            ],
            automation_mode=AutomationMode.SEMI_AUTOMATED
        ))

    def add_policy(self, policy: ContainmentPolicy) -> None:
        """Add a containment policy."""
        self.policies[policy.policy_id] = policy

    async def analyze_threat(self, threat: ThreatContext) -> Optional[ResponsePlan]:
        """Analyze threat and generate response plan."""
        # Find matching policies
        matching_policies = self._find_matching_policies(threat)

        if not matching_policies:
            return None

        # Use the most specific policy
        policy = matching_policies[0]

        # Generate response plan
        plan = ResponsePlan(
            plan_id=f"plan-{uuid.uuid4()}",
            threat_id=threat.threat_id,
            actions=policy.actions,
            automation_mode=policy.automation_mode,
            estimated_impact=self._estimate_impact(policy.actions, threat),
            rollback_plan=self._generate_rollback_plan(policy.actions),
            requires_approval=(policy.automation_mode == AutomationMode.SEMI_AUTOMATED)
        )

        self.response_plans[plan.plan_id] = plan

        if plan.requires_approval:
            self.pending_approvals.add(plan.plan_id)

        return plan

    def _find_matching_policies(self, threat: ThreatContext) -> List[ContainmentPolicy]:
        """Find policies matching the threat."""
        matching = []

        for policy in self.policies.values():
            if not policy.enabled:
                continue

            # Check threat type
            if threat.threat_type not in policy.threat_types:
                continue

            # Check severity
            severity_order = [ThreatSeverity.INFO, ThreatSeverity.LOW,
                            ThreatSeverity.MEDIUM, ThreatSeverity.HIGH,
                            ThreatSeverity.CRITICAL]
            if severity_order.index(threat.severity) < severity_order.index(policy.min_severity):
                continue

            # Check confidence
            if threat.confidence < policy.min_confidence:
                continue

            matching.append(policy)

        return matching

    def _estimate_impact(self, actions: List[ResponseAction], threat: ThreatContext) -> str:
        """Estimate impact of response actions."""
        high_impact_actions = {
            ResponseAction.ISOLATE_HOST,
            ResponseAction.DISABLE_USER,
            ResponseAction.BLOCK_IP
        }

        high_impact_count = sum(1 for action in actions if action in high_impact_actions)

        if high_impact_count >= 2:
            return "High - May disrupt business operations"
        elif high_impact_count == 1:
            return "Medium - Limited business impact"
        else:
            return "Low - Minimal business impact"

    def _generate_rollback_plan(self, actions: List[ResponseAction]) -> List[Dict[str, Any]]:
        """Generate rollback plan for actions."""
        rollback_steps = []

        rollback_map = {
            ResponseAction.ISOLATE_HOST: "restore_network_access",
            ResponseAction.BLOCK_IP: "unblock_ip",
            ResponseAction.BLOCK_DOMAIN: "unblock_domain",
            ResponseAction.DISABLE_USER: "enable_user",
            ResponseAction.QUARANTINE_FILE: "restore_file",
            ResponseAction.KILL_PROCESS: "restart_process",
            ResponseAction.REVOKE_CREDENTIALS: "restore_credentials",
            ResponseAction.BLOCK_PORT: "unblock_port"
        }

        for action in actions:
            if action in rollback_map:
                rollback_steps.append({
                    "action": rollback_map[action],
                    "original_action": action.value
                })

        return rollback_steps

    async def execute_response(self, plan_id: str, approved: bool = False) -> List[ResponseExecution]:
        """Execute response plan."""
        plan = self.response_plans.get(plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")

        # Check approval requirement
        if plan.requires_approval and not approved:
            raise ValueError(f"Plan {plan_id} requires approval")

        if plan_id in self.pending_approvals:
            self.pending_approvals.remove(plan_id)

        # Execute actions
        executions = []
        for action in plan.actions:
            execution = await self._execute_action(plan, action)
            executions.append(execution)
            self.executions[execution.execution_id] = execution

        return executions

    async def _execute_action(self, plan: ResponsePlan, action: ResponseAction) -> ResponseExecution:
        """Execute a single response action."""
        execution = ResponseExecution(
            execution_id=f"exec-{uuid.uuid4()}",
            plan_id=plan.plan_id,
            action=action,
            status=ResponseStatus.IN_PROGRESS,
            target="",  # Would be populated with actual target
            started_at=datetime.utcnow()
        )

        try:
            # Simulate action execution
            await asyncio.sleep(0.1)

            execution.status = ResponseStatus.SUCCESS
            execution.result = {
                "action": action.value,
                "success": True,
                "message": f"Successfully executed {action.value}"
            }

        except Exception as e:
            execution.status = ResponseStatus.FAILED
            execution.error = str(e)

        execution.completed_at = datetime.utcnow()
        return execution


# Global instance
_threat_response_system = None


def get_threat_response_system() -> AutomatedThreatResponseSystem:
    """Get global threat response system instance."""
    global _threat_response_system
    if _threat_response_system is None:
        _threat_response_system = AutomatedThreatResponseSystem()
    return _threat_response_system
