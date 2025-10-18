import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from collections import defaultdict, deque
import random


class AutomationTrigger(str, Enum):
    """Automation trigger types."""
    EVENT_PATTERN = "EVENT_PATTERN"
    THREAT_LEVEL = "THREAT_LEVEL"
    ANOMALY_SCORE = "ANOMALY_SCORE"
    IOC_MATCH = "IOC_MATCH"
    BEHAVIORAL_ANOMALY = "BEHAVIORAL_ANOMALY"
    TIME_BASED = "TIME_BASED"
    MANUAL = "MANUAL"


class AutomationAction(str, Enum):
    """Automation action types."""
    GENERATE_HYPOTHESIS = "GENERATE_HYPOTHESIS"
    START_HUNT = "START_HUNT"
    EXECUTE_PLAYBOOK = "EXECUTE_PLAYBOOK"
    ISOLATE_ASSET = "ISOLATE_ASSET"
    BLOCK_IOC = "BLOCK_IOC"
    CREATE_INCIDENT = "CREATE_INCIDENT"
    ESCALATE = "ESCALATE"
    COLLECT_EVIDENCE = "COLLECT_EVIDENCE"
    NOTIFY = "NOTIFY"
    CUSTOM = "CUSTOM"


class RiskLevel(str, Enum):
    """Risk level for automation actions."""
    SAFE = "SAFE"  # No risk, can auto-execute
    LOW = "LOW"  # Low risk, auto-execute with logging
    MEDIUM = "MEDIUM"  # Medium risk, require approval
    HIGH = "HIGH"  # High risk, require senior approval
    CRITICAL = "CRITICAL"  # Critical risk, require CISO approval


@dataclass
class AutomationRule:
    """Automation rule definition."""
    rule_id: str = field(default_factory=lambda: f"RULE-{uuid.uuid4().hex[:8]}")
    name: str = ""
    description: str = ""
    enabled: bool = True
    
    # Trigger conditions
    trigger_type: AutomationTrigger = AutomationTrigger.EVENT_PATTERN
    trigger_conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Actions
    actions: List[AutomationAction] = field(default_factory=list)
    action_parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Risk assessment
    risk_level: RiskLevel = RiskLevel.MEDIUM
    require_approval: bool = False
    approval_timeout: int = 300  # seconds
    
    # Learning
    success_count: int = 0
    failure_count: int = 0
    false_positive_count: int = 0
    confidence_score: float = 0.5  # 0.0-1.0
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "trigger_type": self.trigger_type.value,
            "trigger_conditions": self.trigger_conditions,
            "actions": [a.value for a in self.actions],
            "action_parameters": self.action_parameters,
            "risk_level": self.risk_level.value,
            "require_approval": self.require_approval,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "false_positive_count": self.false_positive_count,
            "confidence_score": self.confidence_score,
            "created_at": self.created_at.isoformat(),
            "last_triggered": self.last_triggered.isoformat() if self.last_triggered else None,
            "trigger_count": self.trigger_count
        }


@dataclass
class HypothesisGeneration:
    """Generated threat hunting hypothesis."""
    hypothesis_id: str = field(default_factory=lambda: f"HYP-{uuid.uuid4().hex[:8]}")
    hypothesis: str = ""
    confidence: float = 0.0  # 0.0-1.0
    
    # Context
    based_on: List[str] = field(default_factory=list)  # What triggered this hypothesis
    threat_actors: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    
    # Hunt queries
    suggested_queries: List[Dict[str, Any]] = field(default_factory=list)
    
    # Validation
    validated: bool = False
    validation_result: Optional[str] = None
    findings_count: int = 0
    
    # Metadata
    generated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "hypothesis": self.hypothesis,
            "confidence": self.confidence,
            "based_on": self.based_on,
            "threat_actors": self.threat_actors,
            "attack_techniques": self.attack_techniques,
            "iocs": self.iocs,
            "suggested_queries": self.suggested_queries,
            "validated": self.validated,
            "validation_result": self.validation_result,
            "findings_count": self.findings_count,
            "generated_at": self.generated_at.isoformat()
        }


@dataclass
class AutoRemediationPlan:
    """Automated remediation plan."""
    plan_id: str = field(default_factory=lambda: f"PLAN-{uuid.uuid4().hex[:8]}")
    name: str = ""
    description: str = ""
    
    # Risk assessment
    risk_level: RiskLevel = RiskLevel.MEDIUM
    impact_score: float = 0.5  # 0.0-1.0
    confidence: float = 0.5  # 0.0-1.0
    
    # Actions
    steps: List[Dict[str, Any]] = field(default_factory=list)
    estimated_duration: int = 0  # seconds
    
    # Approval
    requires_approval: bool = False
    approved: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    
    # Execution
    status: str = "pending"  # pending, approved, executing, completed, failed, cancelled
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Results
    success: bool = False
    error_message: Optional[str] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "plan_id": self.plan_id,
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "impact_score": self.impact_score,
            "confidence": self.confidence,
            "steps": self.steps,
            "estimated_duration": self.estimated_duration,
            "requires_approval": self.requires_approval,
            "approved": self.approved,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "status": self.status,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "success": self.success,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat()
        }


class AdvancedAutomationEngine:
    """
    Advanced automation engine with ML-powered decision making.
    
    Features:
    - Automated hypothesis generation
    - Intelligent auto-remediation
    - Adaptive playbook selection
    - Self-learning automation rules
    """
    
    def __init__(self):
        """Initialize automation engine."""
        self.rules: Dict[str, AutomationRule] = {}
        self.hypotheses: Dict[str, HypothesisGeneration] = {}
        self.remediation_plans: Dict[str, AutoRemediationPlan] = {}
        
        # Event history for pattern learning
        self.event_history: deque = deque(maxlen=10000)
        
        # Statistics
        self.stats = {
            "total_rules": 0,
            "active_rules": 0,
            "total_triggers": 0,
            "successful_automations": 0,
            "failed_automations": 0,
            "hypotheses_generated": 0,
            "hypotheses_validated": 0,
            "remediation_plans_created": 0,
            "remediation_plans_executed": 0
        }
        
        # Initialize default rules
        self._initialize_default_rules()
    
    def _initialize_default_rules(self):
        """Initialize default automation rules."""
        # Rule 1: Auto-hunt on critical IOC match
        rule1 = AutomationRule(
            name="Auto-Hunt on Critical IOC",
            description="Automatically start threat hunt when critical IOC is detected",
            trigger_type=AutomationTrigger.IOC_MATCH,
            trigger_conditions={"threat_level": "CRITICAL", "confidence": 0.8},
            actions=[AutomationAction.GENERATE_HYPOTHESIS, AutomationAction.START_HUNT],
            risk_level=RiskLevel.LOW,
            require_approval=False
        )
        self.rules[rule1.rule_id] = rule1
        
        # Rule 2: Auto-isolate on ransomware detection
        rule2 = AutomationRule(
            name="Auto-Isolate Ransomware",
            description="Automatically isolate host when ransomware is detected",
            trigger_type=AutomationTrigger.EVENT_PATTERN,
            trigger_conditions={"attack_type": "ransomware", "confidence": 0.9},
            actions=[AutomationAction.ISOLATE_ASSET, AutomationAction.COLLECT_EVIDENCE, AutomationAction.CREATE_INCIDENT],
            risk_level=RiskLevel.MEDIUM,
            require_approval=True
        )
        self.rules[rule2.rule_id] = rule2
        
        # Rule 3: Auto-block malicious IPs
        rule3 = AutomationRule(
            name="Auto-Block Malicious IPs",
            description="Automatically block IPs with high malicious score",
            trigger_type=AutomationTrigger.THREAT_LEVEL,
            trigger_conditions={"threat_level": "HIGH", "ioc_type": "IP"},
            actions=[AutomationAction.BLOCK_IOC, AutomationAction.NOTIFY],
            risk_level=RiskLevel.LOW,
            require_approval=False
        )
        self.rules[rule3.rule_id] = rule3
        
        self.stats["total_rules"] = len(self.rules)
        self.stats["active_rules"] = sum(1 for r in self.rules.values() if r.enabled)

    async def generate_hypothesis(
        self,
        context: Dict[str, Any]
    ) -> HypothesisGeneration:
        """
        Generate threat hunting hypothesis based on context.

        Uses ML and threat intelligence to generate actionable hypotheses.

        Args:
            context: Context data (events, IOCs, threat intel, etc.)

        Returns:
            Generated hypothesis
        """
        self.stats["hypotheses_generated"] += 1

        # Extract context
        events = context.get("events", [])
        iocs = context.get("iocs", [])
        threat_actors = context.get("threat_actors", [])
        attack_techniques = context.get("attack_techniques", [])

        # Generate hypothesis based on patterns
        hypothesis_text = self._generate_hypothesis_text(
            events, iocs, threat_actors, attack_techniques
        )

        # Calculate confidence based on evidence strength
        confidence = self._calculate_hypothesis_confidence(context)

        # Generate suggested queries
        queries = self._generate_hunt_queries(hypothesis_text, iocs, attack_techniques)

        hypothesis = HypothesisGeneration(
            hypothesis=hypothesis_text,
            confidence=confidence,
            based_on=[f"Event pattern analysis", f"{len(iocs)} IOCs", f"{len(threat_actors)} threat actors"],
            threat_actors=threat_actors,
            attack_techniques=attack_techniques,
            iocs=iocs,
            suggested_queries=queries
        )

        self.hypotheses[hypothesis.hypothesis_id] = hypothesis
        return hypothesis

    def _generate_hypothesis_text(
        self,
        events: List[Any],
        iocs: List[str],
        threat_actors: List[str],
        attack_techniques: List[str]
    ) -> str:
        """Generate hypothesis text."""
        if threat_actors:
            actor = threat_actors[0]
            return f"Potential {actor} activity detected. Adversary may be conducting reconnaissance and initial access attempts using known TTPs."
        elif attack_techniques:
            technique = attack_techniques[0]
            return f"Suspicious activity matching {technique}. Adversary may be attempting to establish persistence or escalate privileges."
        elif iocs:
            return f"Multiple IOCs detected in network traffic. Adversary may be communicating with command and control infrastructure."
        else:
            return "Anomalous behavior detected. Potential insider threat or compromised account activity."

    def _calculate_hypothesis_confidence(self, context: Dict[str, Any]) -> float:
        """Calculate hypothesis confidence score."""
        confidence = 0.5

        # Increase confidence based on evidence
        if context.get("threat_actors"):
            confidence += 0.2
        if context.get("attack_techniques"):
            confidence += 0.15
        if len(context.get("iocs", [])) > 3:
            confidence += 0.15

        return min(confidence, 1.0)

    def _generate_hunt_queries(
        self,
        hypothesis: str,
        iocs: List[str],
        techniques: List[str]
    ) -> List[Dict[str, Any]]:
        """Generate hunt queries for hypothesis."""
        queries = []

        # Query for IOCs
        if iocs:
            queries.append({
                "query_type": "SIEM",
                "query": f"Search for IOCs: {', '.join(iocs[:3])}",
                "data_sources": ["network_logs", "firewall_logs"]
            })

        # Query for techniques
        if techniques:
            queries.append({
                "query_type": "EDR",
                "query": f"Search for MITRE technique: {techniques[0]}",
                "data_sources": ["endpoint_logs", "process_logs"]
            })

        # Behavioral query
        queries.append({
            "query_type": "BEHAVIORAL",
            "query": "Search for anomalous user behavior and privilege escalation attempts",
            "data_sources": ["authentication_logs", "audit_logs"]
        })

        return queries

    async def create_remediation_plan(
        self,
        incident_data: Dict[str, Any]
    ) -> AutoRemediationPlan:
        """
        Create automated remediation plan.

        Analyzes incident and generates appropriate remediation steps
        with risk assessment.

        Args:
            incident_data: Incident information

        Returns:
            Remediation plan
        """
        self.stats["remediation_plans_created"] += 1

        # Assess risk
        risk_level = self._assess_remediation_risk(incident_data)
        impact_score = self._calculate_impact_score(incident_data)
        confidence = incident_data.get("confidence", 0.7)

        # Generate remediation steps
        steps = self._generate_remediation_steps(incident_data, risk_level)

        # Estimate duration
        estimated_duration = sum(step.get("duration", 60) for step in steps)

        # Determine if approval required
        requires_approval = risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]

        plan = AutoRemediationPlan(
            name=f"Remediation for {incident_data.get('incident_type', 'Unknown')}",
            description=f"Automated remediation plan for incident {incident_data.get('incident_id', 'N/A')}",
            risk_level=risk_level,
            impact_score=impact_score,
            confidence=confidence,
            steps=steps,
            estimated_duration=estimated_duration,
            requires_approval=requires_approval
        )

        self.remediation_plans[plan.plan_id] = plan
        return plan

    def _assess_remediation_risk(self, incident_data: Dict[str, Any]) -> RiskLevel:
        """Assess risk level of remediation actions."""
        incident_type = incident_data.get("incident_type", "").lower()
        severity = incident_data.get("severity", "MEDIUM").upper()

        # High-risk incidents
        if incident_type in ["ransomware", "data_breach", "insider_threat"]:
            return RiskLevel.HIGH

        # Critical severity
        if severity == "CRITICAL":
            return RiskLevel.HIGH

        # Medium risk by default
        if severity in ["HIGH", "MEDIUM"]:
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _calculate_impact_score(self, incident_data: Dict[str, Any]) -> float:
        """Calculate impact score of remediation."""
        score = 0.5

        # Increase based on affected assets
        affected_assets = incident_data.get("affected_assets", [])
        if len(affected_assets) > 10:
            score += 0.2
        elif len(affected_assets) > 5:
            score += 0.1

        # Increase based on severity
        severity = incident_data.get("severity", "MEDIUM").upper()
        if severity == "CRITICAL":
            score += 0.3
        elif severity == "HIGH":
            score += 0.2

        return min(score, 1.0)

    def _generate_remediation_steps(
        self,
        incident_data: Dict[str, Any],
        risk_level: RiskLevel
    ) -> List[Dict[str, Any]]:
        """Generate remediation steps."""
        steps = []
        incident_type = incident_data.get("incident_type", "").lower()

        # Common first step: Collect evidence
        steps.append({
            "step": 1,
            "action": "collect_evidence",
            "description": "Collect forensic evidence before remediation",
            "duration": 120,
            "risk": "SAFE"
        })

        # Type-specific steps
        if incident_type == "ransomware":
            steps.extend([
                {
                    "step": 2,
                    "action": "isolate_host",
                    "description": "Isolate infected host from network",
                    "duration": 30,
                    "risk": "MEDIUM"
                },
                {
                    "step": 3,
                    "action": "disable_user",
                    "description": "Disable compromised user accounts",
                    "duration": 60,
                    "risk": "MEDIUM"
                },
                {
                    "step": 4,
                    "action": "restore_backup",
                    "description": "Restore from clean backup",
                    "duration": 1800,
                    "risk": "LOW"
                }
            ])
        elif incident_type == "malware":
            steps.extend([
                {
                    "step": 2,
                    "action": "quarantine_file",
                    "description": "Quarantine malicious files",
                    "duration": 60,
                    "risk": "LOW"
                },
                {
                    "step": 3,
                    "action": "scan_system",
                    "description": "Full system antivirus scan",
                    "duration": 600,
                    "risk": "SAFE"
                }
            ])
        elif incident_type == "data_exfiltration":
            steps.extend([
                {
                    "step": 2,
                    "action": "block_ioc",
                    "description": "Block malicious IPs and domains",
                    "duration": 30,
                    "risk": "LOW"
                },
                {
                    "step": 3,
                    "action": "revoke_credentials",
                    "description": "Revoke compromised credentials",
                    "duration": 120,
                    "risk": "MEDIUM"
                },
                {
                    "step": 4,
                    "action": "enable_mfa",
                    "description": "Enable MFA for affected accounts",
                    "duration": 180,
                    "risk": "LOW"
                }
            ])
        else:
            # Generic remediation
            steps.append({
                "step": 2,
                "action": "investigate",
                "description": "Manual investigation required",
                "duration": 3600,
                "risk": "SAFE"
            })

        # Final step: Notify
        steps.append({
            "step": len(steps) + 1,
            "action": "notify",
            "description": "Notify security team of remediation completion",
            "duration": 30,
            "risk": "SAFE"
        })

        return steps

    async def execute_remediation_plan(
        self,
        plan_id: str,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Execute remediation plan.

        Args:
            plan_id: Plan ID
            dry_run: If True, simulate execution without making changes

        Returns:
            Execution results
        """
        plan = self.remediation_plans.get(plan_id)
        if not plan:
            return {"success": False, "error": "Plan not found"}

        # Check approval
        if plan.requires_approval and not plan.approved:
            return {"success": False, "error": "Plan requires approval"}

        # Update status
        plan.status = "executing"
        plan.started_at = datetime.utcnow()

        results = []
        success = True

        try:
            # Execute each step
            for step in plan.steps:
                step_result = await self._execute_remediation_step(step, dry_run)
                results.append(step_result)

                if not step_result.get("success"):
                    success = False
                    break

            plan.status = "completed" if success else "failed"
            plan.completed_at = datetime.utcnow()
            plan.success = success

            if success:
                self.stats["remediation_plans_executed"] += 1

            return {
                "success": success,
                "plan_id": plan_id,
                "steps_executed": len(results),
                "results": results,
                "dry_run": dry_run
            }

        except Exception as e:
            plan.status = "failed"
            plan.error_message = str(e)
            return {"success": False, "error": str(e)}

    async def _execute_remediation_step(
        self,
        step: Dict[str, Any],
        dry_run: bool
    ) -> Dict[str, Any]:
        """Execute single remediation step."""
        # Simulate execution
        await asyncio.sleep(0.1)

        if dry_run:
            return {
                "success": True,
                "step": step["step"],
                "action": step["action"],
                "message": f"[DRY RUN] Would execute: {step['description']}"
            }

        # In production, execute real actions here
        return {
            "success": True,
            "step": step["step"],
            "action": step["action"],
            "message": f"Executed: {step['description']}"
        }

    def approve_remediation_plan(
        self,
        plan_id: str,
        approved_by: str
    ) -> bool:
        """Approve remediation plan."""
        plan = self.remediation_plans.get(plan_id)
        if not plan:
            return False

        plan.approved = True
        plan.approved_by = approved_by
        plan.approved_at = datetime.utcnow()
        plan.status = "approved"

        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Get automation statistics."""
        return {
            **self.stats,
            "hypothesis_validation_rate": (
                self.stats["hypotheses_validated"] / self.stats["hypotheses_generated"]
                if self.stats["hypotheses_generated"] > 0 else 0.0
            ),
            "remediation_success_rate": (
                self.stats["remediation_plans_executed"] / self.stats["remediation_plans_created"]
                if self.stats["remediation_plans_created"] > 0 else 0.0
            )
        }


# Global instance
_advanced_automation: Optional[AdvancedAutomationEngine] = None


def get_advanced_automation() -> AdvancedAutomationEngine:
    """Get or create global advanced automation engine instance."""
    global _advanced_automation

    if _advanced_automation is None:
        _advanced_automation = AdvancedAutomationEngine()

    return _advanced_automation

