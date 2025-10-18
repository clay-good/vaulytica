import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Callable, Tuple
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict
import json

from vaulytica.models import SecurityEvent, Severity
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class WorkflowStatus(str, Enum):
    """Workflow execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ActionType(str, Enum):
    """Types of workflow actions."""
    ENRICHMENT = "ENRICHMENT"  # Enrich with threat intel
    CONTAINMENT = "CONTAINMENT"  # Isolate/block/quarantine
    INVESTIGATION = "INVESTIGATION"  # Gather evidence
    NOTIFICATION = "NOTIFICATION"  # Send alerts
    REMEDIATION = "REMEDIATION"  # Fix/patch/restore
    ANALYSIS = "ANALYSIS"  # Analyze with AI/ML
    DECISION = "DECISION"  # Conditional branching
    INTEGRATION = "INTEGRATION"  # Call external API
    WAIT = "WAIT"  # Wait for condition or timeout


class ActionStatus(str, Enum):
    """Action execution status."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class CasePriority(str, Enum):
    """Case priority levels."""
    P1_CRITICAL = "P1_CRITICAL"  # 15 min SLA
    P2_HIGH = "P2_HIGH"  # 1 hour SLA
    P3_MEDIUM = "P3_MEDIUM"  # 4 hours SLA
    P4_LOW = "P4_LOW"  # 24 hours SLA
    P5_INFO = "P5_INFO"  # 7 days SLA


class CaseStatus(str, Enum):
    """Case status."""
    NEW = "NEW"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    WAITING = "WAITING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


@dataclass
class WorkflowAction:
    """Represents a single action in a workflow."""
    action_id: str
    action_type: ActionType
    name: str
    description: str
    parameters: Dict[str, Any]
    timeout: int = 300  # seconds
    retry_count: int = 3
    retry_delay: int = 5  # seconds
    on_success: Optional[str] = None  # Next action ID
    on_failure: Optional[str] = None  # Next action ID on failure
    condition: Optional[str] = None  # Conditional execution
    status: ActionStatus = ActionStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }


@dataclass
class Workflow:
    """Represents an automated workflow."""
    workflow_id: str
    name: str
    description: str
    trigger_type: str  # event, schedule, manual
    actions: List[WorkflowAction]
    status: WorkflowStatus = WorkflowStatus.PENDING
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "trigger_type": self.trigger_type,
            "status": self.status.value,
            "actions_count": len(self.actions),
            "actions_completed": sum(1 for a in self.actions if a.status == ActionStatus.COMPLETED),
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }


@dataclass
class Case:
    """Represents a security case."""
    case_id: str
    title: str
    description: str
    priority: CasePriority
    status: CaseStatus
    assigned_to: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    related_events: List[str] = field(default_factory=list)
    related_incidents: List[str] = field(default_factory=list)
    workflows: List[str] = field(default_factory=list)
    sla_deadline: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value,
            "status": self.status.value,
            "assigned_to": self.assigned_to,
            "tags": self.tags,
            "related_events": self.related_events,
            "related_incidents": self.related_incidents,
            "workflows": self.workflows,
            "sla_deadline": self.sla_deadline.isoformat() if self.sla_deadline else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None
        }


class SOARPlatform:
    """
    Security Orchestration, Automation and Response Platform.
    
    Provides advanced workflow automation, case management, and
    integration orchestration for security operations.
    """
    
    def __init__(self):
        self.workflows: Dict[str, Workflow] = {}
        self.cases: Dict[str, Case] = {}
        self.workflow_templates: Dict[str, List[WorkflowAction]] = self._initialize_templates()
        self.action_handlers: Dict[ActionType, Callable] = self._register_handlers()
        self.statistics = {
            "total_workflows": 0,
            "workflows_completed": 0,
            "workflows_failed": 0,
            "total_cases": 0,
            "cases_resolved": 0,
            "avg_workflow_time": 0.0,
            "avg_case_resolution_time": 0.0
        }
        logger.info("SOAR Platform initialized")
    
    def _initialize_templates(self) -> Dict[str, List[WorkflowAction]]:
        """Initialize workflow templates."""
        templates = {
            "phishing_response": [
                WorkflowAction(
                    action_id="phish_001",
                    action_type=ActionType.ENRICHMENT,
                    name="Enrich Email IOCs",
                    description="Extract and enrich email indicators",
                    parameters={"extract": ["sender", "urls", "attachments"]},
                    on_success="phish_002"
                ),
                WorkflowAction(
                    action_id="phish_002",
                    action_type=ActionType.ANALYSIS,
                    name="Analyze with AI",
                    description="AI-powered phishing analysis",
                    parameters={"model": "claude", "analysis_type": "phishing"},
                    on_success="phish_003"
                ),
                WorkflowAction(
                    action_id="phish_003",
                    action_type=ActionType.DECISION,
                    name="Determine Severity",
                    description="Decide on response based on severity",
                    parameters={"threshold": "high"},
                    condition="severity >= HIGH",
                    on_success="phish_004",
                    on_failure="phish_006"
                ),
                WorkflowAction(
                    action_id="phish_004",
                    action_type=ActionType.CONTAINMENT,
                    name="Block Sender",
                    description="Block malicious sender",
                    parameters={"action": "block_sender"},
                    on_success="phish_005"
                ),
                WorkflowAction(
                    action_id="phish_005",
                    action_type=ActionType.REMEDIATION,
                    name="Quarantine Emails",
                    description="Quarantine similar emails",
                    parameters={"action": "quarantine", "scope": "organization"},
                    on_success="phish_006"
                ),
                WorkflowAction(
                    action_id="phish_006",
                    action_type=ActionType.NOTIFICATION,
                    name="Notify Security Team",
                    description="Send notification to SOC",
                    parameters={"channels": ["slack", "email"], "priority": "high"}
                )
            ],
            "malware_containment": [
                WorkflowAction(
                    action_id="mal_001",
                    action_type=ActionType.CONTAINMENT,
                    name="Isolate Endpoint",
                    description="Network isolate infected endpoint",
                    parameters={"action": "network_isolate"},
                    on_success="mal_002"
                ),
                WorkflowAction(
                    action_id="mal_002",
                    action_type=ActionType.INVESTIGATION,
                    name="Collect Forensics",
                    description="Gather forensic evidence",
                    parameters={"evidence_types": ["memory", "disk", "network"]},
                    on_success="mal_003"
                ),
                WorkflowAction(
                    action_id="mal_003",
                    action_type=ActionType.ANALYSIS,
                    name="Malware Analysis",
                    description="Analyze malware sample",
                    parameters={"sandbox": True, "deep_analysis": True},
                    on_success="mal_004"
                ),
                WorkflowAction(
                    action_id="mal_004",
                    action_type=ActionType.REMEDIATION,
                    name="Clean Endpoint",
                    description="Remove malware and restore",
                    parameters={"action": "clean_and_restore"}
                )
            ],
            "data_breach_response": [
                WorkflowAction(
                    action_id="breach_001",
                    action_type=ActionType.CONTAINMENT,
                    name="Revoke Access",
                    description="Revoke compromised credentials",
                    parameters={"scope": "affected_accounts"},
                    on_success="breach_002"
                ),
                WorkflowAction(
                    action_id="breach_002",
                    action_type=ActionType.INVESTIGATION,
                    name="Assess Impact",
                    description="Determine data exposure scope",
                    parameters={"check": ["data_accessed", "data_exfiltrated"]},
                    on_success="breach_003"
                ),
                WorkflowAction(
                    action_id="breach_003",
                    action_type=ActionType.NOTIFICATION,
                    name="Notify Stakeholders",
                    description="Notify legal, compliance, executives",
                    parameters={"recipients": ["legal", "compliance", "ciso"]},
                    on_success="breach_004"
                ),
                WorkflowAction(
                    action_id="breach_004",
                    action_type=ActionType.REMEDIATION,
                    name="Implement Controls",
                    description="Deploy additional security controls",
                    parameters={"controls": ["mfa", "monitoring", "dlp"]}
                )
            ]
        }
        return templates

    def _register_handlers(self) -> Dict[ActionType, Callable]:
        """Register action handlers."""
        return {
            ActionType.ENRICHMENT: self._handle_enrichment,
            ActionType.CONTAINMENT: self._handle_containment,
            ActionType.INVESTIGATION: self._handle_investigation,
            ActionType.NOTIFICATION: self._handle_notification,
            ActionType.REMEDIATION: self._handle_remediation,
            ActionType.ANALYSIS: self._handle_analysis,
            ActionType.DECISION: self._handle_decision,
            ActionType.INTEGRATION: self._handle_integration,
            ActionType.WAIT: self._handle_wait
        }

    async def create_workflow(
        self,
        name: str,
        description: str,
        trigger_type: str,
        actions: List[WorkflowAction],
        created_by: Optional[str] = None
    ) -> Workflow:
        """Create a new workflow."""
        workflow_id = f"WF-{datetime.utcnow().strftime('%Y%m%d')}-{len(self.workflows) + 1:04d}"

        workflow = Workflow(
            workflow_id=workflow_id,
            name=name,
            description=description,
            trigger_type=trigger_type,
            actions=actions,
            created_by=created_by
        )

        self.workflows[workflow_id] = workflow
        self.statistics["total_workflows"] += 1

        logger.info(f"Created workflow: {workflow_id} - {name}")
        return workflow

    async def execute_workflow(
        self,
        workflow_id: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute a workflow."""
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow {workflow_id} not found")

        workflow = self.workflows[workflow_id]
        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = datetime.utcnow()
        workflow.context = context or {}

        logger.info(f"Executing workflow: {workflow_id}")

        try:
            # Execute actions in sequence
            current_action_id = workflow.actions[0].action_id if workflow.actions else None

            while current_action_id:
                action = next((a for a in workflow.actions if a.action_id == current_action_id), None)
                if not action:
                    break

                # Execute action
                success = await self._execute_action(action, workflow.context)

                # Determine next action
                if success and action.on_success:
                    current_action_id = action.on_success
                elif not success and action.on_failure:
                    current_action_id = action.on_failure
                else:
                    current_action_id = None

            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = datetime.utcnow()
            self.statistics["workflows_completed"] += 1

            execution_time = (workflow.completed_at - workflow.started_at).total_seconds()

            result = {
                "workflow_id": workflow_id,
                "status": "completed",
                "execution_time": execution_time,
                "actions_executed": sum(1 for a in workflow.actions if a.status == ActionStatus.COMPLETED),
                "actions_failed": sum(1 for a in workflow.actions if a.status == ActionStatus.FAILED)
            }

            logger.info(f"Workflow {workflow_id} completed in {execution_time:.2f}s")
            return result

        except Exception as e:
            workflow.status = WorkflowStatus.FAILED
            workflow.completed_at = datetime.utcnow()
            self.statistics["workflows_failed"] += 1

            logger.error(f"Workflow {workflow_id} failed: {e}")
            return {
                "workflow_id": workflow_id,
                "status": "failed",
                "error": str(e)
            }

    async def _execute_action(self, action: WorkflowAction, context: Dict[str, Any]) -> bool:
        """Execute a single workflow action."""
        action.status = ActionStatus.RUNNING
        action.started_at = datetime.utcnow()

        try:
            # Get handler for action type
            handler = self.action_handlers.get(action.action_type)
            if not handler:
                raise ValueError(f"No handler for action type: {action.action_type}")

            # Execute with retry logic
            for attempt in range(action.retry_count):
                try:
                    result = await handler(action, context)
                    action.result = result
                    action.status = ActionStatus.COMPLETED
                    action.completed_at = datetime.utcnow()
                    return True
                except Exception as e:
                    if attempt < action.retry_count - 1:
                        await asyncio.sleep(action.retry_delay)
                        continue
                    raise e

        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error = str(e)
            action.completed_at = datetime.utcnow()
            logger.error(f"Action {action.action_id} failed: {e}")
            return False

    # Action handlers (simulated for now)
    async def _handle_enrichment(self, action: WorkflowAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle enrichment action."""
        await asyncio.sleep(0.1)  # Simulate API call
        return {
            "enriched": True,
            "iocs_found": 3,
            "threat_score": 0.85
        }

    async def _handle_containment(self, action: WorkflowAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle containment action."""
        await asyncio.sleep(0.2)  # Simulate containment action
        return {
            "contained": True,
            "action": action.parameters.get("action"),
            "affected_assets": 1
        }

    async def _handle_investigation(self, action: WorkflowAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle investigation action."""
        await asyncio.sleep(0.15)  # Simulate evidence collection
        return {
            "evidence_collected": True,
            "evidence_count": 5,
            "evidence_types": action.parameters.get("evidence_types", [])
        }

    async def _handle_notification(self, action: WorkflowAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle notification action."""
        await asyncio.sleep(0.05)  # Simulate notification
        return {
            "notified": True,
            "channels": action.parameters.get("channels", []),
            "recipients": 3
        }

    async def _handle_remediation(self, action: WorkflowAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle remediation action."""
        await asyncio.sleep(0.25)  # Simulate remediation
        return {
            "remediated": True,
            "action": action.parameters.get("action"),
            "success": True
        }

    async def _handle_analysis(self, action: WorkflowAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle analysis action."""
        await asyncio.sleep(0.3)  # Simulate AI analysis
        return {
            "analyzed": True,
            "confidence": 0.92,
            "verdict": "malicious"
        }

    async def _handle_decision(self, action: WorkflowAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle decision action."""
        # Evaluate condition (simplified)
        condition = action.condition or "true"
        result = True  # Simplified - would evaluate actual condition
        return {
            "decision": result,
            "condition": condition
        }

    async def _handle_integration(self, action: WorkflowAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle integration action."""
        await asyncio.sleep(0.1)  # Simulate API call
        return {
            "integration_success": True,
            "response_code": 200
        }

    async def _handle_wait(self, action: WorkflowAction, context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle wait action."""
        wait_time = action.parameters.get("wait_time", 5)
        await asyncio.sleep(min(wait_time, 1))  # Cap at 1s for simulation
        return {
            "waited": True,
            "wait_time": wait_time
        }

    async def create_case(
        self,
        title: str,
        description: str,
        priority: CasePriority,
        assigned_to: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> Case:
        """Create a new security case."""
        case_id = f"CASE-{datetime.utcnow().strftime('%Y%m%d')}-{len(self.cases) + 1:04d}"

        # Calculate SLA deadline based on priority
        sla_hours = {
            CasePriority.P1_CRITICAL: 0.25,  # 15 minutes
            CasePriority.P2_HIGH: 1,
            CasePriority.P3_MEDIUM: 4,
            CasePriority.P4_LOW: 24,
            CasePriority.P5_INFO: 168  # 7 days
        }

        sla_deadline = datetime.utcnow() + timedelta(hours=sla_hours[priority])

        case = Case(
            case_id=case_id,
            title=title,
            description=description,
            priority=priority,
            status=CaseStatus.NEW,
            assigned_to=assigned_to,
            tags=tags or [],
            sla_deadline=sla_deadline
        )

        self.cases[case_id] = case
        self.statistics["total_cases"] += 1

        logger.info(f"Created case: {case_id} - {title}")
        return case

    async def assign_case(self, case_id: str, assigned_to: str) -> Case:
        """Assign a case to an analyst."""
        if case_id not in self.cases:
            raise ValueError(f"Case {case_id} not found")

        case = self.cases[case_id]
        case.assigned_to = assigned_to
        case.status = CaseStatus.ASSIGNED
        case.updated_at = datetime.utcnow()

        logger.info(f"Assigned case {case_id} to {assigned_to}")
        return case

    async def resolve_case(self, case_id: str, resolution: str) -> Case:
        """Resolve a case."""
        if case_id not in self.cases:
            raise ValueError(f"Case {case_id} not found")

        case = self.cases[case_id]
        case.status = CaseStatus.RESOLVED
        case.resolved_at = datetime.utcnow()
        case.updated_at = datetime.utcnow()
        self.statistics["cases_resolved"] += 1

        logger.info(f"Resolved case {case_id}")
        return case

    def get_workflow(self, workflow_id: str) -> Optional[Workflow]:
        """Get a workflow by ID."""
        return self.workflows.get(workflow_id)

    def get_case(self, case_id: str) -> Optional[Case]:
        """Get a case by ID."""
        return self.cases.get(case_id)

    def list_workflows(self, status: Optional[WorkflowStatus] = None, limit: int = 100) -> List[Workflow]:
        """List workflows with optional filtering."""
        workflows = list(self.workflows.values())
        if status:
            workflows = [w for w in workflows if w.status == status]
        workflows.sort(key=lambda w: w.created_at, reverse=True)
        return workflows[:limit]

    def list_cases(self, status: Optional[CaseStatus] = None, limit: int = 100) -> List[Case]:
        """List cases with optional filtering."""
        cases = list(self.cases.values())
        if status:
            cases = [c for c in cases if c.status == status]
        cases.sort(key=lambda c: (c.priority.value, c.created_at))
        return cases[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get SOAR platform statistics."""
        return {
            **self.statistics,
            "workflows_by_status": self._count_workflows_by_status(),
            "cases_by_status": self._count_cases_by_status(),
            "cases_by_priority": self._count_cases_by_priority()
        }

    def _count_workflows_by_status(self) -> Dict[str, int]:
        """Count workflows by status."""
        counts = defaultdict(int)
        for workflow in self.workflows.values():
            counts[workflow.status.value] += 1
        return dict(counts)

    def _count_cases_by_status(self) -> Dict[str, int]:
        """Count cases by status."""
        counts = defaultdict(int)
        for case in self.cases.values():
            counts[case.status.value] += 1
        return dict(counts)

    def _count_cases_by_priority(self) -> Dict[str, int]:
        """Count cases by priority."""
        counts = defaultdict(int)
        for case in self.cases.values():
            counts[case.priority.value] += 1
        return dict(counts)


# Global instance
_soar_platform: Optional[SOARPlatform] = None


def get_soar_platform() -> SOARPlatform:
    """Get the global SOAR platform instance."""
    global _soar_platform
    if _soar_platform is None:
        _soar_platform = SOARPlatform()
    return _soar_platform
