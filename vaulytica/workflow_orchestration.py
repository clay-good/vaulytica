"""
Security Workflow Orchestration System

Provides visual workflow builder, playbook designer, and workflow templates.
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional, Callable


class NodeType(str, Enum):
    """Workflow node types."""
    START = "start"
    END = "end"
    ACTION = "action"
    DECISION = "decision"
    PARALLEL = "parallel"
    LOOP = "loop"
    WAIT = "wait"
    APPROVAL = "approval"
    NOTIFICATION = "notification"
    INTEGRATION = "integration"
    SCRIPT = "script"


class WorkflowStatus(str, Enum):
    """Workflow execution status."""
    DRAFT = "draft"
    ACTIVE = "active"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class WorkflowNode:
    """Workflow node definition."""
    node_id: str
    node_type: NodeType
    name: str
    description: str
    config: Dict[str, Any]
    position: Dict[str, float]  # x, y coordinates for visual editor
    next_nodes: List[str] = field(default_factory=list)
    error_handler: Optional[str] = None


@dataclass
class WorkflowEdge:
    """Workflow edge (connection between nodes)."""
    edge_id: str
    source_node_id: str
    target_node_id: str
    condition: Optional[str] = None  # For decision nodes
    label: Optional[str] = None


@dataclass
class WorkflowDefinition:
    """Complete workflow definition."""
    workflow_id: str
    name: str
    description: str
    version: str
    nodes: Dict[str, WorkflowNode]
    edges: List[WorkflowEdge]
    variables: Dict[str, Any] = field(default_factory=dict)
    triggers: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class WorkflowExecution:
    """Workflow execution instance."""
    execution_id: str
    workflow_id: str
    status: WorkflowStatus
    current_node_id: Optional[str]
    variables: Dict[str, Any]
    execution_log: List[Dict[str, Any]] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


@dataclass
class WorkflowTemplate:
    """Pre-built workflow template."""
    template_id: str
    name: str
    description: str
    category: str
    use_case: str
    workflow_definition: WorkflowDefinition
    parameters: Dict[str, Any] = field(default_factory=dict)


class WorkflowOrchestrator:
    """Security workflow orchestration engine."""

    def __init__(self):
        self.workflows: Dict[str, WorkflowDefinition] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.templates: Dict[str, WorkflowTemplate] = {}
        self.node_handlers: Dict[NodeType, Callable] = {}

        # Initialize templates
        self._initialize_templates()

        # Register node handlers
        self._register_node_handlers()

    def _initialize_templates(self):
        """Initialize pre-built workflow templates."""
        # Phishing response template
        phishing_workflow = self._create_phishing_response_workflow()
        self.templates["phishing-response"] = WorkflowTemplate(
            template_id="phishing-response",
            name="Phishing Email Response",
            description="Automated workflow for responding to phishing emails",
            category="Email Security",
            use_case="Phishing Incident Response",
            workflow_definition=phishing_workflow
        )

        # Malware containment template
        malware_workflow = self._create_malware_containment_workflow()
        self.templates["malware-containment"] = WorkflowTemplate(
            template_id="malware-containment",
            name="Malware Containment",
            description="Automated malware detection and containment workflow",
            category="Endpoint Security",
            use_case="Malware Incident Response",
            workflow_definition=malware_workflow
        )

        # User onboarding template
        onboarding_workflow = self._create_user_onboarding_workflow()
        self.templates["user-onboarding"] = WorkflowTemplate(
            template_id="user-onboarding",
            name="Security User Onboarding",
            description="Security checks and setup for new user onboarding",
            category="Identity & Access",
            use_case="User Lifecycle Management",
            workflow_definition=onboarding_workflow
        )

    def _create_phishing_response_workflow(self) -> WorkflowDefinition:
        """Create phishing response workflow."""
        nodes = {
            "start": WorkflowNode(
                node_id="start",
                node_type=NodeType.START,
                name="Start",
                description="Workflow start",
                config={},
                position={"x": 100, "y": 100}
            ),
            "analyze_email": WorkflowNode(
                node_id="analyze_email",
                node_type=NodeType.ACTION,
                name="Analyze Email",
                description="Analyze email for phishing indicators",
                config={"action": "analyze_phishing_email"},
                position={"x": 100, "y": 200}
            ),
            "is_phishing": WorkflowNode(
                node_id="is_phishing",
                node_type=NodeType.DECISION,
                name="Is Phishing?",
                description="Check if email is phishing",
                config={"condition": "phishing_score > 0.8"},
                position={"x": 100, "y": 300}
            ),
            "quarantine_email": WorkflowNode(
                node_id="quarantine_email",
                node_type=NodeType.ACTION,
                name="Quarantine Email",
                description="Quarantine malicious email",
                config={"action": "quarantine_email"},
                position={"x": 50, "y": 400}
            ),
            "block_sender": WorkflowNode(
                node_id="block_sender",
                node_type=NodeType.ACTION,
                name="Block Sender",
                description="Block sender domain/IP",
                config={"action": "block_sender"},
                position={"x": 50, "y": 500}
            ),
            "notify_users": WorkflowNode(
                node_id="notify_users",
                node_type=NodeType.NOTIFICATION,
                name="Notify Users",
                description="Notify affected users",
                config={"notification_type": "email"},
                position={"x": 50, "y": 600}
            ),
            "end": WorkflowNode(
                node_id="end",
                node_type=NodeType.END,
                name="End",
                description="Workflow end",
                config={},
                position={"x": 100, "y": 700}
            )
        }

        edges = [
            WorkflowEdge("e1", "start", "analyze_email"),
            WorkflowEdge("e2", "analyze_email", "is_phishing"),
            WorkflowEdge("e3", "is_phishing", "quarantine_email", condition="true"),
            WorkflowEdge("e4", "is_phishing", "end", condition="false"),
            WorkflowEdge("e5", "quarantine_email", "block_sender"),
            WorkflowEdge("e6", "block_sender", "notify_users"),
            WorkflowEdge("e7", "notify_users", "end")
        ]

        return WorkflowDefinition(
            workflow_id="wf-phishing-response",
            name="Phishing Response",
            description="Automated phishing email response",
            version="1.0.0",
            nodes=nodes,
            edges=edges,
            triggers=["email_received", "user_reported_phishing"]
        )

    def _create_malware_containment_workflow(self) -> WorkflowDefinition:
        """Create malware containment workflow."""
        nodes = {
            "start": WorkflowNode(
                node_id="start",
                node_type=NodeType.START,
                name="Start",
                description="Workflow start",
                config={},
                position={"x": 100, "y": 100}
            ),
            "scan_host": WorkflowNode(
                node_id="scan_host",
                node_type=NodeType.ACTION,
                name="Scan Host",
                description="Scan host for malware",
                config={"action": "scan_endpoint"},
                position={"x": 100, "y": 200}
            ),
            "isolate_host": WorkflowNode(
                node_id="isolate_host",
                node_type=NodeType.ACTION,
                name="Isolate Host",
                description="Isolate infected host",
                config={"action": "isolate_host"},
                position={"x": 100, "y": 300}
            ),
            "collect_evidence": WorkflowNode(
                node_id="collect_evidence",
                node_type=NodeType.ACTION,
                name="Collect Evidence",
                description="Collect forensic evidence",
                config={"action": "collect_forensics"},
                position={"x": 100, "y": 400}
            ),
            "remediate": WorkflowNode(
                node_id="remediate",
                node_type=NodeType.ACTION,
                name="Remediate",
                description="Remove malware and remediate",
                config={"action": "remediate_malware"},
                position={"x": 100, "y": 500}
            ),
            "end": WorkflowNode(
                node_id="end",
                node_type=NodeType.END,
                name="End",
                description="Workflow end",
                config={},
                position={"x": 100, "y": 600}
            )
        }

        edges = [
            WorkflowEdge("e1", "start", "scan_host"),
            WorkflowEdge("e2", "scan_host", "isolate_host"),
            WorkflowEdge("e3", "isolate_host", "collect_evidence"),
            WorkflowEdge("e4", "collect_evidence", "remediate"),
            WorkflowEdge("e5", "remediate", "end")
        ]

        return WorkflowDefinition(
            workflow_id="wf-malware-containment",
            name="Malware Containment",
            description="Automated malware containment and remediation",
            version="1.0.0",
            nodes=nodes,
            edges=edges,
            triggers=["malware_detected", "edr_alert"]
        )

    def _create_user_onboarding_workflow(self) -> WorkflowDefinition:
        """Create user onboarding workflow."""
        nodes = {
            "start": WorkflowNode(
                node_id="start",
                node_type=NodeType.START,
                name="Start",
                description="Workflow start",
                config={},
                position={"x": 100, "y": 100}
            ),
            "create_account": WorkflowNode(
                node_id="create_account",
                node_type=NodeType.ACTION,
                name="Create Account",
                description="Create user account",
                config={"action": "create_user_account"},
                position={"x": 100, "y": 200}
            ),
            "assign_roles": WorkflowNode(
                node_id="assign_roles",
                node_type=NodeType.ACTION,
                name="Assign Roles",
                description="Assign security roles",
                config={"action": "assign_user_roles"},
                position={"x": 100, "y": 300}
            ),
            "enable_mfa": WorkflowNode(
                node_id="enable_mfa",
                node_type=NodeType.ACTION,
                name="Enable MFA",
                description="Enable multi-factor authentication",
                config={"action": "enable_mfa"},
                position={"x": 100, "y": 400}
            ),
            "send_welcome": WorkflowNode(
                node_id="send_welcome",
                node_type=NodeType.NOTIFICATION,
                name="Send Welcome Email",
                description="Send welcome email with security info",
                config={"notification_type": "email"},
                position={"x": 100, "y": 500}
            ),
            "end": WorkflowNode(
                node_id="end",
                node_type=NodeType.END,
                name="End",
                description="Workflow end",
                config={},
                position={"x": 100, "y": 600}
            )
        }

        edges = [
            WorkflowEdge("e1", "start", "create_account"),
            WorkflowEdge("e2", "create_account", "assign_roles"),
            WorkflowEdge("e3", "assign_roles", "enable_mfa"),
            WorkflowEdge("e4", "enable_mfa", "send_welcome"),
            WorkflowEdge("e5", "send_welcome", "end")
        ]

        return WorkflowDefinition(
            workflow_id="wf-user-onboarding",
            name="User Onboarding",
            description="Security user onboarding workflow",
            version="1.0.0",
            nodes=nodes,
            edges=edges,
            triggers=["user_created", "hr_onboarding"]
        )

    def _register_node_handlers(self):
        """Register handlers for different node types."""
        self.node_handlers[NodeType.ACTION] = self._handle_action_node
        self.node_handlers[NodeType.DECISION] = self._handle_decision_node
        self.node_handlers[NodeType.NOTIFICATION] = self._handle_notification_node

    async def _handle_action_node(self, node: WorkflowNode, execution: WorkflowExecution):
        """Handle action node execution."""
        await asyncio.sleep(0.1)  # Simulate action
        execution.execution_log.append({
            "node_id": node.node_id,
            "node_type": node.node_type.value,
            "action": node.config.get("action"),
            "status": "completed",
            "timestamp": datetime.utcnow().isoformat()
        })

    async def _handle_decision_node(self, node: WorkflowNode, execution: WorkflowExecution):
        """Handle decision node execution."""
        # Evaluate condition (simplified)
        condition = node.config.get("condition", "true")
        result = True  # Simplified evaluation

        execution.execution_log.append({
            "node_id": node.node_id,
            "node_type": node.node_type.value,
            "condition": condition,
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def _handle_notification_node(self, node: WorkflowNode, execution: WorkflowExecution):
        """Handle notification node execution."""
        await asyncio.sleep(0.1)  # Simulate notification
        execution.execution_log.append({
            "node_id": node.node_id,
            "node_type": node.node_type.value,
            "notification_type": node.config.get("notification_type"),
            "status": "sent",
            "timestamp": datetime.utcnow().isoformat()
        })

    def create_workflow(self, definition: WorkflowDefinition) -> None:
        """Create a new workflow."""
        self.workflows[definition.workflow_id] = definition

    async def execute_workflow(self, workflow_id: str, input_variables: Dict[str, Any] = None) -> WorkflowExecution:
        """Execute a workflow."""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found")

        execution = WorkflowExecution(
            execution_id=f"exec-{uuid.uuid4()}",
            workflow_id=workflow_id,
            status=WorkflowStatus.RUNNING,
            current_node_id="start",
            variables=input_variables or {}
        )

        self.executions[execution.execution_id] = execution

        # Execute workflow nodes
        await self._execute_nodes(workflow, execution)

        execution.status = WorkflowStatus.COMPLETED
        execution.completed_at = datetime.utcnow()

        return execution

    async def _execute_nodes(self, workflow: WorkflowDefinition, execution: WorkflowExecution):
        """Execute workflow nodes."""
        current_node_id = "start"

        while current_node_id != "end":
            node = workflow.nodes.get(current_node_id)
            if not node:
                break

            # Execute node
            handler = self.node_handlers.get(node.node_type)
            if handler:
                await handler(node, execution)

            # Get next node
            if node.next_nodes:
                current_node_id = node.next_nodes[0]
            else:
                # Find next node from edges
                next_edges = [e for e in workflow.edges if e.source_node_id == current_node_id]
                if next_edges:
                    current_node_id = next_edges[0].target_node_id
                else:
                    break

            execution.current_node_id = current_node_id


# Global instance
_workflow_orchestrator = None


def get_workflow_orchestrator() -> WorkflowOrchestrator:
    """Get global workflow orchestrator instance."""
    global _workflow_orchestrator
    if _workflow_orchestrator is None:
        _workflow_orchestrator = WorkflowOrchestrator()
    return _workflow_orchestrator
