"""
Vaulytica AI Agent Framework - Core Components

Provides the foundation for modular AI agents with shared context,
orchestration, and explainability.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import uuid
import time
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class AgentCapability(Enum):
    """Agent capabilities"""
    THREAT_DETECTION = "threat_detection"
    THREAT_ANALYSIS = "threat_analysis"
    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    SBOM_ANALYSIS = "sbom_analysis"
    AUTOMATED_REMEDIATION = "automated_remediation"
    COMPLIANCE = "compliance"
    FORENSICS = "forensics"
    ROOT_CAUSE_ANALYSIS = "root_cause_analysis"
    TIMELINE_RECONSTRUCTION = "timeline_reconstruction"
    IMPACT_ASSESSMENT = "impact_assessment"
    POST_MORTEM_GENERATION = "post_mortem_generation"


class AgentStatus(Enum):
    """Agent execution status"""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"


class AgentPriority(Enum):
    """Task priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AgentContext:
    """
    Shared context between agents.

    This is the primary mechanism for inter-agent communication and
    knowledge sharing during incident response workflows.
    """
    # Core identifiers
    incident_id: str
    workflow_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # Data sources
    data_sources: Dict[str, Any] = field(default_factory=dict)
    """Raw data from various sources (logs, EDR, network, cloud, etc.)"""

    documents: List[Dict[str, Any]] = field(default_factory=list)
    """Documents (IR plans, SOPs, playbooks, historical incidents)"""

    communications: List[Dict[str, Any]] = field(default_factory=list)
    """Teams/Slack messages, emails, analyst notes"""

    # Analysis results
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    """Reconstructed timeline of events"""

    findings: List[Dict[str, Any]] = field(default_factory=list)
    """Security findings from various agents"""

    iocs: List[Dict[str, Any]] = field(default_factory=list)
    """Indicators of Compromise"""

    threat_intel: Dict[str, Any] = field(default_factory=dict)
    """Threat intelligence enrichment data"""

    # Incident response specific
    incident_metadata: Dict[str, Any] = field(default_factory=dict)
    """Incident classification, severity, status, etc."""

    affected_assets: List[Dict[str, Any]] = field(default_factory=list)
    """Systems, users, data affected by incident"""

    actions_taken: List[Dict[str, Any]] = field(default_factory=list)
    """Human and automated actions during response"""

    # Audit and explainability
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    """Complete audit trail of agent decisions and actions"""

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    """Additional context-specific metadata"""

    def add_finding(self, agent_id: str, finding: Dict[str, Any]) -> None:
        """Add a finding from an agent"""
        finding["agent_id"] = agent_id
        finding["timestamp"] = datetime.utcnow().isoformat()
        self.findings.append(finding)
        self.updated_at = datetime.utcnow()

    def add_timeline_event(self, event: Dict[str, Any]) -> None:
        """Add an event to the timeline"""
        if "timestamp" not in event:
            event["timestamp"] = datetime.utcnow().isoformat()
        self.timeline.append(event)
        self.updated_at = datetime.utcnow()

    def add_action(self, action: Dict[str, Any]) -> None:
        """Record an action taken"""
        action["recorded_at"] = datetime.utcnow().isoformat()
        self.actions_taken.append(action)
        self.updated_at = datetime.utcnow()

    def add_audit_entry(self, agent_id: str, entry: Dict[str, Any]) -> None:
        """Add an audit trail entry"""
        entry["agent_id"] = agent_id
        entry["timestamp"] = datetime.utcnow().isoformat()
        self.audit_trail.append(entry)
        self.updated_at = datetime.utcnow()


@dataclass
class AgentInput:
    """Input to an agent"""
    context: AgentContext
    task: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: AgentPriority = AgentPriority.MEDIUM
    timeout_seconds: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentOutput:
    """Output from an agent"""
    agent_id: str
    agent_name: str
    status: AgentStatus
    results: Dict[str, Any]
    confidence: float
    reasoning: List[str]
    data_sources_used: List[str]
    recommendations: List[Dict[str, Any]]
    next_actions: List[str]
    audit_trail: List[Dict[str, Any]]
    execution_time: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentMetadata:
    """Metadata about an agent"""
    agent_id: str
    agent_name: str
    agent_version: str
    capabilities: List[AgentCapability]
    description: str
    author: str = "Vaulytica"
    created_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)


class BaseAgent(ABC):
    """
    Base class for all Vaulytica agents.

    All agents must implement this interface to participate in the
    agent framework and orchestration system.
    """

    def __init__(
        self,
        agent_id: str,
        agent_name: str,
        agent_version: str,
        capabilities: List[AgentCapability],
        description: str = ""
    ):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.capabilities = capabilities
        self.description = description
        self.status = AgentStatus.IDLE
        self.context: Optional[AgentContext] = None
        self.logger = get_logger(f"{__name__}.{agent_name}")

        self.metadata = AgentMetadata(
            agent_id=agent_id,
            agent_name=agent_name,
            agent_version=agent_version,
            capabilities=capabilities,
            description=description
        )

    @abstractmethod
    async def execute(self, input_data: AgentInput) -> AgentOutput:
        """
        Execute agent task.

        This is the main entry point for agent execution. Agents should:
        1. Validate input
        2. Update status to RUNNING
        3. Perform their specialized task
        4. Update shared context
        5. Create audit trail entries
        6. Return structured output

        Args:
            input_data: Input containing context, task, and parameters

        Returns:
            AgentOutput with results, reasoning, and recommendations
        """
        pass

    @abstractmethod
    async def validate_input(self, input_data: AgentInput) -> bool:
        """
        Validate input data before execution.

        Args:
            input_data: Input to validate

        Returns:
            True if valid, raises ValueError if invalid
        """
        pass

    def get_capabilities(self) -> List[AgentCapability]:
        """Return agent capabilities"""
        return self.capabilities

    def get_metadata(self) -> AgentMetadata:
        """Return agent metadata"""
        return self.metadata

    async def enrich_context(self, context: AgentContext) -> AgentContext:
        """
        Enrich shared context with agent-specific data.

        Override this method to add agent-specific enrichment to the
        shared context before execution.

        Args:
            context: Shared context to enrich

        Returns:
            Enriched context
        """
        return context

    def _create_audit_entry(
        self,
        action: str,
        data_sources: List[str],
        reasoning: List[str],
        confidence: float,
        decision: str,
        alternatives: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Create an audit trail entry for explainability.

        This supports AI Explainability (XAI) requirements.
        """
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "action": action,
            "data_sources_used": data_sources,
            "reasoning_chain": reasoning,
            "confidence_score": confidence,
            "decision": decision,
            "alternatives_considered": alternatives or [],
            "timestamp": datetime.utcnow().isoformat()
        }

    def _update_status(self, status: AgentStatus):
        """Update agent status"""
        self.status = status
        self.logger.debug(f"Agent status updated to {status.value}")

    async def _execute_with_timeout(
        self,
        input_data: AgentInput,
        timeout_seconds: Optional[int] = None
    ) -> AgentOutput:
        """
        Execute with timeout protection.

        This is a wrapper that can be used by subclasses to add
        timeout protection to their execute methods.
        """
        import asyncio

        timeout = timeout_seconds or input_data.timeout_seconds

        if timeout:
            try:
                return await asyncio.wait_for(
                    self.execute(input_data),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                self.logger.error(f"Agent execution timed out after {timeout}s")
                return AgentOutput(
                    agent_id=self.agent_id,
                    agent_name=self.agent_name,
                    status=AgentStatus.FAILED,
                    results={},
                    confidence=0.0,
                    reasoning=[f"Execution timed out after {timeout} seconds"],
                    data_sources_used=[],
                    recommendations=[],
                    next_actions=[],
                    audit_trail=[],
                    execution_time=timeout,
                    error=f"Timeout after {timeout} seconds"
                )
        else:
            return await self.execute(input_data)


class AgentRegistry:
    """
    Registry for managing available agents.

    Provides agent discovery, registration, and lookup capabilities.
    """

    def __init__(self):
        self._agents: Dict[str, BaseAgent] = {}
        self._capabilities_index: Dict[AgentCapability, Set[str]] = {}
        self.logger = get_logger(__name__)

    def register(self, agent: BaseAgent) -> None:
        """Register an agent"""
        self._agents[agent.agent_id] = agent

        # Index by capabilities
        for capability in agent.capabilities:
            if capability not in self._capabilities_index:
                self._capabilities_index[capability] = set()
            self._capabilities_index[capability].add(agent.agent_id)

        self.logger.info(f"Registered agent: {agent.agent_name} ({agent.agent_id})")

    def unregister(self, agent_id: str) -> None:
        """Unregister an agent"""
        if agent_id in self._agents:
            agent = self._agents[agent_id]

            # Remove from capabilities index
            for capability in agent.capabilities:
                if capability in self._capabilities_index:
                    self._capabilities_index[capability].discard(agent_id)

            del self._agents[agent_id]
            self.logger.info(f"Unregistered agent: {agent_id}")

    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID"""
        return self._agents.get(agent_id)

    def get_agents_by_capability(
        self,
        capability: AgentCapability
    ) -> List[BaseAgent]:
        """Get all agents with a specific capability"""
        agent_ids = self._capabilities_index.get(capability, set())
        return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    def list_agents(self) -> List[AgentMetadata]:
        """List all registered agents"""
        return [agent.get_metadata() for agent in self._agents.values()]

    def get_agent_count(self) -> int:
        """Get total number of registered agents"""
        return len(self._agents)


# Global registry instance
_global_registry: Optional[AgentRegistry] = None


def get_agent_registry() -> AgentRegistry:
    """Get the global agent registry"""
    global _global_registry
    if _global_registry is None:
        _global_registry = AgentRegistry()
    return _global_registry
