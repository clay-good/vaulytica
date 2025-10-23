"""
Agent Orchestrator - Coordinates multiple agents in workflows

Manages agent execution, inter-agent communication, and workflow coordination.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import asyncio
import uuid

from .framework import (
    BaseAgent,
    AgentContext,
    AgentInput,
    AgentOutput,
    AgentStatus,
    AgentCapability,
    AgentPriority,
    get_agent_registry
)
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ExecutionMode(Enum):
    """Agent execution mode"""
    SEQUENTIAL = "sequential"  # Execute agents one after another
    PARALLEL = "parallel"      # Execute agents concurrently
    CONDITIONAL = "conditional"  # Execute based on conditions


@dataclass
class WorkflowStep:
    """A step in a workflow"""
    step_id: str
    agent_id: str
    task: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: AgentPriority = AgentPriority.MEDIUM
    depends_on: List[str] = field(default_factory=list)
    """List of step_ids that must complete before this step"""
    condition: Optional[str] = None
    """Optional condition to evaluate before executing"""
    timeout_seconds: Optional[int] = None


@dataclass
class WorkflowDefinition:
    """Definition of a multi-agent workflow"""
    workflow_id: str
    workflow_name: str
    description: str
    steps: List[WorkflowStep]
    execution_mode: ExecutionMode = ExecutionMode.SEQUENTIAL
    timeout_seconds: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowExecution:
    """Runtime state of a workflow execution"""
    execution_id: str
    workflow_id: str
    workflow_name: str
    context: AgentContext
    status: WorkflowStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    step_results: Dict[str, AgentOutput] = field(default_factory=dict)
    """Map of step_id to agent output"""
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AgentOrchestrator:
    """
    Orchestrates multiple agents in coordinated workflows.

    Responsibilities:
    - Execute multi-agent workflows
    - Manage shared context between agents
    - Handle dependencies and execution order
    - Provide workflow monitoring and control
    - Aggregate results from multiple agents
    """

    def __init__(self):
        self.registry = get_agent_registry()
        self.workflows: Dict[str, WorkflowDefinition] = {}
        self.executions: Dict[str, WorkflowExecution] = {}
        self.logger = get_logger(__name__)

    def register_workflow(self, workflow: WorkflowDefinition) -> None:
        """Register a workflow definition"""
        self.workflows[workflow.workflow_id] = workflow
        self.logger.info(f"Registered workflow: {workflow.workflow_name} ({workflow.workflow_id})")

    async def execute_workflow(
        self,
        workflow_id: str,
        context: AgentContext,
        parameters: Optional[Dict[str, Any]] = None
    ) -> WorkflowExecution:
        """
        Execute a registered workflow.

        Args:
            workflow_id: ID of workflow to execute
            context: Shared context for agents
            parameters: Optional parameters to override workflow defaults

        Returns:
            WorkflowExecution with results from all agents
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow not found: {workflow_id}")

        execution_id = str(uuid.uuid4())
        execution = WorkflowExecution(
            execution_id=execution_id,
            workflow_id=workflow.workflow_id,
            workflow_name=workflow.workflow_name,
            context=context,
            status=WorkflowStatus.RUNNING,
            started_at=datetime.utcnow()
        )

        self.executions[execution_id] = execution
        self.logger.info(f"Starting workflow execution: {workflow.workflow_name} ({execution_id})")

        try:
            if workflow.execution_mode == ExecutionMode.SEQUENTIAL:
                await self._execute_sequential(workflow, execution, parameters)
            elif workflow.execution_mode == ExecutionMode.PARALLEL:
                await self._execute_parallel(workflow, execution, parameters)
            elif workflow.execution_mode == ExecutionMode.CONDITIONAL:
                await self._execute_conditional(workflow, execution, parameters)

            execution.status = WorkflowStatus.COMPLETED
            execution.completed_at = datetime.utcnow()

            duration = (execution.completed_at - execution.started_at).total_seconds()
            self.logger.info(f"Workflow completed: {workflow.workflow_name} in {duration:.2f}s")

        except Exception as e:
            execution.status = WorkflowStatus.FAILED
            execution.completed_at = datetime.utcnow()
            execution.errors.append(str(e))
            self.logger.error(f"Workflow failed: {workflow.workflow_name} - {e}")
            raise

        return execution

    async def _execute_sequential(
        self,
        workflow: WorkflowDefinition,
        execution: WorkflowExecution,
        parameters: Optional[Dict[str, Any]]
    ):
        """Execute workflow steps sequentially"""
        for step in workflow.steps:
            self.logger.debug(f"Executing step: {step.step_id}")

            # Check dependencies
            if not self._check_dependencies(step, execution):
                self.logger.warning(f"Skipping step {step.step_id} - dependencies not met")
                continue

            # Execute step
            result = await self._execute_step(step, execution.context, parameters)
            execution.step_results[step.step_id] = result

            # Update context with results
            execution.context.add_finding(result.agent_id, {
                "step_id": step.step_id,
                "results": result.results,
                "confidence": result.confidence
            })

    async def _execute_parallel(
        self,
        workflow: WorkflowDefinition,
        execution: WorkflowExecution,
        parameters: Optional[Dict[str, Any]]
    ):
        """Execute workflow steps in parallel"""
        # Group steps by dependency level
        levels = self._compute_dependency_levels(workflow.steps)

        for level, steps in enumerate(levels):
            self.logger.debug(f"Executing level {level} with {len(steps)} steps")

            # Execute all steps at this level in parallel
            tasks = [
                self._execute_step(step, execution.context, parameters)
                for step in steps
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for step, result in zip(steps, results):
                if isinstance(result, Exception):
                    execution.errors.append(f"Step {step.step_id} failed: {result}")
                    self.logger.error(f"Step {step.step_id} failed: {result}")
                else:
                    execution.step_results[step.step_id] = result
                    execution.context.add_finding(result.agent_id, {
                        "step_id": step.step_id,
                        "results": result.results,
                        "confidence": result.confidence
                    })

    async def _execute_conditional(
        self,
        workflow: WorkflowDefinition,
        execution: WorkflowExecution,
        parameters: Optional[Dict[str, Any]]
    ):
        """Execute workflow steps based on conditions"""
        for step in workflow.steps:
            # Check dependencies
            if not self._check_dependencies(step, execution):
                continue

            # Evaluate condition if present
            if step.condition and not self._evaluate_condition(step.condition, execution):
                self.logger.debug(f"Skipping step {step.step_id} - condition not met")
                continue

            # Execute step
            result = await self._execute_step(step, execution.context, parameters)
            execution.step_results[step.step_id] = result

            # Update context
            execution.context.add_finding(result.agent_id, {
                "step_id": step.step_id,
                "results": result.results,
                "confidence": result.confidence
            })

    async def _execute_step(
        self,
        step: WorkflowStep,
        context: AgentContext,
        parameters: Optional[Dict[str, Any]]
    ) -> AgentOutput:
        """Execute a single workflow step"""
        agent = self.registry.get_agent(step.agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {step.agent_id}")

        # Merge parameters
        step_params = {**step.parameters}
        if parameters:
            step_params.update(parameters)

        # Create agent input
        agent_input = AgentInput(
            context=context,
            task=step.task,
            parameters=step_params,
            priority=step.priority,
            timeout_seconds=step.timeout_seconds
        )

        # Execute agent
        start_time = datetime.utcnow()
        result = await agent.execute(agent_input)
        duration = (datetime.utcnow() - start_time).total_seconds()

        self.logger.info(
            f"Step {step.step_id} completed in {duration:.2f}s "
            f"(agent: {agent.agent_name}, status: {result.status.value})"
        )

        return result

    def _check_dependencies(
        self,
        step: WorkflowStep,
        execution: WorkflowExecution
    ) -> bool:
        """Check if step dependencies are satisfied"""
        for dep_step_id in step.depends_on:
            if dep_step_id not in execution.step_results:
                return False

            result = execution.step_results[dep_step_id]
            if result.status != AgentStatus.COMPLETED:
                return False

        return True

    def _evaluate_condition(
        self,
        condition: str,
        execution: WorkflowExecution
    ) -> bool:
        """Evaluate a condition expression"""
        # Simple condition evaluation
        # In production, use a proper expression evaluator
        try:
            # Create evaluation context
            eval_context = {
                "results": execution.step_results,
                "context": execution.context,
                "metadata": execution.metadata
            }

            # Evaluate condition
            return eval(condition, {"__builtins__": {}}, eval_context)
        except Exception as e:
            self.logger.warning(f"Failed to evaluate condition '{condition}': {e}")
            return False

    def _compute_dependency_levels(
        self,
        steps: List[WorkflowStep]
    ) -> List[List[WorkflowStep]]:
        """
        Compute dependency levels for parallel execution.

        Returns list of lists, where each inner list contains steps
        that can be executed in parallel.
        """
        levels: List[List[WorkflowStep]] = []
        remaining = steps.copy()
        completed = set()

        while remaining:
            # Find steps with no unsatisfied dependencies
            current_level = []
            for step in remaining:
                if all(dep in completed for dep in step.depends_on):
                    current_level.append(step)

            if not current_level:
                # Circular dependency or invalid workflow
                raise ValueError("Circular dependency detected in workflow")

            levels.append(current_level)

            # Mark steps as completed
            for step in current_level:
                completed.add(step.step_id)
                # OPTIMIZED: Set difference instead of list.remove()

                remaining = [x for x in remaining if x != step]

        return levels

    def get_execution(self, execution_id: str) -> Optional[WorkflowExecution]:
        """Get workflow execution by ID"""
        return self.executions.get(execution_id)

    def list_executions(self) -> List[WorkflowExecution]:
        """List all workflow executions"""
        return list(self.executions.values())

    def cancel_execution(self, execution_id: str) -> None:
        """Cancel a running workflow execution"""
        execution = self.executions.get(execution_id)
        if execution and execution.status == WorkflowStatus.RUNNING:
            execution.status = WorkflowStatus.CANCELLED
            execution.completed_at = datetime.utcnow()
            self.logger.info(f"Cancelled workflow execution: {execution_id}")


# Global orchestrator instance
_global_orchestrator: Optional[AgentOrchestrator] = None


def get_orchestrator() -> AgentOrchestrator:
    """Get the global agent orchestrator"""
    global _global_orchestrator
    if _global_orchestrator is None:
        _global_orchestrator = AgentOrchestrator()
    return _global_orchestrator
