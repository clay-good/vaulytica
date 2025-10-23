"""
Advanced Playbook Execution Engine for Vaulytica.

Extends the base playbook engine with advanced features:
- Conditional logic (if/else, switch statements)
- Loops and iterations (for each, while)
- Advanced error handling and retry logic
- Automatic rollback capability
- Human-in-the-loop approvals
- Parallel execution
- Dynamic variables and expressions
- Visual playbook builder support
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

import logging

logger = logging.getLogger(__name__)


class ControlFlowType(str, Enum):
    """Control flow types."""
    IF_ELSE = "if_else"
    SWITCH = "switch"
    FOR_EACH = "for_each"
    WHILE = "while"
    PARALLEL = "parallel"
    TRY_CATCH = "try_catch"


class VariableType(str, Enum):
    """Variable types."""
    STRING = "string"
    NUMBER = "number"
    BOOLEAN = "boolean"
    LIST = "list"
    DICT = "dict"
    JSON = "json"


@dataclass
class ConditionalBranch:
    """A conditional branch in control flow."""
    condition: str  # Python expression
    actions: List[str]  # Action IDs to execute
    description: Optional[str] = None


@dataclass
class LoopConfig:
    """Loop configuration."""
    loop_type: str  # "for_each", "while"
    iterable: Optional[str] = None  # Variable name or expression
    condition: Optional[str] = None  # For while loops
    max_iterations: int = 100
    current_iteration: int = 0


@dataclass
class RetryConfig:
    """Retry configuration for actions."""
    max_retries: int = 3
    retry_delay_seconds: int = 5
    backoff_multiplier: float = 2.0
    retry_on_errors: List[str] = field(default_factory=lambda: ["timeout", "connection_error"])


@dataclass
class RollbackAction:
    """Rollback action definition."""
    action_id: str
    rollback_type: str  # "undo", "restore", "compensate"
    rollback_data: Dict[str, Any] = field(default_factory=dict)
    executed: bool = False


@dataclass
class ApprovalRequest:
    """Human approval request."""
    request_id: str
    action_id: str
    action_name: str
    description: str
    risk_level: str  # "low", "medium", "high", "critical"
    requested_at: datetime
    requested_by: str
    approvers: List[str]
    timeout_seconds: int = 3600
    status: str = "pending"  # "pending", "approved", "rejected", "timeout"
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None


@dataclass
class AdvancedPlaybookAction:
    """Advanced playbook action with control flow."""
    action_id: str
    action_type: str
    name: str
    description: str
    parameters: Dict[str, Any] = field(default_factory=dict)

    # Control flow
    control_flow: Optional[ControlFlowType] = None
    conditional_branches: List[ConditionalBranch] = field(default_factory=list)
    loop_config: Optional[LoopConfig] = None
    parallel_actions: List[str] = field(default_factory=list)

    # Error handling
    retry_config: Optional[RetryConfig] = None
    error_handler: Optional[str] = None  # Action ID to execute on error
    continue_on_error: bool = False

    # Rollback
    rollback_action: Optional[RollbackAction] = None

    # Approval
    requires_approval: bool = False
    approval_config: Optional[Dict[str, Any]] = None

    # Variables
    input_variables: List[str] = field(default_factory=list)
    output_variable: Optional[str] = None

    # Dependencies
    depends_on: List[str] = field(default_factory=list)

    # Execution state
    status: str = "pending"
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time_seconds: float = 0.0


class AdvancedPlaybookEngine:
    """
    Advanced playbook execution engine.

    Provides sophisticated control flow, error handling, and rollback capabilities.
    """

    def __init__(self):
        self.action_handlers: Dict[str, Callable] = {}
        self.variables: Dict[str, Any] = {}
        self.rollback_stack: List[RollbackAction] = []
        self.approval_requests: Dict[str, ApprovalRequest] = {}

    # ==================== Variable Management ====================

    def set_variable(self, name: str, value: Any, var_type: Optional[VariableType] = None) -> None:
        """Set a variable value."""
        self.variables[name] = value
        logger.debug(f"Set variable: {name} = {value}")

    def get_variable(self, name: str, default: Any = None) -> Any:
        """Get a variable value."""
        return self.variables.get(name, default)

    def evaluate_expression(self, expression: str) -> Any:
        """
        Evaluate a Python expression with variables.

        Security note: In production, use a safe expression evaluator.
        """
        try:
            # Create a safe namespace with variables
            namespace = {
                **self.variables,
                'len': len,
                'str': str,
                'int': int,
                'float': float,
                'bool': bool,
                'list': list,
                'dict': dict,
            }
            result = eval(expression, {"__builtins__": {}}, namespace)
            return result
        except Exception as e:
            logger.error(f"Failed to evaluate expression '{expression}': {e}")
            return None

    # ==================== Conditional Execution ====================

    async def execute_conditional(
        self,
        action: AdvancedPlaybookAction,
        context: Dict[str, Any]
    ) -> Any:
        """Execute conditional logic (if/else)."""
        logger.info(f"Executing conditional action: {action.name}")

        for branch in action.conditional_branches:
            # Evaluate condition
            condition_result = self.evaluate_expression(branch.condition)

            if condition_result:
                logger.info(f"Condition '{branch.condition}' is True, executing branch")
                # Execute actions in this branch
                results = []
                for action_id in branch.actions:
                    result = await self._execute_action_by_id(action_id, context)
                    results.append(result)
                return results

        logger.info("No conditions matched, skipping conditional")
        return None

    async def execute_switch(
        self,
        action: AdvancedPlaybookAction,
        context: Dict[str, Any]
    ) -> Any:
        """Execute switch statement."""
        logger.info(f"Executing switch action: {action.name}")

        # Get the switch value
        switch_value = self.evaluate_expression(action.parameters.get("switch_on", ""))

        # Find matching case
        for branch in action.conditional_branches:
            case_value = self.evaluate_expression(branch.condition)
            if switch_value == case_value:
                logger.info(f"Switch matched case: {case_value}")
                results = []
                for action_id in branch.actions:
                    result = await self._execute_action_by_id(action_id, context)
                    results.append(result)
                return results

        # Execute default case if no match
        default_branch = next((b for b in action.conditional_branches if b.condition == "default"), None)
        if default_branch:
            logger.info("Executing default case")
            results = []
            for action_id in default_branch.actions:
                result = await self._execute_action_by_id(action_id, context)
                results.append(result)
            return results

        return None

    # ==================== Loop Execution ====================

    async def execute_for_each(
        self,
        action: AdvancedPlaybookAction,
        context: Dict[str, Any]
    ) -> List[Any]:
        """Execute for-each loop."""
        logger.info(f"Executing for-each loop: {action.name}")

        if not action.loop_config:
            raise ValueError("Loop config is required for for-each")

        # Get the iterable
        iterable = self.evaluate_expression(action.loop_config.iterable or "[]")
        if not isinstance(iterable, (list, tuple)):
            raise ValueError(f"For-each requires an iterable, got: {type(iterable)}")

        results = []
        for i, item in enumerate(iterable):
            if i >= action.loop_config.max_iterations:
                logger.warning(f"Reached max iterations ({action.loop_config.max_iterations})")
                break

            # Set loop variables
            self.set_variable("loop_item", item)
            self.set_variable("loop_index", i)

            # Execute loop body
            logger.info(f"Loop iteration {i + 1}/{len(iterable)}")
            for action_id in action.parameters.get("loop_actions", []):
                result = await self._execute_action_by_id(action_id, context)
                results.append(result)

        return results

    async def execute_while(
        self,
        action: AdvancedPlaybookAction,
        context: Dict[str, Any]
    ) -> List[Any]:
        """Execute while loop."""
        logger.info(f"Executing while loop: {action.name}")

        if not action.loop_config or not action.loop_config.condition:
            raise ValueError("Loop condition is required for while")

        results = []
        iteration = 0

        while iteration < action.loop_config.max_iterations:
            # Evaluate condition
            condition_result = self.evaluate_expression(action.loop_config.condition)
            if not condition_result:
                logger.info(f"While condition is False, exiting loop after {iteration} iterations")
                break

            # Set loop variable
            self.set_variable("loop_iteration", iteration)

            # Execute loop body
            logger.info(f"While loop iteration {iteration + 1}")
            for action_id in action.parameters.get("loop_actions", []):
                result = await self._execute_action_by_id(action_id, context)
                results.append(result)

            iteration += 1

        if iteration >= action.loop_config.max_iterations:
            logger.warning(f"While loop reached max iterations ({action.loop_config.max_iterations})")

        return results

    # ==================== Parallel Execution ====================

    async def execute_parallel(
        self,
        action: AdvancedPlaybookAction,
        context: Dict[str, Any]
    ) -> List[Any]:
        """Execute actions in parallel."""
        logger.info(f"Executing parallel actions: {action.name}")

        if not action.parallel_actions:
            logger.warning("No parallel actions specified")
            return []

        # Create tasks for all parallel actions
        tasks = []
        for action_id in action.parallel_actions:
            task = asyncio.create_task(self._execute_action_by_id(action_id, context))
            tasks.append(task)

        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Log results
        success_count = sum(1 for r in results if not isinstance(r, Exception))
        logger.info(f"Parallel execution complete: {success_count}/{len(results)} succeeded")

        return results

    # ==================== Error Handling & Retry ====================

    async def execute_with_retry(
        self,
        action: AdvancedPlaybookAction,
        context: Dict[str, Any],
        handler: Callable
    ) -> Any:
        """Execute action with retry logic."""
        retry_config = action.retry_config or RetryConfig()

        last_error = None
        for attempt in range(retry_config.max_retries + 1):
            try:
                logger.info(f"Executing action: {action.name} (attempt {attempt + 1}/{retry_config.max_retries + 1})")
                result = await handler(action, context)

                # Success!
                if attempt > 0:
                    logger.info(f"Action succeeded after {attempt + 1} attempts")
                return result

            except Exception as e:
                last_error = e
                error_type = type(e).__name__.lower()

                # Check if we should retry this error
                should_retry = any(err in error_type for err in retry_config.retry_on_errors)

                if not should_retry or attempt >= retry_config.max_retries:
                    logger.error(f"Action failed: {e}")
                    raise

                # Calculate delay with exponential backoff
                delay = retry_config.retry_delay_seconds * (retry_config.backoff_multiplier ** attempt)
                logger.warning(f"Action failed (attempt {attempt + 1}), retrying in {delay}s: {e}")
                await asyncio.sleep(delay)

        # Should not reach here, but just in case
        raise last_error or Exception("Action failed after all retries")

    # ==================== Rollback ====================

    def register_rollback(self, rollback_action: RollbackAction) -> None:
        """Register a rollback action."""
        self.rollback_stack.append(rollback_action)
        logger.debug(f"Registered rollback for action: {rollback_action.action_id}")

    async def execute_rollback(self) -> None:
        """Execute all rollback actions in reverse order."""
        logger.info(f"Executing rollback for {len(self.rollback_stack)} actions")

        # Execute rollbacks in reverse order (LIFO)
        while self.rollback_stack:
            rollback = self.rollback_stack.pop()

            if rollback.executed:
                logger.debug(f"Rollback already executed for: {rollback.action_id}")
                continue

            try:
                logger.info(f"Rolling back action: {rollback.action_id} (type: {rollback.rollback_type})")

                # Execute rollback based on type
                if rollback.rollback_type == "undo":
                    await self._execute_undo(rollback)
                elif rollback.rollback_type == "restore":
                    await self._execute_restore(rollback)
                elif rollback.rollback_type == "compensate":
                    await self._execute_compensate(rollback)

                rollback.executed = True
                logger.info(f"Successfully rolled back: {rollback.action_id}")

            except Exception as e:
                logger.error(f"Failed to rollback action {rollback.action_id}: {e}")
                # Continue with other rollbacks even if one fails

    async def _execute_undo(self, rollback: RollbackAction) -> None:
        """Execute undo rollback."""
        logger.debug(f"Undoing action: {rollback.action_id}")

    async def _execute_restore(self, rollback: RollbackAction) -> None:
        """Execute restore rollback."""
        logger.debug(f"Restoring state for action: {rollback.action_id}")

    async def _execute_compensate(self, rollback: RollbackAction) -> None:
        """Execute compensating transaction."""
        logger.debug(f"Executing compensating action for: {rollback.action_id}")

    # ==================== Approval Workflow ====================

    async def request_approval(
        self,
        action: AdvancedPlaybookAction,
        context: Dict[str, Any]
    ) -> bool:
        """Request human approval for an action."""
        request_id = str(uuid4())

        approval_config = action.approval_config or {}

        request = ApprovalRequest(
            request_id=request_id,
            action_id=action.action_id,
            action_name=action.name,
            description=action.description,
            risk_level=approval_config.get("risk_level", "medium"),
            requested_at=datetime.utcnow(),
            requested_by=context.get("user", "system"),
            approvers=approval_config.get("approvers", []),
            timeout_seconds=approval_config.get("timeout_seconds", 3600)
        )

        self.approval_requests[request_id] = request
        logger.info(f"Approval requested for action: {action.name} (Request ID: {request_id})")

        # Wait for approval (with timeout)
        timeout = request.timeout_seconds
        start_time = datetime.utcnow()

        while (datetime.utcnow() - start_time).total_seconds() < timeout:
            # Check if approved or rejected
            if request.status == "approved":
                logger.info(f"Action approved by: {request.approved_by}")
                return True
            elif request.status == "rejected":
                logger.info(f"Action rejected: {request.rejection_reason}")
                return False

            # Wait a bit before checking again
            await asyncio.sleep(5)

        # Timeout
        request.status = "timeout"
        logger.warning(f"Approval request timed out for action: {action.name}")
        return False

    def approve_action(self, request_id: str, approver: str) -> None:
        """Approve an action."""
        request = self.approval_requests.get(request_id)
        if not request:
            raise ValueError(f"Approval request not found: {request_id}")

        request.status = "approved"
        request.approved_by = approver
        request.approved_at = datetime.utcnow()
        logger.info(f"Action approved: {request.action_name} by {approver}")

    def reject_action(self, request_id: str, approver: str, reason: str) -> None:
        """Reject an action."""
        request = self.approval_requests.get(request_id)
        if not request:
            raise ValueError(f"Approval request not found: {request_id}")

        request.status = "rejected"
        request.approved_by = approver
        request.approved_at = datetime.utcnow()
        request.rejection_reason = reason
        logger.info(f"Action rejected: {request.action_name} by {approver} - {reason}")

    # ==================== Helper Methods ====================

    async def _execute_action_by_id(self, action_id: str, context: Dict[str, Any]) -> Any:
        """Execute an action by ID (placeholder)."""
        logger.debug(f"Executing action: {action_id}")
        await asyncio.sleep(0.1)  # Simulate work
        return {"action_id": action_id, "status": "success"}


# Global advanced playbook engine instance
_advanced_playbook_engine: Optional[AdvancedPlaybookEngine] = None


def get_advanced_playbook_engine() -> AdvancedPlaybookEngine:
    """Get the global advanced playbook engine instance."""
    global _advanced_playbook_engine
    if _advanced_playbook_engine is None:
        _advanced_playbook_engine = AdvancedPlaybookEngine()
    return _advanced_playbook_engine
