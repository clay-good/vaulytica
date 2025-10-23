"""
Security Analysis Agent - Refactored for Agent Framework

Wraps the existing SecurityAnalystAgent to work with the new agent framework
while preserving all existing functionality.
"""

import time
from typing import List, Dict, Any, Optional
from datetime import datetime

from .framework import (
    BaseAgent,
    AgentCapability,
    AgentStatus,
    AgentContext,
    AgentInput,
    AgentOutput,
    AgentPriority
)
from .security_analyst import SecurityAnalystAgent as LegacySecurityAnalystAgent
from vaulytica.models import SecurityEvent, AnalysisResult
from vaulytica.config import VaulyticaConfig, get_config
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class SecurityAnalysisAgent(BaseAgent):
    """
    Security Analysis Agent for threat detection and analysis.

    This agent wraps the existing SecurityAnalystAgent and adapts it to
    the new agent framework interface while preserving all existing
    functionality.

    Capabilities:
    - Multi-layered threat intelligence enrichment
    - Behavioral anomaly detection
    - Attack pattern recognition
    - Threat actor attribution
    - Attack graph construction
    - ML-powered analysis
    - Real-time threat feed integration
    """

    def __init__(self, config: Optional[VaulyticaConfig] = None):
        """Initialize Security Analysis Agent"""
        if config is None:
            config = get_config()

        super().__init__(
            agent_id="security-analysis-agent",
            agent_name="Security Analysis Agent",
            agent_version="0.31.0",
            capabilities=[
                AgentCapability.THREAT_DETECTION,
                AgentCapability.THREAT_ANALYSIS,
                AgentCapability.THREAT_HUNTING
            ],
            description="Advanced security threat detection and analysis with ML-powered insights"
        )

        # Initialize the legacy agent
        self.legacy_agent = LegacySecurityAnalystAgent(config)
        self.config = config

        logger.info(f"Initialized {self.agent_name} v{self.agent_version}")

    async def execute(self, input_data: AgentInput) -> AgentOutput:
        """
        Execute security analysis task.

        Args:
            input_data: Input containing context, task, and parameters

        Returns:
            AgentOutput with analysis results
        """
        start_time = time.time()
        self._update_status(AgentStatus.RUNNING)

        try:
            # Validate input
            await self.validate_input(input_data)

            # Extract security events from context
            events = self._extract_events_from_context(input_data.context)

            if not events:
                logger.warning("No security events found in context")
                return self._create_empty_output(start_time)

            # Get historical context if available
            historical_context = self._extract_historical_context(input_data.context)

            # Perform analysis using legacy agent
            logger.info(f"Analyzing {len(events)} security event(s)")
            analysis_result = await self.legacy_agent.analyze(
                events=events,
                historical_context=historical_context
            )

            # Convert AnalysisResult to AgentOutput
            output = self._convert_to_agent_output(
                analysis_result,
                input_data,
                start_time
            )

            # Update shared context with findings
            self._update_context_with_findings(input_data.context, analysis_result)

            # Add audit trail
            audit_entry = self._create_audit_entry(
                action="security_analysis",
                data_sources=self._get_data_sources(input_data.context),
                reasoning=self._extract_reasoning(analysis_result),
                confidence=analysis_result.confidence,
                decision=f"Risk Score: {analysis_result.risk_score}/10, Severity: {analysis_result.severity}"
            )
            input_data.context.add_audit_entry(self.agent_id, audit_entry)

            self._update_status(AgentStatus.COMPLETED)
            logger.info(f"Security analysis completed in {output.execution_time:.2f}s")

            return output

        except Exception as e:
            self._update_status(AgentStatus.FAILED)
            logger.error(f"Security analysis failed: {e}")

            return AgentOutput(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                status=AgentStatus.FAILED,
                results={},
                confidence=0.0,
                reasoning=[f"Analysis failed: {str(e)}"],
                data_sources_used=[],
                recommendations=[],
                next_actions=["Review error logs", "Retry analysis with valid input"],
                audit_trail=[],
                execution_time=time.time() - start_time,
                error=str(e)
            )

    async def validate_input(self, input_data: AgentInput) -> bool:
        """
        Validate input data.

        Args:
            input_data: Input to validate

        Returns:
            True if valid

        Raises:
            ValueError: If input is invalid
        """
        if not input_data.context:
            raise ValueError("AgentContext is required")

        if not input_data.context.data_sources:
            raise ValueError("No data sources provided in context")

        # Check for security events in data sources
        has_events = False
        for source_name, source_data in input_data.context.data_sources.items():
            if isinstance(source_data, list) and len(source_data) > 0:
                has_events = True
                break

        if not has_events:
            logger.warning("No events found in data sources, but validation passes")

        return True

    def _extract_events_from_context(self, context: AgentContext) -> List[SecurityEvent]:
        """Extract SecurityEvent objects from context"""
        events = []

        # Look for events in data sources
        for source_name, source_data in context.data_sources.items():
            if isinstance(source_data, list):
                for item in source_data:
                    # If already a SecurityEvent, use it
                    if isinstance(item, SecurityEvent):
                        events.append(item)
                    # If dict, try to convert to SecurityEvent
                    elif isinstance(item, dict):
                        try:
                            event = self._dict_to_security_event(item, source_name)
                            events.append(event)
                        except Exception as e:
                            logger.warning(f"Failed to convert dict to SecurityEvent: {e}")

        return events

    def _dict_to_security_event(self, data: Dict[str, Any], source: str) -> SecurityEvent:
        """Convert dict to SecurityEvent"""
        # Ensure required fields
        if "event_id" not in data:
            data["event_id"] = f"{source}_{hash(str(data))}"
        if "source_system" not in data:
            data["source_system"] = source
        if "title" not in data:
            data["title"] = data.get("description", "Security Event")
        if "timestamp" not in data:
            data["timestamp"] = datetime.utcnow().isoformat()
        if "severity" not in data:
            data["severity"] = "medium"
        if "category" not in data:
            data["category"] = "unknown"
        if "description" not in data:
            data["description"] = str(data)
        if "raw_event" not in data:
            data["raw_event"] = data.copy()

        return SecurityEvent(**data)

    def _extract_historical_context(self, context: AgentContext) -> Optional[List[Dict]]:
        """Extract historical context from documents"""
        if not context.documents:
            return None

        historical = []
        for doc in context.documents:
            if doc.get("type") in ["historical_incident", "after_action_report", "post_mortem"]:
                historical.append(doc)

        return historical if historical else None

    def _convert_to_agent_output(
        self,
        analysis_result: AnalysisResult,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Convert AnalysisResult to AgentOutput"""

        # Extract recommendations
        recommendations = []
        for rec in analysis_result.recommendations:
            recommendations.append({
                "action": rec,
                "priority": self._determine_priority(analysis_result.risk_score),
                "category": "remediation"
            })

        # Extract next actions
        next_actions = []
        if analysis_result.risk_score >= 7.0:
            next_actions.append("Escalate to incident response team")
            next_actions.append("Initiate containment procedures")
        elif analysis_result.risk_score >= 5.0:
            next_actions.append("Continue monitoring")
            next_actions.append("Gather additional evidence")
        else:
            next_actions.append("Document findings")
            next_actions.append("Update threat intelligence")

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "risk_score": analysis_result.risk_score,
                "severity": analysis_result.severity,
                "confidence": analysis_result.confidence,
                "summary": analysis_result.summary,
                "attack_chain": analysis_result.attack_chain,
                "mitre_techniques": [t.dict() for t in analysis_result.mitre_techniques],
                "five_w1h": analysis_result.five_w1h.dict() if analysis_result.five_w1h else None,
                "iocs": analysis_result.iocs,
                "threat_actors": [ta.dict() for ta in analysis_result.threat_actors] if analysis_result.threat_actors else [],
                "behavioral_insights": [bi.dict() for bi in analysis_result.behavioral_insights] if analysis_result.behavioral_insights else [],
                "attack_graph": [node.dict() for node in analysis_result.attack_graph] if analysis_result.attack_graph else []
            },
            confidence=analysis_result.confidence,
            reasoning=self._extract_reasoning(analysis_result),
            data_sources_used=self._get_data_sources(input_data.context),
            recommendations=recommendations,
            next_actions=next_actions,
            audit_trail=[],
            execution_time=time.time() - start_time
        )

    def _update_context_with_findings(self, context: AgentContext, result: AnalysisResult):
        """Update shared context with analysis findings"""

        # Add main finding
        context.add_finding(self.agent_id, {
            "type": "threat_analysis",
            "risk_score": result.risk_score,
            "severity": result.severity,
            "confidence": result.confidence,
            "summary": result.summary,
            "attack_chain": result.attack_chain
        })

        # Add IOCs
        for ioc in result.iocs:
            if ioc not in [existing.get("value") for existing in context.iocs]:
                context.iocs.append({
                    "value": ioc,
                    "type": "unknown",
                    "source": self.agent_id,
                    "first_seen": datetime.utcnow().isoformat()
                })

        # Add threat intelligence
        if result.threat_actors:
            context.threat_intel["threat_actors"] = [
                ta.dict() for ta in result.threat_actors
            ]

    def _extract_reasoning(self, result: AnalysisResult) -> List[str]:
        """Extract reasoning from analysis result"""
        reasoning = []

        reasoning.append(f"Analyzed security event with risk score {result.risk_score}/10")
        reasoning.append(f"Confidence level: {result.confidence:.2%}")
        reasoning.append(f"Severity: {result.severity}")

        if result.mitre_techniques:
            techniques = ", ".join([t.technique_id for t in result.mitre_techniques[:3]])
            reasoning.append(f"Identified MITRE ATT&CK techniques: {techniques}")

        if result.threat_actors:
            actors = ", ".join([ta.name for ta in result.threat_actors[:2]])
            reasoning.append(f"Potential threat actors: {actors}")

        return reasoning

    def _get_data_sources(self, context: AgentContext) -> List[str]:
        """Get list of data sources used"""
        return list(context.data_sources.keys())

    def _determine_priority(self, risk_score: float) -> str:
        """Determine priority based on risk score"""
        if risk_score >= 8.0:
            return "critical"
        elif risk_score >= 6.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        else:
            return "low"

    def _create_empty_output(self, start_time: float) -> AgentOutput:
        """Create empty output when no events found"""
        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={"message": "No security events to analyze"},
            confidence=1.0,
            reasoning=["No security events found in context"],
            data_sources_used=[],
            recommendations=[],
            next_actions=["Verify data sources", "Check event ingestion"],
            audit_trail=[],
            execution_time=time.time() - start_time
        )
