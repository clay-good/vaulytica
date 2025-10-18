import asyncio
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


# ============================================================================
# Enums
# ============================================================================

class PipelineType(Enum):
    """CI/CD pipeline types."""
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    CIRCLECI = "circleci"
    AZURE_DEVOPS = "azure_devops"
    TRAVIS_CI = "travis_ci"


class SecurityGateType(Enum):
    """Security gate types."""
    SAST = "sast"  # Static Application Security Testing
    DAST = "dast"  # Dynamic Application Security Testing
    SCA = "sca"   # Software Composition Analysis
    SECRETS_SCAN = "secrets_scan"
    CONTAINER_SCAN = "container_scan"
    IAC_SCAN = "iac_scan"  # Infrastructure as Code
    LICENSE_CHECK = "license_check"
    COMPLIANCE_CHECK = "compliance_check"


class GateStatus(Enum):
    """Security gate status."""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    SKIPPED = "skipped"
    IN_PROGRESS = "in_progress"


class OrchestrationAction(Enum):
    """Security orchestration actions."""
    SCAN = "scan"
    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    REMEDIATE = "remediate"
    ESCALATE = "escalate"
    NOTIFY = "notify"
    TICKET = "ticket"


class ThreatIntelSource(Enum):
    """Threat intelligence sources."""
    VIRUSTOTAL = "virustotal"
    ALIENVAULT_OTX = "alienvault_otx"
    MITRE_ATTCK = "mitre_attck"
    ABUSE_IPDB = "abuse_ipdb"
    SHODAN = "shodan"
    GREYNOISE = "greynoise"
    INTERNAL = "internal"
    ML_CORRELATION = "ml_correlation"


class PentestType(Enum):
    """Penetration testing types."""
    NETWORK = "network"
    WEB_APPLICATION = "web_application"
    API = "api"
    MOBILE = "mobile"
    CLOUD = "cloud"
    SOCIAL_ENGINEERING = "social_engineering"


class Severity(Enum):
    """Severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class PipelineConfig:
    """CI/CD pipeline configuration."""
    pipeline_id: str
    name: str
    pipeline_type: PipelineType
    repository: str
    branch: str
    security_gates: List[SecurityGateType] = field(default_factory=list)
    fail_on_critical: bool = True
    fail_on_high: bool = False
    auto_remediate: bool = False
    notification_channels: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityGate:
    """Security gate result."""
    gate_id: str
    gate_type: SecurityGateType
    status: GateStatus
    pipeline_id: str
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    duration_seconds: float
    details: Dict[str, Any] = field(default_factory=dict)
    executed_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class OrchestrationWorkflow:
    """Security orchestration workflow."""
    workflow_id: str
    name: str
    description: str
    trigger_conditions: List[str]
    actions: List[OrchestrationAction]
    priority: int = 5  # 1-10, 10 is highest
    enabled: bool = True
    execution_count: int = 0
    last_executed: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIntelIndicator:
    """Threat intelligence indicator."""
    indicator_id: str
    indicator_type: str  # ip, domain, hash, url, email
    value: str
    sources: List[ThreatIntelSource]
    confidence_score: float  # 0.0-1.0
    severity: Severity
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityMetrics:
    """Security metrics and KPIs."""
    metric_id: str
    timestamp: datetime
    vulnerabilities_total: int
    vulnerabilities_by_severity: Dict[str, int]
    mean_time_to_detect: float  # hours
    mean_time_to_respond: float  # hours
    mean_time_to_remediate: float  # hours
    security_posture_score: float  # 0-100
    compliance_score: float  # 0-100
    threat_intel_indicators: int
    incidents_total: int
    incidents_resolved: int
    false_positive_rate: float  # 0.0-1.0


@dataclass
class PentestResult:
    """Penetration testing result."""
    test_id: str
    test_type: PentestType
    target: str
    vulnerabilities_found: int
    critical_findings: List[str]
    high_findings: List[str]
    medium_findings: List[str]
    low_findings: List[str]
    risk_score: float  # 0-10
    recommendations: List[str]
    executed_at: datetime = field(default_factory=datetime.utcnow)
    duration_seconds: float = 0.0


# ============================================================================
# DevSecOps Pipeline Integration
# ============================================================================

class DevSecOpsPipeline:
    """
    DevSecOps pipeline integration with security gates.
    
    Integrates with CI/CD pipelines to enforce security policies and gates.
    """
    
    def __init__(self):
        self.pipelines: Dict[str, PipelineConfig] = {}
        self.gate_results: List[SecurityGate] = []
        self.statistics = {
            "pipelines_configured": 0,
            "gates_executed": 0,
            "gates_passed": 0,
            "gates_failed": 0,
            "vulnerabilities_blocked": 0
        }
    
    async def configure_pipeline(self, config: PipelineConfig) -> Dict[str, Any]:
        """
        Configure a DevSecOps pipeline.
        
        Args:
            config: Pipeline configuration
        
        Returns:
            Configuration result
        """
        logger.info(f"Configuring pipeline: {config.name} ({config.pipeline_type.value})")
        
        self.pipelines[config.pipeline_id] = config
        self.statistics["pipelines_configured"] += 1
        
        return {
            "pipeline_id": config.pipeline_id,
            "status": "configured",
            "security_gates": [gate.value for gate in config.security_gates],
            "fail_on_critical": config.fail_on_critical,
            "fail_on_high": config.fail_on_high
        }
    
    async def execute_security_gates(
        self,
        pipeline_id: str,
        commit_sha: str,
        artifacts: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute security gates for a pipeline run.
        
        Args:
            pipeline_id: Pipeline identifier
            commit_sha: Git commit SHA
            artifacts: Build artifacts to scan
        
        Returns:
            Gate execution results
        """
        logger.info(f"Executing security gates for pipeline: {pipeline_id}")
        
        if pipeline_id not in self.pipelines:
            raise ValueError(f"Pipeline not configured: {pipeline_id}")
        
        config = self.pipelines[pipeline_id]
        gate_results = []
        overall_status = GateStatus.PASSED
        
        for gate_type in config.security_gates:
            result = await self._execute_gate(gate_type, pipeline_id, artifacts)
            gate_results.append(result)
            self.gate_results.append(result)
            self.statistics["gates_executed"] += 1
            
            if result.status == GateStatus.PASSED:
                self.statistics["gates_passed"] += 1
            elif result.status == GateStatus.FAILED:
                self.statistics["gates_failed"] += 1
                overall_status = GateStatus.FAILED
                
                # Check if we should fail the build
                if config.fail_on_critical and result.critical_count > 0:
                    self.statistics["vulnerabilities_blocked"] += result.critical_count
                if config.fail_on_high and result.high_count > 0:
                    self.statistics["vulnerabilities_blocked"] += result.high_count
        
        return {
            "pipeline_id": pipeline_id,
            "commit_sha": commit_sha,
            "overall_status": overall_status.value,
            "gates": [
                {
                    "type": gate.gate_type.value,
                    "status": gate.status.value,
                    "findings": gate.findings_count,
                    "critical": gate.critical_count,
                    "high": gate.high_count,
                    "duration": gate.duration_seconds
                }
                for gate in gate_results
            ],
            "should_fail_build": overall_status == GateStatus.FAILED
        }
    
    async def _execute_gate(
        self,
        gate_type: SecurityGateType,
        pipeline_id: str,
        artifacts: Dict[str, Any]
    ) -> SecurityGate:
        """Execute a single security gate."""
        start_time = datetime.utcnow()
        
        # Simulate gate execution with mock findings
        findings = self._generate_mock_findings(gate_type)
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Determine gate status
        status = GateStatus.PASSED
        if findings["critical"] > 0:
            status = GateStatus.FAILED
        elif findings["high"] > 3:
            status = GateStatus.WARNING
        
        return SecurityGate(
            gate_id=f"gate-{hashlib.md5(f'{pipeline_id}{gate_type.value}{start_time}'.encode()).hexdigest()[:12]}",
            gate_type=gate_type,
            status=status,
            pipeline_id=pipeline_id,
            findings_count=sum(findings.values()),
            critical_count=findings["critical"],
            high_count=findings["high"],
            medium_count=findings["medium"],
            low_count=findings["low"],
            duration_seconds=duration,
            details={"findings": findings}
        )
    
    def _generate_mock_findings(self, gate_type: SecurityGateType) -> Dict[str, int]:
        """Generate mock findings for testing."""
        # Different gate types have different finding patterns
        patterns = {
            SecurityGateType.SAST: {"critical": 1, "high": 3, "medium": 5, "low": 8},
            SecurityGateType.DAST: {"critical": 0, "high": 2, "medium": 4, "low": 6},
            SecurityGateType.SCA: {"critical": 2, "high": 5, "medium": 10, "low": 15},
            SecurityGateType.SECRETS_SCAN: {"critical": 1, "high": 0, "medium": 0, "low": 0},
            SecurityGateType.CONTAINER_SCAN: {"critical": 0, "high": 3, "medium": 7, "low": 12},
            SecurityGateType.IAC_SCAN: {"critical": 0, "high": 1, "medium": 3, "low": 5},
            SecurityGateType.LICENSE_CHECK: {"critical": 0, "high": 0, "medium": 2, "low": 3},
            SecurityGateType.COMPLIANCE_CHECK: {"critical": 0, "high": 1, "medium": 2, "low": 1}
        }
        return patterns.get(gate_type, {"critical": 0, "high": 0, "medium": 0, "low": 0})
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        return self.statistics.copy()


# Singleton instance
_devsecops_pipeline = None

def get_devsecops_pipeline() -> DevSecOpsPipeline:
    """Get the global DevSecOps pipeline instance."""
    global _devsecops_pipeline
    if _devsecops_pipeline is None:
        _devsecops_pipeline = DevSecOpsPipeline()
    return _devsecops_pipeline


# ============================================================================
# Security Orchestration Hub
# ============================================================================

class SecurityOrchestrationHub:
    """
    Security orchestration hub for automated workflow execution.

    Coordinates security responses across multiple tools and platforms.
    """

    def __init__(self):
        self.workflows: Dict[str, OrchestrationWorkflow] = {}
        self.execution_history: List[Dict[str, Any]] = []
        self.statistics = {
            "workflows_created": 0,
            "workflows_executed": 0,
            "actions_performed": 0,
            "incidents_auto_resolved": 0
        }

    async def create_workflow(self, workflow: OrchestrationWorkflow) -> Dict[str, Any]:
        """
        Create a security orchestration workflow.

        Args:
            workflow: Workflow configuration

        Returns:
            Creation result
        """
        logger.info(f"Creating workflow: {workflow.name}")

        self.workflows[workflow.workflow_id] = workflow
        self.statistics["workflows_created"] += 1

        return {
            "workflow_id": workflow.workflow_id,
            "status": "created",
            "actions": [action.value for action in workflow.actions],
            "priority": workflow.priority
        }

    async def execute_workflow(
        self,
        workflow_id: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute a security orchestration workflow.

        Args:
            workflow_id: Workflow identifier
            context: Execution context

        Returns:
            Execution result
        """
        logger.info(f"Executing workflow: {workflow_id}")

        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow not found: {workflow_id}")

        workflow = self.workflows[workflow_id]

        if not workflow.enabled:
            return {"status": "skipped", "reason": "workflow disabled"}

        start_time = datetime.utcnow()
        action_results = []

        # Execute each action in sequence
        for action in workflow.actions:
            result = await self._execute_action(action, context)
            action_results.append(result)
            self.statistics["actions_performed"] += 1

        # Update workflow statistics
        workflow.execution_count += 1
        workflow.last_executed = datetime.utcnow()
        self.statistics["workflows_executed"] += 1

        # Check if incident was auto-resolved
        if OrchestrationAction.REMEDIATE in workflow.actions:
            self.statistics["incidents_auto_resolved"] += 1

        duration = (datetime.utcnow() - start_time).total_seconds()

        execution_record = {
            "workflow_id": workflow_id,
            "executed_at": start_time.isoformat(),
            "duration_seconds": duration,
            "actions": action_results,
            "context": context
        }
        self.execution_history.append(execution_record)

        return execution_record

    async def _execute_action(
        self,
        action: OrchestrationAction,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a single orchestration action."""
        logger.info(f"Executing action: {action.value}")

        # Simulate action execution
        action_handlers = {
            OrchestrationAction.SCAN: self._action_scan,
            OrchestrationAction.ALERT: self._action_alert,
            OrchestrationAction.BLOCK: self._action_block,
            OrchestrationAction.QUARANTINE: self._action_quarantine,
            OrchestrationAction.REMEDIATE: self._action_remediate,
            OrchestrationAction.ESCALATE: self._action_escalate,
            OrchestrationAction.NOTIFY: self._action_notify,
            OrchestrationAction.TICKET: self._action_ticket
        }

        handler = action_handlers.get(action)
        if handler:
            return await handler(context)

        return {"action": action.value, "status": "not_implemented"}

    async def _action_scan(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scan action."""
        return {
            "action": "scan",
            "status": "completed",
            "findings": 5,
            "target": context.get("target", "unknown")
        }

    async def _action_alert(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute alert action."""
        return {
            "action": "alert",
            "status": "sent",
            "channels": ["email", "slack"],
            "recipients": 3
        }

    async def _action_block(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute block action."""
        return {
            "action": "block",
            "status": "blocked",
            "target": context.get("ip_address", "unknown"),
            "duration": "24h"
        }

    async def _action_quarantine(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute quarantine action."""
        return {
            "action": "quarantine",
            "status": "quarantined",
            "asset": context.get("asset_id", "unknown"),
            "location": "quarantine_zone"
        }

    async def _action_remediate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute remediate action."""
        return {
            "action": "remediate",
            "status": "remediated",
            "vulnerability": context.get("vulnerability_id", "unknown"),
            "method": "auto_patch"
        }

    async def _action_escalate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute escalate action."""
        return {
            "action": "escalate",
            "status": "escalated",
            "to": "security_team",
            "priority": "high"
        }

    async def _action_notify(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute notify action."""
        return {
            "action": "notify",
            "status": "notified",
            "channels": ["pagerduty", "teams"],
            "message": "Security incident detected"
        }

    async def _action_ticket(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute ticket creation action."""
        return {
            "action": "ticket",
            "status": "created",
            "ticket_id": f"SEC-{hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()[:8].upper()}",
            "system": "jira"
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestration statistics."""
        return self.statistics.copy()


# Singleton instance
_orchestration_hub = None

def get_orchestration_hub() -> SecurityOrchestrationHub:
    """Get the global security orchestration hub instance."""
    global _orchestration_hub
    if _orchestration_hub is None:
        _orchestration_hub = SecurityOrchestrationHub()
    return _orchestration_hub


# ============================================================================
# Advanced Threat Intelligence Platform
# ============================================================================

class AdvancedThreatIntelligence:
    """
    Advanced threat intelligence platform with ML-based correlation.

    Aggregates and correlates threat intelligence from multiple sources.
    """

    def __init__(self):
        self.indicators: Dict[str, ThreatIntelIndicator] = {}
        self.correlations: List[Dict[str, Any]] = []
        self.statistics = {
            "indicators_collected": 0,
            "sources_integrated": 0,
            "correlations_found": 0,
            "high_confidence_indicators": 0
        }

    async def ingest_indicator(self, indicator: ThreatIntelIndicator) -> Dict[str, Any]:
        """
        Ingest a threat intelligence indicator.

        Args:
            indicator: Threat intelligence indicator

        Returns:
            Ingestion result
        """
        logger.info(f"Ingesting indicator: {indicator.indicator_type} - {indicator.value}")

        # Check if indicator already exists
        if indicator.indicator_id in self.indicators:
            existing = self.indicators[indicator.indicator_id]
            # Merge sources
            existing.sources = list(set(existing.sources + indicator.sources))
            existing.last_seen = indicator.last_seen
            # Update confidence score (average)
            existing.confidence_score = (existing.confidence_score + indicator.confidence_score) / 2
        else:
            self.indicators[indicator.indicator_id] = indicator
            self.statistics["indicators_collected"] += 1

            if indicator.confidence_score >= 0.8:
                self.statistics["high_confidence_indicators"] += 1

        # Track unique sources
        self.statistics["sources_integrated"] = len(set(
            source for ind in self.indicators.values() for source in ind.sources
        ))

        return {
            "indicator_id": indicator.indicator_id,
            "status": "ingested",
            "confidence_score": indicator.confidence_score,
            "sources": [s.value for s in indicator.sources]
        }

    async def correlate_indicators(
        self,
        indicator_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Correlate multiple threat intelligence indicators using ML.

        Args:
            indicator_ids: List of indicator IDs to correlate

        Returns:
            Correlation results
        """
        logger.info(f"Correlating {len(indicator_ids)} indicators")

        indicators = [self.indicators[iid] for iid in indicator_ids if iid in self.indicators]

        if len(indicators) < 2:
            return {"status": "insufficient_data", "correlations": []}

        # Simulate ML-based correlation
        correlations = []

        # Group by indicator type
        by_type = defaultdict(list)
        for ind in indicators:
            by_type[ind.indicator_type].append(ind)

        # Find temporal correlations (indicators seen around the same time)
        for i, ind1 in enumerate(indicators):
            for ind2 in indicators[i+1:]:
                time_diff = abs((ind1.last_seen - ind2.last_seen).total_seconds())
                if time_diff < 3600:  # Within 1 hour
                    correlation = {
                        "correlation_id": f"corr-{hashlib.md5(f'{ind1.indicator_id}{ind2.indicator_id}'.encode()).hexdigest()[:12]}",
                        "indicators": [ind1.indicator_id, ind2.indicator_id],
                        "correlation_type": "temporal",
                        "confidence": 0.75,
                        "time_difference_seconds": time_diff,
                        "description": f"Indicators observed within {time_diff:.0f} seconds"
                    }
                    correlations.append(correlation)
                    self.statistics["correlations_found"] += 1

        # Find tag-based correlations
        for i, ind1 in enumerate(indicators):
            for ind2 in indicators[i+1:]:
                common_tags = set(ind1.tags) & set(ind2.tags)
                if common_tags:
                    correlation = {
                        "correlation_id": f"corr-{hashlib.md5(f'{ind1.indicator_id}{ind2.indicator_id}tags'.encode()).hexdigest()[:12]}",
                        "indicators": [ind1.indicator_id, ind2.indicator_id],
                        "correlation_type": "tag_based",
                        "confidence": 0.65,
                        "common_tags": list(common_tags),
                        "description": f"Indicators share {len(common_tags)} common tags"
                    }
                    correlations.append(correlation)
                    self.statistics["correlations_found"] += 1

        self.correlations.extend(correlations)

        return {
            "status": "completed",
            "indicators_analyzed": len(indicators),
            "correlations_found": len(correlations),
            "correlations": correlations
        }

    async def enrich_indicator(
        self,
        indicator_id: str
    ) -> Dict[str, Any]:
        """
        Enrich a threat intelligence indicator with additional context.

        Args:
            indicator_id: Indicator identifier

        Returns:
            Enriched indicator data
        """
        logger.info(f"Enriching indicator: {indicator_id}")

        if indicator_id not in self.indicators:
            raise ValueError(f"Indicator not found: {indicator_id}")

        indicator = self.indicators[indicator_id]

        # Simulate enrichment from multiple sources
        enrichment = {
            "indicator_id": indicator_id,
            "original_data": {
                "type": indicator.indicator_type,
                "value": indicator.value,
                "confidence": indicator.confidence_score
            },
            "enriched_data": {
                "geolocation": {
                    "country": "US",
                    "city": "New York",
                    "latitude": 40.7128,
                    "longitude": -74.0060
                },
                "reputation": {
                    "score": 25,  # 0-100, lower is worse
                    "category": "malicious"
                },
                "related_campaigns": [
                    "APT29",
                    "Cobalt Strike"
                ],
                "malware_families": [
                    "TrickBot",
                    "Emotet"
                ],
                "attack_techniques": [
                    "T1566.001 - Spearphishing Attachment",
                    "T1059.001 - PowerShell"
                ]
            },
            "sources_consulted": [s.value for s in indicator.sources]
        }

        return enrichment

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        return self.statistics.copy()


# Singleton instance
_threat_intelligence = None

def get_threat_intelligence() -> AdvancedThreatIntelligence:
    """Get the global advanced threat intelligence instance."""
    global _threat_intelligence
    if _threat_intelligence is None:
        _threat_intelligence = AdvancedThreatIntelligence()
    return _threat_intelligence


# ============================================================================
# Security Metrics & KPIs Dashboard
# ============================================================================

class SecurityMetricsDashboard:
    """
    Security metrics and KPIs dashboard for executive reporting.

    Tracks and visualizes security posture and performance metrics.
    """

    def __init__(self):
        self.metrics_history: List[SecurityMetrics] = []
        self.statistics = {
            "metrics_collected": 0,
            "average_posture_score": 0.0,
            "average_compliance_score": 0.0,
            "trend": "stable"
        }

    async def collect_metrics(self) -> SecurityMetrics:
        """
        Collect current security metrics.

        Returns:
            Current security metrics
        """
        logger.info("Collecting security metrics")

        # Simulate metric collection from various sources
        metrics = SecurityMetrics(
            metric_id=f"metrics-{hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()[:12]}",
            timestamp=datetime.utcnow(),
            vulnerabilities_total=127,
            vulnerabilities_by_severity={
                "critical": 8,
                "high": 23,
                "medium": 45,
                "low": 51
            },
            mean_time_to_detect=2.5,  # hours
            mean_time_to_respond=4.2,  # hours
            mean_time_to_remediate=18.7,  # hours
            security_posture_score=78.5,  # 0-100
            compliance_score=85.2,  # 0-100
            threat_intel_indicators=1543,
            incidents_total=45,
            incidents_resolved=38,
            false_positive_rate=0.12  # 12%
        )

        self.metrics_history.append(metrics)
        self.statistics["metrics_collected"] += 1

        # Update averages
        self._update_statistics()

        return metrics

    def _update_statistics(self):
        """Update dashboard statistics."""
        if not self.metrics_history:
            return

        # Calculate averages
        total_posture = sum(m.security_posture_score for m in self.metrics_history)
        total_compliance = sum(m.compliance_score for m in self.metrics_history)

        self.statistics["average_posture_score"] = total_posture / len(self.metrics_history)
        self.statistics["average_compliance_score"] = total_compliance / len(self.metrics_history)

        # Determine trend
        if len(self.metrics_history) >= 2:
            recent = self.metrics_history[-1].security_posture_score
            previous = self.metrics_history[-2].security_posture_score

            if recent > previous + 5:
                self.statistics["trend"] = "improving"
            elif recent < previous - 5:
                self.statistics["trend"] = "declining"
            else:
                self.statistics["trend"] = "stable"

    async def generate_executive_report(self) -> Dict[str, Any]:
        """
        Generate executive security report.

        Returns:
            Executive report
        """
        logger.info("Generating executive security report")

        if not self.metrics_history:
            await self.collect_metrics()

        latest = self.metrics_history[-1]

        # Calculate key metrics
        resolution_rate = (latest.incidents_resolved / latest.incidents_total * 100) if latest.incidents_total > 0 else 0

        report = {
            "report_id": f"exec-report-{hashlib.md5(str(datetime.utcnow()).encode()).hexdigest()[:12]}",
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "security_posture_score": latest.security_posture_score,
                "compliance_score": latest.compliance_score,
                "trend": self.statistics["trend"],
                "risk_level": self._calculate_risk_level(latest.security_posture_score)
            },
            "vulnerabilities": {
                "total": latest.vulnerabilities_total,
                "by_severity": latest.vulnerabilities_by_severity,
                "critical_attention_required": latest.vulnerabilities_by_severity.get("critical", 0)
            },
            "incident_response": {
                "total_incidents": latest.incidents_total,
                "resolved_incidents": latest.incidents_resolved,
                "resolution_rate": f"{resolution_rate:.1f}%",
                "mean_time_to_detect": f"{latest.mean_time_to_detect:.1f}h",
                "mean_time_to_respond": f"{latest.mean_time_to_respond:.1f}h",
                "mean_time_to_remediate": f"{latest.mean_time_to_remediate:.1f}h"
            },
            "threat_intelligence": {
                "indicators_tracked": latest.threat_intel_indicators,
                "false_positive_rate": f"{latest.false_positive_rate * 100:.1f}%"
            },
            "recommendations": self._generate_recommendations(latest)
        }

        return report

    def _calculate_risk_level(self, posture_score: float) -> str:
        """Calculate overall risk level."""
        if posture_score >= 90:
            return "LOW"
        elif posture_score >= 75:
            return "MEDIUM"
        elif posture_score >= 60:
            return "HIGH"
        else:
            return "CRITICAL"

    def _generate_recommendations(self, metrics: SecurityMetrics) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        if metrics.vulnerabilities_by_severity.get("critical", 0) > 5:
            recommendations.append("Prioritize remediation of critical vulnerabilities")

        if metrics.mean_time_to_remediate > 24:
            recommendations.append("Improve remediation processes to reduce MTTR")

        if metrics.false_positive_rate > 0.15:
            recommendations.append("Tune detection rules to reduce false positive rate")

        if metrics.compliance_score < 80:
            recommendations.append("Address compliance gaps to meet regulatory requirements")

        if metrics.security_posture_score < 70:
            recommendations.append("Implement comprehensive security improvements")

        return recommendations

    def get_statistics(self) -> Dict[str, Any]:
        """Get dashboard statistics."""
        return self.statistics.copy()


# Singleton instance
_metrics_dashboard = None

def get_metrics_dashboard() -> SecurityMetricsDashboard:
    """Get the global security metrics dashboard instance."""
    global _metrics_dashboard
    if _metrics_dashboard is None:
        _metrics_dashboard = SecurityMetricsDashboard()
    return _metrics_dashboard


# ============================================================================
# Automated Penetration Testing
# ============================================================================

class AutomatedPentesting:
    """
    Automated penetration testing for continuous security validation.

    Performs automated security testing across multiple attack vectors.
    """

    def __init__(self):
        self.test_results: List[PentestResult] = []
        self.statistics = {
            "tests_executed": 0,
            "vulnerabilities_found": 0,
            "critical_findings": 0,
            "high_findings": 0
        }

    async def execute_pentest(
        self,
        test_type: PentestType,
        target: str,
        scope: Dict[str, Any]
    ) -> PentestResult:
        """
        Execute automated penetration test.

        Args:
            test_type: Type of penetration test
            target: Target system or application
            scope: Test scope and parameters

        Returns:
            Penetration test results
        """
        logger.info(f"Executing {test_type.value} pentest on {target}")

        start_time = datetime.utcnow()

        # Simulate pentest execution
        result = await self._run_pentest(test_type, target, scope)

        duration = (datetime.utcnow() - start_time).total_seconds()
        result.duration_seconds = duration

        self.test_results.append(result)
        self.statistics["tests_executed"] += 1
        self.statistics["vulnerabilities_found"] += result.vulnerabilities_found
        self.statistics["critical_findings"] += len(result.critical_findings)
        self.statistics["high_findings"] += len(result.high_findings)

        return result

    async def _run_pentest(
        self,
        test_type: PentestType,
        target: str,
        scope: Dict[str, Any]
    ) -> PentestResult:
        """Run specific type of penetration test."""

        # Different test types have different finding patterns
        test_patterns = {
            PentestType.NETWORK: {
                "critical": ["Open SMB shares with sensitive data", "Unpatched RDP service"],
                "high": ["Weak SSH configuration", "Open database ports", "Missing firewall rules"],
                "medium": ["Outdated SSL/TLS versions", "Unnecessary open ports", "Weak SNMP community strings"],
                "low": ["Banner disclosure", "DNS zone transfer enabled"]
            },
            PentestType.WEB_APPLICATION: {
                "critical": ["SQL injection in login form", "Remote code execution via file upload"],
                "high": ["XSS in user comments", "CSRF on password change", "Authentication bypass"],
                "medium": ["Missing security headers", "Insecure session management", "Information disclosure"],
                "low": ["Verbose error messages", "Missing HTTPS on non-sensitive pages"]
            },
            PentestType.API: {
                "critical": ["Broken authentication", "Mass assignment vulnerability"],
                "high": ["Broken object level authorization", "Excessive data exposure", "Rate limiting bypass"],
                "medium": ["Security misconfiguration", "Insufficient logging"],
                "low": ["API versioning issues", "Missing input validation"]
            },
            PentestType.MOBILE: {
                "critical": ["Hardcoded API keys", "Insecure data storage"],
                "high": ["Weak encryption", "Certificate pinning bypass", "Insecure communication"],
                "medium": ["Code obfuscation missing", "Debuggable application"],
                "low": ["Excessive permissions", "Outdated libraries"]
            },
            PentestType.CLOUD: {
                "critical": ["Public S3 buckets with sensitive data", "Overly permissive IAM roles"],
                "high": ["Missing encryption at rest", "Weak network segmentation", "Exposed management interfaces"],
                "medium": ["Missing CloudTrail logging", "Inadequate backup policies"],
                "low": ["Missing resource tags", "Unused security groups"]
            },
            PentestType.SOCIAL_ENGINEERING: {
                "critical": ["Successful credential harvesting", "Malware execution"],
                "high": ["Phishing email click-through", "Unauthorized physical access"],
                "medium": ["Information disclosure via phone", "Tailgating success"],
                "low": ["Weak security awareness", "Improper badge handling"]
            }
        }

        pattern = test_patterns.get(test_type, {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        })

        # Calculate risk score
        risk_score = (
            len(pattern["critical"]) * 2.5 +
            len(pattern["high"]) * 1.5 +
            len(pattern["medium"]) * 0.5 +
            len(pattern["low"]) * 0.1
        )

        # Generate recommendations
        recommendations = self._generate_pentest_recommendations(test_type, pattern)

        return PentestResult(
            test_id=f"pentest-{hashlib.md5(f'{target}{test_type.value}{datetime.utcnow()}'.encode()).hexdigest()[:12]}",
            test_type=test_type,
            target=target,
            vulnerabilities_found=sum(len(findings) for findings in pattern.values()),
            critical_findings=pattern["critical"],
            high_findings=pattern["high"],
            medium_findings=pattern["medium"],
            low_findings=pattern["low"],
            risk_score=min(risk_score, 10.0),
            recommendations=recommendations
        )

    def _generate_pentest_recommendations(
        self,
        test_type: PentestType,
        findings: Dict[str, List[str]]
    ) -> List[str]:
        """Generate recommendations based on pentest findings."""
        recommendations = []

        if findings["critical"]:
            recommendations.append(f"URGENT: Address {len(findings['critical'])} critical findings immediately")

        if test_type == PentestType.NETWORK:
            recommendations.extend([
                "Implement network segmentation",
                "Deploy intrusion detection systems",
                "Enforce strong firewall policies"
            ])
        elif test_type == PentestType.WEB_APPLICATION:
            recommendations.extend([
                "Implement input validation and sanitization",
                "Deploy Web Application Firewall (WAF)",
                "Conduct regular security code reviews"
            ])
        elif test_type == PentestType.API:
            recommendations.extend([
                "Implement OAuth 2.0 with proper scopes",
                "Deploy API gateway with rate limiting",
                "Enable comprehensive API logging"
            ])
        elif test_type == PentestType.CLOUD:
            recommendations.extend([
                "Implement least privilege access",
                "Enable encryption for all data at rest",
                "Deploy Cloud Security Posture Management (CSPM)"
            ])

        return recommendations

    def get_statistics(self) -> Dict[str, Any]:
        """Get penetration testing statistics."""
        return self.statistics.copy()


# Singleton instance
_automated_pentesting = None

def get_automated_pentesting() -> AutomatedPentesting:
    """Get the global automated pentesting instance."""
    global _automated_pentesting
    if _automated_pentesting is None:
        _automated_pentesting = AutomatedPentesting()
    return _automated_pentesting


# ============================================================================
# DevSecOps Orchestrator
# ============================================================================

class DevSecOpsOrchestrator:
    """
    Unified orchestrator for all DevSecOps and security operations.

    Coordinates DevSecOps pipelines, security orchestration, threat intelligence,
    metrics, and penetration testing.
    """

    def __init__(self):
        self.pipeline = get_devsecops_pipeline()
        self.orchestration = get_orchestration_hub()
        self.threat_intel = get_threat_intelligence()
        self.metrics = get_metrics_dashboard()
        self.pentesting = get_automated_pentesting()

    async def perform_full_security_assessment(
        self,
        target: str,
        assessment_type: str = "comprehensive"
    ) -> Dict[str, Any]:
        """
        Perform comprehensive security assessment.

        Args:
            target: Target system or application
            assessment_type: Type of assessment (quick, standard, comprehensive)

        Returns:
            Complete assessment results
        """
        logger.info(f"Performing {assessment_type} security assessment on {target}")

        start_time = datetime.utcnow()

        # Collect security metrics
        metrics = await self.metrics.collect_metrics()

        # Execute penetration tests
        pentest_results = []
        if assessment_type in ["standard", "comprehensive"]:
            for test_type in [PentestType.NETWORK, PentestType.WEB_APPLICATION, PentestType.API]:
                result = await self.pentesting.execute_pentest(test_type, target, {})
                pentest_results.append(result)

        # Generate executive report
        exec_report = await self.metrics.generate_executive_report()

        duration = (datetime.utcnow() - start_time).total_seconds()

        return {
            "assessment_id": f"assessment-{hashlib.md5(f'{target}{start_time}'.encode()).hexdigest()[:12]}",
            "target": target,
            "assessment_type": assessment_type,
            "timestamp": start_time.isoformat(),
            "duration_seconds": duration,
            "security_metrics": {
                "posture_score": metrics.security_posture_score,
                "compliance_score": metrics.compliance_score,
                "vulnerabilities_total": metrics.vulnerabilities_total,
                "by_severity": metrics.vulnerabilities_by_severity
            },
            "penetration_testing": {
                "tests_executed": len(pentest_results),
                "total_vulnerabilities": sum(r.vulnerabilities_found for r in pentest_results),
                "critical_findings": sum(len(r.critical_findings) for r in pentest_results),
                "high_findings": sum(len(r.high_findings) for r in pentest_results),
                "results": [
                    {
                        "test_type": r.test_type.value,
                        "vulnerabilities": r.vulnerabilities_found,
                        "risk_score": r.risk_score
                    }
                    for r in pentest_results
                ]
            },
            "executive_report": exec_report,
            "overall_risk_level": exec_report["summary"]["risk_level"]
        }

    def get_comprehensive_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics across all modules."""
        return {
            "devsecops_pipeline": self.pipeline.get_statistics(),
            "security_orchestration": self.orchestration.get_statistics(),
            "threat_intelligence": self.threat_intel.get_statistics(),
            "security_metrics": self.metrics.get_statistics(),
            "automated_pentesting": self.pentesting.get_statistics()
        }


# Singleton instance
_devsecops_orchestrator = None

def get_devsecops_orchestrator() -> DevSecOpsOrchestrator:
    """Get the global DevSecOps orchestrator instance."""
    global _devsecops_orchestrator
    if _devsecops_orchestrator is None:
        _devsecops_orchestrator = DevSecOpsOrchestrator()
    return _devsecops_orchestrator

