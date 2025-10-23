"""
AI agents for security analysis and incident response.

Vaulytica Agent Framework - Modular AI agents for SOC operations.
"""

# Legacy base agent (for backward compatibility)
from .base import BaseAgent as LegacyBaseAgent

# Legacy security analyst (for backward compatibility)
from .security_analyst import SecurityAnalystAgent as LegacySecurityAnalystAgent
from .security_analyst import SecurityAnalystAgent  # Also export with original name

# New agent framework
from .framework import (
    BaseAgent,
    AgentCapability,
    AgentStatus,
    AgentPriority,
    AgentContext,
    AgentInput,
    AgentOutput,
    AgentMetadata,
    AgentRegistry,
    get_agent_registry
)

from .orchestrator import (
    AgentOrchestrator,
    WorkflowDefinition,
    WorkflowStep,
    WorkflowExecution,
    WorkflowStatus,
    ExecutionMode,
    get_orchestrator
)

# New agents
from .security_analysis import SecurityAnalysisAgent
from .incident_response import (
    IncidentResponseAgent,
    IncidentPhase,
    IncidentSeverity,
    IncidentMetrics,
    ImpactAssessment
)
from .vulnerability_management import (
    VulnerabilityManagementAgent,
    VulnerabilitySeverity,
    RemediationStatus,
    VulnerabilityFinding,
    DependencyPath,
    RemediationPlan
)
from .security_questionnaire import (
    SecurityQuestionnaireAgent,
    QuestionType,
    QuestionnaireStatus,
    Question,
    Answer,
    SourceCitation,
    Questionnaire,
    get_security_questionnaire_agent
)
from .brand_protection import (
    BrandProtectionAgent,
    ThreatLevel,
    TakedownStatus,
    PermutationTechnique,
    DomainPermutation,
    MaliciousIntentEvidence,
    ThreatValidation,
    CeaseAndDesist,
    TakedownTracking
)
from .detection_engineering import (
    DetectionEngineeringAgent,
    DetectionPlatform,
    AlertOutcome,
    TuningAction,
    DetectionStatus,
    DetectionRule,
    AlertInstance,
    FalsePositivePattern,
    TuningRecommendation,
    DetectionAnalysis,
    TestDetectionResult,
    DetectionGap,
    get_detection_engineering_agent
)

# Data ingestion
from .data_ingestion import (
    DataIngestionPipeline,
    DataSource,
    DataSourceType,
    IngestionJob,
    IngestionStatus,
    IngestedData,
    get_ingestion_pipeline
)

# Document intelligence (RAG)
from .document_intelligence import (
    DocumentIntelligence,
    Document,
    DocumentType,
    DocumentChunk,
    SearchResult,
    get_document_intelligence
)

# Threat intelligence extractor
from .threat_intel_extractor import (
    ThreatIntelExtractor,
    IOC,
    IOCType,
    DetectionRule,
    RuleType,
    DefenseRecommendation,
    get_threat_intel_extractor
)

# Compliance reporter
from .compliance_reporter import (
    ComplianceReporter,
    ComplianceReport,
    ComplianceRequirement,
    BreachNotification,
    RegulationType,
    DataType,
    get_compliance_reporter
)

__all__ = [
    # Legacy (backward compatibility)
    "LegacyBaseAgent",
    "LegacySecurityAnalystAgent",
    "SecurityAnalystAgent",  # Also export with original name

    # Framework core
    "BaseAgent",
    "AgentCapability",
    "AgentStatus",
    "AgentPriority",
    "AgentContext",
    "AgentInput",
    "AgentOutput",
    "AgentMetadata",
    "AgentRegistry",
    "get_agent_registry",

    # Orchestration
    "AgentOrchestrator",
    "WorkflowDefinition",
    "WorkflowStep",
    "WorkflowExecution",
    "WorkflowStatus",
    "ExecutionMode",
    "get_orchestrator",

    # Agents
    "SecurityAnalysisAgent",
    "IncidentResponseAgent",
    "IncidentPhase",
    "IncidentSeverity",
    "IncidentMetrics",
    "ImpactAssessment",
    "VulnerabilityManagementAgent",
    "VulnerabilitySeverity",
    "RemediationStatus",
    "VulnerabilityFinding",
    "DependencyPath",
    "RemediationPlan",
    "SecurityQuestionnaireAgent",
    "QuestionType",
    "QuestionnaireStatus",
    "Question",
    "Answer",
    "SourceCitation",
    "Questionnaire",
    "get_security_questionnaire_agent",
    "BrandProtectionAgent",
    "ThreatLevel",
    "TakedownStatus",
    "PermutationTechnique",
    "DomainPermutation",
    "MaliciousIntentEvidence",
    "ThreatValidation",
    "CeaseAndDesist",
    "TakedownTracking",
    "DetectionEngineeringAgent",
    "DetectionPlatform",
    "AlertOutcome",
    "TuningAction",
    "DetectionStatus",
    "DetectionRule",
    "AlertInstance",
    "FalsePositivePattern",
    "TuningRecommendation",
    "DetectionAnalysis",
    "TestDetectionResult",
    "DetectionGap",
    "get_detection_engineering_agent",

    # Data ingestion
    "DataIngestionPipeline",
    "DataSource",
    "DataSourceType",
    "IngestionJob",
    "IngestionStatus",
    "IngestedData",
    "get_ingestion_pipeline",

    # Document intelligence
    "DocumentIntelligence",
    "Document",
    "DocumentType",
    "DocumentChunk",
    "SearchResult",
    "get_document_intelligence",

    # Threat intelligence
    "ThreatIntelExtractor",
    "IOC",
    "IOCType",
    "DetectionRule",
    "RuleType",
    "DefenseRecommendation",
    "get_threat_intel_extractor",

    # Compliance
    "ComplianceReporter",
    "ComplianceReport",
    "ComplianceRequirement",
    "BreachNotification",
    "RegulationType",
    "DataType",
    "get_compliance_reporter",
]
