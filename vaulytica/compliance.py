import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict
import json

from vaulytica.models import SecurityEvent
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    SOC2 = "SOC2"
    ISO27001 = "ISO27001"
    NIST_CSF = "NIST_CSF"
    NIST_800_53 = "NIST_800_53"
    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    CIS_CONTROLS = "CIS_CONTROLS"
    CMMC = "CMMC"


class ControlStatus(str, Enum):
    """Control implementation status."""
    IMPLEMENTED = "IMPLEMENTED"
    PARTIALLY_IMPLEMENTED = "PARTIALLY_IMPLEMENTED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    IN_PROGRESS = "IN_PROGRESS"


class ComplianceStatus(str, Enum):
    """Overall compliance status."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    UNDER_REVIEW = "UNDER_REVIEW"


class AuditType(str, Enum):
    """Types of audits."""
    INTERNAL = "INTERNAL"
    EXTERNAL = "EXTERNAL"
    THIRD_PARTY = "THIRD_PARTY"
    REGULATORY = "REGULATORY"
    CONTINUOUS = "CONTINUOUS"


@dataclass
class Control:
    """Represents a security control."""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: str
    status: ControlStatus
    implementation_details: str = ""
    evidence: List[str] = field(default_factory=list)
    last_assessed: Optional[datetime] = None
    next_assessment: Optional[datetime] = None
    owner: Optional[str] = None
    compliance_score: float = 0.0  # 0.0-1.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "framework": self.framework.value,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "status": self.status.value,
            "implementation_details": self.implementation_details,
            "evidence_count": len(self.evidence),
            "last_assessed": self.last_assessed.isoformat() if self.last_assessed else None,
            "next_assessment": self.next_assessment.isoformat() if self.next_assessment else None,
            "owner": self.owner,
            "compliance_score": self.compliance_score
        }


@dataclass
class ComplianceAssessment:
    """Represents a compliance assessment."""
    assessment_id: str
    framework: ComplianceFramework
    status: ComplianceStatus
    controls_assessed: int
    controls_compliant: int
    controls_non_compliant: int
    overall_score: float  # 0.0-1.0
    gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    assessed_at: datetime = field(default_factory=datetime.utcnow)
    assessed_by: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "framework": self.framework.value,
            "status": self.status.value,
            "controls_assessed": self.controls_assessed,
            "controls_compliant": self.controls_compliant,
            "controls_non_compliant": self.controls_non_compliant,
            "overall_score": self.overall_score,
            "gaps_count": len(self.gaps),
            "recommendations_count": len(self.recommendations),
            "assessed_at": self.assessed_at.isoformat(),
            "assessed_by": self.assessed_by
        }


@dataclass
class AuditLog:
    """Represents an audit log entry."""
    log_id: str
    timestamp: datetime
    user: str
    action: str
    resource: str
    result: str
    details: Dict[str, Any]
    ip_address: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": self.log_id,
            "timestamp": self.timestamp.isoformat(),
            "user": self.user,
            "action": self.action,
            "resource": self.resource,
            "result": self.result,
            "details": self.details,
            "ip_address": self.ip_address
        }


class ComplianceEngine:
    """
    Compliance & Audit Engine.
    
    Provides automated compliance checking, control assessment,
    audit trail management, and compliance reporting.
    """
    
    def __init__(self):
        self.controls: Dict[str, Control] = {}
        self.assessments: Dict[str, ComplianceAssessment] = {}
        self.audit_logs: List[AuditLog] = []
        self.control_frameworks: Dict[ComplianceFramework, List[Control]] = self._initialize_frameworks()
        self.statistics = {
            "total_controls": 0,
            "controls_implemented": 0,
            "total_assessments": 0,
            "compliant_assessments": 0,
            "audit_logs_count": 0,
            "avg_compliance_score": 0.0
        }
        logger.info("Compliance Engine initialized")
    
    def _initialize_frameworks(self) -> Dict[ComplianceFramework, List[Control]]:
        """Initialize compliance framework controls."""
        frameworks = {}
        
        # SOC2 Controls
        frameworks[ComplianceFramework.SOC2] = [
            Control(
                control_id="CC6.1",
                framework=ComplianceFramework.SOC2,
                title="Logical and Physical Access Controls",
                description="The entity implements logical access security software, infrastructure, and architectures over protected information assets",
                category="Common Criteria",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.95
            ),
            Control(
                control_id="CC6.6",
                framework=ComplianceFramework.SOC2,
                title="Vulnerability Management",
                description="The entity identifies, reports, and acts upon detected security incidents",
                category="Common Criteria",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.90
            ),
            Control(
                control_id="CC7.2",
                framework=ComplianceFramework.SOC2,
                title="Security Incident Detection",
                description="The entity monitors system components and the operation of those components for anomalies",
                category="Common Criteria",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.92
            )
        ]
        
        # ISO 27001 Controls
        frameworks[ComplianceFramework.ISO27001] = [
            Control(
                control_id="A.9.1.1",
                framework=ComplianceFramework.ISO27001,
                title="Access Control Policy",
                description="An access control policy shall be established, documented and reviewed",
                category="Access Control",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.88
            ),
            Control(
                control_id="A.12.6.1",
                framework=ComplianceFramework.ISO27001,
                title="Management of Technical Vulnerabilities",
                description="Information about technical vulnerabilities shall be obtained in a timely fashion",
                category="Operations Security",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.85
            ),
            Control(
                control_id="A.16.1.1",
                framework=ComplianceFramework.ISO27001,
                title="Responsibilities and Procedures",
                description="Management responsibilities and procedures shall be established",
                category="Incident Management",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.90
            )
        ]
        
        # NIST CSF Controls
        frameworks[ComplianceFramework.NIST_CSF] = [
            Control(
                control_id="ID.AM-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Physical Devices and Systems",
                description="Physical devices and systems within the organization are inventoried",
                category="Identify",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.93
            ),
            Control(
                control_id="DE.CM-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Network Monitoring",
                description="The network is monitored to detect potential cybersecurity events",
                category="Detect",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.91
            ),
            Control(
                control_id="RS.AN-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Incident Analysis",
                description="Notifications from detection systems are investigated",
                category="Respond",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.89
            )
        ]
        
        # PCI-DSS Controls
        frameworks[ComplianceFramework.PCI_DSS] = [
            Control(
                control_id="REQ-1",
                framework=ComplianceFramework.PCI_DSS,
                title="Install and Maintain Firewall",
                description="Install and maintain a firewall configuration to protect cardholder data",
                category="Network Security",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.94
            ),
            Control(
                control_id="REQ-10",
                framework=ComplianceFramework.PCI_DSS,
                title="Track and Monitor Access",
                description="Track and monitor all access to network resources and cardholder data",
                category="Monitoring",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.92
            ),
            Control(
                control_id="REQ-11",
                framework=ComplianceFramework.PCI_DSS,
                title="Test Security Systems",
                description="Regularly test security systems and processes",
                category="Testing",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.87
            )
        ]
        
        # HIPAA Controls
        frameworks[ComplianceFramework.HIPAA] = [
            Control(
                control_id="164.308(a)(1)(ii)(D)",
                framework=ComplianceFramework.HIPAA,
                title="Information System Activity Review",
                description="Implement procedures to regularly review records of information system activity",
                category="Administrative Safeguards",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.90
            ),
            Control(
                control_id="164.312(b)",
                framework=ComplianceFramework.HIPAA,
                title="Audit Controls",
                description="Implement hardware, software, and/or procedural mechanisms that record and examine activity",
                category="Technical Safeguards",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.88
            )
        ]
        
        # GDPR Controls
        frameworks[ComplianceFramework.GDPR] = [
            Control(
                control_id="ART-32",
                framework=ComplianceFramework.GDPR,
                title="Security of Processing",
                description="Implement appropriate technical and organizational measures to ensure security",
                category="Security",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.86
            ),
            Control(
                control_id="ART-33",
                framework=ComplianceFramework.GDPR,
                title="Breach Notification",
                description="Notify supervisory authority of a personal data breach",
                category="Breach Management",
                status=ControlStatus.IMPLEMENTED,
                compliance_score=0.91
            )
        ]
        
        return frameworks
    
    async def assess_framework(
        self,
        framework: ComplianceFramework,
        assessed_by: Optional[str] = None
    ) -> ComplianceAssessment:
        """Perform a compliance assessment for a framework."""
        controls = self.control_frameworks.get(framework, [])
        
        controls_assessed = len(controls)
        controls_compliant = sum(1 for c in controls if c.status == ControlStatus.IMPLEMENTED)
        controls_non_compliant = sum(1 for c in controls if c.status in [
            ControlStatus.NOT_IMPLEMENTED,
            ControlStatus.PARTIALLY_IMPLEMENTED
        ])
        
        overall_score = sum(c.compliance_score for c in controls) / len(controls) if controls else 0.0
        
        # Determine status
        if overall_score >= 0.95:
            status = ComplianceStatus.COMPLIANT
        elif overall_score >= 0.70:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        # Identify gaps
        gaps = [
            f"{c.control_id}: {c.title}"
            for c in controls
            if c.status != ControlStatus.IMPLEMENTED
        ]
        
        # Generate recommendations
        recommendations = [
            f"Implement control {c.control_id}: {c.title}"
            for c in controls
            if c.status == ControlStatus.NOT_IMPLEMENTED
        ]
        
        assessment_id = f"ASSESS-{framework.value}-{datetime.utcnow().strftime('%Y%m%d')}-{len(self.assessments) + 1:03d}"
        
        assessment = ComplianceAssessment(
            assessment_id=assessment_id,
            framework=framework,
            status=status,
            controls_assessed=controls_assessed,
            controls_compliant=controls_compliant,
            controls_non_compliant=controls_non_compliant,
            overall_score=overall_score,
            gaps=gaps,
            recommendations=recommendations,
            assessed_by=assessed_by
        )
        
        self.assessments[assessment_id] = assessment
        self.statistics["total_assessments"] += 1
        if status == ComplianceStatus.COMPLIANT:
            self.statistics["compliant_assessments"] += 1
        
        logger.info(f"Completed assessment {assessment_id} for {framework.value}: {status.value}")
        return assessment

    async def log_audit_event(
        self,
        user: str,
        action: str,
        resource: str,
        result: str,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None
    ) -> AuditLog:
        """Log an audit event."""
        log_id = f"AUDIT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{len(self.audit_logs) + 1:06d}"

        audit_log = AuditLog(
            log_id=log_id,
            timestamp=datetime.utcnow(),
            user=user,
            action=action,
            resource=resource,
            result=result,
            details=details or {},
            ip_address=ip_address
        )

        self.audit_logs.append(audit_log)
        self.statistics["audit_logs_count"] += 1

        return audit_log

    async def check_control_compliance(
        self,
        control_id: str,
        evidence: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Check compliance for a specific control."""
        if control_id not in self.controls:
            # Try to find in frameworks
            for framework_controls in self.control_frameworks.values():
                for control in framework_controls:
                    if control.control_id == control_id:
                        self.controls[control_id] = control
                        break

        if control_id not in self.controls:
            raise ValueError(f"Control {control_id} not found")

        control = self.controls[control_id]

        # Update evidence if provided
        if evidence:
            control.evidence.extend(evidence)

        # Assess control
        control.last_assessed = datetime.utcnow()
        control.next_assessment = datetime.utcnow() + timedelta(days=90)  # Quarterly

        # Calculate compliance score based on evidence and status
        if control.status == ControlStatus.IMPLEMENTED and len(control.evidence) >= 3:
            control.compliance_score = 0.95
        elif control.status == ControlStatus.IMPLEMENTED:
            control.compliance_score = 0.85
        elif control.status == ControlStatus.PARTIALLY_IMPLEMENTED:
            control.compliance_score = 0.60
        else:
            control.compliance_score = 0.30

        result = {
            "control_id": control_id,
            "status": control.status.value,
            "compliance_score": control.compliance_score,
            "evidence_count": len(control.evidence),
            "last_assessed": control.last_assessed.isoformat(),
            "next_assessment": control.next_assessment.isoformat()
        }

        logger.info(f"Checked control {control_id}: score={control.compliance_score:.2f}")
        return result

    async def generate_compliance_report(
        self,
        framework: ComplianceFramework,
        include_evidence: bool = False
    ) -> Dict[str, Any]:
        """Generate a comprehensive compliance report."""
        controls = self.control_frameworks.get(framework, [])

        # Get latest assessment
        framework_assessments = [
            a for a in self.assessments.values()
            if a.framework == framework
        ]
        latest_assessment = max(
            framework_assessments,
            key=lambda a: a.assessed_at
        ) if framework_assessments else None

        # Group controls by category
        controls_by_category = defaultdict(list)
        for control in controls:
            controls_by_category[control.category].append(control)

        # Calculate statistics
        total_controls = len(controls)
        implemented = sum(1 for c in controls if c.status == ControlStatus.IMPLEMENTED)
        partially_implemented = sum(1 for c in controls if c.status == ControlStatus.PARTIALLY_IMPLEMENTED)
        not_implemented = sum(1 for c in controls if c.status == ControlStatus.NOT_IMPLEMENTED)

        avg_score = sum(c.compliance_score for c in controls) / total_controls if total_controls else 0.0

        report = {
            "framework": framework.value,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_controls": total_controls,
                "implemented": implemented,
                "partially_implemented": partially_implemented,
                "not_implemented": not_implemented,
                "compliance_percentage": (implemented / total_controls * 100) if total_controls else 0,
                "average_score": avg_score
            },
            "latest_assessment": latest_assessment.to_dict() if latest_assessment else None,
            "controls_by_category": {
                category: [c.to_dict() for c in controls]
                for category, controls in controls_by_category.items()
            }
        }

        if include_evidence:
            report["evidence"] = {
                c.control_id: c.evidence
                for c in controls
                if c.evidence
            }

        logger.info(f"Generated compliance report for {framework.value}")
        return report

    async def identify_gaps(
        self,
        framework: ComplianceFramework
    ) -> List[Dict[str, Any]]:
        """Identify compliance gaps for a framework."""
        controls = self.control_frameworks.get(framework, [])

        gaps = []
        for control in controls:
            if control.status != ControlStatus.IMPLEMENTED:
                gap = {
                    "control_id": control.control_id,
                    "title": control.title,
                    "category": control.category,
                    "current_status": control.status.value,
                    "compliance_score": control.compliance_score,
                    "priority": "HIGH" if control.compliance_score < 0.5 else "MEDIUM",
                    "recommendation": f"Implement {control.title} to achieve compliance"
                }
                gaps.append(gap)

        # Sort by priority and score
        gaps.sort(key=lambda g: (g["priority"], g["compliance_score"]))

        logger.info(f"Identified {len(gaps)} gaps for {framework.value}")
        return gaps

    def get_audit_logs(
        self,
        user: Optional[str] = None,
        action: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000
    ) -> List[AuditLog]:
        """Retrieve audit logs with filtering."""
        logs = self.audit_logs

        if user:
            logs = [log for log in logs if log.user == user]
        if action:
            logs = [log for log in logs if log.action == action]
        if start_time:
            logs = [log for log in logs if log.timestamp >= start_time]
        if end_time:
            logs = [log for log in logs if log.timestamp <= end_time]

        # Sort by timestamp descending
        logs.sort(key=lambda log: log.timestamp, reverse=True)

        return logs[:limit]

    def get_assessment(self, assessment_id: str) -> Optional[ComplianceAssessment]:
        """Get an assessment by ID."""
        return self.assessments.get(assessment_id)

    def list_assessments(
        self,
        framework: Optional[ComplianceFramework] = None,
        status: Optional[ComplianceStatus] = None,
        limit: int = 100
    ) -> List[ComplianceAssessment]:
        """List assessments with optional filtering."""
        assessments = list(self.assessments.values())

        if framework:
            assessments = [a for a in assessments if a.framework == framework]
        if status:
            assessments = [a for a in assessments if a.status == status]

        assessments.sort(key=lambda a: a.assessed_at, reverse=True)
        return assessments[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get compliance engine statistics."""
        # Calculate average compliance score across all frameworks
        all_controls = []
        for controls in self.control_frameworks.values():
            all_controls.extend(controls)

        avg_score = sum(c.compliance_score for c in all_controls) / len(all_controls) if all_controls else 0.0

        return {
            **self.statistics,
            "avg_compliance_score": avg_score,
            "frameworks_count": len(self.control_frameworks),
            "assessments_by_framework": self._count_assessments_by_framework(),
            "controls_by_status": self._count_controls_by_status()
        }

    def _count_assessments_by_framework(self) -> Dict[str, int]:
        """Count assessments by framework."""
        counts = defaultdict(int)
        for assessment in self.assessments.values():
            counts[assessment.framework.value] += 1
        return dict(counts)

    def _count_controls_by_status(self) -> Dict[str, int]:
        """Count controls by status across all frameworks."""
        counts = defaultdict(int)
        for controls in self.control_frameworks.values():
            for control in controls:
                counts[control.status.value] += 1
        return dict(counts)


# Global instance
_compliance_engine: Optional[ComplianceEngine] = None


def get_compliance_engine() -> ComplianceEngine:
    """Get the global compliance engine instance."""
    global _compliance_engine
    if _compliance_engine is None:
        _compliance_engine = ComplianceEngine()
    return _compliance_engine
