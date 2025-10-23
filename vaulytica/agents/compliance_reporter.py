"""
Compliance Reporter for Vaulytica AI Agent Framework

Generates compliance reports for:
- GDPR (General Data Protection Regulation)
- HIPAA (Health Insurance Portability and Accountability Act)
- PCI-DSS (Payment Card Industry Data Security Standard)
- SOC 2 (Service Organization Control 2)
- ISO 27001
- NIST Cybersecurity Framework

Includes breach notification templates and regulatory guidance.

Version: 0.31.0
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class RegulationType(str, Enum):
    """Types of regulations"""
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_cs"
    CCPA = "ccpa"


class DataType(str, Enum):
    """Types of sensitive data"""
    PII = "pii"  # Personally Identifiable Information
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Information
    FINANCIAL = "financial"
    CONFIDENTIAL = "confidential"


@dataclass
class ComplianceRequirement:
    """Compliance requirement"""
    regulation: RegulationType
    requirement_id: str
    title: str
    description: str
    applicable: bool
    met: bool
    evidence: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)


@dataclass
class BreachNotification:
    """Breach notification template"""
    regulation: RegulationType
    notification_required: bool
    notification_deadline: Optional[datetime]
    notification_recipients: List[str]
    template: str
    regulatory_guidance: str


@dataclass
class ComplianceReport:
    """Compliance report"""
    report_id: str
    incident_id: str
    regulation: RegulationType
    generated_at: datetime
    incident_summary: str
    data_types_affected: List[DataType]
    requirements: List[ComplianceRequirement]
    breach_notification: Optional[BreachNotification]
    recommendations: List[str]
    regulatory_contacts: Dict[str, str]


class ComplianceReporter:
    """
    Generates compliance reports for security incidents.

    Analyzes incidents against regulatory requirements and generates:
    - Compliance assessment reports
    - Breach notification templates
    - Regulatory guidance
    - Remediation recommendations
    """

    def __init__(self):
        logger.info("ComplianceReporter initialized")

    def generate_compliance_report(
        self,
        incident_data: Dict[str, Any],
        regulation: RegulationType
    ) -> ComplianceReport:
        """
        Generate compliance report for an incident.

        Args:
            incident_data: Incident data
            regulation: Regulation to assess against

        Returns:
            ComplianceReport
        """
        incident_id = incident_data.get("incident_id", "unknown")

        # Identify affected data types
        data_types = self._identify_data_types(incident_data)

        # Assess compliance requirements
        requirements = self._assess_requirements(incident_data, regulation)

        # Determine if breach notification is required
        breach_notification = self._generate_breach_notification(
            incident_data, regulation, data_types
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            incident_data, regulation, requirements
        )

        # Get regulatory contacts
        contacts = self._get_regulatory_contacts(regulation)

        report = ComplianceReport(
            report_id=f"compliance-{incident_id}-{regulation.value}",
            incident_id=incident_id,
            regulation=regulation,
            generated_at=datetime.utcnow(),
            incident_summary=self._generate_incident_summary(incident_data),
            data_types_affected=data_types,
            requirements=requirements,
            breach_notification=breach_notification,
            recommendations=recommendations,
            regulatory_contacts=contacts
        )

        logger.info(f"Generated {regulation.value.upper()} compliance report for {incident_id}")
        return report

    def _identify_data_types(self, incident_data: Dict[str, Any]) -> List[DataType]:
        """Identify types of sensitive data affected"""
        data_types = []

        # Analyze incident description and findings
        incident_text = str(incident_data).lower()

        if any(term in incident_text for term in ['personal', 'pii', 'name', 'email', 'address']):
            data_types.append(DataType.PII)

        if any(term in incident_text for term in ['health', 'medical', 'phi', 'patient']):
            data_types.append(DataType.PHI)

        if any(term in incident_text for term in ['credit card', 'payment', 'pci', 'cardholder']):
            data_types.append(DataType.PCI)

        if any(term in incident_text for term in ['financial', 'bank', 'account']):
            data_types.append(DataType.FINANCIAL)

        return data_types

    def _assess_requirements(
        self,
        incident_data: Dict[str, Any],
        regulation: RegulationType
    ) -> List[ComplianceRequirement]:
        """Assess compliance requirements"""
        if regulation == RegulationType.GDPR:
            return self._assess_gdpr_requirements(incident_data)
        elif regulation == RegulationType.HIPAA:
            return self._assess_hipaa_requirements(incident_data)
        elif regulation == RegulationType.PCI_DSS:
            return self._assess_pci_dss_requirements(incident_data)
        else:
            return []

    def _assess_gdpr_requirements(
        self,
        incident_data: Dict[str, Any]
    ) -> List[ComplianceRequirement]:
        """Assess GDPR requirements"""
        requirements = []

        # Article 33: Notification of a personal data breach to the supervisory authority
        requirements.append(ComplianceRequirement(
            regulation=RegulationType.GDPR,
            requirement_id="Article 33",
            title="Breach Notification to Supervisory Authority",
            description="Notify supervisory authority within 72 hours of becoming aware of breach",
            applicable=True,
            met=False,  # To be determined
            evidence=[],
            gaps=["Notification timeline to be confirmed"]
        ))

        # Article 34: Communication of a personal data breach to the data subject
        requirements.append(ComplianceRequirement(
            regulation=RegulationType.GDPR,
            requirement_id="Article 34",
            title="Breach Notification to Data Subjects",
            description="Notify affected individuals without undue delay if high risk",
            applicable=True,
            met=False,
            evidence=[],
            gaps=["Risk assessment pending", "Notification template needed"]
        ))

        # Article 32: Security of processing
        requirements.append(ComplianceRequirement(
            regulation=RegulationType.GDPR,
            requirement_id="Article 32",
            title="Security of Processing",
            description="Implement appropriate technical and organizational measures",
            applicable=True,
            met=False,
            evidence=[],
            gaps=["Security controls to be reviewed"]
        ))

        return requirements

    def _assess_hipaa_requirements(
        self,
        incident_data: Dict[str, Any]
    ) -> List[ComplianceRequirement]:
        """Assess HIPAA requirements"""
        requirements = []

        # Security Rule - Access Controls
        requirements.append(ComplianceRequirement(
            regulation=RegulationType.HIPAA,
            requirement_id="164.312(a)(1)",
            title="Access Control",
            description="Implement technical policies and procedures for access to ePHI",
            applicable=True,
            met=False,
            evidence=[],
            gaps=["Access control review needed"]
        ))

        # Breach Notification Rule
        requirements.append(ComplianceRequirement(
            regulation=RegulationType.HIPAA,
            requirement_id="164.404",
            title="Breach Notification to Individuals",
            description="Notify affected individuals within 60 days",
            applicable=True,
            met=False,
            evidence=[],
            gaps=["Notification timeline to be confirmed"]
        ))

        # Security Incident Procedures
        requirements.append(ComplianceRequirement(
            regulation=RegulationType.HIPAA,
            requirement_id="164.308(a)(6)",
            title="Security Incident Procedures",
            description="Implement policies and procedures to address security incidents",
            applicable=True,
            met=False,
            evidence=[],
            gaps=["Incident response procedures to be documented"]
        ))

        return requirements

    def _assess_pci_dss_requirements(
        self,
        incident_data: Dict[str, Any]
    ) -> List[ComplianceRequirement]:
        """Assess PCI-DSS requirements"""
        requirements = []

        # Requirement 10: Track and monitor all access to network resources and cardholder data
        requirements.append(ComplianceRequirement(
            regulation=RegulationType.PCI_DSS,
            requirement_id="Requirement 10",
            title="Track and Monitor Access",
            description="Implement audit trails for all access to cardholder data",
            applicable=True,
            met=False,
            evidence=[],
            gaps=["Audit trail review needed"]
        ))

        # Requirement 12.10: Implement an incident response plan
        requirements.append(ComplianceRequirement(
            regulation=RegulationType.PCI_DSS,
            requirement_id="Requirement 12.10",
            title="Incident Response Plan",
            description="Create and implement incident response plan",
            applicable=True,
            met=False,
            evidence=[],
            gaps=["IR plan execution to be documented"]
        ))

        return requirements

    def _generate_breach_notification(
        self,
        incident_data: Dict[str, Any],
        regulation: RegulationType,
        data_types: List[DataType]
    ) -> Optional[BreachNotification]:
        """Generate breach notification template"""
        if regulation == RegulationType.GDPR:
            return self._generate_gdpr_notification(incident_data, data_types)
        elif regulation == RegulationType.HIPAA:
            return self._generate_hipaa_notification(incident_data, data_types)
        elif regulation == RegulationType.PCI_DSS:
            return self._generate_pci_notification(incident_data, data_types)
        return None

    def _generate_gdpr_notification(
        self,
        incident_data: Dict[str, Any],
        data_types: List[DataType]
    ) -> BreachNotification:
        """Generate GDPR breach notification"""
        # GDPR requires notification within 72 hours
        notification_deadline = datetime.utcnow() + timedelta(hours=72)

        template = """
GDPR Data Breach Notification

Incident ID: {incident_data.get('incident_id', 'N/A')}
Date of Breach: {datetime.utcnow().strftime('%Y-%m-%d')}

1. Nature of the Personal Data Breach:
   {self._generate_incident_summary(incident_data)}

2. Categories and Approximate Number of Data Subjects Concerned:
   [To be determined based on investigation]

3. Categories and Approximate Number of Personal Data Records Concerned:
   Data Types: {', '.join([dt.value for dt in data_types])}

4. Likely Consequences of the Breach:
   [To be assessed]

5. Measures Taken or Proposed to Address the Breach:
   [To be documented]

6. Contact Point:
   Data Protection Officer
   [Contact details]
"""

        return BreachNotification(
            regulation=RegulationType.GDPR,
            notification_required=True,
            notification_deadline=notification_deadline,
            notification_recipients=["Supervisory Authority", "Affected Data Subjects"],
            template=template,
            regulatory_guidance="Notify supervisory authority within 72 hours per GDPR Article 33"
        )

    def _generate_hipaa_notification(
        self,
        incident_data: Dict[str, Any],
        data_types: List[DataType]
    ) -> BreachNotification:
        """Generate HIPAA breach notification"""
        # HIPAA requires notification within 60 days
        notification_deadline = datetime.utcnow() + timedelta(days=60)

        template = """
HIPAA Breach Notification

Incident ID: {incident_data.get('incident_id', 'N/A')}
Date of Discovery: {datetime.utcnow().strftime('%Y-%m-%d')}

1. Brief Description of the Breach:
   {self._generate_incident_summary(incident_data)}

2. Types of Unsecured Protected Health Information Involved:
   {', '.join([dt.value for dt in data_types if dt == DataType.PHI])}

3. Steps Individuals Should Take to Protect Themselves:
   - Monitor accounts for suspicious activity
   - Review explanation of benefits statements
   - Contact us with questions or concerns

4. What We Are Doing to Investigate and Mitigate:
   [Investigation and remediation steps]

5. Contact Information:
   Privacy Officer
   [Contact details]
"""

        return BreachNotification(
            regulation=RegulationType.HIPAA,
            notification_required=True,
            notification_deadline=notification_deadline,
            notification_recipients=["Affected Individuals", "HHS Secretary", "Media (if >500 affected)"],
            template=template,
            regulatory_guidance="Notify affected individuals within 60 days per HIPAA Breach Notification Rule"
        )

    def _generate_pci_notification(
        self,
        incident_data: Dict[str, Any],
        data_types: List[DataType]
    ) -> BreachNotification:
        """Generate PCI-DSS breach notification"""
        # PCI-DSS requires immediate notification
        notification_deadline = datetime.utcnow() + timedelta(hours=24)

        template = """
PCI-DSS Security Incident Notification

Incident ID: {incident_data.get('incident_id', 'N/A')}
Date of Incident: {datetime.utcnow().strftime('%Y-%m-%d')}

1. Description of Incident:
   {self._generate_incident_summary(incident_data)}

2. Cardholder Data Potentially Compromised:
   [To be determined]

3. Immediate Actions Taken:
   [Containment and remediation steps]

4. Forensic Investigation Status:
   [Investigation status]

5. Contact Information:
   Security Officer
   [Contact details]
"""

        return BreachNotification(
            regulation=RegulationType.PCI_DSS,
            notification_required=True,
            notification_deadline=notification_deadline,
            notification_recipients=["Payment Brands", "Acquiring Bank", "Card Associations"],
            template=template,
            regulatory_guidance="Notify payment brands and acquiring bank immediately per PCI-DSS Requirement 12.10"
        )

    def _generate_recommendations(
        self,
        incident_data: Dict[str, Any],
        regulation: RegulationType,
        requirements: List[ComplianceRequirement]
    ) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []

        # General recommendations
        recommendations.append("Document all incident response activities with timestamps")
        recommendations.append("Preserve evidence for regulatory review")
        recommendations.append("Engage legal counsel for regulatory guidance")

        # Regulation-specific recommendations
        if regulation == RegulationType.GDPR:
            recommendations.append("Notify Data Protection Officer immediately")
            recommendations.append("Prepare notification to supervisory authority within 72 hours")
            recommendations.append("Assess risk to data subjects to determine notification requirements")
            recommendations.append("Document breach in Article 33 register")

        elif regulation == RegulationType.HIPAA:
            recommendations.append("Notify Privacy Officer and Security Officer")
            recommendations.append("Conduct risk assessment per HIPAA Breach Notification Rule")
            recommendations.append("Prepare notifications to affected individuals within 60 days")
            recommendations.append("Report to HHS Secretary if breach affects 500+ individuals")

        elif regulation == RegulationType.PCI_DSS:
            recommendations.append("Notify payment brands and acquiring bank immediately")
            recommendations.append("Engage PCI Forensic Investigator (PFI)")
            recommendations.append("Prepare for potential re-validation of PCI-DSS compliance")
            recommendations.append("Review and update incident response plan per Requirement 12.10")

        # Add recommendations based on gaps
        for req in requirements:
            if req.gaps:
                recommendations.extend([f"{req.requirement_id}: {gap}" for gap in req.gaps])

        return recommendations

    def _generate_incident_summary(self, incident_data: Dict[str, Any]) -> str:
        """Generate incident summary for compliance report"""
        incident_metadata = incident_data.get("incident_metadata", {})

        summary = """
Incident Type: {incident_metadata.get('classification', 'Unknown')}
Severity: {incident_metadata.get('severity', 'Unknown')}
Detection Time: {incident_metadata.get('detection_time', 'Unknown')}
Containment Time: {incident_metadata.get('containment_time', 'Unknown')}

Root Cause: {incident_metadata.get('root_cause', {}).get('primary_cause', 'Under investigation')}

Impact: {incident_metadata.get('impact', {}).get('systems_compromised', 0)} systems affected

Current Status: {incident_metadata.get('status', 'Under investigation')}
"""
        return summary.strip()

    def _get_regulatory_contacts(self, regulation: RegulationType) -> Dict[str, str]:
        """Get regulatory contact information"""
        contacts = {}

        if regulation == RegulationType.GDPR:
            contacts = {
                "Supervisory Authority": "Contact your local Data Protection Authority",
                "EU Commission": "https://example.com",
                "EDPB": "https://example.com"
            }

        elif regulation == RegulationType.HIPAA:
            contacts = {
                "HHS Office for Civil Rights": "https://example.com",
                "Breach Portal": "https://example.com",
                "OCR Hotline": "1-800-368-1019"
            }

        elif regulation == RegulationType.PCI_DSS:
            contacts = {
                "PCI Security Standards Council": "https://example.com",
                "Acquiring Bank": "Contact your acquiring bank immediately",
                "Payment Brands": "Notify Visa, Mastercard, Amex, etc."
            }

        return contacts


# Global singleton instance
_compliance_reporter: Optional[ComplianceReporter] = None


def get_compliance_reporter() -> ComplianceReporter:
    """Get the global compliance reporter instance"""
    global _compliance_reporter
    if _compliance_reporter is None:
        _compliance_reporter = ComplianceReporter()
    return _compliance_reporter
