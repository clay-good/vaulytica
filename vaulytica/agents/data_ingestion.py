"""
Data Ingestion Pipeline for Vaulytica AI Agent Framework

Unified data ingestion system for:
- System and application logs
- Network device logs (firewalls, routers, switches)
- EDR logs (CrowdStrike, SentinelOne, Microsoft Defender)
- Cloud infrastructure logs (AWS CloudTrail, Azure Activity, GCP Audit)
- Threat intelligence feeds (IOCs, threat actors)
- Vulnerability data (CMDB, asset inventory)
- Documents (IR plans, historical incidents, SOPs, playbooks, runbooks, compliance)
- Communications (Teams, Slack, Email)
- Analyst notes and documentation

Version: 0.31.0
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)


class DataSourceType(str, Enum):
    """Types of data sources"""
    SYSTEM_LOGS = "system_logs"
    APPLICATION_LOGS = "application_logs"
    NETWORK_LOGS = "network_logs"
    EDR_LOGS = "edr_logs"
    CLOUD_LOGS = "cloud_logs"
    THREAT_INTEL = "threat_intel"
    VULNERABILITY_DATA = "vulnerability_data"
    DOCUMENTS = "documents"
    COMMUNICATIONS = "communications"
    ANALYST_NOTES = "analyst_notes"


class IngestionStatus(str, Enum):
    """Status of data ingestion"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass
class DataSource:
    """Configuration for a data source"""
    source_id: str
    source_name: str
    source_type: DataSourceType
    connection_config: Dict[str, Any]
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestionJob:
    """Data ingestion job"""
    job_id: str
    incident_id: str
    source_id: str
    source_type: DataSourceType
    status: IngestionStatus = IngestionStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    records_ingested: int = 0
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestedData:
    """Container for ingested data"""
    source_id: str
    source_type: DataSourceType
    data: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    ingestion_time: datetime = field(default_factory=datetime.utcnow)


class DataIngestionPipeline:
    """
    Unified data ingestion pipeline for all data sources.

    Supports:
    - Multiple data source types
    - Parallel ingestion
    - Error handling and retry
    - Data normalization
    - Metadata tracking
    """

    def __init__(self):
        self.sources: Dict[str, DataSource] = {}
        self.jobs: Dict[str, IngestionJob] = {}
        logger.info("DataIngestionPipeline initialized")

    def register_source(self, source: DataSource) -> None:
        """Register a data source"""
        self.sources[source.source_id] = source
        logger.info(f"Registered data source: {source.source_name} ({source.source_type})")

    def unregister_source(self, source_id: str) -> None:
        """Unregister a data source"""
        if source_id in self.sources:
            del self.sources[source_id]
            logger.info(f"Unregistered data source: {source_id}")

    async def ingest_from_source(
        self,
        incident_id: str,
        source_id: str,
        time_range: Optional[Dict[str, datetime]] = None,
        filters: Optional[Dict[str, Any]] = None
    ) -> IngestedData:
        """
        Ingest data from a specific source.

        Args:
            incident_id: Incident ID for tracking
            source_id: Source to ingest from
            time_range: Optional time range (start_time, end_time)
            filters: Optional filters to apply

        Returns:
            IngestedData with ingested records
        """
        if source_id not in self.sources:
            raise ValueError(f"Unknown source: {source_id}")

        source = self.sources[source_id]

        # Create ingestion job
        job = IngestionJob(
            job_id=f"job-{incident_id}-{source_id}-{datetime.utcnow().timestamp()}",
            incident_id=incident_id,
            source_id=source_id,
            source_type=source.source_type,
            status=IngestionStatus.IN_PROGRESS,
            start_time=datetime.utcnow()
        )
        self.jobs[job.job_id] = job

        try:
            # Route to appropriate ingestion handler
            if source.source_type == DataSourceType.SYSTEM_LOGS:
                data = await self._ingest_system_logs(source, time_range, filters)
            elif source.source_type == DataSourceType.APPLICATION_LOGS:
                data = await self._ingest_application_logs(source, time_range, filters)
            elif source.source_type == DataSourceType.NETWORK_LOGS:
                data = await self._ingest_network_logs(source, time_range, filters)
            elif source.source_type == DataSourceType.EDR_LOGS:
                data = await self._ingest_edr_logs(source, time_range, filters)
            elif source.source_type == DataSourceType.CLOUD_LOGS:
                data = await self._ingest_cloud_logs(source, time_range, filters)
            elif source.source_type == DataSourceType.THREAT_INTEL:
                data = await self._ingest_threat_intel(source, time_range, filters)
            elif source.source_type == DataSourceType.VULNERABILITY_DATA:
                data = await self._ingest_vulnerability_data(source, time_range, filters)
            elif source.source_type == DataSourceType.DOCUMENTS:
                data = await self._ingest_documents(source, time_range, filters)
            elif source.source_type == DataSourceType.COMMUNICATIONS:
                data = await self._ingest_communications(source, time_range, filters)
            elif source.source_type == DataSourceType.ANALYST_NOTES:
                data = await self._ingest_analyst_notes(source, time_range, filters)
            else:
                raise ValueError(f"Unsupported source type: {source.source_type}")

            # Update job status
            job.status = IngestionStatus.COMPLETED
            job.end_time = datetime.utcnow()
            job.records_ingested = len(data)

            logger.info(f"Ingested {len(data)} records from {source.source_name}")

            return IngestedData(
                source_id=source_id,
                source_type=source.source_type,
                data=data,
                metadata={
                    "job_id": job.job_id,
                    "source_name": source.source_name,
                    "time_range": time_range,
                    "filters": filters,
                    "records_count": len(data)
                }
            )

        except Exception as e:
            job.status = IngestionStatus.FAILED
            job.end_time = datetime.utcnow()
            job.errors.append(str(e))
            logger.error(f"Ingestion failed for {source.source_name}: {e}")
            raise

    async def ingest_all_sources(
        self,
        incident_id: str,
        time_range: Optional[Dict[str, datetime]] = None,
        filters: Optional[Dict[str, Any]] = None,
        parallel: bool = True
    ) -> List[IngestedData]:
        """
        Ingest data from all enabled sources.

        Args:
            incident_id: Incident ID for tracking
            time_range: Optional time range
            filters: Optional filters
            parallel: Whether to ingest in parallel

        Returns:
            List of IngestedData from all sources
        """
        enabled_sources = [s for s in self.sources.values() if s.enabled]

        if parallel:
            # Parallel ingestion
            tasks = [
                self.ingest_from_source(incident_id, source.source_id, time_range, filters)
                for source in enabled_sources
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Filter out exceptions
            ingested_data = []
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Ingestion error: {result}")
                else:
                    ingested_data.append(result)

            return ingested_data
        else:
            # Sequential ingestion
            ingested_data = []
            for source in enabled_sources:
                try:
                    data = await self.ingest_from_source(
                        incident_id, source.source_id, time_range, filters
                    )
                    ingested_data.append(data)
                except Exception as e:
                    logger.error(f"Ingestion error for {source.source_name}: {e}")

            return ingested_data

    # ========================================================================
    # Ingestion Handlers (to be implemented based on actual integrations)
    # ========================================================================

    async def _ingest_system_logs(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest system logs (syslog, Windows Event Logs, etc.)"""
        # TODO: Implement actual system log ingestion
        # For now, return mock data
        logger.info(f"Ingesting system logs from {source.source_name}")

        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "hostname": "web-server-01",
                "severity": "warning",
                "message": "Failed login attempt for user admin",
                "source": "auth.log"
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "hostname": "db-server-01",
                "severity": "error",
                "message": "Database connection timeout",
                "source": "postgresql.log"
            }
        ]

    async def _ingest_application_logs(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest application logs"""
        logger.info(f"Ingesting application logs from {source.source_name}")

        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "application": "web-app",
                "level": "ERROR",
                "message": "Unhandled exception in payment processing",
                "stack_trace": "..."
            }
        ]

    async def _ingest_network_logs(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest network device logs (firewalls, routers, switches)"""
        logger.info(f"Ingesting network logs from {source.source_name}")

        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "device": "firewall-01",
                "action": "DENY",
                "src_ip": "203.0.113.45",
                "dst_ip": "10.0.1.100",
                "dst_port": 22,
                "protocol": "TCP",
                "rule": "BLOCK_SSH_EXTERNAL"
            }
        ]

    async def _ingest_edr_logs(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest EDR logs (CrowdStrike, SentinelOne, Microsoft Defender)"""
        logger.info(f"Ingesting EDR logs from {source.source_name}")

        # Check which EDR platform
        platform = source.connection_config.get("platform", "generic")

        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "platform": platform,
                "event_type": "process_creation",
                "hostname": "workstation-42",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc <base64>",
                "parent_process": "winword.exe",
                "user": "john.doe",
                "severity": "high"
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "platform": platform,
                "event_type": "network_connection",
                "hostname": "workstation-42",
                "process_name": "powershell.exe",
                "remote_ip": "198.51.100.23",
                "remote_port": 443,
                "direction": "outbound"
            }
        ]

    async def _ingest_cloud_logs(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest cloud infrastructure logs (AWS, Azure, GCP)"""
        logger.info(f"Ingesting cloud logs from {source.source_name}")

        cloud_provider = source.connection_config.get("provider", "aws")

        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "provider": cloud_provider,
                "service": "iam",
                "event_name": "CreateAccessKey",
                "user": "user@example.com",
                "source_ip": "203.0.113.89",
                "user_agent": "aws-cli/2.0",
                "resource": "arn:aws:iam::123456789012:user/admin"
            }
        ]

    async def _ingest_threat_intel(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest threat intelligence feeds (IOCs, threat actors)"""
        logger.info(f"Ingesting threat intel from {source.source_name}")

        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "ioc_type": "ip",
                "ioc_value": "198.51.100.23",
                "threat_type": "c2_server",
                "threat_actor": "APT29",
                "confidence": 0.85,
                "source": "threat_feed_alpha",
                "tags": ["malware", "cozy_bear", "apt"]
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "ioc_type": "domain",
                "ioc_value": "malicious-domain.com",
                "threat_type": "phishing",
                "confidence": 0.92,
                "source": "threat_feed_beta"
            }
        ]

    async def _ingest_vulnerability_data(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest vulnerability data (CMDB, asset inventory, vulnerability scans)"""
        logger.info(f"Ingesting vulnerability data from {source.source_name}")

        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "asset_id": "workstation-42",
                "hostname": "workstation-42.company.com",
                "ip_address": "10.0.1.42",
                "os": "Windows 10",
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2023-12345",
                        "severity": "critical",
                        "cvss_score": 9.8,
                        "description": "Remote code execution vulnerability",
                        "patch_available": True
                    }
                ],
                "last_scan": datetime.utcnow().isoformat()
            }
        ]

    async def _ingest_documents(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest documents (IR plans, historical incidents, SOPs, playbooks, runbooks, compliance)"""
        logger.info(f"Ingesting documents from {source.source_name}")

        # Check document type
        doc_type = filters.get("document_type") if filters else None

        documents = []

        # IR Plans
        if not doc_type or doc_type == "ir_plan":
            documents.append({
                "document_id": "ir-plan-001",
                "document_type": "ir_plan",
                "title": "Incident Response Plan - Ransomware",
                "content": "1. Isolate affected systems\n2. Identify ransomware variant\n3. Assess backup integrity...",
                "version": "2.1",
                "last_updated": datetime.utcnow().isoformat(),
                "tags": ["ransomware", "malware", "containment"]
            })

        # Historical Incidents
        if not doc_type or doc_type == "historical_incident":
            documents.append({
                "document_id": "incident-2024-089",
                "document_type": "historical_incident",
                "title": "Phishing Campaign - Q3 2024",
                "incident_date": "2024-09-15",
                "summary": "Targeted phishing campaign against finance department...",
                "root_cause": "Lack of email security training",
                "lessons_learned": ["Implement security awareness training", "Deploy email filtering"],
                "tags": ["phishing", "social_engineering"]
            })

        # SOPs
        if not doc_type or doc_type == "sop":
            documents.append({
                "document_id": "sop-001",
                "document_type": "sop",
                "title": "Standard Operating Procedure - Evidence Collection",
                "content": "1. Document current state\n2. Create forensic images\n3. Maintain chain of custody...",
                "version": "1.5",
                "tags": ["forensics", "evidence", "procedure"]
            })

        # Playbooks
        if not doc_type or doc_type == "playbook":
            documents.append({
                "document_id": "playbook-malware",
                "document_type": "playbook",
                "title": "Malware Incident Playbook",
                "steps": [
                    {"step": 1, "action": "Isolate infected system", "owner": "SOC Analyst"},
                    {"step": 2, "action": "Collect malware sample", "owner": "Forensics Team"},
                    {"step": 3, "action": "Analyze malware behavior", "owner": "Malware Analyst"}
                ],
                "tags": ["malware", "playbook"]
            })

        return documents

    async def _ingest_communications(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest communications (Teams, Slack, Email)"""
        logger.info(f"Ingesting communications from {source.source_name}")

        platform = source.connection_config.get("platform", "generic")

        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "platform": platform,
                "channel": "incident-response",
                "sender": "user@example.com",
                "message": "We're seeing suspicious activity on workstation-42. Investigating now.",
                "thread_id": "thread-12345",
                "attachments": []
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "platform": platform,
                "channel": "incident-response",
                "sender": "user@example.com",
                "message": "Confirmed malware. Isolating the system now.",
                "thread_id": "thread-12345",
                "attachments": []
            }
        ]

    async def _ingest_analyst_notes(
        self,
        source: DataSource,
        time_range: Optional[Dict[str, datetime]],
        filters: Optional[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Ingest analyst notes and documentation"""
        logger.info(f"Ingesting analyst notes from {source.source_name}")

        return [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "analyst": "user@example.com",
                "note_type": "observation",
                "content": "User reported suspicious email with attachment. Forwarded to SOC for analysis.",
                "incident_id": "INC-2025-001",
                "tags": ["phishing", "user_report"]
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "analyst": "user@example.com",
                "note_type": "action_taken",
                "content": "Isolated workstation-42 from network. Collected memory dump for analysis.",
                "incident_id": "INC-2025-001",
                "tags": ["containment", "forensics"]
            }
        ]


# Global singleton instance
_ingestion_pipeline: Optional[DataIngestionPipeline] = None


def get_ingestion_pipeline() -> DataIngestionPipeline:
    """Get the global data ingestion pipeline instance"""
    global _ingestion_pipeline
    if _ingestion_pipeline is None:
        _ingestion_pipeline = DataIngestionPipeline()
    return _ingestion_pipeline
