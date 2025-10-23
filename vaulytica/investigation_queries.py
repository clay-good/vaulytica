"""
Cross-Platform Investigation Query Generator

Generates recommended queries for investigating security threats
across Datadog, AWS CloudTrail, GCP Audit Logs, and Google Workspace.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from vaulytica.models import SecurityEvent
from vaulytica.logger import get_logger

logger = get_logger(__name__)


@dataclass
class InvestigationQuery:
    """Investigation query for a specific platform."""
    platform: str
    query: str
    description: str
    timeframe: str = "last_7_days"
    service: Optional[str] = None
    log_type: Optional[str] = None
    application: Optional[str] = None
    priority: str = "medium"  # high, medium, low


class InvestigationQueryGenerator:
    """
    Generate cross-platform investigation queries for security events.

    Supports:
    - Datadog (logs, APM, security signals)
    - AWS CloudTrail (API calls, authentication)
    - GCP Audit Logs (activity, data access)
    - Google Workspace (login, Gmail, Drive, Admin)
    """

    def __init__(self):
        """Initialize query generator."""
        logger.info("Investigation query generator initialized")

    def generate_queries(
        self,
        event: SecurityEvent,
        ioc_enrichment: Optional[Dict[str, Any]] = None
    ) -> Dict[str, List[InvestigationQuery]]:
        """
        Generate investigation queries for all platforms.

        Args:
            event: Security event to investigate
            ioc_enrichment: IOC enrichment data (IPs, domains, users, etc.)

        Returns:
            Dictionary of queries by platform
        """
        queries = {
            "datadog": [],
            "aws_cloudtrail": [],
            "gcp_audit": [],
            "google_workspace": []
        }

        # Extract IOCs from event
        iocs = self._extract_iocs(event, ioc_enrichment)

        # Generate platform-specific queries
        queries["datadog"] = self._generate_datadog_queries(event, iocs)
        queries["aws_cloudtrail"] = self._generate_aws_queries(event, iocs)
        queries["gcp_audit"] = self._generate_gcp_queries(event, iocs)
        queries["google_workspace"] = self._generate_workspace_queries(event, iocs)

        # Log summary
        total_queries = sum(len(q) for q in queries.values())
        logger.info(f"Generated {total_queries} investigation queries across {len(queries)} platforms")

        return queries

    def _extract_iocs(
        self,
        event: SecurityEvent,
        ioc_enrichment: Optional[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Extract IOCs from event and enrichment data."""
        iocs = {
            "ips": [],
            "domains": [],
            "urls": [],
            "users": [],
            "hosts": [],
            "hashes": []
        }

        # Extract from technical indicators
        for indicator in event.technical_indicators:
            value = indicator.value
            ioc_type = indicator.indicator_type.lower()

            if ioc_type in ["ip", "source_ip", "dest_ip"]:
                iocs["ips"].append(value)
            elif ioc_type in ["domain", "hostname"]:
                iocs["domains"].append(value)
            elif ioc_type in ["url"]:
                iocs["urls"].append(value)
            elif ioc_type in ["user", "username", "user_id"]:
                iocs["users"].append(value)
            elif ioc_type in ["host", "hostname"]:
                iocs["hosts"].append(value)
            elif ioc_type in ["hash", "md5", "sha1", "sha256"]:
                iocs["hashes"].append(value)

        # Extract from enrichment
        if ioc_enrichment:
            for ioc_value, enrichment in ioc_enrichment.items():
                if hasattr(enrichment, 'ioc_type'):
                    if enrichment.ioc_type == "ip":
                        iocs["ips"].append(ioc_value)
                    elif enrichment.ioc_type == "domain":
                        iocs["domains"].append(ioc_value)
                    elif enrichment.ioc_type == "url":
                        iocs["urls"].append(ioc_value)

        # Deduplicate
        for key in iocs:
            iocs[key] = list(set(iocs[key]))

        return iocs

    def _generate_datadog_queries(
        self,
        event: SecurityEvent,
        iocs: Dict[str, List[str]]
    ) -> List[InvestigationQuery]:
        """Generate Datadog investigation queries."""
        queries = []

        # Query 1: Find all logs from suspicious IPs
        if iocs["ips"]:
            for ip in iocs["ips"][:5]:  # Limit to first 5 IPs
                queries.append(InvestigationQuery(
                    platform="datadog",
                    query=f"source:* @network.client.ip:{ip}",
                    description=f"Find all logs from suspicious IP {ip}",
                    timeframe="last_7_days",
                    priority="high"
                ))

        # Query 2: Find failed authentication attempts
        if iocs["ips"] or iocs["users"]:
            if iocs["ips"]:
                ip_filter = f"@network.client.ip:{iocs['ips'][0]}"
            else:
                ip_filter = ""

            if iocs["users"]:
                user_filter = f"@usr.id:{iocs['users'][0]}"
            else:
                user_filter = ""

            filters = " ".join([f for f in [ip_filter, user_filter] if f])

            queries.append(InvestigationQuery(
                platform="datadog",
                query=f"@http.status_code:[400 TO 499] {filters}",
                description="Find failed authentication attempts",
                timeframe="last_24_hours",
                priority="high"
            ))

        # Query 3: Find all activity from compromised users
        if iocs["users"]:
            for user in iocs["users"][:3]:  # Limit to first 3 users
                queries.append(InvestigationQuery(
                    platform="datadog",
                    query=f"@usr.id:{user} @network.client.ip:*",
                    description=f"Find all IPs used by user {user}",
                    timeframe="last_7_days",
                    priority="high"
                ))

        # Query 4: Find suspicious domains
        if iocs["domains"]:
            for domain in iocs["domains"][:3]:
                queries.append(InvestigationQuery(
                    platform="datadog",
                    query=f"@network.destination.domain:{domain}",
                    description=f"Find all connections to domain {domain}",
                    timeframe="last_7_days",
                    priority="medium"
                ))

        # Query 5: Find related security signals
        queries.append(InvestigationQuery(
            platform="datadog",
            query=f"source:security_monitoring service:{event.source_system}",
            description="Find related security signals",
            timeframe="last_7_days",
            priority="medium"
        ))

        # Query 6: APM trace analysis (if service identified)
        if event.affected_assets:
            for asset in event.affected_assets[:2]:
                if asset.hostname:
                    queries.append(InvestigationQuery(
                        platform="datadog",
                        query=f"service:{asset.hostname} @error.stack:*",
                        description=f"Find errors in service {asset.hostname}",
                        timeframe="last_24_hours",
                        service="APM",
                        priority="medium"
                    ))

        return queries

    def _generate_aws_queries(
        self,
        event: SecurityEvent,
        iocs: Dict[str, List[str]]
    ) -> List[InvestigationQuery]:
        """Generate AWS CloudTrail investigation queries."""
        queries = []

        # Query 1: Find all API calls from suspicious IPs
        if iocs["ips"]:
            for ip in iocs["ips"][:3]:
                queries.append(InvestigationQuery(
                    platform="aws_cloudtrail",
                    query=f"sourceIPAddress = '{ip}'",
                    description=f"Find all AWS API calls from IP {ip}",
                    timeframe="last_7_days",
                    service="CloudTrail",
                    priority="high"
                ))

        # Query 2: Find failed API calls
        if iocs["users"]:
            for user in iocs["users"][:2]:
                queries.append(InvestigationQuery(
                    platform="aws_cloudtrail",
                    query=f"userIdentity.userName = '{user}' AND errorCode EXISTS",
                    description=f"Find failed AWS API calls by user {user}",
                    timeframe="last_7_days",
                    service="CloudTrail",
                    priority="high"
                ))

        # Query 3: Find privilege escalation attempts
        queries.append(InvestigationQuery(
            platform="aws_cloudtrail",
            query="eventName IN ('PutUserPolicy', 'PutRolePolicy', 'AttachUserPolicy', 'AttachRolePolicy')",
            description="Find IAM privilege escalation attempts",
            timeframe="last_7_days",
            service="CloudTrail",
            priority="high"
        ))

        # Query 4: Find data exfiltration (S3 downloads)
        if iocs["ips"]:
            queries.append(InvestigationQuery(
                platform="aws_cloudtrail",
                query=f"eventName = 'GetObject' AND sourceIPAddress = '{iocs['ips'][0]}'",
                description="Find S3 object downloads from suspicious IP",
                timeframe="last_7_days",
                service="CloudTrail",
                priority="medium"
            ))

        # Query 5: Find console logins
        if iocs["ips"]:
            queries.append(InvestigationQuery(
                platform="aws_cloudtrail",
                query=f"eventName = 'ConsoleLogin' AND sourceIPAddress = '{iocs['ips'][0]}'",
                description="Find AWS console logins from suspicious IP",
                timeframe="last_7_days",
                service="CloudTrail",
                priority="high"
            ))

        return queries

    def _generate_gcp_queries(
        self,
        event: SecurityEvent,
        iocs: Dict[str, List[str]]
    ) -> List[InvestigationQuery]:
        """Generate GCP Audit Logs investigation queries."""
        queries = []

        # Query 1: Find all API calls from suspicious IPs
        if iocs["ips"]:
            for ip in iocs["ips"][:3]:
                queries.append(InvestigationQuery(
                    platform="gcp_audit",
                    query=f'protoPayload.requestMetadata.callerIp="{ip}"',
                    description=f"Find all GCP API calls from IP {ip}",
                    timeframe="last_7_days",
                    log_type="cloudaudit.googleapis.com/activity",
                    priority="high"
                ))

        # Query 2: Find IAM policy changes
        queries.append(InvestigationQuery(
            platform="gcp_audit",
            query='protoPayload.methodName:"setIamPolicy"',
            description="Find IAM policy changes",
            timeframe="last_7_days",
            log_type="cloudaudit.googleapis.com/activity",
            priority="high"
        ))

        # Query 3: Find data access (BigQuery, Cloud Storage)
        if iocs["users"]:
            queries.append(InvestigationQuery(
                platform="gcp_audit",
                query=f'protoPayload.authenticationInfo.principalEmail="{iocs["users"][0]}"',
                description=f"Find data access by user {iocs['users'][0]}",
                timeframe="last_7_days",
                log_type="cloudaudit.googleapis.com/data_access",
                priority="medium"
            ))

        # Query 4: Find compute instance creation/modification
        queries.append(InvestigationQuery(
            platform="gcp_audit",
            query='protoPayload.methodName:("insert" OR "update" OR "delete") AND resource.type="gce_instance"',
            description="Find compute instance changes",
            timeframe="last_7_days",
            log_type="cloudaudit.googleapis.com/activity",
            priority="medium"
        ))

        return queries

    def _generate_workspace_queries(
        self,
        event: SecurityEvent,
        iocs: Dict[str, List[str]]
    ) -> List[InvestigationQuery]:
        """Generate Google Workspace investigation queries."""
        queries = []

        # Query 1: Find logins from suspicious IPs
        if iocs["ips"]:
            for ip in iocs["ips"][:3]:
                queries.append(InvestigationQuery(
                    platform="google_workspace",
                    query=f"ip_address:{ip}",
                    description=f"Find Workspace logins from IP {ip}",
                    timeframe="last_7_days",
                    application="login",
                    priority="high"
                ))

        # Query 2: Find email forwarding rules
        if iocs["users"]:
            for user in iocs["users"][:2]:
                queries.append(InvestigationQuery(
                    platform="google_workspace",
                    query=f"email:{user} event_name:add_forwarding_address",
                    description=f"Check if user {user} added email forwarding rules",
                    timeframe="last_30_days",
                    application="gmail",
                    priority="high"
                ))

        # Query 3: Find Drive sharing activity
        if iocs["users"]:
            queries.append(InvestigationQuery(
                platform="google_workspace",
                query=f"email:{iocs['users'][0]} event_name:(share OR change_user_access)",
                description=f"Find Drive sharing activity by user {iocs['users'][0]}",
                timeframe="last_7_days",
                application="drive",
                priority="medium"
            ))

        # Query 4: Find admin activity
        if iocs["users"]:
            queries.append(InvestigationQuery(
                platform="google_workspace",
                query=f"email:{iocs['users'][0]} event_type:ADMIN_SETTINGS",
                description=f"Find admin activity by user {iocs['users'][0]}",
                timeframe="last_7_days",
                application="admin",
                priority="high"
            ))

        # Query 5: Find OAuth app grants
        queries.append(InvestigationQuery(
            platform="google_workspace",
            query="event_name:authorize",
            description="Find OAuth app authorization events",
            timeframe="last_7_days",
            application="token",
            priority="medium"
        ))

        # Query 6: Find impossible travel
        if iocs["users"]:
            queries.append(InvestigationQuery(
                platform="google_workspace",
                query=f"email:{iocs['users'][0]} event_name:login_success",
                description=f"Analyze login locations for impossible travel (user {iocs['users'][0]})",
                timeframe="last_7_days",
                application="login",
                priority="high"
            ))

        return queries


# Global instance
_query_generator: Optional[InvestigationQueryGenerator] = None


def get_investigation_query_generator() -> InvestigationQueryGenerator:
    """Get or create global investigation query generator instance."""
    global _query_generator

    if _query_generator is None:
        _query_generator = InvestigationQueryGenerator()

    return _query_generator

