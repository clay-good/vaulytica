"""Pydantic schemas for API responses."""

from datetime import datetime
from typing import Optional, List, Any, Dict

from pydantic import BaseModel


# Scan Schemas
class ScanRunBase(BaseModel):
    """Base scan run schema."""

    scan_type: str
    domain_name: str
    status: str
    total_items: int = 0
    issues_found: int = 0


class ScanRunResponse(ScanRunBase):
    """Scan run response schema."""

    id: int
    start_time: datetime
    end_time: Optional[datetime] = None
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    triggered_by: Optional[str] = None
    error_message: Optional[str] = None
    # Progress tracking fields
    progress_percent: int = 0
    progress_message: Optional[str] = None
    items_processed: int = 0
    estimated_total: Optional[int] = None

    class Config:
        from_attributes = True


class ScanRunDetailResponse(ScanRunResponse):
    """Detailed scan run response with config."""

    config: Optional[Dict[str, Any]] = None


# Finding Schemas
class SecurityFindingResponse(BaseModel):
    """Security finding response schema."""

    id: int
    check_id: str
    title: str
    description: Optional[str] = None
    severity: str
    passed: bool
    current_value: Optional[str] = None
    expected_value: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    frameworks: Optional[List[str]] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    detected_at: datetime
    status: Optional[str] = "open"
    status_notes: Optional[str] = None
    status_updated_at: Optional[datetime] = None
    status_updated_by: Optional[str] = None

    class Config:
        from_attributes = True


class FileFindingResponse(BaseModel):
    """File finding response schema."""

    id: int
    file_id: str
    file_name: str
    owner_email: Optional[str] = None
    owner_name: Optional[str] = None
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    web_view_link: Optional[str] = None
    is_public: bool = False
    is_shared_externally: bool = False
    external_domains: Optional[List[str]] = None
    external_emails: Optional[List[str]] = None
    risk_score: int = 0
    pii_detected: bool = False
    pii_types: Optional[List[str]] = None
    detected_at: datetime

    class Config:
        from_attributes = True


class UserFindingResponse(BaseModel):
    """User finding response schema."""

    id: int
    user_id: str
    email: str
    full_name: Optional[str] = None
    is_admin: bool = False
    is_suspended: bool = False
    is_archived: bool = False
    last_login_time: Optional[datetime] = None
    creation_time: Optional[datetime] = None
    two_factor_enabled: bool = False
    org_unit_path: Optional[str] = None
    is_inactive: bool = False
    days_since_last_login: Optional[int] = None
    risk_score: int = 0
    risk_factors: Optional[List[str]] = None
    detected_at: datetime

    class Config:
        from_attributes = True


class OAuthFindingResponse(BaseModel):
    """OAuth finding response schema."""

    id: int
    client_id: str
    display_text: Optional[str] = None
    scopes: Optional[List[str]] = None
    user_count: int = 0
    users: Optional[List[str]] = None
    risk_score: int = 0
    is_verified: bool = False
    is_google_app: bool = False
    is_internal: bool = False
    risk_factors: Optional[List[str]] = None
    detected_at: datetime

    class Config:
        from_attributes = True


# Dashboard Schemas
class ScanStatsResponse(BaseModel):
    """Scan statistics response schema."""

    total_scans: int
    completed_scans: int
    failed_scans: int
    total_issues: int
    high_risk_total: int
    medium_risk_total: int
    low_risk_total: int
    success_rate: float
    period_days: int


class DashboardOverviewResponse(BaseModel):
    """Dashboard overview response schema."""

    scan_stats: ScanStatsResponse
    recent_scans: List[ScanRunResponse]
    critical_findings: int
    high_risk_files: int
    inactive_users: int
    risky_oauth_apps: int
    security_score: float
    findings_by_severity: Dict[str, int]
    findings_by_framework: Dict[str, int]


class FindingsSummaryResponse(BaseModel):
    """Findings summary response schema."""

    total_findings: int
    passed: int
    failed: int
    by_severity: Dict[str, int]
    by_framework: Dict[str, int]


# Domain Schemas
class DomainBase(BaseModel):
    """Base domain schema."""

    name: str
    display_name: Optional[str] = None
    admin_email: Optional[str] = None


class DomainCreate(DomainBase):
    """Domain creation schema."""

    credentials_path: Optional[str] = None


class DomainResponse(DomainBase):
    """Domain response schema."""

    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# Trigger Scan Schema
class TriggerScanRequest(BaseModel):
    """Request to trigger a new scan."""

    domain_name: str
    scan_type: str  # files, users, oauth, posture, all
    config: Optional[Dict[str, Any]] = None


class TriggerScanResponse(BaseModel):
    """Response from triggering a scan."""

    id: int
    scan_type: str
    domain_name: str
    status: str
    start_time: datetime
    message: str

    class Config:
        from_attributes = True


class CancelScanResponse(BaseModel):
    """Response from cancelling a scan."""

    id: int
    status: str
    message: str


# Finding Status Update Schema
class FindingStatusUpdateRequest(BaseModel):
    """Request to update finding status."""

    status: str  # open, acknowledged, resolved, false_positive
    notes: Optional[str] = None


class FindingStatusUpdateResponse(BaseModel):
    """Response from updating finding status."""

    id: int
    status: str
    updated_at: datetime
    message: str


# Audit Log Schema
class AuditLogResponse(BaseModel):
    """Audit log entry response schema."""

    id: int
    user_id: Optional[int] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
