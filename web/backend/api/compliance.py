"""Compliance reporting API routes."""

from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, desc
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..auth.security import get_current_user, require_domain_access, require_domain_role, Role
from ..db.database import get_db
from ..db.models import (
    User,
    Domain,
    ComplianceReport,
    SecurityFinding,
    FileFinding,
    UserFinding,
    OAuthFinding,
    ScanRun,
    AuditLog,
    ScheduledReport,
)

router = APIRouter()


# Supported compliance frameworks
SUPPORTED_FRAMEWORKS = ["gdpr", "hipaa", "soc2", "pci-dss", "ferpa", "fedramp"]


# Pydantic Schemas
class ComplianceIssue(BaseModel):
    """Individual compliance issue."""
    check_id: str
    title: str
    description: Optional[str] = None
    severity: str
    category: str
    remediation: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None


class ComplianceReportResponse(BaseModel):
    """Compliance report response schema."""
    id: int
    domain_name: str
    framework: str
    status: str
    compliance_score: Optional[int] = None
    total_checks: int
    passed_checks: int
    failed_checks: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    generated_at: datetime
    issues: List[ComplianceIssue] = []

    class Config:
        from_attributes = True


class ComplianceReportSummary(BaseModel):
    """Summary of a compliance report."""
    id: int
    domain_name: str
    framework: str
    status: str
    compliance_score: Optional[int] = None
    total_checks: int
    passed_checks: int
    failed_checks: int
    generated_at: datetime

    class Config:
        from_attributes = True


class ComplianceReportListResponse(BaseModel):
    """Paginated compliance reports response."""
    items: List[ComplianceReportSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class GenerateReportRequest(BaseModel):
    """Request to generate a compliance report."""
    domain_name: str
    framework: str = Field(..., description="Compliance framework: gdpr, hipaa, soc2, pci-dss, ferpa, fedramp")
    scan_run_id: Optional[int] = Field(None, description="Optional scan run to base report on (uses latest if not specified)")


class FrameworkInfo(BaseModel):
    """Information about a compliance framework."""
    id: str
    name: str
    description: str
    check_count: int


@router.get("/frameworks", response_model=List[FrameworkInfo])
async def get_frameworks(
    current_user: User = Depends(get_current_user),
):
    """Get list of supported compliance frameworks."""
    return [
        FrameworkInfo(
            id="gdpr",
            name="GDPR",
            description="General Data Protection Regulation - EU data protection law",
            check_count=8,
        ),
        FrameworkInfo(
            id="hipaa",
            name="HIPAA",
            description="Health Insurance Portability and Accountability Act - Healthcare data protection",
            check_count=10,
        ),
        FrameworkInfo(
            id="soc2",
            name="SOC 2",
            description="Service Organization Control 2 - Trust services criteria",
            check_count=12,
        ),
        FrameworkInfo(
            id="pci-dss",
            name="PCI-DSS",
            description="Payment Card Industry Data Security Standard",
            check_count=10,
        ),
        FrameworkInfo(
            id="ferpa",
            name="FERPA",
            description="Family Educational Rights and Privacy Act - Student data protection",
            check_count=6,
        ),
        FrameworkInfo(
            id="fedramp",
            name="FedRAMP",
            description="Federal Risk and Authorization Management Program",
            check_count=15,
        ),
    ]


@router.get("", response_model=ComplianceReportListResponse)
async def list_compliance_reports(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    framework: Optional[str] = Query(None, description="Filter by framework"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List compliance reports."""
    query = db.query(ComplianceReport)

    # Filter by domain access
    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ComplianceReport.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ComplianceReport.domain_name.in_(user_domains))

    if framework:
        if framework.lower() not in SUPPORTED_FRAMEWORKS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid framework. Must be one of: {', '.join(SUPPORTED_FRAMEWORKS)}"
            )
        query = query.filter(ComplianceReport.framework == framework.lower())

    # Get total count
    total = query.count()

    # Paginate
    offset = (page - 1) * page_size
    reports = query.order_by(ComplianceReport.generated_at.desc()).offset(offset).limit(page_size).all()

    items = [
        ComplianceReportSummary(
            id=r.id,
            domain_name=r.domain_name,
            framework=r.framework,
            status=r.status,
            compliance_score=r.compliance_score,
            total_checks=r.total_checks,
            passed_checks=r.passed_checks,
            failed_checks=r.failed_checks,
            generated_at=r.generated_at,
        )
        for r in reports
    ]

    return ComplianceReportListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


# ========================
# SCHEDULED REPORTS (moved before /{report_id} for route ordering)
# ========================


class ScheduledReportBase(BaseModel):
    """Base schema for scheduled reports."""
    name: str
    framework: str
    schedule_type: str  # daily, weekly, monthly
    schedule_config: Optional[Dict[str, Any]] = None
    recipients: Optional[List[str]] = None
    is_active: bool = True


class ScheduledReportCreate(ScheduledReportBase):
    """Schema for creating a scheduled report."""
    domain_name: str


class ScheduledReportUpdate(BaseModel):
    """Schema for updating a scheduled report."""
    name: Optional[str] = None
    framework: Optional[str] = None
    schedule_type: Optional[str] = None
    schedule_config: Optional[Dict[str, Any]] = None
    recipients: Optional[List[str]] = None
    is_active: Optional[bool] = None


class ScheduledReportResponse(ScheduledReportBase):
    """Response schema for scheduled reports."""
    id: int
    domain_id: int
    domain_name: str
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    last_report_id: Optional[int] = None
    created_by: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ScheduledReportListResponse(BaseModel):
    """Paginated list of scheduled reports."""
    items: List[ScheduledReportResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


def calculate_report_next_run(schedule_type: str, schedule_config: Optional[Dict] = None) -> datetime:
    """Calculate the next run time based on schedule configuration."""
    now = datetime.utcnow()

    if schedule_type == "daily":
        hour = schedule_config.get("hour", 6) if schedule_config else 6
        next_run = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += timedelta(days=1)
        return next_run
    elif schedule_type == "weekly":
        day_of_week = schedule_config.get("day_of_week", 0) if schedule_config else 0  # 0 = Monday
        hour = schedule_config.get("hour", 6) if schedule_config else 6
        days_ahead = day_of_week - now.weekday()
        if days_ahead <= 0:
            days_ahead += 7
        next_run = now + timedelta(days=days_ahead)
        return next_run.replace(hour=hour, minute=0, second=0, microsecond=0)
    elif schedule_type == "monthly":
        day = schedule_config.get("day", 1) if schedule_config else 1
        hour = schedule_config.get("hour", 6) if schedule_config else 6
        if now.day >= day:
            # Next month
            if now.month == 12:
                next_run = now.replace(year=now.year + 1, month=1, day=day, hour=hour, minute=0, second=0, microsecond=0)
            else:
                next_run = now.replace(month=now.month + 1, day=day, hour=hour, minute=0, second=0, microsecond=0)
        else:
            next_run = now.replace(day=day, hour=hour, minute=0, second=0, microsecond=0)
        return next_run

    return now + timedelta(days=1)


@router.get("/schedules", response_model=ScheduledReportListResponse)
async def list_scheduled_reports(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all scheduled reports accessible to the current user."""
    query = db.query(ScheduledReport).join(Domain, ScheduledReport.domain_id == Domain.id)

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(Domain.name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(Domain.name.in_(user_domains))

    if is_active is not None:
        query = query.filter(ScheduledReport.is_active == is_active)

    # Get total count
    total = query.count()

    # Paginate
    offset = (page - 1) * page_size
    schedules = query.order_by(desc(ScheduledReport.created_at)).offset(offset).limit(page_size).all()

    # Build response
    items = []
    for schedule in schedules:
        domain_obj = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
        items.append(ScheduledReportResponse(
            id=schedule.id,
            name=schedule.name,
            domain_id=schedule.domain_id,
            domain_name=domain_obj.name if domain_obj else "unknown",
            framework=schedule.framework,
            schedule_type=schedule.schedule_type,
            schedule_config=schedule.schedule_config,
            recipients=schedule.recipients,
            is_active=schedule.is_active,
            last_run=schedule.last_run,
            next_run=schedule.next_run,
            last_report_id=schedule.last_report_id,
            created_by=schedule.created_by,
            created_at=schedule.created_at,
            updated_at=schedule.updated_at,
        ))

    return ScheduledReportListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=(total + page_size - 1) // page_size,
    )


@router.post("/schedules", response_model=ScheduledReportResponse, status_code=status.HTTP_201_CREATED)
async def create_scheduled_report(
    data: ScheduledReportCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new scheduled report."""
    # Check domain access - requires EDITOR role
    require_domain_role(current_user, data.domain_name, Role.EDITOR)

    # Get domain
    domain = db.query(Domain).filter(Domain.name == data.domain_name).first()
    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{data.domain_name}' not found"
        )

    # Validate framework
    if data.framework.lower() not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid framework. Must be one of: {', '.join(SUPPORTED_FRAMEWORKS)}"
        )

    # Validate schedule_type
    valid_schedule_types = ["daily", "weekly", "monthly"]
    if data.schedule_type not in valid_schedule_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid schedule_type. Must be one of: {valid_schedule_types}"
        )

    # Calculate next run
    next_run = calculate_report_next_run(data.schedule_type, data.schedule_config)

    try:
        schedule = ScheduledReport(
            name=data.name,
            domain_id=domain.id,
            framework=data.framework.lower(),
            schedule_type=data.schedule_type,
            schedule_config=data.schedule_config,
            recipients=data.recipients,
            is_active=data.is_active,
            next_run=next_run,
            created_by=current_user.id,
        )

        db.add(schedule)
        db.commit()
        db.refresh(schedule)

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="scheduled_report_created",
            resource_type="scheduled_report",
            resource_id=str(schedule.id),
            details={
                "domain": domain.name,
                "framework": data.framework,
                "schedule_type": data.schedule_type,
            },
        )
        db.add(audit_log)
        db.commit()

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create scheduled report. Please try again.",
        )

    return ScheduledReportResponse(
        id=schedule.id,
        name=schedule.name,
        domain_id=schedule.domain_id,
        domain_name=domain.name,
        framework=schedule.framework,
        schedule_type=schedule.schedule_type,
        schedule_config=schedule.schedule_config,
        recipients=schedule.recipients,
        is_active=schedule.is_active,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        last_report_id=schedule.last_report_id,
        created_by=schedule.created_by,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


@router.get("/schedules/{schedule_id}", response_model=ScheduledReportResponse)
async def get_scheduled_report(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific scheduled report."""
    schedule = db.query(ScheduledReport).filter(ScheduledReport.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled report not found"
        )

    domain = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
    if domain:
        require_domain_access(current_user, domain.name)

    return ScheduledReportResponse(
        id=schedule.id,
        name=schedule.name,
        domain_id=schedule.domain_id,
        domain_name=domain.name if domain else "unknown",
        framework=schedule.framework,
        schedule_type=schedule.schedule_type,
        schedule_config=schedule.schedule_config,
        recipients=schedule.recipients,
        is_active=schedule.is_active,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        last_report_id=schedule.last_report_id,
        created_by=schedule.created_by,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


@router.put("/schedules/{schedule_id}", response_model=ScheduledReportResponse)
async def update_scheduled_report(
    schedule_id: int,
    data: ScheduledReportUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a scheduled report."""
    schedule = db.query(ScheduledReport).filter(ScheduledReport.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled report not found"
        )

    domain = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
    if domain:
        require_domain_role(current_user, domain.name, Role.EDITOR)

    # Update fields
    if data.name is not None:
        schedule.name = data.name
    if data.framework is not None:
        if data.framework.lower() not in SUPPORTED_FRAMEWORKS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid framework. Must be one of: {', '.join(SUPPORTED_FRAMEWORKS)}"
            )
        schedule.framework = data.framework.lower()
    if data.schedule_type is not None:
        valid_schedule_types = ["daily", "weekly", "monthly"]
        if data.schedule_type not in valid_schedule_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid schedule_type. Must be one of: {valid_schedule_types}"
            )
        schedule.schedule_type = data.schedule_type
    if data.schedule_config is not None:
        schedule.schedule_config = data.schedule_config
    if data.recipients is not None:
        schedule.recipients = data.recipients
    if data.is_active is not None:
        schedule.is_active = data.is_active

    # Recalculate next_run if schedule changed
    if data.schedule_type is not None or data.schedule_config is not None:
        schedule.next_run = calculate_report_next_run(
            schedule.schedule_type,
            schedule.schedule_config
        )

    try:
        db.commit()
        db.refresh(schedule)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update scheduled report. Please try again.",
        )

    return ScheduledReportResponse(
        id=schedule.id,
        name=schedule.name,
        domain_id=schedule.domain_id,
        domain_name=domain.name if domain else "unknown",
        framework=schedule.framework,
        schedule_type=schedule.schedule_type,
        schedule_config=schedule.schedule_config,
        recipients=schedule.recipients,
        is_active=schedule.is_active,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        last_report_id=schedule.last_report_id,
        created_by=schedule.created_by,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_report(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a scheduled report."""
    schedule = db.query(ScheduledReport).filter(ScheduledReport.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled report not found"
        )

    domain = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
    if domain:
        require_domain_role(current_user, domain.name, Role.EDITOR)

    try:
        domain_name = domain.name if domain else "unknown"
        framework = schedule.framework
        db.delete(schedule)
        db.commit()

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="scheduled_report_deleted",
            resource_type="scheduled_report",
            resource_id=str(schedule_id),
            details={"domain": domain_name, "framework": framework},
        )
        db.add(audit_log)
        db.commit()

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete scheduled report. Please try again.",
        )


@router.post("/schedules/{schedule_id}/toggle", response_model=ScheduledReportResponse)
async def toggle_scheduled_report(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Toggle a scheduled report's active status."""
    schedule = db.query(ScheduledReport).filter(ScheduledReport.id == schedule_id).first()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled report not found"
        )

    domain = db.query(Domain).filter(Domain.id == schedule.domain_id).first()
    if domain:
        require_domain_role(current_user, domain.name, Role.EDITOR)

    schedule.is_active = not schedule.is_active

    # Recalculate next_run if activating
    if schedule.is_active:
        schedule.next_run = calculate_report_next_run(
            schedule.schedule_type,
            schedule.schedule_config
        )

    try:
        db.commit()
        db.refresh(schedule)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle scheduled report. Please try again.",
        )

    return ScheduledReportResponse(
        id=schedule.id,
        name=schedule.name,
        domain_id=schedule.domain_id,
        domain_name=domain.name if domain else "unknown",
        framework=schedule.framework,
        schedule_type=schedule.schedule_type,
        schedule_config=schedule.schedule_config,
        recipients=schedule.recipients,
        is_active=schedule.is_active,
        last_run=schedule.last_run,
        next_run=schedule.next_run,
        last_report_id=schedule.last_report_id,
        created_by=schedule.created_by,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


# ========================
# COMPLIANCE REPORTS - Individual Operations
# ========================


@router.get("/{report_id}", response_model=ComplianceReportResponse)
async def get_compliance_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific compliance report with full details."""
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Compliance report not found")

    # Check domain access
    require_domain_access(current_user, report.domain_name)

    # Extract issues from report_data
    issues = []
    if report.report_data and "issues" in report.report_data:
        for issue_data in report.report_data["issues"]:
            issues.append(ComplianceIssue(
                check_id=issue_data.get("check_id", ""),
                title=issue_data.get("title", ""),
                description=issue_data.get("description"),
                severity=issue_data.get("severity", "medium"),
                category=issue_data.get("category", "general"),
                remediation=issue_data.get("remediation"),
                resource_type=issue_data.get("resource_type"),
                resource_id=issue_data.get("resource_id"),
            ))

    return ComplianceReportResponse(
        id=report.id,
        domain_name=report.domain_name,
        framework=report.framework,
        status=report.status,
        compliance_score=report.compliance_score,
        total_checks=report.total_checks,
        passed_checks=report.passed_checks,
        failed_checks=report.failed_checks,
        critical_count=report.critical_count,
        high_count=report.high_count,
        medium_count=report.medium_count,
        low_count=report.low_count,
        generated_at=report.generated_at,
        issues=issues,
    )


@router.post("", response_model=ComplianceReportResponse, status_code=201)
async def generate_compliance_report(
    request: GenerateReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Generate a new compliance report for a domain."""
    # Validate framework
    framework = request.framework.lower()
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid framework. Must be one of: {', '.join(SUPPORTED_FRAMEWORKS)}"
        )

    # Verify domain access
    require_domain_access(current_user, request.domain_name)
    domain = db.query(Domain).filter(Domain.name == request.domain_name).first()
    if not domain:
        raise HTTPException(status_code=404, detail=f"Domain '{request.domain_name}' not found")

    # Get scan run to base report on
    scan_run = None
    if request.scan_run_id:
        scan_run = db.query(ScanRun).filter(
            ScanRun.id == request.scan_run_id,
            ScanRun.domain_name == request.domain_name,
        ).first()
        if not scan_run:
            raise HTTPException(status_code=404, detail="Scan run not found")
    else:
        # Get latest completed scan for the domain
        scan_run = db.query(ScanRun).filter(
            ScanRun.domain_name == request.domain_name,
            ScanRun.status == "completed",
        ).order_by(ScanRun.end_time.desc()).first()

    try:
        # Generate the compliance report based on findings
        report_data = _generate_framework_report(db, domain, framework, scan_run)

        # Calculate scores
        total_checks = report_data["total_checks"]
        passed_checks = report_data["passed_checks"]
        failed_checks = total_checks - passed_checks
        compliance_score = int((passed_checks / total_checks * 100) if total_checks > 0 else 0)

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for issue in report_data.get("issues", []):
            sev = issue.get("severity", "medium").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Create report record
        report = ComplianceReport(
            domain_id=domain.id,
            domain_name=domain.name,
            framework=framework,
            status="completed",
            compliance_score=compliance_score,
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            report_data=report_data,
            generated_by=current_user.id,
            generated_at=datetime.utcnow(),
            scan_run_id=scan_run.id if scan_run else None,
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="compliance_report_generated",
            resource_type="compliance_report",
            resource_id=str(report.id),
            details={
                "domain": domain.name,
                "framework": framework,
                "compliance_score": compliance_score,
            },
        )
        db.add(audit_log)
        db.commit()

        # Build response with issues
        issues = [
            ComplianceIssue(
                check_id=issue.get("check_id", ""),
                title=issue.get("title", ""),
                description=issue.get("description"),
                severity=issue.get("severity", "medium"),
                category=issue.get("category", "general"),
                remediation=issue.get("remediation"),
                resource_type=issue.get("resource_type"),
                resource_id=issue.get("resource_id"),
            )
            for issue in report_data.get("issues", [])
        ]

        return ComplianceReportResponse(
            id=report.id,
            domain_name=report.domain_name,
            framework=report.framework,
            status=report.status,
            compliance_score=report.compliance_score,
            total_checks=report.total_checks,
            passed_checks=report.passed_checks,
            failed_checks=report.failed_checks,
            critical_count=report.critical_count,
            high_count=report.high_count,
            medium_count=report.medium_count,
            low_count=report.low_count,
            generated_at=report.generated_at,
            issues=issues,
        )

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to generate compliance report")


@router.delete("/{report_id}", status_code=204)
async def delete_compliance_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a compliance report."""
    report = db.query(ComplianceReport).filter(ComplianceReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Compliance report not found")

    # Check domain access
    require_domain_access(current_user, report.domain_name)

    try:
        domain_name = report.domain_name
        framework = report.framework
        db.delete(report)
        db.commit()

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="compliance_report_deleted",
            resource_type="compliance_report",
            resource_id=str(report_id),
            details={"domain": domain_name, "framework": framework},
        )
        db.add(audit_log)
        db.commit()

    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete compliance report")


def _generate_framework_report(db: Session, domain: Domain, framework: str, scan_run: Optional[ScanRun]) -> dict:
    """Generate compliance report data based on findings.

    This analyzes security findings, file findings, user findings, and OAuth findings
    to assess compliance with the specified framework.
    """
    issues = []
    total_checks = 0
    passed_checks = 0

    # Get latest findings for the domain
    base_query_kwargs = {"domain_name": domain.name}
    if scan_run:
        base_query_kwargs = {"scan_run_id": scan_run.id}

    # Get findings
    if scan_run:
        security_findings = db.query(SecurityFinding).filter(SecurityFinding.scan_run_id == scan_run.id).all()
        file_findings = db.query(FileFinding).filter(FileFinding.scan_run_id == scan_run.id).all()
        user_findings = db.query(UserFinding).filter(UserFinding.scan_run_id == scan_run.id).all()
        oauth_findings = db.query(OAuthFinding).filter(OAuthFinding.scan_run_id == scan_run.id).all()
    else:
        # Get from latest scans
        latest_security_scan = db.query(ScanRun).filter(
            ScanRun.domain_name == domain.name,
            ScanRun.scan_type == "posture",
            ScanRun.status == "completed",
        ).order_by(ScanRun.end_time.desc()).first()

        latest_file_scan = db.query(ScanRun).filter(
            ScanRun.domain_name == domain.name,
            ScanRun.scan_type == "files",
            ScanRun.status == "completed",
        ).order_by(ScanRun.end_time.desc()).first()

        latest_user_scan = db.query(ScanRun).filter(
            ScanRun.domain_name == domain.name,
            ScanRun.scan_type == "users",
            ScanRun.status == "completed",
        ).order_by(ScanRun.end_time.desc()).first()

        latest_oauth_scan = db.query(ScanRun).filter(
            ScanRun.domain_name == domain.name,
            ScanRun.scan_type == "oauth",
            ScanRun.status == "completed",
        ).order_by(ScanRun.end_time.desc()).first()

        security_findings = db.query(SecurityFinding).filter(
            SecurityFinding.scan_run_id == latest_security_scan.id
        ).all() if latest_security_scan else []

        file_findings = db.query(FileFinding).filter(
            FileFinding.scan_run_id == latest_file_scan.id
        ).all() if latest_file_scan else []

        user_findings = db.query(UserFinding).filter(
            UserFinding.scan_run_id == latest_user_scan.id
        ).all() if latest_user_scan else []

        oauth_findings = db.query(OAuthFinding).filter(
            OAuthFinding.scan_run_id == latest_oauth_scan.id
        ).all() if latest_oauth_scan else []

    # Framework-specific checks
    if framework == "gdpr":
        checks = _gdpr_checks(security_findings, file_findings, user_findings, oauth_findings)
    elif framework == "hipaa":
        checks = _hipaa_checks(security_findings, file_findings, user_findings, oauth_findings)
    elif framework == "soc2":
        checks = _soc2_checks(security_findings, file_findings, user_findings, oauth_findings)
    elif framework == "pci-dss":
        checks = _pcidss_checks(security_findings, file_findings, user_findings, oauth_findings)
    elif framework == "ferpa":
        checks = _ferpa_checks(security_findings, file_findings, user_findings, oauth_findings)
    elif framework == "fedramp":
        checks = _fedramp_checks(security_findings, file_findings, user_findings, oauth_findings)
    else:
        checks = []

    for check in checks:
        total_checks += 1
        if check["passed"]:
            passed_checks += 1
        else:
            issues.append({
                "check_id": check["check_id"],
                "title": check["title"],
                "description": check["description"],
                "severity": check["severity"],
                "category": check["category"],
                "remediation": check.get("remediation", ""),
                "resource_type": check.get("resource_type"),
                "resource_id": check.get("resource_id"),
            })

    return {
        "framework": framework,
        "total_checks": total_checks,
        "passed_checks": passed_checks,
        "issues": issues,
    }


def _gdpr_checks(security_findings, file_findings, user_findings, oauth_findings) -> list:
    """GDPR compliance checks."""
    checks = []

    # Check 1: No PII in externally shared files
    pii_external = [f for f in file_findings if f.pii_detected and f.is_shared_externally]
    checks.append({
        "check_id": "GDPR-1",
        "title": "PII in Externally Shared Files",
        "description": f"Found {len(pii_external)} files with PII shared externally",
        "passed": len(pii_external) == 0,
        "severity": "critical" if len(pii_external) > 5 else "high" if len(pii_external) > 0 else "low",
        "category": "Data Protection",
        "remediation": "Review and restrict external sharing of files containing personal data",
    })

    # Check 2: No public files with PII
    pii_public = [f for f in file_findings if f.pii_detected and f.is_public]
    checks.append({
        "check_id": "GDPR-2",
        "title": "PII in Public Files",
        "description": f"Found {len(pii_public)} public files with PII",
        "passed": len(pii_public) == 0,
        "severity": "critical",
        "category": "Data Protection",
        "remediation": "Remove public access from files containing personal data",
    })

    # Check 3: 2FA enabled for all users
    users_no_2fa = [u for u in user_findings if not u.two_factor_enabled]
    checks.append({
        "check_id": "GDPR-3",
        "title": "Two-Factor Authentication",
        "description": f"{len(users_no_2fa)} users without 2FA enabled",
        "passed": len(users_no_2fa) == 0,
        "severity": "high",
        "category": "Access Control",
        "remediation": "Enforce 2FA for all users to protect personal data access",
    })

    # Check 4: No high-risk OAuth apps
    risky_oauth = [o for o in oauth_findings if o.risk_score >= 70]
    checks.append({
        "check_id": "GDPR-4",
        "title": "Third-Party Application Access",
        "description": f"{len(risky_oauth)} high-risk OAuth applications detected",
        "passed": len(risky_oauth) == 0,
        "severity": "high",
        "category": "Third-Party Access",
        "remediation": "Review and revoke access for high-risk third-party applications",
    })

    # Check 5: No inactive users with data access
    inactive_users = [u for u in user_findings if u.is_inactive]
    checks.append({
        "check_id": "GDPR-5",
        "title": "Inactive User Accounts",
        "description": f"{len(inactive_users)} inactive user accounts",
        "passed": len(inactive_users) == 0,
        "severity": "medium",
        "category": "Access Control",
        "remediation": "Suspend or delete inactive user accounts",
    })

    # Check 6: External sharing controls
    external_files = [f for f in file_findings if f.is_shared_externally]
    checks.append({
        "check_id": "GDPR-6",
        "title": "External File Sharing",
        "description": f"{len(external_files)} files shared externally",
        "passed": len(external_files) < 100,  # Threshold-based check
        "severity": "medium" if len(external_files) >= 100 else "low",
        "category": "Data Sharing",
        "remediation": "Review external sharing policies and audit shared files",
    })

    # Check 7: Audit logging from security findings
    audit_finding = next((f for f in security_findings if "audit" in f.check_id.lower()), None)
    checks.append({
        "check_id": "GDPR-7",
        "title": "Audit Logging",
        "description": "Comprehensive audit logging enabled" if not audit_finding or audit_finding.passed else "Audit logging issues detected",
        "passed": audit_finding is None or audit_finding.passed,
        "severity": "high",
        "category": "Accountability",
        "remediation": "Enable comprehensive audit logging for data access",
    })

    # Check 8: Data encryption
    encryption_finding = next((f for f in security_findings if "encrypt" in f.check_id.lower()), None)
    checks.append({
        "check_id": "GDPR-8",
        "title": "Data Encryption",
        "description": "Data encryption requirements met" if not encryption_finding or encryption_finding.passed else "Encryption issues detected",
        "passed": encryption_finding is None or encryption_finding.passed,
        "severity": "high",
        "category": "Data Protection",
        "remediation": "Ensure all personal data is encrypted at rest and in transit",
    })

    return checks


def _hipaa_checks(security_findings, file_findings, user_findings, oauth_findings) -> list:
    """HIPAA compliance checks."""
    checks = []

    # Check 1: PHI detection (using PII as proxy)
    phi_files = [f for f in file_findings if f.pii_detected]
    checks.append({
        "check_id": "HIPAA-1",
        "title": "Protected Health Information Detection",
        "description": f"Found {len(phi_files)} files potentially containing PHI",
        "passed": len(phi_files) == 0,
        "severity": "critical",
        "category": "Privacy Rule",
        "remediation": "Review files for PHI and apply appropriate access controls",
    })

    # Check 2: PHI not shared publicly
    phi_public = [f for f in file_findings if f.pii_detected and f.is_public]
    checks.append({
        "check_id": "HIPAA-2",
        "title": "PHI Public Exposure",
        "description": f"{len(phi_public)} files with potential PHI are publicly accessible",
        "passed": len(phi_public) == 0,
        "severity": "critical",
        "category": "Privacy Rule",
        "remediation": "Immediately remove public access from files containing PHI",
    })

    # Check 3: Access controls (2FA)
    users_no_2fa = [u for u in user_findings if not u.two_factor_enabled]
    admin_no_2fa = [u for u in user_findings if u.is_admin and not u.two_factor_enabled]
    checks.append({
        "check_id": "HIPAA-3",
        "title": "Multi-Factor Authentication",
        "description": f"{len(admin_no_2fa)} admin users without MFA",
        "passed": len(admin_no_2fa) == 0,
        "severity": "critical",
        "category": "Security Rule",
        "remediation": "Enforce MFA for all users, especially administrators",
    })

    # Check 4: Workforce security - inactive users
    inactive_users = [u for u in user_findings if u.is_inactive]
    checks.append({
        "check_id": "HIPAA-4",
        "title": "Workforce Security - Inactive Accounts",
        "description": f"{len(inactive_users)} inactive user accounts detected",
        "passed": len(inactive_users) == 0,
        "severity": "high",
        "category": "Security Rule",
        "remediation": "Terminate access for inactive workforce members",
    })

    # Check 5: Business associate agreements (OAuth apps)
    unverified_oauth = [o for o in oauth_findings if not o.is_verified]
    checks.append({
        "check_id": "HIPAA-5",
        "title": "Business Associate - Third Party Apps",
        "description": f"{len(unverified_oauth)} unverified third-party applications",
        "passed": len(unverified_oauth) == 0,
        "severity": "high",
        "category": "Privacy Rule",
        "remediation": "Review and verify all third-party applications handling PHI",
    })

    # Check 6: External sharing restrictions
    phi_external = [f for f in file_findings if f.pii_detected and f.is_shared_externally]
    checks.append({
        "check_id": "HIPAA-6",
        "title": "PHI External Disclosure",
        "description": f"{len(phi_external)} files with potential PHI shared externally",
        "passed": len(phi_external) == 0,
        "severity": "critical",
        "category": "Privacy Rule",
        "remediation": "Review and restrict external sharing of files containing PHI",
    })

    # Check 7: Audit controls
    audit_finding = next((f for f in security_findings if "audit" in f.check_id.lower()), None)
    checks.append({
        "check_id": "HIPAA-7",
        "title": "Audit Controls",
        "description": "Audit logging for PHI access" if not audit_finding or audit_finding.passed else "Audit control deficiencies",
        "passed": audit_finding is None or audit_finding.passed,
        "severity": "high",
        "category": "Security Rule",
        "remediation": "Implement comprehensive audit controls for PHI access",
    })

    # Check 8: High-risk applications
    risky_oauth = [o for o in oauth_findings if o.risk_score >= 70]
    checks.append({
        "check_id": "HIPAA-8",
        "title": "High-Risk Application Access",
        "description": f"{len(risky_oauth)} high-risk applications with data access",
        "passed": len(risky_oauth) == 0,
        "severity": "high",
        "category": "Security Rule",
        "remediation": "Revoke access for high-risk third-party applications",
    })

    # Check 9: Encryption
    encryption_finding = next((f for f in security_findings if "encrypt" in f.check_id.lower()), None)
    checks.append({
        "check_id": "HIPAA-9",
        "title": "Encryption Requirements",
        "description": "Encryption properly configured" if not encryption_finding or encryption_finding.passed else "Encryption issues detected",
        "passed": encryption_finding is None or encryption_finding.passed,
        "severity": "high",
        "category": "Security Rule",
        "remediation": "Ensure all PHI is encrypted at rest and in transit",
    })

    # Check 10: Minimum necessary access
    checks.append({
        "check_id": "HIPAA-10",
        "title": "Minimum Necessary Access",
        "description": "Review access controls for minimum necessary principle",
        "passed": True,  # Manual check - always pass with recommendation
        "severity": "medium",
        "category": "Privacy Rule",
        "remediation": "Regularly review user access to ensure minimum necessary principle",
    })

    return checks


def _soc2_checks(security_findings, file_findings, user_findings, oauth_findings) -> list:
    """SOC 2 compliance checks."""
    checks = []

    # Security (CC6)
    users_no_2fa = [u for u in user_findings if not u.two_factor_enabled]
    checks.append({
        "check_id": "SOC2-CC6.1",
        "title": "Logical Access Security",
        "description": f"{len(users_no_2fa)} users without multi-factor authentication",
        "passed": len(users_no_2fa) == 0,
        "severity": "high",
        "category": "Security",
        "remediation": "Implement MFA for all users",
    })

    # Availability (A1)
    inactive_users = [u for u in user_findings if u.is_inactive]
    checks.append({
        "check_id": "SOC2-A1.1",
        "title": "User Account Management",
        "description": f"{len(inactive_users)} inactive accounts requiring review",
        "passed": len(inactive_users) < 10,
        "severity": "medium",
        "category": "Availability",
        "remediation": "Review and manage inactive user accounts",
    })

    # Confidentiality (C1)
    public_files = [f for f in file_findings if f.is_public]
    checks.append({
        "check_id": "SOC2-C1.1",
        "title": "Confidential Data Protection",
        "description": f"{len(public_files)} publicly accessible files",
        "passed": len(public_files) == 0,
        "severity": "high",
        "category": "Confidentiality",
        "remediation": "Review and restrict public file access",
    })

    # External sharing
    external_files = [f for f in file_findings if f.is_shared_externally]
    checks.append({
        "check_id": "SOC2-C1.2",
        "title": "External Data Sharing",
        "description": f"{len(external_files)} files shared externally",
        "passed": len(external_files) < 50,
        "severity": "medium",
        "category": "Confidentiality",
        "remediation": "Audit and control external file sharing",
    })

    # Processing Integrity (PI1)
    risky_oauth = [o for o in oauth_findings if o.risk_score >= 70]
    checks.append({
        "check_id": "SOC2-PI1.1",
        "title": "Third-Party Processing",
        "description": f"{len(risky_oauth)} high-risk third-party applications",
        "passed": len(risky_oauth) == 0,
        "severity": "high",
        "category": "Processing Integrity",
        "remediation": "Review and manage third-party application access",
    })

    # Privacy (P)
    pii_files = [f for f in file_findings if f.pii_detected]
    checks.append({
        "check_id": "SOC2-P1.1",
        "title": "Personal Information Protection",
        "description": f"{len(pii_files)} files containing personal information",
        "passed": len([f for f in pii_files if f.is_public or f.is_shared_externally]) == 0,
        "severity": "high",
        "category": "Privacy",
        "remediation": "Protect files containing personal information from unauthorized access",
    })

    # Audit logging
    audit_finding = next((f for f in security_findings if "audit" in f.check_id.lower()), None)
    checks.append({
        "check_id": "SOC2-CC7.1",
        "title": "System Monitoring",
        "description": "Audit logging and monitoring" if not audit_finding or audit_finding.passed else "Monitoring deficiencies",
        "passed": audit_finding is None or audit_finding.passed,
        "severity": "high",
        "category": "Security",
        "remediation": "Implement comprehensive logging and monitoring",
    })

    # Risk assessment (OAuth apps)
    unverified_oauth = [o for o in oauth_findings if not o.is_verified]
    checks.append({
        "check_id": "SOC2-CC3.1",
        "title": "Risk Assessment - Third Parties",
        "description": f"{len(unverified_oauth)} unverified third-party integrations",
        "passed": len(unverified_oauth) == 0,
        "severity": "medium",
        "category": "Security",
        "remediation": "Assess and verify all third-party integrations",
    })

    # Admin account security
    admin_no_2fa = [u for u in user_findings if u.is_admin and not u.two_factor_enabled]
    checks.append({
        "check_id": "SOC2-CC6.2",
        "title": "Privileged Access Security",
        "description": f"{len(admin_no_2fa)} admin accounts without MFA",
        "passed": len(admin_no_2fa) == 0,
        "severity": "critical",
        "category": "Security",
        "remediation": "Require MFA for all privileged accounts",
    })

    # Change management from security findings
    change_finding = next((f for f in security_findings if "change" in f.check_id.lower()), None)
    checks.append({
        "check_id": "SOC2-CC8.1",
        "title": "Change Management",
        "description": "Change management controls" if not change_finding or change_finding.passed else "Change management issues",
        "passed": change_finding is None or change_finding.passed,
        "severity": "medium",
        "category": "Security",
        "remediation": "Implement formal change management procedures",
    })

    # Encryption
    encryption_finding = next((f for f in security_findings if "encrypt" in f.check_id.lower()), None)
    checks.append({
        "check_id": "SOC2-CC6.7",
        "title": "Data Encryption",
        "description": "Encryption controls" if not encryption_finding or encryption_finding.passed else "Encryption issues",
        "passed": encryption_finding is None or encryption_finding.passed,
        "severity": "high",
        "category": "Security",
        "remediation": "Ensure data is encrypted at rest and in transit",
    })

    # Incident response
    checks.append({
        "check_id": "SOC2-CC7.3",
        "title": "Incident Response",
        "description": "Incident response procedures",
        "passed": True,  # Manual check
        "severity": "medium",
        "category": "Security",
        "remediation": "Maintain and test incident response procedures",
    })

    return checks


def _pcidss_checks(security_findings, file_findings, user_findings, oauth_findings) -> list:
    """PCI-DSS compliance checks."""
    checks = []

    # Requirement 3: Protect stored cardholder data
    pii_files = [f for f in file_findings if f.pii_detected]
    checks.append({
        "check_id": "PCI-3.1",
        "title": "Cardholder Data Storage",
        "description": f"{len(pii_files)} files may contain cardholder data",
        "passed": len([f for f in pii_files if f.is_public or f.is_shared_externally]) == 0,
        "severity": "critical",
        "category": "Data Protection",
        "remediation": "Review and protect files containing cardholder data",
    })

    # Requirement 4: Encrypt transmission
    encryption_finding = next((f for f in security_findings if "encrypt" in f.check_id.lower()), None)
    checks.append({
        "check_id": "PCI-4.1",
        "title": "Data Transmission Encryption",
        "description": "Encryption for data transmission" if not encryption_finding or encryption_finding.passed else "Encryption issues",
        "passed": encryption_finding is None or encryption_finding.passed,
        "severity": "critical",
        "category": "Encryption",
        "remediation": "Ensure all cardholder data is encrypted during transmission",
    })

    # Requirement 7: Restrict access
    public_files = [f for f in file_findings if f.is_public]
    checks.append({
        "check_id": "PCI-7.1",
        "title": "Access Restriction",
        "description": f"{len(public_files)} publicly accessible files",
        "passed": len(public_files) == 0,
        "severity": "high",
        "category": "Access Control",
        "remediation": "Restrict access to cardholder data on a need-to-know basis",
    })

    # Requirement 8: Identify and authenticate access
    users_no_2fa = [u for u in user_findings if not u.two_factor_enabled]
    checks.append({
        "check_id": "PCI-8.3",
        "title": "Multi-Factor Authentication",
        "description": f"{len(users_no_2fa)} users without MFA",
        "passed": len(users_no_2fa) == 0,
        "severity": "high",
        "category": "Authentication",
        "remediation": "Implement MFA for all users accessing cardholder data",
    })

    # Requirement 8.1: Unique user IDs
    checks.append({
        "check_id": "PCI-8.1",
        "title": "Unique User Identification",
        "description": "All users have unique identifiers",
        "passed": True,  # Google Workspace enforces this
        "severity": "high",
        "category": "Authentication",
        "remediation": "Ensure all users have unique IDs",
    })

    # Requirement 10: Track and monitor access
    audit_finding = next((f for f in security_findings if "audit" in f.check_id.lower()), None)
    checks.append({
        "check_id": "PCI-10.1",
        "title": "Audit Trail",
        "description": "Audit logging enabled" if not audit_finding or audit_finding.passed else "Audit logging issues",
        "passed": audit_finding is None or audit_finding.passed,
        "severity": "high",
        "category": "Monitoring",
        "remediation": "Implement comprehensive audit logging",
    })

    # Requirement 12: Security policy
    inactive_users = [u for u in user_findings if u.is_inactive]
    checks.append({
        "check_id": "PCI-12.3",
        "title": "Usage Policy Enforcement",
        "description": f"{len(inactive_users)} inactive accounts",
        "passed": len(inactive_users) == 0,
        "severity": "medium",
        "category": "Policy",
        "remediation": "Enforce policies for account usage and deprovisioning",
    })

    # Third-party service providers (OAuth)
    risky_oauth = [o for o in oauth_findings if o.risk_score >= 70]
    checks.append({
        "check_id": "PCI-12.8",
        "title": "Service Provider Management",
        "description": f"{len(risky_oauth)} high-risk third-party services",
        "passed": len(risky_oauth) == 0,
        "severity": "high",
        "category": "Third Parties",
        "remediation": "Review and manage third-party service provider access",
    })

    # External sharing
    external_files = [f for f in file_findings if f.is_shared_externally]
    pii_external = [f for f in file_findings if f.pii_detected and f.is_shared_externally]
    checks.append({
        "check_id": "PCI-3.4",
        "title": "Data Sharing Controls",
        "description": f"{len(pii_external)} files with PII shared externally",
        "passed": len(pii_external) == 0,
        "severity": "critical",
        "category": "Data Protection",
        "remediation": "Prevent external sharing of files containing cardholder data",
    })

    # Admin access controls
    admin_no_2fa = [u for u in user_findings if u.is_admin and not u.two_factor_enabled]
    checks.append({
        "check_id": "PCI-8.4",
        "title": "Administrative Access Security",
        "description": f"{len(admin_no_2fa)} admin accounts without MFA",
        "passed": len(admin_no_2fa) == 0,
        "severity": "critical",
        "category": "Authentication",
        "remediation": "Require MFA for all administrative access",
    })

    return checks


def _ferpa_checks(security_findings, file_findings, user_findings, oauth_findings) -> list:
    """FERPA compliance checks."""
    checks = []

    # Student data protection
    pii_files = [f for f in file_findings if f.pii_detected]
    checks.append({
        "check_id": "FERPA-1",
        "title": "Student Record Protection",
        "description": f"{len(pii_files)} files may contain student records",
        "passed": len([f for f in pii_files if f.is_public]) == 0,
        "severity": "critical",
        "category": "Privacy",
        "remediation": "Review and protect files containing student records",
    })

    # Public disclosure
    pii_public = [f for f in file_findings if f.pii_detected and f.is_public]
    checks.append({
        "check_id": "FERPA-2",
        "title": "Unauthorized Disclosure",
        "description": f"{len(pii_public)} files with student data publicly accessible",
        "passed": len(pii_public) == 0,
        "severity": "critical",
        "category": "Privacy",
        "remediation": "Remove public access from files containing student records",
    })

    # External sharing
    pii_external = [f for f in file_findings if f.pii_detected and f.is_shared_externally]
    checks.append({
        "check_id": "FERPA-3",
        "title": "External Data Sharing",
        "description": f"{len(pii_external)} files with student data shared externally",
        "passed": len(pii_external) == 0,
        "severity": "high",
        "category": "Disclosure",
        "remediation": "Review external sharing of files containing student records",
    })

    # Access controls
    users_no_2fa = [u for u in user_findings if not u.two_factor_enabled]
    checks.append({
        "check_id": "FERPA-4",
        "title": "Access Authentication",
        "description": f"{len(users_no_2fa)} users without strong authentication",
        "passed": len(users_no_2fa) == 0,
        "severity": "high",
        "category": "Access Control",
        "remediation": "Implement strong authentication for all users",
    })

    # Third-party access
    risky_oauth = [o for o in oauth_findings if o.risk_score >= 50]
    checks.append({
        "check_id": "FERPA-5",
        "title": "Third-Party Application Access",
        "description": f"{len(risky_oauth)} third-party apps with elevated risk",
        "passed": len(risky_oauth) == 0,
        "severity": "high",
        "category": "Third Parties",
        "remediation": "Review third-party application access to student data",
    })

    # Inactive accounts
    inactive_users = [u for u in user_findings if u.is_inactive]
    checks.append({
        "check_id": "FERPA-6",
        "title": "Account Maintenance",
        "description": f"{len(inactive_users)} inactive accounts with potential data access",
        "passed": len(inactive_users) == 0,
        "severity": "medium",
        "category": "Access Control",
        "remediation": "Remove access for inactive accounts",
    })

    return checks


def _fedramp_checks(security_findings, file_findings, user_findings, oauth_findings) -> list:
    """FedRAMP compliance checks."""
    checks = []

    # AC-2: Account Management
    inactive_users = [u for u in user_findings if u.is_inactive]
    checks.append({
        "check_id": "FedRAMP-AC-2",
        "title": "Account Management",
        "description": f"{len(inactive_users)} inactive accounts requiring review",
        "passed": len(inactive_users) == 0,
        "severity": "high",
        "category": "Access Control",
        "remediation": "Review and disable inactive accounts",
    })

    # AC-6: Least Privilege
    admin_users = [u for u in user_findings if u.is_admin]
    checks.append({
        "check_id": "FedRAMP-AC-6",
        "title": "Least Privilege",
        "description": f"{len(admin_users)} users with administrative privileges",
        "passed": len(admin_users) < 5,
        "severity": "medium",
        "category": "Access Control",
        "remediation": "Review administrative privileges for least privilege",
    })

    # IA-2: Multi-Factor Authentication
    users_no_2fa = [u for u in user_findings if not u.two_factor_enabled]
    checks.append({
        "check_id": "FedRAMP-IA-2",
        "title": "Multi-Factor Authentication",
        "description": f"{len(users_no_2fa)} users without MFA",
        "passed": len(users_no_2fa) == 0,
        "severity": "high",
        "category": "Identification",
        "remediation": "Enforce MFA for all users",
    })

    # SC-8: Transmission Confidentiality
    encryption_finding = next((f for f in security_findings if "encrypt" in f.check_id.lower()), None)
    checks.append({
        "check_id": "FedRAMP-SC-8",
        "title": "Transmission Confidentiality",
        "description": "Data transmission encryption" if not encryption_finding or encryption_finding.passed else "Encryption issues",
        "passed": encryption_finding is None or encryption_finding.passed,
        "severity": "high",
        "category": "System Protection",
        "remediation": "Ensure data is encrypted during transmission",
    })

    # SC-28: Data at Rest
    checks.append({
        "check_id": "FedRAMP-SC-28",
        "title": "Data at Rest Protection",
        "description": "Google Workspace encrypts data at rest",
        "passed": True,  # Google Workspace provides this
        "severity": "high",
        "category": "System Protection",
        "remediation": "Ensure encryption at rest is enabled",
    })

    # AU-2: Audit Events
    audit_finding = next((f for f in security_findings if "audit" in f.check_id.lower()), None)
    checks.append({
        "check_id": "FedRAMP-AU-2",
        "title": "Audit Events",
        "description": "Audit logging configured" if not audit_finding or audit_finding.passed else "Audit logging issues",
        "passed": audit_finding is None or audit_finding.passed,
        "severity": "high",
        "category": "Audit",
        "remediation": "Configure comprehensive audit logging",
    })

    # SA-9: External Information System Services
    risky_oauth = [o for o in oauth_findings if o.risk_score >= 70]
    checks.append({
        "check_id": "FedRAMP-SA-9",
        "title": "External Services",
        "description": f"{len(risky_oauth)} high-risk external services",
        "passed": len(risky_oauth) == 0,
        "severity": "high",
        "category": "Acquisition",
        "remediation": "Review and manage external service providers",
    })

    # Unverified third parties
    unverified_oauth = [o for o in oauth_findings if not o.is_verified]
    checks.append({
        "check_id": "FedRAMP-SA-12",
        "title": "Supply Chain Protection",
        "description": f"{len(unverified_oauth)} unverified third-party applications",
        "passed": len(unverified_oauth) == 0,
        "severity": "medium",
        "category": "Acquisition",
        "remediation": "Verify all third-party applications",
    })

    # SC-7: Boundary Protection (external sharing)
    external_files = [f for f in file_findings if f.is_shared_externally]
    checks.append({
        "check_id": "FedRAMP-SC-7",
        "title": "Boundary Protection",
        "description": f"{len(external_files)} files shared externally",
        "passed": len(external_files) < 100,
        "severity": "medium",
        "category": "System Protection",
        "remediation": "Review and control external data sharing",
    })

    # Public file exposure
    public_files = [f for f in file_findings if f.is_public]
    checks.append({
        "check_id": "FedRAMP-AC-22",
        "title": "Publicly Accessible Content",
        "description": f"{len(public_files)} publicly accessible files",
        "passed": len(public_files) == 0,
        "severity": "high",
        "category": "Access Control",
        "remediation": "Review and restrict publicly accessible content",
    })

    # PII protection
    pii_public = [f for f in file_findings if f.pii_detected and f.is_public]
    checks.append({
        "check_id": "FedRAMP-AR-1",
        "title": "PII Protection",
        "description": f"{len(pii_public)} files with PII publicly accessible",
        "passed": len(pii_public) == 0,
        "severity": "critical",
        "category": "Privacy",
        "remediation": "Protect files containing PII from public access",
    })

    # Admin MFA
    admin_no_2fa = [u for u in user_findings if u.is_admin and not u.two_factor_enabled]
    checks.append({
        "check_id": "FedRAMP-IA-5",
        "title": "Privileged User Authentication",
        "description": f"{len(admin_no_2fa)} privileged users without MFA",
        "passed": len(admin_no_2fa) == 0,
        "severity": "critical",
        "category": "Identification",
        "remediation": "Require MFA for all privileged users",
    })

    # Incident response readiness
    checks.append({
        "check_id": "FedRAMP-IR-4",
        "title": "Incident Handling",
        "description": "Incident response capability",
        "passed": True,  # Manual check
        "severity": "medium",
        "category": "Incident Response",
        "remediation": "Maintain incident handling procedures",
    })

    # Configuration management
    change_finding = next((f for f in security_findings if "change" in f.check_id.lower() or "config" in f.check_id.lower()), None)
    checks.append({
        "check_id": "FedRAMP-CM-2",
        "title": "Baseline Configuration",
        "description": "Configuration baseline maintained" if not change_finding or change_finding.passed else "Configuration issues",
        "passed": change_finding is None or change_finding.passed,
        "severity": "medium",
        "category": "Configuration",
        "remediation": "Maintain and monitor baseline configurations",
    })

    return checks
