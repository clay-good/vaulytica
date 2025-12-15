"""Findings API routes."""

import csv
import io
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Generic, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import desc, func, case
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, joinedload

from ..auth.security import get_current_user, require_domain_access
from ..core.cache import (
    get_cache,
    make_cache_key,
    invalidate_cache,
    CACHE_PREFIX_FINDINGS_SUMMARY,
    CACHE_TTL_FINDINGS_SUMMARY,
)
from ..db.database import get_db
from ..db.models import (
    User,
    ScanRun,
    SecurityFinding,
    FileFinding,
    UserFinding,
    OAuthFinding,
    AuditLog,
)
from .schemas import (
    SecurityFindingResponse,
    FileFindingResponse,
    UserFindingResponse,
    OAuthFindingResponse,
    FindingsSummaryResponse,
    FindingStatusUpdateRequest,
    FindingStatusUpdateResponse,
)

router = APIRouter()


# Pagination response wrapper
T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response with metadata."""
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int
    has_next: bool
    has_prev: bool


@router.get("/security")
async def get_security_findings(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    passed: Optional[bool] = Query(None, description="Filter by passed status"),
    framework: Optional[str] = Query(None, description="Filter by compliance framework"),
    days: int = Query(30, ge=1, le=365),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get security findings across all scans with pagination."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    query = (
        db.query(SecurityFinding)
        .join(ScanRun)
        .filter(SecurityFinding.detected_at >= cutoff_date)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    if severity:
        query = query.filter(SecurityFinding.severity == severity)
    if passed is not None:
        query = query.filter(SecurityFinding.passed == passed)
    if framework:
        query = query.filter(SecurityFinding.frameworks.contains([framework]))

    # Get total count
    total = query.count()

    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size

    findings = query.order_by(desc(SecurityFinding.detected_at)).offset(offset).limit(page_size).all()

    return {
        "items": [SecurityFindingResponse.model_validate(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


@router.get("/security/summary", response_model=FindingsSummaryResponse)
async def get_security_findings_summary(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get security findings summary using SQL aggregations with caching."""
    # Build cache key based on user context and parameters
    if current_user.is_superuser:
        user_context = "superuser"
    else:
        user_domains = sorted([ud.domain for ud in current_user.domains])
        user_context = ",".join(user_domains) if user_domains else "none"

    cache_key = make_cache_key(
        CACHE_PREFIX_FINDINGS_SUMMARY,
        domain=domain or "all",
        days=days,
        user_context=user_context,
    )

    # Check cache first
    cache = get_cache()
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        return FindingsSummaryResponse(**cached_result)

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Base query for domain filtering
    base_filter = SecurityFinding.detected_at >= cutoff_date

    if domain:
        require_domain_access(current_user, domain)
        domain_filter = ScanRun.domain_name == domain
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        domain_filter = ScanRun.domain_name.in_(user_domains)
    else:
        domain_filter = True  # No filter for superuser

    # Get total, passed, and failed counts in a single query
    counts = (
        db.query(
            func.count(SecurityFinding.id).label("total"),
            func.sum(case((SecurityFinding.passed == True, 1), else_=0)).label("passed"),
            func.sum(case((SecurityFinding.passed == False, 1), else_=0)).label("failed"),
        )
        .join(ScanRun)
        .filter(base_filter)
        .filter(domain_filter)
        .first()
    )

    total = counts.total or 0
    passed = counts.passed or 0
    failed = counts.failed or 0

    # Get counts by severity using SQL GROUP BY
    severity_counts = (
        db.query(
            func.coalesce(SecurityFinding.severity, "unknown").label("severity"),
            func.count(SecurityFinding.id).label("count"),
        )
        .join(ScanRun)
        .filter(base_filter)
        .filter(domain_filter)
        .group_by(func.coalesce(SecurityFinding.severity, "unknown"))
        .all()
    )

    by_severity = {row.severity: row.count for row in severity_counts}

    # For frameworks, we need to fetch findings that have frameworks (smaller subset)
    # and aggregate in Python since JSON arrays can't be efficiently grouped in SQL
    framework_findings = (
        db.query(SecurityFinding.frameworks)
        .join(ScanRun)
        .filter(base_filter)
        .filter(domain_filter)
        .filter(SecurityFinding.frameworks.isnot(None))
        .all()
    )

    by_framework = {}
    for (frameworks,) in framework_findings:
        if frameworks:
            for fw in frameworks:
                by_framework[fw] = by_framework.get(fw, 0) + 1

    result = {
        "total_findings": total,
        "passed": passed,
        "failed": failed,
        "by_severity": by_severity,
        "by_framework": by_framework,
    }

    # Cache the result
    cache.set(cache_key, result, CACHE_TTL_FINDINGS_SUMMARY)

    return FindingsSummaryResponse(**result)


@router.get("/files/high-risk")
async def get_high_risk_files(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    min_risk_score: int = Query(70, ge=0, le=100),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get high-risk file findings with pagination."""
    query = (
        db.query(FileFinding)
        .join(ScanRun)
        .filter(FileFinding.risk_score >= min_risk_score)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    total = query.count()
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size

    findings = query.order_by(desc(FileFinding.risk_score)).offset(offset).limit(page_size).all()

    return {
        "items": [FileFindingResponse.model_validate(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


@router.get("/files/public")
async def get_public_files(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get publicly shared file findings with pagination."""
    query = (
        db.query(FileFinding)
        .join(ScanRun)
        .filter(FileFinding.is_public == True)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    total = query.count()
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size

    findings = query.order_by(desc(FileFinding.detected_at)).offset(offset).limit(page_size).all()

    return {
        "items": [FileFindingResponse.model_validate(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


@router.get("/files/pii")
async def get_files_with_pii(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get files with detected PII with pagination."""
    query = (
        db.query(FileFinding)
        .join(ScanRun)
        .filter(FileFinding.pii_detected == True)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    total = query.count()
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size

    findings = query.order_by(desc(FileFinding.risk_score)).offset(offset).limit(page_size).all()

    return {
        "items": [FileFindingResponse.model_validate(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


@router.get("/users/inactive")
async def get_inactive_users(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    min_days: int = Query(90, ge=1),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get inactive user findings with pagination."""
    query = (
        db.query(UserFinding)
        .join(ScanRun)
        .filter(UserFinding.is_inactive == True)
        .filter(UserFinding.days_since_last_login >= min_days)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    total = query.count()
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size

    findings = query.order_by(desc(UserFinding.days_since_last_login)).offset(offset).limit(page_size).all()

    return {
        "items": [UserFindingResponse.model_validate(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


@router.get("/users/no-2fa")
async def get_users_without_2fa(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    admins_only: bool = Query(False, description="Filter to admins only"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get users without 2FA enabled with pagination."""
    query = (
        db.query(UserFinding)
        .join(ScanRun)
        .filter(UserFinding.two_factor_enabled == False)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    if admins_only:
        query = query.filter(UserFinding.is_admin == True)

    total = query.count()
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size

    findings = query.order_by(desc(UserFinding.risk_score)).offset(offset).limit(page_size).all()

    return {
        "items": [UserFindingResponse.model_validate(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


@router.get("/oauth/risky")
async def get_risky_oauth_apps(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    min_risk_score: int = Query(50, ge=0, le=100),
    unverified_only: bool = Query(False, description="Filter to unverified apps"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get risky OAuth app findings with pagination."""
    query = (
        db.query(OAuthFinding)
        .join(ScanRun)
        .filter(OAuthFinding.risk_score >= min_risk_score)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    if unverified_only:
        query = query.filter(OAuthFinding.is_verified == False)

    total = query.count()
    total_pages = (total + page_size - 1) // page_size
    offset = (page - 1) * page_size

    findings = query.order_by(desc(OAuthFinding.risk_score)).offset(offset).limit(page_size).all()

    return {
        "items": [OAuthFindingResponse.model_validate(f) for f in findings],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_prev": page > 1,
    }


# Export Endpoints
@router.get("/export/security")
async def export_security_findings(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    passed: Optional[bool] = Query(None, description="Filter by passed status"),
    days: int = Query(30, ge=1, le=365),
    format: str = Query("csv", description="Export format: csv or json"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export security findings as CSV or JSON."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    query = (
        db.query(SecurityFinding)
        .join(ScanRun)
        .filter(SecurityFinding.detected_at >= cutoff_date)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    if severity:
        query = query.filter(SecurityFinding.severity == severity)
    if passed is not None:
        query = query.filter(SecurityFinding.passed == passed)

    findings = query.order_by(desc(SecurityFinding.detected_at)).all()

    if format == "json":
        data = [
            {
                "id": f.id,
                "check_id": f.check_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "passed": f.passed,
                "current_value": f.current_value,
                "expected_value": f.expected_value,
                "impact": f.impact,
                "remediation": f.remediation,
                "frameworks": f.frameworks,
                "detected_at": f.detected_at.isoformat() if f.detected_at else None,
            }
            for f in findings
        ]
        return StreamingResponse(
            io.BytesIO(json.dumps(data, indent=2).encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=security_findings_{datetime.utcnow().strftime('%Y%m%d')}.json"}
        )
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Check ID", "Title", "Description", "Severity", "Passed", "Impact", "Remediation", "Frameworks", "Detected At"])
        for f in findings:
            writer.writerow([
                f.id,
                f.check_id,
                f.title,
                f.description or "",
                f.severity,
                "Yes" if f.passed else "No",
                f.impact or "",
                f.remediation or "",
                ", ".join(f.frameworks) if f.frameworks else "",
                f.detected_at.isoformat() if f.detected_at else "",
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=security_findings_{datetime.utcnow().strftime('%Y%m%d')}.csv"}
        )


@router.get("/export/files")
async def export_file_findings(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    min_risk_score: int = Query(0, ge=0, le=100),
    public_only: bool = Query(False, description="Filter to public files only"),
    pii_only: bool = Query(False, description="Filter to files with PII only"),
    format: str = Query("csv", description="Export format: csv or json"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export file findings as CSV or JSON."""
    query = (
        db.query(FileFinding)
        .join(ScanRun)
        .filter(FileFinding.risk_score >= min_risk_score)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    if public_only:
        query = query.filter(FileFinding.is_public == True)
    if pii_only:
        query = query.filter(FileFinding.pii_detected == True)

    findings = query.order_by(desc(FileFinding.risk_score)).limit(1000).all()

    if format == "json":
        data = [
            {
                "id": f.id,
                "file_id": f.file_id,
                "file_name": f.file_name,
                "owner_email": f.owner_email,
                "mime_type": f.mime_type,
                "file_size": f.file_size,
                "is_public": f.is_public,
                "is_shared_externally": f.is_shared_externally,
                "external_domains": f.external_domains,
                "risk_score": f.risk_score,
                "pii_detected": f.pii_detected,
                "pii_types": f.pii_types,
                "web_view_link": f.web_view_link,
                "detected_at": f.detected_at.isoformat() if f.detected_at else None,
            }
            for f in findings
        ]
        return StreamingResponse(
            io.BytesIO(json.dumps(data, indent=2).encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=file_findings_{datetime.utcnow().strftime('%Y%m%d')}.json"}
        )
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "File ID", "File Name", "Owner Email", "MIME Type", "Size", "Public", "External", "Risk Score", "PII Detected", "PII Types", "Link", "Detected At"])
        for f in findings:
            writer.writerow([
                f.id,
                f.file_id,
                f.file_name,
                f.owner_email or "",
                f.mime_type or "",
                f.file_size or "",
                "Yes" if f.is_public else "No",
                "Yes" if f.is_shared_externally else "No",
                f.risk_score,
                "Yes" if f.pii_detected else "No",
                ", ".join(f.pii_types) if f.pii_types else "",
                f.web_view_link or "",
                f.detected_at.isoformat() if f.detected_at else "",
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=file_findings_{datetime.utcnow().strftime('%Y%m%d')}.csv"}
        )


@router.get("/export/users")
async def export_user_findings(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    inactive_only: bool = Query(False, description="Filter to inactive users only"),
    no_2fa_only: bool = Query(False, description="Filter to users without 2FA"),
    format: str = Query("csv", description="Export format: csv or json"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export user findings as CSV or JSON."""
    query = db.query(UserFinding).join(ScanRun)

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    if inactive_only:
        query = query.filter(UserFinding.is_inactive == True)
    if no_2fa_only:
        query = query.filter(UserFinding.two_factor_enabled == False)

    findings = query.order_by(desc(UserFinding.risk_score)).limit(1000).all()

    if format == "json":
        data = [
            {
                "id": f.id,
                "user_id": f.user_id,
                "email": f.email,
                "full_name": f.full_name,
                "is_admin": f.is_admin,
                "is_suspended": f.is_suspended,
                "last_login_time": f.last_login_time.isoformat() if f.last_login_time else None,
                "two_factor_enabled": f.two_factor_enabled,
                "org_unit_path": f.org_unit_path,
                "is_inactive": f.is_inactive,
                "days_since_last_login": f.days_since_last_login,
                "risk_score": f.risk_score,
                "risk_factors": f.risk_factors,
                "detected_at": f.detected_at.isoformat() if f.detected_at else None,
            }
            for f in findings
        ]
        return StreamingResponse(
            io.BytesIO(json.dumps(data, indent=2).encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=user_findings_{datetime.utcnow().strftime('%Y%m%d')}.json"}
        )
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "User ID", "Email", "Full Name", "Admin", "Suspended", "Last Login", "2FA Enabled", "Org Unit", "Inactive", "Days Since Login", "Risk Score", "Detected At"])
        for f in findings:
            writer.writerow([
                f.id,
                f.user_id,
                f.email,
                f.full_name or "",
                "Yes" if f.is_admin else "No",
                "Yes" if f.is_suspended else "No",
                f.last_login_time.isoformat() if f.last_login_time else "",
                "Yes" if f.two_factor_enabled else "No",
                f.org_unit_path or "",
                "Yes" if f.is_inactive else "No",
                f.days_since_last_login or "",
                f.risk_score,
                f.detected_at.isoformat() if f.detected_at else "",
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=user_findings_{datetime.utcnow().strftime('%Y%m%d')}.csv"}
        )


@router.get("/export/oauth")
async def export_oauth_findings(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    min_risk_score: int = Query(0, ge=0, le=100),
    unverified_only: bool = Query(False, description="Filter to unverified apps"),
    format: str = Query("csv", description="Export format: csv or json"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export OAuth findings as CSV or JSON."""
    query = (
        db.query(OAuthFinding)
        .join(ScanRun)
        .filter(OAuthFinding.risk_score >= min_risk_score)
    )

    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    if unverified_only:
        query = query.filter(OAuthFinding.is_verified == False)

    findings = query.order_by(desc(OAuthFinding.risk_score)).limit(1000).all()

    if format == "json":
        data = [
            {
                "id": f.id,
                "client_id": f.client_id,
                "display_text": f.display_text,
                "scopes": f.scopes,
                "user_count": f.user_count,
                "users": f.users,
                "risk_score": f.risk_score,
                "is_verified": f.is_verified,
                "is_google_app": f.is_google_app,
                "is_internal": f.is_internal,
                "risk_factors": f.risk_factors,
                "detected_at": f.detected_at.isoformat() if f.detected_at else None,
            }
            for f in findings
        ]
        return StreamingResponse(
            io.BytesIO(json.dumps(data, indent=2).encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=oauth_findings_{datetime.utcnow().strftime('%Y%m%d')}.json"}
        )
    else:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["ID", "Client ID", "Display Name", "User Count", "Risk Score", "Verified", "Google App", "Internal", "Scopes", "Detected At"])
        for f in findings:
            writer.writerow([
                f.id,
                f.client_id,
                f.display_text or "",
                f.user_count,
                f.risk_score,
                "Yes" if f.is_verified else "No",
                "Yes" if f.is_google_app else "No",
                "Yes" if f.is_internal else "No",
                ", ".join(f.scopes) if f.scopes else "",
                f.detected_at.isoformat() if f.detected_at else "",
            ])
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=oauth_findings_{datetime.utcnow().strftime('%Y%m%d')}.csv"}
        )


# Finding Status Update Endpoint
@router.patch("/security/{finding_id}/status", response_model=FindingStatusUpdateResponse)
async def update_finding_status(
    finding_id: int,
    request: FindingStatusUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update the status of a security finding.

    Valid statuses: open, acknowledged, resolved, false_positive
    """
    # Validate status
    valid_statuses = ["open", "acknowledged", "resolved", "false_positive"]
    if request.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
        )

    # Get the finding with scan_run eagerly loaded in single query
    finding = (
        db.query(SecurityFinding)
        .options(joinedload(SecurityFinding.scan_run))
        .filter(SecurityFinding.id == finding_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Access scan_run from the joined result
    scan = finding.scan_run
    if not scan:
        raise HTTPException(status_code=404, detail="Associated scan not found")

    require_domain_access(current_user, scan.domain_name)

    # Store the old status for audit log
    old_status = finding.status

    try:
        # Update the finding status
        finding.status = request.status
        finding.status_notes = request.notes
        finding.status_updated_at = datetime.utcnow()
        finding.status_updated_by = current_user.email
        db.commit()

        # Invalidate findings summary cache since status changed
        invalidate_cache(CACHE_PREFIX_FINDINGS_SUMMARY)

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="finding_status_updated",
            resource_type="security_finding",
            resource_id=str(finding_id),
            details={
                "old_status": old_status,
                "new_status": request.status,
                "notes": request.notes,
                "domain": scan.domain_name,
                "finding_title": finding.title,
            },
        )
        db.add(audit_log)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update finding status")

    return FindingStatusUpdateResponse(
        id=finding_id,
        status=request.status,
        updated_at=finding.status_updated_at,
        message=f"Finding status updated to '{request.status}' successfully.",
    )


@router.get("/security/{finding_id}", response_model=SecurityFindingResponse)
async def get_security_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific security finding by ID."""
    # Use joinedload to fetch finding and scan in a single query
    finding = (
        db.query(SecurityFinding)
        .options(joinedload(SecurityFinding.scan_run))
        .filter(SecurityFinding.id == finding_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Access scan_run from the joined result
    scan = finding.scan_run
    if not scan:
        raise HTTPException(status_code=404, detail="Associated scan not found")

    require_domain_access(current_user, scan.domain_name)

    return SecurityFindingResponse.model_validate(finding)


@router.get("/files/{finding_id}", response_model=FileFindingResponse)
async def get_file_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific file finding by ID."""
    finding = (
        db.query(FileFinding)
        .options(joinedload(FileFinding.scan_run))
        .filter(FileFinding.id == finding_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    scan = finding.scan_run
    if not scan:
        raise HTTPException(status_code=404, detail="Associated scan not found")

    require_domain_access(current_user, scan.domain_name)

    return FileFindingResponse.model_validate(finding)


@router.get("/users/{finding_id}", response_model=UserFindingResponse)
async def get_user_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific user finding by ID."""
    finding = (
        db.query(UserFinding)
        .options(joinedload(UserFinding.scan_run))
        .filter(UserFinding.id == finding_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    scan = finding.scan_run
    if not scan:
        raise HTTPException(status_code=404, detail="Associated scan not found")

    require_domain_access(current_user, scan.domain_name)

    return UserFindingResponse.model_validate(finding)


@router.get("/oauth/{finding_id}", response_model=OAuthFindingResponse)
async def get_oauth_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a specific OAuth finding by ID."""
    finding = (
        db.query(OAuthFinding)
        .options(joinedload(OAuthFinding.scan_run))
        .filter(OAuthFinding.id == finding_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    scan = finding.scan_run
    if not scan:
        raise HTTPException(status_code=404, detail="Associated scan not found")

    require_domain_access(current_user, scan.domain_name)

    return OAuthFindingResponse.model_validate(finding)
