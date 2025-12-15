"""Scan API routes."""

from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, case
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..auth.security import get_current_user, require_domain_access, require_domain_role, Role
from ..core.cache import (
    get_cache,
    make_cache_key,
    invalidate_cache,
    CACHE_PREFIX_SCAN_STATS,
    CACHE_TTL_SCAN_STATS,
)
from ..core.websocket import broadcast_scan_progress, broadcast_scan_status, broadcast_scan_completed, broadcast_scan_failed
from ..db.database import get_db
from ..db.models import User, ScanRun, Domain, AuditLog, SecurityFinding, FileFinding, UserFinding, OAuthFinding
from .schemas import (
    ScanRunResponse,
    ScanRunDetailResponse,
    ScanStatsResponse,
    SecurityFindingResponse,
    FileFindingResponse,
    UserFindingResponse,
    OAuthFindingResponse,
    TriggerScanRequest,
    TriggerScanResponse,
    CancelScanResponse,
)

router = APIRouter()


@router.get("/recent", response_model=List[ScanRunResponse])
async def get_recent_scans(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    scan_type: Optional[str] = Query(None, description="Filter by scan type"),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get recent scan runs."""
    query = db.query(ScanRun).order_by(desc(ScanRun.start_time))

    # Filter by domain if specified
    if domain:
        require_domain_access(current_user, domain)
        query = query.filter(ScanRun.domain_name == domain)
    elif not current_user.is_superuser:
        # Only show domains user has access to
        user_domains = [ud.domain for ud in current_user.domains]
        query = query.filter(ScanRun.domain_name.in_(user_domains))

    # Filter by scan type if specified
    if scan_type:
        query = query.filter(ScanRun.scan_type == scan_type)

    scans = query.limit(limit).all()
    return [ScanRunResponse.model_validate(scan) for scan in scans]


@router.get("/stats", response_model=ScanStatsResponse)
async def get_scan_stats(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get scan statistics for dashboard using SQL aggregations with caching."""
    # Build cache key based on user context and parameters
    # Superusers see all data, regular users see their accessible domains
    if current_user.is_superuser:
        user_context = "superuser"
    else:
        user_domains = sorted([ud.domain for ud in current_user.domains])
        user_context = ",".join(user_domains) if user_domains else "none"

    cache_key = make_cache_key(
        CACHE_PREFIX_SCAN_STATS,
        domain=domain or "all",
        days=days,
        user_context=user_context,
    )

    # Check cache first
    cache = get_cache()
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        return ScanStatsResponse(**cached_result)

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Build domain filter
    if domain:
        require_domain_access(current_user, domain)
        domain_filter = ScanRun.domain_name == domain
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        domain_filter = ScanRun.domain_name.in_(user_domains)
    else:
        domain_filter = True  # No filter for superuser

    # Calculate all statistics in a single SQL query
    stats = (
        db.query(
            func.count(ScanRun.id).label("total_scans"),
            func.sum(case((ScanRun.status == "completed", 1), else_=0)).label("completed_scans"),
            func.sum(case((ScanRun.status == "failed", 1), else_=0)).label("failed_scans"),
            func.coalesce(func.sum(ScanRun.issues_found), 0).label("total_issues"),
            func.coalesce(func.sum(ScanRun.high_risk_count), 0).label("high_risk_total"),
            func.coalesce(func.sum(ScanRun.medium_risk_count), 0).label("medium_risk_total"),
            func.coalesce(func.sum(ScanRun.low_risk_count), 0).label("low_risk_total"),
        )
        .filter(ScanRun.start_time >= cutoff_date)
        .filter(domain_filter)
        .first()
    )

    total_scans = stats.total_scans or 0
    completed_scans = stats.completed_scans or 0
    failed_scans = stats.failed_scans or 0
    total_issues = stats.total_issues or 0
    high_risk_total = stats.high_risk_total or 0
    medium_risk_total = stats.medium_risk_total or 0
    low_risk_total = stats.low_risk_total or 0

    result = {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "total_issues": total_issues,
        "high_risk_total": high_risk_total,
        "medium_risk_total": medium_risk_total,
        "low_risk_total": low_risk_total,
        "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0,
        "period_days": days,
    }

    # Cache the result
    cache.set(cache_key, result, CACHE_TTL_SCAN_STATS)

    return ScanStatsResponse(**result)


@router.get("/compare")
async def compare_scans(
    scan_id_1: int = Query(..., description="First scan ID (older)"),
    scan_id_2: int = Query(..., description="Second scan ID (newer)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compare findings between two scan runs.

    Returns the differences including:
    - New findings in the newer scan
    - Resolved findings (in old scan but not in new)
    - Unchanged findings
    - Summary statistics
    """
    # Get both scans
    scan1 = db.query(ScanRun).filter(ScanRun.id == scan_id_1).first()
    scan2 = db.query(ScanRun).filter(ScanRun.id == scan_id_2).first()

    if not scan1 or not scan2:
        raise HTTPException(status_code=404, detail="One or both scans not found")

    # Verify same domain
    if scan1.domain_name != scan2.domain_name:
        raise HTTPException(
            status_code=400,
            detail="Can only compare scans from the same domain"
        )

    # Verify access
    require_domain_access(current_user, scan1.domain_name)

    # Verify same scan type
    if scan1.scan_type != scan2.scan_type:
        raise HTTPException(
            status_code=400,
            detail="Can only compare scans of the same type"
        )

    # Determine which scan is older/newer
    if scan1.start_time > scan2.start_time:
        old_scan, new_scan = scan2, scan1
    else:
        old_scan, new_scan = scan1, scan2

    comparison = {
        "old_scan": {
            "id": old_scan.id,
            "scan_type": old_scan.scan_type,
            "status": old_scan.status,
            "start_time": old_scan.start_time.isoformat() if old_scan.start_time else None,
            "end_time": old_scan.end_time.isoformat() if old_scan.end_time else None,
            "issues_found": old_scan.issues_found,
        },
        "new_scan": {
            "id": new_scan.id,
            "scan_type": new_scan.scan_type,
            "status": new_scan.status,
            "start_time": new_scan.start_time.isoformat() if new_scan.start_time else None,
            "end_time": new_scan.end_time.isoformat() if new_scan.end_time else None,
            "issues_found": new_scan.issues_found,
        },
        "domain": old_scan.domain_name,
        "scan_type": old_scan.scan_type,
        "new_issues": [],
        "resolved_issues": [],
        "unchanged_count": 0,
        "summary": {},
    }

    scan_type = old_scan.scan_type

    # Compare based on scan type
    if scan_type == "posture":
        old_findings = {f.check_id: f for f in db.query(SecurityFinding).filter(
            SecurityFinding.scan_run_id == old_scan.id
        ).all()}
        new_findings = {f.check_id: f for f in db.query(SecurityFinding).filter(
            SecurityFinding.scan_run_id == new_scan.id
        ).all()}

        # Find new issues (failed in new, not failed or not present in old)
        for check_id, finding in new_findings.items():
            if not finding.passed:
                old_finding = old_findings.get(check_id)
                if not old_finding or old_finding.passed:
                    comparison["new_issues"].append({
                        "check_id": finding.check_id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "category": finding.resource_type,  # Use resource_type as category
                    })

        # Find resolved issues (failed in old, passed or not present in new)
        for check_id, finding in old_findings.items():
            if not finding.passed:
                new_finding = new_findings.get(check_id)
                if not new_finding or new_finding.passed:
                    comparison["resolved_issues"].append({
                        "check_id": finding.check_id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "category": finding.resource_type,
                    })

        # Count unchanged
        unchanged = 0
        for check_id in set(old_findings.keys()) & set(new_findings.keys()):
            if old_findings[check_id].passed == new_findings[check_id].passed:
                unchanged += 1
        comparison["unchanged_count"] = unchanged

    elif scan_type == "files":
        old_findings = {f.file_id: f for f in db.query(FileFinding).filter(
            FileFinding.scan_run_id == old_scan.id
        ).all()}
        new_findings = {f.file_id: f for f in db.query(FileFinding).filter(
            FileFinding.scan_run_id == new_scan.id
        ).all()}

        # New risky files
        for file_id, finding in new_findings.items():
            if finding.risk_score >= 50:  # Consider risky if score >= 50
                old_finding = old_findings.get(file_id)
                if not old_finding or old_finding.risk_score < 50:
                    comparison["new_issues"].append({
                        "file_id": finding.file_id,
                        "file_name": finding.file_name,
                        "risk_score": finding.risk_score,
                        "is_public": finding.is_public,
                        "is_shared_externally": finding.is_shared_externally,
                    })

        # Resolved (was risky, now not risky or removed)
        for file_id, finding in old_findings.items():
            if finding.risk_score >= 50:
                new_finding = new_findings.get(file_id)
                if not new_finding or new_finding.risk_score < 50:
                    comparison["resolved_issues"].append({
                        "file_id": finding.file_id,
                        "file_name": finding.file_name,
                        "old_risk_score": finding.risk_score,
                    })

        comparison["unchanged_count"] = len(
            set(old_findings.keys()) & set(new_findings.keys())
        ) - len(comparison["new_issues"]) - len(comparison["resolved_issues"])

    elif scan_type == "users":
        old_findings = {f.email: f for f in db.query(UserFinding).filter(
            UserFinding.scan_run_id == old_scan.id
        ).all()}
        new_findings = {f.email: f for f in db.query(UserFinding).filter(
            UserFinding.scan_run_id == new_scan.id
        ).all()}

        # New issues (inactive or no 2FA)
        for email, finding in new_findings.items():
            is_issue = finding.is_inactive or not finding.two_factor_enabled
            old_finding = old_findings.get(email)
            was_issue = old_finding and (old_finding.is_inactive or not old_finding.two_factor_enabled)
            if is_issue and not was_issue:
                comparison["new_issues"].append({
                    "email": finding.email,
                    "display_name": finding.full_name,
                    "is_inactive": finding.is_inactive,
                    "two_factor_enabled": finding.two_factor_enabled,
                })

        # Resolved issues
        for email, finding in old_findings.items():
            was_issue = finding.is_inactive or not finding.two_factor_enabled
            new_finding = new_findings.get(email)
            is_issue = new_finding and (new_finding.is_inactive or not new_finding.two_factor_enabled)
            if was_issue and not is_issue:
                comparison["resolved_issues"].append({
                    "email": finding.email,
                    "display_name": finding.full_name,
                })

        comparison["unchanged_count"] = len(new_findings) - len(comparison["new_issues"])

    elif scan_type == "oauth":
        old_findings = {f.client_id: f for f in db.query(OAuthFinding).filter(
            OAuthFinding.scan_run_id == old_scan.id
        ).all()}
        new_findings = {f.client_id: f for f in db.query(OAuthFinding).filter(
            OAuthFinding.scan_run_id == new_scan.id
        ).all()}

        # New risky apps
        for client_id, finding in new_findings.items():
            if finding.risk_score >= 50:
                old_finding = old_findings.get(client_id)
                if not old_finding or old_finding.risk_score < 50:
                    comparison["new_issues"].append({
                        "client_id": finding.client_id,
                        "display_text": finding.display_text,
                        "risk_score": finding.risk_score,
                        "is_verified": finding.is_verified,
                        "scopes_count": len(finding.scopes) if finding.scopes else 0,
                    })

        # Resolved (was risky, now not or removed)
        for client_id, finding in old_findings.items():
            if finding.risk_score >= 50:
                new_finding = new_findings.get(client_id)
                if not new_finding or new_finding.risk_score < 50:
                    comparison["resolved_issues"].append({
                        "client_id": finding.client_id,
                        "display_text": finding.display_text,
                        "old_risk_score": finding.risk_score,
                    })

        comparison["unchanged_count"] = len(new_findings) - len(comparison["new_issues"])

    # Build summary
    comparison["summary"] = {
        "new_issues_count": len(comparison["new_issues"]),
        "resolved_issues_count": len(comparison["resolved_issues"]),
        "unchanged_count": comparison["unchanged_count"],
        "old_total_issues": old_scan.issues_found or 0,
        "new_total_issues": new_scan.issues_found or 0,
        "change_percentage": round(
            ((new_scan.issues_found or 0) - (old_scan.issues_found or 0)) / max(old_scan.issues_found or 1, 1) * 100, 2
        ),
    }

    return comparison


@router.get("/{scan_id}", response_model=ScanRunDetailResponse)
async def get_scan_details(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get detailed information about a specific scan."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    require_domain_access(current_user, scan.domain_name)

    return ScanRunDetailResponse.model_validate(scan)


@router.get("/{scan_id}/findings/security", response_model=List[SecurityFindingResponse])
async def get_scan_security_findings(
    scan_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    passed: Optional[bool] = Query(None, description="Filter by passed status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get security findings for a specific scan."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    require_domain_access(current_user, scan.domain_name)

    query = db.query(SecurityFinding).filter(SecurityFinding.scan_run_id == scan_id)

    if severity:
        query = query.filter(SecurityFinding.severity == severity)
    if passed is not None:
        query = query.filter(SecurityFinding.passed == passed)

    findings = query.order_by(SecurityFinding.severity).all()
    return [SecurityFindingResponse.model_validate(f) for f in findings]


@router.get("/{scan_id}/findings/files", response_model=List[FileFindingResponse])
async def get_scan_file_findings(
    scan_id: int,
    public_only: bool = Query(False, description="Filter to public files only"),
    external_only: bool = Query(False, description="Filter to externally shared only"),
    min_risk_score: int = Query(0, ge=0, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get file findings for a specific scan."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    require_domain_access(current_user, scan.domain_name)

    query = db.query(FileFinding).filter(FileFinding.scan_run_id == scan_id)

    if public_only:
        query = query.filter(FileFinding.is_public == True)
    if external_only:
        query = query.filter(FileFinding.is_shared_externally == True)
    if min_risk_score > 0:
        query = query.filter(FileFinding.risk_score >= min_risk_score)

    findings = query.order_by(desc(FileFinding.risk_score)).all()
    return [FileFindingResponse.model_validate(f) for f in findings]


@router.get("/{scan_id}/findings/users", response_model=List[UserFindingResponse])
async def get_scan_user_findings(
    scan_id: int,
    inactive_only: bool = Query(False, description="Filter to inactive users only"),
    no_2fa_only: bool = Query(False, description="Filter to users without 2FA"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get user findings for a specific scan."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    require_domain_access(current_user, scan.domain_name)

    query = db.query(UserFinding).filter(UserFinding.scan_run_id == scan_id)

    if inactive_only:
        query = query.filter(UserFinding.is_inactive == True)
    if no_2fa_only:
        query = query.filter(UserFinding.two_factor_enabled == False)

    findings = query.order_by(desc(UserFinding.risk_score)).all()
    return [UserFindingResponse.model_validate(f) for f in findings]


@router.get("/{scan_id}/findings/oauth", response_model=List[OAuthFindingResponse])
async def get_scan_oauth_findings(
    scan_id: int,
    unverified_only: bool = Query(False, description="Filter to unverified apps only"),
    min_risk_score: int = Query(0, ge=0, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get OAuth app findings for a specific scan."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    require_domain_access(current_user, scan.domain_name)

    query = db.query(OAuthFinding).filter(OAuthFinding.scan_run_id == scan_id)

    if unverified_only:
        query = query.filter(OAuthFinding.is_verified == False)
    if min_risk_score > 0:
        query = query.filter(OAuthFinding.risk_score >= min_risk_score)

    findings = query.order_by(desc(OAuthFinding.risk_score)).all()
    return [OAuthFindingResponse.model_validate(f) for f in findings]


@router.post("/trigger", response_model=TriggerScanResponse)
async def trigger_scan(
    request: TriggerScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Trigger a new scan for a domain.

    Valid scan types: files, users, oauth, posture, all
    """
    # Validate scan type
    valid_scan_types = ["files", "users", "oauth", "posture", "all"]
    if request.scan_type not in valid_scan_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan type. Must be one of: {', '.join(valid_scan_types)}"
        )

    # Verify user has EDITOR role for this domain (required to trigger scans)
    require_domain_role(current_user, request.domain_name, Role.EDITOR)

    # Check if domain exists and is active
    domain = db.query(Domain).filter(Domain.name == request.domain_name).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    if not domain.is_active:
        raise HTTPException(status_code=400, detail="Domain is not active")

    # Check for any running scans on this domain
    running_scan = db.query(ScanRun).filter(
        ScanRun.domain_name == request.domain_name,
        ScanRun.status == "running"
    ).first()
    if running_scan:
        raise HTTPException(
            status_code=409,
            detail=f"A scan is already running for this domain (ID: {running_scan.id})"
        )

    # Create new scan run
    scan_run = ScanRun(
        scan_type=request.scan_type,
        domain_id=domain.id,
        domain_name=request.domain_name,
        status="running",
        config=request.config,
        triggered_by=current_user.email,
        start_time=datetime.utcnow(),
    )

    try:
        db.add(scan_run)
        db.commit()
        db.refresh(scan_run)

        # Invalidate scan stats cache since a new scan was created
        invalidate_cache(CACHE_PREFIX_SCAN_STATS)

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="scan_triggered",
            resource_type="scan",
            resource_id=str(scan_run.id),
            details={
                "domain": request.domain_name,
                "scan_type": request.scan_type,
                "config": request.config,
            },
        )
        db.add(audit_log)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create scan")

    return TriggerScanResponse(
        id=scan_run.id,
        scan_type=scan_run.scan_type,
        domain_name=scan_run.domain_name,
        status=scan_run.status,
        start_time=scan_run.start_time,
        message=f"Scan triggered successfully. Scan ID: {scan_run.id}",
    )


@router.post("/{scan_id}/cancel", response_model=CancelScanResponse)
async def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Cancel a running scan."""
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Verify user has EDITOR role for this domain (required to cancel scans)
    require_domain_role(current_user, scan.domain_name, Role.EDITOR)

    if scan.status != "running":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan with status '{scan.status}'. Only running scans can be cancelled."
        )

    try:
        scan.status = "cancelled"
        scan.end_time = datetime.utcnow()
        scan.error_message = f"Cancelled by {current_user.email}"
        db.commit()

        # Invalidate scan stats cache since scan status changed
        invalidate_cache(CACHE_PREFIX_SCAN_STATS)

        # Broadcast cancellation via WebSocket
        await broadcast_scan_status(scan_id, "cancelled", {
            "cancelled_by": current_user.email,
            "end_time": scan.end_time.isoformat(),
        })

        # Log the action
        audit_log = AuditLog(
            user_id=current_user.id,
            action="scan_cancelled",
            resource_type="scan",
            resource_id=str(scan_id),
            details={
                "domain": scan.domain_name,
                "scan_type": scan.scan_type,
            },
        )
        db.add(audit_log)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to cancel scan")

    return CancelScanResponse(
        id=scan_id,
        status="cancelled",
        message=f"Scan {scan_id} has been cancelled successfully.",
    )


@router.patch("/{scan_id}/progress", response_model=ScanRunResponse)
async def update_scan_progress(
    scan_id: int,
    progress_percent: Optional[int] = Query(None, ge=0, le=100, description="Progress percentage (0-100)"),
    progress_message: Optional[str] = Query(None, max_length=255, description="Current operation message"),
    items_processed: Optional[int] = Query(None, ge=0, description="Number of items processed"),
    estimated_total: Optional[int] = Query(None, ge=0, description="Estimated total items"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update progress of a running scan.

    This endpoint is called by the CLI during scan execution to report progress.
    """
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Verify user has EDITOR role for this domain
    require_domain_role(current_user, scan.domain_name, Role.EDITOR)

    if scan.status != "running" and scan.status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot update progress for scan with status '{scan.status}'."
        )

    try:
        if progress_percent is not None:
            scan.progress_percent = progress_percent
        if progress_message is not None:
            scan.progress_message = progress_message
        if items_processed is not None:
            scan.items_processed = items_processed
        if estimated_total is not None:
            scan.estimated_total = estimated_total
        db.commit()
        db.refresh(scan)

        # Broadcast progress update via WebSocket
        await broadcast_scan_progress(scan_id, {
            "progress_percent": scan.progress_percent,
            "progress_message": scan.progress_message,
            "items_processed": scan.items_processed,
            "estimated_total": scan.estimated_total,
            "status": scan.status,
        })
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update progress")

    return ScanRunResponse.model_validate(scan)


@router.post("/{scan_id}/process-alerts")
async def process_scan_alerts(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Process alert rules after a scan completes.

    Checks all active alert rules for the scan's domain and sends notifications
    if any findings match the alert conditions.
    """
    from ..core.notifications import send_scan_completion_notification, send_alert_notification

    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Verify user has access to this domain
    require_domain_access(current_user, scan.domain_name)

    # Get domain
    domain = db.query(Domain).filter(Domain.name == scan.domain_name).first()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    # Get active alert rules for this domain
    from ..db.models import AlertRule
    alert_rules = db.query(AlertRule).filter(
        AlertRule.domain_id == domain.id,
        AlertRule.is_active == True,
    ).all()

    notifications_sent = []

    # Process each alert rule
    for rule in alert_rules:
        triggered = False
        findings_count = 0
        sample_findings = []

        # Check scan completion alerts
        if rule.condition_type == "scan_completed" and scan.status == "completed":
            scan_types = rule.condition_value.get("scan_type", ["all"])
            if "all" in scan_types or scan.scan_type in scan_types:
                triggered = True
                findings_count = scan.issues_found

        elif rule.condition_type == "scan_failed" and scan.status == "failed":
            scan_types = rule.condition_value.get("scan_type", ["all"])
            if "all" in scan_types or scan.scan_type in scan_types:
                triggered = True

        # Check finding-based alerts
        elif rule.condition_type == "high_risk_file" and scan.scan_type in ["files", "all"]:
            threshold = rule.condition_value.get("threshold", 75)
            high_risk_files = db.query(FileFinding).filter(
                FileFinding.scan_run_id == scan_id,
                FileFinding.risk_score >= threshold,
            ).all()
            if high_risk_files:
                triggered = True
                findings_count = len(high_risk_files)
                sample_findings = [{"name": f.file_name, "risk_score": f.risk_score} for f in high_risk_files[:5]]

        elif rule.condition_type == "public_file" and scan.scan_type in ["files", "all"]:
            public_files = db.query(FileFinding).filter(
                FileFinding.scan_run_id == scan_id,
                FileFinding.is_public == True,
            ).all()
            if public_files:
                triggered = True
                findings_count = len(public_files)
                sample_findings = [{"name": f.file_name} for f in public_files[:5]]

        elif rule.condition_type == "external_share" and scan.scan_type in ["files", "all"]:
            external_files = db.query(FileFinding).filter(
                FileFinding.scan_run_id == scan_id,
                FileFinding.is_shared_externally == True,
            ).all()
            if external_files:
                triggered = True
                findings_count = len(external_files)
                sample_findings = [{"name": f.file_name} for f in external_files[:5]]

        elif rule.condition_type == "inactive_user" and scan.scan_type in ["users", "all"]:
            days = rule.condition_value.get("days", 90)
            inactive_users = db.query(UserFinding).filter(
                UserFinding.scan_run_id == scan_id,
                UserFinding.is_inactive == True,
                UserFinding.days_since_last_login >= days,
            ).all()
            if inactive_users:
                triggered = True
                findings_count = len(inactive_users)
                sample_findings = [{"email": u.email} for u in inactive_users[:5]]

        elif rule.condition_type == "no_2fa_user" and scan.scan_type in ["users", "all"]:
            no_2fa_users = db.query(UserFinding).filter(
                UserFinding.scan_run_id == scan_id,
                UserFinding.two_factor_enabled == False,
            ).all()
            if no_2fa_users:
                triggered = True
                findings_count = len(no_2fa_users)
                sample_findings = [{"email": u.email} for u in no_2fa_users[:5]]

        elif rule.condition_type == "risky_oauth" and scan.scan_type in ["oauth", "all"]:
            threshold = rule.condition_value.get("threshold", 75)
            risky_apps = db.query(OAuthFinding).filter(
                OAuthFinding.scan_run_id == scan_id,
                OAuthFinding.risk_score >= threshold,
            ).all()
            if risky_apps:
                triggered = True
                findings_count = len(risky_apps)
                sample_findings = [{"name": a.display_text or a.client_id, "risk_score": a.risk_score} for a in risky_apps[:5]]

        elif rule.condition_type == "security_finding" and scan.scan_type in ["posture", "all"]:
            severities = rule.condition_value.get("severity", ["critical", "high"])
            findings = db.query(SecurityFinding).filter(
                SecurityFinding.scan_run_id == scan_id,
                SecurityFinding.passed == False,
                SecurityFinding.severity.in_(severities),
            ).all()
            if findings:
                triggered = True
                findings_count = len(findings)
                sample_findings = [{"title": f.title, "severity": f.severity} for f in findings[:5]]

        # Send notification if rule was triggered
        if triggered:
            try:
                results = send_alert_notification(
                    rule_name=rule.name,
                    condition_type=rule.condition_type,
                    domain_name=scan.domain_name,
                    findings_count=findings_count,
                    channels=rule.notification_channels or [],
                    config=rule.notification_config or {},
                    sample_findings=sample_findings,
                )
                notifications_sent.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "condition_type": rule.condition_type,
                    "findings_count": findings_count,
                    "notification_results": results,
                })
            except Exception as e:
                notifications_sent.append({
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "error": str(e),
                })

    return {
        "scan_id": scan_id,
        "domain": scan.domain_name,
        "scan_type": scan.scan_type,
        "scan_status": scan.status,
        "rules_checked": len(alert_rules),
        "notifications_sent": notifications_sent,
    }
