"""Dashboard API routes."""

from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, case, cast, Date
from sqlalchemy.orm import Session

from ..auth.security import get_current_user, require_domain_access
from ..core.cache import (
    get_cache,
    make_cache_key,
    CACHE_PREFIX_DASHBOARD,
    CACHE_TTL_DASHBOARD,
)
from ..db.database import get_db
from ..db.models import (
    User,
    ScanRun,
    SecurityFinding,
    FileFinding,
    UserFinding,
    OAuthFinding,
)
from .schemas import ScanRunResponse, DashboardOverviewResponse, ScanStatsResponse

router = APIRouter()


@router.get("/overview", response_model=DashboardOverviewResponse)
async def get_dashboard_overview(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get comprehensive dashboard overview with caching and SQL aggregations."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Build base query filters
    if domain:
        require_domain_access(current_user, domain)
        domain_filter = ScanRun.domain_name == domain
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        domain_filter = ScanRun.domain_name.in_(user_domains)
    else:
        domain_filter = True

    # Build cache key based on user context
    if current_user.is_superuser:
        user_context = "superuser"
    else:
        user_domains_sorted = sorted([ud.domain for ud in current_user.domains])
        user_context = ",".join(user_domains_sorted) if user_domains_sorted else "none"

    cache_key = make_cache_key(
        CACHE_PREFIX_DASHBOARD,
        endpoint="overview",
        domain=domain or "all",
        days=days,
        user_context=user_context,
    )

    # Check cache first
    cache = get_cache()
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        return DashboardOverviewResponse(**cached_result)

    # Get scan stats using SQL aggregations (optimized from Python loops)
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

    scan_stats = ScanStatsResponse(
        total_scans=total_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        total_issues=total_issues,
        high_risk_total=high_risk_total,
        medium_risk_total=medium_risk_total,
        low_risk_total=low_risk_total,
        success_rate=(completed_scans / total_scans * 100) if total_scans > 0 else 0,
        period_days=days,
    )

    # Get recent scans
    recent_scans_query = (
        db.query(ScanRun)
        .filter(domain_filter)
        .order_by(desc(ScanRun.start_time))
        .limit(5)
    )
    recent_scans = [ScanRunResponse.model_validate(s) for s in recent_scans_query.all()]

    # Get critical findings count
    critical_findings = (
        db.query(SecurityFinding)
        .join(ScanRun)
        .filter(
            SecurityFinding.detected_at >= cutoff_date,
            SecurityFinding.severity == "critical",
            SecurityFinding.passed == False,
            domain_filter,
        )
        .count()
    )

    # Get high-risk files count
    high_risk_files = (
        db.query(FileFinding)
        .join(ScanRun)
        .filter(
            FileFinding.detected_at >= cutoff_date,
            FileFinding.risk_score >= 70,
            domain_filter,
        )
        .count()
    )

    # Get inactive users count
    inactive_users = (
        db.query(UserFinding)
        .join(ScanRun)
        .filter(
            UserFinding.detected_at >= cutoff_date,
            UserFinding.is_inactive == True,
            domain_filter,
        )
        .count()
    )

    # Get risky OAuth apps count
    risky_oauth_apps = (
        db.query(OAuthFinding)
        .join(ScanRun)
        .filter(
            OAuthFinding.detected_at >= cutoff_date,
            OAuthFinding.risk_score >= 50,
            domain_filter,
        )
        .count()
    )

    # Calculate security score (0-100)
    # Higher score = better security posture
    security_score = calculate_security_score(
        critical_findings=critical_findings,
        high_risk_files=high_risk_files,
        inactive_users=inactive_users,
        risky_oauth_apps=risky_oauth_apps,
        total_scans=total_scans,
        completed_scans=completed_scans,
    )

    # Get findings by severity
    severity_counts = (
        db.query(SecurityFinding.severity, func.count(SecurityFinding.id))
        .join(ScanRun)
        .filter(
            SecurityFinding.detected_at >= cutoff_date,
            SecurityFinding.passed == False,
            domain_filter,
        )
        .group_by(SecurityFinding.severity)
        .all()
    )
    findings_by_severity = {sev: count for sev, count in severity_counts}

    # Get findings by framework (only fetch frameworks column for efficiency)
    framework_counts: Dict[str, int] = {}
    frameworks_query = (
        db.query(SecurityFinding.frameworks)
        .join(ScanRun)
        .filter(
            SecurityFinding.detected_at >= cutoff_date,
            SecurityFinding.passed == False,
            SecurityFinding.frameworks.isnot(None),  # Filter early to reduce data
            domain_filter,
        )
        .all()
    )
    for (frameworks,) in frameworks_query:
        if frameworks:
            for fw in frameworks:
                framework_counts[fw] = framework_counts.get(fw, 0) + 1

    # Build response
    result = {
        "scan_stats": scan_stats.model_dump(),
        "recent_scans": [s.model_dump() for s in recent_scans],
        "critical_findings": critical_findings,
        "high_risk_files": high_risk_files,
        "inactive_users": inactive_users,
        "risky_oauth_apps": risky_oauth_apps,
        "security_score": security_score,
        "findings_by_severity": findings_by_severity,
        "findings_by_framework": framework_counts,
    }

    # Cache the result
    cache.set(cache_key, result, CACHE_TTL_DASHBOARD)

    return DashboardOverviewResponse(**result)


def calculate_security_score(
    critical_findings: int,
    high_risk_files: int,
    inactive_users: int,
    risky_oauth_apps: int,
    total_scans: int,
    completed_scans: int,
) -> float:
    """
    Calculate an overall security score (0-100).
    Higher score = better security posture.
    """
    # Start with perfect score
    score = 100.0

    # Deduct for critical findings (heavy penalty)
    score -= min(critical_findings * 5, 30)

    # Deduct for high-risk files
    score -= min(high_risk_files * 2, 20)

    # Deduct for inactive users
    score -= min(inactive_users * 0.5, 15)

    # Deduct for risky OAuth apps
    score -= min(risky_oauth_apps * 1, 15)

    # Bonus for regular scanning
    if total_scans > 0:
        scan_success_rate = completed_scans / total_scans
        score += scan_success_rate * 5  # Up to 5 bonus points

    # Penalty for no recent scans
    if total_scans == 0:
        score -= 20

    # Ensure score is between 0 and 100
    return max(0, min(100, score))


@router.get("/trends")
async def get_security_trends(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    days: int = Query(30, ge=7, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get security trends over time using SQL aggregations."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    if domain:
        require_domain_access(current_user, domain)
        domain_filter = ScanRun.domain_name == domain
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        domain_filter = ScanRun.domain_name.in_(user_domains)
    else:
        domain_filter = True

    # Use SQL GROUP BY to aggregate by date (optimized from Python loops)
    # cast to Date for grouping by day
    daily_stats = (
        db.query(
            cast(ScanRun.start_time, Date).label("date"),
            func.count(ScanRun.id).label("scans"),
            func.coalesce(func.sum(ScanRun.issues_found), 0).label("issues"),
            func.coalesce(func.sum(ScanRun.high_risk_count), 0).label("high_risk"),
        )
        .filter(ScanRun.start_time >= cutoff_date)
        .filter(domain_filter)
        .group_by(cast(ScanRun.start_time, Date))
        .order_by(cast(ScanRun.start_time, Date))
        .all()
    )

    # Convert to response format
    trends = [
        {
            "date": str(row.date),
            "scans": row.scans,
            "issues": row.issues,
            "high_risk": row.high_risk,
        }
        for row in daily_stats
    ]

    return {"trends": trends, "period_days": days}


@router.get("/compliance-summary")
async def get_compliance_summary(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    framework: Optional[str] = Query(None, description="Filter by framework"),
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get compliance summary by framework."""
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    if domain:
        require_domain_access(current_user, domain)
        domain_filter = ScanRun.domain_name == domain
    elif not current_user.is_superuser:
        user_domains = [ud.domain for ud in current_user.domains]
        domain_filter = ScanRun.domain_name.in_(user_domains)
    else:
        domain_filter = True

    findings = (
        db.query(SecurityFinding)
        .join(ScanRun)
        .filter(
            SecurityFinding.detected_at >= cutoff_date,
            domain_filter,
        )
        .all()
    )

    # Group by framework
    frameworks_data: Dict[str, Dict[str, Any]] = {}
    for finding in findings:
        if not finding.frameworks:
            continue
        for fw in finding.frameworks:
            if framework and fw != framework:
                continue
            if fw not in frameworks_data:
                frameworks_data[fw] = {
                    "framework": fw,
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                }
            frameworks_data[fw]["total"] += 1
            if finding.passed:
                frameworks_data[fw]["passed"] += 1
            else:
                frameworks_data[fw]["failed"] += 1
                if finding.severity:
                    frameworks_data[fw][finding.severity] = (
                        frameworks_data[fw].get(finding.severity, 0) + 1
                    )

    # Calculate compliance percentages
    for fw_data in frameworks_data.values():
        total = fw_data["total"]
        if total > 0:
            fw_data["compliance_rate"] = (fw_data["passed"] / total) * 100
        else:
            fw_data["compliance_rate"] = 0

    return {
        "frameworks": list(frameworks_data.values()),
        "period_days": days,
    }
