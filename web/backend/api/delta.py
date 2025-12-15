"""Delta tracking and deduplication API routes."""

from datetime import datetime
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..auth.security import get_current_user, require_domain_access
from ..db.database import get_db
from ..db.models import User, ScanRun
from ..services.deduplication import (
    FindingType,
    FindingDeduplicator,
    DeltaTracker,
    deduplicate_findings_for_scan,
    generate_fingerprint,
)

router = APIRouter()


# Response schemas
class SecurityFindingSummary(BaseModel):
    """Summary of a security posture finding."""
    check_id: str
    title: str
    severity: str
    passed: bool
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None


class FileFindingSummary(BaseModel):
    """Summary of a file finding."""
    file_id: str
    file_name: str
    owner_email: Optional[str] = None
    is_public: bool = False
    is_shared_externally: bool = False
    pii_detected: bool = False
    risk_score: int = 0
    severity: Optional[str] = None


class UserFindingSummary(BaseModel):
    """Summary of a user finding."""
    user_id: str
    email: str
    full_name: Optional[str] = None
    is_admin: bool = False
    is_inactive: bool = False
    two_factor_enabled: bool = False
    risk_score: int = 0
    severity: Optional[str] = None


class OAuthFindingSummary(BaseModel):
    """Summary of an OAuth app finding."""
    client_id: str
    display_text: Optional[str] = None
    user_count: int = 0
    is_verified: bool = False
    risk_score: int = 0
    severity: Optional[str] = None


class FindingSummary(BaseModel):
    """Generic summary of a finding's key attributes.

    This model accepts any fields dynamically to support different finding types.
    For type-specific access, use the typed summary models above.
    """

    class Config:
        extra = "allow"


class DeltaFinding(BaseModel):
    """A finding in a delta comparison."""
    id: int
    fingerprint: str
    summary: Dict[str, Any]


class ChangedFinding(BaseModel):
    """A finding that changed between scans."""
    previous_id: int
    current_id: int
    fingerprint: str
    changes: List[Dict[str, Any]]
    previous_summary: Dict[str, Any]
    current_summary: Dict[str, Any]


class UnchangedFinding(BaseModel):
    """A finding that remained the same between scans."""
    previous_id: int
    current_id: int
    fingerprint: str
    summary: Dict[str, Any]


class DeltaSummary(BaseModel):
    """Summary counts for a delta comparison."""
    new_count: int
    resolved_count: int
    unchanged_count: int
    changed_count: int
    total_in_scan_1: int
    total_in_scan_2: int


class DeltaComparisonResponse(BaseModel):
    """Response for delta comparison between two scans."""
    scan_1_id: int
    scan_2_id: int
    finding_type: str
    summary: DeltaSummary
    new: List[Dict[str, Any]]
    resolved: List[Dict[str, Any]]
    unchanged: List[Dict[str, Any]]
    changed: List[Dict[str, Any]]


class TrendDataPoint(BaseModel):
    """A single data point in trend analysis."""
    scan_id: int
    scan_time: str
    total_findings: int
    new: Optional[int] = None
    resolved: Optional[int] = None
    net_change: Optional[int] = None


class TrendResponse(BaseModel):
    """Response for trend analysis."""
    domain_name: str
    finding_type: str
    num_scans: int
    data_points: List[TrendDataPoint]


class DeduplicationResponse(BaseModel):
    """Response for deduplication analysis."""
    scan_id: int
    finding_type: str
    total: int
    new: int
    recurring: int
    previous_scan_id: Optional[int] = None


class FindingHistoryEntry(BaseModel):
    """An entry in a finding's history."""
    scan_id: int
    scan_time: datetime
    finding_id: Optional[int] = None
    present: bool
    summary: Optional[Dict[str, Any]] = None


class FindingHistoryResponse(BaseModel):
    """Response for finding history."""
    fingerprint: str
    domain_name: str
    finding_type: str
    history: List[FindingHistoryEntry]


class DuplicatesResponse(BaseModel):
    """Response for duplicates query."""
    domain_name: str
    finding_type: str
    duplicate_count: int
    duplicates: Dict[str, List[int]]


@router.get("/compare", response_model=DeltaComparisonResponse)
async def compare_scans_delta(
    scan_id_1: int = Query(..., description="First (older) scan ID"),
    scan_id_2: int = Query(..., description="Second (newer) scan ID"),
    finding_type: str = Query(..., description="Finding type: security, file, user, oauth"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compare findings between two scans to see what changed.

    This endpoint shows:
    - New findings that appeared in scan_2 but not in scan_1
    - Resolved findings that were in scan_1 but not in scan_2
    - Unchanged findings present in both scans with same attributes
    - Changed findings present in both but with attribute changes

    The scans must be of the same type and domain.
    """
    # Validate finding type
    try:
        ft = FindingType(finding_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding type. Must be one of: security, file, user, oauth"
        )

    # Get scans and validate access
    scan_1 = db.query(ScanRun).filter(ScanRun.id == scan_id_1).first()
    scan_2 = db.query(ScanRun).filter(ScanRun.id == scan_id_2).first()

    if not scan_1:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id_1} not found"
        )
    if not scan_2:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id_2} not found"
        )

    # Check domain access
    require_domain_access(current_user, scan_1.domain_name)
    require_domain_access(current_user, scan_2.domain_name)

    # Validate scans are from same domain
    if scan_1.domain_name != scan_2.domain_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scans must be from the same domain"
        )

    # Validate scan types match the finding type
    scan_type_map = {
        FindingType.SECURITY: "posture",
        FindingType.FILE: "files",
        FindingType.USER: "users",
        FindingType.OAUTH: "oauth",
    }
    expected_type = scan_type_map[ft]
    if scan_1.scan_type != expected_type or scan_2.scan_type != expected_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scans must be of type '{expected_type}' for {finding_type} findings"
        )

    # Perform comparison
    tracker = DeltaTracker(db)
    result = tracker.compare_scans(scan_id_1, scan_id_2, ft)

    return DeltaComparisonResponse(**result)


@router.get("/latest", response_model=Optional[DeltaComparisonResponse])
async def get_latest_delta(
    domain: str = Query(..., description="Domain name"),
    finding_type: str = Query(..., description="Finding type: security, file, user, oauth"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get delta between the two most recent scans for a domain.

    Returns null if there are fewer than 2 completed scans.
    """
    # Validate finding type
    try:
        ft = FindingType(finding_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding type. Must be one of: security, file, user, oauth"
        )

    # Check domain access
    require_domain_access(current_user, domain)

    tracker = DeltaTracker(db)
    result = tracker.get_delta_summary(domain, ft)

    if result is None:
        return None

    return DeltaComparisonResponse(**result)


@router.get("/trend", response_model=TrendResponse)
async def get_findings_trend(
    domain: str = Query(..., description="Domain name"),
    finding_type: str = Query(..., description="Finding type: security, file, user, oauth"),
    num_scans: int = Query(10, ge=2, le=50, description="Number of scans to include"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get trend data showing how findings changed over multiple scans.

    Returns data points for each scan showing total findings and
    net changes from the previous scan.
    """
    # Validate finding type
    try:
        ft = FindingType(finding_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding type. Must be one of: security, file, user, oauth"
        )

    # Check domain access
    require_domain_access(current_user, domain)

    tracker = DeltaTracker(db)
    result = tracker.get_trend_data(domain, ft, num_scans)

    return TrendResponse(**result)


@router.get("/duplicates", response_model=DuplicatesResponse)
async def get_duplicate_findings(
    domain: str = Query(..., description="Domain name"),
    finding_type: str = Query(..., description="Finding type: security, file, user, oauth"),
    lookback_scans: int = Query(5, ge=1, le=20, description="Number of scans to check"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Find duplicate findings across recent scans.

    Returns findings that appear in multiple scans, identified by their
    fingerprint. This helps identify recurring issues.
    """
    # Validate finding type
    try:
        ft = FindingType(finding_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding type. Must be one of: security, file, user, oauth"
        )

    # Check domain access
    require_domain_access(current_user, domain)

    deduplicator = FindingDeduplicator(db)
    duplicates = deduplicator.find_duplicates(domain, ft, lookback_scans)

    return DuplicatesResponse(
        domain_name=domain,
        finding_type=finding_type,
        duplicate_count=len(duplicates),
        duplicates=duplicates,
    )


@router.get("/history/{fingerprint}", response_model=FindingHistoryResponse)
async def get_finding_history(
    fingerprint: str,
    domain: str = Query(..., description="Domain name"),
    finding_type: str = Query(..., description="Finding type: security, file, user, oauth"),
    max_scans: int = Query(10, ge=1, le=50, description="Maximum scans to look back"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get the history of a specific finding across scans.

    Uses the finding's fingerprint to track it across multiple scans,
    showing when it appeared, disappeared, or changed.
    """
    # Validate finding type
    try:
        ft = FindingType(finding_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding type. Must be one of: security, file, user, oauth"
        )

    # Check domain access
    require_domain_access(current_user, domain)

    deduplicator = FindingDeduplicator(db)
    history = deduplicator.get_finding_history(fingerprint, domain, ft, max_scans)

    return FindingHistoryResponse(
        fingerprint=fingerprint,
        domain_name=domain,
        finding_type=finding_type,
        history=history,
    )


@router.post("/analyze/{scan_id}", response_model=DeduplicationResponse)
async def analyze_scan_deduplication(
    scan_id: int,
    finding_type: str = Query(..., description="Finding type: security, file, user, oauth"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Analyze a scan to identify new vs recurring findings.

    Compares the scan's findings against the previous scan of the same
    type to categorize findings as new (first time seen) or recurring
    (seen in previous scan).
    """
    # Validate finding type
    try:
        ft = FindingType(finding_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid finding type. Must be one of: security, file, user, oauth"
        )

    # Get scan and validate access
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found"
        )

    require_domain_access(current_user, scan.domain_name)

    try:
        result = deduplicate_findings_for_scan(db, scan_id, ft)
        return DeduplicationResponse(**result)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
