"""Finding deduplication and delta tracking service.

This module provides functionality for:
1. Generating fingerprints for findings to identify duplicates across scans
2. Linking related findings across scans using the fingerprint system
3. Tracking what changed between scans (new, resolved, unchanged findings)
"""

import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Set
from enum import Enum

from sqlalchemy import and_, func, desc
from sqlalchemy.orm import Session

from ..db.models import (
    ScanRun,
    SecurityFinding,
    FileFinding,
    UserFinding,
    OAuthFinding,
)


class FindingType(str, Enum):
    """Types of findings."""
    SECURITY = "security"
    FILE = "file"
    USER = "user"
    OAUTH = "oauth"


class DeltaStatus(str, Enum):
    """Status of a finding in delta comparison."""
    NEW = "new"           # Finding appeared in current scan but not previous
    RESOLVED = "resolved"  # Finding was in previous scan but not current
    UNCHANGED = "unchanged"  # Finding exists in both scans
    CHANGED = "changed"    # Finding exists in both but attributes changed


def generate_security_fingerprint(finding: SecurityFinding) -> str:
    """Generate a unique fingerprint for a security finding.

    The fingerprint is based on immutable characteristics that identify
    the same security issue across different scans.
    """
    # Security findings are identified by their check_id and resource
    # These represent the same security check on the same resource
    components = [
        finding.check_id or "",
        finding.resource_type or "",
        finding.resource_id or "",
    ]

    fingerprint_data = "|".join(components)
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]


def generate_file_fingerprint(finding: FileFinding) -> str:
    """Generate a unique fingerprint for a file finding.

    The fingerprint is based on the file ID which is immutable in Google Drive.
    """
    # File findings are identified by their Google Drive file_id
    # which remains constant even if the file is renamed or moved
    components = [
        finding.file_id or "",
    ]

    fingerprint_data = "|".join(components)
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]


def generate_user_fingerprint(finding: UserFinding) -> str:
    """Generate a unique fingerprint for a user finding.

    The fingerprint is based on the user ID which is immutable in Google Workspace.
    """
    # User findings are identified by their Google Workspace user_id
    components = [
        finding.user_id or "",
    ]

    fingerprint_data = "|".join(components)
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]


def generate_oauth_fingerprint(finding: OAuthFinding) -> str:
    """Generate a unique fingerprint for an OAuth finding.

    The fingerprint is based on the OAuth client ID which is unique per app.
    """
    # OAuth findings are identified by their client_id
    components = [
        finding.client_id or "",
    ]

    fingerprint_data = "|".join(components)
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]


def generate_fingerprint(finding: Any, finding_type: FindingType) -> str:
    """Generate a fingerprint for any finding type."""
    if finding_type == FindingType.SECURITY:
        return generate_security_fingerprint(finding)
    elif finding_type == FindingType.FILE:
        return generate_file_fingerprint(finding)
    elif finding_type == FindingType.USER:
        return generate_user_fingerprint(finding)
    elif finding_type == FindingType.OAUTH:
        return generate_oauth_fingerprint(finding)
    else:
        raise ValueError(f"Unknown finding type: {finding_type}")


class FindingDeduplicator:
    """Service for deduplicating findings across scans."""

    def __init__(self, db: Session):
        self.db = db

    def get_fingerprint_map(
        self,
        scan_id: int,
        finding_type: FindingType,
    ) -> Dict[str, Any]:
        """Get a map of fingerprints to findings for a scan.

        Returns:
            Dict mapping fingerprint -> finding object
        """
        if finding_type == FindingType.SECURITY:
            model = SecurityFinding
            generator = generate_security_fingerprint
        elif finding_type == FindingType.FILE:
            model = FileFinding
            generator = generate_file_fingerprint
        elif finding_type == FindingType.USER:
            model = UserFinding
            generator = generate_user_fingerprint
        elif finding_type == FindingType.OAUTH:
            model = OAuthFinding
            generator = generate_oauth_fingerprint
        else:
            raise ValueError(f"Unknown finding type: {finding_type}")

        findings = self.db.query(model).filter(model.scan_run_id == scan_id).all()

        return {generator(f): f for f in findings}

    def find_duplicates(
        self,
        domain_name: str,
        finding_type: FindingType,
        lookback_scans: int = 5,
    ) -> Dict[str, List[int]]:
        """Find duplicate findings across recent scans.

        Args:
            domain_name: Domain to search within
            finding_type: Type of findings to check
            lookback_scans: Number of recent scans to include

        Returns:
            Dict mapping fingerprint -> list of finding IDs that share it
        """
        # Get recent scans for this domain and scan type
        scan_type_map = {
            FindingType.SECURITY: "posture",
            FindingType.FILE: "files",
            FindingType.USER: "users",
            FindingType.OAUTH: "oauth",
        }

        scans = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.domain_name == domain_name,
                ScanRun.scan_type == scan_type_map[finding_type],
                ScanRun.status == "completed",
            )
            .order_by(desc(ScanRun.start_time))
            .limit(lookback_scans)
            .all()
        )

        # Build fingerprint -> finding IDs map
        fingerprint_to_ids: Dict[str, List[int]] = {}

        for scan in scans:
            fp_map = self.get_fingerprint_map(scan.id, finding_type)
            for fingerprint, finding in fp_map.items():
                if fingerprint not in fingerprint_to_ids:
                    fingerprint_to_ids[fingerprint] = []
                fingerprint_to_ids[fingerprint].append(finding.id)

        # Filter to only duplicates (more than one ID per fingerprint)
        return {fp: ids for fp, ids in fingerprint_to_ids.items() if len(ids) > 1}

    def get_finding_history(
        self,
        fingerprint: str,
        domain_name: str,
        finding_type: FindingType,
        max_scans: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get the history of a finding across scans using its fingerprint.

        Args:
            fingerprint: The finding's fingerprint
            domain_name: Domain to search within
            finding_type: Type of finding
            max_scans: Maximum number of scans to look back

        Returns:
            List of dicts with scan info and finding state for each occurrence
        """
        scan_type_map = {
            FindingType.SECURITY: "posture",
            FindingType.FILE: "files",
            FindingType.USER: "users",
            FindingType.OAUTH: "oauth",
        }

        scans = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.domain_name == domain_name,
                ScanRun.scan_type == scan_type_map[finding_type],
                ScanRun.status == "completed",
            )
            .order_by(desc(ScanRun.start_time))
            .limit(max_scans)
            .all()
        )

        history = []
        for scan in scans:
            fp_map = self.get_fingerprint_map(scan.id, finding_type)
            if fingerprint in fp_map:
                finding = fp_map[fingerprint]
                history.append({
                    "scan_id": scan.id,
                    "scan_time": scan.start_time,
                    "finding_id": finding.id,
                    "present": True,
                    "summary": self._get_finding_summary(finding, finding_type),
                })
            else:
                history.append({
                    "scan_id": scan.id,
                    "scan_time": scan.start_time,
                    "finding_id": None,
                    "present": False,
                    "summary": None,
                })

        return history

    def _get_finding_summary(self, finding: Any, finding_type: FindingType) -> Dict[str, Any]:
        """Get a summary of key attributes for a finding."""
        if finding_type == FindingType.SECURITY:
            return {
                "check_id": finding.check_id,
                "title": finding.title,
                "severity": finding.severity,
                "passed": finding.passed,
                "status": finding.status,
            }
        elif finding_type == FindingType.FILE:
            return {
                "file_name": finding.file_name,
                "owner_email": finding.owner_email,
                "is_public": finding.is_public,
                "is_shared_externally": finding.is_shared_externally,
                "risk_score": finding.risk_score,
                "pii_detected": finding.pii_detected,
            }
        elif finding_type == FindingType.USER:
            return {
                "email": finding.email,
                "is_admin": finding.is_admin,
                "is_inactive": finding.is_inactive,
                "two_factor_enabled": finding.two_factor_enabled,
                "risk_score": finding.risk_score,
            }
        elif finding_type == FindingType.OAUTH:
            return {
                "display_text": finding.display_text,
                "user_count": finding.user_count,
                "risk_score": finding.risk_score,
                "is_verified": finding.is_verified,
            }
        return {}


class DeltaTracker:
    """Service for tracking changes between scans."""

    def __init__(self, db: Session):
        self.db = db
        self.deduplicator = FindingDeduplicator(db)

    def compare_scans(
        self,
        scan_id_1: int,
        scan_id_2: int,
        finding_type: FindingType,
    ) -> Dict[str, Any]:
        """Compare findings between two scans.

        Args:
            scan_id_1: First (older) scan ID
            scan_id_2: Second (newer) scan ID
            finding_type: Type of findings to compare

        Returns:
            Dict with new, resolved, unchanged, and changed findings
        """
        # Get fingerprint maps for both scans
        fp_map_1 = self.deduplicator.get_fingerprint_map(scan_id_1, finding_type)
        fp_map_2 = self.deduplicator.get_fingerprint_map(scan_id_2, finding_type)

        fp_set_1 = set(fp_map_1.keys())
        fp_set_2 = set(fp_map_2.keys())

        # Categorize findings
        new_fps = fp_set_2 - fp_set_1
        resolved_fps = fp_set_1 - fp_set_2
        common_fps = fp_set_1 & fp_set_2

        # Build results
        new_findings = []
        for fp in new_fps:
            finding = fp_map_2[fp]
            new_findings.append({
                "id": finding.id,
                "fingerprint": fp,
                "summary": self.deduplicator._get_finding_summary(finding, finding_type),
            })

        resolved_findings = []
        for fp in resolved_fps:
            finding = fp_map_1[fp]
            resolved_findings.append({
                "id": finding.id,
                "fingerprint": fp,
                "summary": self.deduplicator._get_finding_summary(finding, finding_type),
            })

        unchanged_findings = []
        changed_findings = []

        for fp in common_fps:
            finding_1 = fp_map_1[fp]
            finding_2 = fp_map_2[fp]

            summary_1 = self.deduplicator._get_finding_summary(finding_1, finding_type)
            summary_2 = self.deduplicator._get_finding_summary(finding_2, finding_type)

            # Check if attributes changed
            changes = self._detect_changes(summary_1, summary_2, finding_type)

            if changes:
                changed_findings.append({
                    "previous_id": finding_1.id,
                    "current_id": finding_2.id,
                    "fingerprint": fp,
                    "changes": changes,
                    "previous_summary": summary_1,
                    "current_summary": summary_2,
                })
            else:
                unchanged_findings.append({
                    "previous_id": finding_1.id,
                    "current_id": finding_2.id,
                    "fingerprint": fp,
                    "summary": summary_2,
                })

        return {
            "scan_1_id": scan_id_1,
            "scan_2_id": scan_id_2,
            "finding_type": finding_type.value,
            "summary": {
                "new_count": len(new_findings),
                "resolved_count": len(resolved_findings),
                "unchanged_count": len(unchanged_findings),
                "changed_count": len(changed_findings),
                "total_in_scan_1": len(fp_map_1),
                "total_in_scan_2": len(fp_map_2),
            },
            "new": new_findings,
            "resolved": resolved_findings,
            "unchanged": unchanged_findings,
            "changed": changed_findings,
        }

    def _detect_changes(
        self,
        summary_1: Dict[str, Any],
        summary_2: Dict[str, Any],
        finding_type: FindingType,
    ) -> List[Dict[str, Any]]:
        """Detect specific changes between two finding summaries.

        Returns list of changes with field name, old value, and new value.
        """
        changes = []

        # Define which fields to track for changes per finding type
        tracked_fields = {
            FindingType.SECURITY: ["severity", "passed", "status"],
            FindingType.FILE: ["is_public", "is_shared_externally", "risk_score", "pii_detected"],
            FindingType.USER: ["is_admin", "is_inactive", "two_factor_enabled", "risk_score"],
            FindingType.OAUTH: ["user_count", "risk_score", "is_verified"],
        }

        for field in tracked_fields.get(finding_type, []):
            old_val = summary_1.get(field)
            new_val = summary_2.get(field)

            if old_val != new_val:
                changes.append({
                    "field": field,
                    "old_value": old_val,
                    "new_value": new_val,
                })

        return changes

    def get_delta_summary(
        self,
        domain_name: str,
        finding_type: FindingType,
    ) -> Optional[Dict[str, Any]]:
        """Get a delta summary between the two most recent scans.

        Args:
            domain_name: Domain to analyze
            finding_type: Type of findings to compare

        Returns:
            Delta comparison result or None if not enough scans
        """
        scan_type_map = {
            FindingType.SECURITY: "posture",
            FindingType.FILE: "files",
            FindingType.USER: "users",
            FindingType.OAUTH: "oauth",
        }

        scans = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.domain_name == domain_name,
                ScanRun.scan_type == scan_type_map[finding_type],
                ScanRun.status == "completed",
            )
            .order_by(desc(ScanRun.start_time))
            .limit(2)
            .all()
        )

        if len(scans) < 2:
            return None

        # scans[0] is newer, scans[1] is older
        return self.compare_scans(scans[1].id, scans[0].id, finding_type)

    def get_trend_data(
        self,
        domain_name: str,
        finding_type: FindingType,
        num_scans: int = 10,
    ) -> Dict[str, Any]:
        """Get trend data showing how findings changed over multiple scans.

        Args:
            domain_name: Domain to analyze
            finding_type: Type of findings
            num_scans: Number of recent scans to include

        Returns:
            Dict with trend data points
        """
        scan_type_map = {
            FindingType.SECURITY: "posture",
            FindingType.FILE: "files",
            FindingType.USER: "users",
            FindingType.OAUTH: "oauth",
        }

        scans = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.domain_name == domain_name,
                ScanRun.scan_type == scan_type_map[finding_type],
                ScanRun.status == "completed",
            )
            .order_by(desc(ScanRun.start_time))
            .limit(num_scans)
            .all()
        )

        # Reverse to get chronological order
        scans = list(reversed(scans))

        data_points = []
        previous_fps: Optional[Set[str]] = None

        for scan in scans:
            fp_map = self.deduplicator.get_fingerprint_map(scan.id, finding_type)
            current_fps = set(fp_map.keys())

            point = {
                "scan_id": scan.id,
                "scan_time": scan.start_time.isoformat(),
                "total_findings": len(current_fps),
            }

            if previous_fps is not None:
                new_count = len(current_fps - previous_fps)
                resolved_count = len(previous_fps - current_fps)
                point["new"] = new_count
                point["resolved"] = resolved_count
                point["net_change"] = new_count - resolved_count
            else:
                point["new"] = None
                point["resolved"] = None
                point["net_change"] = None

            data_points.append(point)
            previous_fps = current_fps

        return {
            "domain_name": domain_name,
            "finding_type": finding_type.value,
            "num_scans": len(data_points),
            "data_points": data_points,
        }


def deduplicate_findings_for_scan(
    db: Session,
    scan_id: int,
    finding_type: FindingType,
) -> Dict[str, Any]:
    """Mark findings as duplicates if they match previous scan findings.

    This is useful for identifying recurring issues vs new issues.

    Returns:
        Dict with counts of new vs recurring findings
    """
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    tracker = DeltaTracker(db)
    deduplicator = FindingDeduplicator(db)

    # Get the previous scan of same type for this domain
    scan_type_map = {
        FindingType.SECURITY: "posture",
        FindingType.FILE: "files",
        FindingType.USER: "users",
        FindingType.OAUTH: "oauth",
    }

    previous_scan = (
        db.query(ScanRun)
        .filter(
            ScanRun.domain_name == scan.domain_name,
            ScanRun.scan_type == scan_type_map[finding_type],
            ScanRun.status == "completed",
            ScanRun.id < scan_id,
        )
        .order_by(desc(ScanRun.start_time))
        .first()
    )

    current_fp_map = deduplicator.get_fingerprint_map(scan_id, finding_type)

    if not previous_scan:
        # First scan - all findings are new
        return {
            "scan_id": scan_id,
            "finding_type": finding_type.value,
            "total": len(current_fp_map),
            "new": len(current_fp_map),
            "recurring": 0,
            "previous_scan_id": None,
        }

    previous_fp_map = deduplicator.get_fingerprint_map(previous_scan.id, finding_type)
    previous_fps = set(previous_fp_map.keys())
    current_fps = set(current_fp_map.keys())

    new_fps = current_fps - previous_fps
    recurring_fps = current_fps & previous_fps

    return {
        "scan_id": scan_id,
        "finding_type": finding_type.value,
        "total": len(current_fp_map),
        "new": len(new_fps),
        "recurring": len(recurring_fps),
        "previous_scan_id": previous_scan.id,
    }
