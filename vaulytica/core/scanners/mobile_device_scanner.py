"""Mobile device scanner for Google Workspace mobile device management."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta, timezone
import time
import structlog
from googleapiclient.errors import HttpError

logger = structlog.get_logger(__name__)


@dataclass
class MobileDevice:
    """Represents a mobile device."""

    device_id: str
    resource_id: str
    email: str
    model: str = ""
    os: str = ""  # ANDROID, IOS, WINDOWS_PHONE
    os_version: str = ""
    type: str = ""  # ANDROID, IOS_SYNC, GOOGLE_SYNC
    status: str = ""  # APPROVED, BLOCKED, PENDING
    last_sync: Optional[datetime] = None
    first_sync: Optional[datetime] = None
    user_agent: str = ""
    imei: str = ""
    serial_number: str = ""
    is_compromised: bool = False
    is_encrypted: bool = False
    is_password_protected: bool = False
    risk_score: int = 0
    # Enhanced security fields
    has_outdated_os: bool = False
    has_unknown_sources: bool = False  # Android only
    has_developer_mode: bool = False  # Android only
    has_usb_debugging: bool = False  # Android only
    is_supervised: bool = False  # iOS only
    compliance_state: str = ""  # COMPLIANT, NON_COMPLIANT, UNKNOWN
    security_patch_level: str = ""  # Android only
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class MobileDeviceScanResult:
    """Results from a mobile device scan."""

    total_devices: int = 0
    android_devices: int = 0
    ios_devices: int = 0
    approved_devices: int = 0
    blocked_devices: int = 0
    pending_devices: int = 0
    compromised_devices: int = 0
    unencrypted_devices: int = 0
    no_password_devices: int = 0
    inactive_devices: int = 0
    devices: List[MobileDevice] = field(default_factory=list)
    issues: List[Dict] = field(default_factory=list)
    statistics: Dict = field(default_factory=dict)
    # Enhanced security metrics
    outdated_os_devices: int = 0
    developer_mode_devices: int = 0
    usb_debugging_devices: int = 0
    unknown_sources_devices: int = 0
    non_compliant_devices: int = 0
    high_risk_devices: int = 0
    recommendations: List[Dict] = field(default_factory=list)


class MobileDeviceScanner:
    """Scanner for mobile devices."""

    def __init__(self, client, domain: str, inactive_days: int = 90):
        """Initialize the mobile device scanner.

        Args:
            client: Authenticated Google Workspace client
            domain: Primary domain to scan
            inactive_days: Number of days to consider a device inactive
        """
        self.client = client
        self.domain = domain
        self.inactive_days = inactive_days
        self.logger = logger.bind(scanner="mobile_device", domain=domain)

    def scan_all_devices(
        self,
        max_users: Optional[int] = None,
        os_filter: Optional[str] = None
    ) -> MobileDeviceScanResult:
        """Scan all mobile devices in the domain with enhanced performance.

        Args:
            max_users: Maximum number of users to scan (for performance testing)
            os_filter: Filter by OS type ("ANDROID", "IOS", "IOS_SYNC")

        Returns:
            MobileDeviceScanResult with all findings

        Raises:
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_users is not None and (not isinstance(max_users, int) or max_users < 1):
            raise ValueError("max_users must be a positive integer")
        if os_filter and os_filter not in ["ANDROID", "IOS", "IOS_SYNC"]:
            raise ValueError("os_filter must be ANDROID, IOS, or IOS_SYNC")

        self.logger.info(
            "starting_mobile_device_scan",
            max_users=max_users,
            os_filter=os_filter
        )
        scan_start_time = time.time()

        result = MobileDeviceScanResult()
        failed_users = []

        try:
            # Get all users in the domain
            users = self._list_all_users()

            # Apply max_users limit if specified
            if max_users:
                users = users[:max_users]
                self.logger.info("limiting_scan_to_max_users", max_users=max_users)

            # Scan devices for each user
            scanned_users = 0
            for user in users:
                user_email = user.get("primaryEmail", "")

                try:
                    devices = self._scan_user_devices(user_email)
                    scanned_users += 1

                    # Log progress every 100 users
                    if scanned_users % 100 == 0:
                        self.logger.info(
                            "mobile_device_scan_progress",
                            scanned=scanned_users,
                            total=len(users),
                            devices_found=result.total_devices
                        )
                except HttpError as e:
                    if e.resp.status == 403:
                        self.logger.debug(
                            "insufficient_permissions_for_user",
                            user=user_email,
                            error=str(e)
                        )
                    else:
                        self.logger.warning(
                            "failed_to_scan_user_devices",
                            user=user_email,
                            error=str(e)
                        )
                    failed_users.append({"email": user_email, "error": str(e)})
                    continue
                except Exception as e:
                    self.logger.warning(
                        "unexpected_error_scanning_user",
                        user=user_email,
                        error=str(e)
                    )
                    failed_users.append({"email": user_email, "error": str(e)})
                    continue

                for device in devices:
                    # Apply OS filter if specified
                    if os_filter and device.os != os_filter:
                        continue
                    result.devices.append(device)
                    result.total_devices += 1

                    # Count by OS
                    if device.os == "ANDROID":
                        result.android_devices += 1
                    elif device.os in ["IOS", "IOS_SYNC"]:
                        result.ios_devices += 1

                    # Count by status
                    if device.status == "APPROVED":
                        result.approved_devices += 1
                    elif device.status == "BLOCKED":
                        result.blocked_devices += 1
                    elif device.status == "PENDING":
                        result.pending_devices += 1

                    # Count security issues
                    if device.is_compromised:
                        result.compromised_devices += 1
                    if not device.is_encrypted:
                        result.unencrypted_devices += 1
                    if not device.is_password_protected:
                        result.no_password_devices += 1

                    # Count enhanced security issues
                    if device.has_outdated_os:
                        result.outdated_os_devices += 1
                    if device.has_developer_mode:
                        result.developer_mode_devices += 1
                    if device.has_usb_debugging:
                        result.usb_debugging_devices += 1
                    if device.has_unknown_sources:
                        result.unknown_sources_devices += 1
                    if device.compliance_state == "NON_COMPLIANT":
                        result.non_compliant_devices += 1
                    if device.risk_score >= 70:
                        result.high_risk_devices += 1

                    # Check for inactive devices
                    if self._is_device_inactive(device):
                        result.inactive_devices += 1

            # Generate issues and recommendations
            result.issues = self._generate_issues(result)
            result.recommendations = self._generate_recommendations(result)

            # Calculate statistics
            result.statistics = self._calculate_statistics(result)

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            self.logger.info(
                "mobile_device_scan_complete",
                total_devices=result.total_devices,
                compromised=result.compromised_devices,
                unencrypted=result.unencrypted_devices,
                high_risk=result.high_risk_devices,
                outdated_os=result.outdated_os_devices,
                developer_mode=result.developer_mode_devices,
                issues=len(result.issues),
                recommendations=len(result.recommendations),
                failed_users=len(failed_users),
                scan_duration_seconds=round(scan_duration, 2),
            )

            # Log warning if many users failed
            if failed_users and len(failed_users) > 10:
                self.logger.warning(
                    "many_users_failed_mobile_scan",
                    failed_count=len(failed_users),
                    sample_errors=failed_users[:5]
                )

        except Exception as e:
            self.logger.error("mobile_device_scan_failed", error=str(e))
            raise

        return result

    def _list_all_users(self) -> List[Dict]:
        """List all users in the domain."""
        users = []
        page_token = None

        try:
            while True:
                response = (
                    self.client.admin.users()
                    .list(domain=self.domain, pageToken=page_token, maxResults=500)
                    .execute()
                )

                users.extend(response.get("users", []))

                page_token = response.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            self.logger.error("failed_to_list_users", error=str(e))
            raise

        return users

    def _scan_user_devices(self, user_email: str) -> List[MobileDevice]:
        """Scan mobile devices for a specific user."""
        devices = []

        try:
            # Get mobile devices for user
            response = (
                self.client.admin.mobiledevices()
                .list(customerId="my_customer", query=f"email:{user_email}")
                .execute()
            )

            for device_data in response.get("mobiledevices", []):
                device = self._parse_device(device_data, user_email)
                devices.append(device)

        except HttpError as e:
            self.logger.debug("failed_to_scan_devices", user=user_email, error=str(e))

        return devices

    def _parse_device(self, device_data: Dict, user_email: str) -> MobileDevice:
        """Parse a device from API response."""
        device = MobileDevice(
            device_id=device_data.get("deviceId", ""),
            resource_id=device_data.get("resourceId", ""),
            email=user_email,
            model=device_data.get("model", ""),
            os=device_data.get("os", ""),
            os_version=device_data.get("osVersion", ""),
            type=device_data.get("type", ""),
            status=device_data.get("status", ""),
            user_agent=device_data.get("userAgent", ""),
            imei=device_data.get("imei", ""),
            serial_number=device_data.get("serialNumber", ""),
        )

        # Parse timestamps
        if "lastSync" in device_data:
            device.last_sync = datetime.fromisoformat(device_data["lastSync"].replace("Z", "+00:00"))
        if "firstSync" in device_data:
            device.first_sync = datetime.fromisoformat(device_data["firstSync"].replace("Z", "+00:00"))

        # Parse security settings
        device.is_compromised = device_data.get("compromisedStatus", "") == "COMPROMISED"
        device.is_encrypted = device_data.get("encryptionStatus", "") == "ENCRYPTED"
        device.is_password_protected = device_data.get("passwordStatus", "") == "PASSWORD_SET"

        # Parse enhanced security settings
        device.compliance_state = device_data.get("complianceState", "UNKNOWN")
        device.security_patch_level = device_data.get("securityPatchLevel", "")

        # Android-specific settings
        if device.os == "ANDROID":
            device.has_unknown_sources = device_data.get("unknownSourcesStatus", False)
            device.has_developer_mode = device_data.get("developerOptionsStatus", False)
            device.has_usb_debugging = device_data.get("adbStatus", False)

        # iOS-specific settings
        if device.os in ["IOS", "IOS_SYNC"]:
            device.is_supervised = device_data.get("supvisionStatus", "") == "SUPERVISED"

        # Check for outdated OS
        device.has_outdated_os = self._is_os_outdated(device.os, device.os_version)

        # Calculate risk score
        device.risk_score = self._calculate_device_risk_score(device)

        return device

    def _calculate_device_risk_score(self, device: MobileDevice) -> int:
        """Calculate enhanced risk score for a device (0-100)."""
        score = 0
        device.risk_factors = []

        # CRITICAL: Compromised devices (rooted/jailbroken)
        if device.is_compromised:
            score += 50
            device.risk_factors.append("Device is compromised (rooted/jailbroken)")

        # HIGH: Developer mode or USB debugging enabled (Android)
        if device.has_developer_mode:
            score += 25
            device.risk_factors.append("Developer mode enabled")

        if device.has_usb_debugging:
            score += 20
            device.risk_factors.append("USB debugging enabled")

        # HIGH: Unknown sources enabled (Android)
        if device.has_unknown_sources:
            score += 20
            device.risk_factors.append("Unknown sources enabled")

        # HIGH: Unencrypted devices
        if not device.is_encrypted:
            score += 20
            device.risk_factors.append("Device not encrypted")

        # MEDIUM: No password protection
        if not device.is_password_protected:
            score += 15
            device.risk_factors.append("No password protection")

        # MEDIUM: Outdated OS
        if device.has_outdated_os:
            score += 15
            device.risk_factors.append(f"Outdated OS version: {device.os_version}")

        # MEDIUM: Non-compliant device
        if device.compliance_state == "NON_COMPLIANT":
            score += 15
            device.risk_factors.append("Device is non-compliant")

        # LOW: Blocked devices
        if device.status == "BLOCKED":
            score += 10
            device.risk_factors.append("Device is blocked")

        # LOW: Pending approval
        if device.status == "PENDING":
            score += 5
            device.risk_factors.append("Device pending approval")

        # LOW: Inactive devices
        if self._is_device_inactive(device):
            score += 5
            device.risk_factors.append(f"Device inactive for {self.inactive_days}+ days")

        # BONUS: iOS supervised devices are lower risk
        if device.is_supervised:
            score = int(score * 0.8)  # 20% reduction

        return min(100, score)

    def _is_device_inactive(self, device: MobileDevice) -> bool:
        """Check if a device is inactive."""
        if not device.last_sync:
            return True

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.inactive_days)
        return device.last_sync < cutoff_date

    def _is_os_outdated(self, os: str, os_version: str) -> bool:
        """Check if device OS version is outdated.

        Args:
            os: Operating system (ANDROID, IOS, etc.)
            os_version: OS version string

        Returns:
            True if OS is outdated
        """
        if not os_version:
            return True  # Unknown version is considered outdated

        try:
            # Extract major version number
            version_parts = os_version.split(".")
            if not version_parts:
                return True

            major_version = int(version_parts[0])

            # Android: versions below 11 are outdated (as of 2025)
            if os == "ANDROID":
                return major_version < 11

            # iOS: versions below 16 are outdated (as of 2025)
            if os in ["IOS", "IOS_SYNC"]:
                return major_version < 16

            # Unknown OS
            return False

        except (ValueError, IndexError):
            return True  # Can't parse version, consider outdated

    def _generate_issues(self, result: MobileDeviceScanResult) -> List[Dict]:
        """Generate enhanced list of security issues found."""
        issues = []

        # CRITICAL: Compromised devices
        for device in result.devices:
            if device.is_compromised:
                issues.append(
                    {
                        "type": "compromised_device",
                        "severity": "critical",
                        "device": device.model,
                        "os": device.os,
                        "user": device.email,
                        "description": "Device is compromised (rooted/jailbroken)",
                        "risk_score": device.risk_score,
                        "risk_factors": device.risk_factors,
                        "recommendation": "Block device immediately and investigate",
                    }
                )

        # HIGH: Developer mode enabled (Android)
        for device in result.devices:
            if device.has_developer_mode:
                issues.append(
                    {
                        "type": "developer_mode_enabled",
                        "severity": "high",
                        "device": device.model,
                        "os": device.os,
                        "user": device.email,
                        "description": "Developer mode is enabled",
                        "risk_score": device.risk_score,
                        "recommendation": "Require user to disable developer mode",
                    }
                )

        # HIGH: USB debugging enabled (Android)
        for device in result.devices:
            if device.has_usb_debugging:
                issues.append(
                    {
                        "type": "usb_debugging_enabled",
                        "severity": "high",
                        "device": device.model,
                        "os": device.os,
                        "user": device.email,
                        "description": "USB debugging is enabled",
                        "risk_score": device.risk_score,
                        "recommendation": "Require user to disable USB debugging",
                    }
                )

        # HIGH: Unknown sources enabled (Android)
        for device in result.devices:
            if device.has_unknown_sources:
                issues.append(
                    {
                        "type": "unknown_sources_enabled",
                        "severity": "high",
                        "device": device.model,
                        "os": device.os,
                        "user": device.email,
                        "description": "Unknown sources enabled (can install apps from outside Play Store)",
                        "risk_score": device.risk_score,
                        "recommendation": "Disable unknown sources to prevent malware",
                    }
                )

        # HIGH: Unencrypted devices
        for device in result.devices:
            if not device.is_encrypted:
                issues.append(
                    {
                        "type": "unencrypted_device",
                        "severity": "high",
                        "device": device.model,
                        "os": device.os,
                        "user": device.email,
                        "description": "Device is not encrypted",
                        "risk_score": device.risk_score,
                        "recommendation": "Enable device encryption",
                    }
                )

        # MEDIUM: No password protection
        for device in result.devices:
            if not device.is_password_protected:
                issues.append(
                    {
                        "type": "no_password_device",
                        "severity": "medium",
                        "device": device.model,
                        "os": device.os,
                        "user": device.email,
                        "description": "Device has no password protection",
                        "risk_score": device.risk_score,
                        "recommendation": "Require password/PIN/biometric authentication",
                    }
                )

        # MEDIUM: Outdated OS
        for device in result.devices:
            if device.has_outdated_os:
                issues.append(
                    {
                        "type": "outdated_os",
                        "severity": "medium",
                        "device": device.model,
                        "os": device.os,
                        "os_version": device.os_version,
                        "user": device.email,
                        "description": f"Device running outdated OS version: {device.os_version}",
                        "risk_score": device.risk_score,
                        "recommendation": "Update to latest OS version",
                    }
                )

        # MEDIUM: Non-compliant devices
        for device in result.devices:
            if device.compliance_state == "NON_COMPLIANT":
                issues.append(
                    {
                        "type": "non_compliant_device",
                        "severity": "medium",
                        "device": device.model,
                        "os": device.os,
                        "user": device.email,
                        "description": "Device is non-compliant with security policies",
                        "risk_score": device.risk_score,
                        "recommendation": "Review compliance requirements and remediate",
                    }
                )

        # LOW: Inactive devices
        for device in result.devices:
            if self._is_device_inactive(device):
                issues.append(
                    {
                        "type": "inactive_device",
                        "severity": "low",
                        "device": device.model,
                        "os": device.os,
                        "user": device.email,
                        "description": f"Device inactive for {self.inactive_days}+ days",
                        "last_sync": device.last_sync.isoformat() if device.last_sync else "Never",
                        "recommendation": "Consider removing inactive device",
                    }
                )

        return issues

    def _generate_recommendations(self, result: MobileDeviceScanResult) -> List[Dict]:
        """Generate security recommendations based on scan results."""
        recommendations = []

        # Recommendation: Enable Mobile Device Management
        if result.total_devices > 10 and result.high_risk_devices > 5:
            recommendations.append({
                "priority": "high",
                "title": "Enable Advanced Mobile Device Management",
                "description": f"{result.high_risk_devices} high-risk devices detected",
                "action": "Configure device policies in Admin Console > Devices > Mobile",
                "benefit": "Enforce security policies and reduce risk",
            })

        # Recommendation: Block compromised devices
        if result.compromised_devices > 0:
            recommendations.append({
                "priority": "critical",
                "title": f"Block {result.compromised_devices} Compromised Devices",
                "description": "Compromised devices pose immediate security risk",
                "action": "Block devices immediately and investigate",
                "benefit": "Prevent data breaches from rooted/jailbroken devices",
            })

        # Recommendation: Enforce encryption
        if result.unencrypted_devices > 5:
            recommendations.append({
                "priority": "high",
                "title": f"Enforce Encryption on {result.unencrypted_devices} Devices",
                "description": "Unencrypted devices expose data if lost or stolen",
                "action": "Enable encryption requirement in device policies",
                "benefit": "Protect data at rest on mobile devices",
            })

        # Recommendation: Disable developer mode
        if result.developer_mode_devices > 0:
            recommendations.append({
                "priority": "high",
                "title": f"Disable Developer Mode on {result.developer_mode_devices} Devices",
                "description": "Developer mode enables risky debugging features",
                "action": "Require users to disable developer mode",
                "benefit": "Reduce attack surface on Android devices",
            })

        # Recommendation: Update outdated devices
        if result.outdated_os_devices > 10:
            recommendations.append({
                "priority": "medium",
                "title": f"Update {result.outdated_os_devices} Devices with Outdated OS",
                "description": "Outdated OS versions have known security vulnerabilities",
                "action": "Notify users to update their devices",
                "benefit": "Patch security vulnerabilities",
            })

        # Recommendation: Remove inactive devices
        if result.inactive_devices > 20:
            recommendations.append({
                "priority": "low",
                "title": f"Remove {result.inactive_devices} Inactive Devices",
                "description": "Inactive devices may be lost or no longer in use",
                "action": "Review and remove inactive devices",
                "benefit": "Reduce attack surface and improve inventory accuracy",
            })

        return recommendations

    def _calculate_statistics(self, result: MobileDeviceScanResult) -> Dict:
        """Calculate enhanced summary statistics."""
        return {
            "total_devices": result.total_devices,
            "android_devices": result.android_devices,
            "ios_devices": result.ios_devices,
            "approved_devices": result.approved_devices,
            "blocked_devices": result.blocked_devices,
            "pending_devices": result.pending_devices,
            "compromised_devices": result.compromised_devices,
            "unencrypted_devices": result.unencrypted_devices,
            "no_password_devices": result.no_password_devices,
            "inactive_devices": result.inactive_devices,
            "outdated_os_devices": result.outdated_os_devices,
            "developer_mode_devices": result.developer_mode_devices,
            "usb_debugging_devices": result.usb_debugging_devices,
            "unknown_sources_devices": result.unknown_sources_devices,
            "non_compliant_devices": result.non_compliant_devices,
            "high_risk_devices": result.high_risk_devices,
            "total_issues": len(result.issues),
            "total_recommendations": len(result.recommendations),
        }

