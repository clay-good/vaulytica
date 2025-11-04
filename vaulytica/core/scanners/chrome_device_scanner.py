"""Chrome OS device scanner for Google Workspace Chrome Enterprise."""

import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime, timedelta, timezone
import structlog
from googleapiclient.errors import HttpError

logger = structlog.get_logger(__name__)


@dataclass
class ChromeDevice:
    """Represents a Chrome OS device (Chromebook, Chromebox, Chromebase)."""

    device_id: str
    serial_number: str
    asset_id: str = ""
    annotated_location: str = ""
    annotated_user: str = ""
    last_sync: Optional[datetime] = None
    last_enrollment_time: Optional[datetime] = None
    
    # Device info
    model: str = ""
    os_version: str = ""
    platform_version: str = ""
    firmware_version: str = ""
    
    # Status
    status: str = ""  # ACTIVE, PROVISIONED, DISABLED, DEPROVISIONED
    boot_mode: str = ""  # Verified, Dev
    
    # User info
    recent_users: List[str] = field(default_factory=list)
    
    # Security
    auto_update_expiration: Optional[datetime] = None
    is_auto_update_expired: bool = False
    
    # Network
    ethernet_mac_address: str = ""
    wifi_mac_address: str = ""
    
    # Organization
    org_unit_path: str = ""
    
    # Risk assessment
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)


@dataclass
class ChromeDeviceScanResult:
    """Results from a Chrome device scan."""

    total_devices: int = 0
    active_devices: int = 0
    provisioned_devices: int = 0
    disabled_devices: int = 0
    deprovisioned_devices: int = 0
    auto_update_expired: int = 0
    dev_mode_devices: int = 0
    inactive_devices: int = 0
    devices: List[ChromeDevice] = field(default_factory=list)
    issues: List[Dict] = field(default_factory=list)


class ChromeDeviceScanner:
    """Scanner for Chrome OS devices (Chromebooks, Chromeboxes, Chromebases)."""

    def __init__(self, client, customer_id: str = "my_customer", inactive_days: int = 90):
        """Initialize the Chrome device scanner.

        Args:
            client: Authenticated Google Workspace client
            customer_id: Customer ID (default: "my_customer")
            inactive_days: Number of days to consider a device inactive
        """
        self.client = client
        self.customer_id = customer_id
        self.inactive_days = inactive_days
        self.logger = logger.bind(scanner="chrome_device", customer=customer_id)

    def scan_all_devices(
        self,
        org_unit_path: Optional[str] = None,
        query: Optional[str] = None,
        max_devices: Optional[int] = None,
    ) -> ChromeDeviceScanResult:
        """Scan all Chrome OS devices with enhanced performance.

        Args:
            org_unit_path: Optional OU path to filter devices
            query: Optional search query
            max_devices: Maximum number of devices to scan (for performance testing)

        Returns:
            ChromeDeviceScanResult with all findings

        Raises:
            ValueError: If invalid parameters provided
        """
        # Input validation
        if max_devices is not None and (not isinstance(max_devices, int) or max_devices < 1):
            raise ValueError("max_devices must be a positive integer")
        if org_unit_path and not isinstance(org_unit_path, str):
            raise ValueError("org_unit_path must be a string")
        if query and not isinstance(query, str):
            raise ValueError("query must be a string")

        self.logger.info(
            "starting_chrome_device_scan",
            org_unit=org_unit_path,
            query=query,
            max_devices=max_devices,
        )
        scan_start_time = time.time()

        result = ChromeDeviceScanResult()
        failed_devices = []
        scanned_count = 0

        try:
            # List all Chrome devices
            devices = self._list_all_devices(org_unit_path, query)

            for device_data in devices:
                try:
                    device = self._parse_device(device_data)
                    result.devices.append(device)

                    # Update counters
                    result.total_devices += 1
                    scanned_count += 1

                    if device.status == "ACTIVE":
                        result.active_devices += 1
                    elif device.status == "PROVISIONED":
                        result.provisioned_devices += 1
                    elif device.status == "DISABLED":
                        result.disabled_devices += 1
                    elif device.status == "DEPROVISIONED":
                        result.deprovisioned_devices += 1

                    if device.is_auto_update_expired:
                        result.auto_update_expired += 1

                    if device.boot_mode == "Dev":
                        result.dev_mode_devices += 1

                    # Check if inactive
                    if device.last_sync:
                        days_since_sync = (datetime.now(timezone.utc) - device.last_sync).days
                        if days_since_sync > self.inactive_days:
                            result.inactive_devices += 1

                    # Log progress every 50 devices
                    if scanned_count % 50 == 0:
                        self.logger.info(
                            "chrome_device_scan_progress",
                            scanned=scanned_count,
                            active=result.active_devices,
                            expired=result.auto_update_expired,
                            dev_mode=result.dev_mode_devices,
                        )

                    # Check max_devices limit
                    if max_devices and scanned_count >= max_devices:
                        self.logger.info("max_devices_limit_reached", max_devices=max_devices)
                        break

                except Exception as e:
                    self.logger.warning(
                        "failed_to_parse_device",
                        device_id=device_data.get("deviceId", "unknown"),
                        error=str(e)
                    )
                    failed_devices.append({
                        "device_id": device_data.get("deviceId", "unknown"),
                        "error": str(e)
                    })
                    continue

            # Generate issues
            result.issues = self._generate_issues(result)

            # Calculate scan duration
            scan_duration = time.time() - scan_start_time

            self.logger.info(
                "chrome_device_scan_complete",
                total_devices=result.total_devices,
                active=result.active_devices,
                auto_update_expired=result.auto_update_expired,
                dev_mode=result.dev_mode_devices,
                failed_devices=len(failed_devices),
                scan_duration_seconds=round(scan_duration, 2),
            )

            # Log warning if many devices failed
            if failed_devices and len(failed_devices) > 5:
                self.logger.warning(
                    "many_devices_failed_parse",
                    failed_count=len(failed_devices),
                    sample_errors=failed_devices[:3]
                )

        except HttpError as e:
            if e.resp.status == 403:
                self.logger.error("insufficient_permissions_to_list_devices", error=str(e))
                raise
            else:
                self.logger.error("chrome_device_scan_failed", error=str(e))
                raise
        except Exception as e:
            self.logger.error("chrome_device_scan_failed", error=str(e))
            raise

        return result

    def _list_all_devices(
        self,
        org_unit_path: Optional[str] = None,
        query: Optional[str] = None,
    ) -> List[Dict]:
        """List all Chrome devices using pagination."""
        devices = []
        page_token = None

        try:
            while True:
                params = {
                    "customerId": self.customer_id,
                    "maxResults": 200,
                }
                
                if org_unit_path:
                    params["orgUnitPath"] = org_unit_path
                
                if query:
                    params["query"] = query
                
                if page_token:
                    params["pageToken"] = page_token

                response = self.client.admin.chromeosdevices().list(**params).execute()
                
                devices.extend(response.get("chromeosdevices", []))
                
                page_token = response.get("nextPageToken")
                if not page_token:
                    break

        except HttpError as e:
            self.logger.error("failed_to_list_devices", error=str(e))
            raise

        return devices

    def _parse_device(self, device_data: Dict) -> ChromeDevice:
        """Parse Chrome device data from API response."""
        
        # Parse timestamps
        last_sync = None
        if "lastSync" in device_data:
            try:
                last_sync = datetime.fromisoformat(
                    device_data["lastSync"].replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                pass

        last_enrollment = None
        if "lastEnrollmentTime" in device_data:
            try:
                last_enrollment = datetime.fromisoformat(
                    device_data["lastEnrollmentTime"].replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                pass

        auto_update_expiration = None
        is_expired = False
        if "autoUpdateExpiration" in device_data:
            try:
                auto_update_expiration = datetime.fromtimestamp(
                    int(device_data["autoUpdateExpiration"]) / 1000,
                    tz=timezone.utc
                )
                is_expired = auto_update_expiration < datetime.now(timezone.utc)
            except (ValueError, TypeError):
                pass

        # Extract recent users
        recent_users = []
        for user in device_data.get("recentUsers", []):
            if "email" in user:
                recent_users.append(user["email"])

        device = ChromeDevice(
            device_id=device_data.get("deviceId", ""),
            serial_number=device_data.get("serialNumber", ""),
            asset_id=device_data.get("annotatedAssetId", ""),
            annotated_location=device_data.get("annotatedLocation", ""),
            annotated_user=device_data.get("annotatedUser", ""),
            last_sync=last_sync,
            last_enrollment_time=last_enrollment,
            model=device_data.get("model", ""),
            os_version=device_data.get("osVersion", ""),
            platform_version=device_data.get("platformVersion", ""),
            firmware_version=device_data.get("firmwareVersion", ""),
            status=device_data.get("status", ""),
            boot_mode=device_data.get("bootMode", ""),
            recent_users=recent_users,
            auto_update_expiration=auto_update_expiration,
            is_auto_update_expired=is_expired,
            ethernet_mac_address=device_data.get("ethernetMacAddress", ""),
            wifi_mac_address=device_data.get("macAddress", ""),
            org_unit_path=device_data.get("orgUnitPath", ""),
        )

        # Calculate risk score
        device.risk_score = self._calculate_risk_score(device)

        return device

    def _calculate_risk_score(self, device: ChromeDevice) -> int:
        """Calculate risk score for a device (0-100)."""
        score = 0
        device.risk_factors = []

        # Auto-update expired (critical)
        if device.is_auto_update_expired:
            score += 40
            device.risk_factors.append("Auto-update expired")

        # Developer mode (high risk)
        if device.boot_mode == "Dev":
            score += 30
            device.risk_factors.append("Developer mode enabled")

        # Disabled/deprovisioned
        if device.status in ["DISABLED", "DEPROVISIONED"]:
            score += 20
            device.risk_factors.append(f"Device {device.status.lower()}")

        # Inactive device
        if device.last_sync:
            days_since_sync = (datetime.now(timezone.utc) - device.last_sync).days
            if days_since_sync > self.inactive_days:
                score += 10
                device.risk_factors.append(f"Inactive for {days_since_sync} days")

        return min(score, 100)

    def _generate_issues(self, result: ChromeDeviceScanResult) -> List[Dict]:
        """Generate list of security issues found."""
        issues = []

        # Auto-update expired devices
        for device in result.devices:
            if device.is_auto_update_expired:
                issues.append({
                    "type": "auto_update_expired",
                    "severity": "critical",
                    "device": device.model,
                    "serial": device.serial_number,
                    "user": device.annotated_user or "Unassigned",
                    "description": f"Auto-update expired on {device.auto_update_expiration}",
                    "risk_score": device.risk_score,
                })

        # Developer mode devices
        for device in result.devices:
            if device.boot_mode == "Dev":
                issues.append({
                    "type": "developer_mode",
                    "severity": "high",
                    "device": device.model,
                    "serial": device.serial_number,
                    "user": device.annotated_user or "Unassigned",
                    "description": "Device is in developer mode (security disabled)",
                    "risk_score": device.risk_score,
                })

        # Inactive devices
        for device in result.devices:
            if device.last_sync:
                days_since_sync = (datetime.now(timezone.utc) - device.last_sync).days
                if days_since_sync > self.inactive_days:
                    issues.append({
                        "type": "inactive_device",
                        "severity": "medium",
                        "device": device.model,
                        "serial": device.serial_number,
                        "user": device.annotated_user or "Unassigned",
                        "description": f"Device inactive for {days_since_sync} days",
                        "risk_score": device.risk_score,
                    })

        return issues

