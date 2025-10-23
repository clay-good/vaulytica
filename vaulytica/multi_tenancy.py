"""
Multi-Tenancy Support for Vaulytica.

Provides organization management, RBAC, data isolation, and billing.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Any
from uuid import uuid4

logger = logging.getLogger(__name__)


# ==================== Enums ====================

class OrganizationTier(str, Enum):
    """Organization subscription tiers."""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class UserRole(str, Enum):
    """User roles."""
    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    SECURITY_ANALYST = "security_analyst"
    INCIDENT_RESPONDER = "incident_responder"
    COMPLIANCE_OFFICER = "compliance_officer"
    VIEWER = "viewer"
    API_USER = "api_user"


class Permission(str, Enum):
    """Permissions."""
    # Incident permissions
    INCIDENT_VIEW = "incident.view"
    INCIDENT_CREATE = "incident.create"
    INCIDENT_UPDATE = "incident.update"
    INCIDENT_DELETE = "incident.delete"
    INCIDENT_ASSIGN = "incident.assign"

    # Alert permissions
    ALERT_VIEW = "alert.view"
    ALERT_ACKNOWLEDGE = "alert.acknowledge"
    ALERT_RESOLVE = "alert.resolve"

    # User permissions
    USER_VIEW = "user.view"
    USER_CREATE = "user.create"
    USER_UPDATE = "user.update"
    USER_DELETE = "user.delete"

    # Organization permissions
    ORG_VIEW = "org.view"
    ORG_UPDATE = "org.update"
    ORG_BILLING = "org.billing"

    # Configuration permissions
    CONFIG_VIEW = "config.view"
    CONFIG_UPDATE = "config.update"

    # Report permissions
    REPORT_VIEW = "report.view"
    REPORT_CREATE = "report.create"
    REPORT_EXPORT = "report.export"


class BillingStatus(str, Enum):
    """Billing status."""
    ACTIVE = "active"
    TRIAL = "trial"
    SUSPENDED = "suspended"
    CANCELLED = "cancelled"
    PAST_DUE = "past_due"


# ==================== Data Models ====================

@dataclass
class Organization:
    """Represents an organization (tenant)."""
    org_id: str
    name: str
    tier: OrganizationTier
    billing_status: BillingStatus
    created_at: datetime
    owner_user_id: str
    settings: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    max_users: int = 10
    max_incidents: int = 1000
    data_retention_days: int = 90
    api_rate_limit: int = 1000  # requests per hour


@dataclass
class User:
    """Represents a user."""
    user_id: str
    org_id: str
    email: str
    name: str
    role: UserRole
    permissions: Set[Permission]
    created_at: datetime
    last_login: Optional[datetime] = None
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoleDefinition:
    """Defines a role with permissions."""
    role: UserRole
    permissions: Set[Permission]
    description: str


@dataclass
class BillingInfo:
    """Billing information for an organization."""
    org_id: str
    tier: OrganizationTier
    billing_status: BillingStatus
    billing_email: str
    monthly_cost: float
    next_billing_date: datetime
    payment_method: Optional[str] = None
    invoice_history: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class UsageMetrics:
    """Usage metrics for an organization."""
    org_id: str
    period_start: datetime
    period_end: datetime
    incident_count: int = 0
    alert_count: int = 0
    api_calls: int = 0
    storage_gb: float = 0.0
    user_count: int = 0


# ==================== Multi-Tenancy Manager ====================

class MultiTenancyManager:
    """
    Multi-tenancy manager for Vaulytica.

    Provides:
    - Organization management
    - Role-based access control (RBAC)
    - Data isolation
    - Billing management
    """

    def __init__(self):
        """Initialize the multi-tenancy manager."""
        self.organizations: Dict[str, Organization] = {}
        self.users: Dict[str, User] = {}
        self.billing_info: Dict[str, BillingInfo] = {}
        self.usage_metrics: Dict[str, UsageMetrics] = {}
        self.role_definitions = self._initialize_role_definitions()
        logger.info("Multi-tenancy manager initialized")

    def _initialize_role_definitions(self) -> Dict[UserRole, RoleDefinition]:
        """Initialize role definitions with permissions."""
        return {
            UserRole.SUPER_ADMIN: RoleDefinition(
                role=UserRole.SUPER_ADMIN,
                permissions=set(Permission),  # All permissions
                description="Super administrator with full access"
            ),
            UserRole.ORG_ADMIN: RoleDefinition(
                role=UserRole.ORG_ADMIN,
                permissions={
                    Permission.INCIDENT_VIEW, Permission.INCIDENT_CREATE, Permission.INCIDENT_UPDATE,
                    Permission.INCIDENT_DELETE, Permission.INCIDENT_ASSIGN,
                    Permission.ALERT_VIEW, Permission.ALERT_ACKNOWLEDGE, Permission.ALERT_RESOLVE,
                    Permission.USER_VIEW, Permission.USER_CREATE, Permission.USER_UPDATE, Permission.USER_DELETE,
                    Permission.ORG_VIEW, Permission.ORG_UPDATE, Permission.ORG_BILLING,
                    Permission.CONFIG_VIEW, Permission.CONFIG_UPDATE,
                    Permission.REPORT_VIEW, Permission.REPORT_CREATE, Permission.REPORT_EXPORT
                },
                description="Organization administrator"
            ),
            UserRole.SECURITY_ANALYST: RoleDefinition(
                role=UserRole.SECURITY_ANALYST,
                permissions={
                    Permission.INCIDENT_VIEW, Permission.INCIDENT_CREATE, Permission.INCIDENT_UPDATE,
                    Permission.ALERT_VIEW, Permission.ALERT_ACKNOWLEDGE, Permission.ALERT_RESOLVE,
                    Permission.REPORT_VIEW, Permission.REPORT_CREATE
                },
                description="Security analyst"
            ),
            UserRole.INCIDENT_RESPONDER: RoleDefinition(
                role=UserRole.INCIDENT_RESPONDER,
                permissions={
                    Permission.INCIDENT_VIEW, Permission.INCIDENT_UPDATE, Permission.INCIDENT_ASSIGN,
                    Permission.ALERT_VIEW, Permission.ALERT_ACKNOWLEDGE, Permission.ALERT_RESOLVE
                },
                description="Incident responder"
            ),
            UserRole.COMPLIANCE_OFFICER: RoleDefinition(
                role=UserRole.COMPLIANCE_OFFICER,
                permissions={
                    Permission.INCIDENT_VIEW, Permission.ALERT_VIEW,
                    Permission.REPORT_VIEW, Permission.REPORT_CREATE, Permission.REPORT_EXPORT
                },
                description="Compliance officer"
            ),
            UserRole.VIEWER: RoleDefinition(
                role=UserRole.VIEWER,
                permissions={
                    Permission.INCIDENT_VIEW, Permission.ALERT_VIEW, Permission.REPORT_VIEW
                },
                description="Read-only viewer"
            ),
            UserRole.API_USER: RoleDefinition(
                role=UserRole.API_USER,
                permissions={
                    Permission.INCIDENT_VIEW, Permission.INCIDENT_CREATE,
                    Permission.ALERT_VIEW, Permission.ALERT_ACKNOWLEDGE
                },
                description="API user for integrations"
            )
        }

    # ==================== Organization Management ====================

    def create_organization(
        self,
        name: str,
        owner_email: str,
        owner_name: str,
        tier: OrganizationTier = OrganizationTier.FREE
    ) -> Organization:
        """Create a new organization."""
        org_id = str(uuid4())

        # Create organization
        org = Organization(
            org_id=org_id,
            name=name,
            tier=tier,
            billing_status=BillingStatus.TRIAL if tier != OrganizationTier.FREE else BillingStatus.ACTIVE,
            created_at=datetime.utcnow(),
            owner_user_id=""  # Will be set after creating owner user
        )

        # Set tier-specific limits
        if tier == OrganizationTier.FREE:
            org.max_users = 5
            org.max_incidents = 100
            org.data_retention_days = 30
            org.api_rate_limit = 100
        elif tier == OrganizationTier.STARTER:
            org.max_users = 10
            org.max_incidents = 1000
            org.data_retention_days = 90
            org.api_rate_limit = 1000
        elif tier == OrganizationTier.PROFESSIONAL:
            org.max_users = 50
            org.max_incidents = 10000
            org.data_retention_days = 365
            org.api_rate_limit = 10000
        elif tier == OrganizationTier.ENTERPRISE:
            org.max_users = 1000
            org.max_incidents = 100000
            org.data_retention_days = 730
            org.api_rate_limit = 100000

        # Create owner user
        owner_user = self.create_user(
            org_id=org_id,
            email=owner_email,
            name=owner_name,
            role=UserRole.ORG_ADMIN
        )

        org.owner_user_id = owner_user.user_id
        self.organizations[org_id] = org

        logger.info(f"Created organization: {name} ({tier})")
        return org

    def get_organization(self, org_id: str) -> Optional[Organization]:
        """Get an organization by ID."""
        return self.organizations.get(org_id)

    def update_organization(self, org_id: str, **updates) -> Optional[Organization]:
        """Update an organization."""
        org = self.organizations.get(org_id)
        if not org:
            return None

        for key, value in updates.items():
            if hasattr(org, key):
                setattr(org, key, value)

        logger.info(f"Updated organization: {org_id}")
        return org

    # ==================== User Management ====================

    def create_user(
        self,
        org_id: str,
        email: str,
        name: str,
        role: UserRole
    ) -> User:
        """Create a new user."""
        user_id = str(uuid4())

        # Get permissions for role
        role_def = self.role_definitions.get(role)
        permissions = role_def.permissions if role_def else set()

        user = User(
            user_id=user_id,
            org_id=org_id,
            email=email,
            name=name,
            role=role,
            permissions=permissions,
            created_at=datetime.utcnow()
        )

        self.users[user_id] = user
        logger.info(f"Created user: {email} ({role})")
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        """Get a user by ID."""
        return self.users.get(user_id)

    def get_org_users(self, org_id: str) -> List[User]:
        """Get all users for an organization."""
        return [u for u in self.users.values() if u.org_id == org_id]

    def check_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if a user has a specific permission."""
        user = self.users.get(user_id)
        if not user:
            return False

        return permission in user.permissions

    # ==================== Data Isolation ====================

    def get_org_data(self, org_id: str, data_type: str) -> List[Any]:
        """Get data for an organization (enforces data isolation)."""
        # This would filter data by org_id in production
        logger.info(f"Fetching {data_type} data for org: {org_id}")
        return []

    def validate_data_access(self, user_id: str, resource_org_id: str) -> bool:
        """Validate that a user can access data from a specific org."""
        user = self.users.get(user_id)
        if not user:
            return False

        # Users can only access data from their own organization
        return user.org_id == resource_org_id


# Global multi-tenancy manager instance
_tenancy_manager: Optional[MultiTenancyManager] = None


def get_tenancy_manager() -> MultiTenancyManager:
    """Get the global multi-tenancy manager instance."""
    global _tenancy_manager
    if _tenancy_manager is None:
        _tenancy_manager = MultiTenancyManager()
    return _tenancy_manager
