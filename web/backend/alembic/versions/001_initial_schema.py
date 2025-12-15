"""Initial database schema for Vaulytica web app.

Revision ID: 001
Revises: None
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all tables."""
    # Webapp Users table
    op.create_table(
        'webapp_users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255)),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('is_superuser', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('last_login', sa.DateTime()),
    )
    op.create_index('ix_webapp_users_email', 'webapp_users', ['email'])

    # Domains table
    op.create_table(
        'domains',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(255), unique=True, nullable=False),
        sa.Column('display_name', sa.String(255)),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('credentials_path', sa.Text()),
        sa.Column('admin_email', sa.String(255)),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index('ix_domains_name', 'domains', ['name'])

    # User Domains table
    op.create_table(
        'user_domains',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('webapp_users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('domain', sa.String(255), nullable=False),
        sa.Column('role', sa.String(50), default='viewer'),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
    op.create_index('idx_user_domain', 'user_domains', ['user_id', 'domain'], unique=True)

    # Scan Runs table
    op.create_table(
        'scan_runs',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('start_time', sa.DateTime(), nullable=False, default=sa.func.now()),
        sa.Column('end_time', sa.DateTime()),
        sa.Column('status', sa.String(20), nullable=False, default='running'),
        sa.Column('domain_id', sa.Integer(), sa.ForeignKey('domains.id')),
        sa.Column('domain_name', sa.String(255), nullable=False),
        sa.Column('total_items', sa.Integer(), default=0),
        sa.Column('issues_found', sa.Integer(), default=0),
        sa.Column('high_risk_count', sa.Integer(), default=0),
        sa.Column('medium_risk_count', sa.Integer(), default=0),
        sa.Column('low_risk_count', sa.Integer(), default=0),
        sa.Column('config', sa.JSON()),
        sa.Column('error_message', sa.Text()),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('triggered_by', sa.String(255)),
    )
    op.create_index('ix_scan_runs_scan_type', 'scan_runs', ['scan_type'])
    op.create_index('ix_scan_runs_domain_name', 'scan_runs', ['domain_name'])
    op.create_index('idx_scan_run_domain_time', 'scan_runs', ['domain_name', 'start_time'])
    op.create_index('idx_scan_run_status', 'scan_runs', ['status'])

    # Security Findings table
    op.create_table(
        'security_findings',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('scan_run_id', sa.Integer(), sa.ForeignKey('scan_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('check_id', sa.String(50), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('severity', sa.String(20), nullable=False),
        sa.Column('passed', sa.Boolean(), nullable=False),
        sa.Column('current_value', sa.Text()),
        sa.Column('expected_value', sa.Text()),
        sa.Column('impact', sa.Text()),
        sa.Column('remediation', sa.Text()),
        sa.Column('frameworks', sa.JSON()),
        sa.Column('resource_type', sa.String(100)),
        sa.Column('resource_id', sa.String(255)),
        sa.Column('detected_at', sa.DateTime(), default=sa.func.now()),
    )
    op.create_index('ix_security_findings_check_id', 'security_findings', ['check_id'])
    op.create_index('ix_security_findings_severity', 'security_findings', ['severity'])
    op.create_index('ix_security_findings_passed', 'security_findings', ['passed'])
    op.create_index('idx_finding_severity', 'security_findings', ['severity', 'passed'])
    op.create_index('idx_finding_scan', 'security_findings', ['scan_run_id', 'severity'])

    # File Findings table
    op.create_table(
        'file_findings',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('scan_run_id', sa.Integer(), sa.ForeignKey('scan_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('file_id', sa.String(255), nullable=False),
        sa.Column('file_name', sa.String(500), nullable=False),
        sa.Column('owner_email', sa.String(255)),
        sa.Column('owner_name', sa.String(255)),
        sa.Column('mime_type', sa.String(255)),
        sa.Column('file_size', sa.Integer()),
        sa.Column('web_view_link', sa.Text()),
        sa.Column('is_public', sa.Boolean(), default=False),
        sa.Column('is_shared_externally', sa.Boolean(), default=False),
        sa.Column('external_domains', sa.JSON()),
        sa.Column('external_emails', sa.JSON()),
        sa.Column('risk_score', sa.Integer(), default=0),
        sa.Column('pii_detected', sa.Boolean(), default=False),
        sa.Column('pii_types', sa.JSON()),
        sa.Column('created_time', sa.DateTime()),
        sa.Column('modified_time', sa.DateTime()),
        sa.Column('detected_at', sa.DateTime(), default=sa.func.now()),
    )
    op.create_index('ix_file_findings_file_id', 'file_findings', ['file_id'])
    op.create_index('ix_file_findings_owner_email', 'file_findings', ['owner_email'])
    op.create_index('ix_file_findings_is_public', 'file_findings', ['is_public'])
    op.create_index('ix_file_findings_is_shared_externally', 'file_findings', ['is_shared_externally'])
    op.create_index('idx_file_finding_risk', 'file_findings', ['risk_score'])
    op.create_index('idx_file_finding_sharing', 'file_findings', ['is_public', 'is_shared_externally'])

    # User Findings table
    op.create_table(
        'user_findings',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('scan_run_id', sa.Integer(), sa.ForeignKey('scan_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.String(255), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255)),
        sa.Column('is_admin', sa.Boolean(), default=False),
        sa.Column('is_suspended', sa.Boolean(), default=False),
        sa.Column('is_archived', sa.Boolean(), default=False),
        sa.Column('last_login_time', sa.DateTime()),
        sa.Column('creation_time', sa.DateTime()),
        sa.Column('two_factor_enabled', sa.Boolean(), default=False),
        sa.Column('org_unit_path', sa.String(500)),
        sa.Column('is_inactive', sa.Boolean(), default=False),
        sa.Column('days_since_last_login', sa.Integer()),
        sa.Column('risk_score', sa.Integer(), default=0),
        sa.Column('risk_factors', sa.JSON()),
        sa.Column('detected_at', sa.DateTime(), default=sa.func.now()),
    )
    op.create_index('ix_user_findings_user_id', 'user_findings', ['user_id'])
    op.create_index('ix_user_findings_email', 'user_findings', ['email'])
    op.create_index('ix_user_findings_is_inactive', 'user_findings', ['is_inactive'])
    op.create_index('idx_user_finding_inactive', 'user_findings', ['is_inactive'])
    op.create_index('idx_user_finding_2fa', 'user_findings', ['two_factor_enabled'])

    # OAuth Findings table
    op.create_table(
        'oauth_findings',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('scan_run_id', sa.Integer(), sa.ForeignKey('scan_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('client_id', sa.String(255), nullable=False),
        sa.Column('display_text', sa.String(500)),
        sa.Column('scopes', sa.JSON()),
        sa.Column('user_count', sa.Integer(), default=0),
        sa.Column('users', sa.JSON()),
        sa.Column('risk_score', sa.Integer(), default=0),
        sa.Column('is_verified', sa.Boolean(), default=False),
        sa.Column('is_google_app', sa.Boolean(), default=False),
        sa.Column('is_internal', sa.Boolean(), default=False),
        sa.Column('risk_factors', sa.JSON()),
        sa.Column('detected_at', sa.DateTime(), default=sa.func.now()),
    )
    op.create_index('ix_oauth_findings_client_id', 'oauth_findings', ['client_id'])
    op.create_index('idx_oauth_finding_risk', 'oauth_findings', ['risk_score'])
    op.create_index('idx_oauth_finding_verified', 'oauth_findings', ['is_verified'])

    # Audit Logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('webapp_users.id', ondelete='SET NULL')),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(100)),
        sa.Column('resource_id', sa.String(255)),
        sa.Column('details', sa.JSON()),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text()),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_created_at', 'audit_logs', ['created_at'])
    op.create_index('idx_audit_log_user_action', 'audit_logs', ['user_id', 'action'])

    # Alert Rules table
    op.create_table(
        'alert_rules',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('domain_id', sa.Integer(), sa.ForeignKey('domains.id', ondelete='CASCADE')),
        sa.Column('condition_type', sa.String(50), nullable=False),
        sa.Column('condition_value', sa.JSON()),
        sa.Column('notification_channels', sa.JSON()),
        sa.Column('notification_config', sa.JSON()),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('webapp_users.id', ondelete='SET NULL')),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )

    # Scheduled Scans table
    op.create_table(
        'scheduled_scans',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('domain_id', sa.Integer(), sa.ForeignKey('domains.id', ondelete='CASCADE'), nullable=False),
        sa.Column('scan_type', sa.String(50), nullable=False),
        sa.Column('schedule_type', sa.String(20), nullable=False),
        sa.Column('schedule_config', sa.JSON()),
        sa.Column('scan_config', sa.JSON()),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('last_run', sa.DateTime()),
        sa.Column('next_run', sa.DateTime()),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('webapp_users.id', ondelete='SET NULL')),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table('scheduled_scans')
    op.drop_table('alert_rules')
    op.drop_table('audit_logs')
    op.drop_table('oauth_findings')
    op.drop_table('user_findings')
    op.drop_table('file_findings')
    op.drop_table('security_findings')
    op.drop_table('scan_runs')
    op.drop_table('user_domains')
    op.drop_table('domains')
    op.drop_table('webapp_users')
