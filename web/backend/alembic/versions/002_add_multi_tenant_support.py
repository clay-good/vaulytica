"""Add multi-tenant support with tenant_id and row-level security.

Revision ID: 002
Revises: 001
Create Date: 2024-12-14 00:00:00.000000

This migration adds proper multi-tenant support by:
1. Creating a tenants table
2. Adding tenant_id foreign key to all data tables
3. Creating row-level security policies for PostgreSQL
4. Adding appropriate indexes for tenant-based queries
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '002'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add multi-tenant support."""
    # Get database dialect
    bind = op.get_bind()
    dialect = bind.dialect.name

    # Create tenants table
    op.create_table(
        'tenants',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), unique=True, nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True, nullable=False),
        sa.Column('plan', sa.String(50), default='free'),  # free, professional, enterprise
        sa.Column('max_domains', sa.Integer(), default=1),
        sa.Column('max_users', sa.Integer(), default=5),
        sa.Column('settings', sa.JSON()),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )
    op.create_index('ix_tenants_slug', 'tenants', ['slug'], unique=True)
    op.create_index('ix_tenants_is_active', 'tenants', ['is_active'])

    # Add tenant_id to domains table
    op.add_column('domains', sa.Column('tenant_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_domains_tenant_id', 'domains', 'tenants',
        ['tenant_id'], ['id'], ondelete='CASCADE'
    )
    op.create_index('ix_domains_tenant_id', 'domains', ['tenant_id'])

    # Add tenant_id to webapp_users table (users belong to a tenant)
    op.add_column('webapp_users', sa.Column('tenant_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_webapp_users_tenant_id', 'webapp_users', 'tenants',
        ['tenant_id'], ['id'], ondelete='SET NULL'
    )
    op.create_index('ix_webapp_users_tenant_id', 'webapp_users', ['tenant_id'])

    # Add tenant_id to scan_runs table
    op.add_column('scan_runs', sa.Column('tenant_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_scan_runs_tenant_id', 'scan_runs', 'tenants',
        ['tenant_id'], ['id'], ondelete='CASCADE'
    )
    op.create_index('ix_scan_runs_tenant_id', 'scan_runs', ['tenant_id'])
    op.create_index('idx_scan_runs_tenant_domain', 'scan_runs', ['tenant_id', 'domain_name'])

    # Add tenant_id to audit_logs table
    op.add_column('audit_logs', sa.Column('tenant_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_audit_logs_tenant_id', 'audit_logs', 'tenants',
        ['tenant_id'], ['id'], ondelete='SET NULL'
    )
    op.create_index('ix_audit_logs_tenant_id', 'audit_logs', ['tenant_id'])

    # Add tenant_id to alert_rules table
    op.add_column('alert_rules', sa.Column('tenant_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_alert_rules_tenant_id', 'alert_rules', 'tenants',
        ['tenant_id'], ['id'], ondelete='CASCADE'
    )
    op.create_index('ix_alert_rules_tenant_id', 'alert_rules', ['tenant_id'])

    # Add tenant_id to scheduled_scans table
    op.add_column('scheduled_scans', sa.Column('tenant_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'fk_scheduled_scans_tenant_id', 'scheduled_scans', 'tenants',
        ['tenant_id'], ['id'], ondelete='CASCADE'
    )
    op.create_index('ix_scheduled_scans_tenant_id', 'scheduled_scans', ['tenant_id'])

    # Create tenant_members table for user-tenant mapping
    op.create_table(
        'tenant_members',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('tenant_id', sa.Integer(), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('webapp_users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role', sa.String(50), default='member', nullable=False),  # owner, admin, member
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
    op.create_index('idx_tenant_members_tenant_user', 'tenant_members', ['tenant_id', 'user_id'], unique=True)
    op.create_index('ix_tenant_members_user_id', 'tenant_members', ['user_id'])

    # For PostgreSQL, add Row Level Security (RLS) policies
    if dialect == 'postgresql':
        # Enable RLS on data tables
        op.execute(text("ALTER TABLE scan_runs ENABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE security_findings ENABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE file_findings ENABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE user_findings ENABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE oauth_findings ENABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE scheduled_scans ENABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE domains ENABLE ROW LEVEL SECURITY"))

        # Create RLS policies for scan_runs
        op.execute(text("""
            CREATE POLICY scan_runs_tenant_isolation ON scan_runs
                USING (
                    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::int
                    OR tenant_id IS NULL
                )
        """))

        # Create RLS policies for domains
        op.execute(text("""
            CREATE POLICY domains_tenant_isolation ON domains
                USING (
                    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::int
                    OR tenant_id IS NULL
                )
        """))

        # Create RLS policies for findings (via scan_run_id)
        op.execute(text("""
            CREATE POLICY security_findings_tenant_isolation ON security_findings
                USING (
                    scan_run_id IN (
                        SELECT id FROM scan_runs
                        WHERE tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::int
                        OR tenant_id IS NULL
                    )
                )
        """))

        op.execute(text("""
            CREATE POLICY file_findings_tenant_isolation ON file_findings
                USING (
                    scan_run_id IN (
                        SELECT id FROM scan_runs
                        WHERE tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::int
                        OR tenant_id IS NULL
                    )
                )
        """))

        op.execute(text("""
            CREATE POLICY user_findings_tenant_isolation ON user_findings
                USING (
                    scan_run_id IN (
                        SELECT id FROM scan_runs
                        WHERE tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::int
                        OR tenant_id IS NULL
                    )
                )
        """))

        op.execute(text("""
            CREATE POLICY oauth_findings_tenant_isolation ON oauth_findings
                USING (
                    scan_run_id IN (
                        SELECT id FROM scan_runs
                        WHERE tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::int
                        OR tenant_id IS NULL
                    )
                )
        """))

        # Create RLS policies for audit_logs
        op.execute(text("""
            CREATE POLICY audit_logs_tenant_isolation ON audit_logs
                USING (
                    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::int
                    OR tenant_id IS NULL
                )
        """))

        # Create RLS policies for alert_rules
        op.execute(text("""
            CREATE POLICY alert_rules_tenant_isolation ON alert_rules
                USING (
                    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::int
                    OR tenant_id IS NULL
                )
        """))

        # Create RLS policies for scheduled_scans
        op.execute(text("""
            CREATE POLICY scheduled_scans_tenant_isolation ON scheduled_scans
                USING (
                    tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::int
                    OR tenant_id IS NULL
                )
        """))

        # Create function to set tenant context
        op.execute(text("""
            CREATE OR REPLACE FUNCTION set_tenant_context(tenant_id_param integer)
            RETURNS void AS $$
            BEGIN
                PERFORM set_config('app.current_tenant_id', tenant_id_param::text, false);
            END;
            $$ LANGUAGE plpgsql;
        """))

        # Create function to get current tenant
        op.execute(text("""
            CREATE OR REPLACE FUNCTION get_current_tenant_id()
            RETURNS integer AS $$
            BEGIN
                RETURN NULLIF(current_setting('app.current_tenant_id', true), '')::int;
            END;
            $$ LANGUAGE plpgsql;
        """))


def downgrade() -> None:
    """Remove multi-tenant support."""
    bind = op.get_bind()
    dialect = bind.dialect.name

    # For PostgreSQL, drop RLS policies first
    if dialect == 'postgresql':
        # Drop functions
        op.execute(text("DROP FUNCTION IF EXISTS set_tenant_context(integer)"))
        op.execute(text("DROP FUNCTION IF EXISTS get_current_tenant_id()"))

        # Drop policies
        op.execute(text("DROP POLICY IF EXISTS scan_runs_tenant_isolation ON scan_runs"))
        op.execute(text("DROP POLICY IF EXISTS domains_tenant_isolation ON domains"))
        op.execute(text("DROP POLICY IF EXISTS security_findings_tenant_isolation ON security_findings"))
        op.execute(text("DROP POLICY IF EXISTS file_findings_tenant_isolation ON file_findings"))
        op.execute(text("DROP POLICY IF EXISTS user_findings_tenant_isolation ON user_findings"))
        op.execute(text("DROP POLICY IF EXISTS oauth_findings_tenant_isolation ON oauth_findings"))
        op.execute(text("DROP POLICY IF EXISTS audit_logs_tenant_isolation ON audit_logs"))
        op.execute(text("DROP POLICY IF EXISTS alert_rules_tenant_isolation ON alert_rules"))
        op.execute(text("DROP POLICY IF EXISTS scheduled_scans_tenant_isolation ON scheduled_scans"))

        # Disable RLS on tables
        op.execute(text("ALTER TABLE scan_runs DISABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE security_findings DISABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE file_findings DISABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE user_findings DISABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE oauth_findings DISABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE alert_rules DISABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE scheduled_scans DISABLE ROW LEVEL SECURITY"))
        op.execute(text("ALTER TABLE domains DISABLE ROW LEVEL SECURITY"))

    # Drop tenant_members table
    op.drop_table('tenant_members')

    # Remove tenant_id from scheduled_scans
    op.drop_index('ix_scheduled_scans_tenant_id', 'scheduled_scans')
    op.drop_constraint('fk_scheduled_scans_tenant_id', 'scheduled_scans', type_='foreignkey')
    op.drop_column('scheduled_scans', 'tenant_id')

    # Remove tenant_id from alert_rules
    op.drop_index('ix_alert_rules_tenant_id', 'alert_rules')
    op.drop_constraint('fk_alert_rules_tenant_id', 'alert_rules', type_='foreignkey')
    op.drop_column('alert_rules', 'tenant_id')

    # Remove tenant_id from audit_logs
    op.drop_index('ix_audit_logs_tenant_id', 'audit_logs')
    op.drop_constraint('fk_audit_logs_tenant_id', 'audit_logs', type_='foreignkey')
    op.drop_column('audit_logs', 'tenant_id')

    # Remove tenant_id from scan_runs
    op.drop_index('idx_scan_runs_tenant_domain', 'scan_runs')
    op.drop_index('ix_scan_runs_tenant_id', 'scan_runs')
    op.drop_constraint('fk_scan_runs_tenant_id', 'scan_runs', type_='foreignkey')
    op.drop_column('scan_runs', 'tenant_id')

    # Remove tenant_id from webapp_users
    op.drop_index('ix_webapp_users_tenant_id', 'webapp_users')
    op.drop_constraint('fk_webapp_users_tenant_id', 'webapp_users', type_='foreignkey')
    op.drop_column('webapp_users', 'tenant_id')

    # Remove tenant_id from domains
    op.drop_index('ix_domains_tenant_id', 'domains')
    op.drop_constraint('fk_domains_tenant_id', 'domains', type_='foreignkey')
    op.drop_column('domains', 'tenant_id')

    # Drop tenants table
    op.drop_index('ix_tenants_is_active', 'tenants')
    op.drop_index('ix_tenants_slug', 'tenants')
    op.drop_table('tenants')
