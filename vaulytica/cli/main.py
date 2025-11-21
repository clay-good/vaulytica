"""Main CLI entry point for Vaulytica."""

import sys
from pathlib import Path
from typing import Optional

import click
import structlog
from rich.console import Console
from rich.panel import Panel

from vaulytica import __version__

# Initialize console for rich output
console = Console()

# Configure structured logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)


@click.group()
@click.version_option(version=__version__, prog_name="vaulytica")
@click.option(
    "--config",
    "-c",
    type=click.Path(path_type=Path),
    envvar="VAULYTICA_CONFIG",
    help="Path to configuration file (default: config.yaml)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug logging",
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path], verbose: bool, debug: bool) -> None:
    """Vaulytica: Google Workspace Security & Compliance Tool.

    An open-source CLI tool for scanning Google Workspace for security issues,
    detecting PII in shared files, and managing employee lifecycle.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)

    # Store config path in context
    ctx.obj["config_path"] = config or Path("config.yaml")
    ctx.obj["verbose"] = verbose
    ctx.obj["debug"] = debug

    # Configure logging level
    if debug:
        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(logging_level=10)  # DEBUG
        )
    elif verbose:
        structlog.configure(
            wrapper_class=structlog.make_filtering_bound_logger(logging_level=20)  # INFO
        )

    logger.debug("cli_initialized", config=str(config), verbose=verbose, debug=debug)


@cli.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Show version information."""
    console.print(
        Panel(
            f"[bold cyan]Vaulytica[/bold cyan] v{__version__}\n\n"
            f"Open-source Google Workspace security tool\n"
            f"License: MIT",
            title="Version Info",
            border_style="cyan",
        )
    )


@cli.command()
@click.option(
    "--oauth",
    is_flag=True,
    help="Use OAuth 2.0 instead of service account",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing configuration",
)
@click.pass_context
def init(ctx: click.Context, oauth: bool, force: bool) -> None:
    """Initialize Vaulytica configuration.

    Creates a config.yaml file with default settings.
    """
    from vaulytica.cli.commands.init import init_command

    init_command(ctx, oauth, force)


# Import and register custom PII commands
from vaulytica.cli.commands.custom_pii import custom_pii_group
cli.add_command(custom_pii_group)


@cli.group()
@click.pass_context
def scan(ctx: click.Context) -> None:
    """Scan Google Workspace for security issues."""
    pass


@scan.command("files")
@click.option(
    "--domain",
    "-d",
    help="Domain to scan (from config if not specified)",
)
@click.option(
    "--external-only",
    is_flag=True,
    help="Only scan files shared externally",
)
@click.option(
    "--public-only",
    is_flag=True,
    help="Only scan publicly shared files",
)
@click.option(
    "--check-pii",
    is_flag=True,
    help="Check files for PII (Personally Identifiable Information)",
)
@click.option(
    "--user",
    "-u",
    help="Scan specific user's files only",
)
@click.option(
    "--incremental",
    is_flag=True,
    help="Only scan files modified since last scan",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (auto-generated if not specified)",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["csv", "json"], case_sensitive=False),
    default="csv",
    help="Output format",
)
@click.pass_context
def scan_files(
    ctx: click.Context,
    domain: Optional[str],
    external_only: bool,
    public_only: bool,
    check_pii: bool,
    user: Optional[str],
    incremental: bool,
    output: Optional[Path],
    format: str,
) -> None:
    """Scan Google Drive files for sharing and PII issues."""
    from vaulytica.cli.commands.scan import scan_files_command

    scan_files_command(
        ctx, domain, external_only, public_only, check_pii, user, incremental, output, format
    )


@scan.command("users")
@click.option(
    "--domain",
    "-d",
    help="Domain to scan (from config if not specified)",
)
@click.option(
    "--inactive-days",
    type=int,
    default=90,
    help="Consider users inactive after N days",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["csv", "json"], case_sensitive=False),
    default="csv",
    help="Output format",
)
@click.pass_context
def scan_users(
    ctx: click.Context,
    domain: Optional[str],
    inactive_days: int,
    output: Optional[Path],
    format: str,
) -> None:
    """Scan for inactive users and service accounts."""
    from vaulytica.cli.commands.scan import scan_users_command

    scan_users_command(ctx, domain, inactive_days, output, format)


@scan.command("shared-drives")
@click.option(
    "--domain",
    "-d",
    help="Domain to scan (from config if not specified)",
)
@click.option(
    "--scan-files/--no-scan-files",
    default=True,
    help="Scan files within Shared Drives",
)
@click.option(
    "--external-only",
    is_flag=True,
    help="Only scan files shared externally",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path",
)
@click.pass_context
def scan_shared_drives(
    ctx: click.Context,
    domain: Optional[str],
    scan_files: bool,
    external_only: bool,
    output: Optional[Path],
) -> None:
    """Scan Shared Drives for security issues."""
    from vaulytica.cli.commands.scan import scan_shared_drives_command

    scan_shared_drives_command(ctx, domain, scan_files, external_only, output)


@scan.command("oauth-apps")
@click.option(
    "--domain",
    "-d",
    help="Domain to scan (from config if not specified)",
)
@click.option(
    "--user",
    "-u",
    help="Scan specific user's OAuth tokens only",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path",
)
@click.pass_context
def scan_oauth_apps(
    ctx: click.Context,
    domain: Optional[str],
    user: Optional[str],
    output: Optional[Path],
) -> None:
    """Scan OAuth apps and third-party integrations."""
    from vaulytica.cli.commands.scan import scan_oauth_apps_command

    scan_oauth_apps_command(ctx, domain, user, output)


@scan.command("groups")
@click.option(
    "--external-members",
    is_flag=True,
    help="Show only groups with external members",
)
@click.option(
    "--public-groups",
    is_flag=True,
    help="Show only public groups",
)
@click.option(
    "--orphaned",
    is_flag=True,
    help="Show only orphaned groups (no owners)",
)
@click.option(
    "--min-risk-score",
    type=int,
    default=0,
    help="Minimum risk score (0-100)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Save results to file (CSV or JSON)",
)
@click.pass_context
def scan_groups(
    ctx: click.Context,
    external_members: bool,
    public_groups: bool,
    orphaned: bool,
    min_risk_score: int,
    output: Optional[Path],
) -> None:
    """Scan Google Groups for security issues."""
    from vaulytica.cli.commands.scan import scan_groups_command

    scan_groups_command(ctx, external_members, public_groups, orphaned, min_risk_score, output)


@scan.command("gmail")
@click.option(
    "--domain",
    "-d",
    help="Domain to scan (from config if not specified)",
)
@click.option(
    "--user",
    "-u",
    help="Specific user email to scan",
)
@click.option(
    "--days-back",
    type=int,
    default=30,
    help="Number of days to look back (default: 30)",
)
@click.option(
    "--max-messages",
    type=int,
    default=100,
    help="Maximum messages to scan per user (default: 100)",
)
@click.option(
    "--check-pii",
    is_flag=True,
    help="Scan attachments for PII",
)
@click.option(
    "--external-only",
    is_flag=True,
    help="Only scan emails sent to external recipients",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Save results to file (CSV or JSON)",
)
@click.pass_context
def scan_gmail(
    ctx: click.Context,
    domain: Optional[str],
    user: Optional[str],
    days_back: int,
    max_messages: int,
    check_pii: bool,
    external_only: bool,
    output: Optional[Path],
) -> None:
    """Scan Gmail messages and attachments for PII."""
    from vaulytica.cli.commands.scan import scan_gmail_command

    scan_gmail_command(ctx, domain, user, days_back, max_messages, check_pii, external_only, output)


@scan.command("gmail-security")
@click.option(
    "--delegates",
    is_flag=True,
    help="Check for Gmail delegates",
)
@click.option(
    "--forwarding",
    is_flag=True,
    help="Check for auto-forwarding rules",
)
@click.option(
    "--send-as",
    is_flag=True,
    help="Check for send-as aliases",
)
@click.option(
    "--filters",
    is_flag=True,
    help="Check for risky filters",
)
@click.option(
    "--all",
    "check_all",
    is_flag=True,
    help="Check all security settings",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Save results to file (CSV or JSON)",
)
@click.pass_context
def scan_gmail_security(
    ctx: click.Context,
    delegates: bool,
    forwarding: bool,
    send_as: bool,
    filters: bool,
    check_all: bool,
    output: Optional[Path],
) -> None:
    """Scan Gmail for security issues."""
    from vaulytica.cli.commands.scan import scan_gmail_security_command

    scan_gmail_security_command(ctx, delegates, forwarding, send_as, filters, check_all, output)


@scan.command("audit-logs")
@click.option(
    "--admin-activity",
    is_flag=True,
    help="Scan admin activity logs",
)
@click.option(
    "--login-audit",
    is_flag=True,
    help="Scan login activity logs",
)
@click.option(
    "--drive-activity",
    is_flag=True,
    help="Scan Drive activity logs",
)
@click.option(
    "--token-activity",
    is_flag=True,
    help="Scan OAuth token activity logs",
)
@click.option(
    "--anomalies",
    is_flag=True,
    help="Detect anomalies in activity",
)
@click.option(
    "--days-back",
    type=int,
    default=7,
    help="Number of days to look back",
)
@click.option(
    "--max-results",
    type=int,
    default=1000,
    help="Maximum number of events",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Save results to file (CSV or JSON)",
)
@click.pass_context
def scan_audit_logs(
    ctx: click.Context,
    admin_activity: bool,
    login_audit: bool,
    drive_activity: bool,
    token_activity: bool,
    anomalies: bool,
    days_back: int,
    max_results: int,
    output: Optional[Path],
) -> None:
    """Scan audit logs for security events."""
    from vaulytica.cli.commands.scan import scan_audit_logs_command

    scan_audit_logs_command(
        ctx, admin_activity, login_audit, drive_activity, token_activity, anomalies, days_back, max_results, output
    )


@scan.command("calendar")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file",
)
@click.option(
    "--check-pii",
    is_flag=True,
    help="Scan calendar events for PII",
)
@click.option(
    "--days-ahead",
    type=int,
    default=30,
    help="Number of days ahead to scan events (default: 30)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (CSV or JSON)",
)
@click.pass_context
def scan_calendar(
    ctx: click.Context,
    config_path: Optional[Path],
    check_pii: bool,
    days_ahead: int,
    output: Optional[Path],
) -> None:
    """Scan Google Calendar for security issues."""
    from vaulytica.cli.commands.scan import scan_calendar_command

    scan_calendar_command(config_path, check_pii, days_ahead, output)


@scan.command("vault")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (CSV or JSON)",
)
@click.pass_context
def scan_vault(
    ctx: click.Context,
    config_path: Optional[Path],
    output: Optional[Path],
) -> None:
    """Scan Google Vault for legal holds and retention policies."""
    from vaulytica.cli.commands.scan import scan_vault_command

    scan_vault_command(config_path, output)


@scan.command("devices")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file",
)
@click.option(
    "--inactive-days",
    type=int,
    default=90,
    help="Number of days to consider a device inactive (default: 90)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (CSV or JSON)",
)
@click.pass_context
def scan_devices(
    ctx: click.Context,
    config_path: Optional[Path],
    inactive_days: int,
    output: Optional[Path],
) -> None:
    """Scan mobile devices for security and compliance issues."""
    from vaulytica.cli.commands.scan import scan_mobile_devices_command

    scan_mobile_devices_command(config_path, inactive_days, output)


@scan.command("chrome-devices")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file",
)
@click.option(
    "--org-unit",
    "-o",
    help="Organizational unit path to filter devices (e.g., /Engineering)",
)
@click.option(
    "--inactive-days",
    type=int,
    default=90,
    help="Number of days to consider a device inactive (default: 90)",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Output file path (CSV or JSON)",
)
@click.pass_context
def scan_chrome_devices(
    ctx: click.Context,
    config_path: Optional[Path],
    org_unit: Optional[str],
    inactive_days: int,
    output: Optional[Path],
) -> None:
    """Scan Chrome OS devices (Chromebooks, Chromeboxes, Chromebases) for security issues."""
    from vaulytica.cli.commands.scan import scan_chrome_devices_command

    scan_chrome_devices_command(config_path, org_unit, inactive_days, output)


@scan.command("licenses")
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True, path_type=Path),
    help="Path to configuration file",
)
@click.option(
    "--unused-days",
    type=int,
    default=90,
    help="Consider license unused if user inactive for N days (default: 90)",
)
@click.option(
    "--show-recommendations",
    is_flag=True,
    help="Show cost optimization recommendations",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (CSV or JSON)",
)
@click.pass_context
def scan_licenses(
    ctx: click.Context,
    config_path: Optional[Path],
    unused_days: int,
    show_recommendations: bool,
    output: Optional[Path],
) -> None:
    """Scan Google Workspace licenses for cost optimization opportunities."""
    from vaulytica.cli.commands.scan import scan_licenses_command

    scan_licenses_command(config_path, unused_days, show_recommendations, output)


@cli.group()
@click.pass_context
def report(ctx: click.Context) -> None:
    """Generate reports from scan results."""
    pass


@report.command("generate")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["csv", "json", "html"], case_sensitive=False),
    default="csv",
    help="Report format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    required=True,
    help="Output file path",
)
@click.option(
    "--scan-id",
    help="Generate report for specific scan ID",
)
@click.pass_context
def generate_report(
    ctx: click.Context,
    format: str,
    output: Path,
    scan_id: Optional[str],
) -> None:
    """Generate a report from scan results."""
    from vaulytica.cli.commands.report import generate_report_command

    generate_report_command(ctx, format, output, scan_id)


@report.command("dashboard")
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default="dashboard.html",
    help="Output file path (default: dashboard.html)",
)
@click.option(
    "--scan-id",
    help="Generate dashboard for specific scan ID",
)
@click.pass_context
def generate_dashboard(
    ctx: click.Context,
    output: Path,
    scan_id: Optional[str],
) -> None:
    """Generate an interactive HTML dashboard."""
    from vaulytica.cli.commands.report import generate_dashboard_command

    generate_dashboard_command(ctx, output, scan_id)


@cli.command()
@click.option(
    "--test-email",
    is_flag=True,
    help="Send a test email alert",
)
@click.pass_context
def test(ctx: click.Context, test_email: bool) -> None:
    """Test Vaulytica configuration and connectivity."""
    from vaulytica.cli.commands.test import test_command

    test_command(ctx, test_email)


@cli.command()
@click.pass_context
def config(ctx: click.Context) -> None:
    """Show current configuration."""
    from vaulytica.cli.commands.config import config_command

    config_command(ctx)


@cli.group()
@click.pass_context
def offboard(ctx: click.Context) -> None:
    """Employee offboarding commands."""
    from vaulytica.cli.commands.offboard import offboard as offboard_group

    return offboard_group


# Register offboard subcommands
from vaulytica.cli.commands.offboard import offboard as offboard_group
from vaulytica.cli.commands.policy import policy as policy_group

cli.add_command(offboard_group)
cli.add_command(policy_group)


@cli.command("compliance")
@click.option(
    "--framework",
    "-f",
    type=click.Choice(["gdpr", "hipaa", "soc2", "pci-dss", "ferpa", "fedramp"], case_sensitive=False),
    required=True,
    help="Compliance framework to report on",
)
@click.option(
    "--domain",
    "-d",
    help="Domain to scan (from config if not specified)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Output file path (JSON format)",
)
@click.pass_context
def compliance(
    ctx: click.Context,
    framework: str,
    domain: Optional[str],
    output: Optional[Path],
) -> None:
    """Generate compliance reports (GDPR, HIPAA, SOC 2, PCI-DSS, FERPA, FedRAMP)."""
    from vaulytica.cli.commands.compliance import compliance_report_command

    compliance_report_command(ctx, framework.lower(), domain, output)


# Register monitor, workflow, metrics, schedule, users, bulk, ou, backup, and resources commands
from vaulytica.cli.commands.monitor import monitor_group
from vaulytica.cli.commands.workflow import workflow_group
from vaulytica.cli.commands.metrics import metrics
from vaulytica.cli.commands.schedule import schedule
from vaulytica.cli.commands.users import users_group
from vaulytica.cli.commands.bulk import bulk_group
from vaulytica.cli.commands.ou import ou_group
from vaulytica.cli.commands.backup import backup_group
from vaulytica.cli.commands.resources import resources_group
from vaulytica.cli.commands.shadow_it import shadow_it_group
from vaulytica.cli.commands.chrome_enterprise import chrome_group
from vaulytica.cli.commands.security_posture import security_posture_group

cli.add_command(monitor_group)
cli.add_command(workflow_group)
cli.add_command(metrics)
cli.add_command(schedule)
cli.add_command(users_group)
cli.add_command(bulk_group)
cli.add_command(ou_group)
cli.add_command(backup_group)
cli.add_command(resources_group)
cli.add_command(shadow_it_group)
cli.add_command(chrome_group)
cli.add_command(security_posture_group)


def main() -> None:
    """Main entry point."""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("unhandled_exception")
        sys.exit(1)


if __name__ == "__main__":
    main()

