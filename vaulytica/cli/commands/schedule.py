"""CLI commands for scheduled scans."""

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from vaulytica.core.scheduler import (
    ScanScheduler,
    ScheduleType,
    ScanType,
    get_scheduler,
)

console = Console()


@click.group()
def schedule():
    """Manage scheduled scans."""
    pass


@schedule.command("add")
@click.option(
    "--name",
    "-n",
    required=True,
    help="Schedule name",
)
@click.option(
    "--scan-type",
    "-t",
    type=click.Choice(["files", "users", "gmail", "shared_drives", "oauth"]),
    required=True,
    help="Type of scan",
)
@click.option(
    "--schedule-type",
    type=click.Choice(["cron", "interval"]),
    default="cron",
    help="Schedule type (default: cron)",
)
@click.option(
    "--schedule",
    "-s",
    required=True,
    help="Schedule expression (cron: '0 2 * * *', interval: '6h')",
)
@click.option(
    "--config",
    "-c",
    help="Scan configuration (JSON string)",
)
@click.option(
    "--enabled/--disabled",
    default=True,
    help="Enable schedule immediately (default: enabled)",
)
def add_schedule(
    name: str,
    scan_type: str,
    schedule_type: str,
    schedule: str,
    config: Optional[str],
    enabled: bool,
) -> None:
    """Add a new scheduled scan.

    Examples:

        # Daily file scan at 2 AM
        vaulytica schedule add -n "Daily File Scan" -t files -s "0 2 * * *"

        # User scan every 6 hours
        vaulytica schedule add -n "Periodic User Scan" -t users --schedule-type interval -s "6h"

        # Gmail scan every 30 minutes
        vaulytica schedule add -n "Gmail Monitor" -t gmail --schedule-type interval -s "30m"
    """
    import json

    scheduler = get_scheduler()

    # Parse config if provided
    scan_config = {}
    if config:
        try:
            scan_config = json.loads(config)
        except json.JSONDecodeError as e:
            console.print(f"[red]✗[/red] Invalid JSON config: {e}")
            raise click.Abort()

    # Add schedule
    try:
        scheduled_scan = scheduler.add_schedule(
            name=name,
            scan_type=ScanType(scan_type),
            schedule_type=ScheduleType(schedule_type),
            schedule=schedule,
            config=scan_config,
            enabled=enabled,
        )

        console.print(f"[green]✓[/green] Schedule added: {scheduled_scan.id}")
        console.print(f"  Name: {name}")
        console.print(f"  Type: {scan_type}")
        console.print(f"  Schedule: {schedule}")
        console.print(f"  Enabled: {enabled}")

        if scheduled_scan.next_run:
            console.print(f"  Next run: {scheduled_scan.next_run}")

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to add schedule: {e}")
        raise click.Abort()


@schedule.command("list")
@click.option(
    "--enabled-only",
    is_flag=True,
    help="Only show enabled schedules",
)
def list_schedules(enabled_only: bool) -> None:
    """List all scheduled scans."""
    scheduler = get_scheduler()
    schedules = scheduler.list_schedules(enabled_only=enabled_only)

    if not schedules:
        console.print("[yellow]No schedules found[/yellow]")
        return

    # Create table
    table = Table(title="Scheduled Scans", show_header=True, header_style="bold cyan")
    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("Schedule")
    table.add_column("Enabled")
    table.add_column("Runs")
    table.add_column("Failures")
    table.add_column("Last Run")
    table.add_column("Next Run")

    for scan in schedules:
        enabled_str = "[green]✓[/green]" if scan.enabled else "[red]✗[/red]"
        last_run = scan.last_run[:19] if scan.last_run else "Never"
        next_run = scan.next_run[:19] if scan.next_run else "N/A"

        table.add_row(
            scan.id,
            scan.name,
            scan.scan_type.value,
            scan.schedule,
            enabled_str,
            str(scan.run_count),
            str(scan.failure_count),
            last_run,
            next_run,
        )

    console.print(table)


@schedule.command("show")
@click.argument("scan_id")
def show_schedule(scan_id: str) -> None:
    """Show details of a scheduled scan."""
    scheduler = get_scheduler()
    scan = scheduler.get_schedule(scan_id)

    if not scan:
        console.print(f"[red]✗[/red] Schedule not found: {scan_id}")
        raise click.Abort()

    # Create panel with details
    details = f"""
[bold]Name:[/bold] {scan.name}
[bold]ID:[/bold] {scan.id}
[bold]Type:[/bold] {scan.scan_type.value}
[bold]Schedule Type:[/bold] {scan.schedule_type.value}
[bold]Schedule:[/bold] {scan.schedule}
[bold]Enabled:[/bold] {'Yes' if scan.enabled else 'No'}

[bold]Statistics:[/bold]
  Run Count: {scan.run_count}
  Failure Count: {scan.failure_count}
  Last Run: {scan.last_run or 'Never'}
  Next Run: {scan.next_run or 'N/A'}

[bold]Timestamps:[/bold]
  Created: {scan.created_at}
  Updated: {scan.updated_at}

[bold]Configuration:[/bold]
{_format_config(scan.config)}
    """.strip()

    console.print(Panel(details, title="Schedule Details", border_style="cyan"))


@schedule.command("remove")
@click.argument("scan_id")
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip confirmation",
)
def remove_schedule(scan_id: str, yes: bool) -> None:
    """Remove a scheduled scan."""
    scheduler = get_scheduler()

    # Check if exists
    scan = scheduler.get_schedule(scan_id)
    if not scan:
        console.print(f"[red]✗[/red] Schedule not found: {scan_id}")
        raise click.Abort()

    # Confirm
    if not yes:
        console.print(f"Remove schedule: {scan.name} ({scan_id})?")
        if not click.confirm("Are you sure?"):
            console.print("Cancelled")
            return

    # Remove
    if scheduler.remove_schedule(scan_id):
        console.print(f"[green]✓[/green] Schedule removed: {scan_id}")
    else:
        console.print(f"[red]✗[/red] Failed to remove schedule")


@schedule.command("enable")
@click.argument("scan_id")
def enable_schedule(scan_id: str) -> None:
    """Enable a scheduled scan."""
    scheduler = get_scheduler()

    if scheduler.enable_schedule(scan_id):
        console.print(f"[green]✓[/green] Schedule enabled: {scan_id}")

        # Show next run time
        scan = scheduler.get_schedule(scan_id)
        if scan and scan.next_run:
            console.print(f"  Next run: {scan.next_run}")
    else:
        console.print(f"[red]✗[/red] Failed to enable schedule")


@schedule.command("disable")
@click.argument("scan_id")
def disable_schedule(scan_id: str) -> None:
    """Disable a scheduled scan."""
    scheduler = get_scheduler()

    if scheduler.disable_schedule(scan_id):
        console.print(f"[green]✓[/green] Schedule disabled: {scan_id}")
    else:
        console.print(f"[red]✗[/red] Failed to disable schedule")


@schedule.command("run")
@click.option(
    "--daemon",
    "-d",
    is_flag=True,
    help="Run as daemon (background process)",
)
def run_scheduler(daemon: bool) -> None:
    """Start the scheduler to run scheduled scans.

    Examples:

        # Run in foreground (blocking)
        vaulytica schedule run

        # Run as daemon (background)
        vaulytica schedule run --daemon
    """
    scheduler = get_scheduler()

    # Register scan callbacks
    _register_callbacks(scheduler)

    if daemon:
        console.print("[cyan]Starting scheduler in daemon mode...[/cyan]")
        scheduler.start()
        console.print("[green]✓[/green] Scheduler started")
        console.print(f"  Active jobs: {len(scheduler.scheduler.get_jobs())}")
        console.print("  Use 'vaulytica schedule stop' to stop")
    else:
        console.print("[cyan]Starting scheduler (press Ctrl+C to stop)...[/cyan]")
        console.print(f"  Active jobs: {len(scheduler.list_schedules(enabled_only=True))}")
        console.print()

        # Run forever (blocking)
        scheduler.run_forever()


@schedule.command("stop")
def stop_scheduler() -> None:
    """Stop the scheduler."""
    scheduler = get_scheduler()
    scheduler.stop()
    console.print("[green]✓[/green] Scheduler stopped")


def _register_callbacks(scheduler: ScanScheduler) -> None:
    """Register scan callbacks with scheduler.

    Args:
        scheduler: ScanScheduler instance
    """
    from vaulytica.core.auth.client import GoogleWorkspaceClient
    from vaulytica.core.scanners.file_scanner import FileScanner
    from vaulytica.core.scanners.user_scanner import UserScanner
    from vaulytica.core.scanners.gmail_scanner import GmailScanner
    from vaulytica.config.loader import load_config

    # Load config
    config = load_config()

    # Create client
    client = GoogleWorkspaceClient(
        service_account_file=config.google_workspace.service_account_file,
        subject_email=config.google_workspace.subject_email,
        scopes=config.google_workspace.scopes,
    )

    # Register file scan callback
    def file_scan_callback(scan_config):
        scanner = FileScanner(client, config.google_workspace.domain)
        files = scanner.scan_files(
            external_only=scan_config.get("external_only", False),
            include_shared_drives=scan_config.get("include_shared_drives", False),
        )
        console.print(f"[green]✓[/green] File scan complete: {len(files)} files scanned")

    scheduler.register_scan_callback(ScanType.FILES, file_scan_callback)

    # Register user scan callback
    def user_scan_callback(scan_config):
        scanner = UserScanner(client, config.google_workspace.domain)
        users = scanner.scan_users()
        console.print(f"[green]✓[/green] User scan complete: {len(users)} users scanned")

    scheduler.register_scan_callback(ScanType.USERS, user_scan_callback)

    # Register Gmail scan callback
    def gmail_scan_callback(scan_config):
        scanner = GmailScanner(client, config.google_workspace.domain)
        messages = scanner.scan_messages(
            user_email=scan_config.get("user_email"),
            max_results=scan_config.get("max_results", 100),
        )
        console.print(f"[green]✓[/green] Gmail scan complete: {len(messages)} messages scanned")

    scheduler.register_scan_callback(ScanType.GMAIL, gmail_scan_callback)


def _format_config(config: dict) -> str:
    """Format configuration dictionary for display.

    Args:
        config: Configuration dictionary

    Returns:
        Formatted string
    """
    if not config:
        return "  (none)"

    import json

    return "  " + json.dumps(config, indent=2).replace("\n", "\n  ")

