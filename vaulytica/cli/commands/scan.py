"""Scan command implementations."""

from pathlib import Path
from typing import Optional, List
from datetime import datetime, timezone
import csv
import json

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()


def _save_files_to_output(files: List, output: Path, format: str) -> None:
    """Save file scan results to output file.

    Args:
        files: List of FileInfo objects
        output: Output file path
        format: Output format (csv or json)
    """
    output.parent.mkdir(parents=True, exist_ok=True)

    if format == "csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([
                "File ID",
                "File Name",
                "Owner",
                "Risk Score",
                "Is Public",
                "Is Shared Externally",
                "External Domains",
                "External Emails",
                "Web View Link",
                "Modified Time",
            ])
            # Write data
            for file_info in files:
                writer.writerow([
                    file_info.id,
                    file_info.name,
                    file_info.owner_email,
                    file_info.risk_score,
                    "Yes" if file_info.is_public else "No",
                    "Yes" if file_info.is_shared_externally else "No",
                    ", ".join(file_info.external_domains) if file_info.external_domains else "",
                    ", ".join(file_info.external_emails) if file_info.external_emails else "",
                    file_info.web_view_link or "",
                    file_info.modified_time.isoformat() if file_info.modified_time else "",
                ])

    elif format == "json":
        data = []
        for file_info in files:
            data.append({
                "id": file_info.id,
                "name": file_info.name,
                "owner": file_info.owner_email,
                "risk_score": file_info.risk_score,
                "is_public": file_info.is_public,
                "is_shared_externally": file_info.is_shared_externally,
                "external_domains": file_info.external_domains or [],
                "external_emails": file_info.external_emails or [],
                "web_view_link": file_info.web_view_link,
                "modified_time": file_info.modified_time.isoformat() if file_info.modified_time else None,
            })

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


def _save_users_to_output(users: List, output: Path, format: str) -> None:
    """Save user scan results to output file.

    Args:
        users: List of UserInfo objects
        output: Output file path
        format: Output format (csv or json)
    """
    output.parent.mkdir(parents=True, exist_ok=True)

    if format == "csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([
                "User ID",
                "Email",
                "Full Name",
                "Is Admin",
                "Is Suspended",
                "Is Inactive",
                "Days Since Last Login",
                "Last Login Time",
                "Org Unit Path",
            ])
            # Write data
            for user in users:
                writer.writerow([
                    user.id,
                    user.email,
                    user.full_name,
                    "Yes" if user.is_admin else "No",
                    "Yes" if user.is_suspended else "No",
                    "Yes" if user.is_inactive else "No",
                    user.days_since_last_login or "N/A",
                    user.last_login_time.isoformat() if user.last_login_time else "Never",
                    user.org_unit_path,
                ])

    elif format == "json":
        data = []
        for user in users:
            data.append({
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "is_admin": user.is_admin,
                "is_suspended": user.is_suspended,
                "is_inactive": user.is_inactive,
                "days_since_last_login": user.days_since_last_login,
                "last_login_time": user.last_login_time.isoformat() if user.last_login_time else None,
                "org_unit_path": user.org_unit_path,
            })

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


def scan_files_command(
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
    from datetime import datetime
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.scanners.file_scanner import FileScanner
    from vaulytica.storage.state import StateManager
    from rich.table import Table

    console.print("[cyan]Starting file scan...[/cyan]")

    if incremental:
        console.print("[cyan]Incremental mode:[/cyan] Only scanning files modified since last scan")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    try:
        config = load_config(config_path)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise click.Abort()

    # Use domain from config if not specified
    if not domain:
        domain = config.get("google_workspace", {}).get("domain")
        if not domain:
            console.print("[red]Error: No domain specified in config or command line[/red]")
            raise click.Abort()

    console.print(f"[cyan]Domain:[/cyan] {domain}")
    console.print(f"[cyan]External only:[/cyan] {external_only}")
    console.print(f"[cyan]Public only:[/cyan] {public_only}")
    console.print(f"[cyan]Check PII:[/cyan] {check_pii}")

    # Create Google Workspace client
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Authenticating...", total=None)
            client = create_client_from_config(config)
            progress.update(task, description="[green]✓[/green] Authenticated")

            # Create state manager for incremental scanning
            state_manager = None
            scan_id = None
            if incremental:
                state_manager = StateManager()
                scan_id = state_manager.record_scan_start("file_scan", domain)

            # Create file scanner
            scanning_config = config.get("scanning", {})
            scanner = FileScanner(
                client,
                domain=domain,
                batch_size=scanning_config.get("batch_size", 100),
                rate_limit_delay=scanning_config.get("rate_limit_delay", 0.1),
                state_manager=state_manager,
                incremental=incremental,
            )

            # Scan files
            scan_task = progress.add_task("Scanning files...", total=None)
            files = list(scanner.scan_all_files(
                external_only=external_only,
                public_only=public_only,
                user_email=user,
            ))
            progress.update(scan_task, description=f"[green]✓[/green] Found {len(files)} files")

            # Record scan completion
            if scan_id and state_manager:
                state_manager.record_scan_end(
                    scan_id=scan_id,
                    status="completed",
                    files_scanned=len(files),
                )

        # Display results
        if files:
            console.print(f"\n[cyan]Found {len(files)} files with sharing issues:[/cyan]\n")

            # Show top 10 highest risk files
            files_sorted = sorted(files, key=lambda f: f.risk_score, reverse=True)
            table = Table(show_header=True, header_style="bold cyan")
            table.add_column("File Name", style="white", no_wrap=False, max_width=40)
            table.add_column("Owner", style="cyan", max_width=25)
            table.add_column("Risk", style="red", justify="center")
            table.add_column("Public", justify="center")
            table.add_column("External", justify="center")

            for file_info in files_sorted[:10]:
                risk_color = "red" if file_info.risk_score >= 75 else "yellow" if file_info.risk_score >= 50 else "green"
                table.add_row(
                    file_info.name,
                    file_info.owner_email,
                    f"[{risk_color}]{file_info.risk_score}[/{risk_color}]",
                    "✓" if file_info.is_public else "",
                    "✓" if file_info.is_shared_externally else "",
                )

            console.print(table)

            if len(files) > 10:
                console.print(f"\n[dim]Showing top 10 of {len(files)} files[/dim]")

            # Save to output file if specified
            if output:
                _save_files_to_output(files, output, format)
                console.print(f"\n[green]✓[/green] Results saved to {output}")

        else:
            console.print("\n[green]No files found with sharing issues[/green]")

    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        if ctx.obj.get("debug"):
            raise
        raise click.Abort()

    console.print("\n[green]✓[/green] Scan complete")


def scan_users_command(
    ctx: click.Context,
    domain: Optional[str],
    inactive_days: int,
    output: Optional[Path],
    format: str = "csv",
) -> None:
    """Scan for inactive users and service accounts."""
    from vaulytica.config.loader import load_config

    console.print("[cyan]Starting user scan...[/cyan]")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    try:
        config = load_config(config_path)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise click.Abort()

    # Use domain from config if not specified
    if not domain:
        domain = config.get("google_workspace", {}).get("domain")
        if not domain:
            console.print("[red]Error: No domain specified in config or command line[/red]")
            raise click.Abort()

    console.print(f"[cyan]Domain:[/cyan] {domain}")
    console.print(f"[cyan]Inactive threshold:[/cyan] {inactive_days} days\n")

    # Create client
    try:
        client = create_client_from_config(config)
    except Exception as e:
        console.print(f"[red]Error creating client: {e}[/red]")
        raise click.Abort()

    # Create user scanner
    from vaulytica.core.scanners.user_scanner import UserScanner

    scanner = UserScanner(client, domain, inactive_threshold_days=inactive_days)

    # Scan users
    with console.status("[bold green]Scanning users..."):
        result = scanner.scan_all_users()

    # Display summary
    console.print("\n[bold green]✓ User Scan Complete[/bold green]\n")

    summary_table = Table(title="User Scan Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="green")

    summary_table.add_row("Total Users", str(result.total_users))
    summary_table.add_row("Active Users", str(result.active_users))
    summary_table.add_row("Inactive Users", str(result.inactive_users))
    summary_table.add_row("Suspended Users", str(result.suspended_users))
    summary_table.add_row("Admin Users", str(result.admin_users))

    console.print(summary_table)

    # Display inactive users
    if result.inactive_users > 0:
        console.print("\n[bold yellow]⚠️  Inactive Users:[/bold yellow]\n")

        inactive_table = Table()
        inactive_table.add_column("Email", style="cyan")
        inactive_table.add_column("Name", style="white")
        inactive_table.add_column("Last Login", style="yellow")
        inactive_table.add_column("Days Inactive", style="red")

        inactive_users = [u for u in result.users if u.is_inactive]
        for user in inactive_users[:20]:  # Show first 20
            last_login = (
                user.last_login_time.strftime("%Y-%m-%d")
                if user.last_login_time
                else "Never"
            )

            inactive_table.add_row(
                user.email,
                user.full_name,
                last_login,
                str(user.days_since_last_login or "N/A"),
            )

        console.print(inactive_table)

        if len(inactive_users) > 20:
            console.print(f"\n[dim]... and {len(inactive_users) - 20} more inactive users[/dim]")

    # Save to file if requested
    if output:
        _save_users_to_output(result.users, output, format)
        console.print(f"\n[green]✓[/green] Results saved to {output}")


def scan_shared_drives_command(
    ctx: click.Context,
    domain: Optional[str],
    scan_files: bool,
    external_only: bool,
    output: Optional[Path],
) -> None:
    """Scan Shared Drives for security issues."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.scanners.shared_drive_scanner import SharedDriveScanner

    console.print("[cyan]Starting Shared Drive scan...[/cyan]")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    try:
        config = load_config(config_path)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise click.Abort()

    # Use domain from config if not specified
    if not domain:
        domain = config.get("google_workspace", {}).get("domain")
        if not domain:
            console.print("[red]Error: No domain specified in config or command line[/red]")
            raise click.Abort()

    console.print(f"[cyan]Domain:[/cyan] {domain}")
    console.print(f"[cyan]Scan files:[/cyan] {scan_files}")
    console.print(f"[cyan]External only:[/cyan] {external_only}\n")

    # Create client
    try:
        client = create_client_from_config(config)
    except Exception as e:
        console.print(f"[red]Error creating client: {e}[/red]")
        raise click.Abort()

    # Create scanner
    scanner = SharedDriveScanner(client, domain)

    # Scan Shared Drives
    with console.status("[bold green]Scanning Shared Drives..."):
        result = scanner.scan_all_shared_drives(
            scan_files=scan_files,
            external_only=external_only,
        )

    # Display summary
    console.print("\n[bold green]✓ Shared Drive Scan Complete[/bold green]\n")

    summary_table = Table(title="Shared Drive Scan Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="green")

    summary_table.add_row("Total Shared Drives", str(result.total_drives))
    if scan_files:
        summary_table.add_row("Files Scanned", str(result.total_files_scanned))
        summary_table.add_row("Files with Issues", str(result.files_with_issues))
        summary_table.add_row(
            "Drives with External Files",
            str(result.drives_with_external_files),
        )

    console.print(summary_table)

    # Display Shared Drives
    if result.drives:
        console.print("\n[bold]Shared Drives:[/bold]\n")

        drives_table = Table()
        drives_table.add_column("Name", style="cyan")
        drives_table.add_column("ID", style="dim")
        drives_table.add_column("Created", style="white")
        drives_table.add_column("Hidden", style="yellow")

        for drive in result.drives[:20]:  # Show first 20
            drives_table.add_row(
                drive.name,
                drive.id[:20] + "...",
                drive.created_time.strftime("%Y-%m-%d"),
                "Yes" if drive.hidden else "No",
            )

        console.print(drives_table)

        if len(result.drives) > 20:
            console.print(f"\n[dim]... and {len(result.drives) - 20} more drives[/dim]")

    # Display files with issues
    if result.files:
        console.print("\n[bold yellow]⚠️  Files with Issues:[/bold yellow]\n")

        files_table = Table()
        files_table.add_column("File", style="cyan")
        files_table.add_column("Owner", style="white")
        files_table.add_column("Risk", style="red")
        files_table.add_column("Public", style="yellow")
        files_table.add_column("External", style="yellow")

        for file_info in result.files[:20]:  # Show first 20
            files_table.add_row(
                file_info.name[:40],
                file_info.owner_email,
                str(file_info.risk_score),
                "Yes" if file_info.is_public else "No",
                "Yes" if file_info.is_shared_externally else "No",
            )

        console.print(files_table)

        if len(result.files) > 20:
            console.print(f"\n[dim]... and {len(result.files) - 20} more files[/dim]")

    # Save to file if requested
    if output:
        console.print(f"\n[cyan]Saving results to {output}...[/cyan]")

        with open(output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Drive Name",
                "Drive ID",
                "File Name",
                "File ID",
                "Owner",
                "Risk Score",
                "Is Public",
                "Is External",
                "External Domains",
            ])

            for file_info in result.files:
                # Find the drive this file belongs to (simplified)
                writer.writerow([
                    "",  # Drive name not tracked per file
                    "",  # Drive ID not tracked per file
                    file_info.name,
                    file_info.id,
                    file_info.owner_email,
                    file_info.risk_score,
                    file_info.is_public,
                    file_info.is_shared_externally,
                    ", ".join(file_info.external_domains),
                ])

        console.print(f"[green]✓ Results saved to {output}[/green]")


def scan_oauth_apps_command(
    ctx: click.Context,
    domain: Optional[str],
    user: Optional[str],
    output: Optional[Path],
) -> None:
    """Scan OAuth apps and third-party integrations."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.scanners.oauth_scanner import OAuthScanner

    console.print("[cyan]Starting OAuth app scan...[/cyan]")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    try:
        config = load_config(config_path)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise click.Abort()

    # Use domain from config if not specified
    if not domain:
        domain = config.get("google_workspace", {}).get("domain")
        if not domain:
            console.print("[red]Error: No domain specified in config or command line[/red]")
            raise click.Abort()

    console.print(f"[cyan]Domain:[/cyan] {domain}")
    if user:
        console.print(f"[cyan]User:[/cyan] {user}\n")
    else:
        console.print("[cyan]Scanning all users...[/cyan]\n")

    # Create client
    try:
        client = create_client_from_config(config)
    except Exception as e:
        console.print(f"[red]Error creating client: {e}[/red]")
        raise click.Abort()

    # Create scanner
    scanner = OAuthScanner(client, domain)

    # Scan OAuth tokens
    with console.status("[bold green]Scanning OAuth tokens..."):
        result = scanner.scan_oauth_tokens(user_email=user)

    # Display summary
    console.print("\n[bold green]✓ OAuth Scan Complete[/bold green]\n")

    summary_table = Table(title="OAuth Scan Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="green")

    summary_table.add_row("Total Apps", str(result.total_apps))
    summary_table.add_row("High Risk Apps", str(result.high_risk_apps))
    summary_table.add_row("Total Tokens", str(result.total_tokens))

    console.print(summary_table)

    # Display high-risk apps
    high_risk_apps = [a for a in result.apps if a.risk_score >= 75]
    if high_risk_apps:
        console.print("\n[bold red]🔴 High Risk Apps:[/bold red]\n")

        apps_table = Table()
        apps_table.add_column("App", style="cyan")
        apps_table.add_column("Users", style="white")
        apps_table.add_column("Scopes", style="yellow")
        apps_table.add_column("Risk", style="red")

        for app in high_risk_apps[:20]:  # Show first 20
            apps_table.add_row(
                app.display_text[:40],
                str(app.user_count),
                str(len(app.scopes)),
                str(app.risk_score),
            )

        console.print(apps_table)

        if len(high_risk_apps) > 20:
            console.print(f"\n[dim]... and {len(high_risk_apps) - 20} more high-risk apps[/dim]")

    # Display all apps
    if result.apps:
        console.print("\n[bold]All OAuth Apps:[/bold]\n")

        all_apps_table = Table()
        all_apps_table.add_column("App", style="cyan")
        all_apps_table.add_column("Users", style="white")
        all_apps_table.add_column("Scopes", style="yellow")
        all_apps_table.add_column("Risk", style="green")
        all_apps_table.add_column("Google", style="dim")

        # Sort by risk score
        sorted_apps = sorted(result.apps, key=lambda a: a.risk_score, reverse=True)

        for app in sorted_apps[:20]:  # Show first 20
            risk_color = "red" if app.risk_score >= 75 else "yellow" if app.risk_score >= 50 else "green"

            all_apps_table.add_row(
                app.display_text[:40],
                str(app.user_count),
                str(len(app.scopes)),
                f"[{risk_color}]{app.risk_score}[/{risk_color}]",
                "Yes" if app.is_google_app else "No",
            )

        console.print(all_apps_table)

        if len(sorted_apps) > 20:
            console.print(f"\n[dim]... and {len(sorted_apps) - 20} more apps[/dim]")

    # Save to file if requested
    if output:
        console.print(f"\n[cyan]Saving results to {output}...[/cyan]")

        with open(output, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "App Name",
                "Client ID",
                "User Count",
                "Scope Count",
                "Risk Score",
                "Is Google App",
                "Scopes",
            ])

            for app in result.apps:
                writer.writerow([
                    app.display_text,
                    app.client_id,
                    app.user_count,
                    len(app.scopes),
                    app.risk_score,
                    app.is_google_app,
                    "; ".join(app.scopes),
                ])

        console.print(f"[green]✓ Results saved to {output}[/green]")


@click.command("groups")
@click.option(
    "--external-members",
    is_flag=True,
    help="Show only groups with external members",
)
@click.option(
    "--public-groups",
    is_flag=True,
    help="Show only public groups (anyone can join)",
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
    help="Minimum risk score to display (0-100)",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Save results to file (CSV or JSON based on extension)",
)
@click.pass_context
def scan_groups_command(
    ctx: click.Context,
    external_members: bool,
    public_groups: bool,
    orphaned: bool,
    min_risk_score: int,
    output: Optional[Path],
) -> None:
    """Scan Google Groups for security issues.

    Detects:
    - Groups with external members
    - Public groups (anyone can join)
    - Orphaned groups (no owners)
    - Nested group memberships
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.scanners.group_scanner import GroupScanner

    console.print("[cyan]Starting Groups security scan...[/cyan]")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)
    domain = config.google_workspace.domain

    # Create scanner
    scanner = GroupScanner(client, domain)

    # Scan groups
    with console.status("[bold green]Scanning groups..."):
        result = scanner.scan_all_groups(include_members=True)

    # Filter results
    filtered_groups = result.groups

    if external_members:
        filtered_groups = [g for g in filtered_groups if g.external_members]

    if public_groups:
        filtered_groups = [g for g in filtered_groups if g.is_public]

    if orphaned:
        filtered_groups = [g for g in filtered_groups if g.is_orphaned]

    if min_risk_score > 0:
        filtered_groups = [g for g in filtered_groups if g.risk_score >= min_risk_score]

    # Display results
    console.print(f"\n[bold]Groups Scan Results[/bold]")
    console.print(f"Total groups: {result.total_groups}")
    console.print(f"Groups with external members: {result.groups_with_external_members}")
    console.print(f"Public groups: {result.public_groups}")
    console.print(f"Orphaned groups: {result.orphaned_groups}")
    console.print(f"Total issues: {len(result.issues)}")

    if filtered_groups:
        console.print(f"\n[bold]Filtered Results ({len(filtered_groups)} groups):[/bold]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Group Email", style="cyan")
        table.add_column("Name")
        table.add_column("Members", justify="right")
        table.add_column("External", justify="right")
        table.add_column("Risk", justify="right")
        table.add_column("Issues")

        for group in filtered_groups:
            issues = []
            if group.external_members:
                issues.append(f"Ext:{len(group.external_members)}")
            if group.is_public:
                issues.append("Public")
            if group.is_orphaned:
                issues.append("Orphaned")

            risk_color = "red" if group.risk_score >= 75 else "yellow" if group.risk_score >= 50 else "green"

            table.add_row(
                group.email,
                group.name[:40] if len(group.name) > 40 else group.name,
                str(group.direct_members_count),
                str(len(group.external_members)),
                f"[{risk_color}]{group.risk_score}[/{risk_color}]",
                ", ".join(issues),
            )

        console.print(table)

    # Save to file if requested
    if output:
        _save_groups_to_output(filtered_groups, result, output)

    console.print("\n[green]✓ Groups scan complete[/green]")


def _save_groups_to_output(groups: List, result, output: Path) -> None:
    """Save group scan results to output file."""
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.suffix.lower() == ".csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([
                "Group Email",
                "Group Name",
                "Description",
                "Members Count",
                "External Members",
                "External Member Emails",
                "Is Public",
                "Is Orphaned",
                "Nested Groups",
                "Risk Score",
            ])

            # Write data
            for group in groups:
                writer.writerow([
                    group.email,
                    group.name,
                    group.description,
                    group.direct_members_count,
                    len(group.external_members),
                    "; ".join([m.email for m in group.external_members]),
                    group.is_public,
                    group.is_orphaned,
                    "; ".join(group.nested_groups),
                    group.risk_score,
                ])

        console.print(f"[green]✓ Results saved to {output}[/green]")

    elif output.suffix.lower() == ".json":
        data = {
            "summary": {
                "total_groups": result.total_groups,
                "groups_with_external_members": result.groups_with_external_members,
                "public_groups": result.public_groups,
                "orphaned_groups": result.orphaned_groups,
                "total_issues": len(result.issues),
            },
            "groups": [
                {
                    "email": g.email,
                    "name": g.name,
                    "description": g.description,
                    "members_count": g.direct_members_count,
                    "external_members": [m.email for m in g.external_members],
                    "is_public": g.is_public,
                    "is_orphaned": g.is_orphaned,
                    "nested_groups": g.nested_groups,
                    "risk_score": g.risk_score,
                }
                for g in groups
            ],
            "issues": result.issues,
        }

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]✓ Results saved to {output}[/green]")


def scan_gmail_command(
    ctx: click.Context,
    domain: Optional[str],
    user: Optional[str],
    days_back: int,
    max_messages: int,
    check_pii: bool,
    external_only: bool,
    output: Optional[Path],
) -> None:
    """Scan Gmail messages and attachments for PII.

    Args:
        ctx: Click context
        domain: Domain to scan
        user: Specific user to scan
        days_back: Number of days to look back
        max_messages: Maximum messages to scan per user
        check_pii: Whether to scan attachments for PII
        external_only: Only scan emails sent to external recipients
        output: Optional output file path
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.scanners.gmail_scanner import GmailScanner
    from vaulytica.core.detectors.pii_detector import PIIDetector

    console.print("[bold blue]🔍 Scanning Gmail messages and attachments...[/bold blue]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Use provided domain or get from config
    if not domain:
        domain = config.google_workspace.domain

    # Create client
    client = create_client_from_config(config)

    # Create PII detector if needed
    pii_detector = PIIDetector() if check_pii else None

    # Create scanner
    scanner = GmailScanner(client, domain, pii_detector)

    # Scan Gmail
    with console.status("[bold green]Scanning Gmail..."):
        if user:
            # Scan specific user
            result = scanner.scan_user_attachments(
                user_email=user,
                days_back=days_back,
                max_messages=max_messages,
                external_only=external_only,
            )
        else:
            # Scan all users (limited to max_messages per user)
            console.print("[yellow]⚠ Scanning all users - this may take a while[/yellow]")
            result = scanner.scan_user_attachments(
                user_email=user or f"*@{domain}",
                days_back=days_back,
                max_messages=max_messages,
                external_only=external_only,
            )

    # Display results
    console.print(f"\n[bold]📊 Gmail Scan Results:[/bold]")
    console.print(f"  Total messages scanned: {result.total_messages}")
    console.print(f"  Total attachments found: {result.total_attachments}")
    console.print(f"  Attachments scanned: {result.attachments_scanned}")

    if check_pii:
        console.print(f"  Attachments with PII: {result.attachments_with_pii}")

        if result.attachments_with_pii > 0:
            console.print(f"\n[yellow]⚠ Found {result.attachments_with_pii} attachments with PII![/yellow]")

    # Display attachment results
    if result.results:
        table = Table(title="Gmail Attachment Scan Results")
        table.add_column("User", style="cyan")
        table.add_column("Subject", style="white")
        table.add_column("Attachment", style="yellow")
        table.add_column("External", style="magenta")
        table.add_column("PII Found", style="red")
        table.add_column("Risk Score", style="red")

        for attachment_result in result.results[:50]:  # Limit to 50 for display
            table.add_row(
                attachment_result.user_email,
                attachment_result.subject[:50] if attachment_result.subject else "N/A",
                attachment_result.filename,
                "Yes" if attachment_result.is_sent_externally else "No",
                "Yes" if attachment_result.pii_result and attachment_result.pii_result.has_pii else "No",
                str(attachment_result.risk_score),
            )

        console.print(table)

        if len(result.results) > 50:
            console.print(f"\n[dim]... and {len(result.results) - 50} more results[/dim]")

    # Save to output file if requested
    if output:
        _save_gmail_results_to_output(result, output)


def _save_gmail_results_to_output(result, output: Path) -> None:
    """Save Gmail scan results to output file."""
    if output.suffix.lower() == ".csv":
        import csv

        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "User Email",
                "Subject",
                "Filename",
                "MIME Type",
                "Size",
                "External",
                "PII Found",
                "Risk Score",
                "PII Types",
            ])

            for r in result.results:
                pii_types = ""
                if r.pii_result and r.pii_result.has_pii:
                    pii_types = ", ".join([f.pii_type for f in r.pii_result.findings])

                writer.writerow([
                    r.user_email,
                    r.subject,
                    r.filename,
                    r.mime_type,
                    r.size,
                    "Yes" if r.is_sent_externally else "No",
                    "Yes" if r.pii_result and r.pii_result.has_pii else "No",
                    r.risk_score,
                    pii_types,
                ])

        console.print(f"[green]✓ Results saved to {output}[/green]")

    elif output.suffix.lower() == ".json":
        import json

        data = {
            "scan_type": "gmail",
            "total_messages": result.total_messages,
            "total_attachments": result.total_attachments,
            "attachments_scanned": result.attachments_scanned,
            "attachments_with_pii": result.attachments_with_pii,
            "results": [
                {
                    "user_email": r.user_email,
                    "subject": r.subject,
                    "filename": r.filename,
                    "mime_type": r.mime_type,
                    "size": r.size,
                    "is_sent_externally": r.is_sent_externally,
                    "has_pii": r.pii_result.has_pii if r.pii_result else False,
                    "risk_score": r.risk_score,
                    "pii_findings": [
                        {
                            "pii_type": f.pii_type,
                            "value": f.value,
                            "confidence": f.confidence,
                        }
                        for f in r.pii_result.findings
                    ] if r.pii_result else [],
                }
                for r in result.results
            ],
        }

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]✓ Results saved to {output}[/green]")


@click.command("gmail-security")
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
    type=click.Path(path_type=Path),
    help="Save results to file (CSV or JSON)",
)
@click.pass_context
def scan_gmail_security_command(
    ctx: click.Context,
    delegates: bool,
    forwarding: bool,
    send_as: bool,
    filters: bool,
    check_all: bool,
    output: Optional[Path],
) -> None:
    """Scan Gmail for security issues (delegates, forwarding, etc.).

    Detects:
    - Gmail delegates (especially external)
    - Auto-forwarding rules
    - Send-as aliases
    - Risky filters (auto-delete, auto-forward)
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.scanners.gmail_security_scanner import GmailSecurityScanner

    console.print("[cyan]Starting Gmail security scan...[/cyan]")

    # If --all is specified, check everything
    if check_all:
        delegates = forwarding = send_as = filters = True

    # If nothing specified, check everything by default
    if not any([delegates, forwarding, send_as, filters]):
        delegates = forwarding = send_as = filters = True

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)
    domain = config.google_workspace.domain

    # Create scanner
    scanner = GmailSecurityScanner(client, domain)

    # Scan Gmail security
    with console.status("[bold green]Scanning Gmail security settings..."):
        result = scanner.scan_all_users(
            check_delegates=delegates,
            check_forwarding=forwarding,
            check_send_as=send_as,
            check_filters=filters,
        )

    # Display results
    console.print(f"\n[bold]Gmail Security Scan Results[/bold]")
    console.print(f"Total users scanned: {result.total_users_scanned}")
    console.print(f"Users with delegates: {result.users_with_delegates}")
    console.print(f"Users with forwarding: {result.users_with_forwarding}")
    console.print(f"Users with send-as aliases: {result.users_with_send_as}")
    console.print(f"Users with risky filters: {result.users_with_risky_filters}")
    console.print(f"Total issues: {len(result.issues)}")

    # Display delegates
    if result.delegates:
        console.print(f"\n[bold]Delegates ({len(result.delegates)}):[/bold]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("User", style="cyan")
        table.add_column("Delegate")
        table.add_column("External", justify="center")
        table.add_column("Status")

        for delegate in result.delegates:
            is_external = not delegate.delegate_email.endswith(f"@{domain}")
            external_marker = "[red]✓[/red]" if is_external else ""

            table.add_row(
                delegate.user_email,
                delegate.delegate_email,
                external_marker,
                delegate.verification_status,
            )

        console.print(table)

    # Display forwarding rules
    if result.forwarding_rules:
        console.print(f"\n[bold]Forwarding Rules ({len(result.forwarding_rules)}):[/bold]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("User", style="cyan")
        table.add_column("Forward To")
        table.add_column("External", justify="center")

        for rule in result.forwarding_rules:
            is_external = not rule.forward_to.endswith(f"@{domain}")
            external_marker = "[red]✓[/red]" if is_external else ""

            table.add_row(
                rule.user_email,
                rule.forward_to,
                external_marker,
            )

        console.print(table)

    # Display send-as aliases
    if result.send_as_aliases:
        console.print(f"\n[bold]Send-As Aliases ({len(result.send_as_aliases)}):[/bold]\n")

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("User", style="cyan")
        table.add_column("Send As")
        table.add_column("Display Name")

        for alias in result.send_as_aliases[:20]:  # Limit to first 20
            table.add_row(
                alias.user_email,
                alias.send_as_email,
                alias.display_name,
            )

        console.print(table)

        if len(result.send_as_aliases) > 20:
            console.print(f"[dim]... and {len(result.send_as_aliases) - 20} more[/dim]")

    # Save to file if requested
    if output:
        _save_gmail_security_to_output(result, output)

    console.print("\n[green]✓ Gmail security scan complete[/green]")


def _save_gmail_security_to_output(result, output: Path) -> None:
    """Save Gmail security scan results to output file."""
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.suffix.lower() == ".csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write delegates
            writer.writerow(["Type", "User", "Target", "Details"])

            for delegate in result.delegates:
                writer.writerow([
                    "Delegate",
                    delegate.user_email,
                    delegate.delegate_email,
                    delegate.verification_status,
                ])

            for rule in result.forwarding_rules:
                writer.writerow([
                    "Forwarding",
                    rule.user_email,
                    rule.forward_to,
                    "Enabled" if rule.enabled else "Disabled",
                ])

            for alias in result.send_as_aliases:
                writer.writerow([
                    "Send-As",
                    alias.user_email,
                    alias.send_as_email,
                    alias.display_name,
                ])

        console.print(f"[green]✓ Results saved to {output}[/green]")

    elif output.suffix.lower() == ".json":
        data = {
            "summary": result.statistics,
            "delegates": [
                {
                    "user": d.user_email,
                    "delegate": d.delegate_email,
                    "status": d.verification_status,
                }
                for d in result.delegates
            ],
            "forwarding_rules": [
                {
                    "user": r.user_email,
                    "forward_to": r.forward_to,
                    "enabled": r.enabled,
                }
                for r in result.forwarding_rules
            ],
            "send_as_aliases": [
                {
                    "user": a.user_email,
                    "send_as": a.send_as_email,
                    "display_name": a.display_name,
                }
                for a in result.send_as_aliases
            ],
            "issues": result.issues,
        }

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]✓ Results saved to {output}[/green]")


@click.command("audit-logs")
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
    help="Number of days to look back (default: 7)",
)
@click.option(
    "--max-results",
    type=int,
    default=1000,
    help="Maximum number of events to retrieve (default: 1000)",
)
@click.option(
    "--output",
    type=click.Path(path_type=Path),
    help="Save results to file (CSV or JSON)",
)
@click.pass_context
def scan_audit_logs_command(
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
    """Scan audit logs for security events and anomalies.

    Detects:
    - Admin activity (user changes, settings changes)
    - Login activity (failed logins, suspicious logins)
    - Drive activity (downloads, sharing changes)
    - OAuth token activity
    - Anomalies (unusual locations, times, mass downloads)
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.scanners.audit_log_scanner import AuditLogScanner
    from vaulytica.core.detectors.anomaly_detector import AnomalyDetector

    console.print("[cyan]Starting audit log scan...[/cyan]")

    # If nothing specified, scan everything
    if not any([admin_activity, login_audit, drive_activity, token_activity, anomalies]):
        admin_activity = login_audit = drive_activity = anomalies = True

    # Load configuration
    config_path = ctx.obj.get("config_path")
    config = load_config(config_path)

    # Create client
    client = create_client_from_config(config)
    domain = config.google_workspace.domain

    # Create scanner
    scanner = AuditLogScanner(client, domain)

    # Collect all events
    all_events = []

    # Scan admin activity
    if admin_activity:
        with console.status("[bold green]Scanning admin activity..."):
            result = scanner.scan_admin_activity(days_back, max_results)
            all_events.extend(result.events)

        console.print(f"Admin events: {result.admin_events}")
        console.print(f"Suspicious admin events: {len(result.suspicious_events)}")

        if result.suspicious_events:
            console.print("\n[bold yellow]Suspicious Admin Events:[/bold yellow]")
            for event in result.suspicious_events[:10]:
                console.print(
                    f"  • {event.timestamp.strftime('%Y-%m-%d %H:%M')} - "
                    f"{event.actor_email} - {event.event_name}"
                )

    # Scan login activity
    if login_audit:
        with console.status("[bold green]Scanning login activity..."):
            result = scanner.scan_login_activity(days_back, max_results)
            all_events.extend(result.events)

        console.print(f"\nLogin events: {result.login_events}")
        console.print(f"Suspicious login events: {len(result.suspicious_events)}")

        if result.suspicious_events:
            console.print("\n[bold yellow]Suspicious Login Events:[/bold yellow]")
            for event in result.suspicious_events[:10]:
                console.print(
                    f"  • {event.timestamp.strftime('%Y-%m-%d %H:%M')} - "
                    f"{event.actor_email} - {event.event_name} from {event.ip_address}"
                )

    # Scan drive activity
    if drive_activity:
        with console.status("[bold green]Scanning Drive activity..."):
            result = scanner.scan_drive_activity(days_back, max_results)
            all_events.extend(result.events)

        console.print(f"\nDrive events: {result.drive_events}")
        console.print(f"Suspicious drive events: {len(result.suspicious_events)}")

    # Scan token activity
    if token_activity:
        with console.status("[bold green]Scanning OAuth token activity..."):
            result = scanner.scan_token_activity(days_back, max_results)
            all_events.extend(result.events)

        console.print(f"\nToken events: {result.token_events}")

    # Detect anomalies
    if anomalies and all_events:
        console.print("\n[bold cyan]Detecting anomalies...[/bold cyan]")

        detector = AnomalyDetector(domain)
        anomaly_result = detector.detect_anomalies(all_events)

        console.print(f"\nTotal anomalies detected: {anomaly_result.total_anomalies}")
        console.print(f"  Critical: {anomaly_result.critical_anomalies}")
        console.print(f"  High: {anomaly_result.high_anomalies}")
        console.print(f"  Medium: {anomaly_result.medium_anomalies}")
        console.print(f"  Low: {anomaly_result.low_anomalies}")

        if anomaly_result.anomalies:
            console.print("\n[bold red]Detected Anomalies:[/bold red]")

            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Type")
            table.add_column("Severity")
            table.add_column("User", style="cyan")
            table.add_column("Description")

            for anomaly in anomaly_result.anomalies[:20]:
                severity_color = {
                    "critical": "red",
                    "high": "yellow",
                    "medium": "blue",
                    "low": "green",
                }.get(anomaly.severity, "white")

                table.add_row(
                    anomaly.anomaly_type,
                    f"[{severity_color}]{anomaly.severity}[/{severity_color}]",
                    anomaly.user_email,
                    anomaly.description[:60],
                )

            console.print(table)

            if len(anomaly_result.anomalies) > 20:
                console.print(
                    f"[dim]... and {len(anomaly_result.anomalies) - 20} more anomalies[/dim]"
                )

    # Save to file if requested
    if output:
        _save_audit_logs_to_output(all_events, output)

    console.print("\n[green]✓ Audit log scan complete[/green]")


def _save_audit_logs_to_output(events: List, output: Path) -> None:
    """Save audit log results to output file."""
    output.parent.mkdir(parents=True, exist_ok=True)

    if output.suffix.lower() == ".csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([
                "Timestamp",
                "Event Type",
                "Event Name",
                "Actor",
                "IP Address",
                "Severity",
            ])

            # Write data
            for event in events:
                writer.writerow([
                    event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    event.event_type,
                    event.event_name,
                    event.actor_email,
                    event.ip_address,
                    event.severity,
                ])

        console.print(f"[green]✓ Results saved to {output}[/green]")

    elif output.suffix.lower() == ".json":
        data = {
            "total_events": len(events),
            "events": [
                {
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type,
                    "event_name": event.event_name,
                    "actor": event.actor_email,
                    "ip_address": event.ip_address,
                    "severity": event.severity,
                    "parameters": event.parameters,
                }
                for event in events
            ],
        }

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]✓ Results saved to {output}[/green]")


def scan_calendar_command(
    config_path: Optional[Path],
    check_pii: bool,
    days_ahead: int,
    output: Optional[Path],
) -> None:
    """Scan Google Calendar for security issues.

    Args:
        config_path: Path to configuration file
        check_pii: Whether to scan events for PII
        days_ahead: Number of days ahead to scan events
        output: Optional output file path
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import GoogleWorkspaceClient
    from vaulytica.core.scanners.calendar_scanner import CalendarScanner
    from vaulytica.core.detectors.pii_detector import PIIDetector

    console.print("[bold blue]🔍 Scanning Google Calendar...[/bold blue]\n")

    # Load configuration
    config = load_config(config_path)

    # Create client
    client = GoogleWorkspaceClient(
        credentials_path=config.credentials_path,
        impersonate_user=config.impersonate_user,
    )

    # Create PII detector if needed
    pii_detector = None
    if check_pii:
        pii_detector = PIIDetector()

    # Create scanner
    scanner = CalendarScanner(
        client=client,
        domain=config.domain,
        pii_detector=pii_detector,
    )

    # Run scan with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning calendars...", total=None)
        result = scanner.scan_all_calendars(
            check_pii=check_pii,
            days_ahead=days_ahead,
        )
        progress.update(task, completed=True)

    # Display summary
    console.print("\n[bold green]✓ Calendar Scan Complete[/bold green]\n")

    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="magenta")

    summary_table.add_row("Total Calendars", str(result.total_calendars))
    summary_table.add_row("Public Calendars", str(result.public_calendars))
    summary_table.add_row(
        "Calendars with External Shares",
        str(result.calendars_with_external_shares),
    )
    if check_pii:
        summary_table.add_row("Events Scanned", str(result.total_events_scanned))
        summary_table.add_row("Events with PII", str(result.events_with_pii))
    summary_table.add_row("Total Issues", str(len(result.issues)))

    console.print(summary_table)

    # Display issues
    if result.issues:
        console.print("\n[bold yellow]⚠ Issues Found:[/bold yellow]\n")

        issues_table = Table(title="Calendar Security Issues")
        issues_table.add_column("Type", style="cyan")
        issues_table.add_column("Severity", style="yellow")
        issues_table.add_column("Calendar/Event", style="white")
        issues_table.add_column("Description", style="white")

        for issue in result.issues[:50]:  # Limit to 50 for display
            issues_table.add_row(
                issue["type"],
                issue["severity"],
                issue.get("calendar", issue.get("event", "")),
                issue["description"],
            )

        console.print(issues_table)

        if len(result.issues) > 50:
            console.print(f"\n[dim]... and {len(result.issues) - 50} more issues[/dim]")

    # Save to output file if requested
    if output:
        _save_calendar_results_to_output(result, output)


def _save_calendar_results_to_output(result, output: Path) -> None:
    """Save calendar scan results to output file."""
    output.parent.mkdir(parents=True, exist_ok=True)

    # Determine format from extension
    format = "json" if output.suffix == ".json" else "csv"

    if format == "csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([
                "Calendar ID",
                "Summary",
                "Owner",
                "Is Public",
                "External Shares",
                "Risk Score",
            ])

            # Write calendar data
            for calendar in result.calendars:
                writer.writerow([
                    calendar.calendar_id,
                    calendar.summary,
                    calendar.owner_email,
                    "Yes" if calendar.is_public else "No",
                    ", ".join(calendar.external_shares) if calendar.external_shares else "",
                    calendar.risk_score,
                ])

        console.print(f"[green]✓ Results saved to {output}[/green]")

    else:  # JSON
        data = {
            "scan_type": "calendar",
            "summary": result.statistics,
            "calendars": [
                {
                    "calendar_id": cal.calendar_id,
                    "summary": cal.summary,
                    "owner": cal.owner_email,
                    "is_public": cal.is_public,
                    "external_shares": cal.external_shares,
                    "risk_score": cal.risk_score,
                }
                for cal in result.calendars
            ],
            "issues": result.issues,
        }

        if result.events_with_pii_list:
            data["events_with_pii"] = [
                {
                    "event_id": event.event_id,
                    "calendar_id": event.calendar_id,
                    "summary": event.summary,
                    "pii_types": event.pii_types,
                }
                for event in result.events_with_pii_list
            ]

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]✓ Results saved to {output}[/green]")


def scan_vault_command(
    config_path: Optional[Path],
    output: Optional[Path],
) -> None:
    """Scan Google Vault for legal holds and retention policies.

    Args:
        config_path: Path to configuration file
        output: Optional output file path
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import GoogleWorkspaceClient
    from vaulytica.core.scanners.vault_scanner import VaultScanner

    console.print("[bold blue]🔍 Scanning Google Vault...[/bold blue]\n")

    # Load configuration
    config = load_config(config_path)

    # Create client
    client = GoogleWorkspaceClient(
        credentials_path=config.credentials_path,
        impersonate_user=config.impersonate_user,
    )

    # Create scanner
    scanner = VaultScanner(
        client=client,
        domain=config.domain,
    )

    # Run scan with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning Vault...", total=None)
        result = scanner.scan_all()
        progress.update(task, completed=True)

    # Display summary
    console.print("\n[bold green]✓ Vault Scan Complete[/bold green]\n")

    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="magenta")

    summary_table.add_row("Total Matters", str(result.total_matters))
    summary_table.add_row("Open Matters", str(result.open_matters))
    summary_table.add_row("Closed Matters", str(result.closed_matters))
    summary_table.add_row("Total Holds", str(result.total_holds))
    summary_table.add_row("Retention Policies", str(result.total_retention_policies))
    summary_table.add_row("Total Issues", str(len(result.issues)))

    console.print(summary_table)

    # Display issues
    if result.issues:
        console.print("\n[bold yellow]⚠ Issues Found:[/bold yellow]\n")

        issues_table = Table(title="Vault Compliance Issues")
        issues_table.add_column("Type", style="cyan")
        issues_table.add_column("Severity", style="yellow")
        issues_table.add_column("Description", style="white")

        for issue in result.issues[:50]:  # Limit to 50 for display
            issues_table.add_row(
                issue["type"],
                issue["severity"],
                issue["description"],
            )

        console.print(issues_table)

        if len(result.issues) > 50:
            console.print(f"\n[dim]... and {len(result.issues) - 50} more issues[/dim]")

    # Save to output file if requested
    if output:
        _save_vault_results_to_output(result, output)


def _save_vault_results_to_output(result, output: Path) -> None:
    """Save Vault scan results to output file."""
    output.parent.mkdir(parents=True, exist_ok=True)

    # Determine format from extension
    format = "json" if output.suffix == ".json" else "csv"

    if format == "csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([
                "Matter ID",
                "Matter Name",
                "State",
                "Holds Count",
            ])

            # Write matter data
            for matter in result.matters:
                writer.writerow([
                    matter.matter_id,
                    matter.name,
                    matter.state,
                    matter.holds_count,
                ])

        console.print(f"[green]✓ Results saved to {output}[/green]")

    else:  # JSON
        data = {
            "scan_type": "vault",
            "summary": result.statistics,
            "matters": [
                {
                    "matter_id": matter.matter_id,
                    "name": matter.name,
                    "state": matter.state,
                    "holds_count": matter.holds_count,
                }
                for matter in result.matters
            ],
            "holds": [
                {
                    "hold_id": hold.hold_id,
                    "matter_id": hold.matter_id,
                    "name": hold.name,
                    "corpus": hold.corpus,
                    "accounts": hold.accounts,
                }
                for hold in result.holds
            ],
            "retention_policies": [
                {
                    "policy_id": policy.policy_id,
                    "name": policy.name,
                    "corpus": policy.corpus,
                    "retention_period_days": policy.retention_period_days,
                }
                for policy in result.retention_policies
            ],
            "issues": result.issues,
        }

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]✓ Results saved to {output}[/green]")


def scan_mobile_devices_command(
    config_path: Optional[Path],
    inactive_days: int,
    output: Optional[Path],
) -> None:
    """Scan mobile devices for security and compliance issues.

    Args:
        config_path: Path to configuration file
        inactive_days: Number of days to consider a device inactive
        output: Optional output file path
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import GoogleWorkspaceClient
    from vaulytica.core.scanners.mobile_device_scanner import MobileDeviceScanner

    console.print("[bold blue]🔍 Scanning Mobile Devices...[/bold blue]\n")

    # Load configuration
    config = load_config(config_path)

    # Create client
    client = GoogleWorkspaceClient(
        credentials_path=config.credentials_path,
        impersonate_user=config.impersonate_user,
    )

    # Create scanner
    scanner = MobileDeviceScanner(
        client=client,
        domain=config.domain,
        inactive_days=inactive_days,
    )

    # Run scan with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning mobile devices...", total=None)
        result = scanner.scan_all_devices()
        progress.update(task, completed=True)

    # Display summary
    console.print("\n[bold green]✓ Mobile Device Scan Complete[/bold green]\n")

    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="magenta")

    summary_table.add_row("Total Devices", str(result.total_devices))
    summary_table.add_row("Android Devices", str(result.android_devices))
    summary_table.add_row("iOS Devices", str(result.ios_devices))
    summary_table.add_row("Approved Devices", str(result.approved_devices))
    summary_table.add_row("Blocked Devices", str(result.blocked_devices))
    summary_table.add_row("Compromised Devices", str(result.compromised_devices))
    summary_table.add_row("Unencrypted Devices", str(result.unencrypted_devices))
    summary_table.add_row("No Password Devices", str(result.no_password_devices))
    summary_table.add_row("Inactive Devices", str(result.inactive_devices))
    summary_table.add_row("Total Issues", str(len(result.issues)))

    console.print(summary_table)

    # Display issues
    if result.issues:
        console.print("\n[bold yellow]⚠ Issues Found:[/bold yellow]\n")

        issues_table = Table(title="Mobile Device Security Issues")
        issues_table.add_column("Type", style="cyan")
        issues_table.add_column("Severity", style="yellow")
        issues_table.add_column("Device", style="white")
        issues_table.add_column("User", style="white")
        issues_table.add_column("Description", style="white")

        for issue in result.issues[:50]:  # Limit to 50 for display
            issues_table.add_row(
                issue["type"],
                issue["severity"],
                issue.get("device", ""),
                issue.get("user", ""),
                issue["description"],
            )

        console.print(issues_table)

        if len(result.issues) > 50:
            console.print(f"\n[dim]... and {len(result.issues) - 50} more issues[/dim]")

    # Save to output file if requested
    if output:
        _save_mobile_device_results_to_output(result, output)


def _save_mobile_device_results_to_output(result, output: Path) -> None:
    """Save mobile device scan results to output file."""
    output.parent.mkdir(parents=True, exist_ok=True)

    # Determine format from extension
    format = "json" if output.suffix == ".json" else "csv"

    if format == "csv":
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow([
                "Device ID",
                "User",
                "Model",
                "OS",
                "Status",
                "Compromised",
                "Encrypted",
                "Password Protected",
                "Last Sync",
                "Risk Score",
            ])

            # Write device data
            for device in result.devices:
                writer.writerow([
                    device.device_id,
                    device.email,
                    device.model,
                    device.os,
                    device.status,
                    "Yes" if device.is_compromised else "No",
                    "Yes" if device.is_encrypted else "No",
                    "Yes" if device.is_password_protected else "No",
                    device.last_sync.isoformat() if device.last_sync else "Never",
                    device.risk_score,
                ])

        console.print(f"[green]✓ Results saved to {output}[/green]")

    else:  # JSON
        data = {
            "scan_type": "mobile_devices",
            "summary": result.statistics,
            "devices": [
                {
                    "device_id": device.device_id,
                    "user": device.email,
                    "model": device.model,
                    "os": device.os,
                    "status": device.status,
                    "is_compromised": device.is_compromised,
                    "is_encrypted": device.is_encrypted,
                    "is_password_protected": device.is_password_protected,
                    "last_sync": device.last_sync.isoformat() if device.last_sync else None,
                    "risk_score": device.risk_score,
                }
                for device in result.devices
            ],
            "issues": result.issues,
        }

        with open(output, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]✓ Results saved to {output}[/green]")


def scan_chrome_devices_command(
    config_path: Optional[Path],
    org_unit: Optional[str],
    inactive_days: int,
    output: Optional[Path],
) -> None:
    """Scan Chrome OS devices (Chromebooks, Chromeboxes, Chromebases).

    Args:
        config_path: Path to configuration file
        org_unit: Optional OU path to filter devices
        inactive_days: Number of days to consider a device inactive
        output: Optional output file path
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import GoogleWorkspaceClient
    from vaulytica.core.scanners.chrome_device_scanner import ChromeDeviceScanner

    console.print("[bold blue]🔍 Scanning Chrome OS Devices...[/bold blue]\n")

    # Load configuration
    config = load_config(config_path)

    # Create client
    client = GoogleWorkspaceClient(
        credentials_path=config.credentials_path,
        impersonate_user=config.impersonate_user,
    )

    # Create scanner
    scanner = ChromeDeviceScanner(
        client=client,
        inactive_days=inactive_days,
    )

    # Run scan with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning Chrome OS devices...", total=None)
        result = scanner.scan_all_devices(org_unit_path=org_unit)
        progress.update(task, completed=True)

    # Display summary
    console.print("\n[bold green]✓ Chrome Device Scan Complete[/bold green]\n")

    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="magenta")

    summary_table.add_row("Total Devices", str(result.total_devices))
    summary_table.add_row("Active Devices", str(result.active_devices))
    summary_table.add_row("Provisioned Devices", str(result.provisioned_devices))
    summary_table.add_row("Disabled Devices", str(result.disabled_devices))
    summary_table.add_row("Auto-Update Expired", str(result.auto_update_expired))
    summary_table.add_row("Developer Mode", str(result.dev_mode_devices))
    summary_table.add_row("Inactive Devices", str(result.inactive_devices))
    summary_table.add_row("Total Issues", str(len(result.issues)))

    console.print(summary_table)

    # Display high-risk devices
    if result.issues:
        console.print("\n[bold red]⚠️  Security Issues Found[/bold red]\n")

        issues_table = Table(title="Chrome Device Issues")
        issues_table.add_column("Severity", style="red")
        issues_table.add_column("Type", style="yellow")
        issues_table.add_column("Device", style="cyan")
        issues_table.add_column("User", style="magenta")
        issues_table.add_column("Description", style="white")

        for issue in result.issues[:20]:  # Show top 20
            issues_table.add_row(
                issue["severity"],
                issue["type"],
                issue["device"],
                issue["user"],
                issue["description"],
            )

        console.print(issues_table)

        if len(result.issues) > 20:
            console.print(f"\n[yellow]... and {len(result.issues) - 20} more issues[/yellow]")

    # Save output if requested
    if output:
        console.print(f"\n[cyan]Saving results to {output}...[/cyan]")

        if output.suffix.lower() == ".csv":
            import csv

            with open(output, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Device ID",
                    "Serial Number",
                    "Model",
                    "Status",
                    "OS Version",
                    "User",
                    "Location",
                    "Last Sync",
                    "Auto-Update Expired",
                    "Developer Mode",
                    "Risk Score",
                ])

                for device in result.devices:
                    writer.writerow([
                        device.device_id,
                        device.serial_number,
                        device.model,
                        device.status,
                        device.os_version,
                        device.annotated_user,
                        device.annotated_location,
                        device.last_sync.isoformat() if device.last_sync else "",
                        "Yes" if device.is_auto_update_expired else "No",
                        "Yes" if device.boot_mode == "Dev" else "No",
                        device.risk_score,
                    ])

            console.print(f"[green]✓ Results saved to {output}[/green]")

        else:  # JSON
            data = {
                "scan_type": "chrome_devices",
                "summary": {
                    "total_devices": result.total_devices,
                    "active_devices": result.active_devices,
                    "auto_update_expired": result.auto_update_expired,
                    "dev_mode_devices": result.dev_mode_devices,
                    "inactive_devices": result.inactive_devices,
                },
                "devices": [
                    {
                        "device_id": device.device_id,
                        "serial_number": device.serial_number,
                        "model": device.model,
                        "status": device.status,
                        "os_version": device.os_version,
                        "user": device.annotated_user,
                        "location": device.annotated_location,
                        "last_sync": device.last_sync.isoformat() if device.last_sync else None,
                        "auto_update_expired": device.is_auto_update_expired,
                        "boot_mode": device.boot_mode,
                        "org_unit_path": device.org_unit_path,
                        "risk_score": device.risk_score,
                        "risk_factors": device.risk_factors,
                    }
                    for device in result.devices
                ],
                "issues": result.issues,
            }

            with open(output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            console.print(f"[green]✓ Results saved to {output}[/green]")


def scan_licenses_command(
    config_path: Optional[Path],
    unused_days: int,
    show_recommendations: bool,
    output: Optional[Path],
) -> None:
    """Scan Google Workspace licenses for cost optimization.

    Args:
        config_path: Path to configuration file
        unused_days: Consider license unused if user inactive for N days
        show_recommendations: Show cost optimization recommendations
        output: Optional output file path
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import GoogleWorkspaceClient
    from vaulytica.core.scanners.license_scanner import LicenseScanner

    console.print("[bold blue]🔍 Scanning Google Workspace Licenses...[/bold blue]\n")

    # Load configuration
    config = load_config(config_path)

    # Create client
    client = GoogleWorkspaceClient(
        credentials_path=config.credentials_path,
        impersonate_user=config.impersonate_user,
    )

    # Create scanner
    scanner = LicenseScanner(
        client=client,
        unused_days=unused_days,
    )

    # Run scan with progress indicator
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning licenses...", total=None)
        result = scanner.scan_all_licenses()
        progress.update(task, completed=True)

    # Display summary
    console.print("\n[bold green]✓ License Scan Complete[/bold green]\n")

    summary_table = Table(title="License Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="magenta")

    summary_table.add_row("Total Licenses", str(result.total_licenses))
    summary_table.add_row("Assigned Licenses", str(result.assigned_licenses))
    summary_table.add_row("Available Licenses", str(result.available_licenses))
    summary_table.add_row("Unused Licenses", f"[red]{result.unused_licenses_count}[/red]")
    summary_table.add_row("Underutilized Licenses", f"[yellow]{result.underutilized_licenses_count}[/yellow]")
    summary_table.add_row("Monthly Cost", f"${result.total_monthly_cost:,.2f}")
    summary_table.add_row("Potential Savings", f"[green]${result.potential_savings:,.2f}[/green]")

    console.print(summary_table)

    # Display recommendations
    if show_recommendations and result.recommendations:
        console.print("\n[bold yellow]💡 Cost Optimization Recommendations[/bold yellow]\n")
        for i, recommendation in enumerate(result.recommendations, 1):
            console.print(f"{i}. {recommendation}")

    # Display unused licenses
    if result.unused_licenses:
        console.print(f"\n[bold red]⚠️  {len(result.unused_licenses)} Unused Licenses Found[/bold red]\n")

        unused_table = Table(title="Unused Licenses")
        unused_table.add_column("User", style="cyan")
        unused_table.add_column("License Type", style="yellow")
        unused_table.add_column("Assigned Date", style="magenta")
        unused_table.add_column("Last Used", style="white")

        for license_assignment in result.unused_licenses[:20]:  # Show top 20
            unused_table.add_row(
                license_assignment.user_email,
                license_assignment.sku_name,
                license_assignment.assigned_date.strftime("%Y-%m-%d") if license_assignment.assigned_date else "N/A",
                license_assignment.last_used.strftime("%Y-%m-%d") if license_assignment.last_used else "Never",
            )

        console.print(unused_table)

        if len(result.unused_licenses) > 20:
            console.print(f"\n[dim]... and {len(result.unused_licenses) - 20} more[/dim]")

    # Save to file if requested
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)

        if output.suffix == ".csv":
            with open(output, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow([
                    "User Email",
                    "License Type",
                    "SKU ID",
                    "Assigned Date",
                    "Last Used",
                    "Status",
                    "Days Unused",
                ])
                # Write unused licenses
                for license_assignment in result.unused_licenses:
                    days_unused = (datetime.now(timezone.utc) - license_assignment.last_used).days if license_assignment.last_used else "N/A"
                    writer.writerow([
                        license_assignment.user_email,
                        license_assignment.sku_name,
                        license_assignment.sku_id,
                        license_assignment.assigned_date.strftime("%Y-%m-%d") if license_assignment.assigned_date else "N/A",
                        license_assignment.last_used.strftime("%Y-%m-%d") if license_assignment.last_used else "Never",
                        "Unused" if not license_assignment.is_active else "Underutilized",
                        days_unused,
                    ])

            console.print(f"[green]✓ Results saved to {output}[/green]")

        else:  # JSON
            data = {
                "scan_type": "licenses",
                "summary": {
                    "total_licenses": result.total_licenses,
                    "assigned_licenses": result.assigned_licenses,
                    "available_licenses": result.available_licenses,
                    "unused_licenses": result.unused_licenses_count,
                    "underutilized_licenses": result.underutilized_licenses_count,
                    "total_monthly_cost": result.total_monthly_cost,
                    "potential_savings": result.potential_savings,
                },
                "recommendations": result.recommendations,
                "unused_licenses": [
                    {
                        "user_email": license_assignment.user_email,
                        "sku_id": license_assignment.sku_id,
                        "sku_name": license_assignment.sku_name,
                        "assigned_date": license_assignment.assigned_date.isoformat() if license_assignment.assigned_date else None,
                        "last_used": license_assignment.last_used.isoformat() if license_assignment.last_used else None,
                        "is_active": license_assignment.is_active,
                    }
                    for license_assignment in result.unused_licenses
                ],
            }

            with open(output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            console.print(f"[green]✓ Results saved to {output}[/green]")

