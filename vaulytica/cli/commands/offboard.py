"""Offboarding CLI commands."""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from vaulytica.config.loader import load_config
from vaulytica.core.auth.client import create_client_from_config
from vaulytica.core.lifecycle.offboarding import OffboardingManager
from vaulytica.core.scanners.user_scanner import UserScanner

console = Console()


@click.group()
def offboard():
    """Employee offboarding commands."""
    pass


@offboard.command(name="user")
@click.argument("user_email")
@click.option(
    "--transfer-to",
    help="Email address to transfer files to (defaults to manager)",
)
@click.option(
    "--revoke-external-shares/--keep-external-shares",
    default=True,
    help="Revoke external shares on user's files",
)
@click.option(
    "--transfer-ownership/--no-transfer-ownership",
    default=True,
    help="Transfer file ownership to recipient",
)
@click.option(
    "--dry-run/--execute",
    default=True,
    help="Dry run mode (no actual changes)",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Save report to file (JSON format)",
)
@click.pass_context
def offboard_user(
    ctx,
    user_email: str,
    transfer_to: str,
    revoke_external_shares: bool,
    transfer_ownership: bool,
    dry_run: bool,
    output: str,
):
    """Offboard a user and transfer their files.

    This command will:
    - Find all files owned by the user
    - Transfer ownership to manager or specified user
    - Revoke external shares (optional)
    - Generate offboarding report

    Example:
        vaulytica offboard user john@company.com --transfer-to manager@company.com
    """
    try:
        # Load config
        config = load_config(ctx.obj.get("config_path"))

        # Create client
        client = create_client_from_config(config)

        # Get domain
        domain = config["google_workspace"]["domain"]

        # Create offboarding manager
        manager = OffboardingManager(client, domain, dry_run=dry_run)

        # Show warning for execute mode
        if not dry_run:
            console.print(
                Panel(
                    "[bold red]⚠️  EXECUTE MODE - Changes will be made![/bold red]\n\n"
                    f"User: {user_email}\n"
                    f"Transfer to: {transfer_to or 'manager'}\n"
                    f"Revoke external shares: {revoke_external_shares}\n"
                    f"Transfer ownership: {transfer_ownership}",
                    title="Offboarding Confirmation",
                    border_style="red",
                )
            )

            if not click.confirm("Do you want to proceed?"):
                console.print("[yellow]Offboarding cancelled[/yellow]")
                return

        # Run offboarding
        console.print(f"\n[bold]Offboarding user: {user_email}[/bold]")

        if dry_run:
            console.print("[yellow]🔍 DRY RUN MODE - No changes will be made[/yellow]\n")

        with console.status("[bold green]Processing offboarding..."):
            report = manager.offboard_user(
                user_email=user_email,
                transfer_to=transfer_to,
                revoke_external_shares=revoke_external_shares,
                transfer_ownership=transfer_ownership,
            )

        # Display summary
        console.print("\n[bold green]✓ Offboarding Complete[/bold green]\n")

        summary_table = Table(title="Offboarding Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")

        summary_table.add_row("User", report.user_email)
        summary_table.add_row("Name", report.user_name)
        summary_table.add_row("Manager", report.manager_email or "N/A")
        summary_table.add_row("Files Found", str(report.files_found))
        summary_table.add_row("Files Transferred", str(report.files_transferred))
        summary_table.add_row("Shares Revoked", str(report.shares_revoked))
        summary_table.add_row("Total Actions", str(len(report.actions)))

        console.print(summary_table)

        # Display actions
        if report.actions:
            console.print("\n[bold]Actions Taken:[/bold]\n")

            actions_table = Table()
            actions_table.add_column("Action", style="cyan")
            actions_table.add_column("File", style="white")
            actions_table.add_column("Status", style="green")

            for action in report.actions[:20]:  # Show first 20
                status_icon = "✓" if action.status == "success" else "✗"
                status_color = "green" if action.status == "success" else "red"

                actions_table.add_row(
                    action.action_type,
                    action.file_name[:50],
                    f"[{status_color}]{status_icon} {action.status}[/{status_color}]",
                )

            console.print(actions_table)

            if len(report.actions) > 20:
                console.print(f"\n[dim]... and {len(report.actions) - 20} more actions[/dim]")

        # Save report if requested
        if output:
            import json
            from datetime import datetime

            report_data = {
                "user_email": report.user_email,
                "user_name": report.user_name,
                "manager_email": report.manager_email,
                "offboarding_time": report.offboarding_time.isoformat(),
                "files_found": report.files_found,
                "files_transferred": report.files_transferred,
                "shares_revoked": report.shares_revoked,
                "actions": [
                    {
                        "action_type": action.action_type,
                        "file_id": action.file_id,
                        "file_name": action.file_name,
                        "from_user": action.from_user,
                        "to_user": action.to_user,
                        "status": action.status,
                        "error_message": action.error_message,
                        "timestamp": action.timestamp.isoformat(),
                    }
                    for action in report.actions
                ],
            }

            with open(output, "w") as f:
                json.dump(report_data, f, indent=2)

            console.print(f"\n[green]Report saved to: {output}[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise click.Abort()


@offboard.command(name="list-suspended")
@click.pass_context
def list_suspended(ctx):
    """List all suspended users who may need offboarding.

    Example:
        vaulytica offboard list-suspended
    """
    try:
        # Load config
        config = load_config(ctx.obj.get("config_path"))

        # Create client
        client = create_client_from_config(config)

        # Get domain
        domain = config["google_workspace"]["domain"]

        # Create user scanner
        scanner = UserScanner(client, domain)

        # Get suspended users
        with console.status("[bold green]Fetching suspended users..."):
            suspended_users = scanner.get_suspended_users()

        if not suspended_users:
            console.print("[green]No suspended users found[/green]")
            return

        # Display results
        console.print(f"\n[bold]Found {len(suspended_users)} suspended users:[/bold]\n")

        table = Table()
        table.add_column("Email", style="cyan")
        table.add_column("Name", style="white")
        table.add_column("Manager", style="yellow")
        table.add_column("Last Login", style="dim")

        for user in suspended_users:
            last_login = (
                user.last_login_time.strftime("%Y-%m-%d")
                if user.last_login_time
                else "Never"
            )

            table.add_row(
                user.email,
                user.full_name,
                user.manager_email or "N/A",
                last_login,
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise click.Abort()

