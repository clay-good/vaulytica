"""Policy management CLI commands."""

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from vaulytica.config.loader import load_config
from vaulytica.core.auth.client import create_client_from_config
from vaulytica.core.policies.expiration import ExpirationManager, ExpirationPolicy
from vaulytica.core.scanners.file_scanner import FileScanner

console = Console()


@click.group()
def policy():
    """Policy management commands."""
    pass


@policy.command(name="expire")
@click.option(
    "--expiration-days",
    type=int,
    default=30,
    help="Days after which external shares expire",
)
@click.option(
    "--grace-period",
    type=int,
    default=7,
    help="Days before expiration to send notifications",
)
@click.option(
    "--exempt-domain",
    multiple=True,
    help="Domains to exempt from expiration (can specify multiple)",
)
@click.option(
    "--exempt-user",
    multiple=True,
    help="Users to exempt from expiration (can specify multiple)",
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
def expire_shares(
    ctx,
    expiration_days: int,
    grace_period: int,
    exempt_domain: tuple,
    exempt_user: tuple,
    dry_run: bool,
    output: str,
):
    """Apply auto-expiration policy to external shares.

    This command will:
    - Scan all files for external shares
    - Identify shares older than expiration threshold
    - Revoke expired shares (or notify in dry-run mode)
    - Send notifications for shares approaching expiration

    Example:
        vaulytica policy expire --expiration-days 30 --grace-period 7 --dry-run
    """
    try:
        # Load config
        config = load_config(ctx.obj.get("config_path"))

        # Create client
        client = create_client_from_config(config)

        # Get domain
        domain = config["google_workspace"]["domain"]

        # Create policy
        policy = ExpirationPolicy(
            name="auto-expire-external-shares",
            expiration_days=expiration_days,
            grace_period_days=grace_period,
            notify_before_expiry=True,
            exempted_domains=list(exempt_domain),
            exempted_users=list(exempt_user),
        )

        # Show policy details
        console.print("\n[bold]Expiration Policy:[/bold]\n")

        policy_table = Table()
        policy_table.add_column("Setting", style="cyan")
        policy_table.add_column("Value", style="white")

        policy_table.add_row("Expiration Days", str(policy.expiration_days))
        policy_table.add_row("Grace Period", str(policy.grace_period_days))
        policy_table.add_row("Notify Before Expiry", str(policy.notify_before_expiry))
        policy_table.add_row("Exempted Domains", ", ".join(policy.exempted_domains) or "None")
        policy_table.add_row("Exempted Users", ", ".join(policy.exempted_users) or "None")

        console.print(policy_table)

        # Show warning for execute mode
        if not dry_run:
            console.print(
                Panel(
                    "[bold red]⚠️  EXECUTE MODE - Shares will be revoked![/bold red]\n\n"
                    f"Shares older than {expiration_days} days will be permanently revoked.",
                    title="Expiration Confirmation",
                    border_style="red",
                )
            )

            if not click.confirm("Do you want to proceed?"):
                console.print("[yellow]Policy execution cancelled[/yellow]")
                return

        if dry_run:
            console.print("\n[yellow]🔍 DRY RUN MODE - No changes will be made[/yellow]\n")

        # Scan files
        console.print("[bold]Scanning files for external shares...[/bold]")

        scanner = FileScanner(client, domain)

        files = []
        with console.status("[bold green]Scanning..."):
            for file_info in scanner.scan_all_files(external_only=True):
                files.append(file_info)

        console.print(f"[green]Found {len(files)} files with external shares[/green]\n")

        # Apply policy
        console.print("[bold]Applying expiration policy...[/bold]")

        manager = ExpirationManager(client, domain, dry_run=dry_run)

        with console.status("[bold green]Processing..."):
            report = manager.apply_policy(policy, files)

        # Display summary
        console.print("\n[bold green]✓ Policy Applied[/bold green]\n")

        summary_table = Table(title="Expiration Summary")
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="green")

        summary_table.add_row("Files Scanned", str(report.files_scanned))
        summary_table.add_row("Shares Expired", str(report.shares_expired))
        summary_table.add_row("Shares Notified", str(report.shares_notified))
        summary_table.add_row("Shares Exempted", str(report.shares_exempted))
        summary_table.add_row("Total Actions", str(len(report.actions)))

        console.print(summary_table)

        # Display actions
        if report.actions:
            console.print("\n[bold]Actions Taken:[/bold]\n")

            actions_table = Table()
            actions_table.add_column("Action", style="cyan")
            actions_table.add_column("File", style="white")
            actions_table.add_column("Shared With", style="yellow")
            actions_table.add_column("Days", style="dim")
            actions_table.add_column("Status", style="green")

            for action in report.actions[:20]:  # Show first 20
                status_icon = "✓" if action.status == "success" else "✗"
                status_color = "green" if action.status == "success" else "red"

                action_color = {
                    "expire": "red",
                    "notify": "yellow",
                    "exempt": "blue",
                }.get(action.action, "white")

                actions_table.add_row(
                    f"[{action_color}]{action.action}[/{action_color}]",
                    action.file_name[:40],
                    action.permission_email[:30],
                    str(action.days_shared),
                    f"[{status_color}]{status_icon} {action.status}[/{status_color}]",
                )

            console.print(actions_table)

            if len(report.actions) > 20:
                console.print(f"\n[dim]... and {len(report.actions) - 20} more actions[/dim]")

        # Save report if requested
        if output:
            import json

            report_data = {
                "policy_name": report.policy_name,
                "scan_time": report.scan_time.isoformat(),
                "files_scanned": report.files_scanned,
                "shares_expired": report.shares_expired,
                "shares_notified": report.shares_notified,
                "shares_exempted": report.shares_exempted,
                "actions": [
                    {
                        "file_id": action.file_id,
                        "file_name": action.file_name,
                        "permission_id": action.permission_id,
                        "permission_email": action.permission_email,
                        "permission_type": action.permission_type,
                        "shared_date": action.shared_date.isoformat(),
                        "days_shared": action.days_shared,
                        "action": action.action,
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

