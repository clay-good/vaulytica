"""Bulk operations commands."""

import csv
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, track
from rich.panel import Panel

console = Console()


@click.group(name="bulk")
@click.pass_context
def bulk_group(ctx):
    """Bulk operations for users, groups, and resources."""
    pass


@bulk_group.command(name="create-users")
@click.argument("csv_file", type=click.Path(exists=True, path_type=Path))
@click.option("--dry-run", is_flag=True, help="Preview changes without applying")
@click.pass_context
def bulk_create_users(ctx: click.Context, csv_file: Path, dry_run: bool):
    """Create multiple users from CSV file.

    CSV format:
    email,first_name,last_name,password,org_unit,title,department
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.user_provisioning import UserProvisioner

    console.print(f"[cyan]Bulk creating users from: {csv_file}[/cyan]\n")

    # Read CSV
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            users = list(reader)
    except Exception as e:
        console.print(f"[red]Error reading CSV: {e}[/red]")
        raise click.Abort()

    if not users:
        console.print("[yellow]No users found in CSV[/yellow]")
        return

    console.print(f"Found {len(users)} users to create\n")

    # Preview
    table = Table(title="Users to Create")
    table.add_column("Email", style="cyan")
    table.add_column("Name", style="green")
    table.add_column("OU", style="yellow")

    for user in users[:10]:  # Show first 10
        name = f"{user.get('first_name', '')} {user.get('last_name', '')}"
        table.add_row(
            user.get('email', ''),
            name,
            user.get('org_unit', '/')
        )

    if len(users) > 10:
        console.print(f"[dim]... and {len(users) - 10} more[/dim]\n")

    console.print(table)
    console.print()

    if dry_run:
        console.print("[yellow]Dry run - no changes made[/yellow]")
        return

    # Confirm
    if not click.confirm(f"Create {len(users)} users?"):
        console.print("[yellow]Cancelled[/yellow]")
        return

    # Load configuration
    config_path = ctx.obj.get("config_path")
    try:
        config = load_config(config_path)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise click.Abort()

    # Create client
    try:
        client = create_client_from_config(config)
    except Exception as e:
        console.print(f"[red]Error creating client: {e}[/red]")
        raise click.Abort()

    # Create users
    provisioner = UserProvisioner(client)

    results = {
        "success": [],
        "failed": [],
    }

    for user_data in track(users, description="Creating users..."):
        try:
            email = user_data.get('email')
            if not email:
                results["failed"].append({"email": "unknown", "error": "Missing email"})
                continue

            user = provisioner.create_user(
                email=email,
                first_name=user_data.get('first_name', ''),
                last_name=user_data.get('last_name', ''),
                password=user_data.get('password', ''),
                org_unit_path=user_data.get('org_unit', '/'),
                title=user_data.get('title'),
                department=user_data.get('department'),
            )
            results["success"].append(email)
        except Exception as e:
            results["failed"].append({"email": email, "error": str(e)})

    # Display results
    console.print()
    console.print(Panel.fit(
        f"[green]✓ Created: {len(results['success'])}[/green]\n"
        f"[red]✗ Failed: {len(results['failed'])}[/red]",
        border_style="cyan"
    ))

    if results["failed"]:
        console.print("\n[red]Failed users:[/red]")
        for item in results["failed"]:
            console.print(f"  • {item['email']}: {item['error']}")


@bulk_group.command(name="suspend-users")
@click.argument("csv_file", type=click.Path(exists=True, path_type=Path))
@click.option("--dry-run", is_flag=True, help="Preview changes without applying")
@click.pass_context
def bulk_suspend_users(ctx: click.Context, csv_file: Path, dry_run: bool):
    """Suspend multiple users from CSV file.

    CSV format:
    email,reason
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.user_provisioning import UserProvisioner

    console.print(f"[yellow]Bulk suspending users from: {csv_file}[/yellow]\n")

    # Read CSV
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            users = list(reader)
    except Exception as e:
        console.print(f"[red]Error reading CSV: {e}[/red]")
        raise click.Abort()

    if not users:
        console.print("[yellow]No users found in CSV[/yellow]")
        return

    console.print(f"Found {len(users)} users to suspend\n")

    # Preview
    for user in users[:10]:
        console.print(f"  • {user.get('email', '')}")

    if len(users) > 10:
        console.print(f"[dim]... and {len(users) - 10} more[/dim]\n")

    if dry_run:
        console.print("[yellow]Dry run - no changes made[/yellow]")
        return

    # Confirm
    if not click.confirm(f"Suspend {len(users)} users?"):
        console.print("[yellow]Cancelled[/yellow]")
        return

    # Load configuration
    config_path = ctx.obj.get("config_path")
    try:
        config = load_config(config_path)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        raise click.Abort()

    # Create client
    try:
        client = create_client_from_config(config)
    except Exception as e:
        console.print(f"[red]Error creating client: {e}[/red]")
        raise click.Abort()

    # Suspend users
    provisioner = UserProvisioner(client)

    results = {
        "success": [],
        "failed": [],
    }

    for user_data in track(users, description="Suspending users..."):
        try:
            email = user_data.get('email')
            if not email:
                results["failed"].append({"email": "unknown", "error": "Missing email"})
                continue

            provisioner.suspend_user(email)
            results["success"].append(email)
        except Exception as e:
            results["failed"].append({"email": email, "error": str(e)})

    # Display results
    console.print()
    console.print(Panel.fit(
        f"[green]✓ Suspended: {len(results['success'])}[/green]\n"
        f"[red]✗ Failed: {len(results['failed'])}[/red]",
        border_style="yellow"
    ))

    if results["failed"]:
        console.print("\n[red]Failed users:[/red]")
        for item in results["failed"]:
            console.print(f"  • {item['email']}: {item['error']}")


@bulk_group.command(name="export-users")
@click.argument("output_file", type=click.Path(path_type=Path))
@click.option("--domain", help="Domain to export (from config if not specified)")
@click.pass_context
def bulk_export_users(ctx: click.Context, output_file: Path, domain: str):
    """Export all users to CSV file."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.scanners.user_scanner import UserScanner

    console.print(f"[cyan]Exporting users to: {output_file}[/cyan]\n")

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
            console.print("[red]Error: No domain specified[/red]")
            raise click.Abort()

    # Create client
    try:
        client = create_client_from_config(config)
    except Exception as e:
        console.print(f"[red]Error creating client: {e}[/red]")
        raise click.Abort()

    # Scan users
    scanner = UserScanner(client, domain)

    with Progress() as progress:
        task = progress.add_task("Scanning users...", total=None)
        result = scanner.scan_all_users()
        progress.update(task, completed=True)

    # Export to CSV
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'email', 'first_name', 'last_name', 'full_name',
                'is_admin', 'is_suspended', 'is_2fa_enrolled',
                'org_unit', 'last_login', 'creation_time'
            ])

            for user in result.users:
                writer.writerow([
                    user.email,
                    user.first_name,
                    user.last_name,
                    user.full_name,
                    user.is_admin,
                    user.is_suspended,
                    user.is_2fa_enrolled,
                    user.org_unit_path,
                    user.last_login_time,
                    user.creation_time,
                ])

        console.print(f"\n[green]✓ Exported {len(result.users)} users to {output_file}[/green]")

    except Exception as e:
        console.print(f"[red]Error exporting users: {e}[/red]")
        raise click.Abort()

