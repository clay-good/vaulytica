"""User management commands."""

from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group(name="users")
@click.pass_context
def users_group(ctx):
    """User provisioning and management commands."""
    pass


@users_group.command(name="create")
@click.argument("email")
@click.option("--first-name", required=True, help="User's first name")
@click.option("--last-name", required=True, help="User's last name")
@click.option("--password", help="Initial password (will prompt if not provided)")
@click.option("--org-unit", default="/", help="Organizational unit path")
@click.option("--change-password", is_flag=True, default=True, help="Require password change on first login")
@click.pass_context
def create_user(
    ctx: click.Context,
    email: str,
    first_name: str,
    last_name: str,
    password: Optional[str],
    org_unit: str,
    change_password: bool,
):
    """Create a new user account."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.user_provisioning import UserProvisioner
    
    console.print(f"[cyan]Creating user: {email}[/cyan]\n")
    
    # Prompt for password if not provided
    if not password:
        password = click.prompt("Enter initial password", hide_input=True, confirmation_prompt=True)
    
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
    
    # Create user
    try:
        provisioner = UserProvisioner(client)
        user = provisioner.create_user(
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password,
            org_unit_path=org_unit,
            change_password_at_next_login=change_password,
        )
        
        console.print(Panel.fit(
            f"[green]✓ User created successfully![/green]\n\n"
            f"Email: {user['primaryEmail']}\n"
            f"Name: {user['name']['fullName']}\n"
            f"OU: {user.get('orgUnitPath', '/')}\n"
            f"Change password required: {change_password}",
            border_style="green"
        ))
        
    except Exception as e:
        console.print(f"[red]Error creating user: {e}[/red]")
        raise click.Abort()


@users_group.command(name="suspend")
@click.argument("email")
@click.option("--reason", help="Reason for suspension")
@click.pass_context
def suspend_user(ctx: click.Context, email: str, reason: Optional[str]):
    """Suspend a user account."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.user_provisioning import UserProvisioner
    
    console.print(f"[yellow]Suspending user: {email}[/yellow]\n")
    
    if reason:
        console.print(f"Reason: {reason}\n")
    
    # Confirm action
    if not click.confirm("Are you sure you want to suspend this user?"):
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
    
    # Suspend user
    try:
        provisioner = UserProvisioner(client)
        provisioner.suspend_user(email)
        
        console.print(f"[green]✓ User suspended: {email}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error suspending user: {e}[/red]")
        raise click.Abort()


@users_group.command(name="restore")
@click.argument("email")
@click.pass_context
def restore_user(ctx: click.Context, email: str):
    """Restore a suspended user account."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.user_provisioning import UserProvisioner
    
    console.print(f"[cyan]Restoring user: {email}[/cyan]\n")
    
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
    
    # Restore user
    try:
        provisioner = UserProvisioner(client)
        provisioner.restore_user(email)
        
        console.print(f"[green]✓ User restored: {email}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error restoring user: {e}[/red]")
        raise click.Abort()


@users_group.command(name="delete")
@click.argument("email")
@click.option("--force", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def delete_user(ctx: click.Context, email: str, force: bool):
    """Delete a user account (permanent)."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.user_provisioning import UserProvisioner
    
    console.print(f"[red]⚠ WARNING: Deleting user: {email}[/red]\n")
    console.print("[yellow]This action is PERMANENT and cannot be undone![/yellow]\n")
    
    # Confirm action
    if not force:
        if not click.confirm("Are you absolutely sure you want to delete this user?"):
            console.print("[yellow]Cancelled[/yellow]")
            return
        
        # Double confirmation
        confirmation = click.prompt("Type the email address to confirm")
        if confirmation != email:
            console.print("[red]Email does not match. Cancelled.[/red]")
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
    
    # Delete user
    try:
        provisioner = UserProvisioner(client)
        provisioner.delete_user(email)
        
        console.print(f"[green]✓ User deleted: {email}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error deleting user: {e}[/red]")
        raise click.Abort()


@users_group.command(name="update")
@click.argument("email")
@click.option("--first-name", help="Update first name")
@click.option("--last-name", help="Update last name")
@click.option("--org-unit", help="Move to organizational unit")
@click.option("--title", help="Update job title")
@click.option("--department", help="Update department")
@click.option("--manager", help="Set manager email")
@click.pass_context
def update_user(
    ctx: click.Context,
    email: str,
    first_name: Optional[str],
    last_name: Optional[str],
    org_unit: Optional[str],
    title: Optional[str],
    department: Optional[str],
    manager: Optional[str],
):
    """Update user account details."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.lifecycle.user_provisioning import UserProvisioner
    
    console.print(f"[cyan]Updating user: {email}[/cyan]\n")
    
    # Build update dict
    updates = {}
    if first_name:
        updates["first_name"] = first_name
    if last_name:
        updates["last_name"] = last_name
    if org_unit:
        updates["org_unit_path"] = org_unit
    if title:
        updates["title"] = title
    if department:
        updates["department"] = department
    if manager:
        updates["manager_email"] = manager
    
    if not updates:
        console.print("[yellow]No updates specified[/yellow]")
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
    
    # Update user
    try:
        provisioner = UserProvisioner(client)
        user = provisioner.update_user(email, **updates)
        
        console.print(f"[green]✓ User updated successfully![/green]\n")
        
        # Display updated fields
        table = Table(title="Updated Fields")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in updates.items():
            table.add_row(key.replace("_", " ").title(), str(value))
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error updating user: {e}[/red]")
        raise click.Abort()

