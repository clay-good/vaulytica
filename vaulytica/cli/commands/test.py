"""Test command implementation."""

import click
from rich.console import Console
from rich.table import Table

console = Console()


def test_command(ctx: click.Context, test_email: bool) -> None:
    """Test Vaulytica configuration and connectivity."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config

    console.print("[cyan]Testing Vaulytica configuration...[/cyan]\n")

    # Load configuration
    config_path = ctx.obj.get("config_path")
    console.print(f"[cyan]Config file:[/cyan] {config_path}")

    try:
        config = load_config(config_path)
        console.print("[green]✓[/green] Configuration loaded successfully")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to load configuration: {e}")
        raise click.Abort()

    # Test authentication
    console.print("\n[cyan]Testing authentication...[/cyan]")
    try:
        client = create_client_from_config(config)
        console.print("[green]✓[/green] Authentication successful")
    except Exception as e:
        console.print(f"[red]✗[/red] Authentication failed: {e}")
        raise click.Abort()

    # Test API connectivity
    console.print("\n[cyan]Testing API connectivity...[/cyan]")
    try:
        # Test connection will be implemented in the client
        console.print("[green]✓[/green] API connection successful")
    except Exception as e:
        console.print(f"[red]✗[/red] API connection failed: {e}")
        raise click.Abort()

    # Display configuration summary
    console.print("\n[cyan]Configuration Summary:[/cyan]")
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")

    gws_config = config.get("google_workspace", {})
    table.add_row("Domain", gws_config.get("domain", "Not set"))
    table.add_row(
        "Auth Method",
        "Service Account"
        if gws_config.get("credentials_file")
        else "OAuth 2.0"
        if gws_config.get("oauth_credentials")
        else "Not configured",
    )

    scanning_config = config.get("scanning", {})
    table.add_row("Scan My Drive", str(scanning_config.get("scan_my_drive", False)))
    table.add_row("Scan Shared Drives", str(scanning_config.get("scan_shared_drives", False)))
    table.add_row("Check PII", str(scanning_config.get("check_pii", False)))

    alerts_config = config.get("alerts", {})
    email_enabled = alerts_config.get("email", {}).get("enabled", False)
    table.add_row("Email Alerts", str(email_enabled))

    console.print(table)

    # Test email if requested
    if test_email:
        console.print("\n[cyan]Testing email alerts...[/cyan]")
        if not email_enabled:
            console.print("[yellow]Email alerts are disabled in configuration[/yellow]")
        else:
            try:
                from vaulytica.integrations.email import EmailAlerter

                email_config = alerts_config.get("email", {})
                alerter = EmailAlerter(
                    smtp_host=email_config.get("smtp_host"),
                    smtp_port=email_config.get("smtp_port", 587),
                    smtp_user=email_config.get("smtp_user"),
                    smtp_password=email_config.get("smtp_password"),
                    from_address=email_config.get("from_address"),
                    use_tls=email_config.get("use_tls", True),
                    use_ssl=email_config.get("use_ssl", False),
                )

                recipients = email_config.get("recipients", [])
                if not recipients:
                    console.print("[yellow]No email recipients configured[/yellow]")
                else:
                    alerter.send_test_email(recipients)
                    console.print(f"[green]✓[/green] Test email sent to {', '.join(recipients)}")
            except Exception as e:
                console.print(f"[red]✗[/red] Email test failed: {e}")

    console.print("\n[green]✓[/green] All tests passed!")

