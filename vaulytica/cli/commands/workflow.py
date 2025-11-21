"""Workflow commands for automated security use cases."""

import click
from typing import Optional
from rich.console import Console
from rich.table import Table

console = Console()


@click.group(name="workflow")
def workflow_group():
    """Run automated security workflows."""
    pass


@workflow_group.command(name="external-pii-alert")
@click.option(
    "--domain",
    required=True,
    help="Organization domain (e.g., companyname.com)",
)
@click.option(
    "--min-risk-score",
    type=int,
    default=50,
    help="Minimum risk score to alert on (0-100)",
)
@click.option(
    "--max-file-size",
    type=int,
    default=10,
    help="Maximum file size to scan in MB",
)
@click.option(
    "--no-content-scan",
    is_flag=True,
    help="Skip downloading and scanning file content",
)
@click.option(
    "--alert-email",
    multiple=True,
    help="Email addresses to send alerts to (can specify multiple)",
)
@click.option(
    "--alert-webhook",
    help="Webhook URL for SIEM integration",
)
@click.option(
    "--webhook-format",
    type=click.Choice(["json", "splunk", "datadog", "elasticsearch"]),
    default="json",
    help="Webhook payload format",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Run without sending alerts (test mode)",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Save results to JSON file",
)
@click.pass_context
def external_pii_alert_command(
    ctx: click.Context,
    domain: str,
    min_risk_score: int,
    max_file_size: int,
    no_content_scan: bool,
    alert_email: tuple,
    alert_webhook: Optional[str],
    webhook_format: str,
    dry_run: bool,
    output: Optional[str],
):
    """Scan for externally shared files with PII and send alerts.

    This workflow:
    1. Scans all Drive files shared externally (outside your domain)
    2. Downloads and scans file content for PII
    3. Sends alerts via email and/or webhook for findings

    Example:

        vaulytica workflow external-pii-alert \\
            --domain companyname.com \\
            --alert-email security@companyname.com \\
            --alert-webhook https://siem.companyname.com/webhook \\
            --min-risk-score 75
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.workflows.external_pii_alert import (
        ExternalPIIAlertWorkflow,
        ExternalPIIAlertConfig,
    )

    console.print("\n[bold cyan]🔍 External PII Alert Workflow[/bold cyan]\n")

    if dry_run:
        console.print("[yellow]⚠️  DRY RUN MODE - No alerts will be sent[/yellow]\n")

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

    # Create workflow config
    workflow_config = ExternalPIIAlertConfig(
        domain=domain,
        min_risk_score=min_risk_score,
        max_file_size_mb=max_file_size,
        scan_file_content=not no_content_scan,
        alert_email=list(alert_email) if alert_email else None,
        alert_webhook=alert_webhook,
        webhook_format=webhook_format,
        dry_run=dry_run,
    )

    # Display configuration
    config_table = Table(title="Workflow Configuration")
    config_table.add_column("Setting", style="cyan")
    config_table.add_column("Value", style="white")

    config_table.add_row("Domain", domain)
    config_table.add_row("Min Risk Score", str(min_risk_score))
    config_table.add_row("Max File Size", f"{max_file_size} MB")
    config_table.add_row("Content Scanning", "Yes" if not no_content_scan else "No")
    config_table.add_row("Alert Email", ", ".join(alert_email) if alert_email else "None")
    config_table.add_row("Alert Webhook", alert_webhook or "None")
    config_table.add_row("Dry Run", "Yes" if dry_run else "No")

    console.print(config_table)
    console.print()

    # Run workflow
    workflow = ExternalPIIAlertWorkflow(client, workflow_config)
    result = workflow.run(show_progress=True)

    # Display results
    console.print("\n[bold green]✓ Workflow Complete[/bold green]\n")

    summary_table = Table(title="Workflow Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Total Files Scanned", str(result.total_files_scanned))
    summary_table.add_row("External Files Found", str(result.external_files_found))
    summary_table.add_row("Files with PII", str(result.files_with_pii))
    summary_table.add_row("Alerts Sent", str(result.alerts_sent))
    summary_table.add_row("Duration", f"{result.duration_seconds():.2f}s")

    console.print(summary_table)

    # Display findings
    if result.findings:
        console.print("\n[bold yellow]⚠️  Findings:[/bold yellow]\n")

        findings_table = Table()
        findings_table.add_column("File Name", style="cyan", max_width=40)
        findings_table.add_column("Owner", style="white")
        findings_table.add_column("Risk", style="red")
        findings_table.add_column("PII Types", style="yellow")
        findings_table.add_column("External Domains", style="magenta")

        for finding in result.findings[:20]:  # Show first 20
            pii_types = ", ".join([t.value for t in finding.pii_result.pii_types_found])
            external_domains = ", ".join(finding.file_info.external_domains[:3])

            if len(finding.file_info.external_domains) > 3:
                external_domains += f" +{len(finding.file_info.external_domains) - 3} more"

            findings_table.add_row(
                finding.file_info.name[:40],
                finding.file_info.owner_email,
                str(finding.file_info.risk_score),
                pii_types,
                external_domains,
            )

        console.print(findings_table)

        if len(result.findings) > 20:
            console.print(f"\n[dim]... and {len(result.findings) - 20} more findings[/dim]")

    # Display errors
    if result.errors:
        console.print("\n[bold red]❌ Errors:[/bold red]\n")
        for error in result.errors:
            console.print(f"  • {error}")

    # Save to file
    if output:
        import json

        output_data = {
            "workflow": "external_pii_alert",
            "timestamp": result.start_time.isoformat() if result.start_time else None,
            "duration_seconds": result.duration_seconds(),
            "summary": {
                "total_files_scanned": result.total_files_scanned,
                "external_files_found": result.external_files_found,
                "files_with_pii": result.files_with_pii,
                "alerts_sent": result.alerts_sent,
            },
            "findings": [
                {
                    "file": {
                        "id": f.file_info.id,
                        "name": f.file_info.name,
                        "owner": f.file_info.owner_email,
                        "url": f.file_info.web_view_link,
                        "risk_score": f.file_info.risk_score,
                        "external_domains": f.file_info.external_domains,
                        "external_emails": f.file_info.external_emails,
                    },
                    "pii": {
                        "types": [t.value for t in f.pii_result.pii_types_found],
                        "total_matches": f.pii_result.total_matches,
                        "high_confidence": f.pii_result.high_confidence_matches,
                    },
                }
                for f in result.findings
            ],
            "errors": result.errors,
        }

        with open(output, "w") as f:
            json.dump(output_data, f, indent=2)

        console.print(f"\n[green]✓ Results saved to {output}[/green]")

    # Summary message
    if dry_run:
        console.print(
            "\n[yellow]This was a dry run. Re-run without --dry-run to send alerts.[/yellow]"
        )
    elif result.alerts_sent > 0:
        console.print(
            f"\n[green]✓ Successfully sent {result.alerts_sent} alerts[/green]"
        )
    elif result.files_with_pii == 0:
        console.print("\n[green]✓ No files with PII found[/green]")
    else:
        console.print(
            "\n[yellow]⚠️  Files with PII found but no alerts configured[/yellow]"
        )


@workflow_group.command(name="gmail-external-pii-alert")
@click.option(
    "--domain",
    required=True,
    help="Organization domain (e.g., companyname.com)",
)
@click.option(
    "--user",
    multiple=True,
    help="Specific users to scan (can specify multiple, or omit for all users)",
)
@click.option(
    "--days-back",
    type=int,
    default=7,
    help="Number of days to look back",
)
@click.option(
    "--max-messages",
    type=int,
    default=100,
    help="Maximum messages per user to scan",
)
@click.option(
    "--min-risk-score",
    type=int,
    default=50,
    help="Minimum risk score to alert on (0-100)",
)
@click.option(
    "--alert-email",
    multiple=True,
    help="Email addresses to send alerts to (can specify multiple)",
)
@click.option(
    "--alert-webhook",
    help="Webhook URL for SIEM integration",
)
@click.option(
    "--webhook-format",
    type=click.Choice(["json", "splunk", "datadog", "elasticsearch"]),
    default="json",
    help="Webhook payload format",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Run without sending alerts (test mode)",
)
@click.option(
    "--output",
    type=click.Path(),
    help="Save results to JSON file",
)
@click.pass_context
def gmail_external_pii_alert_command(
    ctx: click.Context,
    domain: str,
    user: tuple,
    days_back: int,
    max_messages: int,
    min_risk_score: int,
    alert_email: tuple,
    alert_webhook: Optional[str],
    webhook_format: str,
    dry_run: bool,
    output: Optional[str],
):
    """Scan Gmail attachments sent externally for PII and send alerts.

    This workflow:
    1. Scans Gmail attachments for specified users (or all users)
    2. Filters for emails sent to external recipients (outside your domain)
    3. Detects PII in attachment content
    4. Sends alerts via email and/or webhook for findings

    Example:

        vaulytica workflow gmail-external-pii-alert \\
            --domain companyname.com \\
            --user user1@companyname.com \\
            --user user2@companyname.com \\
            --days-back 7 \\
            --alert-webhook https://siem.companyname.com/webhook
    """
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.workflows.gmail_external_pii_alert import (
        GmailExternalPIIAlertWorkflow,
        GmailExternalPIIAlertConfig,
    )

    console.print("\n[bold cyan]📧 Gmail External PII Alert Workflow[/bold cyan]\n")

    if dry_run:
        console.print("[yellow]⚠️  DRY RUN MODE - No alerts will be sent[/yellow]\n")

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

    # Create workflow config
    workflow_config = GmailExternalPIIAlertConfig(
        domain=domain,
        users=list(user) if user else None,
        days_back=days_back,
        max_messages_per_user=max_messages,
        min_risk_score=min_risk_score,
        alert_email=list(alert_email) if alert_email else None,
        alert_webhook=alert_webhook,
        webhook_format=webhook_format,
        dry_run=dry_run,
    )

    # Display configuration
    config_table = Table(title="Workflow Configuration")
    config_table.add_column("Setting", style="cyan")
    config_table.add_column("Value", style="white")

    config_table.add_row("Domain", domain)
    config_table.add_row("Users", ", ".join(user) if user else "All users")
    config_table.add_row("Days Back", str(days_back))
    config_table.add_row("Max Messages/User", str(max_messages))
    config_table.add_row("Min Risk Score", str(min_risk_score))
    config_table.add_row("Alert Email", ", ".join(alert_email) if alert_email else "None")
    config_table.add_row("Alert Webhook", alert_webhook or "None")
    config_table.add_row("Dry Run", "Yes" if dry_run else "No")

    console.print(config_table)
    console.print()

    # Run workflow
    workflow = GmailExternalPIIAlertWorkflow(client, workflow_config)
    result = workflow.run(show_progress=True)

    # Display results
    console.print("\n[bold green]✓ Workflow Complete[/bold green]\n")

    summary_table = Table(title="Workflow Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Users Scanned", str(result.total_users_scanned))
    summary_table.add_row("Messages Scanned", str(result.total_messages_scanned))
    summary_table.add_row("Attachments Scanned", str(result.total_attachments_scanned))
    summary_table.add_row("External Attachments", str(result.external_attachments_found))
    summary_table.add_row("Attachments with PII", str(result.attachments_with_pii))
    summary_table.add_row("Alerts Sent", str(result.alerts_sent))
    summary_table.add_row("Duration", f"{result.duration_seconds():.2f}s")

    console.print(summary_table)

    # Display findings
    if result.findings:
        console.print("\n[bold yellow]⚠️  Findings:[/bold yellow]\n")

        findings_table = Table()
        findings_table.add_column("User", style="cyan", max_width=30)
        findings_table.add_column("Filename", style="white", max_width=30)
        findings_table.add_column("Risk", style="red")
        findings_table.add_column("PII Types", style="yellow")
        findings_table.add_column("External Recipients", style="magenta", max_width=30)

        for finding in result.findings[:20]:  # Show first 20
            pii_types = ", ".join(
                [t.value for t in finding.pii_result.pii_types_found]
            ) if finding.pii_result else ""

            external_recips = ", ".join(finding.attachment.external_recipients[:2])
            if len(finding.attachment.external_recipients) > 2:
                external_recips += f" +{len(finding.attachment.external_recipients) - 2}"

            findings_table.add_row(
                finding.attachment.user_email[:30],
                finding.attachment.filename[:30],
                str(finding.risk_score),
                pii_types,
                external_recips,
            )

        console.print(findings_table)

        if len(result.findings) > 20:
            console.print(f"\n[dim]... and {len(result.findings) - 20} more findings[/dim]")

    # Display errors
    if result.errors:
        console.print("\n[bold red]❌ Errors:[/bold red]\n")
        for error in result.errors[:10]:  # Show first 10
            console.print(f"  • {error}")
        if len(result.errors) > 10:
            console.print(f"\n[dim]... and {len(result.errors) - 10} more errors[/dim]")

    # Save to file
    if output:
        import json

        output_data = {
            "workflow": "gmail_external_pii_alert",
            "timestamp": result.start_time.isoformat() if result.start_time else None,
            "duration_seconds": result.duration_seconds(),
            "summary": {
                "users_scanned": result.total_users_scanned,
                "messages_scanned": result.total_messages_scanned,
                "attachments_scanned": result.total_attachments_scanned,
                "external_attachments": result.external_attachments_found,
                "attachments_with_pii": result.attachments_with_pii,
                "alerts_sent": result.alerts_sent,
            },
            "findings": [
                {
                    "user": f.attachment.user_email,
                    "attachment": {
                        "filename": f.attachment.filename,
                        "mime_type": f.attachment.mime_type,
                        "size": f.attachment.size,
                        "message_id": f.attachment.message_id,
                    },
                    "email": {
                        "subject": f.attachment.subject,
                        "sender": f.attachment.sender,
                        "date": f.attachment.date.isoformat(),
                        "external_recipients": f.attachment.external_recipients,
                    },
                    "pii": {
                        "types": [t.value for t in f.pii_result.pii_types_found]
                        if f.pii_result
                        else [],
                        "total_matches": f.pii_result.total_matches
                        if f.pii_result
                        else 0,
                        "high_confidence": f.pii_result.high_confidence_matches
                        if f.pii_result
                        else 0,
                    },
                    "risk_score": f.risk_score,
                }
                for f in result.findings
            ],
            "errors": result.errors,
        }

        with open(output, "w") as f:
            json.dump(output_data, f, indent=2)

        console.print(f"\n[green]✓ Results saved to {output}[/green]")

    # Summary message
    if dry_run:
        console.print(
            "\n[yellow]This was a dry run. Re-run without --dry-run to send alerts.[/yellow]"
        )
    elif result.alerts_sent > 0:
        console.print(
            f"\n[green]✓ Successfully sent {result.alerts_sent} alerts[/green]"
        )
    elif result.attachments_with_pii == 0:
        console.print("\n[green]✓ No attachments with PII found[/green]")
    else:
        console.print(
            "\n[yellow]⚠️  Attachments with PII found but no alerts configured[/yellow]"
        )


@workflow_group.command(name="list")
def list_workflows():
    """List available workflows."""
    console.print("\n[bold cyan]Available Workflows:[/bold cyan]\n")

    workflows = [
        {
            "name": "external-pii-alert",
            "description": "Scan for externally shared files with PII and send alerts",
            "status": "✅ Available",
        },
        {
            "name": "gmail-external-pii-alert",
            "description": "Scan Gmail attachments sent externally for PII",
            "status": "✅ Available",
        },
    ]

    table = Table()
    table.add_column("Workflow", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Status", style="green")

    for workflow in workflows:
        table.add_row(workflow["name"], workflow["description"], workflow["status"])

    console.print(table)
    console.print()

