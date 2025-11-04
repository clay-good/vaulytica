"""Compliance reporting commands."""

import csv
import json
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


def compliance_report_command(
    ctx: click.Context,
    framework: str,
    domain: Optional[str],
    output: Optional[Path],
) -> None:
    """Generate compliance report."""
    from vaulytica.config.loader import load_config
    from vaulytica.core.auth.client import create_client_from_config
    from vaulytica.core.scanners.file_scanner import FileScanner
    from vaulytica.core.scanners.user_scanner import UserScanner
    from vaulytica.core.compliance.reporting import ComplianceReporter

    console.print(f"[cyan]Generating {framework.upper()} compliance report...[/cyan]")

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

    console.print(f"[cyan]Domain:[/cyan] {domain}\n")

    # Create client
    try:
        client = create_client_from_config(config)
    except Exception as e:
        console.print(f"[red]Error creating client: {e}[/red]")
        raise click.Abort()

    # Scan files and users
    console.print("[cyan]Scanning files...[/cyan]")
    file_scanner = FileScanner(client, domain)
    files = list(file_scanner.scan_all_files(external_only=True))

    console.print(f"[green]✓ Scanned {len(files)} files[/green]")

    console.print("[cyan]Scanning users...[/cyan]")
    user_scanner = UserScanner(client, domain)
    user_result = user_scanner.scan_all_users()

    console.print(f"[green]✓ Scanned {len(user_result.users)} users[/green]\n")

    # Generate report
    reporter = ComplianceReporter(domain)

    if framework == "gdpr":
        report = reporter.generate_gdpr_report(files, user_result.users)
        _display_gdpr_report(report)
        if output:
            _save_gdpr_report(report, output)

    elif framework == "hipaa":
        report = reporter.generate_hipaa_report(files, user_result.users)
        _display_hipaa_report(report)
        if output:
            _save_hipaa_report(report, output)

    elif framework == "soc2":
        report = reporter.generate_soc2_report(files, user_result.users)
        _display_soc2_report(report)
        if output:
            _save_soc2_report(report, output)

    elif framework == "pci-dss":
        report = reporter.generate_pcidss_report(files, user_result.users)
        _display_pcidss_report(report)
        if output:
            _save_pcidss_report(report, output)

    elif framework == "ferpa":
        report = reporter.generate_ferpa_report(files, user_result.users)
        _display_ferpa_report(report)
        if output:
            _save_ferpa_report(report, output)

    elif framework == "fedramp":
        # Get impact level from config or default to Moderate
        impact_level = config.get("compliance", {}).get("fedramp", {}).get("level", "Moderate")
        report = reporter.generate_fedramp_report(files, user_result.users, impact_level=impact_level)
        _display_fedramp_report(report)
        if output:
            _save_fedramp_report(report, output)


def _display_gdpr_report(report) -> None:
    """Display GDPR report."""
    score = report.calculate_compliance_score()
    score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print(Panel(
        f"[bold]GDPR Compliance Score: [{score_color}]{score}/100[/{score_color}][/bold]",
        title="GDPR Compliance Report",
        border_style="cyan",
    ))

    # Summary
    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="white")

    summary_table.add_row("Files Shared Outside EU", str(report.files_shared_outside_eu))
    summary_table.add_row("Files with PII Shared Externally", str(report.files_with_pii_shared_externally))
    summary_table.add_row("Users Without 2FA", str(report.users_without_2fa))
    summary_table.add_row("Inactive Users with Data Access", str(report.inactive_users_with_data_access))
    summary_table.add_row("Total Issues", str(len(report.issues)))

    console.print(summary_table)

    # Issues
    if report.issues:
        _display_issues(report.issues)


def _display_hipaa_report(report) -> None:
    """Display HIPAA report."""
    score = report.calculate_compliance_score()
    score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print(Panel(
        f"[bold]HIPAA Compliance Score: [{score_color}]{score}/100[/{score_color}][/bold]",
        title="HIPAA Compliance Report",
        border_style="cyan",
    ))

    # Summary
    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="white")

    summary_table.add_row("Files with PHI", str(report.files_with_phi))
    summary_table.add_row("Files with PHI Shared Externally", str(report.files_with_phi_shared_externally))
    summary_table.add_row("Files with PHI Publicly Shared", str(report.files_with_phi_publicly_shared))
    summary_table.add_row("Users Without 2FA", str(report.users_without_2fa))
    summary_table.add_row("Admin Users Without 2FA", str(report.admin_users_without_2fa))
    summary_table.add_row("Total Issues", str(len(report.issues)))

    console.print(summary_table)

    # Issues
    if report.issues:
        _display_issues(report.issues)


def _display_soc2_report(report) -> None:
    """Display SOC 2 report."""
    score = report.calculate_compliance_score()
    score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print(Panel(
        f"[bold]SOC 2 Compliance Score: [{score_color}]{score}/100[/{score_color}][/bold]",
        title="SOC 2 Compliance Report",
        border_style="cyan",
    ))

    # Summary
    summary_table = Table(title="Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Count", style="white")

    summary_table.add_row("Files Publicly Shared", str(report.files_publicly_shared))
    summary_table.add_row("Files Shared Externally", str(report.files_shared_externally))
    summary_table.add_row("Inactive Users", str(report.inactive_users))
    summary_table.add_row("Suspended Users", str(report.suspended_users))
    summary_table.add_row("Total Issues", str(len(report.issues)))

    console.print(summary_table)

    # Issues
    if report.issues:
        _display_issues(report.issues)


def _display_issues(issues) -> None:
    """Display compliance issues."""
    console.print("\n[bold yellow]⚠️  Compliance Issues:[/bold yellow]\n")

    issues_table = Table()
    issues_table.add_column("Severity", style="red")
    issues_table.add_column("Category", style="cyan")
    issues_table.add_column("Description", style="white")
    issues_table.add_column("Resource", style="dim")

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_issues = sorted(issues, key=lambda i: severity_order.get(i.severity, 4))

    for issue in sorted_issues[:20]:  # Show first 20
        severity_color = {
            "critical": "red",
            "high": "yellow",
            "medium": "blue",
            "low": "green",
        }.get(issue.severity, "white")

        issues_table.add_row(
            f"[{severity_color}]{issue.severity.upper()}[/{severity_color}]",
            issue.category,
            issue.description[:60],
            issue.affected_resource[:30],
        )

    console.print(issues_table)

    if len(sorted_issues) > 20:
        console.print(f"\n[dim]... and {len(sorted_issues) - 20} more issues[/dim]")


def _save_gdpr_report(report, output: Path) -> None:
    """Save GDPR report to file."""
    console.print(f"\n[cyan]Saving report to {output}...[/cyan]")

    data = {
        "framework": "GDPR",
        "report_time": report.report_time.isoformat(),
        "domain": report.domain,
        "compliance_score": report.calculate_compliance_score(),
        "summary": {
            "files_shared_outside_eu": report.files_shared_outside_eu,
            "files_with_pii_shared_externally": report.files_with_pii_shared_externally,
            "users_without_2fa": report.users_without_2fa,
            "inactive_users_with_data_access": report.inactive_users_with_data_access,
        },
        "issues": [
            {
                "severity": issue.severity,
                "category": issue.category,
                "description": issue.description,
                "recommendation": issue.recommendation,
                "affected_resource": issue.affected_resource,
                "resource_type": issue.resource_type,
            }
            for issue in report.issues
        ],
    }

    with open(output, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]✓ Report saved to {output}[/green]")


def _save_hipaa_report(report, output: Path) -> None:
    """Save HIPAA report to file."""
    console.print(f"\n[cyan]Saving report to {output}...[/cyan]")

    data = {
        "framework": "HIPAA",
        "report_time": report.report_time.isoformat(),
        "domain": report.domain,
        "compliance_score": report.calculate_compliance_score(),
        "summary": {
            "files_with_phi": report.files_with_phi,
            "files_with_phi_shared_externally": report.files_with_phi_shared_externally,
            "files_with_phi_publicly_shared": report.files_with_phi_publicly_shared,
            "users_without_2fa": report.users_without_2fa,
            "admin_users_without_2fa": report.admin_users_without_2fa,
        },
        "issues": [
            {
                "severity": issue.severity,
                "category": issue.category,
                "description": issue.description,
                "recommendation": issue.recommendation,
                "affected_resource": issue.affected_resource,
                "resource_type": issue.resource_type,
            }
            for issue in report.issues
        ],
    }

    with open(output, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]✓ Report saved to {output}[/green]")


def _save_soc2_report(report, output: Path) -> None:
    """Save SOC 2 report to file."""
    console.print(f"\n[cyan]Saving report to {output}...[/cyan]")

    data = {
        "framework": "SOC2",
        "report_time": report.report_time.isoformat(),
        "domain": report.domain,
        "compliance_score": report.calculate_compliance_score(),
        "summary": {
            "files_publicly_shared": report.files_publicly_shared,
            "files_shared_externally": report.files_shared_externally,
            "inactive_users": report.inactive_users,
            "suspended_users": report.suspended_users,
        },
        "issues": [
            {
                "severity": issue.severity,
                "category": issue.category,
                "description": issue.description,
                "recommendation": issue.recommendation,
                "affected_resource": issue.affected_resource,
                "resource_type": issue.resource_type,
            }
            for issue in report.issues
        ],
    }

    with open(output, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]✓ Report saved to {output}[/green]")


def _display_pcidss_report(report) -> None:
    """Display PCI-DSS report."""
    score = report.calculate_compliance_score()
    score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print(Panel(
        f"[bold]PCI-DSS Compliance Score: [{score_color}]{score}/100[/{score_color}][/bold]",
        title="PCI-DSS Compliance Report",
        border_style="cyan",
    ))

    # Summary table
    table = Table(title="Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="yellow")

    table.add_row("Files with Card Data", str(report.files_with_card_data))
    table.add_row("Card Data Shared Externally", str(report.files_with_card_data_shared_externally))
    table.add_row("Card Data Publicly Shared", str(report.files_with_card_data_publicly_shared))
    table.add_row("Users without 2FA", str(report.users_without_2fa))

    console.print(table)

    # Issues table
    if report.issues:
        console.print("\n[bold red]Issues Found:[/bold red]")
        issues_table = Table()
        issues_table.add_column("Severity", style="red")
        issues_table.add_column("Category", style="yellow")
        issues_table.add_column("Description", style="white")

        for issue in report.issues[:10]:  # Show first 10
            issues_table.add_row(
                issue.severity.upper(),
                issue.category,
                issue.description,
            )

        console.print(issues_table)

        if len(report.issues) > 10:
            console.print(f"\n[yellow]... and {len(report.issues) - 10} more issues[/yellow]")


def _save_pcidss_report(report, output: Path) -> None:
    """Save PCI-DSS report to file."""
    data = {
        "framework": "PCI-DSS",
        "report_time": report.report_time.isoformat(),
        "domain": report.domain,
        "compliance_score": report.calculate_compliance_score(),
        "summary": {
            "files_with_card_data": report.files_with_card_data,
            "files_with_card_data_shared_externally": report.files_with_card_data_shared_externally,
            "files_with_card_data_publicly_shared": report.files_with_card_data_publicly_shared,
            "users_without_2fa": report.users_without_2fa,
        },
        "issues": [
            {
                "severity": issue.severity,
                "category": issue.category,
                "description": issue.description,
                "recommendation": issue.recommendation,
                "affected_resource": issue.affected_resource,
                "resource_type": issue.resource_type,
            }
            for issue in report.issues
        ],
    }

    with open(output, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]✓ Report saved to {output}[/green]")


def _display_ferpa_report(report) -> None:
    """Display FERPA report."""
    score = report.calculate_compliance_score()
    score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print(Panel(
        f"[bold]FERPA Compliance Score: [{score_color}]{score}/100[/{score_color}][/bold]",
        title="FERPA Compliance Report",
        border_style="cyan",
    ))

    # Summary table
    table = Table(title="Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="yellow")

    table.add_row("Files with Student Data", str(report.files_with_student_data))
    table.add_row("Student Data Shared Externally", str(report.files_with_student_data_shared_externally))
    table.add_row("Student Data Publicly Shared", str(report.files_with_student_data_publicly_shared))
    table.add_row("Users without 2FA", str(report.users_without_2fa))
    table.add_row("Inactive Users with Access", str(report.inactive_users_with_student_data_access))

    console.print(table)

    # Issues table
    if report.issues:
        console.print("\n[bold red]Issues Found:[/bold red]")
        issues_table = Table()
        issues_table.add_column("Severity", style="red")
        issues_table.add_column("Category", style="yellow")
        issues_table.add_column("Description", style="white")

        for issue in report.issues[:10]:  # Show first 10
            issues_table.add_row(
                issue.severity.upper(),
                issue.category,
                issue.description,
            )

        console.print(issues_table)

        if len(report.issues) > 10:
            console.print(f"\n[yellow]... and {len(report.issues) - 10} more issues[/yellow]")


def _save_ferpa_report(report, output: Path) -> None:
    """Save FERPA report to file."""
    data = {
        "framework": "FERPA",
        "report_time": report.report_time.isoformat(),
        "domain": report.domain,
        "compliance_score": report.calculate_compliance_score(),
        "summary": {
            "files_with_student_data": report.files_with_student_data,
            "files_with_student_data_shared_externally": report.files_with_student_data_shared_externally,
            "files_with_student_data_publicly_shared": report.files_with_student_data_publicly_shared,
            "users_without_2fa": report.users_without_2fa,
            "inactive_users_with_student_data_access": report.inactive_users_with_student_data_access,
        },
        "issues": [
            {
                "severity": issue.severity,
                "category": issue.category,
                "description": issue.description,
                "recommendation": issue.recommendation,
                "affected_resource": issue.affected_resource,
                "resource_type": issue.resource_type,
            }
            for issue in report.issues
        ],
    }

    with open(output, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]✓ Report saved to {output}[/green]")


def _display_fedramp_report(report) -> None:
    """Display FedRAMP report."""
    score = report.calculate_compliance_score()
    score_color = "green" if score >= 80 else "yellow" if score >= 60 else "red"

    console.print(Panel(
        f"[bold]FedRAMP Compliance Score: [{score_color}]{score}/100[/{score_color}][/bold]\n"
        f"Impact Level: {report.impact_level}",
        title="FedRAMP Compliance Report",
        border_style="cyan",
    ))

    # Summary table
    table = Table(title="Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="yellow")

    table.add_row("Users without 2FA", str(report.users_without_2fa))
    table.add_row("Inactive Accounts", str(report.inactive_accounts))
    table.add_row("Files Shared Externally", str(report.files_shared_externally))
    table.add_row("Files Publicly Shared", str(report.files_publicly_shared))
    table.add_row("Sensitive Data Exposed", str(report.files_with_sensitive_data_exposed))

    console.print(table)

    # Issues table
    if report.issues:
        console.print("\n[bold red]Issues Found:[/bold red]")
        issues_table = Table()
        issues_table.add_column("Severity", style="red")
        issues_table.add_column("Category", style="yellow")
        issues_table.add_column("Description", style="white")

        for issue in report.issues[:10]:  # Show first 10
            issues_table.add_row(
                issue.severity.upper(),
                issue.category,
                issue.description,
            )

        console.print(issues_table)

        if len(report.issues) > 10:
            console.print(f"\n[yellow]... and {len(report.issues) - 10} more issues[/yellow]")


def _save_fedramp_report(report, output: Path) -> None:
    """Save FedRAMP report to file."""
    data = {
        "framework": "FedRAMP",
        "report_time": report.report_time.isoformat(),
        "domain": report.domain,
        "impact_level": report.impact_level,
        "compliance_score": report.calculate_compliance_score(),
        "summary": {
            "users_without_2fa": report.users_without_2fa,
            "inactive_accounts": report.inactive_accounts,
            "files_shared_externally": report.files_shared_externally,
            "files_publicly_shared": report.files_publicly_shared,
            "files_with_sensitive_data_exposed": report.files_with_sensitive_data_exposed,
        },
        "issues": [
            {
                "severity": issue.severity,
                "category": issue.category,
                "description": issue.description,
                "recommendation": issue.recommendation,
                "affected_resource": issue.affected_resource,
                "resource_type": issue.resource_type,
            }
            for issue in report.issues
        ],
    }

    with open(output, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]✓ Report saved to {output}[/green]")

