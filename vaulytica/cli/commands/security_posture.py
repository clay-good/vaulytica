"""Security Posture Assessment CLI commands."""

import json
from pathlib import Path
from typing import Optional

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress

from vaulytica.core.auth.client import GoogleWorkspaceClient
from vaulytica.core.security.posture_scanner import (
    PostureScanner,
    ComplianceFramework,
    FindingSeverity,
)

console = Console()


@click.group(name="security-posture")
def security_posture_group() -> None:
    """Security posture assessment and baseline scanning."""
    pass


@security_posture_group.command(name="assess")
@click.option(
    "--credentials",
    "-c",
    required=True,
    type=click.Path(exists=True),
    help="Path to service account credentials JSON file",
)
@click.option(
    "--admin-email",
    "-a",
    required=True,
    help="Google Workspace admin email for impersonation",
)
@click.option(
    "--domain",
    "-d",
    required=True,
    help="Google Workspace domain to assess",
)
@click.option(
    "--framework",
    "-f",
    multiple=True,
    type=click.Choice(
        [f.value for f in ComplianceFramework], case_sensitive=False
    ),
    help="Compliance frameworks to assess against (can specify multiple)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    help="Save assessment results to JSON file",
)
@click.option(
    "--show-passed",
    is_flag=True,
    help="Show passed checks in addition to failures",
)
@click.option(
    "--severity-filter",
    type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
    help="Only show findings of specified severity or higher",
)
def assess_security_posture(
    credentials: str,
    admin_email: str,
    domain: str,
    framework: tuple,
    output: Optional[Path],
    show_passed: bool,
    severity_filter: Optional[str],
) -> None:
    """Perform comprehensive security posture assessment.

    Example:
        vaulytica security-posture assess \\
            --credentials service-account.json \\
            --admin-email admin@example.com \\
            --domain example.com \\
            --framework cis --framework nist \\
            --output assessment.json
    """
    try:
        # Initialize client
        console.print("\n[cyan]Initializing Google Workspace client...[/cyan]")
        client = GoogleWorkspaceClient(
            credentials_path=credentials,
            admin_email=admin_email,
        )

        # Parse frameworks
        frameworks = None
        if framework:
            frameworks = [ComplianceFramework(f) for f in framework]

        # Initialize scanner
        scanner = PostureScanner(client=client, domain=domain)

        # Run assessment with progress bar
        console.print(
            f"\n[cyan]Running security posture assessment for {domain}...[/cyan]\n"
        )

        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=100)
            baseline = scanner.scan_security_posture(frameworks=frameworks)
            progress.update(task, completed=100)

        # Display summary panel
        score_color = (
            "green"
            if baseline.security_score >= 80
            else "yellow"
            if baseline.security_score >= 60
            else "red"
        )

        console.print(
            Panel(
                f"[bold]Security Score: [{score_color}]{baseline.security_score}/100[/{score_color}][/bold]\n\n"
                f"Total Checks: {baseline.total_checks}\n"
                f"Passed: [green]{baseline.passed_checks}[/green]\n"
                f"Failed: [red]{baseline.failed_checks}[/red]\n\n"
                f"[bold red]Critical:[/bold red] {baseline.critical_findings}\n"
                f"[bold yellow]High:[/bold yellow] {baseline.high_findings}\n"
                f"[bold blue]Medium:[/bold blue] {baseline.medium_findings}\n"
                f"[bold white]Low:[/bold white] {baseline.low_findings}\n\n"
                f"Scan Duration: {baseline.scan_duration_seconds:.2f}s",
                title=f"[bold cyan]Security Posture Assessment - {domain}[/bold cyan]",
                border_style="cyan",
            )
        )

        # Determine severity filter level
        severity_levels = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
        }
        min_severity = severity_levels.get(severity_filter.lower(), 0) if severity_filter else 0

        severity_map = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
            FindingSeverity.INFO: 0,
        }

        # Display findings
        findings_to_show = baseline.findings
        if not show_passed:
            findings_to_show = [f for f in findings_to_show if not f.passed]

        if severity_filter:
            findings_to_show = [
                f for f in findings_to_show
                if severity_map.get(f.severity, 0) >= min_severity
            ]

        # Group by severity
        critical_findings = [
            f for f in findings_to_show if f.severity == FindingSeverity.CRITICAL
        ]
        high_findings = [
            f for f in findings_to_show if f.severity == FindingSeverity.HIGH
        ]
        medium_findings = [
            f for f in findings_to_show if f.severity == FindingSeverity.MEDIUM
        ]
        low_findings = [
            f for f in findings_to_show if f.severity == FindingSeverity.LOW
        ]

        # Display critical findings
        if critical_findings:
            console.print("\n[bold red]🚨 CRITICAL FINDINGS:[/bold red]\n")
            for finding in critical_findings:
                _display_finding(finding)

        # Display high findings
        if high_findings:
            console.print("\n[bold yellow]⚠️  HIGH SEVERITY FINDINGS:[/bold yellow]\n")
            for finding in high_findings:
                _display_finding(finding)

        # Display medium findings
        if medium_findings:
            console.print("\n[bold blue]ℹ️  MEDIUM SEVERITY FINDINGS:[/bold blue]\n")
            for finding in medium_findings:
                _display_finding(finding)

        # Display low findings
        if low_findings:
            console.print("\n[bold white]📋 LOW SEVERITY FINDINGS:[/bold white]\n")
            for finding in low_findings:
                _display_finding(finding)

        # Display frameworks assessed
        if baseline.frameworks_assessed:
            console.print("\n[bold cyan]Compliance Frameworks Assessed:[/bold cyan]")
            for fw in baseline.frameworks_assessed:
                console.print(f"  • {fw.value.upper()}")

        # Save to file
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            with open(output, "w") as f:
                json.dump(baseline.to_dict(), f, indent=2)
            console.print(f"\n[green]✓[/green] Assessment saved to: {output}")

        # Exit with non-zero code if critical findings
        if baseline.critical_findings > 0:
            console.print(
                f"\n[red]⚠️  Found {baseline.critical_findings} CRITICAL security issues![/red]"
            )

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}", style="red")
        raise click.Abort() from e


@security_posture_group.command(name="summary")
@click.option(
    "--credentials",
    "-c",
    required=True,
    type=click.Path(exists=True),
    help="Path to service account credentials JSON file",
)
@click.option(
    "--admin-email",
    "-a",
    required=True,
    help="Google Workspace admin email for impersonation",
)
@click.option(
    "--domain",
    "-d",
    required=True,
    help="Google Workspace domain to assess",
)
def security_summary(credentials: str, admin_email: str, domain: str) -> None:
    """Quick security posture summary (critical and high severity only).

    Example:
        vaulytica security-posture summary \\
            --credentials service-account.json \\
            --admin-email admin@example.com \\
            --domain example.com
    """
    try:
        # Initialize client
        client = GoogleWorkspaceClient(
            credentials_path=credentials,
            admin_email=admin_email,
        )

        # Initialize scanner
        scanner = PostureScanner(client=client, domain=domain)

        # Run assessment
        console.print("\n[cyan]Running quick security assessment...[/cyan]\n")
        baseline = scanner.scan_security_posture()

        # Get critical and high findings
        critical = scanner.get_critical_findings()
        high = [
            f
            for f in scanner.get_failed_findings()
            if f.severity == FindingSeverity.HIGH
        ]

        # Display summary table
        table = Table(title=f"\n🔒 Security Summary - {domain}", box=box.ROUNDED)
        table.add_column("Check ID", style="cyan")
        table.add_column("Title", style="white")
        table.add_column("Severity", style="red")
        table.add_column("Status", style="red")

        for finding in critical:
            table.add_row(
                finding.check_id,
                finding.title,
                "CRITICAL",
                "❌ FAILED",
            )

        for finding in high:
            table.add_row(
                finding.check_id,
                finding.title,
                "HIGH",
                "❌ FAILED",
            )

        console.print(table)

        # Display score
        score_color = (
            "green"
            if baseline.security_score >= 80
            else "yellow"
            if baseline.security_score >= 60
            else "red"
        )
        console.print(
            f"\n[bold]Overall Security Score: [{score_color}]{baseline.security_score}/100[/{score_color}][/bold]"
        )

        if baseline.critical_findings == 0 and baseline.high_findings == 0:
            console.print(
                "\n[green]✓ No critical or high severity issues found![/green]"
            )

    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}", style="red")
        raise click.Abort() from e


@security_posture_group.command(name="frameworks")
def list_frameworks() -> None:
    """List available compliance frameworks.

    Example:
        vaulytica security-posture frameworks
    """
    table = Table(
        title="Available Compliance Frameworks", box=box.ROUNDED
    )
    table.add_column("Framework", style="cyan")
    table.add_column("Description", style="white")

    frameworks_info = [
        ("CIS", "CIS Google Workspace Benchmark - Industry security standard"),
        ("NIST", "NIST Cybersecurity Framework - Federal standard"),
        ("GOOGLE_BEST_PRACTICES", "Google's recommended security practices"),
        ("HIPAA", "Healthcare data protection requirements"),
        ("PCI_DSS", "Payment card industry security standards"),
        ("GDPR", "EU data protection regulation compliance"),
        ("SOC2", "Service organization control audit framework"),
    ]

    for framework, desc in frameworks_info:
        table.add_row(framework, desc)

    console.print(table)


def _display_finding(finding) -> None:
    """Display a single finding with details."""
    status_symbol = "✅" if finding.passed else "❌"
    severity_color = {
        FindingSeverity.CRITICAL: "red",
        FindingSeverity.HIGH: "yellow",
        FindingSeverity.MEDIUM: "blue",
        FindingSeverity.LOW: "white",
        FindingSeverity.INFO: "dim",
    }.get(finding.severity, "white")

    console.print(
        Panel(
            f"[bold]{status_symbol} {finding.title}[/bold]\n\n"
            f"{finding.description}\n\n"
            f"[bold]Current Value:[/bold] {finding.current_value}\n"
            f"[bold]Expected Value:[/bold] {finding.expected_value}\n\n"
            f"[bold]Impact:[/bold] {finding.impact}\n\n"
            f"[bold]Remediation:[/bold]\n{finding.remediation}",
            title=f"[{severity_color}]{finding.check_id} - {finding.severity.value.upper()}[/{severity_color}]",
            border_style=severity_color,
        )
    )
