"""Command-line interface for Vaulytica."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
import click
from vaulytica.config import load_config
from vaulytica.logger import setup_logger, get_logger
from vaulytica.validators import (
    validate_json_file,
    validate_output_path,
    validate_source_type,
    validate_directory,
    validate_pattern,
    ValidationError
)

logger = get_logger(__name__)
from vaulytica.parsers import (
    GuardDutyParser,
    GCPSecurityCommandCenterParser,
    DatadogParser,
    CrowdStrikeParser,
    SnowflakeParser
)
from vaulytica.agents import (
    SecurityAnalystAgent,
    IncidentResponseAgent,
    VulnerabilityManagementAgent,
    DetectionEngineeringAgent,
    BrandProtectionAgent,
    SecurityQuestionnaireAgent,
    AgentInput,
    AgentContext
)
from vaulytica.rag import IncidentRAG
from vaulytica.output import OutputFormatter
from vaulytica.html_report import HTMLReportGenerator
from vaulytica.cache import AnalysisCache
from vaulytica.batch import BatchProcessor


@click.group()
@click.version_option(version="0.30.0")
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--log-file', type=click.Path(path_type=Path), help='Log file path')
def cli(debug: bool, log_file: Optional[Path]) -> None:
    """Vaulytica: AI-powered security event analysis framework with deep learning, AutoML, interactive visualizations, incident management, automated forensics & investigation, threat hunting, SOAR, compliance, external threat intelligence, advanced automation, multi-platform ticketing (ServiceNow, Jira, PagerDuty, Datadog), Cloud Security Posture Management (CSPM), vulnerability management, Container Security & Kubernetes Security Posture Management (K8s SPM), IAM Security & Secrets Management, Zero Trust Architecture, Network Security, Data Loss Prevention (DLP), Encryption Management, API Security, Application Security Testing (AST), Security Automation, DevSecOps Integration, Security Orchestration, Advanced Threat Intelligence, Security Metrics & KPIs, Automated Penetration Testing, Supply Chain Security, SBOM Management, Security GRC, Security Posture Analytics, Continuous Monitoring, Predictive Security Intelligence, Attack Surface Management, Security Data Lake, Threat Modeling, and Incident Simulation."""
    import logging
    log_level = logging.DEBUG if debug else logging.INFO
    setup_logger(level=log_level, log_file=log_file)


def _validate_and_initialize(
    input_file: Path,
    source: str,
    api_key: Optional[str],
    output_json: Optional[Path],
    output_markdown: Optional[Path],
    output_html: Optional[Path]
):
    """Validate inputs and initialize configuration."""
    logger.info(f"Starting analysis of {input_file}")

    supported_sources = ['guardduty', 'gcp-scc', 'datadog', 'crowdstrike', 'snowflake']
    source = validate_source_type(source, supported_sources)

    raw_data = validate_json_file(input_file)

    if output_json:
        validate_output_path(output_json)
    if output_markdown:
        validate_output_path(output_markdown)
    if output_html:
        validate_output_path(output_html)

    config = load_config(api_key=api_key)

    return raw_data, source, config


def _parse_events(raw_data, source: str):
    """Parse events from raw data using appropriate parser."""
    parser_map = {
        'guardduty': GuardDutyParser(),
        'gcp-scc': GCPSecurityCommandCenterParser(),
        'datadog': DatadogParser(),
        'crowdstrike': CrowdStrikeParser(),
        'snowflake': SnowflakeParser()
    }

    parser = parser_map.get(source)
    if not parser:
        raise ValueError(f"Unsupported source: {source}")

    if isinstance(raw_data, list):
        events = [parser.parse(event) for event in raw_data]
    else:
        events = [parser.parse(raw_data)]

    logger.info(f"Successfully parsed {len(events)} event(s)")
    return events


def _get_cached_result(cache, event):
    """Try to get cached analysis result."""
    if not cache:
        return None

    try:
        cached_result = cache.get(event)
        if cached_result:
            click.secho("✓ Using cached analysis result", fg='yellow')
            logger.info("Using cached analysis result")
            return cached_result
    except Exception as e:
        click.secho(f"⚠ Cache error: {e}", fg='yellow')
        logger.warning(f"Cache error: {e}")

    return None


def _get_historical_context(enable_rag: bool, config, event):
    """Get historical context from RAG if enabled."""
    if not enable_rag:
        return None, None

    try:
        rag = IncidentRAG(config)
        historical_context = rag.find_similar_incidents(
            event,
            max_results=config.max_historical_incidents
        )
        if historical_context:
            click.secho(f"✓ Found {len(historical_context)} similar historical incident(s)", fg='blue')
            logger.info(f"Found {len(historical_context)} similar incidents")
        return rag, historical_context
    except Exception as e:
        click.secho(f"⚠ RAG warning: {e}", fg='yellow')
        logger.warning(f"RAG error: {e}")
        return None, None


def _perform_analysis(config, events, historical_context):
    """Perform AI analysis on events."""
    agent = SecurityAnalystAgent(config)

    click.secho("⚙ Analyzing with AI security analyst...", fg='cyan')
    logger.info("Starting AI analysis")

    result = asyncio.run(agent.analyze(events, historical_context))
    logger.info(f"Analysis complete - Risk: {result.risk_score:.1f}/10")

    return result


def _cache_and_store_result(cache, rag, event, result, store_result: bool):
    """Cache and store analysis result."""
    if cache:
        try:
            cache.set(event, result)
            logger.debug("Analysis cached")
        except Exception as e:
            logger.warning(f"Failed to cache result: {e}")

    if store_result and rag:
        try:
            rag.store_incident(event, result)
            click.secho("✓ Analysis stored in RAG database", fg='green')
            logger.info("Analysis stored in RAG database")
        except Exception as e:
            click.secho(f"⚠ Failed to store in RAG: {e}", fg='yellow')
            logger.warning(f"Failed to store in RAG: {e}")


def _generate_reports(config, event, result, output_json, output_markdown, output_html):
    """Generate output reports."""
    formatter = OutputFormatter()
    html_gen = HTMLReportGenerator()

    if not output_json and not output_markdown and not output_html:
        output_json = config.output_dir / f"{result.event_id}_analysis.json"
        output_markdown = config.output_dir / f"{result.event_id}_analysis.md"
        output_html = config.output_dir / f"{result.event_id}_analysis.html"

    click.echo()
    click.secho("📊 Generating Reports:", fg='cyan', bold=True)

    if output_json:
        formatter.save_json(event, result, output_json)
        click.secho(f"  ✓ JSON: {output_json}", fg='green')
        logger.info(f"JSON report saved to {output_json}")

    if output_markdown:
        formatter.save_markdown(event, result, output_markdown)
        click.secho(f"  ✓ Markdown: {output_markdown}", fg='green')
        logger.info(f"Markdown report saved to {output_markdown}")

    if output_html:
        html_gen.generate(event, result, output_html)
        click.secho(f"  ✓ HTML: {output_html}", fg='green')
        logger.info(f"HTML report saved to {output_html}")


def _display_results(result):
    """Display analysis results."""
    click.echo()
    click.secho(f"{'='*60}", fg='cyan')
    risk_color = 'red' if result.risk_score >= 7 else 'yellow' if result.risk_score >= 4 else 'green'
    click.secho(f"  Risk Score: {result.risk_score:.1f}/10", fg=risk_color, bold=True)
    click.secho(f"  Confidence: {int(result.confidence*100)}%", fg='blue')
    click.secho(f"  Processing Time: {result.processing_time_seconds:.2f}s", fg='white')
    click.secho(f"{'='*60}\n", fg='cyan')


@cli.command()
@click.argument('input_file', type=click.Path(exists=True, path_type=Path))
@click.option('--source',
              type=click.Choice(['guardduty', 'gcp-scc', 'datadog', 'crowdstrike', 'snowflake']),
              required=True,
              help='Source system type')
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--output-json', type=click.Path(path_type=Path), help='Save JSON output to file')
@click.option('--output-markdown', type=click.Path(path_type=Path), help='Save Markdown output to file')
@click.option('--output-html', type=click.Path(path_type=Path), help='Save HTML output to file')
@click.option('--enable-rag/--no-rag', default=True, help='Enable historical incident correlation')
@click.option('--enable-cache/--no-cache', default=True, help='Enable analysis caching')
@click.option('--store-result/--no-store', default=True, help='Store result in RAG database')
def analyze(
    input_file: Path,
    source: str,
    api_key: Optional[str],
    output_json: Optional[Path],
    output_markdown: Optional[Path],
    output_html: Optional[Path],
    enable_rag: bool,
    enable_cache: bool,
    store_result: bool
) -> None:
    """Analyze security events from input file."""

    # Validate and initialize
    try:
        raw_data, source, config = _validate_and_initialize(
            input_file, source, api_key, output_json, output_markdown, output_html
        )
    except ValidationError as e:
        click.secho(f"✗ Validation error: {e}", fg='red', bold=True)
        logger.error(f"Validation error: {e}")
        sys.exit(1)
    except ValueError as e:
        click.secho(f"✗ Configuration error: {e}", fg='red', bold=True)
        click.echo("  Set ANTHROPIC_API_KEY environment variable or use --api-key option")
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        click.secho(f"✗ Unexpected error: {e}", fg='red', bold=True)
        logger.exception("Unexpected error during initialization")
        sys.exit(1)

    # Display header
    click.secho(f"\n{'='*60}", fg='cyan')
    click.secho("  VAULYTICA SECURITY ANALYST", fg='cyan', bold=True)
    click.secho(f"{'='*60}\n", fg='cyan')

    # Parse events
    try:
        events = _parse_events(raw_data, source)
        click.secho(f"✓ Parsed {len(events)} event(s) from {source}", fg='green')
    except Exception as e:
        click.secho(f"✗ Parsing error: {e}", fg='red')
        logger.exception("Parsing error")
        sys.exit(1)

    # Perform analysis
    try:
        cache = AnalysisCache(config) if enable_cache else None

        # Try cache first
        result = _get_cached_result(cache, events[0])

        # If not cached, perform analysis
        if not result:
            rag, historical_context = _get_historical_context(enable_rag, config, events[0])

            try:
                result = _perform_analysis(config, events, historical_context)
            except Exception as e:
                click.secho(f"✗ Analysis error: {e}", fg='red')
                logger.exception("Analysis error")
                sys.exit(1)

            _cache_and_store_result(cache, rag, events[0], result, store_result)

    except Exception as e:
        click.secho(f"✗ Analysis failed: {e}", fg='red')
        logger.exception("Analysis failed")
        sys.exit(1)

    # Generate reports
    try:
        _generate_reports(config, events[0], result, output_json, output_markdown, output_html)
    except Exception as e:
        click.secho(f"✗ Error generating reports: {e}", fg='red')
        logger.exception("Error generating reports")
        sys.exit(1)

    # Display results
    _display_results(result)


@cli.command()
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--metrics', is_flag=True, help='Show metrics instead of stats')
def stats(api_key: Optional[str], metrics: bool) -> None:
    """Show system statistics and metrics."""

    try:
        config = load_config(api_key=api_key)
    except ValueError as e:
        click.echo(f"Configuration error: {e}")
        return

    try:
        if metrics:
            # Show metrics from metrics collector
            from vaulytica.metrics import get_metrics_collector
            metrics_collector = get_metrics_collector()
            metrics_data = metrics_collector.get_summary()

            click.echo("\n=== Vaulytica Metrics ===\n")

            click.echo("Analysis:")
            click.echo(f"  Total analyses: {metrics_data['analysis']['total_analyses']}")
            click.echo(f"  Errors: {metrics_data['analysis']['errors']} ({metrics_data['analysis']['error_rate']:.1f}%)")
            click.echo(f"  By platform: {metrics_data['analysis']['by_platform']}")

            click.echo("\nCache:")
            click.echo(f"  Hits: {metrics_data['cache']['hits']}")
            click.echo(f"  Misses: {metrics_data['cache']['misses']}")
            click.echo(f"  Hit rate: {metrics_data['cache']['hit_rate_percent']:.1f}%")

            click.echo("\nPerformance:")
            click.echo(f"  Avg latency: {metrics_data['performance']['avg_latency_seconds']}s")
            click.echo(f"  P95 latency: {metrics_data['performance']['p95_latency_seconds']}s")
            click.echo(f"  P99 latency: {metrics_data['performance']['p99_latency_seconds']}s")

            click.echo("\nCost:")
            click.echo(f"  Total tokens: {metrics_data['cost']['total_tokens']:,}")
            click.echo(f"  Total cost: ${metrics_data['cost']['total_cost_usd']}")
            click.echo(f"  Avg tokens/analysis: {metrics_data['cost']['avg_tokens_per_analysis']}")

            click.echo("\nRisk:")
            click.echo(f"  Average risk score: {metrics_data['risk']['average_risk_score']}")
            click.echo(f"  High-risk events: {metrics_data['risk']['high_risk_events']}")
            click.echo(f"  Medium-risk events: {metrics_data['risk']['medium_risk_events']}")
            click.echo(f"  Low-risk events: {metrics_data['risk']['low_risk_events']}")

            if metrics_data['threats']['top_mitre_techniques']:
                click.echo("\nTop MITRE ATT&CK Techniques:")
                for technique, count in metrics_data['threats']['top_mitre_techniques'][:5]:
                    click.echo(f"  {technique}: {count}")

            click.echo()
        else:
            # Show traditional stats
            rag = IncidentRAG(config)
            rag_stats = rag.get_collection_stats()

            cache = AnalysisCache(config)
            cache_stats = cache.get_stats()

            click.echo("\n=== Vaulytica System Statistics ===\n")
            click.echo("RAG Database:")
            click.echo(f"  Total incidents: {rag_stats['total_incidents']}")
            click.echo(f"  Collection: {rag_stats['collection_name']}")
            click.echo("\nCache:")
            click.echo(f"  Total entries: {cache_stats['total_entries']}")
            click.echo(f"  Total size: {cache_stats['total_size_mb']} MB")
            click.echo(f"  TTL: {cache_stats['ttl_hours']} hours")
            click.echo(f"  Cache directory: {cache_stats['cache_dir']}\n")

    except Exception as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.argument('directory', type=click.Path(exists=True, path_type=Path))
@click.option('--source',
              type=click.Choice(['guardduty', 'gcp-scc', 'datadog', 'crowdstrike', 'snowflake']),
              required=True,
              help='Source system type')
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--pattern', default='*.json', help='File pattern to match')
@click.option('--output-report', type=click.Path(path_type=Path), help='Batch report output path')
@click.option('--enable-cache/--no-cache', default=True, help='Enable analysis caching')
def batch(
    directory: Path,
    source: str,
    api_key: Optional[str],
    pattern: str,
    output_report: Optional[Path],
    enable_cache: bool
) -> None:
    """Batch process multiple security events from a directory."""

    try:
        logger.info(f"Starting batch processing of {directory}")

        supported_sources = ['guardduty', 'gcp-scc', 'datadog', 'crowdstrike', 'snowflake']
        source = validate_source_type(source, supported_sources)
        validate_directory(directory, must_exist=True)
        validate_pattern(pattern)

        if output_report:
            validate_output_path(output_report)

        config = load_config(api_key=api_key)

    except ValidationError as e:
        click.secho(f"✗ Validation error: {e}", fg='red')
        logger.error(f"Validation error: {e}")
        sys.exit(1)
    except ValueError as e:
        click.secho(f"✗ Configuration error: {e}", fg='red')
        logger.error(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        click.secho(f"✗ Unexpected error: {e}", fg='red')
        logger.exception("Unexpected error during batch initialization")
        sys.exit(1)

    parser_map = {
        'guardduty': GuardDutyParser(),
        'gcp-scc': GCPSecurityCommandCenterParser(),
        'datadog': DatadogParser(),
        'crowdstrike': CrowdStrikeParser(),
        'snowflake': SnowflakeParser()
    }

    parser = parser_map.get(source)
    if not parser:
        click.secho(f"✗ Unsupported source: {source}", fg='red')
        logger.error(f"Unsupported source: {source}")
        sys.exit(1)

    processor = BatchProcessor(config)

    click.secho(f"\n⚙ Processing events from {directory} with pattern {pattern}...", fg='cyan')

    try:
        result = processor.process_directory(
            directory,
            parser,
            pattern=pattern,
            use_cache=enable_cache
        )

        summary = result["summary"]
        click.echo()
        click.secho("✓ Batch processing complete:", fg='green', bold=True)
        click.echo(f"  Total events: {summary['total_events']}")
        click.echo(f"  Successful: {summary['successful']}")
        click.echo(f"  Failed: {summary['failed']}")
        click.secho(f"  Cache hits: {summary['cache_hits']}", fg='yellow')
        click.secho(f"  Cache misses: {summary['cache_misses']}", fg='blue')
        click.echo(f"  Processing time: {summary['processing_time_seconds']:.2f}s")

        logger.info(f"Batch processing complete: {summary['successful']}/{summary['total_events']} successful")

        if not output_report:
            output_report = config.output_dir / "batch_report.json"

        processor.generate_batch_report(result, output_report)
        click.echo(f"\nBatch report saved to {output_report}")
        logger.info(f"Batch report saved to {output_report}")

    except Exception as e:
        click.secho(f"✗ Batch processing error: {e}", fg='red')
        logger.exception("Batch processing error")
        sys.exit(1)


@cli.command()
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--clear-cache', is_flag=True, help='Clear analysis cache')
@click.option('--clear-expired', is_flag=True, help='Clear expired cache entries only')
def clear(api_key: Optional[str], clear_cache: bool, clear_expired: bool) -> None:
    """Clear cached data."""

    try:
        config = load_config(api_key=api_key)
    except ValueError as e:
        click.echo(f"Configuration error: {e}")
        return

    cache = AnalysisCache(config)

    if clear_expired:
        cleared = cache.clear_expired()
        click.echo(f"Cleared {cleared} expired cache entries")
    elif clear_cache:
        cleared = cache.clear_all()
        click.echo(f"Cleared {cleared} cache entries")
    else:
        click.echo("Specify --clear-cache or --clear-expired")


@cli.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8000, type=int, help='Port to bind to')
@click.option('--reload', is_flag=True, help='Enable auto-reload for development')
@click.option('--workers', default=1, type=int, help='Number of worker processes')
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
def serve(host: str, port: int, reload: bool, workers: int, api_key: Optional[str]) -> None:
    """Start REST API server for SOAR integration."""

    try:
        # Validate configuration
        config = load_config(api_key=api_key)
        click.secho("✓ Configuration validated", fg='green')

    except ValueError as e:
        click.secho(f"✗ Configuration error: {e}", fg='red', bold=True)
        click.echo("  Set ANTHROPIC_API_KEY environment variable or use --api-key option")
        sys.exit(1)

    try:
        import uvicorn
    except ImportError:
        click.secho("✗ FastAPI/Uvicorn not installed", fg='red', bold=True)
        click.echo("  Install with: pip install 'fastapi>=0.104.0' 'uvicorn[standard]>=0.24.0'")
        sys.exit(1)

    click.echo("")
    click.secho("============================================================", fg='cyan', bold=True)
    click.secho("  VAULYTICA API SERVER", fg='cyan', bold=True)
    click.secho("============================================================", fg='cyan', bold=True)
    click.echo("")
    click.echo(f"  Host: {host}")
    click.echo(f"  Port: {port}")
    click.echo(f"  Workers: {workers}")
    click.echo(f"  Reload: {reload}")
    click.echo("")
    click.echo(f"  API Documentation: http://{host}:{port}/docs")
    click.echo(f"  Health Check: http://{host}:{port}/health")
    click.echo("")
    click.secho("============================================================", fg='cyan', bold=True)
    click.echo("")

    # Start server
    uvicorn.run(
        "vaulytica.api:app",
        host=host,
        port=port,
        reload=reload,
        workers=workers if not reload else 1,
        log_level="info"
    )


@cli.command(name='incident-response')
@click.argument('incident_file', type=click.Path(exists=True, path_type=Path))
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--output', type=click.Path(path_type=Path), help='Output file path')
def incident_response(incident_file: Path, api_key: Optional[str], output: Optional[Path]) -> None:
    """Run incident response agent on incident data."""

    try:
        config = load_config(api_key=api_key)
        agent = IncidentResponseAgent()

        click.secho("\n=== INCIDENT RESPONSE AGENT ===\n", fg='cyan', bold=True)

        # Load incident data
        with open(incident_file, 'r') as f:
            incident_data = json.load(f)

        # Create agent input
        agent_input = AgentInput(
            task="respond_to_incident",
            context=AgentContext(
                incident_id=incident_data.get('incident_id', 'INC-001'),
                workflow_id="CLI-WORKFLOW"
            ),
            parameters=incident_data
        )

        # Execute agent
        click.secho("⚙ Analyzing incident and generating response plan...", fg='cyan')
        result = asyncio.run(agent.execute(agent_input))

        # Display results
        click.secho(f"\n✓ Incident Response Complete", fg='green', bold=True)
        click.echo(f"  Status: {result.status}")
        click.echo(f"  Execution Time: {result.execution_time:.2f}s")

        # Save output
        if output:
            with open(output, 'w') as f:
                json.dump(result.data, f, indent=2, default=str)
            click.secho(f"\n✓ Results saved to {output}", fg='green')
        else:
            click.echo(f"\nResults:\n{json.dumps(result.data, indent=2, default=str)}")

    except Exception as e:
        click.secho(f"✗ Error: {e}", fg='red')
        logger.exception("Incident response error")
        sys.exit(1)


@cli.command(name='vuln-management')
@click.argument('vuln_file', type=click.Path(exists=True, path_type=Path))
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--output', type=click.Path(path_type=Path), help='Output file path')
def vuln_management(vuln_file: Path, api_key: Optional[str], output: Optional[Path]) -> None:
    """Run vulnerability management agent on vulnerability data."""

    try:
        config = load_config(api_key=api_key)
        agent = VulnerabilityManagementAgent()

        click.secho("\n=== VULNERABILITY MANAGEMENT AGENT ===\n", fg='cyan', bold=True)

        # Load vulnerability data
        with open(vuln_file, 'r') as f:
            vuln_data = json.load(f)

        # Create agent input
        agent_input = AgentInput(
            task="analyze_vulnerability",
            context=AgentContext(
                incident_id=vuln_data.get('vuln_id', 'VULN-001'),
                workflow_id="CLI-WORKFLOW"
            ),
            parameters=vuln_data
        )

        # Execute agent
        click.secho("⚙ Analyzing vulnerability and generating remediation plan...", fg='cyan')
        result = asyncio.run(agent.execute(agent_input))

        # Display results
        click.secho(f"\n✓ Vulnerability Analysis Complete", fg='green', bold=True)
        click.echo(f"  Status: {result.status}")
        click.echo(f"  Execution Time: {result.execution_time:.2f}s")

        # Save output
        if output:
            with open(output, 'w') as f:
                json.dump(result.data, f, indent=2, default=str)
            click.secho(f"\n✓ Results saved to {output}", fg='green')
        else:
            click.echo(f"\nResults:\n{json.dumps(result.data, indent=2, default=str)}")

    except Exception as e:
        click.secho(f"✗ Error: {e}", fg='red')
        logger.exception("Vulnerability management error")
        sys.exit(1)


@cli.command(name='detection-engineering')
@click.argument('detection_file', type=click.Path(exists=True, path_type=Path))
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--output', type=click.Path(path_type=Path), help='Output file path')
def detection_engineering(detection_file: Path, api_key: Optional[str], output: Optional[Path]) -> None:
    """Run detection engineering agent for detection tuning."""

    try:
        config = load_config(api_key=api_key)
        agent = DetectionEngineeringAgent()

        click.secho("\n=== DETECTION ENGINEERING AGENT ===\n", fg='cyan', bold=True)

        # Load detection data
        with open(detection_file, 'r') as f:
            detection_data = json.load(f)

        # Create agent input
        agent_input = AgentInput(
            task="tune_detection",
            context=AgentContext(
                incident_id=detection_data.get('detection_id', 'DET-001'),
                workflow_id="CLI-WORKFLOW"
            ),
            parameters=detection_data
        )

        # Execute agent
        click.secho("⚙ Analyzing detection and generating tuning recommendations...", fg='cyan')
        result = asyncio.run(agent.execute(agent_input))

        # Display results
        click.secho(f"\n✓ Detection Analysis Complete", fg='green', bold=True)
        click.echo(f"  Status: {result.status}")
        click.echo(f"  Execution Time: {result.execution_time:.2f}s")

        # Save output
        if output:
            with open(output, 'w') as f:
                json.dump(result.data, f, indent=2, default=str)
            click.secho(f"\n✓ Results saved to {output}", fg='green')
        else:
            click.echo(f"\nResults:\n{json.dumps(result.data, indent=2, default=str)}")

    except Exception as e:
        click.secho(f"✗ Error: {e}", fg='red')
        logger.exception("Detection engineering error")
        sys.exit(1)


@cli.command(name='brand-protection')
@click.option('--domain', required=True, help='Domain to protect')
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--output', type=click.Path(path_type=Path), help='Output file path')
def brand_protection(domain: str, api_key: Optional[str], output: Optional[Path]) -> None:
    """Run brand protection agent for domain monitoring."""

    try:
        config = load_config(api_key=api_key)
        agent = BrandProtectionAgent()

        click.secho("\n=== BRAND PROTECTION AGENT ===\n", fg='cyan', bold=True)

        # Create agent input
        agent_input = AgentInput(
            task="generate_permutations",
            context=AgentContext(
                incident_id=f"BRAND-{domain}",
                workflow_id="CLI-WORKFLOW"
            ),
            parameters={"domain": domain}
        )

        # Execute agent
        click.secho(f"⚙ Generating domain permutations for {domain}...", fg='cyan')
        result = asyncio.run(agent.execute(agent_input))

        # Display results
        click.secho(f"\n✓ Brand Protection Analysis Complete", fg='green', bold=True)
        click.echo(f"  Status: {result.status}")
        click.echo(f"  Execution Time: {result.execution_time:.2f}s")

        # Save output
        if output:
            with open(output, 'w') as f:
                json.dump(result.data, f, indent=2, default=str)
            click.secho(f"\n✓ Results saved to {output}", fg='green')
        else:
            click.echo(f"\nResults:\n{json.dumps(result.data, indent=2, default=str)}")

    except Exception as e:
        click.secho(f"✗ Error: {e}", fg='red')
        logger.exception("Brand protection error")
        sys.exit(1)


@cli.command(name='security-questionnaire')
@click.argument('questionnaire_file', type=click.Path(exists=True, path_type=Path))
@click.option('--documents-dir', type=click.Path(exists=True, path_type=Path), help='Directory with security documents')
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--output', type=click.Path(path_type=Path), help='Output file path')
def security_questionnaire(questionnaire_file: Path, documents_dir: Optional[Path], api_key: Optional[str], output: Optional[Path]) -> None:
    """Run security questionnaire agent to answer questionnaires."""

    try:
        config = load_config(api_key=api_key)
        agent = SecurityQuestionnaireAgent()

        click.secho("\n=== SECURITY QUESTIONNAIRE AGENT ===\n", fg='cyan', bold=True)

        # Load questionnaire
        with open(questionnaire_file, 'r') as f:
            if questionnaire_file.suffix == '.json':
                questionnaire_data = json.load(f)
            else:
                questionnaire_data = {"file": str(questionnaire_file)}

        # Create agent input
        agent_input = AgentInput(
            task="answer_questionnaire",
            context=AgentContext(
                incident_id=f"QUEST-{questionnaire_file.stem}",
                workflow_id="CLI-WORKFLOW"
            ),
            parameters={
                "questionnaire": questionnaire_data,
                "documents_dir": str(documents_dir) if documents_dir else None
            }
        )

        # Execute agent
        click.secho("⚙ Processing questionnaire...", fg='cyan')
        result = asyncio.run(agent.execute(agent_input))

        # Display results
        click.secho(f"\n✓ Questionnaire Processing Complete", fg='green', bold=True)
        click.echo(f"  Status: {result.status}")
        click.echo(f"  Execution Time: {result.execution_time:.2f}s")

        # Save output
        if output:
            with open(output, 'w') as f:
                json.dump(result.data, f, indent=2, default=str)
            click.secho(f"\n✓ Results saved to {output}", fg='green')
        else:
            click.echo(f"\nResults:\n{json.dumps(result.data, indent=2, default=str)}")

    except Exception as e:
        click.secho(f"✗ Error: {e}", fg='red')
        logger.exception("Security questionnaire error")
        sys.exit(1)


@cli.command(name='list-agents')
def list_agents() -> None:
    """List all available AI agents and their capabilities."""

    click.secho("\n=== VAULYTICA AI AGENTS ===\n", fg='cyan', bold=True)

    agents_info = [
        {
            "name": "Security Analysis Agent",
            "command": "analyze",
            "description": "Analyze security events from SIEM platforms",
            "capabilities": ["Threat analysis", "Risk scoring", "MITRE ATT&CK mapping"]
        },
        {
            "name": "Incident Response Agent",
            "command": "incident-response",
            "description": "Automated incident response and containment",
            "capabilities": ["Incident triage", "Containment actions", "Response playbooks"]
        },
        {
            "name": "Vulnerability Management Agent",
            "command": "vuln-management",
            "description": "Vulnerability analysis and remediation planning",
            "capabilities": ["Vulnerability prioritization", "Remediation plans", "SBOM analysis"]
        },
        {
            "name": "Detection Engineering Agent",
            "command": "detection-engineering",
            "description": "Detection tuning and false positive reduction",
            "capabilities": ["FP pattern recognition", "Detection tuning", "A/B testing"]
        },
        {
            "name": "Brand Protection Agent",
            "command": "brand-protection",
            "description": "Domain monitoring and takedown coordination",
            "capabilities": ["Domain permutations", "Threat validation", "Takedown tracking"]
        },
        {
            "name": "Security Questionnaire Agent",
            "command": "security-questionnaire",
            "description": "Automated security questionnaire completion",
            "capabilities": ["Document ingestion", "RAG-based answers", "Response library"]
        }
    ]

    for agent in agents_info:
        click.secho(f"{agent['name']}", fg='green', bold=True)
        click.echo(f"  Command: vaulytica {agent['command']}")
        click.echo(f"  Description: {agent['description']}")
        click.echo(f"  Capabilities:")
        for cap in agent['capabilities']:
            click.echo(f"    - {cap}")
        click.echo()

    click.secho("Use 'vaulytica <command> --help' for more information on each agent.\n", fg='yellow')


if __name__ == '__main__':
    cli()
