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
from vaulytica.agents import SecurityAnalystAgent
from vaulytica.rag import IncidentRAG
from vaulytica.output import OutputFormatter
from vaulytica.html_report import HTMLReportGenerator
from vaulytica.cache import AnalysisCache
from vaulytica.batch import BatchProcessor


@click.group()
@click.version_option(version="0.30.0")
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--log-file', type=click.Path(path_type=Path), help='Log file path')
def cli(debug: bool, log_file: Optional[Path]):
    """Vaulytica: AI-powered security event analysis framework with deep learning, AutoML, interactive visualizations, incident management, automated forensics & investigation, threat hunting, SOAR, compliance, external threat intelligence, advanced automation, multi-platform ticketing (ServiceNow, Jira, PagerDuty, Datadog), Cloud Security Posture Management (CSPM), vulnerability management, Container Security & Kubernetes Security Posture Management (K8s SPM), IAM Security & Secrets Management, Zero Trust Architecture, Network Security, Data Loss Prevention (DLP), Encryption Management, API Security, Application Security Testing (AST), Security Automation, DevSecOps Integration, Security Orchestration, Advanced Threat Intelligence, Security Metrics & KPIs, Automated Penetration Testing, Supply Chain Security, SBOM Management, Security GRC, Security Posture Analytics, Continuous Monitoring, Predictive Security Intelligence, Attack Surface Management, Security Data Lake, Threat Modeling, and Incident Simulation."""
    import logging
    log_level = logging.DEBUG if debug else logging.INFO
    setup_logger(level=log_level, log_file=log_file)


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
):
    """Analyze security events from input file."""

    try:
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

    click.secho(f"\n{'='*60}", fg='cyan')
    click.secho("  VAULYTICA SECURITY ANALYST", fg='cyan', bold=True)
    click.secho(f"{'='*60}\n", fg='cyan')

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

    try:
        if isinstance(raw_data, list):
            events = [parser.parse(event) for event in raw_data]
        else:
            events = [parser.parse(raw_data)]
        logger.info(f"Successfully parsed {len(events)} event(s)")
    except Exception as e:
        click.secho(f"✗ Parsing error: {e}", fg='red')
        logger.exception("Parsing error")
        sys.exit(1)

    click.secho(f"✓ Parsed {len(events)} event(s) from {source}", fg='green')
    
    try:
        cache = AnalysisCache(config) if enable_cache else None
        cached_result = None

        if cache:
            try:
                cached_result = cache.get(events[0])
                if cached_result:
                    click.secho("✓ Using cached analysis result", fg='yellow')
                    logger.info("Using cached analysis result")
                    result = cached_result
            except Exception as e:
                click.secho(f"⚠ Cache error: {e}", fg='yellow')
                logger.warning(f"Cache error: {e}")

        if not cached_result:
            rag = None
            historical_context = None

            if enable_rag:
                try:
                    rag = IncidentRAG(config)
                    historical_context = rag.find_similar_incidents(
                        events[0],
                        max_results=config.max_historical_incidents
                    )
                    if historical_context:
                        click.secho(f"✓ Found {len(historical_context)} similar historical incident(s)", fg='blue')
                        logger.info(f"Found {len(historical_context)} similar incidents")
                except Exception as e:
                    click.secho(f"⚠ RAG warning: {e}", fg='yellow')
                    logger.warning(f"RAG error: {e}")

            agent = SecurityAnalystAgent(config)

            click.secho("⚙ Analyzing with AI security analyst...", fg='cyan')
            logger.info("Starting AI analysis")

            try:
                result = asyncio.run(agent.analyze(events, historical_context))
                logger.info(f"Analysis complete - Risk: {result.risk_score:.1f}/10")
            except Exception as e:
                click.secho(f"✗ Analysis error: {e}", fg='red')
                logger.exception("Analysis error")
                sys.exit(1)

            if cache:
                try:
                    cache.set(events[0], result)
                    logger.debug("Analysis cached")
                except Exception as e:
                    logger.warning(f"Failed to cache result: {e}")

            if store_result and rag:
                try:
                    rag.store_incident(events[0], result)
                    click.secho("✓ Analysis stored in RAG database", fg='green')
                    logger.info("Analysis stored in RAG database")
                except Exception as e:
                    click.secho(f"⚠ Failed to store in RAG: {e}", fg='yellow')
                    logger.warning(f"Failed to store in RAG: {e}")

    except Exception as e:
        click.secho(f"✗ Analysis failed: {e}", fg='red')
        logger.exception("Analysis failed")
        sys.exit(1)

    try:
        formatter = OutputFormatter()
        html_gen = HTMLReportGenerator()

        if not output_json and not output_markdown and not output_html:
            output_json = config.output_dir / f"{result.event_id}_analysis.json"
            output_markdown = config.output_dir / f"{result.event_id}_analysis.md"
            output_html = config.output_dir / f"{result.event_id}_analysis.html"

        click.echo()
        click.secho("📊 Generating Reports:", fg='cyan', bold=True)

        if output_json:
            formatter.save_json(events[0], result, output_json)
            click.secho(f"  ✓ JSON: {output_json}", fg='green')
            logger.info(f"JSON report saved to {output_json}")

        if output_markdown:
            formatter.save_markdown(events[0], result, output_markdown)
            click.secho(f"  ✓ Markdown: {output_markdown}", fg='green')
            logger.info(f"Markdown report saved to {output_markdown}")

        if output_html:
            html_gen.generate(events[0], result, output_html)
            click.secho(f"  ✓ HTML: {output_html}", fg='green')
            logger.info(f"HTML report saved to {output_html}")

    except Exception as e:
        click.secho(f"✗ Error generating reports: {e}", fg='red')
        logger.exception("Error generating reports")
        sys.exit(1)

    click.echo()
    click.secho(f"{'='*60}", fg='cyan')
    risk_color = 'red' if result.risk_score >= 7 else 'yellow' if result.risk_score >= 4 else 'green'
    click.secho(f"  Risk Score: {result.risk_score:.1f}/10", fg=risk_color, bold=True)
    click.secho(f"  Confidence: {int(result.confidence*100)}%", fg='blue')
    click.secho(f"  Processing Time: {result.processing_time_seconds:.2f}s", fg='white')
    click.secho(f"{'='*60}\n", fg='cyan')


@cli.command()
@click.option('--api-key', envvar='ANTHROPIC_API_KEY', help='Anthropic API key')
@click.option('--metrics', is_flag=True, help='Show metrics instead of stats')
def stats(api_key: Optional[str], metrics: bool):
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
            click.echo(f"RAG Database:")
            click.echo(f"  Total incidents: {rag_stats['total_incidents']}")
            click.echo(f"  Collection: {rag_stats['collection_name']}")
            click.echo(f"\nCache:")
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
):
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
def clear(api_key: Optional[str], clear_cache: bool, clear_expired: bool):
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
def serve(host: str, port: int, reload: bool, workers: int, api_key: Optional[str]):
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


if __name__ == '__main__':
    cli()

