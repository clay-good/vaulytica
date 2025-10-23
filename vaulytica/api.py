"""REST API server for Vaulytica SOAR integration."""

import asyncio
import time
import signal
import sys
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path
from collections import defaultdict
from fastapi import FastAPI, HTTPException, BackgroundTasks, status, Request, Query, Body, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field
from vaulytica.config import load_config
from vaulytica.parsers import (
    GuardDutyParser,
    GCPSecurityCommandCenterParser,
    DatadogParser,
    CrowdStrikeParser,
    SnowflakeParser
)
from vaulytica.agents import SecurityAnalystAgent
from vaulytica.rag import IncidentRAG
from vaulytica.cache import AnalysisCache
from vaulytica.models import SecurityEvent, AnalysisResult, Severity, EventCategory
from vaulytica.logger import setup_logger, get_logger
from vaulytica.webhooks import webhook_router, WebhookProcessor, set_webhook_processor
from vaulytica.notifications import NotificationManager, NotificationConfig
from vaulytica.metrics import get_metrics_collector
from vaulytica.correlation import CorrelationEngine
from vaulytica.playbooks import PlaybookEngine, ActionStatus, ApprovalLevel
from vaulytica.threat_feeds import ThreatFeedIntegration
from vaulytica.dashboard import DashboardManager, get_dashboard_manager
from vaulytica.visualizations import VisualizationEngine, get_visualization_engine
from vaulytica.incidents import (
    IncidentManager, get_incident_manager, TicketingManager, get_ticketing_manager,
    IncidentStatus, IncidentPriority, EscalationLevel, TicketingSystem, TicketingConfig,
    process_security_event, get_incident_summary, format_incident_for_notification
)
from vaulytica.ai_soc_analytics import (
    AISOCAnalytics, get_ai_soc_analytics,
    RiskLevel, ThreatCategory, TriagePriority, HuntingHypothesisStatus
)
from vaulytica.streaming import (
    StreamingAnalytics, get_streaming_analytics,
    WindowType, PatternType, CEPPattern, StreamState,
    create_custom_cep_pattern, convert_pattern_match_to_dict, convert_correlation_to_dict
)
from vaulytica.forensics import (
    ForensicsEngine, get_forensics_engine,
    EvidenceType, EvidenceSource, CollectionMethod, EvidenceStatus,
    InvestigationType, InvestigationStatus, AnalysisType
)

# Initialize logger
setup_logger()
logger = get_logger(__name__)

# Setup templates and static files
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app_static = StaticFiles(directory=str(BASE_DIR / "static"))

# Initialize FastAPI app
app = FastAPI(
    title="Vaulytica API",
    description="AI-powered security event analysis API with deep learning, AutoML, interactive visualizations, incident management, AI SOC analytics, real-time streaming analytics, automated forensics & investigation, threat hunting, SOAR, compliance & audit, external threat intelligence integration, advanced automation, multi-platform ticketing (ServiceNow, Jira, PagerDuty, Datadog), Cloud Security Posture Management (CSPM), vulnerability management, Container Security & Kubernetes Security Posture Management (K8s SPM), IAM Security & Secrets Management, Zero Trust Architecture, Network Security, Data Loss Prevention (DLP), Encryption Management, API Security, Application Security Testing (AST), Security Automation, DevSecOps Integration, Security Orchestration, Advanced Threat Intelligence, Security Metrics & KPIs, Automated Penetration Testing, Supply Chain Security, SBOM Management, Security GRC, Security Posture Analytics, Continuous Monitoring, Predictive Security Intelligence, Attack Surface Management, Security Data Lake, Threat Modeling, and Incident Simulation",
    version="0.30.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Add trusted host middleware (configure for production)
# app.add_middleware(TrustedHostMiddleware, allowed_hosts=["example.com", "*.example.com"])

# Mount static files
app.mount("/static", app_static, name="static")

# Include webhook router
app.include_router(webhook_router)

# Rate limiting state
rate_limit_store = defaultdict(list)
RATE_LIMIT_REQUESTS = 100  # requests per window
RATE_LIMIT_WINDOW = 60  # seconds

# Application state
app_state = {
    "is_ready": False,
    "is_healthy": True,
    "startup_time": None,
    "shutdown_requested": False
}


# Rate limiting middleware
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Simple rate limiting middleware."""
    # Skip rate limiting for health checks
    if request.url.path in ["/health", "/ready", "/metrics"]:
        return await call_next(request)

    client_ip = request.client.host
    current_time = time.time()

    # Clean old requests
    rate_limit_store[client_ip] = [
        req_time for req_time in rate_limit_store[client_ip]
        if current_time - req_time < RATE_LIMIT_WINDOW
    ]

    # Check rate limit
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={
                "detail": f"Rate limit exceeded. Max {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds."
            }
        )

    # Record request
    rate_limit_store[client_ip].append(current_time)

    return await call_next(request)


# Middleware for metrics collection
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Collect metrics for all API requests."""
    start_time = time.time()
    response = await call_next(request)
    latency = time.time() - start_time

    # Record API metrics
    metrics.record_api_request(
        endpoint=request.url.path,
        method=request.method,
        status_code=response.status_code,
        latency_seconds=latency
    )

    return response


# Security headers middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosnif"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


# Global state
config = None
agent = None
rag = None
cache = None
parsers = {}
notification_manager = None
metrics = get_metrics_collector()
correlation_engine = None
playbook_engine = None
threat_feeds = None
visualization_engine = None
incident_manager = None
ticketing_manager = None
ai_soc_analytics = None
streaming_analytics = None
forensics_engine = None


# Request/Response Models
class AnalysisRequest(BaseModel):
    """Request model for analysis endpoint."""

    source: str = Field(
        ...,
        description="Source system type",
        examples=["guardduty", "gcp-scc", "datadog", "crowdstrike", "snowflake"]
    )
    event: Dict[str, Any] = Field(
        ...,
        description="Raw security event data"
    )
    enable_rag: bool = Field(
        default=True,
        description="Enable historical incident correlation"
    )
    enable_cache: bool = Field(
        default=True,
        description="Enable analysis caching"
    )
    store_result: bool = Field(
        default=True,
        description="Store result in RAG database"
    )


class AnalysisResponse(BaseModel):
    """Response model for analysis endpoint."""

    event_id: str
    risk_score: float
    confidence: float
    executive_summary: str
    five_w1h: Dict[str, str]
    attack_chain: List[str]
    mitre_techniques: List[Dict[str, Any]]
    immediate_actions: List[str]
    short_term_recommendations: List[str]
    long_term_recommendations: List[str]
    investigation_queries: List[str]
    processing_time_seconds: float
    cached: bool = False


class HealthResponse(BaseModel):
    """Response model for health check."""

    status: str
    version: str
    timestamp: str
    rag_incidents: int
    cache_entries: int


class StatsResponse(BaseModel):
    """Response model for statistics."""

    rag_stats: Dict[str, Any]
    cache_stats: Dict[str, Any]


# Startup and Shutdown
@app.on_event("startup")
async def startup_event():
    """Initialize components on startup."""
    global config, agent, rag, cache, parsers, notification_manager, correlation_engine, visualization_engine, incident_manager, ticketing_manager, ai_soc_analytics, streaming_analytics, forensics_engine

    try:
        logger.info("Starting Vaulytica API server...")

        # Load configuration
        config = load_config()
        logger.info("Configuration loaded")

        # Initialize components
        agent = SecurityAnalystAgent(config)
        rag = IncidentRAG(config) if config.enable_rag else None
        cache = AnalysisCache(config) if config.enable_cache else None

        # Initialize correlation engine
        correlation_engine = CorrelationEngine(
            temporal_window_minutes=60,
            min_correlation_confidence=0.5,
            min_campaign_events=3
        )
        logger.info("Correlation engine initialized")

        # Initialize playbook engine
        playbook_engine = PlaybookEngine(
            auto_execute=False,  # Require manual approval by default
            require_approval=True
        )
        logger.info("Playbook engine initialized")

        # Initialize threat feed integration (v0.9.0)
        if config.enable_threat_feeds:
            threat_feeds = ThreatFeedIntegration(
                virustotal_api_key=config.virustotal_api_key,
                otx_api_key=config.alienvault_otx_api_key,
                abuseipdb_api_key=config.abuseipdb_api_key,
                shodan_api_key=config.shodan_api_key,
                enable_cache=True,
                cache_ttl_hours=config.threat_feed_cache_ttl,
                timeout_seconds=config.threat_feed_timeout
            )
            logger.info("Threat feed integration initialized")
        else:
            logger.info("Threat feed integration disabled")

        # Initialize parsers
        parsers = {
            'guardduty': GuardDutyParser(),
            'gcp-scc': GCPSecurityCommandCenterParser(),
            'datadog': DatadogParser(),
            'crowdstrike': CrowdStrikeParser(),
            'snowflake': SnowflakeParser()
        }

        # Initialize webhook processor
        webhook_processor = WebhookProcessor(config, agent, rag, cache)
        set_webhook_processor(webhook_processor)
        logger.info("Webhook processor initialized")

        # Initialize notification manager
        notification_config = NotificationConfig(
            slack_webhook_url=config.slack_webhook_url,
            slack_channel=config.slack_channel,
            teams_webhook_url=config.teams_webhook_url,
            smtp_host=config.smtp_host,
            smtp_port=config.smtp_port,
            smtp_username=config.smtp_username,
            smtp_password=config.smtp_password,
            smtp_from=config.smtp_from,
            smtp_to=config.smtp_to,
            min_risk_score=config.min_risk_score_notify,
            notify_on_cache_hit=config.notify_on_cache_hit
        )
        notification_manager = NotificationManager(notification_config)
        logger.info("Notification manager initialized")

        # Initialize visualization engine (v0.13.0)
        visualization_engine = get_visualization_engine()
        logger.info("Visualization engine initialized")

        # Initialize incident manager (v0.14.0)
        incident_manager = get_incident_manager(
            enable_auto_escalation=True
        )
        logger.info("Incident manager initialized")

        # Initialize ticketing manager (v0.14.0)
        ticketing_manager = get_ticketing_manager()
        logger.info("Ticketing manager initialized")

        # Initialize AI SOC Analytics (v0.15.0)
        ai_soc_analytics = get_ai_soc_analytics(
            ml_engine=agent.ml_engine if hasattr(agent, 'ml_engine') else None,
            advanced_ml=agent.advanced_ml if hasattr(agent, 'advanced_ml') else None
        )
        logger.info("AI SOC Analytics initialized")

        # Initialize Streaming Analytics (v0.16.0)
        from datetime import timedelta
        streaming_analytics = get_streaming_analytics(
            window_size=timedelta(minutes=5),
            window_type=WindowType.TUMBLING,
            correlation_window=timedelta(minutes=10)
        )
        logger.info("Streaming Analytics initialized")

        # Initialize Forensics Engine (v0.17.0)
        forensics_engine = get_forensics_engine()
        logger.info("Forensics Engine initialized")

        # Start incident maintenance background task
        asyncio.create_task(incident_maintenance_background())

        # Mark application as ready
        app_state["is_ready"] = True
        app_state["startup_time"] = datetime.utcnow()

        logger.info("Vaulytica API server started successfully")

    except Exception as e:
        logger.error(f"Failed to start API server: {e}")
        app_state["is_healthy"] = False
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down Vaulytica API server...")
    app_state["shutdown_requested"] = True
    app_state["is_ready"] = False

    # Graceful shutdown - wait for ongoing requests
    await asyncio.sleep(2)

    logger.info("Vaulytica API server shutdown complete")


# Graceful shutdown signal handlers
def handle_shutdown_signal(signum: int, frame: Any) -> None:
    """Handle shutdown signals gracefully."""
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    app_state["shutdown_requested"] = True
    app_state["is_ready"] = False


# Register signal handlers
signal.signal(signal.SIGTERM, handle_shutdown_signal)
signal.signal(signal.SIGINT, handle_shutdown_signal)


# API Endpoints
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Vaulytica API",
        "version": "0.21.0",
        "description": "AI-powered security event analysis with deep learning, AutoML, interactive visualizations, incident management, AI SOC analytics, real-time streaming analytics, automated forensics & investigation, threat hunting, SOAR, compliance, external threat intelligence, advanced automation, multi-platform ticketing (ServiceNow, Jira, PagerDuty, Datadog), and web dashboard",
        "status": "operational" if app_state["is_ready"] else "initializing",
        "endpoints": {
            "docs": "/docs",
            "health": "/health",
            "ready": "/ready",
            "live": "/live",
            "metrics": "/metrics",
            "analyze": "/analyze",
            "incidents": "/incidents",
            "forensics": "/forensics",
            "streaming": "/streaming",
            "ai_soc": "/ai-soc",
            "visualizations": "/visualizations",
            "threat_hunting": "/threat-hunting",
            "soar": "/soar",
            "compliance": "/compliance",
            "threat_intel": "/threat-intel",
            "automation": "/automation",
            "datadog": "/datadog",
            "ticketing": "/ticketing"
        },
        "features": [
            "AI-powered analysis with Claude",
            "Deep learning & AutoML",
            "Real-time streaming analytics",
            "Incident management & alerting",
            "AI SOC analytics",
            "Automated forensics & investigation",
            "Interactive visualizations",
            "Threat intelligence integration",
            "Automated response playbooks"
        ]
    }


@app.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring.
    Returns 200 if service is healthy, 503 if unhealthy.
    """
    if not app_state["is_healthy"]:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "version": "0.17.0",
                "timestamp": datetime.utcnow().isoformat()
            }
        )

    try:
        # Check critical components
        checks = {
            "agent": agent is not None,
            "rag": rag is not None,
            "cache": cache is not None,
            "incident_manager": incident_manager is not None,
            "ai_soc_analytics": ai_soc_analytics is not None,
            "streaming_analytics": streaming_analytics is not None,
            "forensics_engine": forensics_engine is not None
        }

        all_healthy = all(checks.values())

        return {
            "status": "healthy" if all_healthy else "degraded",
            "version": "0.17.0",
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": (datetime.utcnow() - app_state["startup_time"]).total_seconds() if app_state["startup_time"] else 0,
            "components": checks
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "version": "0.17.0",
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }
        )


@app.get("/ready")
async def readiness_check():
    """
    Readiness check endpoint for Kubernetes/load balancers.
    Returns 200 when ready to accept traffic, 503 otherwise.
    """
    if not app_state["is_ready"] or app_state["shutdown_requested"]:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "ready": False,
                "reason": "shutdown_requested" if app_state["shutdown_requested"] else "not_initialized"
            }
        )

    return {
        "ready": True,
        "version": "0.17.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/live")
async def liveness_check():
    """
    Liveness check endpoint for Kubernetes.
    Returns 200 if process is alive, 503 if it should be restarted.
    """
    return {
        "alive": True,
        "version": "0.17.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get system statistics."""
    try:
        rag_stats = rag.get_collection_stats() if rag else {}
        cache_stats = cache.get_stats() if cache else {}

        return StatsResponse(
            rag_stats=rag_stats,
            cache_stats=cache_stats
        )
    except Exception as e:
        logger.error(f"Failed to get stats: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get stats: {str(e)}"
        )


@app.get("/metrics")
async def get_metrics():
    """Get comprehensive metrics summary."""
    try:
        return JSONResponse(content=metrics.get_summary())
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve metrics: {str(e)}"
        )


@app.get("/metrics/prometheus", response_class=PlainTextResponse)
async def get_prometheus_metrics():
    """Export metrics in Prometheus format."""
    try:
        return metrics.export_prometheus()
    except Exception as e:
        logger.error(f"Failed to export Prometheus metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to export metrics: {str(e)}"
        )


@app.post("/analyze", response_model=AnalysisResponse, status_code=status.HTTP_200_OK)
async def analyze_event(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """
    Analyze a security event.

    This endpoint accepts a raw security event from various sources and returns
    a comprehensive AI-powered analysis including risk scoring, MITRE ATT&CK mapping,
    and actionable recommendations.
    """
    try:
        logger.info(f"Received analysis request for source: {request.source}")

        # Validate source
        if request.source not in parsers:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported source: {request.source}. Supported: {list(parsers.keys())}"
            )

        # Parse event
        parser = parsers[request.source]
        try:
            event = parser.parse(request.event)
            logger.info(f"Parsed event: {event.event_id}")
        except Exception as e:
            logger.error(f"Failed to parse event: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to parse event: {str(e)}"
            )

        # Check cache
        cached_result = None
        if request.enable_cache and cache:
            cached_result = cache.get(event)
            if cached_result:
                logger.info(f"Cache hit for event: {event.event_id}")

                # Record metrics for cached result
                mitre_ids = [t.technique_id for t in cached_result.mitre_techniques]
                metrics.record_analysis(
                    platform=request.source,
                    risk_score=cached_result.risk_score,
                    latency_seconds=0.0,  # Cached, no latency
                    tokens_used=0,  # No tokens for cache hit
                    cached=True,
                    mitre_techniques=mitre_ids
                )

                return _format_response(cached_result, cached=True)

        # Find similar incidents
        historical_context = []
        if request.enable_rag and rag:
            try:
                historical_context = rag.find_similar_incidents(event, max_results=5)
                logger.info(f"Found {len(historical_context)} similar incidents")
            except Exception as e:
                logger.warning(f"RAG query failed: {e}")

        # Perform analysis
        analysis_start = time.time()
        try:
            result = await agent.analyze([event], historical_context=historical_context)
            analysis_latency = time.time() - analysis_start
            logger.info(f"Analysis complete for event: {event.event_id}")

            # Record metrics for successful analysis
            mitre_ids = [t.technique_id for t in result.mitre_techniques]
            metrics.record_analysis(
                platform=request.source,
                risk_score=result.risk_score,
                latency_seconds=analysis_latency,
                tokens_used=result.tokens_used if hasattr(result, 'tokens_used') else 0,
                cached=False,
                mitre_techniques=mitre_ids
            )

        except Exception as e:
            logger.error(f"Analysis failed: {e}")

            # Record error metrics
            metrics.record_analysis(
                platform=request.source,
                risk_score=0.0,
                latency_seconds=0.0,
                tokens_used=0,
                cached=False,
                error=True
            )

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Analysis failed: {str(e)}"
            )

        # Store in cache (background task)
        if request.enable_cache and cache:
            background_tasks.add_task(cache.set, event, result)

        # Store in RAG (background task)
        if request.store_result and rag:
            background_tasks.add_task(rag.store_incident, event, result)

        # Add to correlation engine (background task)
        if correlation_engine:
            background_tasks.add_task(correlation_engine.add_event, event, result)

            # Get correlations for response
            correlated_events = correlation_engine.get_correlated_events(event.event_id)
            result.correlated_event_ids = [e.event_id for e in correlated_events]

            # Get cluster/campaign info
            cluster = correlation_engine.get_cluster_by_event(event.event_id)
            if cluster:
                result.cluster_id = cluster.cluster_id

            campaign = correlation_engine.get_campaign_by_event(event.event_id)
            if campaign:
                result.campaign_id = campaign.campaign_id

        # Send notifications (background task)
        if notification_manager:
            background_tasks.add_task(
                notification_manager.send_notification,
                result,
                request.source,
                False  # not cached
            )

        return _format_response(result, cached=False)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unexpected error in analyze endpoint")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error: {str(e)}"
        )


def _format_response(result: AnalysisResult, cached: bool = False) -> AnalysisResponse:
    """Format AnalysisResult to AnalysisResponse."""
    return AnalysisResponse(
        event_id=result.event_id,
        risk_score=result.risk_score,
        confidence=result.confidence,
        executive_summary=result.executive_summary,
        five_w1h={
            "who": result.five_w1h.who,
            "what": result.five_w1h.what,
            "when": result.five_w1h.when,
            "where": result.five_w1h.where,
            "why": result.five_w1h.why,
            "how": result.five_w1h.how
        },
        attack_chain=result.attack_chain,
        mitre_techniques=[
            {
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": m.tactic,
                "confidence": m.confidence
            }
            for m in result.mitre_techniques
        ],
        immediate_actions=result.immediate_actions,
        short_term_recommendations=result.short_term_recommendations,
        long_term_recommendations=result.long_term_recommendations,
        investigation_queries=result.investigation_queries,
        processing_time_seconds=result.processing_time_seconds,
        cached=cached
    )


@app.get("/correlation/stats", tags=["Correlation"])
async def get_correlation_stats():
    """Get correlation engine statistics."""
    if not correlation_engine:
        raise HTTPException(status_code=503, detail="Correlation engine not initialized")

    stats = correlation_engine.get_statistics()
    return stats


@app.get("/correlation/event/{event_id}", tags=["Correlation"])
async def get_event_correlations(event_id: str):
    """Get correlations for a specific event."""
    if not correlation_engine:
        raise HTTPException(status_code=503, detail="Correlation engine not initialized")

    report = correlation_engine.generate_correlation_report(event_id)

    if "error" in report:
        raise HTTPException(status_code=404, detail=report["error"])

    return report


@app.get("/correlation/campaigns", tags=["Correlation"])
async def get_campaigns():
    """Get all detected attack campaigns."""
    if not correlation_engine:
        raise HTTPException(status_code=503, detail="Correlation engine not initialized")

    campaigns = correlation_engine.detect_campaigns()

    return {
        "total_campaigns": len(campaigns),
        "campaigns": [
            {
                "campaign_id": c.campaign_id,
                "campaign_name": c.campaign_name,
                "status": c.status.value,
                "total_events": c.total_events,
                "first_seen": c.first_seen.isoformat() if c.first_seen else None,
                "last_seen": c.last_seen.isoformat() if c.last_seen else None,
                "targeted_assets": list(c.targeted_assets),
                "threat_actors": c.threat_actors,
                "confidence": c.confidence,
                "severity_score": c.severity_score
            }
            for c in campaigns
        ]
    }


@app.get("/correlation/campaign/{campaign_id}", tags=["Correlation"])
async def get_campaign_details(campaign_id: str):
    """Get detailed information about a specific campaign."""
    if not correlation_engine:
        raise HTTPException(status_code=503, detail="Correlation engine not initialized")

    if campaign_id not in correlation_engine.campaigns:
        raise HTTPException(status_code=404, detail="Campaign not found")

    campaign = correlation_engine.campaigns[campaign_id]

    return {
        "campaign_id": campaign.campaign_id,
        "campaign_name": campaign.campaign_name,
        "status": campaign.status.value,
        "total_events": campaign.total_events,
        "first_seen": campaign.first_seen.isoformat() if campaign.first_seen else None,
        "last_seen": campaign.last_seen.isoformat() if campaign.last_seen else None,
        "targeted_assets": list(campaign.targeted_assets),
        "threat_actors": campaign.threat_actors,
        "ttps": list(campaign.ttps),
        "iocs": list(campaign.iocs),
        "confidence": campaign.confidence,
        "severity_score": campaign.severity_score,
        "clusters": [
            {
                "cluster_id": cluster.cluster_id,
                "event_count": len(cluster.events),
                "event_ids": [e.event_id for e in cluster.events]
            }
            for cluster in campaign.clusters
        ]
    }


@app.get("/correlation/graph", tags=["Correlation"])
async def get_correlation_graph():
    """Get correlation graph data for visualization."""
    if not correlation_engine:
        raise HTTPException(status_code=503, detail="Correlation engine not initialized")

    graph_data = correlation_engine.export_graph_data()
    return graph_data


# Playbook Endpoints
@app.get("/playbooks", tags=["Playbooks"])
async def list_playbooks():
    """List all available playbooks."""
    if not playbook_engine:
        raise HTTPException(status_code=503, detail="Playbook engine not initialized")

    playbooks_list = []
    for playbook in playbook_engine.playbooks.values():
        playbooks_list.append({
            "playbook_id": playbook.playbook_id,
            "name": playbook.name,
            "description": playbook.description,
            "threat_types": playbook.threat_types,
            "severity_threshold": playbook.severity_threshold.value,
            "requires_approval": playbook.requires_approval,
            "auto_execute": playbook.auto_execute,
            "actions_count": len(playbook.actions),
            "tags": playbook.tags
        })

    return {
        "total_playbooks": len(playbooks_list),
        "playbooks": playbooks_list
    }


@app.get("/playbooks/{playbook_id}", tags=["Playbooks"])
async def get_playbook(playbook_id: str):
    """Get detailed playbook information."""
    if not playbook_engine:
        raise HTTPException(status_code=503, detail="Playbook engine not initialized")

    playbook = playbook_engine.playbooks.get(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    actions_list = []
    for action in playbook.actions:
        actions_list.append({
            "action_id": action.action_id,
            "action_type": action.action_type.value,
            "description": action.description,
            "target": action.target,
            "approval_level": action.approval_level.value,
            "status": action.status.value
        })

    return {
        "playbook_id": playbook.playbook_id,
        "name": playbook.name,
        "description": playbook.description,
        "threat_types": playbook.threat_types,
        "severity_threshold": playbook.severity_threshold.value,
        "requires_approval": playbook.requires_approval,
        "auto_execute": playbook.auto_execute,
        "tags": playbook.tags,
        "actions": actions_list,
        "created_at": playbook.created_at.isoformat()
    }


@app.post("/playbooks/select", tags=["Playbooks"])
async def select_playbooks_for_event(event_id: str):
    """Select appropriate playbooks for an event."""
    if not playbook_engine or not correlation_engine:
        raise HTTPException(status_code=503, detail="Engines not initialized")

    # Get event and analysis from correlation engine
    event = correlation_engine.events.get(event_id)
    analysis = correlation_engine.analyses.get(event_id)

    if not event or not analysis:
        raise HTTPException(status_code=404, detail="Event not found")

    # Select playbooks
    matching_playbooks = playbook_engine.select_playbooks(event, analysis)

    playbooks_list = []
    for playbook in matching_playbooks:
        playbooks_list.append({
            "playbook_id": playbook.playbook_id,
            "name": playbook.name,
            "description": playbook.description,
            "requires_approval": playbook.requires_approval,
            "auto_execute": playbook.auto_execute,
            "actions_count": len(playbook.actions)
        })

    return {
        "event_id": event_id,
        "matching_playbooks": len(playbooks_list),
        "playbooks": playbooks_list
    }


@app.post("/playbooks/execute", tags=["Playbooks"])
async def execute_playbook_endpoint(
    playbook_id: str,
    event_id: str,
    dry_run: bool = True
):
    """Execute a playbook for an event."""
    if not playbook_engine or not correlation_engine:
        raise HTTPException(status_code=503, detail="Engines not initialized")

    # Get playbook
    playbook = playbook_engine.playbooks.get(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    # Get event and analysis
    event = correlation_engine.events.get(event_id)
    analysis = correlation_engine.analyses.get(event_id)

    if not event or not analysis:
        raise HTTPException(status_code=404, detail="Event not found")

    # Execute playbook
    execution = playbook_engine.execute_playbook(playbook, event, analysis, dry_run=dry_run)

    return {
        "execution_id": execution.execution_id,
        "playbook_name": execution.playbook.name,
        "status": execution.status,
        "dry_run": dry_run,
        "started_at": execution.started_at.isoformat(),
        "actions_completed": execution.actions_completed,
        "actions_failed": execution.actions_failed,
        "actions_skipped": execution.actions_skipped
    }


@app.get("/playbooks/executions/{execution_id}", tags=["Playbooks"])
async def get_execution_status_endpoint(execution_id: str):
    """Get playbook execution status."""
    if not playbook_engine:
        raise HTTPException(status_code=503, detail="Playbook engine not initialized")

    try:
        status_info = playbook_engine.get_execution_status(execution_id)
        return status_info
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/playbooks/executions/{execution_id}/approve", tags=["Playbooks"])
async def approve_action_endpoint(
    execution_id: str,
    action_id: str,
    approver: str
):
    """Approve a pending action."""
    if not playbook_engine:
        raise HTTPException(status_code=503, detail="Playbook engine not initialized")

    try:
        playbook_engine.approve_action(execution_id, action_id, approver)
        return {
            "status": "approved",
            "execution_id": execution_id,
            "action_id": action_id,
            "approver": approver
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/playbooks/executions/{execution_id}/rollback", tags=["Playbooks"])
async def rollback_action_endpoint(
    execution_id: str,
    action_id: str
):
    """Rollback a completed action."""
    if not playbook_engine:
        raise HTTPException(status_code=503, detail="Playbook engine not initialized")

    try:
        playbook_engine.rollback_action(execution_id, action_id)
        return {
            "status": "rolled_back",
            "execution_id": execution_id,
            "action_id": action_id
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============================================================================
# Threat Feed Endpoints (v0.9.0)
# ============================================================================

@app.post("/threat-feeds/enrich", tags=["Threat Feeds"])
async def enrich_ioc(
    ioc_value: str,
    ioc_type: str = Query(..., description="IOC type: ip, domain, hash, url")
):
    """
    Enrich an IOC with real-time threat intelligence.

    Queries multiple threat feeds and returns aggregated results.
    """
    if not threat_feeds:
        raise HTTPException(
            status_code=503,
            detail="Threat feed integration not enabled"
        )

    try:
        result = threat_feeds.enrich_ioc(ioc_value, ioc_type)

        return {
            "ioc_value": result.ioc_value,
            "ioc_type": result.ioc_type,
            "is_malicious": result.is_malicious,
            "consensus_verdict": result.consensus_verdict,
            "overall_confidence": result.overall_confidence,
            "overall_threat_score": result.overall_threat_score,
            "sources_checked": result.sources_checked,
            "sources_flagged": result.sources_flagged,
            "tags": list(result.tags),
            "malware_families": list(result.malware_families),
            "threat_actors": list(result.threat_actors),
            "source_results": [
                {
                    "source": r.source.value,
                    "is_malicious": r.is_malicious,
                    "confidence": r.confidence,
                    "threat_score": r.threat_score,
                    "tags": r.tags,
                    "detection_count": r.detection_count,
                    "total_scans": r.total_scans
                }
                for r in result.results
            ]
        }
    except Exception as e:
        logger.error(f"Error enriching IOC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/threat-feeds/batch-enrich", tags=["Threat Feeds"])
async def batch_enrich_iocs(
    iocs: List[Dict[str, str]] = Body(..., description="List of {ioc_value, ioc_type} objects")
):
    """
    Batch enrich multiple IOCs with threat intelligence.

    Example:
    [
        {"ioc_value": "198.51.100.5", "ioc_type": "ip"},
        {"ioc_value": "evil.com", "ioc_type": "domain"}
    ]
    """
    if not threat_feeds:
        raise HTTPException(
            status_code=503,
            detail="Threat feed integration not enabled"
        )

    try:
        ioc_tuples = [(ioc["ioc_value"], ioc["ioc_type"]) for ioc in iocs]
        results = threat_feeds.batch_enrich(ioc_tuples)

        return {
            "total_iocs": len(results),
            "results": {
                ioc_value: {
                    "is_malicious": result.is_malicious,
                    "consensus_verdict": result.consensus_verdict,
                    "overall_threat_score": result.overall_threat_score,
                    "sources_checked": result.sources_checked,
                    "sources_flagged": result.sources_flagged
                }
                for ioc_value, result in results.items()
            }
        }
    except Exception as e:
        logger.error(f"Error batch enriching IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-feeds/stats", tags=["Threat Feeds"])
async def get_threat_feed_stats():
    """Get threat feed integration statistics."""
    if not threat_feeds:
        raise HTTPException(
            status_code=503,
            detail="Threat feed integration not enabled"
        )

    return threat_feeds.get_statistics()


@app.post("/threat-feeds/clear-cache", tags=["Threat Feeds"])
async def clear_threat_feed_cache():
    """Clear threat feed cache."""
    if not threat_feeds:
        raise HTTPException(
            status_code=503,
            detail="Threat feed integration not enabled"
        )

    threat_feeds.clear_cache()
    return {"status": "cache_cleared"}


# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )


# ============================================================================
# Dashboard Routes (v0.11.0)
# ============================================================================

@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
async def dashboard_home(request: Request):
    """Serve the main dashboard page."""
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/visualizations", response_class=HTMLResponse, tags=["Visualizations"])
async def visualizations_page(request: Request):
    """Serve the advanced visualizations page."""
    return templates.TemplateResponse("visualizations.html", {"request": request})


@app.websocket("/ws/dashboard")
async def dashboard_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    dashboard = get_dashboard_manager()
    await dashboard.register_websocket(websocket)

    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            # Handle any client messages if needed
    except WebSocketDisconnect:
        await dashboard.unregister_websocket(websocket)


@app.get("/api/dashboard/stats", tags=["Dashboard"])
async def get_dashboard_stats():
    """Get current dashboard statistics."""
    dashboard = get_dashboard_manager()
    return dashboard.get_stats()


@app.get("/api/dashboard/events", tags=["Dashboard"])
async def get_dashboard_events(limit: int = Query(50, ge=1, le=100)):
    """Get recent events for dashboard."""
    dashboard = get_dashboard_manager()
    return dashboard.get_recent_events(limit)


@app.get("/api/dashboard/severity", tags=["Dashboard"])
async def get_severity_distribution():
    """Get severity distribution for charts."""
    dashboard = get_dashboard_manager()
    return dashboard.get_severity_distribution()


@app.get("/api/dashboard/timeline", tags=["Dashboard"])
async def get_timeline_data(hours: int = Query(24, ge=1, le=168)):
    """Get timeline data for charts."""
    dashboard = get_dashboard_manager()
    return dashboard.get_timeline_data(hours)


@app.get("/api/dashboard/ml-insights", tags=["Dashboard"])
async def get_ml_insights():
    """Get ML engine insights for dashboard."""
    dashboard = get_dashboard_manager()
    return dashboard.get_ml_insights()


@app.post("/api/dashboard/test-event", tags=["Dashboard"])
async def create_test_event():
    """Create a test event for dashboard demonstration."""
    from vaulytica.models import SecurityEvent, Severity, EventCategory

    dashboard = get_dashboard_manager()

    # Create test event
    event = SecurityEvent(
        event_id=f"test_{int(time.time())}",
        source_system="test",
        timestamp=datetime.utcnow(),
        severity=Severity.HIGH,
        category=EventCategory.UNAUTHORIZED_ACCESS,
        title="Test Security Event",
        description="This is a test event for dashboard demonstration",
        raw_event={"test": True},
        metadata={"source_ip": "192.168.1.100", "target_ip": "10.0.0.50"}
    )

    # Add to dashboard
    summary = await dashboard.add_event(event)

    return {"message": "Test event created", "event": summary}


# ============================================================================
# Visualization API Endpoints (v0.13.0)
# ============================================================================

@app.get("/visualizations/attack-graph", response_model=Dict[str, Any])
async def get_attack_graph(
    limit: int = Query(100, description="Maximum number of events to include"),
    hours: int = Query(24, description="Time window in hours")
):
    """
    Get attack graph visualization.

    Returns interactive graph showing attack chains and kill chains.
    """
    if not visualization_engine:
        raise HTTPException(status_code=503, detail="Visualization engine not initialized")

    try:
        # Get recent events from dashboard
        dashboard = get_dashboard_manager()
        events = dashboard.get_recent_events(limit=limit, hours=hours)

        if not events:
            return {
                "nodes": [],
                "edges": [],
                "metadata": {"total_events": 0, "message": "No events found"}
            }

        # Generate attack graph
        attack_graph = visualization_engine.generate_attack_graph(events)

        return attack_graph

    except Exception as e:
        logger.error(f"Error generating attack graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/visualizations/threat-map", response_model=Dict[str, Any])
async def get_threat_map(
    limit: int = Query(100, description="Maximum number of events to include"),
    hours: int = Query(24, description="Time window in hours")
):
    """
    Get threat map visualization.

    Returns geographic map showing attack origins and targets.
    """
    if not visualization_engine:
        raise HTTPException(status_code=503, detail="Visualization engine not initialized")

    try:
        # Get recent events from dashboard
        dashboard = get_dashboard_manager()
        events = dashboard.get_recent_events(limit=limit, hours=hours)

        if not events:
            return {
                "points": [],
                "connections": [],
                "metadata": {"total_events": 0, "message": "No events found"}
            }

        # Generate threat map
        threat_map = visualization_engine.generate_threat_map(events)

        return threat_map

    except Exception as e:
        logger.error(f"Error generating threat map: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/visualizations/network-topology", response_model=Dict[str, Any])
async def get_network_topology(
    limit: int = Query(100, description="Maximum number of events to include"),
    hours: int = Query(24, description="Time window in hours")
):
    """
    Get network topology visualization.

    Returns graph showing network assets and their relationships.
    """
    if not visualization_engine:
        raise HTTPException(status_code=503, detail="Visualization engine not initialized")

    try:
        # Get recent events from dashboard
        dashboard = get_dashboard_manager()
        events = dashboard.get_recent_events(limit=limit, hours=hours)

        if not events:
            return {
                "nodes": [],
                "edges": [],
                "metadata": {"total_events": 0, "message": "No events found"}
            }

        # Generate network topology
        network_topology = visualization_engine.generate_network_topology(events)

        return network_topology

    except Exception as e:
        logger.error(f"Error generating network topology: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/visualizations/timeline", response_model=Dict[str, Any])
async def get_timeline(
    limit: int = Query(100, description="Maximum number of events to include"),
    hours: int = Query(24, description="Time window in hours")
):
    """
    Get timeline visualization.

    Returns interactive timeline showing attack progression.
    """
    if not visualization_engine:
        raise HTTPException(status_code=503, detail="Visualization engine not initialized")

    try:
        # Get recent events from dashboard
        dashboard = get_dashboard_manager()
        events = dashboard.get_recent_events(limit=limit, hours=hours)

        if not events:
            return {
                "events": [],
                "grouped": {},
                "metadata": {"total_events": 0, "message": "No events found"}
            }

        # Generate timeline
        timeline = visualization_engine.generate_timeline(events)

        return timeline

    except Exception as e:
        logger.error(f"Error generating timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/visualizations/correlation-matrix", response_model=Dict[str, Any])
async def get_correlation_matrix(
    limit: int = Query(100, description="Maximum number of events to include"),
    hours: int = Query(24, description="Time window in hours"),
    dimension1: str = Query("source_ip", description="First dimension"),
    dimension2: str = Query("category", description="Second dimension")
):
    """
    Get correlation matrix visualization.

    Returns heatmap showing correlations between dimensions.
    """
    if not visualization_engine:
        raise HTTPException(status_code=503, detail="Visualization engine not initialized")

    try:
        # Get recent events from dashboard
        dashboard = get_dashboard_manager()
        events = dashboard.get_recent_events(limit=limit, hours=hours)

        if not events:
            return {
                "matrix": [],
                "dimensions": {"rows": [], "columns": []},
                "metadata": {"total_events": 0, "message": "No events found"}
            }

        # Generate correlation matrix
        correlation_matrix = visualization_engine.generate_correlation_matrix(
            events, dimension1, dimension2
        )

        return correlation_matrix

    except Exception as e:
        logger.error(f"Error generating correlation matrix: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/visualizations/all", response_model=Dict[str, Any])
async def get_all_visualizations(
    limit: int = Query(100, description="Maximum number of events to include"),
    hours: int = Query(24, description="Time window in hours")
):
    """
    Get all visualizations at once.

    Returns all visualization types in a single response.
    """
    if not visualization_engine:
        raise HTTPException(status_code=503, detail="Visualization engine not initialized")

    try:
        # Get recent events from dashboard
        dashboard = get_dashboard_manager()
        events = dashboard.get_recent_events(limit=limit, hours=hours)

        if not events:
            return {
                "attack_graph": {"nodes": [], "edges": [], "metadata": {}},
                "threat_map": {"points": [], "connections": [], "metadata": {}},
                "network_topology": {"nodes": [], "edges": [], "metadata": {}},
                "timeline": {"events": [], "grouped": {}, "metadata": {}},
                "correlation_matrix": {"matrix": [], "dimensions": {}, "metadata": {}},
                "metadata": {"total_events": 0, "message": "No events found"}
            }

        # Generate all visualizations
        all_visualizations = visualization_engine.generate_all(events)
        all_visualizations["metadata"] = {
            "total_events": len(events),
            "timestamp": datetime.utcnow().isoformat()
        }

        return all_visualizations

    except Exception as e:
        logger.error(f"Error generating visualizations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/visualizations/stats", response_model=Dict[str, Any])
async def get_visualization_stats():
    """Get visualization engine statistics."""
    if not visualization_engine:
        raise HTTPException(status_code=503, detail="Visualization engine not initialized")

    return visualization_engine.get_stats()


# ============================================================================
# Incident Management Endpoints (v0.14.0)
# ============================================================================


async def incident_maintenance_background():
    """Background task for incident maintenance."""
    while True:
        try:
            if incident_manager:
                incident_manager.check_sla_breaches()
                incident_manager.check_and_escalate_incidents()
                incident_manager.cleanup()
            await asyncio.sleep(60)  # Run every minute
        except Exception as e:
            logger.error(f"Error in incident maintenance: {e}")
            await asyncio.sleep(60)


@app.post("/incidents/process", response_model=Dict[str, Any])
async def process_incident(
    event: SecurityEvent,
    analysis: Optional[AnalysisResult] = None,
    create_tickets: bool = Query(False, description="Create tickets in external systems")
):
    """
    Process security event and create/update incident.

    This endpoint processes a security event, creates or updates an incident,
    and optionally creates tickets in external ticketing systems.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    try:
        incident, is_new = await process_security_event(event, analysis, create_tickets)

        return {
            "incident": get_incident_summary(incident),
            "is_new_incident": is_new,
            "message": "New incident created" if is_new else "Added to existing incident"
        }
    except Exception as e:
        logger.error(f"Error processing incident: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents", response_model=Dict[str, Any])
async def get_incidents(
    status: Optional[str] = Query(None, description="Filter by status"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    assigned_to: Optional[str] = Query(None, description="Filter by assignee"),
    limit: int = Query(100, description="Maximum number of incidents")
):
    """
    Get incidents with optional filters.

    Returns a list of incidents matching the specified filters.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    try:
        # Parse filters
        status_filter = IncidentStatus(status) if status else None
        priority_filter = IncidentPriority(priority) if priority else None
        severity_filter = Severity(severity) if severity else None

        incidents = incident_manager.get_incidents(
            status=status_filter,
            priority=priority_filter,
            severity=severity_filter,
            assigned_to=assigned_to,
            limit=limit
        )

        return {
            "incidents": [get_incident_summary(inc) for inc in incidents],
            "total": len(incidents),
            "filters": {
                "status": status,
                "priority": priority,
                "severity": severity,
                "assigned_to": assigned_to
            }
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid filter value: {e}")
    except Exception as e:
        logger.error(f"Error getting incidents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents/{incident_id}", response_model=Dict[str, Any])
async def get_incident(incident_id: str):
    """
    Get incident by ID.

    Returns detailed information about a specific incident.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    incident = incident_manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "incident": incident.dict(),
        "summary": get_incident_summary(incident)
    }


@app.post("/incidents/{incident_id}/acknowledge", response_model=Dict[str, Any])
async def acknowledge_incident(
    incident_id: str,
    user: str = Body(..., embed=True, description="User acknowledging the incident")
):
    """
    Acknowledge an incident.

    Marks the incident as acknowledged and assigns it to the user.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    success = incident_manager.acknowledge_incident(incident_id, user)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = incident_manager.get_incident(incident_id)
    return {
        "success": True,
        "incident": get_incident_summary(incident),
        "message": f"Incident acknowledged by {user}"
    }


@app.post("/incidents/{incident_id}/investigate", response_model=Dict[str, Any])
async def start_investigation(
    incident_id: str,
    user: str = Body(..., embed=True, description="User starting investigation")
):
    """
    Start investigating an incident.

    Marks the incident as under investigation.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    success = incident_manager.start_investigation(incident_id, user)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = incident_manager.get_incident(incident_id)
    return {
        "success": True,
        "incident": get_incident_summary(incident),
        "message": f"Investigation started by {user}"
    }


@app.post("/incidents/{incident_id}/resolve", response_model=Dict[str, Any])
async def resolve_incident(
    incident_id: str,
    user: str = Body(..., embed=True, description="User resolving the incident"),
    resolution_note: str = Body(..., embed=True, description="Resolution note")
):
    """
    Resolve an incident.

    Marks the incident as resolved with a resolution note.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    success = incident_manager.resolve_incident(incident_id, user, resolution_note)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = incident_manager.get_incident(incident_id)

    # Close tickets in external systems
    if ticketing_manager and incident.external_tickets:
        try:
            await ticketing_manager.close_tickets(incident, resolution_note)
        except Exception as e:
            logger.error(f"Failed to close external tickets: {e}")

    return {
        "success": True,
        "incident": get_incident_summary(incident),
        "message": f"Incident resolved by {user}"
    }


@app.post("/incidents/{incident_id}/close", response_model=Dict[str, Any])
async def close_incident(
    incident_id: str,
    user: str = Body(..., embed=True, description="User closing the incident"),
    close_note: Optional[str] = Body(None, embed=True, description="Close note")
):
    """
    Close an incident.

    Marks the incident as closed. Can only close resolved incidents.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    success = incident_manager.close_incident(incident_id, user, close_note)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found or not resolved")

    incident = incident_manager.get_incident(incident_id)
    return {
        "success": True,
        "incident": get_incident_summary(incident),
        "message": f"Incident closed by {user}"
    }


@app.post("/incidents/{incident_id}/reopen", response_model=Dict[str, Any])
async def reopen_incident(
    incident_id: str,
    user: str = Body(..., embed=True, description="User reopening the incident"),
    reason: str = Body(..., embed=True, description="Reason for reopening")
):
    """
    Reopen a resolved or closed incident.

    Reopens the incident with a reason.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    success = incident_manager.reopen_incident(incident_id, user, reason)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident = incident_manager.get_incident(incident_id)
    return {
        "success": True,
        "incident": get_incident_summary(incident),
        "message": f"Incident reopened by {user}"
    }


@app.post("/incidents/{incident_id}/escalate", response_model=Dict[str, Any])
async def escalate_incident(
    incident_id: str,
    to_level: str = Body(..., embed=True, description="Escalation level"),
    reason: str = Body(..., embed=True, description="Escalation reason")
):
    """
    Escalate an incident to a higher level.

    Escalates the incident and reassigns to on-call user at new level.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    try:
        escalation_level = EscalationLevel(to_level)
        success = incident_manager.escalate_incident(incident_id, escalation_level, reason)
        if not success:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident = incident_manager.get_incident(incident_id)
        return {
            "success": True,
            "incident": get_incident_summary(incident),
            "message": f"Incident escalated to {escalation_level.value}"
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid escalation level")


@app.post("/incidents/{incident_id}/note", response_model=Dict[str, Any])
async def add_incident_note(
    incident_id: str,
    user: str = Body(..., embed=True, description="User adding note"),
    note: str = Body(..., embed=True, description="Note content")
):
    """
    Add a note to an incident.

    Adds a timestamped note to the incident.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    incident = incident_manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.add_note(user, note)

    return {
        "success": True,
        "incident": get_incident_summary(incident),
        "message": "Note added successfully"
    }


@app.post("/incidents/{incident_id}/tag", response_model=Dict[str, Any])
async def add_incident_tag(
    incident_id: str,
    tag: str = Body(..., embed=True, description="Tag to add")
):
    """
    Add a tag to an incident.

    Adds a tag for categorization and filtering.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    incident = incident_manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.add_tag(tag)

    return {
        "success": True,
        "incident": get_incident_summary(incident),
        "message": f"Tag '{tag}' added successfully"
    }


@app.get("/incidents/metrics", response_model=Dict[str, Any])
async def get_incident_metrics():
    """
    Get incident metrics and statistics.

    Returns comprehensive metrics about incidents, SLA breaches, and escalations.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    metrics = incident_manager.get_metrics()

    return {
        "metrics": {
            "total_incidents": metrics.total_incidents,
            "open_incidents": metrics.open_incidents,
            "acknowledged_incidents": metrics.acknowledged_incidents,
            "investigating_incidents": metrics.investigating_incidents,
            "resolved_incidents": metrics.resolved_incidents,
            "closed_incidents": metrics.closed_incidents,
            "sla_breaches": metrics.sla_breaches,
            "escalations": metrics.escalations,
            "alerts_deduplicated": metrics.alerts_deduplicated,
            "deduplication_rate": round(metrics.deduplication_rate, 2),
            "avg_time_to_acknowledge_seconds": metrics.avg_time_to_acknowledge,
            "avg_time_to_resolve_seconds": metrics.avg_time_to_resolve,
            "avg_incident_age_seconds": metrics.avg_incident_age
        },
        "by_priority": dict(metrics.incidents_by_priority),
        "by_severity": dict(metrics.incidents_by_severity),
        "by_status": dict(metrics.incidents_by_status),
        "timestamp": metrics.timestamp.isoformat()
    }


@app.post("/incidents/ticketing/configure", response_model=Dict[str, Any])
async def configure_ticketing(config: TicketingConfig):
    """
    Configure ticketing system integration.

    Adds or updates a ticketing system integration.
    """
    if not ticketing_manager:
        raise HTTPException(status_code=503, detail="Ticketing manager not initialized")

    try:
        ticketing_manager.add_integration(config)
        return {
            "success": True,
            "system": config.system.value,
            "enabled": config.enabled,
            "message": f"{config.system.value} integration configured"
        }
    except Exception as e:
        logger.error(f"Error configuring ticketing: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/incidents/{incident_id}/tickets/create", response_model=Dict[str, Any])
async def create_incident_tickets(incident_id: str):
    """
    Create tickets in external systems for an incident.

    Creates tickets in all configured ticketing systems.
    """
    if not incident_manager or not ticketing_manager:
        raise HTTPException(status_code=503, detail="Incident or ticketing manager not initialized")

    incident = incident_manager.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        tickets = await ticketing_manager.create_tickets(incident)
        return {
            "success": True,
            "incident_id": incident_id,
            "tickets": tickets,
            "message": f"Created {len(tickets)} tickets"
        }
    except Exception as e:
        logger.error(f"Error creating tickets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/incidents/on-call/schedule", response_model=Dict[str, Any])
async def get_on_call_schedule():
    """
    Get on-call schedule for all escalation levels.

    Returns the current on-call rotation schedule.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    schedules = incident_manager.on_call_schedule.get_all_schedules()

    return {
        "schedules": schedules,
        "current_on_call": {
            level: incident_manager.on_call_schedule.get_on_call_user(EscalationLevel(level))
            for level in schedules.keys()
        }
    }


@app.post("/incidents/on-call/add", response_model=Dict[str, Any])
async def add_on_call_user(
    level: str = Body(..., embed=True, description="Escalation level"),
    user: str = Body(..., embed=True, description="User email/ID")
):
    """
    Add user to on-call rotation.

    Adds a user to the on-call schedule for a specific escalation level.
    """
    if not incident_manager:
        raise HTTPException(status_code=503, detail="Incident manager not initialized")

    try:
        escalation_level = EscalationLevel(level)
        incident_manager.on_call_schedule.add_user(escalation_level, user)
        return {
            "success": True,
            "level": level,
            "user": user,
            "message": f"Added {user} to {level} on-call rotation"
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid escalation level")


# ============================================================================
# AI SOC Analytics Endpoints (v0.15.0)
# ============================================================================

@app.post("/analytics/comprehensive", response_model=Dict[str, Any])
async def analyze_comprehensive(event: SecurityEvent):
    """
    Perform comprehensive AI-powered SOC analysis on a security event.

    Returns:
    - Threat predictions
    - Risk scores
    - Behavioral profiles
    - Hunting hypotheses
    - Attack path analysis
    - Overall threat assessment
    """
    if not ai_soc_analytics:
        raise HTTPException(status_code=503, detail="AI SOC Analytics not initialized")

    try:
        results = ai_soc_analytics.analyze_comprehensive(event)
        return {
            "success": True,
            "event_id": event.event_id,
            "analysis": results,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error in comprehensive analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analytics/predict-threats", response_model=Dict[str, Any])
async def predict_threats(
    time_window_hours: int = Query(24, description="Prediction time window in hours"),
    limit: int = Query(10, description="Maximum number of predictions")
):
    """
    Predict future threats based on recent activity.

    Returns threat predictions with probability, severity, and recommended actions.
    """
    if not ai_soc_analytics:
        raise HTTPException(status_code=503, detail="AI SOC Analytics not initialized")

    try:
        recent_events = list(ai_soc_analytics.event_history)
        predictions = ai_soc_analytics.predictive_analytics.predict_threats(
            recent_events,
            time_window=timedelta(hours=time_window_hours)
        )

        return {
            "success": True,
            "predictions": [ai_soc_analytics._prediction_to_dict(p) for p in predictions[:limit]],
            "total_predictions": len(predictions),
            "time_window_hours": time_window_hours,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error predicting threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/analytics/risk-scores", response_model=Dict[str, Any])
async def get_risk_scores(
    entity_type: Optional[str] = Query(None, description="Filter by entity type (asset, user, threat)"),
    risk_level: Optional[str] = Query(None, description="Filter by risk level"),
    limit: int = Query(10, description="Maximum number of results")
):
    """
    Get risk scores for entities.

    Returns risk scores with contributing factors and confidence.
    """
    if not ai_soc_analytics:
        raise HTTPException(status_code=503, detail="AI SOC Analytics not initialized")

    try:
        all_risks = ai_soc_analytics.get_top_risks(limit=100)

        # Apply filters
        if entity_type:
            all_risks = [r for r in all_risks if r.entity_type == entity_type]
        if risk_level:
            all_risks = [r for r in all_risks if r.risk_level.value == risk_level]

        return {
            "success": True,
            "risk_scores": [ai_soc_analytics._risk_score_to_dict(r) for r in all_risks[:limit]],
            "total_count": len(all_risks),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting risk scores: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analytics/triage", response_model=Dict[str, Any])
async def triage_incident_ai(incident_id: str):
    """
    Perform AI-powered automated triage on an incident.

    Returns triage priority, threat category, and recommended actions.
    """
    if not ai_soc_analytics or not incident_manager:
        raise HTTPException(status_code=503, detail="AI SOC Analytics or Incident Manager not initialized")

    try:
        incident = incident_manager.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        recent_events = list(ai_soc_analytics.event_history)
        triage_result = ai_soc_analytics.triage_incident(incident, recent_events)

        return {
            "success": True,
            "incident_id": incident_id,
            "triage": {
                "priority": triage_result.triage_priority.value,
                "severity": triage_result.severity_assessment.value,
                "threat_category": triage_result.threat_category.value,
                "confidence": triage_result.confidence,
                "reasoning": triage_result.reasoning,
                "key_indicators": triage_result.key_indicators,
                "recommended_actions": triage_result.recommended_actions,
                "estimated_impact": triage_result.estimated_impact,
                "requires_escalation": triage_result.requires_escalation,
                "assigned_team": triage_result.assigned_team
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in AI triage: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analytics/hunting/generate-hypotheses", response_model=Dict[str, Any])
async def generate_hunting_hypotheses():
    """
    Generate threat hunting hypotheses based on recent activity.

    Returns hypotheses with indicators to search and recommended queries.
    """
    if not ai_soc_analytics:
        raise HTTPException(status_code=503, detail="AI SOC Analytics not initialized")

    try:
        recent_events = list(ai_soc_analytics.event_history)
        hypotheses = ai_soc_analytics.threat_hunting.generate_hypotheses(recent_events)

        return {
            "success": True,
            "hypotheses": [ai_soc_analytics._hypothesis_to_dict(h) for h in hypotheses],
            "total_count": len(hypotheses),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error generating hunting hypotheses: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analytics/hunting/execute", response_model=Dict[str, Any])
async def execute_threat_hunt(hypothesis_id: str):
    """
    Execute a threat hunt based on a hypothesis.

    Returns findings and updated hypothesis status.
    """
    if not ai_soc_analytics:
        raise HTTPException(status_code=503, detail="AI SOC Analytics not initialized")

    try:
        hypothesis = ai_soc_analytics.threat_hunting.hypotheses.get(hypothesis_id)
        if not hypothesis:
            raise HTTPException(status_code=404, detail="Hypothesis not found")

        recent_events = list(ai_soc_analytics.event_history)
        updated_hypothesis = ai_soc_analytics.hunt_threats(hypothesis, recent_events)

        return {
            "success": True,
            "hypothesis": ai_soc_analytics._hypothesis_to_dict(updated_hypothesis),
            "findings": updated_hypothesis.findings,
            "timestamp": datetime.utcnow().isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing threat hunt: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/analytics/behavioral-profiles", response_model=Dict[str, Any])
async def get_behavioral_profiles(
    entity_type: Optional[str] = Query(None, description="Filter by entity type (user, asset)"),
    anomalies_only: bool = Query(False, description="Show only entities with anomalies"),
    limit: int = Query(20, description="Maximum number of results")
):
    """
    Get behavioral profiles for users and entities.

    Returns UEBA profiles with anomaly detection results.
    """
    if not ai_soc_analytics:
        raise HTTPException(status_code=503, detail="AI SOC Analytics not initialized")

    try:
        all_profiles = list(ai_soc_analytics.behavioral_analytics.profiles.values())

        # Apply filters
        if entity_type:
            all_profiles = [p for p in all_profiles if p.entity_type == entity_type]
        if anomalies_only:
            all_profiles = [p for p in all_profiles if p.anomalous_behaviors]

        # Sort by risk score
        all_profiles.sort(key=lambda p: p.risk_score, reverse=True)

        return {
            "success": True,
            "profiles": [ai_soc_analytics._profile_to_dict(p) for p in all_profiles[:limit]],
            "total_count": len(all_profiles),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting behavioral profiles: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analytics/attack-path", response_model=Dict[str, Any])
async def analyze_attack_path(
    source: str = Body(..., embed=True, description="Source asset"),
    target: str = Body(..., embed=True, description="Target asset")
):
    """
    Analyze potential attack path from source to target.

    Returns attack path with techniques, blast radius, and mitigation steps.
    """
    if not ai_soc_analytics:
        raise HTTPException(status_code=503, detail="AI SOC Analytics not initialized")

    try:
        recent_events = list(ai_soc_analytics.event_history)
        attack_path = ai_soc_analytics.attack_path_analyzer.analyze_attack_path(
            source, target, recent_events
        )

        return {
            "success": True,
            "attack_path": ai_soc_analytics._attack_path_to_dict(attack_path),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error analyzing attack path: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/analytics/soc-metrics", response_model=Dict[str, Any])
async def get_soc_metrics():
    """
    Get SOC performance metrics.

    Returns comprehensive metrics on threat detection, response times, and accuracy.
    """
    if not ai_soc_analytics:
        raise HTTPException(status_code=503, detail="AI SOC Analytics not initialized")

    try:
        metrics = ai_soc_analytics.get_metrics()

        return {
            "success": True,
            "metrics": {
                "total_threats_predicted": metrics.total_threats_predicted,
                "threats_prevented": metrics.threats_prevented,
                "false_positives": metrics.false_positives,
                "true_positives": metrics.true_positives,
                "mean_time_to_detect_seconds": metrics.mean_time_to_detect,
                "mean_time_to_respond_seconds": metrics.mean_time_to_respond,
                "mean_time_to_resolve_seconds": metrics.mean_time_to_resolve,
                "triage_accuracy": metrics.triage_accuracy,
                "risk_score_accuracy": metrics.risk_score_accuracy,
                "hunting_success_rate": metrics.hunting_success_rate
            },
            "timestamp": metrics.timestamp.isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting SOC metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/analytics/dashboard-summary", response_model=Dict[str, Any])
async def get_analytics_dashboard_summary():
    """
    Get summary of all AI SOC analytics for dashboard display.

    Returns high-level overview of threats, risks, and SOC performance.
    """
    if not ai_soc_analytics:
        raise HTTPException(status_code=503, detail="AI SOC Analytics not initialized")

    try:
        # Get top threats
        recent_events = list(ai_soc_analytics.event_history)
        predictions = ai_soc_analytics.predictive_analytics.predict_threats(
            recent_events[-100:] if len(recent_events) > 100 else recent_events,
            time_window=timedelta(hours=24)
        )

        # Get top risks
        top_risks = ai_soc_analytics.get_top_risks(limit=5)

        # Get behavioral anomalies
        profiles_with_anomalies = [
            p for p in ai_soc_analytics.behavioral_analytics.profiles.values()
            if p.anomalous_behaviors
        ]

        # Get active hunting hypotheses
        active_hypotheses = [
            h for h in ai_soc_analytics.threat_hunting.hypotheses.values()
            if h.status == HuntingHypothesisStatus.ACTIVE
        ]

        # Get metrics
        metrics = ai_soc_analytics.get_metrics()

        return {
            "success": True,
            "summary": {
                "threat_predictions": {
                    "total": len(predictions),
                    "critical": sum(1 for p in predictions if p.predicted_severity == Severity.CRITICAL),
                    "high": sum(1 for p in predictions if p.predicted_severity == Severity.HIGH),
                    "top_predictions": [ai_soc_analytics._prediction_to_dict(p) for p in predictions[:3]]
                },
                "risk_assessment": {
                    "total_entities": len(ai_soc_analytics.risk_engine.risk_scores),
                    "critical_risk": sum(1 for r in top_risks if r.risk_level == RiskLevel.CRITICAL),
                    "high_risk": sum(1 for r in top_risks if r.risk_level == RiskLevel.HIGH),
                    "top_risks": [ai_soc_analytics._risk_score_to_dict(r) for r in top_risks]
                },
                "behavioral_analytics": {
                    "total_profiles": len(ai_soc_analytics.behavioral_analytics.profiles),
                    "anomalies_detected": len(profiles_with_anomalies),
                    "high_risk_entities": sum(1 for p in profiles_with_anomalies if p.risk_score > 0.7)
                },
                "threat_hunting": {
                    "active_hypotheses": len(active_hypotheses),
                    "total_findings": len(ai_soc_analytics.threat_hunting.findings)
                },
                "soc_performance": {
                    "mean_time_to_detect": metrics.mean_time_to_detect,
                    "mean_time_to_respond": metrics.mean_time_to_respond,
                    "triage_accuracy": metrics.triage_accuracy
                }
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Error getting analytics dashboard summary: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Streaming Analytics Endpoints (v0.16.0)
# ============================================================================

@app.post("/streaming/process", response_model=Dict[str, Any])
async def process_streaming_event(event: SecurityEvent):
    """
    Process event through streaming analytics pipeline.

    Returns:
    - Stream processing results
    - Pattern matches
    - Correlations
    - Window assignments
    """
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        result = await streaming_analytics.process_event(event)
        return result
    except Exception as e:
        logger.error(f"Error processing streaming event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/streaming/batch", response_model=Dict[str, Any])
async def process_streaming_batch(events: List[SecurityEvent]):
    """Process a batch of events through streaming analytics."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        result = await streaming_analytics.process_batch(events)
        return result
    except Exception as e:
        logger.error(f"Error processing streaming batch: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/streaming/windows", response_model=Dict[str, Any])
async def get_stream_windows(window_id: Optional[str] = Query(None)):
    """Get window aggregations from stream processor."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        aggregations = streaming_analytics.get_window_aggregations(window_id)

        return {
            "windows": [agg.dict() for agg in aggregations],
            "total_windows": len(aggregations)
        }
    except Exception as e:
        logger.error(f"Error getting stream windows: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/streaming/patterns", response_model=Dict[str, Any])
async def get_pattern_matches(
    pattern_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000)
):
    """Get CEP pattern matches."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        matches = streaming_analytics.get_pattern_matches(pattern_id, limit)

        return {
            "pattern_matches": [convert_pattern_match_to_dict(m) for m in matches],
            "total_matches": len(matches)
        }
    except Exception as e:
        logger.error(f"Error getting pattern matches: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/streaming/correlations", response_model=Dict[str, Any])
async def get_stream_correlations(
    correlation_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000)
):
    """Get streaming correlations."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        correlations = streaming_analytics.get_correlations(correlation_type, limit)

        return {
            "correlations": [convert_correlation_to_dict(c) for c in correlations],
            "total_correlations": len(correlations)
        }
    except Exception as e:
        logger.error(f"Error getting correlations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/streaming/cep-patterns", response_model=Dict[str, Any])
async def get_cep_patterns():
    """Get all registered CEP patterns."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        patterns = streaming_analytics.get_cep_patterns()

        return {
            "patterns": [
                {
                    "pattern_id": p.pattern_id,
                    "pattern_name": p.pattern_name,
                    "pattern_type": p.pattern_type.value,
                    "time_window_minutes": p.time_window.total_seconds() / 60,
                    "min_occurrences": p.min_occurrences,
                    "severity": p.severity.value,
                    "description": p.description
                }
                for p in patterns
            ],
            "total_patterns": len(patterns)
        }
    except Exception as e:
        logger.error(f"Error getting CEP patterns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/streaming/cep-patterns", response_model=Dict[str, Any])
async def add_cep_pattern(
    pattern_id: str = Body(...),
    pattern_name: str = Body(...),
    pattern_type: str = Body(...),
    conditions: List[Dict[str, Any]] = Body(...),
    time_window_minutes: int = Body(10),
    min_occurrences: int = Body(1),
    severity: str = Body("MEDIUM"),
    description: str = Body("")
):
    """Add a custom CEP pattern."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        from vaulytica.models import Severity

        pattern = create_custom_cep_pattern(
            pattern_id=pattern_id,
            pattern_name=pattern_name,
            pattern_type=PatternType(pattern_type),
            conditions=conditions,
            time_window_minutes=time_window_minutes,
            min_occurrences=min_occurrences,
            severity=Severity[severity],
            description=description
        )

        streaming_analytics.add_cep_pattern(pattern)

        return {
            "status": "success",
            "message": f"Pattern '{pattern_name}' added successfully",
            "pattern_id": pattern_id
        }
    except Exception as e:
        logger.error(f"Error adding CEP pattern: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/streaming/cep-patterns/{pattern_id}", response_model=Dict[str, Any])
async def remove_cep_pattern(pattern_id: str):
    """Remove a CEP pattern."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        success = streaming_analytics.remove_cep_pattern(pattern_id)

        if success:
            return {
                "status": "success",
                "message": f"Pattern '{pattern_id}' removed successfully"
            }
        else:
            raise HTTPException(status_code=404, detail=f"Pattern '{pattern_id}' not found")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing CEP pattern: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/streaming/replay", response_model=Dict[str, Any])
async def replay_events(
    start_time: Optional[str] = Body(None),
    end_time: Optional[str] = Body(None),
    speed: float = Body(1.0)
):
    """Replay historical events."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        from datetime import datetime

        start_dt = datetime.fromisoformat(start_time) if start_time else None
        end_dt = datetime.fromisoformat(end_time) if end_time else None

        result = await streaming_analytics.replay_events(
            start_time=start_dt,
            end_time=end_dt,
            speed=speed
        )

        return result
    except Exception as e:
        logger.error(f"Error replaying events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/streaming/replay/stop", response_model=Dict[str, Any])
async def stop_replay():
    """Stop ongoing event replay."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        streaming_analytics.stop_replay()

        return {
            "status": "success",
            "message": "Replay stopped"
        }
    except Exception as e:
        logger.error(f"Error stopping replay: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/streaming/time-travel", response_model=Dict[str, Any])
async def time_travel(
    timestamp: str = Query(...),
    window_minutes: int = Query(5)
):
    """Get events around a specific time (time travel)."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        from datetime import datetime, timedelta

        target_time = datetime.fromisoformat(timestamp)
        window = timedelta(minutes=window_minutes)

        events = streaming_analytics.get_events_at_time(target_time, window)

        return {
            "target_time": timestamp,
            "window_minutes": window_minutes,
            "events": [
                {
                    "event_id": e.event_id,
                    "title": e.title,
                    "severity": e.severity.value,
                    "timestamp": e.timestamp.isoformat()
                }
                for e in events
            ],
            "total_events": len(events)
        }
    except Exception as e:
        logger.error(f"Error in time travel: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/streaming/metrics", response_model=Dict[str, Any])
async def get_streaming_metrics():
    """Get comprehensive streaming analytics metrics."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        metrics = streaming_analytics.get_comprehensive_metrics()
        return metrics
    except Exception as e:
        logger.error(f"Error getting streaming metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/streaming/control/pause", response_model=Dict[str, Any])
async def pause_streaming():
    """Pause streaming analytics."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        streaming_analytics.pause()

        return {
            "status": "success",
            "message": "Streaming analytics paused"
        }
    except Exception as e:
        logger.error(f"Error pausing streaming: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/streaming/control/resume", response_model=Dict[str, Any])
async def resume_streaming():
    """Resume streaming analytics."""
    try:
        if not streaming_analytics:
            raise HTTPException(status_code=503, detail="Streaming analytics not initialized")

        streaming_analytics.resume()

        return {
            "status": "success",
            "message": "Streaming analytics resumed"
        }
    except Exception as e:
        logger.error(f"Error resuming streaming: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Forensics & Investigation Endpoints (v0.17.0)
# ============================================================================

@app.post("/forensics/evidence/collect", response_model=Dict[str, Any])
async def collect_evidence(
    evidence_type: EvidenceType,
    source: EvidenceSource,
    source_system: str,
    collected_by: str,
    collection_method: CollectionMethod = CollectionMethod.AUTOMATED,
    source_ip: Optional[str] = None,
    source_hostname: Optional[str] = None,
    source_path: Optional[str] = None,
    data: Optional[Dict[str, Any]] = None,
    tags: Optional[List[str]] = None
):
    """Collect evidence from a source."""
    try:
        evidence = await forensics_engine.evidence_collector.collect_evidence(
            evidence_type=evidence_type,
            source=source,
            source_system=source_system,
            collected_by=collected_by,
            collection_method=collection_method,
            source_ip=source_ip,
            source_hostname=source_hostname,
            source_path=source_path,
            data=data,
            tags=tags
        )
        return evidence.model_dump()
    except Exception as e:
        logger.error(f"Error collecting evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/forensics/evidence/{evidence_id}", response_model=Dict[str, Any])
async def get_evidence(evidence_id: str):
    """Get evidence by ID."""
    try:
        evidence = forensics_engine.evidence_collector.get_evidence(evidence_id)
        if not evidence:
            raise HTTPException(status_code=404, detail="Evidence not found")
        return evidence.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/forensics/evidence", response_model=Dict[str, Any])
async def list_evidence(
    evidence_type: Optional[EvidenceType] = None,
    source: Optional[EvidenceSource] = None,
    status: Optional[EvidenceStatus] = None,
    limit: int = 100
):
    """List evidence with optional filters."""
    try:
        evidence_list = forensics_engine.evidence_collector.list_evidence(
            evidence_type=evidence_type,
            source=source,
            status=status
        )
        return {
            "total": len(evidence_list),
            "evidence": [e.model_dump() for e in evidence_list[:limit]]
        }
    except Exception as e:
        logger.error(f"Error listing evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/forensics/evidence/{evidence_id}/custody", response_model=Dict[str, Any])
async def add_custody_entry(
    evidence_id: str,
    action: str,
    actor: str,
    location: str,
    purpose: str,
    notes: Optional[str] = None
):
    """Add chain of custody entry to evidence."""
    try:
        success = forensics_engine.evidence_collector.add_custody_entry(
            evidence_id=evidence_id,
            action=action,
            actor=actor,
            location=location,
            purpose=purpose,
            notes=notes
        )
        if not success:
            raise HTTPException(status_code=404, detail="Evidence not found")
        return {"status": "success", "message": "Custody entry added"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding custody entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/forensics/evidence/{evidence_id}/verify", response_model=Dict[str, Any])
async def verify_evidence_integrity(evidence_id: str):
    """Verify evidence integrity."""
    try:
        is_valid, message = forensics_engine.evidence_collector.verify_integrity(evidence_id)
        return {
            "evidence_id": evidence_id,
            "is_valid": is_valid,
            "message": message
        }
    except Exception as e:
        logger.error(f"Error verifying evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/forensics/evidence/{evidence_id}/analyze", response_model=Dict[str, Any])
async def analyze_evidence(
    evidence_id: str,
    analysis_type: AnalysisType,
    analyzed_by: str,
    analysis_tool: Optional[str] = None
):
    """Analyze evidence."""
    try:
        result = await forensics_engine.evidence_analyzer.analyze_evidence(
            evidence_id=evidence_id,
            analysis_type=analysis_type,
            analyzed_by=analyzed_by,
            analysis_tool=analysis_tool
        )
        return result.model_dump()
    except Exception as e:
        logger.error(f"Error analyzing evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/forensics/investigations", response_model=Dict[str, Any])
async def create_investigation(
    investigation_type: InvestigationType,
    title: str,
    description: str,
    severity: Severity,
    lead_investigator: str,
    related_incidents: Optional[List[str]] = None,
    related_events: Optional[List[str]] = None,
    use_template: bool = True
):
    """Create a new investigation."""
    try:
        investigation = forensics_engine.investigation_manager.create_investigation(
            investigation_type=investigation_type,
            title=title,
            description=description,
            severity=severity,
            lead_investigator=lead_investigator,
            related_incidents=related_incidents,
            related_events=related_events,
            use_template=use_template
        )
        return investigation.model_dump()
    except Exception as e:
        logger.error(f"Error creating investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/forensics/investigations/{investigation_id}", response_model=Dict[str, Any])
async def get_investigation(investigation_id: str):
    """Get investigation by ID."""
    try:
        investigation = forensics_engine.investigation_manager.get_investigation(investigation_id)
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return investigation.model_dump()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting investigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/forensics/investigations", response_model=Dict[str, Any])
async def list_investigations(
    investigation_type: Optional[InvestigationType] = None,
    status: Optional[InvestigationStatus] = None,
    lead_investigator: Optional[str] = None,
    limit: int = 100
):
    """List investigations with optional filters."""
    try:
        investigations = forensics_engine.investigation_manager.list_investigations(
            investigation_type=investigation_type,
            status=status,
            lead_investigator=lead_investigator
        )
        return {
            "total": len(investigations),
            "investigations": [i.model_dump() for i in investigations[:limit]]
        }
    except Exception as e:
        logger.error(f"Error listing investigations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/forensics/investigations/{investigation_id}/evidence", response_model=Dict[str, Any])
async def link_evidence_to_investigation(
    investigation_id: str,
    evidence_id: str
):
    """Link evidence to investigation."""
    try:
        success = forensics_engine.investigation_manager.add_evidence_to_investigation(
            investigation_id=investigation_id,
            evidence_id=evidence_id
        )
        if not success:
            raise HTTPException(status_code=404, detail="Investigation or evidence not found")
        return {"status": "success", "message": "Evidence linked to investigation"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error linking evidence: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/forensics/investigations/{investigation_id}/tasks/{task_id}", response_model=Dict[str, Any])
async def update_task_status(
    investigation_id: str,
    task_id: str,
    status: str,
    findings: Optional[str] = None,
    assigned_to: Optional[str] = None
):
    """Update investigation task status."""
    try:
        success = forensics_engine.investigation_manager.update_task_status(
            investigation_id=investigation_id,
            task_id=task_id,
            status=status,
            findings=findings,
            assigned_to=assigned_to
        )
        if not success:
            raise HTTPException(status_code=404, detail="Investigation or task not found")
        return {"status": "success", "message": "Task updated"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/forensics/investigations/{investigation_id}/report", response_model=Dict[str, Any])
async def generate_forensic_report(
    investigation_id: str,
    format: str = "markdown"
):
    """Generate forensic investigation report."""
    try:
        report = forensics_engine.report_generator.generate_report(
            investigation_id=investigation_id,
            format=format
        )
        return {
            "investigation_id": investigation_id,
            "format": format,
            "report": report
        }
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/forensics/investigations/from-event", response_model=Dict[str, Any])
async def create_investigation_from_event(
    event: SecurityEvent,
    lead_investigator: str
):
    """Create investigation from security event."""
    try:
        investigation = await forensics_engine.create_investigation_from_event(
            event=event,
            lead_investigator=lead_investigator
        )
        return investigation.model_dump()
    except Exception as e:
        logger.error(f"Error creating investigation from event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/forensics/metrics", response_model=Dict[str, Any])
async def get_forensics_metrics():
    """Get comprehensive forensics metrics."""
    try:
        return forensics_engine.get_comprehensive_metrics()
    except Exception as e:
        logger.error(f"Error getting forensics metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Threat Hunting Endpoints (v0.18.0)
# ============================================================================

@app.post("/threat-hunting/campaigns")
async def create_hunt_campaign(
    name: str,
    description: str,
    hunt_type: str,
    hypothesis: str,
    priority: int = 3,
    assigned_to: Optional[str] = None
):
    """Create a new threat hunting campaign."""
    try:
        from vaulytica.threat_hunting import get_threat_hunting_engine, HuntType
        engine = get_threat_hunting_engine()

        campaign = await engine.create_campaign(
            name=name,
            description=description,
            hunt_type=HuntType(hunt_type),
            hypothesis=hypothesis,
            priority=priority,
            assigned_to=assigned_to
        )
        return campaign.to_dict()
    except Exception as e:
        logger.error(f"Error creating hunt campaign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/threat-hunting/campaigns/{hunt_id}/start")
async def start_hunt_campaign(hunt_id: str):
    """Start a threat hunting campaign."""
    try:
        from vaulytica.threat_hunting import get_threat_hunting_engine
        engine = get_threat_hunting_engine()
        campaign = await engine.start_campaign(hunt_id)
        return campaign.to_dict()
    except Exception as e:
        logger.error(f"Error starting hunt campaign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/threat-hunting/campaigns/{hunt_id}/execute")
async def execute_hunt_campaign(hunt_id: str, simulate: bool = True):
    """Execute all queries in a hunt campaign."""
    try:
        engine = get_threat_hunting_engine()
        result = await engine.execute_campaign(hunt_id, simulate=simulate)
        return result
    except Exception as e:
        logger.error(f"Error executing hunt campaign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-hunting/campaigns")
async def list_hunt_campaigns(status: Optional[str] = None, limit: int = 100):
    """List threat hunting campaigns."""
    try:
        from vaulytica.threat_hunting import get_threat_hunting_engine, HuntStatus
        engine = get_threat_hunting_engine()

        hunt_status = HuntStatus(status) if status else None
        campaigns = engine.list_campaigns(status=hunt_status, limit=limit)
        return [c.to_dict() for c in campaigns]
    except Exception as e:
        logger.error(f"Error listing hunt campaigns: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-hunting/campaigns/{hunt_id}")
async def get_hunt_campaign(hunt_id: str):
    """Get a specific hunt campaign."""
    try:
        engine = get_threat_hunting_engine()
        campaign = engine.get_campaign(hunt_id)
        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")
        return campaign.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting hunt campaign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/threat-hunting/ioc-hunt")
async def create_ioc_hunt(ioc: str, ioc_type: str, name: Optional[str] = None):
    """Generate a hunt campaign from an IOC."""
    try:
        engine = get_threat_hunting_engine()
        campaign = await engine.generate_hunt_from_ioc(ioc, ioc_type, name)
        return campaign.to_dict()
    except Exception as e:
        logger.error(f"Error creating IOC hunt: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-hunting/statistics")
async def get_threat_hunting_statistics():
    """Get threat hunting statistics."""
    try:
        engine = get_threat_hunting_engine()
        return engine.get_statistics()
    except Exception as e:
        logger.error(f"Error getting threat hunting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# SOAR Platform Endpoints (v0.18.0)
# ============================================================================

@app.post("/soar/workflows")
async def create_workflow(
    name: str,
    description: str,
    trigger_type: str,
    actions: List[Dict[str, Any]],
    created_by: Optional[str] = None
):
    """Create a new SOAR workflow."""
    try:
        from vaulytica.soar import get_soar_platform, WorkflowAction, ActionType
        platform = get_soar_platform()

        # Convert action dicts to WorkflowAction objects
        workflow_actions = [
            WorkflowAction(
                action_id=a["action_id"],
                action_type=ActionType(a["action_type"]),
                name=a["name"],
                description=a["description"],
                parameters=a.get("parameters", {}),
                on_success=a.get("on_success"),
                on_failure=a.get("on_failure")
            )
            for a in actions
        ]

        workflow = await platform.create_workflow(
            name=name,
            description=description,
            trigger_type=trigger_type,
            actions=workflow_actions,
            created_by=created_by
        )
        return workflow.to_dict()
    except Exception as e:
        logger.error(f"Error creating workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/soar/workflows/{workflow_id}/execute")
async def execute_workflow(workflow_id: str, context: Optional[Dict[str, Any]] = None):
    """Execute a SOAR workflow."""
    try:
        from vaulytica.soar import get_soar_platform
        platform = get_soar_platform()
        result = await platform.execute_workflow(workflow_id, context)
        return result
    except Exception as e:
        logger.error(f"Error executing workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/soar/workflows")
async def list_workflows(status: Optional[str] = None, limit: int = 100):
    """List SOAR workflows."""
    try:
        from vaulytica.soar import get_soar_platform, WorkflowStatus
        platform = get_soar_platform()

        workflow_status = WorkflowStatus(status) if status else None
        workflows = platform.list_workflows(status=workflow_status, limit=limit)
        return [w.to_dict() for w in workflows]
    except Exception as e:
        logger.error(f"Error listing workflows: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/soar/cases")
async def create_case(
    title: str,
    description: str,
    priority: str,
    assigned_to: Optional[str] = None,
    tags: Optional[List[str]] = None
):
    """Create a new security case."""
    try:
        from vaulytica.soar import get_soar_platform, CasePriority
        platform = get_soar_platform()

        case = await platform.create_case(
            title=title,
            description=description,
            priority=CasePriority(priority),
            assigned_to=assigned_to,
            tags=tags
        )
        return case.to_dict()
    except Exception as e:
        logger.error(f"Error creating case: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/soar/cases")
async def list_cases(status: Optional[str] = None, limit: int = 100):
    """List security cases."""
    try:
        from vaulytica.soar import get_soar_platform, CaseStatus
        platform = get_soar_platform()

        case_status = CaseStatus(status) if status else None
        cases = platform.list_cases(status=case_status, limit=limit)
        return [c.to_dict() for c in cases]
    except Exception as e:
        logger.error(f"Error listing cases: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/soar/statistics")
async def get_soar_statistics():
    """Get SOAR platform statistics."""
    try:
        platform = get_soar_platform()
        return platform.get_statistics()
    except Exception as e:
        logger.error(f"Error getting SOAR statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Compliance & Audit Endpoints (v0.18.0)
# ============================================================================

@app.post("/compliance/assess/{framework}")
async def assess_compliance_framework(framework: str, assessed_by: Optional[str] = None):
    """Perform a compliance assessment for a framework."""
    try:
        from vaulytica.compliance import get_compliance_engine, ComplianceFramework
        engine = get_compliance_engine()

        assessment = await engine.assess_framework(
            ComplianceFramework(framework),
            assessed_by=assessed_by
        )
        return assessment.to_dict()
    except Exception as e:
        logger.error(f"Error assessing compliance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/compliance/report/{framework}")
async def get_compliance_report(framework: str, include_evidence: bool = False):
    """Generate a compliance report for a framework."""
    try:
        engine = get_compliance_engine()

        report = await engine.generate_compliance_report(
            ComplianceFramework(framework),
            include_evidence=include_evidence
        )
        return report
    except Exception as e:
        logger.error(f"Error generating compliance report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/compliance/gaps/{framework}")
async def get_compliance_gaps(framework: str):
    """Identify compliance gaps for a framework."""
    try:
        engine = get_compliance_engine()

        gaps = await engine.identify_gaps(ComplianceFramework(framework))
        return gaps
    except Exception as e:
        logger.error(f"Error identifying compliance gaps: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/compliance/audit-log")
async def log_audit_event(
    user: str,
    action: str,
    resource: str,
    result: str,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None
):
    """Log an audit event."""
    try:
        from vaulytica.compliance import get_compliance_engine
        engine = get_compliance_engine()

        audit_log = await engine.log_audit_event(
            user=user,
            action=action,
            resource=resource,
            result=result,
            details=details,
            ip_address=ip_address
        )
        return audit_log.to_dict()
    except Exception as e:
        logger.error(f"Error logging audit event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/compliance/audit-logs")
async def get_audit_logs(
    user: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 1000
):
    """Retrieve audit logs with filtering."""
    try:
        engine = get_compliance_engine()

        logs = engine.get_audit_logs(user=user, action=action, limit=limit)
        return [log.to_dict() for log in logs]
    except Exception as e:
        logger.error(f"Error getting audit logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/compliance/assessments")
async def list_compliance_assessments(framework: Optional[str] = None, limit: int = 100):
    """List compliance assessments."""
    try:
        engine = get_compliance_engine()

        fw = ComplianceFramework(framework) if framework else None
        assessments = engine.list_assessments(framework=fw, limit=limit)
        return [a.to_dict() for a in assessments]
    except Exception as e:
        logger.error(f"Error listing assessments: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/compliance/statistics")
async def get_compliance_statistics():
    """Get compliance engine statistics."""
    try:
        engine = get_compliance_engine()
        return engine.get_statistics()
    except Exception as e:
        logger.error(f"Error getting compliance statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Threat Intelligence Integration Endpoints (v0.19.0)
# ============================================================================

@app.post("/threat-intel/enrich")
async def enrich_ioc(
    ioc: str,
    ioc_type: str,
    sources: Optional[List[str]] = None
):
    """Enrich IOC with external threat intelligence."""
    try:
        from vaulytica.threat_intel_integration import get_threat_intel_integration, IOCType, ThreatIntelSource

        integration = get_threat_intel_integration()
        ioc_type_enum = IOCType(ioc_type.upper())

        # Convert sources if provided
        source_enums = None
        if sources:
            source_enums = [ThreatIntelSource(s.upper()) for s in sources]

        intel = await integration.enrich_ioc(ioc, ioc_type_enum, source_enums)
        return intel.to_dict()
    except Exception as e:
        logger.error(f"Error enriching IOC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/threat-intel/batch-enrich")
async def batch_enrich_iocs(
    iocs: List[Dict[str, str]],
    max_concurrent: int = 10
):
    """Batch enrich multiple IOCs."""
    try:
        from vaulytica.threat_intel_integration import get_threat_intel_integration, IOCType

        integration = get_threat_intel_integration()

        # Convert to tuples
        ioc_tuples = [(item["ioc"], IOCType(item["ioc_type"].upper())) for item in iocs]

        results = await integration.batch_enrich(ioc_tuples, max_concurrent)
        return [intel.to_dict() for intel in results]
    except Exception as e:
        logger.error(f"Error batch enriching IOCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-intel/mitre/{technique_id}")
async def get_mitre_technique(technique_id: str):
    """Get MITRE ATT&CK technique information."""
    try:
        from vaulytica.threat_intel_integration import get_threat_intel_integration

        integration = get_threat_intel_integration()
        technique = integration.get_mitre_technique(technique_id)

        if not technique:
            raise HTTPException(status_code=404, detail="Technique not found")

        return technique.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting MITRE technique: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-intel/mitre/search")
async def search_mitre_techniques(
    tactic: Optional[str] = None,
    platform: Optional[str] = None,
    keyword: Optional[str] = None
):
    """Search MITRE ATT&CK techniques."""
    try:

        integration = get_threat_intel_integration()
        techniques = integration.search_mitre_techniques(tactic, platform, keyword)

        return [t.to_dict() for t in techniques]
    except Exception as e:
        logger.error(f"Error searching MITRE techniques: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threat-intel/statistics")
async def get_threat_intel_statistics():
    """Get threat intelligence integration statistics."""
    try:

        integration = get_threat_intel_integration()
        return integration.get_statistics()
    except Exception as e:
        logger.error(f"Error getting threat intel statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Advanced Automation Endpoints (v0.19.0)
# ============================================================================

@app.post("/automation/generate-hypothesis")
async def generate_hypothesis(context: Dict[str, Any]):
    """Generate threat hunting hypothesis from context."""
    try:
        from vaulytica.advanced_automation import get_advanced_automation

        automation = get_advanced_automation()
        hypothesis = await automation.generate_hypothesis(context)

        return hypothesis.to_dict()
    except Exception as e:
        logger.error(f"Error generating hypothesis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/automation/remediation-plan")
async def create_remediation_plan(incident_data: Dict[str, Any]):
    """Create automated remediation plan."""
    try:

        automation = get_advanced_automation()
        plan = await automation.create_remediation_plan(incident_data)

        return plan.to_dict()
    except Exception as e:
        logger.error(f"Error creating remediation plan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/automation/remediation-plan/{plan_id}/approve")
async def approve_remediation_plan(plan_id: str, approved_by: str):
    """Approve remediation plan."""
    try:

        automation = get_advanced_automation()
        success = automation.approve_remediation_plan(plan_id, approved_by)

        if not success:
            raise HTTPException(status_code=404, detail="Plan not found")

        return {"success": True, "plan_id": plan_id, "approved_by": approved_by}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error approving remediation plan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/automation/remediation-plan/{plan_id}/execute")
async def execute_remediation_plan(plan_id: str, dry_run: bool = False):
    """Execute remediation plan."""
    try:

        automation = get_advanced_automation()
        result = await automation.execute_remediation_plan(plan_id, dry_run)

        return result
    except Exception as e:
        logger.error(f"Error executing remediation plan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/automation/hypotheses")
async def list_hypotheses(limit: int = 100):
    """List generated hypotheses."""
    try:

        automation = get_advanced_automation()
        hypotheses = list(automation.hypotheses.values())[:limit]

        return [h.to_dict() for h in hypotheses]
    except Exception as e:
        logger.error(f"Error listing hypotheses: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/automation/remediation-plans")
async def list_remediation_plans(status: Optional[str] = None, limit: int = 100):
    """List remediation plans."""
    try:

        automation = get_advanced_automation()
        plans = list(automation.remediation_plans.values())

        # Filter by status if provided
        if status:
            plans = [p for p in plans if p.status == status]

        plans = plans[:limit]
        return [p.to_dict() for p in plans]
    except Exception as e:
        logger.error(f"Error listing remediation plans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/automation/statistics")
async def get_automation_statistics():
    """Get automation engine statistics."""
    try:

        automation = get_advanced_automation()
        return automation.get_statistics()
    except Exception as e:
        logger.error(f"Error getting automation statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Datadog Case Management Integration Endpoints (v0.20.0)
# ============================================================================

@app.post("/datadog/cases")
async def create_datadog_case(
    incident_id: str,
    api_key: Optional[str] = None,
    app_key: Optional[str] = None
):
    """
    Create Datadog case from Vaulytica incident.

    Creates a new case in Datadog Case Management and establishes
    bidirectional sync mapping.
    """
    try:
        from vaulytica.datadog_integration import get_datadog_case_manager
        from vaulytica.incidents import get_incident_manager

        # Get incident
        incident_manager = get_incident_manager()
        incident = incident_manager.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

        # Get case manager
        case_manager = get_datadog_case_manager(api_key, app_key)

        # Create case
        case = await case_manager.create_case_from_incident(incident, None)
        if not case:
            raise HTTPException(status_code=500, detail="Failed to create Datadog case")

        return {
            "status": "success",
            "incident_id": incident_id,
            "case_id": case.case_id,
            "case": case.to_dict()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating Datadog case: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/datadog/cases/{case_id}")
async def get_datadog_case(
    case_id: str,
    api_key: Optional[str] = None,
    app_key: Optional[str] = None
):
    """Get Datadog case by ID."""
    try:

        case_manager = get_datadog_case_manager(api_key, app_key)
        case = await case_manager.api_client.get_case(case_id)

        if not case:
            raise HTTPException(status_code=404, detail=f"Case {case_id} not found")

        return case.to_dict()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting Datadog case: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/datadog/cases")
async def list_datadog_cases(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    limit: int = 100,
    api_key: Optional[str] = None,
    app_key: Optional[str] = None
):
    """List Datadog cases with optional filters."""
    try:
        from vaulytica.datadog_integration import (
            get_datadog_case_manager,
            DatadogCaseStatus,
            DatadogCasePriority
        )

        case_manager = get_datadog_case_manager(api_key, app_key)

        # Parse filters
        status_filter = DatadogCaseStatus(status) if status else None
        priority_filter = DatadogCasePriority(priority) if priority else None

        # List cases
        cases = await case_manager.api_client.list_cases(
            status=status_filter,
            priority=priority_filter,
            limit=limit
        )

        return {
            "total": len(cases),
            "cases": [case.to_dict() for case in cases]
        }

    except Exception as e:
        logger.error(f"Error listing Datadog cases: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/datadog/cases/{case_id}/sync")
async def sync_incident_to_case(
    case_id: str,
    incident_id: str,
    api_key: Optional[str] = None,
    app_key: Optional[str] = None
):
    """Sync Vaulytica incident updates to Datadog case."""
    try:

        # Get incident
        incident_manager = get_incident_manager()
        incident = incident_manager.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

        # Get case manager
        case_manager = get_datadog_case_manager(api_key, app_key)

        # Sync
        success = await case_manager.sync_incident_to_case(incident, case_id)

        return {
            "status": "success" if success else "failed",
            "incident_id": incident_id,
            "case_id": case_id,
            "synced": success
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error syncing incident to case: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/datadog/mappings")
async def get_datadog_mappings(
    api_key: Optional[str] = None,
    app_key: Optional[str] = None
):
    """Get all incident-to-case sync mappings."""
    try:

        case_manager = get_datadog_case_manager(api_key, app_key)

        mappings = []
        for incident_id, mapping in case_manager.mappings.items():
            mappings.append({
                "incident_id": mapping.incident_id,
                "case_id": mapping.case_id,
                "last_synced": mapping.last_synced.isoformat(),
                "sync_direction": mapping.sync_direction,
                "metadata": mapping.metadata
            })

        return {
            "total": len(mappings),
            "mappings": mappings
        }

    except Exception as e:
        logger.error(f"Error getting mappings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/datadog/statistics")
async def get_datadog_statistics(
    api_key: Optional[str] = None,
    app_key: Optional[str] = None
):
    """Get Datadog integration statistics."""
    try:

        case_manager = get_datadog_case_manager(api_key, app_key)

        return {
            "case_manager": case_manager.get_statistics(),
            "api_client": case_manager.api_client.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error getting Datadog statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/datadog/test")
async def run_datadog_tests(
    api_key: Optional[str] = None,
    app_key: Optional[str] = None,
    site: str = "datadoghq.com"
):
    """Run live Datadog integration tests."""
    try:
        from vaulytica.datadog_live_testing import run_live_tests

        suite = await run_live_tests(api_key, app_key, site)

        return suite.to_dict()

    except Exception as e:
        logger.error(f"Error running Datadog tests: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Unified Ticketing Endpoints
# ============================================================================

@app.post("/ticketing/create")
async def create_tickets_for_incident(
    incident_id: str,
    platforms: Optional[List[str]] = None
):
    """
    Create tickets across multiple platforms for an incident.

    Args:
        incident_id: Vaulytica incident ID
        platforms: List of platforms (servicenow, jira, pagerduty, datadog)
    """
    try:
        from vaulytica.ticketing import (
            get_unified_ticketing_manager,
            create_ticketing_config_from_env,
            TicketingPlatform
        )

        # Get or create ticketing manager
        ticketing_config = create_ticketing_config_from_env()
        manager = get_unified_ticketing_manager(ticketing_config)

        # Get incident
        incident_manager = get_incident_manager()
        incident = incident_manager.get_incident(incident_id)

        if not incident:
            raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

        # Parse platforms
        platform_list = None
        if platforms:
            platform_list = [TicketingPlatform(p) for p in platforms]

        # Create tickets
        tickets = await manager.create_tickets_for_incident(
            incident,
            analysis=None,
            platforms=platform_list
        )

        return {
            "status": "success",
            "incident_id": incident_id,
            "tickets_created": len(tickets),
            "tickets": [
                {
                    "platform": t.platform.value,
                    "ticket_id": t.ticket_id,
                    "ticket_number": t.ticket_number,
                    "title": t.title,
                    "status": t.status,
                    "priority": t.priority,
                    "url": t.url
                }
                for t in tickets
            ]
        }

    except Exception as e:
        logger.error(f"Error creating tickets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ticketing/tickets/{incident_id}")
async def get_tickets_for_incident(incident_id: str):
    """Get all tickets for an incident."""
    try:
        from vaulytica.ticketing import get_unified_ticketing_manager

        manager = get_unified_ticketing_manager()
        tickets = manager.get_tickets_for_incident(incident_id)

        return {
            "status": "success",
            "incident_id": incident_id,
            "ticket_count": len(tickets),
            "tickets": [
                {
                    "platform": t.platform.value,
                    "ticket_id": t.ticket_id,
                    "ticket_number": t.ticket_number,
                    "title": t.title,
                    "status": t.status,
                    "priority": t.priority,
                    "created_at": t.created_at.isoformat(),
                    "updated_at": t.updated_at.isoformat(),
                    "url": t.url,
                    "assignee": t.assignee
                }
                for t in tickets
            ]
        }

    except Exception as e:
        logger.error(f"Error getting tickets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ticketing/statistics")
async def get_ticketing_statistics():
    """Get unified ticketing statistics."""
    try:

        manager = get_unified_ticketing_manager()
        stats = manager.get_statistics()

        return {
            "status": "success",
            "statistics": stats
        }

    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CSPM & Vulnerability Management Endpoints
# ============================================================================

@app.post("/cspm/scan")
async def scan_cloud_resources(
    provider: str = "aws",
    region: Optional[str] = None
):
    """
    Scan cloud resources.

    Args:
        provider: Cloud provider (aws, azure, gcp)
        region: Region to scan (AWS only)
    """
    try:
        from vaulytica.cspm import get_cloud_scanner, CloudProvider

        scanner = get_cloud_scanner()

        if provider == "aws":
            resources = await scanner.scan_aws_resources(region or "us-east-1")
        elif provider == "azure":
            resources = await scanner.scan_azure_resources("subscription-id")
        elif provider == "gcp":
            resources = await scanner.scan_gcp_resources("project-id")
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")

        return {
            "status": "success",
            "provider": provider,
            "resources_discovered": len(resources),
            "resources": [
                {
                    "resource_id": r.resource_id,
                    "resource_type": r.resource_type.value,
                    "name": r.name,
                    "region": r.region,
                    "tags": r.tags
                }
                for r in resources
            ]
        }

    except Exception as e:
        logger.error(f"Error scanning resources: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cspm/assess")
async def assess_compliance(
    provider: str = "aws",
    frameworks: Optional[List[str]] = None
):
    """
    Run compliance assessment.

    Args:
        provider: Cloud provider
        frameworks: Compliance frameworks to check
    """
    try:
        from vaulytica.cspm import get_cspm_orchestrator, CloudProvider, ComplianceFramework

        orchestrator = get_cspm_orchestrator()

        # Parse frameworks
        framework_list = None
        if frameworks:
            framework_list = [ComplianceFramework(f) for f in frameworks]

        # Run assessment
        results = await orchestrator.run_full_assessment(
            provider=CloudProvider(provider),
            frameworks=framework_list
        )

        return {
            "status": "success",
            **results
        }

    except Exception as e:
        logger.error(f"Error assessing compliance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cspm/findings")
async def get_compliance_findings(
    severity: Optional[str] = None,
    framework: Optional[str] = None
):
    """Get compliance findings."""
    try:
        from vaulytica.cspm import get_compliance_engine, Severity, ComplianceFramework

        engine = get_compliance_engine()

        if severity:
            findings = engine.get_findings_by_severity(Severity(severity))
        else:
            findings = list(engine.findings.values())

        if framework:
            findings = [f for f in findings if f.check.framework.value == framework]

        return {
            "status": "success",
            "findings_count": len(findings),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "resource_id": f.resource.resource_id,
                    "resource_name": f.resource.name,
                    "framework": f.check.framework.value,
                    "risk_score": f.risk_score,
                    "remediation": f.remediation
                }
                for f in findings
            ]
        }

    except Exception as e:
        logger.error(f"Error getting findings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cspm/drift/check")
async def check_configuration_drift():
    """Check configuration drift for all resources."""
    try:
        from vaulytica.cspm import get_cloud_scanner, get_drift_engine

        scanner = get_cloud_scanner()
        drift_engine = get_drift_engine()

        # Get all resources
        resources = list(scanner.resources.values())

        # Check drift
        detections = await drift_engine.check_all_resources(resources)

        drifted = [d for d in detections if d.drifted]

        return {
            "status": "success",
            "total_resources": len(resources),
            "drifted_resources": len(drifted),
            "drift_rate": (len(drifted) / len(resources) * 100) if resources else 0,
            "drifted": [
                {
                    "resource_id": d.resource.resource_id,
                    "resource_name": d.resource.name,
                    "resource_type": d.resource.resource_type.value,
                    "drift_details": d.drift_details,
                    "detected_at": d.detected_at.isoformat()
                }
                for d in drifted
            ]
        }

    except Exception as e:
        logger.error(f"Error checking drift: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/vulnerability/scan")
async def scan_vulnerabilities():
    """Scan all resources for vulnerabilities."""
    try:
        from vaulytica.cspm import get_cloud_scanner
        from vaulytica.vulnerability_management import get_vulnerability_scanner

        scanner = get_cloud_scanner()
        vuln_scanner = get_vulnerability_scanner()

        # Get all resources
        resources = list(scanner.resources.values())

        # Scan for vulnerabilities
        assessments = await vuln_scanner.scan_all_resources(resources)

        return {
            "status": "success",
            "resources_scanned": len(resources),
            "assessments": [
                {
                    "assessment_id": a.assessment_id,
                    "resource_id": a.resource.resource_id,
                    "resource_name": a.resource.name,
                    "vulnerabilities_found": len(a.vulnerabilities),
                    "risk_score": a.risk_score,
                    "priority": a.priority.value,
                    "vulnerabilities": [
                        {
                            "cve_id": v.cve_id,
                            "title": v.title,
                            "severity": v.severity.value,
                            "cvss_score": v.cvss_v3_score,
                            "exploit_available": v.exploit_available,
                            "patch_available": v.patch_available
                        }
                        for v in a.vulnerabilities
                    ]
                }
                for a in assessments
            ]
        }

    except Exception as e:
        logger.error(f"Error scanning vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/remediation/plan")
async def create_remediation_plan(
    resource_id: str,
    finding_id: Optional[str] = None,
    vulnerability_id: Optional[str] = None
):
    """Create remediation plan for a finding or vulnerability."""
    try:
        from vaulytica.cspm import get_cloud_scanner, get_compliance_engine
        from vaulytica.remediation import get_remediation_engine

        scanner = get_cloud_scanner()
        remediation_engine = get_remediation_engine()

        # Get resource
        resource = scanner.get_resource(resource_id)
        if not resource:
            raise HTTPException(status_code=404, detail=f"Resource {resource_id} not found")

        # Get finding or vulnerability
        finding = None
        vulnerability = None

        if finding_id:
            compliance_engine = get_compliance_engine()
            finding = compliance_engine.get_finding(finding_id)

        if vulnerability_id:
            vuln_scanner = get_vulnerability_scanner()
            vulnerability = vuln_scanner.get_assessment(vulnerability_id)

        # Create plan
        plan = await remediation_engine.create_remediation_plan(
            resource=resource,
            finding=finding,
            vulnerability=vulnerability
        )

        return {
            "status": "success",
            "plan": {
                "plan_id": plan.plan_id,
                "title": plan.title,
                "description": plan.description,
                "remediation_type": plan.remediation_type.value,
                "status": plan.status.value,
                "steps": plan.steps,
                "iac_template": plan.iac_template,
                "iac_format": plan.iac_format.value if plan.iac_format else None,
                "estimated_effort": plan.estimated_effort,
                "risk_of_change": plan.risk_of_change,
                "requires_downtime": plan.requires_downtime,
                "requires_approval": plan.requires_approval
            }
        }

    except Exception as e:
        logger.error(f"Error creating remediation plan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/remediation/execute")
async def execute_remediation_plan(
    plan_id: str,
    dry_run: bool = True
):
    """Execute a remediation plan."""
    try:

        remediation_engine = get_remediation_engine()

        # Execute plan
        result = await remediation_engine.execute_plan(plan_id, dry_run=dry_run)

        return {
            "status": "success",
            **result
        }

    except Exception as e:
        logger.error(f"Error executing remediation plan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cspm/statistics")
async def get_cspm_statistics():
    """Get CSPM statistics."""
    try:
        from vaulytica.cspm import get_cspm_orchestrator

        orchestrator = get_cspm_orchestrator()
        vuln_scanner = get_vulnerability_scanner()
        remediation_engine = get_remediation_engine()

        return {
            "status": "success",
            "cspm": orchestrator.get_unified_statistics(),
            "vulnerabilities": vuln_scanner.get_statistics(),
            "remediation": remediation_engine.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error getting CSPM statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Container Security & Kubernetes Security Endpoints (v0.23.0)
# ============================================================================

@app.post("/container/scan")
async def scan_container_image(
    image_ref: str = Query(..., description="Container image reference (e.g., nginx:1.21)"),
    registry: Optional[str] = Query(None, description="Container registry URL")
):
    """
    Scan container image for vulnerabilities.

    Performs layer-by-layer analysis, package scanning, and CVE detection.
    """
    try:
        from vaulytica.container_security import get_container_scanner

        scanner = get_container_scanner()
        scan_result = await scanner.scan_image(image_ref, registry)

        return {
            "status": "success",
            "scan_id": scan_result.scan_id,
            "image": {
                "repository": scan_result.image.repository,
                "tag": scan_result.image.tag,
                "digest": scan_result.image.digest,
                "size_mb": scan_result.image.size_bytes / 1_000_000
            },
            "vulnerabilities": {
                "total": len(scan_result.vulnerabilities),
                "by_severity": scan_result.get_vulnerability_count_by_severity(),
                "details": [
                    {
                        "cve_id": v.cve_id,
                        "package": v.package_name,
                        "version": v.package_version,
                        "fixed_version": v.fixed_version,
                        "severity": v.severity.value,
                        "cvss_score": v.cvss_score,
                        "description": v.description
                    }
                    for v in scan_result.vulnerabilities[:10]  # First 10
                ]
            },
            "packages": len(scan_result.packages),
            "layers": len(scan_result.layers),
            "risk_score": scan_result.risk_score,
            "scan_duration_ms": scan_result.scan_duration_ms
        }

    except Exception as e:
        logger.error(f"Error scanning container image: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/kubernetes/scan")
async def scan_kubernetes_namespace(
    namespace: str = Query("default", description="Kubernetes namespace to scan")
):
    """
    Scan Kubernetes namespace for resources.

    Discovers pods, deployments, services, secrets, and other resources.
    """
    try:
        from vaulytica.container_security import get_k8s_scanner

        scanner = get_k8s_scanner()
        resources = await scanner.scan_namespace(namespace)

        return {
            "status": "success",
            "namespace": namespace,
            "resources": {
                "total": len(resources),
                "by_type": {
                    resource_type: len([r for r in resources if r.resource_type.value == resource_type])
                    for resource_type in set(r.resource_type.value for r in resources)
                },
                "details": [
                    {
                        "resource_id": r.resource_id,
                        "type": r.resource_type.value,
                        "name": r.name,
                        "namespace": r.namespace,
                        "labels": r.labels
                    }
                    for r in resources
                ]
            }
        }

    except Exception as e:
        logger.error(f"Error scanning Kubernetes namespace: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/kubernetes/check-cis")
async def check_kubernetes_cis_benchmark(
    namespace: str = Query("default", description="Kubernetes namespace to check")
):
    """
    Check CIS Kubernetes Benchmark compliance.

    Runs CIS benchmark checks on Kubernetes resources.
    """
    try:

        scanner = get_k8s_scanner()
        resources = await scanner.scan_namespace(namespace)
        findings = await scanner.check_cis_kubernetes_benchmark(resources)

        return {
            "status": "success",
            "namespace": namespace,
            "findings": {
                "total": len(findings),
                "by_severity": {
                    severity: len([f for f in findings if f.severity.value == severity])
                    for severity in set(f.severity.value for f in findings)
                },
                "by_category": {
                    category: len([f for f in findings if f.category == category])
                    for category in set(f.category for f in findings)
                },
                "details": [
                    {
                        "finding_id": f.finding_id,
                        "severity": f.severity.value,
                        "title": f.title,
                        "description": f.description,
                        "remediation": f.remediation,
                        "category": f.category,
                        "cis_benchmark": f.cis_benchmark,
                        "risk_score": f.risk_score,
                        "resource": {
                            "type": f.resource.resource_type.value,
                            "name": f.resource.name
                        }
                    }
                    for f in findings
                ]
            }
        }

    except Exception as e:
        logger.error(f"Error checking CIS Kubernetes benchmark: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/container/runtime/monitor")
async def monitor_container_runtime(
    container_id: str = Query(..., description="Container ID to monitor"),
    duration_seconds: int = Query(60, description="Monitoring duration in seconds")
):
    """
    Monitor container runtime behavior.

    Detects suspicious syscalls, network activity, and file access.
    """
    try:
        from vaulytica.container_security import get_runtime_monitor

        monitor = get_runtime_monitor()
        events = await monitor.monitor_container(container_id, duration_seconds)

        return {
            "status": "success",
            "container_id": container_id,
            "duration_seconds": duration_seconds,
            "events": {
                "total": len(events),
                "by_type": {
                    event_type: len([e for e in events if e.event_type == event_type])
                    for event_type in set(e.event_type for e in events)
                },
                "by_severity": {
                    severity: len([e for e in events if e.severity.value == severity])
                    for severity in set(e.severity.value for e in events)
                },
                "blocked": len([e for e in events if e.blocked]),
                "details": [
                    {
                        "event_id": e.event_id,
                        "type": e.event_type,
                        "severity": e.severity.value,
                        "description": e.description,
                        "blocked": e.blocked,
                        "timestamp": e.timestamp.isoformat()
                    }
                    for e in events
                ]
            }
        }

    except Exception as e:
        logger.error(f"Error monitoring container runtime: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/container/sbom/generate")
async def generate_sbom(
    image_ref: str = Query(..., description="Container image reference")
):
    """
    Generate Software Bill of Materials (SBOM) for container image.

    Creates CycloneDX format SBOM with all components and dependencies.
    """
    try:
        from vaulytica.container_security import get_supply_chain_security, get_container_scanner

        # Scan image first
        scanner = get_container_scanner()
        scan_result = await scanner.scan_image(image_ref)

        # Generate SBOM
        supply_chain = get_supply_chain_security()
        sbom = await supply_chain.generate_sbom(scan_result.image)

        return {
            "status": "success",
            "sbom_id": sbom.sbom_id,
            "format": sbom.format,
            "version": sbom.version,
            "image": {
                "repository": sbom.image.repository,
                "tag": sbom.image.tag
            },
            "components": len(sbom.components),
            "sbom_json": sbom.to_json()
        }

    except Exception as e:
        logger.error(f"Error generating SBOM: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/container/verify-signature")
async def verify_container_signature(
    image_ref: str = Query(..., description="Container image reference"),
    public_key: Optional[str] = Query(None, description="Public key for verification")
):
    """
    Verify container image signature and provenance.

    Validates image authenticity and build provenance.
    """
    try:

        # Scan image first
        scanner = get_container_scanner()
        scan_result = await scanner.scan_image(image_ref)

        # Verify signature
        supply_chain = get_supply_chain_security()
        verification = await supply_chain.verify_image_signature(scan_result.image, public_key)

        return {
            "status": "success",
            "image": image_ref,
            "verification": verification
        }

    except Exception as e:
        logger.error(f"Error verifying container signature: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/container/security/assess")
async def full_container_security_assessment(
    image_ref: str = Query(..., description="Container image reference"),
    namespace: str = Query("default", description="Kubernetes namespace"),
    monitor_runtime: bool = Query(True, description="Monitor runtime behavior")
):
    """
    Perform full container security assessment.

    Combines image scanning, K8s security checks, SBOM generation, and runtime monitoring.
    """
    try:
        from vaulytica.container_security import get_container_security_orchestrator

        orchestrator = get_container_security_orchestrator()
        assessment = await orchestrator.full_security_assessment(
            image_ref,
            namespace,
            monitor_runtime
        )

        return {
            "status": "success",
            "assessment": assessment
        }

    except Exception as e:
        logger.error(f"Error performing security assessment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/container/statistics")
async def get_container_security_statistics():
    """Get container security statistics."""
    try:

        orchestrator = get_container_security_orchestrator()

        return {
            "status": "success",
            "statistics": orchestrator.get_unified_statistics()
        }

    except Exception as e:
        logger.error(f"Error getting container security statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# IAM SECURITY & SECRETS MANAGEMENT ENDPOINTS (v0.24.0)
# ============================================================================

@app.post("/iam/analyze-principal")
async def analyze_iam_principal(
    principal_id: str = Query(..., description="IAM principal ID"),
    principal_type: str = Query(..., description="Principal type (user, role, service_account)"),
    name: str = Query(..., description="Principal name"),
    provider: str = Query(..., description="Cloud provider (aws, azure, gcp)"),
    permissions: List[str] = Body(default=[], description="List of permissions")
):
    """
    Analyze IAM principal for security issues.

    Checks for privilege escalation paths, over-privileged roles, and provides recommendations.
    """
    try:
        from vaulytica.iam_security import get_iam_analyzer, IAMPrincipal, IAMPrincipalType
        from vaulytica.cspm import CloudProvider

        analyzer = get_iam_analyzer()

        # Create principal object
        principal = IAMPrincipal(
            principal_id=principal_id,
            principal_type=IAMPrincipalType(principal_type),
            name=name,
            provider=CloudProvider(provider.upper()),
            created_at=datetime.utcnow(),
            permissions=set(permissions)
        )

        # Analyze principal
        analysis = await analyzer.analyze_principal(principal)

        # Get escalation paths
        escalation_paths = [
            {
                "path_id": p.path_id,
                "escalation_type": p.escalation_type,
                "severity": p.severity.value,
                "description": p.description,
                "risk_score": p.risk_score,
                "mitigation": p.mitigation
            }
            for p in analyzer.get_escalation_paths()
            if p.principal.principal_id == principal_id
        ]

        return {
            "status": "success",
            "analysis": analysis,
            "escalation_paths": escalation_paths,
            "statistics": analyzer.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error analyzing IAM principal: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/secrets/scan-file")
async def scan_file_for_secrets(
    file_path: str = Query(..., description="File path to scan"),
    content: str = Body(..., description="File content to scan"),
    location: str = Query("source_code", description="Secret location type")
):
    """
    Scan file content for exposed secrets.

    Uses pattern matching and entropy analysis to detect hardcoded secrets.
    """
    try:
        from vaulytica.iam_security import get_secrets_scanner, SecretLocation

        scanner = get_secrets_scanner()

        # Scan file
        secrets = await scanner.scan_file(
            file_path,
            content,
            SecretLocation(location)
        )

        return {
            "status": "success",
            "secrets_found": len(secrets),
            "secrets": [
                {
                    "secret_id": s.secret_id,
                    "type": s.secret_type.value,
                    "location": s.location.value,
                    "file_path": s.file_path,
                    "line_number": s.line_number,
                    "severity": s.severity.value,
                    "entropy_score": s.entropy_score,
                    "remediation": s.remediation
                }
                for s in secrets
            ],
            "statistics": scanner.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error scanning file for secrets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/secrets/scan-directory")
async def scan_directory_for_secrets(
    directory_path: str = Query(..., description="Directory path to scan"),
    file_extensions: Optional[List[str]] = Query(None, description="File extensions to scan")
):
    """
    Scan directory for exposed secrets.

    Recursively scans files for hardcoded secrets.
    """
    try:
        from vaulytica.iam_security import get_secrets_scanner

        scanner = get_secrets_scanner()

        # Scan directory
        secrets = await scanner.scan_directory(directory_path, file_extensions)

        # Group by severity
        by_severity = {}
        for s in secrets:
            severity = s.severity.value
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append({
                "secret_id": s.secret_id,
                "type": s.secret_type.value,
                "file_path": s.file_path,
                "line_number": s.line_number
            })

        return {
            "status": "success",
            "secrets_found": len(secrets),
            "by_severity": by_severity,
            "statistics": scanner.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error scanning directory for secrets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/credentials/register")
async def register_credential(
    name: str = Query(..., description="Credential name"),
    credential_type: str = Query(..., description="Credential type"),
    owner: str = Query(..., description="Credential owner"),
    expires_days: Optional[int] = Query(None, description="Days until expiration")
):
    """
    Register credential for lifecycle management.

    Tracks credential expiration and rotation.
    """
    try:
        from vaulytica.iam_security import get_credential_manager

        manager = get_credential_manager()

        # Calculate expiration
        expires_at = None
        if expires_days:
            from datetime import timedelta
            expires_at = datetime.utcnow() + timedelta(days=expires_days)

        # Register credential
        credential = await manager.register_credential(
            name,
            credential_type,
            owner,
            expires_at
        )

        return {
            "status": "success",
            "credential": {
                "credential_id": credential.credential_id,
                "name": credential.name,
                "type": credential.credential_type,
                "owner": credential.owner,
                "expires_at": credential.expires_at.isoformat() if credential.expires_at else None,
                "rotation_policy": credential.rotation_policy
            }
        }

    except Exception as e:
        logger.error(f"Error registering credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/credentials/rotate")
async def rotate_credential(
    credential_id: str = Query(..., description="Credential ID to rotate")
):
    """
    Rotate a managed credential.

    Updates credential and extends expiration based on rotation policy.
    """
    try:

        manager = get_credential_manager()

        # Rotate credential
        success = await manager.rotate_credential(credential_id)

        if not success:
            raise HTTPException(status_code=404, detail="Credential not found")

        return {
            "status": "success",
            "message": f"Credential {credential_id} rotated successfully",
            "statistics": manager.get_statistics()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error rotating credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/credentials/expiring")
async def get_expiring_credentials(
    days_threshold: int = Query(30, description="Days until expiration threshold")
):
    """
    Get credentials expiring soon.

    Returns list of credentials that will expire within the threshold.
    """
    try:

        manager = get_credential_manager()

        # Check expiring credentials
        expiring = await manager.check_expiring_credentials(days_threshold)

        return {
            "status": "success",
            "expiring_count": len(expiring),
            "credentials": [
                {
                    "credential_id": c.credential_id,
                    "name": c.name,
                    "type": c.credential_type,
                    "owner": c.owner,
                    "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                    "days_until_expiration": (c.expires_at - datetime.utcnow()).days if c.expires_at else None
                }
                for c in expiring
            ]
        }

    except Exception as e:
        logger.error(f"Error getting expiring credentials: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/zerotrust/create-policy")
async def create_zero_trust_policy(
    name: str = Query(..., description="Policy name"),
    principal: str = Query(..., description="Principal (user, role, service)"),
    resource: str = Query(..., description="Resource to access"),
    action: str = Query(..., description="Policy action (allow, deny, challenge, audit)"),
    conditions: Optional[Dict[str, Any]] = Body(None, description="Access conditions")
):
    """
    Create zero trust access policy.

    Defines access control with continuous verification and conditions.
    """
    try:
        from vaulytica.iam_security import get_zero_trust_engine, ZeroTrustPolicyAction

        engine = get_zero_trust_engine()

        # Create policy
        policy = await engine.create_policy(
            name,
            principal,
            resource,
            ZeroTrustPolicyAction(action),
            conditions
        )

        return {
            "status": "success",
            "policy": {
                "policy_id": policy.policy_id,
                "name": policy.name,
                "principal": policy.principal,
                "resource": policy.resource,
                "action": policy.action.value,
                "conditions": policy.conditions,
                "enabled": policy.enabled
            }
        }

    except Exception as e:
        logger.error(f"Error creating zero trust policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/zerotrust/evaluate-access")
async def evaluate_zero_trust_access(
    principal: str = Query(..., description="Requesting principal"),
    resource: str = Query(..., description="Requested resource"),
    context: Dict[str, Any] = Body(..., description="Request context (location, device, time, etc.)")
):
    """
    Evaluate access request against zero trust policies.

    Returns access decision based on policies and context.
    """
    try:
        from vaulytica.iam_security import get_zero_trust_engine

        engine = get_zero_trust_engine()

        # Evaluate access
        action, reason = await engine.evaluate_access(principal, resource, context)

        return {
            "status": "success",
            "decision": action.value,
            "reason": reason,
            "statistics": engine.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error evaluating access: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/identity/analyze-threat")
async def analyze_identity_threat(
    principal_id: str = Query(..., description="IAM principal ID"),
    principal_type: str = Query(..., description="Principal type"),
    name: str = Query(..., description="Principal name"),
    provider: str = Query(..., description="Cloud provider"),
    access_event: Dict[str, Any] = Body(..., description="Access event details")
):
    """
    Analyze access pattern for identity-based threats.

    Detects anomalous access, privilege abuse, and lateral movement.
    """
    try:
        from vaulytica.iam_security import get_identity_threat_detector, IAMPrincipal, IAMPrincipalType

        detector = get_identity_threat_detector()

        # Create principal
        principal = IAMPrincipal(
            principal_id=principal_id,
            principal_type=IAMPrincipalType(principal_type),
            name=name,
            provider=CloudProvider(provider.upper()),
            created_at=datetime.utcnow()
        )

        # Analyze access pattern
        threat = await detector.analyze_access_pattern(principal, access_event)

        if threat:
            return {
                "status": "threat_detected",
                "threat": {
                    "threat_id": threat.threat_id,
                    "type": threat.threat_type,
                    "severity": threat.severity.value,
                    "description": threat.description,
                    "indicators": threat.indicators,
                    "risk_score": threat.risk_score,
                    "detected_at": threat.detected_at.isoformat()
                },
                "statistics": detector.get_statistics()
            }
        else:
            return {
                "status": "no_threat",
                "message": "No threats detected in access pattern"
            }

    except Exception as e:
        logger.error(f"Error analyzing identity threat: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/iam/full-assessment")
async def perform_full_iam_assessment(
    principals: List[Dict[str, Any]] = Body(..., description="List of IAM principals to analyze"),
    scan_paths: Optional[List[str]] = Body(None, description="Paths to scan for secrets")
):
    """
    Perform comprehensive IAM security assessment.

    Combines IAM analysis, secrets scanning, credential management, and threat detection.
    """
    try:
        from vaulytica.iam_security import get_iam_orchestrator, IAMPrincipal, IAMPrincipalType

        orchestrator = get_iam_orchestrator()

        # Convert principals
        principal_objects = []
        for p in principals:
            principal = IAMPrincipal(
                principal_id=p["principal_id"],
                principal_type=IAMPrincipalType(p["principal_type"]),
                name=p["name"],
                provider=CloudProvider(p["provider"].upper()),
                created_at=datetime.utcnow(),
                permissions=set(p.get("permissions", []))
            )
            principal_objects.append(principal)

        # Perform assessment
        assessment = await orchestrator.full_iam_assessment(
            principal_objects,
            scan_paths
        )

        return {
            "status": "success",
            "assessment": assessment
        }

    except Exception as e:
        logger.error(f"Error performing IAM assessment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/iam/statistics")
async def get_iam_security_statistics():
    """Get comprehensive IAM security statistics."""
    try:
        from vaulytica.iam_security import (
            get_iam_analyzer,
            get_secrets_scanner,
            get_credential_manager,
            get_zero_trust_engine,
            get_identity_threat_detector
        )

        return {
            "status": "success",
            "statistics": {
                "iam_analyzer": get_iam_analyzer().get_statistics(),
                "secrets_scanner": get_secrets_scanner().get_statistics(),
                "credential_manager": get_credential_manager().get_statistics(),
                "zero_trust_engine": get_zero_trust_engine().get_statistics(),
                "threat_detector": get_identity_threat_detector().get_statistics()
            }
        }

    except Exception as e:
        logger.error(f"Error getting IAM statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Network Security & DLP Endpoints (v0.25.0)
# ============================================================================

@app.post("/network/analyze-firewall-rule")
async def analyze_firewall_rule(
    rule_id: str = Query(..., description="Firewall rule ID"),
    name: str = Query(..., description="Rule name"),
    action: str = Query(..., description="Rule action (allow, deny, drop, reject)"),
    protocol: str = Query(..., description="Network protocol (tcp, udp, icmp, http, https, ssh)"),
    source_ip: str = Query(..., description="Source IP address or CIDR"),
    destination_ip: str = Query("*", description="Destination IP address or CIDR"),
    source_port: Optional[str] = Query(None, description="Source port"),
    destination_port: Optional[str] = Query(None, description="Destination port")
):
    """
    Analyze firewall rule for security issues.

    Returns analysis with risk score and security recommendations.
    """
    try:
        from vaulytica.network_security import (
            get_network_analyzer,
            FirewallRule,
            FirewallAction,
            NetworkProtocol
        )

        analyzer = get_network_analyzer()

        # Create firewall rule
        rule = FirewallRule(
            rule_id=rule_id,
            name=name,
            action=FirewallAction(action),
            protocol=NetworkProtocol(protocol),
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port
        )

        # Analyze rule
        result = await analyzer.analyze_firewall_rule(rule)

        return {
            "status": "success",
            "analysis": result,
            "statistics": analyzer.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error analyzing firewall rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/network/analyze-flow")
async def analyze_network_flow(
    flow_id: str = Query(..., description="Flow ID"),
    source_ip: str = Query(..., description="Source IP address"),
    source_port: int = Query(..., description="Source port"),
    destination_ip: str = Query(..., description="Destination IP address"),
    destination_port: int = Query(..., description="Destination port"),
    protocol: str = Query(..., description="Network protocol"),
    bytes_sent: int = Query(0, description="Bytes sent"),
    bytes_received: int = Query(0, description="Bytes received"),
    packets_sent: int = Query(0, description="Packets sent"),
    packets_received: int = Query(0, description="Packets received"),
    duration_seconds: float = Query(0.0, description="Flow duration in seconds")
):
    """
    Analyze network flow for threats.

    Returns detected threats if any.
    """
    try:
        from vaulytica.network_security import (
            get_network_analyzer,
            NetworkFlow,
            NetworkProtocol
        )

        analyzer = get_network_analyzer()

        # Create network flow
        flow = NetworkFlow(
            flow_id=flow_id,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=NetworkProtocol(protocol),
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            packets_sent=packets_sent,
            packets_received=packets_received,
            duration_seconds=duration_seconds,
            timestamp=datetime.utcnow()
        )

        # Analyze flow
        threat = await analyzer.analyze_network_flow(flow)

        return {
            "status": "success",
            "threat_detected": threat is not None,
            "threat": {
                "threat_id": threat.threat_id,
                "type": threat.threat_type.value,
                "severity": threat.severity.value,
                "source_ip": threat.source_ip,
                "destination_ip": threat.destination_ip,
                "description": threat.description,
                "risk_score": threat.risk_score
            } if threat else None,
            "statistics": analyzer.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error analyzing network flow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/data/classify")
async def classify_data(
    content: str = Body(..., description="Content to classify"),
    location: str = Query(..., description="Data location (file path, database, etc.)"),
    context: str = Query("", description="Additional context")
):
    """
    Classify data for sensitive information.

    Returns detected sensitive data with classification levels.
    """
    try:
        from vaulytica.network_security import get_data_classifier

        classifier = get_data_classifier()

        # Classify data
        sensitive_data = await classifier.classify_data(content, location, context)

        return {
            "status": "success",
            "sensitive_data_count": len(sensitive_data),
            "sensitive_data": [
                {
                    "data_id": d.data_id,
                    "type": d.data_type.value,
                    "classification": d.classification.value,
                    "location": d.location,
                    "masked_value": d.matched_value,
                    "confidence": d.confidence,
                    "line_number": d.line_number
                }
                for d in sensitive_data
            ],
            "statistics": classifier.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error classifying data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dlp/create-policy")
async def create_dlp_policy(
    name: str = Query(..., description="Policy name"),
    data_types: List[str] = Body(..., description="Data types to protect (pii, phi, pci, ssn, credit_card, etc.)"),
    action: str = Query(..., description="DLP action (allow, block, quarantine, alert, encrypt)"),
    classification_level: str = Query(..., description="Minimum classification level (public, internal, confidential, restricted)")
):
    """
    Create DLP policy.

    Returns created policy details.
    """
    try:
        from vaulytica.dlp import (
            get_dlp_engine,
            SensitiveDataType,
            DLPAction,
            DataClassification
        )

        engine = get_dlp_engine()

        # Convert data types
        data_type_enums = [SensitiveDataType(dt) for dt in data_types]

        # Create policy
        policy = await engine.create_policy(
            name=name,
            data_types=data_type_enums,
            action=DLPAction(action),
            classification_level=DataClassification(classification_level)
        )

        return {
            "status": "success",
            "policy": {
                "policy_id": policy.policy_id,
                "name": policy.name,
                "data_types": [dt.value for dt in policy.data_types],
                "action": policy.action.value,
                "classification_level": policy.classification_level.value,
                "enabled": policy.enabled
            },
            "statistics": engine.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error creating DLP policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/dlp/enforce")
async def enforce_dlp_policy(
    content: str = Body(..., description="Content to check"),
    location: str = Query(..., description="Content location"),
    operation: str = Query("transfer", description="Operation being performed")
):
    """
    Enforce DLP policies on content.

    Returns enforcement decision (allow, block, encrypt, alert).
    """
    try:
        from vaulytica.network_security import get_dlp_engine

        engine = get_dlp_engine()

        # Enforce policy
        result = await engine.enforce_policy(content, location, operation)

        return {
            "status": "success",
            "enforcement": result,
            "statistics": engine.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error enforcing DLP policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/encryption/register-key")
async def register_encryption_key(
    name: str = Query(..., description="Key name"),
    algorithm: str = Query(..., description="Encryption algorithm (aes-256, aes-128, rsa-2048, rsa-4096, ecdsa)"),
    key_size: int = Query(..., description="Key size in bits"),
    purpose: str = Query(..., description="Key purpose (encryption, signing, etc.)"),
    rotation_policy_days: int = Query(365, description="Days between rotations")
):
    """
    Register encryption key for lifecycle management.

    Returns registered key details.
    """
    try:

        manager = get_encryption_manager()

        # Register key
        key = await manager.register_key(
            name=name,
            algorithm=EncryptionAlgorithm(algorithm),
            key_size=key_size,
            purpose=purpose,
            rotation_policy_days=rotation_policy_days
        )

        return {
            "status": "success",
            "key": {
                "key_id": key.key_id,
                "name": key.name,
                "algorithm": key.algorithm.value,
                "key_size": key.key_size,
                "purpose": key.purpose,
                "rotation_policy_days": key.rotation_policy_days,
                "is_active": key.is_active
            },
            "statistics": manager.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error registering encryption key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/encryption/rotate-key")
async def rotate_encryption_key(
    key_id: str = Query(..., description="Key ID to rotate")
):
    """
    Rotate encryption key.

    Returns new key details.
    """
    try:
        from vaulytica.network_security import get_encryption_manager

        manager = get_encryption_manager()

        # Rotate key
        new_key = await manager.rotate_key(key_id)

        return {
            "status": "success",
            "new_key": {
                "key_id": new_key.key_id,
                "name": new_key.name,
                "algorithm": new_key.algorithm.value,
                "key_size": new_key.key_size,
                "is_active": new_key.is_active,
                "last_rotated": new_key.last_rotated.isoformat() if new_key.last_rotated else None
            },
            "statistics": manager.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error rotating encryption key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/encryption/check-rotation")
async def check_key_rotation():
    """
    Check for encryption keys needing rotation.

    Returns list of keys that need rotation.
    """
    try:

        manager = get_encryption_manager()

        # Check rotation
        keys_needing_rotation = await manager.check_key_rotation()

        return {
            "status": "success",
            "keys_needing_rotation": len(keys_needing_rotation),
            "keys": [
                {
                    "key_id": key.key_id,
                    "name": key.name,
                    "algorithm": key.algorithm.value,
                    "created_at": key.created_at.isoformat(),
                    "rotation_policy_days": key.rotation_policy_days
                }
                for key in keys_needing_rotation
            ],
            "statistics": manager.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error checking key rotation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/network/full-assessment")
async def perform_network_security_assessment(
    firewall_rules: List[Dict[str, Any]] = Body(..., description="Firewall rules to analyze"),
    network_flows: List[Dict[str, Any]] = Body(..., description="Network flows to analyze"),
    data_locations: List[Dict[str, str]] = Body(default=[], description="Data locations to scan (path, content)")
):
    """
    Perform comprehensive network security assessment.

    Returns complete assessment with risk scores and recommendations.
    """
    try:

        orchestrator = get_network_security_orchestrator()

        # Convert firewall rules
        rules = []
        for rule_data in firewall_rules:
            rule = FirewallRule(
                rule_id=rule_data["rule_id"],
                name=rule_data["name"],
                action=FirewallAction(rule_data["action"]),
                protocol=NetworkProtocol(rule_data["protocol"]),
                source_ip=rule_data["source_ip"],
                destination_ip=rule_data.get("destination_ip", "*"),
                source_port=rule_data.get("source_port"),
                destination_port=rule_data.get("destination_port")
            )
            rules.append(rule)

        # Convert network flows
        flows = []
        for flow_data in network_flows:
            flow = NetworkFlow(
                flow_id=flow_data["flow_id"],
                source_ip=flow_data["source_ip"],
                source_port=flow_data["source_port"],
                destination_ip=flow_data["destination_ip"],
                destination_port=flow_data["destination_port"],
                protocol=NetworkProtocol(flow_data["protocol"]),
                bytes_sent=flow_data.get("bytes_sent", 0),
                bytes_received=flow_data.get("bytes_received", 0),
                packets_sent=flow_data.get("packets_sent", 0),
                packets_received=flow_data.get("packets_received", 0),
                duration_seconds=flow_data.get("duration_seconds", 0.0),
                timestamp=datetime.utcnow()
            )
            flows.append(flow)

        # Perform assessment
        assessment = await orchestrator.perform_full_assessment(
            firewall_rules=rules,
            network_flows=flows,
            data_locations=data_locations
        )

        return {
            "status": "success",
            "assessment": assessment
        }

    except Exception as e:
        logger.error(f"Error performing network security assessment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/network/statistics")
async def get_network_security_statistics():
    """
    Get network security statistics.

    Returns statistics from all network security components.
    """
    try:

        return {
            "status": "success",
            "statistics": {
                "network_analyzer": get_network_analyzer().get_statistics(),
                "data_classifier": get_data_classifier().get_statistics(),
                "dlp_engine": get_dlp_engine().get_statistics(),
                "encryption_manager": get_encryption_manager().get_statistics(),
                "threat_detector": get_network_threat_detector().get_statistics()
            }
        }

    except Exception as e:
        logger.error(f"Error getting network security statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# API Security & Application Security Testing Endpoints (v0.26.0)
# ============================================================================

@app.post("/api-security/scan-endpoint")
async def scan_api_endpoint(
    endpoint_id: str = Query(..., description="Endpoint ID"),
    path: str = Query(..., description="API endpoint path"),
    method: str = Query(..., description="HTTP method (GET, POST, PUT, DELETE, PATCH)"),
    auth_type: str = Query(..., description="Authentication type (none, basic, bearer, api_key, oauth2, jwt)"),
    parameters: str = Query("", description="Comma-separated list of parameters"),
    requires_auth: bool = Query(True, description="Whether endpoint requires authentication")
):
    """
    Scan API endpoint for security vulnerabilities.

    Tests for:
    - Authentication issues
    - Authorization bypass
    - Injection vulnerabilities
    - Security misconfigurations
    """
    try:
        from vaulytica.api_security import get_api_scanner, APIEndpoint, APIMethod, AuthType

        scanner = get_api_scanner()

        # Parse parameters
        param_list = [p.strip() for p in parameters.split(",") if p.strip()]

        # Create endpoint
        endpoint = APIEndpoint(
            endpoint_id=endpoint_id,
            path=path,
            method=APIMethod(method.upper()),
            auth_type=AuthType(auth_type.lower()),
            parameters=param_list,
            requires_auth=requires_auth
        )

        # Scan endpoint
        vulnerabilities = await scanner.scan_endpoint(endpoint)

        return {
            "status": "success",
            "endpoint": {
                "endpoint_id": endpoint.endpoint_id,
                "path": endpoint.path,
                "method": endpoint.method.value
            },
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "type": v.vulnerability_type.value,
                    "owasp_category": v.owasp_category.value,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "remediation": v.remediation,
                    "cwe_id": v.cwe_id
                }
                for v in vulnerabilities
            ],
            "statistics": scanner.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error scanning API endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/app-security/test-sql-injection")
async def test_sql_injection(
    target: str = Query(..., description="Target URL or endpoint"),
    parameters: str = Query(..., description="Comma-separated list of parameters to test")
):
    """
    Test for SQL injection vulnerabilities.

    Tests parameters with various SQL injection payloads.
    """
    try:
        from vaulytica.api_security import get_app_tester

        tester = get_app_tester()

        # Parse parameters
        param_list = [p.strip() for p in parameters.split(",") if p.strip()]

        # Test SQL injection
        vulnerabilities = await tester.test_sql_injection(target, param_list)

        return {
            "status": "success",
            "target": target,
            "parameters_tested": param_list,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "type": v.vulnerability_type.value,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "remediation": v.remediation
                }
                for v in vulnerabilities
            ],
            "statistics": tester.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error testing SQL injection: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/app-security/test-xss")
async def test_xss(
    target: str = Query(..., description="Target URL or endpoint"),
    parameters: str = Query(..., description="Comma-separated list of parameters to test")
):
    """
    Test for XSS vulnerabilities.

    Tests parameters with various XSS payloads.
    """
    try:

        tester = get_app_tester()

        # Parse parameters
        param_list = [p.strip() for p in parameters.split(",") if p.strip()]

        # Test XSS
        vulnerabilities = await tester.test_xss(target, param_list)

        return {
            "status": "success",
            "target": target,
            "parameters_tested": param_list,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "type": v.vulnerability_type.value,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "remediation": v.remediation
                }
                for v in vulnerabilities
            ],
            "statistics": tester.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error testing XSS: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/app-security/test-csr")
async def test_csrf(
    target: str = Query(..., description="Target URL or endpoint")
):
    """
    Test for CSRF vulnerabilities.

    Checks if CSRF protection is implemented.
    """
    try:

        tester = get_app_tester()

        # Test CSRF
        vulnerabilities = await tester.test_csrf(target)

        return {
            "status": "success",
            "target": target,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "type": v.vulnerability_type.value,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "remediation": v.remediation
                }
                for v in vulnerabilities
            ],
            "statistics": tester.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error testing CSRF: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/app-security/test-ssr")
async def test_ssrf(
    target: str = Query(..., description="Target URL or endpoint"),
    parameters: str = Query(..., description="Comma-separated list of parameters to test")
):
    """
    Test for SSRF vulnerabilities.

    Tests URL parameters with internal/localhost payloads.
    """
    try:

        tester = get_app_tester()

        # Parse parameters
        param_list = [p.strip() for p in parameters.split(",") if p.strip()]

        # Test SSRF
        vulnerabilities = await tester.test_ssrf(target, param_list)

        return {
            "status": "success",
            "target": target,
            "parameters_tested": param_list,
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [
                {
                    "vuln_id": v.vuln_id,
                    "type": v.vulnerability_type.value,
                    "severity": v.severity.value,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "remediation": v.remediation
                }
                for v in vulnerabilities
            ],
            "statistics": tester.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error testing SSRF: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/threat-protection/analyze-request")
async def analyze_api_request(
    source_ip: str = Query(..., description="Source IP address"),
    endpoint: str = Query(..., description="API endpoint"),
    method: str = Query(..., description="HTTP method"),
    user_agent: str = Query(..., description="User agent string"),
    headers: str = Query("{}", description="Request headers as JSON")
):
    """
    Analyze API request for threats.

    Detects:
    - Bot attacks
    - Credential stuffing
    - API abuse
    - Rate limit bypass
    """
    try:
        from vaulytica.api_security import get_threat_protection
        import json

        protection = get_threat_protection()

        # Parse headers
        headers_dict = json.loads(headers)

        # Analyze request
        threat = await protection.analyze_request(
            source_ip=source_ip,
            endpoint=endpoint,
            method=method,
            user_agent=user_agent,
            headers=headers_dict
        )

        if threat:
            return {
                "status": "threat_detected",
                "threat": {
                    "threat_id": threat.threat_id,
                    "type": threat.threat_type.value,
                    "severity": threat.severity.value,
                    "source_ip": threat.source_ip,
                    "endpoint": threat.endpoint,
                    "description": threat.description,
                    "indicators": threat.indicators,
                    "risk_score": threat.risk_score
                },
                "action": "block" if threat.severity.value in ["critical", "high"] else "monitor",
                "statistics": protection.get_statistics()
            }
        else:
            return {
                "status": "no_threat",
                "message": "Request appears legitimate",
                "statistics": protection.get_statistics()
            }

    except Exception as e:
        logger.error(f"Error analyzing API request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/security-automation/schedule-scan")
async def schedule_security_scan(
    target: str = Query(..., description="Scan target"),
    scan_type: str = Query(..., description="Scan type (api, app, full)"),
    frequency: str = Query("daily", description="Scan frequency (hourly, daily, weekly)")
):
    """
    Schedule automated security scan.

    Automates regular security testing.
    """
    try:
        from vaulytica.api_security import get_security_automation

        automation = get_security_automation()

        # Schedule scan
        scan = await automation.schedule_scan(target, scan_type, frequency)

        return {
            "status": "success",
            "scan": scan,
            "message": f"Scheduled {scan_type} scan for {target} ({frequency})"
        }

    except Exception as e:
        logger.error(f"Error scheduling scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/security-automation/execute-scan")
async def execute_security_scan(
    target: str = Query(..., description="Scan target"),
    scan_type: str = Query(..., description="Scan type (api, app, full)")
):
    """
    Execute security scan immediately.

    Runs comprehensive security testing.
    """
    try:

        automation = get_security_automation()

        # Execute scan
        report = await automation.execute_scan(target, scan_type)

        return {
            "status": "success",
            "report": {
                "report_id": report.report_id,
                "scan_target": report.scan_target,
                "total_vulnerabilities": len(report.vulnerabilities),
                "critical_count": report.critical_count,
                "high_count": report.high_count,
                "medium_count": report.medium_count,
                "low_count": report.low_count,
                "overall_risk_score": report.overall_risk_score,
                "scan_duration": report.scan_duration
            },
            "statistics": automation.get_statistics()
        }

    except Exception as e:
        logger.error(f"Error executing scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api-security/full-assessment")
async def perform_full_api_security_assessment(
    target: str = Query(..., description="Target application"),
    endpoints_json: str = Query(..., description="JSON array of endpoints to scan"),
    test_parameters: str = Query(..., description="Comma-separated list of parameters to test")
):
    """
    Perform comprehensive API security assessment.

    Includes:
    - API endpoint scanning
    - Application security testing
    - Threat detection
    - Vulnerability reporting
    """
    try:
        from vaulytica.api_security import get_api_security_orchestrator, APIEndpoint, APIMethod, AuthType

        orchestrator = get_api_security_orchestrator()

        # Parse endpoints
        endpoints_data = json.loads(endpoints_json)
        endpoints = [
            APIEndpoint(
                endpoint_id=ep.get("endpoint_id", f"ep-{i}"),
                path=ep["path"],
                method=APIMethod(ep["method"].upper()),
                auth_type=AuthType(ep.get("auth_type", "none").lower()),
                parameters=ep.get("parameters", []),
                requires_auth=ep.get("requires_auth", True)
            )
            for i, ep in enumerate(endpoints_data)
        ]

        # Parse test parameters
        param_list = [p.strip() for p in test_parameters.split(",") if p.strip()]

        # Perform assessment
        results = await orchestrator.perform_full_assessment(target, endpoints, param_list)

        return {
            "status": "success",
            "assessment": results
        }

    except Exception as e:
        logger.error(f"Error performing full assessment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api-security/statistics")
async def get_api_security_statistics():
    """
    Get comprehensive API security statistics.

    Returns statistics from all security modules.
    """
    try:
        from vaulytica.api_security import (
            get_api_scanner,
            get_app_tester,
            get_threat_protection,
            get_security_automation,
            get_vulnerability_reporter
        )

        return {
            "status": "success",
            "statistics": {
                "api_scanner": get_api_scanner().get_statistics(),
                "app_tester": get_app_tester().get_statistics(),
                "threat_protection": get_threat_protection().get_statistics(),
                "security_automation": get_security_automation().get_statistics(),
                "vulnerability_reporter": get_vulnerability_reporter().get_statistics()
            }
        }

    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# DevSecOps & Security Orchestration Endpoints (v0.27.0)
# ============================================================================

@app.post("/devsecops/configure-pipeline")
async def configure_devsecops_pipeline(
    pipeline_id: str = Body(...),
    name: str = Body(...),
    pipeline_type: str = Body(...),
    repository: str = Body(...),
    branch: str = Body(...),
    security_gates: List[str] = Body(...),
    fail_on_critical: bool = Body(True),
    fail_on_high: bool = Body(False)
):
    """Configure a DevSecOps pipeline with security gates."""
    try:
        from vaulytica.devsecops import get_devsecops_pipeline, PipelineConfig, PipelineType, SecurityGateType

        pipeline = get_devsecops_pipeline()

        config = PipelineConfig(
            pipeline_id=pipeline_id,
            name=name,
            pipeline_type=PipelineType(pipeline_type),
            repository=repository,
            branch=branch,
            security_gates=[SecurityGateType(gate) for gate in security_gates],
            fail_on_critical=fail_on_critical,
            fail_on_high=fail_on_high
        )

        result = await pipeline.configure_pipeline(config)
        return result
    except Exception as e:
        logger.error(f"Error configuring pipeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/devsecops/execute-gates")
async def execute_security_gates(
    pipeline_id: str = Body(...),
    commit_sha: str = Body(...),
    artifacts: Dict[str, Any] = Body(...)
):
    """Execute security gates for a pipeline run."""
    try:
        from vaulytica.devsecops import get_devsecops_pipeline

        pipeline = get_devsecops_pipeline()
        result = await pipeline.execute_security_gates(pipeline_id, commit_sha, artifacts)
        return result
    except Exception as e:
        logger.error(f"Error executing gates: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/orchestration/create-workflow")
async def create_orchestration_workflow(
    workflow_id: str = Body(...),
    name: str = Body(...),
    description: str = Body(...),
    trigger_conditions: List[str] = Body(...),
    actions: List[str] = Body(...),
    priority: int = Body(5)
):
    """Create a security orchestration workflow."""
    try:
        from vaulytica.devsecops import get_orchestration_hub, OrchestrationWorkflow, OrchestrationAction

        hub = get_orchestration_hub()

        workflow = OrchestrationWorkflow(
            workflow_id=workflow_id,
            name=name,
            description=description,
            trigger_conditions=trigger_conditions,
            actions=[OrchestrationAction(action) for action in actions],
            priority=priority
        )

        result = await hub.create_workflow(workflow)
        return result
    except Exception as e:
        logger.error(f"Error creating workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/orchestration/execute-workflow")
async def execute_orchestration_workflow(
    workflow_id: str = Body(...),
    context: Dict[str, Any] = Body(...)
):
    """Execute a security orchestration workflow."""
    try:
        from vaulytica.devsecops import get_orchestration_hub

        hub = get_orchestration_hub()
        result = await hub.execute_workflow(workflow_id, context)
        return result
    except Exception as e:
        logger.error(f"Error executing workflow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/threat-intel/ingest-indicator")
async def ingest_threat_indicator(
    indicator_id: str = Body(...),
    indicator_type: str = Body(...),
    value: str = Body(...),
    sources: List[str] = Body(...),
    confidence_score: float = Body(...),
    severity: str = Body(...),
    tags: List[str] = Body([])
):
    """Ingest a threat intelligence indicator."""
    try:
        from vaulytica.devsecops import get_threat_intelligence, ThreatIntelIndicator, ThreatIntelSource, Severity

        intel = get_threat_intelligence()

        indicator = ThreatIntelIndicator(
            indicator_id=indicator_id,
            indicator_type=indicator_type,
            value=value,
            sources=[ThreatIntelSource(s) for s in sources],
            confidence_score=confidence_score,
            severity=Severity(severity),
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            tags=tags
        )

        result = await intel.ingest_indicator(indicator)
        return result
    except Exception as e:
        logger.error(f"Error ingesting indicator: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/threat-intel/correlate-indicators")
async def correlate_threat_indicators(
    indicator_ids: List[str] = Body(...)
):
    """Correlate multiple threat intelligence indicators."""
    try:
        from vaulytica.devsecops import get_threat_intelligence

        intel = get_threat_intelligence()
        result = await intel.correlate_indicators(indicator_ids)
        return result
    except Exception as e:
        logger.error(f"Error correlating indicators: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/threat-intel/enrich-indicator")
async def enrich_threat_indicator(
    indicator_id: str = Body(...)
):
    """Enrich a threat intelligence indicator."""
    try:

        intel = get_threat_intelligence()
        result = await intel.enrich_indicator(indicator_id)
        return result
    except Exception as e:
        logger.error(f"Error enriching indicator: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/metrics/collect")
async def collect_security_metrics():
    """Collect current security metrics."""
    try:
        from vaulytica.devsecops import get_metrics_dashboard

        dashboard = get_metrics_dashboard()
        metrics = await dashboard.collect_metrics()

        return {
            "metric_id": metrics.metric_id,
            "timestamp": metrics.timestamp.isoformat(),
            "vulnerabilities_total": metrics.vulnerabilities_total,
            "vulnerabilities_by_severity": metrics.vulnerabilities_by_severity,
            "security_posture_score": metrics.security_posture_score,
            "compliance_score": metrics.compliance_score,
            "mean_time_to_detect": metrics.mean_time_to_detect,
            "mean_time_to_respond": metrics.mean_time_to_respond,
            "mean_time_to_remediate": metrics.mean_time_to_remediate
        }
    except Exception as e:
        logger.error(f"Error collecting metrics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/metrics/executive-report")
async def generate_executive_report():
    """Generate executive security report."""
    try:

        dashboard = get_metrics_dashboard()
        report = await dashboard.generate_executive_report()
        return report
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/pentesting/execute")
async def execute_penetration_test(
    test_type: str = Body(...),
    target: str = Body(...),
    scope: Dict[str, Any] = Body({})
):
    """Execute automated penetration test."""
    try:
        from vaulytica.devsecops import get_automated_pentesting, PentestType

        pentesting = get_automated_pentesting()
        result = await pentesting.execute_pentest(PentestType(test_type), target, scope)

        return {
            "test_id": result.test_id,
            "test_type": result.test_type.value,
            "target": result.target,
            "vulnerabilities_found": result.vulnerabilities_found,
            "critical_findings": result.critical_findings,
            "high_findings": result.high_findings,
            "medium_findings": result.medium_findings,
            "low_findings": result.low_findings,
            "risk_score": result.risk_score,
            "recommendations": result.recommendations,
            "duration_seconds": result.duration_seconds
        }
    except Exception as e:
        logger.error(f"Error executing pentest: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/devsecops/full-assessment")
async def perform_full_security_assessment(
    target: str = Body(...),
    assessment_type: str = Body("comprehensive")
):
    """Perform comprehensive security assessment."""
    try:
        from vaulytica.devsecops import get_devsecops_orchestrator

        orchestrator = get_devsecops_orchestrator()
        result = await orchestrator.perform_full_security_assessment(target, assessment_type)
        return result
    except Exception as e:
        logger.error(f"Error performing assessment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/devsecops/statistics")
async def get_devsecops_statistics():
    """Get comprehensive DevSecOps statistics."""
    try:

        orchestrator = get_devsecops_orchestrator()
        stats = orchestrator.get_comprehensive_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Supply Chain Security & GRC Endpoints (v0.28.0)
# ============================================================================

@app.post("/supply-chain/scan-dependencies")
async def scan_dependencies(request: Dict[str, Any]):
    """Scan project dependencies for security issues."""
    try:
        from vaulytica.supply_chain_security import get_supply_chain_scanner

        scanner = get_supply_chain_scanner()
        result = await scanner.scan_dependencies(
            project_name=request.get("project_name"),
            dependencies=request.get("dependencies", [])
        )

        return {
            "scan_id": result.scan_id,
            "project_name": result.project_name,
            "timestamp": result.timestamp.isoformat(),
            "dependencies_scanned": result.dependencies_scanned,
            "vulnerabilities_found": result.vulnerabilities_found,
            "critical": result.critical_vulnerabilities,
            "high": result.high_vulnerabilities,
            "medium": result.medium_vulnerabilities,
            "low": result.low_vulnerabilities,
            "license_issues": result.license_issues,
            "threats": [t.value for t in result.supply_chain_threats],
            "risk_score": result.risk_score,
            "recommendations": result.recommendations
        }
    except Exception as e:
        logger.error(f"Error scanning dependencies: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/sbom/generate")
async def generate_sbom(request: Dict[str, Any]):
    """Generate Software Bill of Materials (SBOM)."""
    try:
        from vaulytica.supply_chain_security import (
            get_sbom_manager,
            Dependency,
            DependencyType,
            LicenseType,
            SBOMFormat
        )

        manager = get_sbom_manager()

        # Convert dependencies
        dependencies = []
        for dep_data in request.get("dependencies", []):
            dep = Dependency(
                name=dep_data.get("name"),
                version=dep_data.get("version"),
                dependency_type=DependencyType(dep_data.get("type", "direct")),
                ecosystem=dep_data.get("ecosystem", "unknown"),
                license=dep_data.get("license", "unknown"),
                license_type=LicenseType.UNKNOWN,
                vulnerabilities=dep_data.get("vulnerabilities", [])
            )
            dependencies.append(dep)

        sbom_format = SBOMFormat(request.get("format", "cyclonedx"))
        sbom = await manager.generate_sbom(
            project_name=request.get("project_name"),
            project_version=request.get("project_version"),
            dependencies=dependencies,
            format=sbom_format
        )

        return {
            "sbom_id": sbom.sbom_id,
            "format": sbom.format.value,
            "spec_version": sbom.spec_version,
            "project_name": sbom.project_name,
            "project_version": sbom.project_version,
            "components": len(sbom.components),
            "timestamp": sbom.timestamp.isoformat()
        }
    except Exception as e:
        logger.error(f"Error generating SBOM: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sbom/export/{sbom_id}")
async def export_sbom(sbom_id: str, format: str = "json"):
    """Export SBOM in specified format."""
    try:
        from vaulytica.supply_chain_security import get_sbom_manager

        manager = get_sbom_manager()
        sbom_data = await manager.export_sbom(sbom_id, format)
        return sbom_data
    except Exception as e:
        logger.error(f"Error exporting SBOM: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/sbom/correlate-vulnerabilities/{sbom_id}")
async def correlate_sbom_vulnerabilities(sbom_id: str):
    """Correlate SBOM components with vulnerabilities."""
    try:

        manager = get_sbom_manager()
        result = await manager.correlate_vulnerabilities(sbom_id)
        return result
    except Exception as e:
        logger.error(f"Error correlating vulnerabilities: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/policy/create")
async def create_policy(request: Dict[str, Any]):
    """Create a security/compliance policy."""
    try:

        engine = get_policy_engine()

        policy = Policy(
            policy_id=request.get("policy_id"),
            name=request.get("name"),
            description=request.get("description"),
            policy_type=PolicyType(request.get("type")),
            severity=PolicySeverity(request.get("severity")),
            rules=request.get("rules", []),
            enabled=request.get("enabled", True),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            owner=request.get("owner", "system"),
            tags=request.get("tags", [])
        )

        result = await engine.create_policy(policy)
        return result
    except Exception as e:
        logger.error(f"Error creating policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/policy/evaluate")
async def evaluate_policy(request: Dict[str, Any]):
    """Evaluate policy against a resource."""
    try:
        from vaulytica.supply_chain_security import get_policy_engine

        engine = get_policy_engine()
        result = await engine.evaluate_policy(
            policy_id=request.get("policy_id"),
            resource=request.get("resource", {})
        )
        return result
    except Exception as e:
        logger.error(f"Error evaluating policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/risk/identify")
async def identify_risk(request: Dict[str, Any]):
    """Identify a new security risk."""
    try:

        risk_mgmt = get_risk_management()

        risk = Risk(
            risk_id=request.get("risk_id"),
            title=request.get("title"),
            description=request.get("description"),
            category=request.get("category"),
            risk_level=RiskLevel.MEDIUM,  # Will be calculated
            likelihood=request.get("likelihood", 0.5),
            impact=request.get("impact", 0.5),
            risk_score=0.0,  # Will be calculated
            status=RiskStatus.IDENTIFIED,
            owner=request.get("owner", "system"),
            identified_at=datetime.utcnow(),
            treatment_plan="",
            residual_risk=0.0,
            controls=request.get("controls", [])
        )

        result = await risk_mgmt.identify_risk(risk)
        return result
    except Exception as e:
        logger.error(f"Error identifying risk: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/risk/assess/{risk_id}")
async def assess_risk(risk_id: str):
    """Assess an identified risk."""
    try:
        from vaulytica.supply_chain_security import get_risk_management

        risk_mgmt = get_risk_management()
        result = await risk_mgmt.assess_risk(risk_id)
        return result
    except Exception as e:
        logger.error(f"Error assessing risk: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/risk/treat/{risk_id}")
async def treat_risk(risk_id: str, request: Dict[str, Any]):
    """Apply risk treatment."""
    try:

        risk_mgmt = get_risk_management()
        result = await risk_mgmt.treat_risk(
            risk_id=risk_id,
            treatment_type=request.get("treatment_type"),
            treatment_plan=request.get("treatment_plan", "")
        )
        return result
    except Exception as e:
        logger.error(f"Error treating risk: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/risk/report")
async def generate_risk_report():
    """Generate comprehensive risk report."""
    try:

        risk_mgmt = get_risk_management()
        report = await risk_mgmt.generate_risk_report()
        return report
    except Exception as e:
        logger.error(f"Error generating risk report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/grc/implement-control")
async def implement_control(request: Dict[str, Any]):
    """Implement a compliance control."""
    try:

        grc = get_grc_platform()

        control = ComplianceControl(
            control_id=request.get("control_id"),
            framework=ComplianceFramework(request.get("framework")),
            control_number=request.get("control_number"),
            title=request.get("title"),
            description=request.get("description"),
            status=ControlStatus(request.get("status", "not_implemented")),
            evidence=request.get("evidence", []),
            last_assessed=datetime.utcnow(),
            next_assessment=datetime.utcnow() + timedelta(days=90),
            owner=request.get("owner", "system"),
            automated=request.get("automated", False)
        )

        result = await grc.implement_control(control)
        return result
    except Exception as e:
        logger.error(f"Error implementing control: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/grc/assess-control/{control_id}")
async def assess_control(control_id: str):
    """Assess a compliance control."""
    try:
        from vaulytica.supply_chain_security import get_grc_platform

        grc = get_grc_platform()
        result = await grc.assess_control(control_id)
        return result
    except Exception as e:
        logger.error(f"Error assessing control: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/grc/compliance-score/{framework}")
async def calculate_compliance_score(framework: str):
    """Calculate compliance score for a framework."""
    try:

        grc = get_grc_platform()
        result = await grc.calculate_compliance_score(ComplianceFramework(framework))
        return result
    except Exception as e:
        logger.error(f"Error calculating compliance score: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/grc/audit-trail")
async def get_audit_trail(
    resource_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
):
    """Get audit trail."""
    try:

        grc = get_grc_platform()

        start = datetime.fromisoformat(start_date) if start_date else None
        end = datetime.fromisoformat(end_date) if end_date else None

        trail = await grc.get_audit_trail(resource_id, start, end)
        return {"audit_logs": trail}
    except Exception as e:
        logger.error(f"Error getting audit trail: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/supply-chain/comprehensive-assessment")
async def perform_comprehensive_assessment(request: Dict[str, Any]):
    """Perform comprehensive supply chain and GRC assessment."""
    try:

        orchestrator = get_supply_chain_grc_orchestrator()

        framework = ComplianceFramework(request.get("framework", "soc2"))

        result = await orchestrator.perform_comprehensive_assessment(
            project_name=request.get("project_name"),
            project_version=request.get("project_version"),
            dependencies=request.get("dependencies", []),
            framework=framework
        )
        return result
    except Exception as e:
        logger.error(f"Error performing assessment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/supply-chain/statistics")
async def get_supply_chain_statistics():
    """Get comprehensive supply chain and GRC statistics."""
    try:
        from vaulytica.supply_chain_security import get_supply_chain_grc_orchestrator

        orchestrator = get_supply_chain_grc_orchestrator()
        stats = orchestrator.get_comprehensive_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# SECURITY POSTURE ANALYTICS & CONTINUOUS MONITORING ENDPOINTS (v0.29.0)
# ============================================================================

@app.post("/posture/calculate-score")
async def calculate_posture_score(request: Dict[str, Any]):
    """Calculate security posture score."""
    try:
        from vaulytica.security_posture import get_security_posture_orchestrator, PostureMetric, PostureDimension

        orchestrator = get_security_posture_orchestrator()

        # Parse metrics from request
        metrics = []
        for m in request.get('metrics', []):
            metric = PostureMetric(
                metric_id=m['metric_id'],
                name=m['name'],
                dimension=PostureDimension(m['dimension']),
                value=m['value'],
                weight=m.get('weight', 1.0),
                threshold_good=m.get('threshold_good', 90.0),
                threshold_fair=m.get('threshold_fair', 75.0),
                current_status=m.get('current_status', 'unknown')
            )
            metrics.append(metric)

        score = await orchestrator.scoring_engine.calculate_posture_score(
            request['organization_id'],
            metrics
        )

        return {
            'overall_score': score.overall_score,
            'posture_level': score.posture_level.value,
            'dimension_scores': {k.value: v for k, v in score.dimension_scores.items()},
            'recommendations': score.recommendations,
            'calculated_at': score.calculated_at.isoformat(),
            'factors': score.factors,
        }
    except Exception as e:
        logger.error(f"Error calculating posture score: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/posture/score/{organization_id}")
async def get_posture_score(organization_id: str):
    """Get current posture score for organization."""
    try:
        from vaulytica.security_posture import get_security_posture_orchestrator

        orchestrator = get_security_posture_orchestrator()
        score = await orchestrator.scoring_engine.get_posture_score(organization_id)

        if not score:
            raise HTTPException(status_code=404, detail="Posture score not found")

        return {
            'overall_score': score.overall_score,
            'posture_level': score.posture_level.value,
            'dimension_scores': {k.value: v for k, v in score.dimension_scores.items()},
            'recommendations': score.recommendations,
            'calculated_at': score.calculated_at.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting posture score: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/monitoring/create-baseline")
async def create_baseline(request: Dict[str, Any]):
    """Create security baseline snapshot."""
    try:
        from vaulytica.security_posture import get_security_posture_orchestrator, PostureScore, PostureLevel, PostureDimension, PostureMetric

        orchestrator = get_security_posture_orchestrator()

        # Parse posture score
        score_data = request['posture_score']
        posture_score = PostureScore(
            overall_score=score_data['overall_score'],
            dimension_scores={PostureDimension(k): v for k, v in score_data['dimension_scores'].items()},
            posture_level=PostureLevel(score_data['posture_level']),
            recommendations=score_data.get('recommendations', [])
        )

        # Parse metrics
        metrics = {}
        for m_id, m in request.get('metrics', {}).items():
            metrics[m_id] = PostureMetric(
                metric_id=m_id,
                name=m['name'],
                dimension=PostureDimension(m['dimension']),
                value=m['value'],
                weight=m.get('weight', 1.0),
                threshold_good=m.get('threshold_good', 90.0),
                threshold_fair=m.get('threshold_fair', 75.0),
                current_status=m.get('current_status', 'unknown')
            )

        baseline = await orchestrator.monitoring_system.create_baseline(
            request['organization_id'],
            posture_score,
            metrics,
            request.get('approved_by')
        )

        return {
            'snapshot_id': baseline.snapshot_id,
            'timestamp': baseline.timestamp.isoformat(),
            'configuration_hash': baseline.configuration_hash,
            'approved_by': baseline.approved_by,
        }
    except Exception as e:
        logger.error(f"Error creating baseline: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/monitoring/detect-drift")
async def detect_drift(request: Dict[str, Any]):
    """Detect configuration drift from baseline."""
    try:

        orchestrator = get_security_posture_orchestrator()

        # Parse current score
        score_data = request['current_score']
        current_score = PostureScore(
            overall_score=score_data['overall_score'],
            dimension_scores={PostureDimension(k): v for k, v in score_data['dimension_scores'].items()},
            posture_level=PostureLevel(score_data['posture_level']),
            recommendations=score_data.get('recommendations', [])
        )

        # Parse current metrics
        current_metrics = {}
        for m_id, m in request.get('current_metrics', {}).items():
            current_metrics[m_id] = PostureMetric(
                metric_id=m_id,
                name=m['name'],
                dimension=PostureDimension(m['dimension']),
                value=m['value'],
                weight=m.get('weight', 1.0),
                threshold_good=m.get('threshold_good', 90.0),
                threshold_fair=m.get('threshold_fair', 75.0),
                current_status=m.get('current_status', 'unknown')
            )

        drift = await orchestrator.monitoring_system.detect_drift(
            request['organization_id'],
            current_score,
            current_metrics
        )

        if not drift:
            return {
                'drift_detected': False,
                'message': 'No drift detected from baseline'
            }

        return {
            'drift_detected': True,
            'drift_id': drift.drift_id,
            'drift_percentage': drift.drift_percentage,
            'severity': drift.drift_severity.value,
            'drifted_metrics_count': len(drift.drifted_metrics),
            'drifted_metrics': drift.drifted_metrics,
            'detected_at': drift.detected_at.isoformat(),
            'details': drift.details,
        }
    except Exception as e:
        logger.error(f"Error detecting drift: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/monitoring/alerts")
async def get_monitoring_alerts(
    organization_id: Optional[str] = None,
    severity: Optional[str] = None,
    unresolved_only: bool = True
):
    """Get monitoring alerts with optional filters."""
    try:
        from vaulytica.cspm import Severity

        orchestrator = get_security_posture_orchestrator()

        severity_enum = Severity(severity) if severity else None
        alerts = await orchestrator.monitoring_system.get_alerts(
            organization_id, severity_enum, unresolved_only
        )

        return {
            'alerts': [
                {
                    'alert_id': a.alert_id,
                    'alert_type': a.alert_type,
                    'severity': a.severity.value,
                    'dimension': a.dimension.value,
                    'message': a.message,
                    'details': a.details,
                    'triggered_at': a.triggered_at.isoformat(),
                    'acknowledged': a.acknowledged,
                    'resolved': a.resolved,
                }
                for a in alerts
            ],
            'total_count': len(alerts),
        }
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/monitoring/acknowledge-alert/{alert_id}")
async def acknowledge_alert(alert_id: str):
    """Acknowledge a monitoring alert."""
    try:

        orchestrator = get_security_posture_orchestrator()
        result = await orchestrator.monitoring_system.acknowledge_alert(alert_id)

        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error acknowledging alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/monitoring/resolve-alert/{alert_id}")
async def resolve_alert(alert_id: str):
    """Resolve a monitoring alert."""
    try:

        orchestrator = get_security_posture_orchestrator()
        result = await orchestrator.monitoring_system.resolve_alert(alert_id)

        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error resolving alert: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predictive/predict-threats")
async def predict_threats(request: Dict[str, Any]):
    """Predict potential security threats."""
    try:

        orchestrator = get_security_posture_orchestrator()

        # Parse historical scores
        historical_scores = [
            (datetime.fromisoformat(item['timestamp']), item['score'])
            for item in request.get('historical_scores', [])
        ]

        predictions = await orchestrator.predictive_intelligence.predict_threats(
            request['organization_id'],
            historical_scores,
            request.get('current_indicators', {})
        )

        return {
            'predictions': [
                {
                    'prediction_id': p.prediction_id,
                    'threat_type': p.threat_type,
                    'probability': p.probability,
                    'confidence': p.confidence.value,
                    'predicted_timeframe': p.predicted_timeframe,
                    'indicators': p.indicators,
                    'recommended_actions': p.recommended_actions,
                    'risk_score': p.risk_score,
                    'created_at': p.created_at.isoformat(),
                }
                for p in predictions
            ],
            'total_predictions': len(predictions),
        }
    except Exception as e:
        logger.error(f"Error predicting threats: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/predictive/predictions")
async def get_predictions(
    organization_id: Optional[str] = None,
    threat_type: Optional[str] = None,
    min_probability: float = 0.0
):
    """Get threat predictions with optional filters."""
    try:

        orchestrator = get_security_posture_orchestrator()
        predictions = await orchestrator.predictive_intelligence.get_predictions(
            organization_id, threat_type, min_probability
        )

        return {
            'predictions': [
                {
                    'prediction_id': p.prediction_id,
                    'threat_type': p.threat_type,
                    'probability': p.probability,
                    'confidence': p.confidence.value,
                    'predicted_timeframe': p.predicted_timeframe,
                    'risk_score': p.risk_score,
                    'created_at': p.created_at.isoformat(),
                }
                for p in predictions
            ],
            'total_count': len(predictions),
        }
    except Exception as e:
        logger.error(f"Error getting predictions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/trends/analyze")
async def analyze_trend(request: Dict[str, Any]):
    """Analyze security trend for a dimension."""
    try:
        from vaulytica.security_posture import get_security_posture_orchestrator, PostureDimension

        orchestrator = get_security_posture_orchestrator()

        # Parse data points
        data_points = [
            (datetime.fromisoformat(item['timestamp']), item['value'])
            for item in request.get('data_points', [])
        ]

        trend = await orchestrator.trend_analysis.analyze_trend(
            request['trend_id'],
            PostureDimension(request['dimension']),
            data_points,
            request.get('forecast_days', 30)
        )

        return {
            'trend_id': trend.trend_id,
            'dimension': trend.dimension.value,
            'direction': trend.direction.value,
            'change_percentage': trend.change_percentage,
            'time_period_days': trend.time_period_days,
            'confidence': trend.confidence.value if trend.confidence else None,
            'forecast': [
                {'timestamp': dt.isoformat(), 'value': val}
                for dt, val in (trend.forecast or [])
            ],
        }
    except Exception as e:
        logger.error(f"Error analyzing trend: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/trends/{trend_id}")
async def get_trend(trend_id: str):
    """Get trend by ID."""
    try:

        orchestrator = get_security_posture_orchestrator()
        trend = await orchestrator.trend_analysis.get_trend(trend_id)

        if not trend:
            raise HTTPException(status_code=404, detail="Trend not found")

        return {
            'trend_id': trend.trend_id,
            'dimension': trend.dimension.value,
            'direction': trend.direction.value,
            'change_percentage': trend.change_percentage,
            'time_period_days': trend.time_period_days,
            'confidence': trend.confidence.value if trend.confidence else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting trend: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/benchmark/compare")
async def compare_to_industry(request: Dict[str, Any]):
    """Compare organization's score to industry benchmarks."""
    try:
        from vaulytica.security_posture import get_security_posture_orchestrator, IndustryType, PostureDimension

        orchestrator = get_security_posture_orchestrator()

        # Parse dimension scores
        dimension_scores = {
            PostureDimension(k): v
            for k, v in request.get('dimension_scores', {}).items()
        }

        comparison = await orchestrator.benchmark_engine.compare_to_industry(
            request['organization_id'],
            request['your_score'],
            IndustryType(request['industry']),
            request['company_size'],
            dimension_scores
        )

        return {
            'your_score': comparison.your_score,
            'industry_average': comparison.industry_average,
            'percentile_rank': comparison.percentile_rank,
            'gap_to_average': comparison.gap_to_average,
            'gap_to_top_performers': comparison.gap_to_top_performers,
            'areas_above_average': comparison.areas_above_average,
            'areas_below_average': comparison.areas_below_average,
            'recommendations': comparison.recommendations,
        }
    except Exception as e:
        logger.error(f"Error comparing to industry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/benchmark/available")
async def get_available_benchmarks():
    """Get list of available industry benchmarks."""
    try:

        orchestrator = get_security_posture_orchestrator()
        benchmarks = await orchestrator.benchmark_engine.get_available_benchmarks()

        return {
            'benchmarks': benchmarks,
            'total_count': len(benchmarks),
        }
    except Exception as e:
        logger.error(f"Error getting benchmarks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/posture/comprehensive-analysis")
async def perform_comprehensive_analysis(request: Dict[str, Any]):
    """Perform comprehensive security posture analysis."""
    try:
        from vaulytica.security_posture import get_security_posture_orchestrator, PostureMetric, PostureDimension, IndustryType

        orchestrator = get_security_posture_orchestrator()

        # Parse metrics
        metrics = []
        for m in request.get('metrics', []):
            metric = PostureMetric(
                metric_id=m['metric_id'],
                name=m['name'],
                dimension=PostureDimension(m['dimension']),
                value=m['value'],
                weight=m.get('weight', 1.0),
                threshold_good=m.get('threshold_good', 90.0),
                threshold_fair=m.get('threshold_fair', 75.0),
                current_status=m.get('current_status', 'unknown')
            )
            metrics.append(metric)

        result = await orchestrator.perform_comprehensive_analysis(
            request['organization_id'],
            metrics,
            IndustryType(request['industry']),
            request['company_size'],
            request.get('current_indicators', {})
        )

        return result
    except Exception as e:
        logger.error(f"Error performing comprehensive analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/posture/statistics")
async def get_posture_statistics():
    """Get comprehensive security posture statistics."""
    try:

        orchestrator = get_security_posture_orchestrator()
        stats = await orchestrator.get_comprehensive_statistics()

        return stats
    except Exception as e:
        logger.error(f"Error getting posture statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Attack Surface Management API Endpoints (v0.30.0)
# ============================================================================

@app.post("/asm/discover-assets")
async def discover_assets(request: Dict[str, Any]):
    """Discover assets for organization."""
    try:
        from vaulytica.attack_surface_management import get_attack_surface_discovery

        discovery = get_attack_surface_discovery()

        assets = await discovery.discover_assets(
            organization_id=request['organization_id'],
            domains=request['domains'],
            scan_depth=request.get('scan_depth', 'standard')
        )

        return {
            'success': True,
            'assets': [
                {
                    'asset_id': a.asset_id,
                    'asset_type': a.asset_type,
                    'name': a.name,
                    'is_public': a.is_public,
                    'exposure_level': a.exposure_level,
                    'exposure_score': a.exposure_score,
                    'risk_score': a.risk_score,
                    'is_shadow_it': a.is_shadow_it,
                }
                for a in assets
            ],
            'total_count': len(assets)
        }
    except Exception as e:
        logger.error(f"Error discovering assets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/asm/assets")
async def get_assets(
    organization_id: str = Query(...),
    asset_type: Optional[str] = Query(None),
    is_public: Optional[bool] = Query(None),
    is_shadow_it: Optional[bool] = Query(None)
):
    """Get discovered assets with optional filters."""
    try:

        discovery = get_attack_surface_discovery()

        # Get all assets for organization
        all_assets = [a for a in discovery.assets.values()]

        # Apply filters
        filtered_assets = all_assets
        if asset_type:
            filtered_assets = [a for a in filtered_assets if a.asset_type == asset_type]
        if is_public is not None:
            filtered_assets = [a for a in filtered_assets if a.is_public == is_public]
        if is_shadow_it is not None:
            filtered_assets = [a for a in filtered_assets if a.is_shadow_it == is_shadow_it]

        return {
            'success': True,
            'assets': [
                {
                    'asset_id': a.asset_id,
                    'asset_type': a.asset_type,
                    'name': a.name,
                    'is_public': a.is_public,
                    'exposure_level': a.exposure_level,
                    'exposure_score': a.exposure_score,
                    'risk_score': a.risk_score,
                    'is_shadow_it': a.is_shadow_it,
                }
                for a in filtered_assets
            ],
            'total_count': len(filtered_assets)
        }
    except Exception as e:
        logger.error(f"Error getting assets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/asm/asset/{asset_id}")
async def get_asset(asset_id: str):
    """Get asset by ID."""
    try:

        discovery = get_attack_surface_discovery()

        if asset_id not in discovery.assets:
            raise HTTPException(status_code=404, detail=f"Asset not found: {asset_id}")

        asset = discovery.assets[asset_id]

        return {
            'success': True,
            'asset': {
                'asset_id': asset.asset_id,
                'asset_type': asset.asset_type,
                'name': asset.name,
                'description': asset.description,
                'discovered_at': asset.discovered_at.isoformat(),
                'last_seen': asset.last_seen.isoformat(),
                'ip_addresses': asset.ip_addresses,
                'domains': asset.domains,
                'ports': asset.ports,
                'services': asset.services,
                'technologies': asset.technologies,
                'is_public': asset.is_public,
                'exposure_level': asset.exposure_level,
                'exposure_score': asset.exposure_score,
                'vulnerabilities': asset.vulnerabilities,
                'cve_ids': asset.cve_ids,
                'misconfigurations': asset.misconfigurations,
                'owner': asset.owner,
                'business_unit': asset.business_unit,
                'is_shadow_it': asset.is_shadow_it,
                'is_approved': asset.is_approved,
                'risk_score': asset.risk_score,
                'criticality': asset.criticality,
                'tags': asset.tags,
                'metadata': asset.metadata,
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting asset: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/asm/generate-report")
async def generate_attack_surface_report(request: Dict[str, Any]):
    """Generate attack surface report."""
    try:

        discovery = get_attack_surface_discovery()

        report = await discovery.generate_attack_surface_report(request['organization_id'])

        return {
            'success': True,
            'report': {
                'report_id': report.report_id,
                'organization_id': report.organization_id,
                'generated_at': report.generated_at.isoformat(),
                'total_assets': report.total_assets,
                'assets_by_type': {k.value: v for k, v in report.assets_by_type.items()},
                'public_assets': report.public_assets,
                'shadow_it_assets': report.shadow_it_assets,
                'critical_exposures': report.critical_exposures,
                'high_exposures': report.high_exposures,
                'medium_exposures': report.medium_exposures,
                'low_exposures': report.low_exposures,
                'average_exposure_score': report.average_exposure_score,
                'total_vulnerabilities': report.total_vulnerabilities,
                'critical_vulnerabilities': report.critical_vulnerabilities,
                'high_vulnerabilities': report.high_vulnerabilities,
                'unique_cves': report.unique_cves,
                'overall_risk_score': report.overall_risk_score,
                'recommendations': report.recommendations,
                'quick_wins': report.quick_wins,
                'asset_growth_rate': report.asset_growth_rate,
                'exposure_trend': report.exposure_trend,
            }
        }
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/asm/statistics")
async def get_asm_statistics():
    """Get attack surface discovery statistics."""
    try:

        discovery = get_attack_surface_discovery()
        stats = discovery.get_statistics()

        return {
            'success': True,
            'statistics': stats
        }
    except Exception as e:
        logger.error(f"Error getting ASM statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Security Data Lake API Endpoints (v0.30.0)
# ============================================================================

@app.post("/datalake/ingest")
async def ingest_data(request: Dict[str, Any]):
    """Ingest security data into data lake."""
    try:
        from vaulytica.attack_surface_management import get_security_data_lake, DataSourceType

        data_lake = get_security_data_lake()

        record_ids = await data_lake.ingest_data(
            source_type=DataSourceType(request['source_type']),
            source_name=request['source_name'],
            records=request['records'],
            retention_days=request.get('retention_days', 90)
        )

        return {
            'success': True,
            'record_ids': record_ids,
            'count': len(record_ids)
        }
    except Exception as e:
        logger.error(f"Error ingesting data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/datalake/query")
async def query_data(request: Dict[str, Any]):
    """Query security data lake."""
    try:
        from vaulytica.attack_surface_management import get_security_data_lake

        data_lake = get_security_data_lake()

        records = await data_lake.query_data(
            filters=request.get('filters', {}),
            limit=request.get('limit', 100),
            offset=request.get('offset', 0)
        )

        return {
            'success': True,
            'records': [
                {
                    'record_id': r.record_id,
                    'source_type': r.source_type,
                    'source_name': r.source_name,
                    'timestamp': r.timestamp.isoformat(),
                    'event_type': r.event_type,
                    'severity': r.severity,
                    'source_ip': r.source_ip,
                    'destination_ip': r.destination_ip,
                    'user': r.user,
                    'action': r.action,
                    'result': r.result,
                }
                for r in records
            ],
            'count': len(records)
        }
    except Exception as e:
        logger.error(f"Error querying data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/datalake/record/{record_id}")
async def get_record(record_id: str):
    """Get record by ID."""
    try:

        data_lake = get_security_data_lake()

        if record_id not in data_lake.records:
            raise HTTPException(status_code=404, detail=f"Record not found: {record_id}")

        record = data_lake.records[record_id]

        return {
            'success': True,
            'record': {
                'record_id': record.record_id,
                'source_type': record.source_type,
                'source_name': record.source_name,
                'timestamp': record.timestamp.isoformat(),
                'ingested_at': record.ingested_at.isoformat(),
                'event_type': record.event_type,
                'severity': record.severity,
                'source_ip': record.source_ip,
                'destination_ip': record.destination_ip,
                'user': record.user,
                'action': record.action,
                'result': record.result,
                'raw_data': record.raw_data,
                'enriched_data': record.enriched_data,
                'tags': record.tags,
                'retention_days': record.retention_days,
                'expires_at': record.expires_at.isoformat(),
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting record: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/datalake/cleanup")
async def cleanup_expired_data():
    """Cleanup expired data from data lake."""
    try:

        data_lake = get_security_data_lake()

        deleted_count = await data_lake.cleanup_expired_data()

        return {
            'success': True,
            'deleted_count': deleted_count
        }
    except Exception as e:
        logger.error(f"Error cleaning up data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/datalake/statistics")
async def get_datalake_statistics():
    """Get data lake statistics."""
    try:

        data_lake = get_security_data_lake()
        stats = data_lake.get_statistics()

        return {
            'success': True,
            'statistics': stats
        }
    except Exception as e:
        logger.error(f"Error getting data lake statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Threat Modeling API Endpoints (v0.30.0)
# ============================================================================

@app.post("/threatmodel/create")
async def create_threat_model(request: Dict[str, Any]):
    """Create threat model."""
    try:
        from vaulytica.attack_surface_management import get_threat_modeling_engine

        threat_modeling = get_threat_modeling_engine()

        model = await threat_modeling.create_threat_model(
            system_name=request['system_name'],
            system_type=request['system_type'],
            components=request['components'],
            data_flows=request.get('data_flows', []),
            trust_boundaries=request.get('trust_boundaries', []),
            owner=request['owner']
        )

        return {
            'success': True,
            'model': {
                'model_id': model.model_id,
                'name': model.name,
                'description': model.description,
                'system_name': model.system_name,
                'system_type': model.system_type,
                'total_threats': model.total_threats,
                'critical_threats': model.critical_threats,
                'high_threats': model.high_threats,
                'overall_risk_score': model.overall_risk_score,
                'residual_risk_score': model.residual_risk_score,
                'mitigation_coverage': model.mitigation_coverage,
                'owner': model.owner,
            }
        }
    except Exception as e:
        logger.error(f"Error creating threat model: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threatmodel/{model_id}")
async def get_threat_model(model_id: str):
    """Get threat model by ID."""
    try:

        threat_modeling = get_threat_modeling_engine()

        if model_id not in threat_modeling.models:
            raise HTTPException(status_code=404, detail=f"Threat model not found: {model_id}")

        model = threat_modeling.models[model_id]

        return {
            'success': True,
            'model': {
                'model_id': model.model_id,
                'name': model.name,
                'description': model.description,
                'created_at': model.created_at.isoformat(),
                'updated_at': model.updated_at.isoformat(),
                'system_name': model.system_name,
                'system_type': model.system_type,
                'components': model.components,
                'data_flows': model.data_flows,
                'trust_boundaries': model.trust_boundaries,
                'threats': [
                    {
                        'threat_id': t.threat_id,
                        'category': t.category,
                        'title': t.title,
                        'description': t.description,
                        'affected_component': t.affected_component,
                        'risk_score': t.risk_score,
                        'likelihood': t.likelihood,
                        'impact': t.impact,
                        'mitigation_status': t.mitigation_status,
                    }
                    for t in model.threats
                ],
                'total_threats': model.total_threats,
                'critical_threats': model.critical_threats,
                'high_threats': model.high_threats,
                'overall_risk_score': model.overall_risk_score,
                'residual_risk_score': model.residual_risk_score,
                'mitigations': model.mitigations,
                'mitigation_coverage': model.mitigation_coverage,
                'owner': model.owner,
                'reviewers': model.reviewers,
                'last_reviewed': model.last_reviewed.isoformat(),
                'next_review': model.next_review.isoformat(),
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting threat model: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threatmodel/models")
async def get_all_threat_models():
    """Get all threat models."""
    try:

        threat_modeling = get_threat_modeling_engine()

        models = list(threat_modeling.models.values())

        return {
            'success': True,
            'models': [
                {
                    'model_id': m.model_id,
                    'name': m.name,
                    'system_name': m.system_name,
                    'system_type': m.system_type,
                    'total_threats': m.total_threats,
                    'critical_threats': m.critical_threats,
                    'overall_risk_score': m.overall_risk_score,
                    'residual_risk_score': m.residual_risk_score,
                    'mitigation_coverage': m.mitigation_coverage,
                }
                for m in models
            ],
            'total_count': len(models)
        }
    except Exception as e:
        logger.error(f"Error getting threat models: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/threatmodel/statistics")
async def get_threat_modeling_statistics():
    """Get threat modeling statistics."""
    try:

        threat_modeling = get_threat_modeling_engine()
        stats = threat_modeling.get_statistics()

        return {
            'success': True,
            'statistics': stats
        }
    except Exception as e:
        logger.error(f"Error getting threat modeling statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Security Metrics Dashboard API Endpoints (v0.30.0)
# ============================================================================

@app.post("/metrics/track")
async def track_metric(request: Dict[str, Any]):
    """Track security metric."""
    try:
        from vaulytica.attack_surface_management import get_security_metrics_dashboard

        dashboard = get_security_metrics_dashboard()

        metric = await dashboard.track_metric(
            name=request['name'],
            category=request['category'],
            current_value=request['current_value'],
            target_value=request['target_value'],
            unit=request.get('unit', 'count'),
            is_higher_better=request.get('is_higher_better', True)
        )

        return {
            'success': True,
            'metric': {
                'metric_id': metric.metric_id,
                'name': metric.name,
                'category': metric.category,
                'current_value': metric.current_value,
                'previous_value': metric.previous_value,
                'target_value': metric.target_value,
                'trend': metric.trend,
                'change_percentage': metric.change_percentage,
                'unit': metric.unit,
            }
        }
    except Exception as e:
        logger.error(f"Error tracking metric: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/metrics/dashboard")
async def generate_executive_dashboard(request: Dict[str, Any]):
    """Generate executive dashboard."""
    try:

        dashboard = get_security_metrics_dashboard()

        exec_dashboard = await dashboard.generate_executive_dashboard(request['organization_id'])

        return {
            'success': True,
            'dashboard': exec_dashboard
        }
    except Exception as e:
        logger.error(f"Error generating dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/metrics/statistics")
async def get_metrics_statistics():
    """Get metrics dashboard statistics."""
    try:

        dashboard = get_security_metrics_dashboard()
        stats = dashboard.get_statistics()

        return {
            'success': True,
            'statistics': stats
        }
    except Exception as e:
        logger.error(f"Error getting metrics statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Incident Simulation API Endpoints (v0.30.0)
# ============================================================================

@app.post("/simulation/create")
async def create_simulation(request: Dict[str, Any]):
    """Create incident simulation."""
    try:
        from vaulytica.attack_surface_management import get_incident_simulation_platform

        simulation_platform = get_incident_simulation_platform()

        simulation = await simulation_platform.create_simulation(
            scenario_type=request['scenario_type'],
            participants=request['participants'],
            facilitator=request['facilitator']
        )

        return {
            'success': True,
            'simulation': {
                'simulation_id': simulation.simulation_id,
                'name': simulation.name,
                'description': simulation.description,
                'scenario_type': simulation.scenario_type,
                'participants': simulation.participants,
                'facilitator': simulation.facilitator,
                'expected_actions': simulation.expected_actions,
                'success_criteria': simulation.success_criteria,
                'status': simulation.status,
            }
        }
    except Exception as e:
        logger.error(f"Error creating simulation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/simulation/run/{simulation_id}")
async def run_simulation(simulation_id: str):
    """Run incident simulation."""
    try:

        simulation_platform = get_incident_simulation_platform()

        simulation = await simulation_platform.run_simulation(simulation_id)

        return {
            'success': True,
            'simulation': {
                'simulation_id': simulation.simulation_id,
                'name': simulation.name,
                'status': simulation.status,
                'started_at': simulation.started_at.isoformat() if simulation.started_at else None,
                'completed_at': simulation.completed_at.isoformat() if simulation.completed_at else None,
                'response_time_minutes': simulation.response_time_minutes,
                'success_rate': simulation.success_rate,
                'actions_taken': simulation.actions_taken,
                'strengths': simulation.strengths,
                'weaknesses': simulation.weaknesses,
                'recommendations': simulation.recommendations,
            }
        }
    except Exception as e:
        logger.error(f"Error running simulation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/simulation/statistics")
async def get_simulation_statistics():
    """Get simulation platform statistics."""
    try:

        simulation_platform = get_incident_simulation_platform()
        stats = simulation_platform.get_statistics()

        return {
            'success': True,
            'statistics': stats
        }
    except Exception as e:
        logger.error(f"Error getting simulation statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# ASM Orchestration API Endpoint (v0.30.0)
# ============================================================================

@app.post("/asm/comprehensive-assessment")
async def perform_comprehensive_assessment(request: Dict[str, Any]):
    """Perform comprehensive security assessment."""
    try:
        from vaulytica.attack_surface_management import get_asm_orchestrator

        orchestrator = get_asm_orchestrator()

        assessment = await orchestrator.perform_comprehensive_assessment(
            organization_id=request['organization_id'],
            domains=request['domains'],
            system_name=request['system_name'],
            system_type=request['system_type'],
            components=request['components']
        )

        return {
            'success': True,
            'assessment': assessment
        }
    except Exception as e:
        logger.error(f"Error performing comprehensive assessment: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
