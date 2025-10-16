"""REST API server for Vaulytica SOAR integration."""

import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, BackgroundTasks, status
from fastapi.responses import JSONResponse
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
from vaulytica.models import SecurityEvent, AnalysisResult
from vaulytica.logger import setup_logger, get_logger
from vaulytica.webhooks import webhook_router, WebhookProcessor, set_webhook_processor
from vaulytica.notifications import NotificationManager, NotificationConfig

# Initialize logger
setup_logger()
logger = get_logger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Vaulytica API",
    description="AI-powered security event analysis API for SOAR integration with webhook receivers",
    version="0.3.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Include webhook router
app.include_router(webhook_router)

# Global state
config = None
agent = None
rag = None
cache = None
parsers = {}
notification_manager = None


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
    global config, agent, rag, cache, parsers, notification_manager

    try:
        logger.info("Starting Vaulytica API server...")

        # Load configuration
        config = load_config()
        logger.info("Configuration loaded")

        # Initialize components
        agent = SecurityAnalystAgent(config)
        rag = IncidentRAG(config) if config.enable_rag else None
        cache = AnalysisCache(config) if config.enable_cache else None

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

        logger.info("Vaulytica API server started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start API server: {e}")
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down Vaulytica API server...")


# API Endpoints
@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Vaulytica API",
        "version": "0.3.0",
        "description": "AI-powered security event analysis",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    try:
        rag_count = rag.get_collection_stats()["total_incidents"] if rag else 0
        cache_count = cache.get_stats()["total_entries"] if cache else 0
        
        return HealthResponse(
            status="healthy",
            version="0.4.0",
            timestamp=datetime.utcnow().isoformat(),
            rag_incidents=rag_count,
            cache_entries=cache_count
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )


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
        try:
            result = await agent.analyze([event], historical_context=historical_context)
            logger.info(f"Analysis complete for event: {event.event_id}")
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
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


# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.exception("Unhandled exception")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

