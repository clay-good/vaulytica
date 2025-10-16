"""Webhook receiver endpoints for real-time event ingestion."""

import hashlib
import hmac
import json
from datetime import datetime
from typing import Optional, Dict, Any, Callable
from fastapi import APIRouter, Request, HTTPException, Header, BackgroundTasks, status
from pydantic import BaseModel, Field
from vaulytica.logger import get_logger
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
from vaulytica.config import VaulyticaConfig

logger = get_logger(__name__)

# Create webhook router
webhook_router = APIRouter(prefix="/webhooks", tags=["webhooks"])


class WebhookEvent(BaseModel):
    """Webhook event metadata."""
    
    webhook_id: str
    source: str
    timestamp: str
    event_count: int
    signature_valid: bool = True


class WebhookResponse(BaseModel):
    """Webhook response."""
    
    status: str
    webhook_id: str
    events_received: int
    events_processed: int
    message: str


class WebhookProcessor:
    """Process webhook events asynchronously."""
    
    def __init__(
        self,
        config: VaulyticaConfig,
        agent: SecurityAnalystAgent,
        rag: Optional[IncidentRAG] = None,
        cache: Optional[AnalysisCache] = None
    ):
        self.config = config
        self.agent = agent
        self.rag = rag
        self.cache = cache
        self.parsers = {
            'guardduty': GuardDutyParser(),
            'gcp-scc': GCPSecurityCommandCenterParser(),
            'datadog': DatadogParser(),
            'crowdstrike': CrowdStrikeParser(),
            'snowflake': SnowflakeParser()
        }
    
    async def process_event(self, source: str, raw_event: Dict[str, Any]):
        """Process a single webhook event."""
        try:
            # Parse event
            parser = self.parsers.get(source)
            if not parser:
                logger.error(f"No parser for source: {source}")
                return
            
            event = parser.parse(raw_event)
            logger.info(f"Processing webhook event: {event.event_id}")
            
            # Check cache
            if self.cache:
                cached = self.cache.get(event)
                if cached:
                    logger.info(f"Using cached result for {event.event_id}")
                    return cached
            
            # Find similar incidents
            historical_context = []
            if self.rag:
                try:
                    historical_context = self.rag.find_similar_incidents(event, max_results=5)
                except Exception as e:
                    logger.warning(f"RAG query failed: {e}")
            
            # Analyze
            result = await self.agent.analyze([event], historical_context=historical_context)
            
            # Store in cache
            if self.cache:
                self.cache.set(event, result)
            
            # Store in RAG
            if self.rag:
                self.rag.store_incident(event, result)
            
            logger.info(f"Webhook event processed: {event.event_id}, risk={result.risk_score}")
            return result
            
        except Exception as e:
            logger.exception(f"Failed to process webhook event: {e}")
            raise


def verify_signature(
    payload: bytes,
    signature: str,
    secret: str,
    algorithm: str = "sha256"
) -> bool:
    """
    Verify webhook signature.
    
    Args:
        payload: Raw request body
        signature: Signature from header
        secret: Webhook secret
        algorithm: Hash algorithm (sha256, sha1)
    
    Returns:
        True if signature is valid
    """
    if not secret or not signature:
        return False
    
    try:
        # Compute expected signature
        if algorithm == "sha256":
            expected = hmac.new(
                secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
        elif algorithm == "sha1":
            expected = hmac.new(
                secret.encode(),
                payload,
                hashlib.sha1
            ).hexdigest()
        else:
            return False
        
        # Compare signatures (constant time)
        return hmac.compare_digest(signature, expected)
        
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False


# Global processor instance (set by API server)
processor: Optional[WebhookProcessor] = None


def set_webhook_processor(proc: WebhookProcessor):
    """Set global webhook processor."""
    global processor
    processor = proc


@webhook_router.post("/guardduty", response_model=WebhookResponse)
async def guardduty_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_amz_sns_message_type: Optional[str] = Header(None),
    x_amz_sns_topic_arn: Optional[str] = Header(None)
):
    """
    AWS GuardDuty webhook endpoint.
    
    Receives events from AWS SNS topic subscribed to GuardDuty findings.
    Supports SNS subscription confirmation and notification messages.
    """
    if not processor:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook processor not initialized"
        )
    
    try:
        body = await request.body()
        data = json.loads(body)
        
        # Handle SNS subscription confirmation
        if x_amz_sns_message_type == "SubscriptionConfirmation":
            logger.info(f"SNS subscription confirmation: {data.get('SubscribeURL')}")
            return WebhookResponse(
                status="confirmed",
                webhook_id=data.get("MessageId", "unknown"),
                events_received=0,
                events_processed=0,
                message="SNS subscription confirmed. Visit SubscribeURL to complete."
            )
        
        # Handle notification
        if x_amz_sns_message_type == "Notification":
            message = json.loads(data.get("Message", "{}"))
            
            # Process in background
            background_tasks.add_task(
                processor.process_event,
                "guardduty",
                message
            )
            
            return WebhookResponse(
                status="accepted",
                webhook_id=data.get("MessageId", "unknown"),
                events_received=1,
                events_processed=0,
                message="GuardDuty event accepted for processing"
            )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported message type: {x_amz_sns_message_type}"
        )
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in GuardDuty webhook: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )
    except Exception as e:
        logger.exception("GuardDuty webhook error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@webhook_router.post("/datadog", response_model=WebhookResponse)
async def datadog_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_datadog_signature: Optional[str] = Header(None)
):
    """
    Datadog webhook endpoint.
    
    Receives security signals from Datadog Security Monitoring.
    Supports signature verification for webhook authentication.
    """
    if not processor:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook processor not initialized"
        )
    
    try:
        body = await request.body()
        
        # Verify signature if secret is configured
        webhook_secret = processor.config.webhook_secret if hasattr(processor.config, 'webhook_secret') else None
        if webhook_secret and x_datadog_signature:
            if not verify_signature(body, x_datadog_signature, webhook_secret):
                logger.warning("Invalid Datadog webhook signature")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid webhook signature"
                )
        
        data = json.loads(body)
        
        # Process in background
        background_tasks.add_task(
            processor.process_event,
            "datadog",
            data
        )
        
        return WebhookResponse(
            status="accepted",
            webhook_id=data.get("id", "unknown"),
            events_received=1,
            events_processed=0,
            message="Datadog event accepted for processing"
        )
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in Datadog webhook: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Datadog webhook error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@webhook_router.post("/crowdstrike", response_model=WebhookResponse)
async def crowdstrike_webhook(
    request: Request,
    background_tasks: BackgroundTasks
):
    """
    CrowdStrike webhook endpoint.
    
    Receives detections from CrowdStrike Falcon platform.
    """
    if not processor:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook processor not initialized"
        )
    
    try:
        body = await request.body()
        data = json.loads(body)
        
        # CrowdStrike can send batch events
        events = data if isinstance(data, list) else [data]
        
        # Process each event in background
        for event in events:
            background_tasks.add_task(
                processor.process_event,
                "crowdstrike",
                event
            )
        
        return WebhookResponse(
            status="accepted",
            webhook_id=f"cs-{datetime.utcnow().timestamp()}",
            events_received=len(events),
            events_processed=0,
            message=f"CrowdStrike events accepted for processing"
        )
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in CrowdStrike webhook: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON payload"
        )
    except Exception as e:
        logger.exception("CrowdStrike webhook error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

