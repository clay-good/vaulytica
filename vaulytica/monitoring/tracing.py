"""
Distributed Tracing Module

Provides OpenTelemetry-based distributed tracing for request tracking across services.
"""

import time
import uuid
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

# Try to import OpenTelemetry
try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.trace import Status, StatusCode
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    logger.warning("OpenTelemetry not available. Install with: pip install opentelemetry-api opentelemetry-sdk")


class SpanKind(str, Enum):
    """Span kinds"""
    INTERNAL = "internal"
    SERVER = "server"
    CLIENT = "client"
    PRODUCER = "producer"
    CONSUMER = "consumer"


@dataclass
class Span:
    """Trace span"""
    span_id: str
    trace_id: str
    parent_span_id: Optional[str]
    name: str
    kind: SpanKind
    start_time: float
    end_time: Optional[float] = None
    duration: Optional[float] = None
    status: str = "ok"
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: list = field(default_factory=list)

    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        """Add an event to the span"""
        self.events.append({
            'name': name,
            'timestamp': time.time(),
            'attributes': attributes or {}
        })

    def set_attribute(self, key: str, value: Any) -> None:
        """Set a span attribute"""
        self.attributes[key] = value

    def set_status(self, status: str, description: Optional[str] = None) -> None:
        """Set span status"""
        self.status = status
        if description:
            self.attributes['status_description'] = description

    def end(self) -> None:
        """End the span"""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time


class TracingContext:
    """Thread-local tracing context"""

    def __init__(self):
        self.trace_id: Optional[str] = None
        self.span_stack: list[Span] = []

    def start_trace(self, trace_id: Optional[str] = None) -> str:
        """Start a new trace"""
        self.trace_id = trace_id or str(uuid.uuid4())
        return self.trace_id

    def push_span(self, span: Span) -> None:
        """Push a span onto the stack"""
        self.span_stack.append(span)

    def pop_span(self) -> Optional[Span]:
        """Pop a span from the stack"""
        if self.span_stack:
            return self.span_stack.pop()
        return None

    def current_span(self) -> Optional[Span]:
        """Get the current span"""
        if self.span_stack:
            return self.span_stack[-1]
        return None

    def clear(self) -> None:
        """Clear the context"""
        self.trace_id = None
        self.span_stack.clear()


class DistributedTracer:
    """
    Distributed tracing system.

    Features:
    - OpenTelemetry integration
    - Custom span tracking
    - Request correlation
    - Performance analysis
    """

    def __init__(self, service_name: str = "vaulytica", enable_otel: bool = True):
        """
        Initialize distributed tracer.

        Args:
            service_name: Name of the service
            enable_otel: Enable OpenTelemetry integration
        """
        self.service_name = service_name
        self.enable_otel = enable_otel and OTEL_AVAILABLE

        # Tracing storage
        self.traces: Dict[str, list[Span]] = {}
        self.contexts: Dict[str, TracingContext] = {}

        # Initialize OpenTelemetry
        if self.enable_otel:
            self._initialize_otel()

        logger.info(f"DistributedTracer initialized for {service_name} (OpenTelemetry: {self.enable_otel})")

    def _initialize_otel(self):
        """Initialize OpenTelemetry"""
        try:
            resource = Resource.create({"service.name": self.service_name})
            provider = TracerProvider(resource=resource)

            # Add console exporter for development
            processor = BatchSpanProcessor(ConsoleSpanExporter())
            provider.add_span_processor(processor)

            trace.set_tracer_provider(provider)
            self.tracer = trace.get_tracer(__name__)
        except Exception as e:
            logger.error(f"Failed to initialize OpenTelemetry: {e}")
            self.enable_otel = False

    def start_trace(self, trace_id: Optional[str] = None) -> str:
        """Start a new trace"""
        trace_id = trace_id or str(uuid.uuid4())
        self.traces[trace_id] = []
        self.contexts[trace_id] = TracingContext()
        self.contexts[trace_id].start_trace(trace_id)
        return trace_id

    def start_span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None
    ) -> Span:
        """Start a new span"""
        # Get or create trace
        if trace_id is None:
            trace_id = self.start_trace()
        elif trace_id not in self.traces:
            self.start_trace(trace_id)

        context = self.contexts[trace_id]
        parent_span = context.current_span()

        span = Span(
            span_id=str(uuid.uuid4()),
            trace_id=trace_id,
            parent_span_id=parent_span.span_id if parent_span else None,
            name=name,
            kind=kind,
            start_time=time.time(),
            attributes=attributes or {}
        )

        context.push_span(span)
        self.traces[trace_id].append(span)

        return span

    def end_span(self, span: Span) -> None:
        """End a span"""
        span.end()

        if span.trace_id in self.contexts:
            self.contexts[span.trace_id].pop_span()

    @contextmanager
    def trace_span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: Optional[Dict[str, Any]] = None
    ) -> None:
        """Context manager for tracing a span"""
        span = self.start_span(name, trace_id, kind, attributes)
        try:
            yield span
            span.set_status("ok")
        except Exception as e:
            span.set_status("error", str(e))
            raise
        finally:
            self.end_span(span)

    def get_trace(self, trace_id: str) -> list[Span]:
        """Get all spans for a trace"""
        return self.traces.get(trace_id, [])

    def get_trace_summary(self, trace_id: str) -> Dict[str, Any]:
        """Get summary of a trace"""
        spans = self.get_trace(trace_id)
        if not spans:
            return {"error": "Trace not found"}

        total_duration = sum(s.duration for s in spans if s.duration)

        return {
            "trace_id": trace_id,
            "span_count": len(spans),
            "total_duration": total_duration,
            "start_time": min(s.start_time for s in spans),
            "end_time": max(s.end_time for s in spans if s.end_time),
            "status": "error" if any(s.status == "error" for s in spans) else "ok",
            "spans": [
                {
                    "span_id": s.span_id,
                    "name": s.name,
                    "duration": s.duration,
                    "status": s.status
                }
                for s in spans
            ]
        }

    def clear_trace(self, trace_id: str) -> None:
        """Clear a trace from storage"""
        if trace_id in self.traces:
            del self.traces[trace_id]
        if trace_id in self.contexts:
            del self.contexts[trace_id]


def traced(
    span_name: Optional[str] = None,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: Optional[Dict[str, Any]] = None
) -> None:
    """
    Decorator to automatically trace function execution.

    Args:
        span_name: Name of the span (defaults to function name)
        kind: Span kind
        attributes: Additional attributes
    """
    def decorator(func: Callable) -> Callable:
        """Decorator function for distributed tracing."""
        name = span_name or func.__name__

        @wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            """Synchronous wrapper for tracing."""
            tracer = get_distributed_tracer()
            with tracer.trace_span(name, kind=kind, attributes=attributes) as span:
                span.set_attribute("function", func.__name__)
                span.set_attribute("module", func.__module__)
                return func(*args, **kwargs)

        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            tracer = get_distributed_tracer()
            with tracer.trace_span(name, kind=kind, attributes=attributes) as span:
                span.set_attribute("function", func.__name__)
                span.set_attribute("module", func.__module__)
                return await func(*args, **kwargs)

        # Return appropriate wrapper based on function type
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


# Global distributed tracer instance
_distributed_tracer: Optional[DistributedTracer] = None


def get_distributed_tracer(service_name: str = "vaulytica") -> DistributedTracer:
    """Get the global distributed tracer instance."""
    global _distributed_tracer
    if _distributed_tracer is None:
        _distributed_tracer = DistributedTracer(service_name=service_name)
    return _distributed_tracer
