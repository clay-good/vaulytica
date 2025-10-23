"""
Vaulytica Monitoring Module

Provides comprehensive monitoring, metrics, tracing, and health checks.
"""

from .metrics import (
    MetricsCollector,
    MetricType,
    MetricDefinition,
    get_metrics_collector,
    timed_metric
)

from .tracing import (
    DistributedTracer,
    Span,
    SpanKind,
    TracingContext,
    get_distributed_tracer,
    traced
)

__all__ = [
    # Metrics
    'MetricsCollector',
    'MetricType',
    'MetricDefinition',
    'get_metrics_collector',
    'timed_metric',

    # Tracing
    'DistributedTracer',
    'Span',
    'SpanKind',
    'TracingContext',
    'get_distributed_tracer',
    'traced',
]
