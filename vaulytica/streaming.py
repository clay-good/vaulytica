"""
Vaulytica Real-Time Streaming Analytics

Provides real-time event stream processing with:
- Event stream processing with <100ms latency
- Complex Event Processing (CEP) for pattern matching
- Sliding window analytics (time-based and count-based)
- Streaming correlation across multiple event streams
- Streaming aggregations and metrics
- Event replay and time travel for testing
- Backpressure handling for high-volume bursts

Author: Vaulytica Team
Version: 0.16.0
"""

import asyncio
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Any, Optional, Callable, Deque, Set, Tuple
from pydantic import BaseModel, Field
import hashlib
import json

from vaulytica.models import SecurityEvent, Severity, EventCategory
from vaulytica.logger import get_logger

logger = get_logger(__name__)


# ============================================================================
# Data Models and Enums
# ============================================================================

class WindowType(str, Enum):
    """Window types for stream processing."""
    TUMBLING = "tumbling"  # Non-overlapping fixed windows
    SLIDING = "sliding"    # Overlapping windows
    SESSION = "session"    # Dynamic windows based on activity gaps
    COUNT = "count"        # Fixed count windows


class PatternType(str, Enum):
    """Complex event pattern types."""
    SEQUENCE = "sequence"           # Events in specific order
    CONJUNCTION = "conjunction"     # All events must occur
    DISJUNCTION = "disjunction"     # Any event can occur
    NEGATION = "negation"           # Event must NOT occur
    ITERATION = "iteration"         # Event repeats N times
    TEMPORAL = "temporal"           # Events within time window


class StreamState(str, Enum):
    """Stream processor state."""
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class StreamWindow:
    """Represents a time or count-based window."""
    window_id: str
    window_type: WindowType
    start_time: datetime
    end_time: Optional[datetime]
    events: List[SecurityEvent] = field(default_factory=list)
    event_count: int = 0
    aggregations: Dict[str, Any] = field(default_factory=dict)

    def add_event(self, event: SecurityEvent) -> None:
        """Add event to window."""
        self.events.append(event)
        self.event_count += 1

    def is_complete(self, current_time: datetime, window_size: timedelta) -> bool:
        """Check if window is complete."""
        if self.window_type == WindowType.TUMBLING:
            return current_time >= self.start_time + window_size
        elif self.window_type == WindowType.SLIDING:
            return current_time >= self.start_time + window_size
        return False


@dataclass
class CEPPattern:
    """Complex Event Processing pattern definition."""
    pattern_id: str
    pattern_name: str
    pattern_type: PatternType
    conditions: List[Dict[str, Any]]
    time_window: timedelta
    min_occurrences: int = 1
    max_occurrences: Optional[int] = None
    description: str = ""
    severity: Severity = Severity.MEDIUM

    def matches(self, events: List[SecurityEvent]) -> bool:
        """Check if events match this pattern."""
        if len(events) < self.min_occurrences:
            return False

        if self.max_occurrences and len(events) > self.max_occurrences:
            return False

        # Check time window
        if len(events) > 1:
            time_span = events[-1].timestamp - events[0].timestamp
            if time_span > self.time_window:
                return False

        # Check pattern-specific conditions
        if self.pattern_type == PatternType.SEQUENCE:
            return self._check_sequence(events)
        elif self.pattern_type == PatternType.CONJUNCTION:
            return self._check_conjunction(events)
        elif self.pattern_type == PatternType.ITERATION:
            return self._check_iteration(events)

        return True

    def _check_sequence(self, events: List[SecurityEvent]) -> bool:
        """Check if events match sequence pattern."""
        if len(events) != len(self.conditions):
            return False

        for event, condition in zip(events, self.conditions):
            if not self._event_matches_condition(event, condition):
                return False
        return True

    def _check_conjunction(self, events: List[SecurityEvent]) -> bool:
        """Check if all conditions are met."""
        matched_conditions = set()
        for event in events:
            for i, condition in enumerate(self.conditions):
                if self._event_matches_condition(event, condition):
                    matched_conditions.add(i)
        return len(matched_conditions) == len(self.conditions)

    def _check_iteration(self, events: List[SecurityEvent]) -> bool:
        """Check if event repeats N times."""
        if not self.conditions:
            return False

        condition = self.conditions[0]
        matches = sum(1 for e in events if self._event_matches_condition(e, condition))

        if matches < self.min_occurrences:
            return False
        if self.max_occurrences and matches > self.max_occurrences:
            return False
        return True

    def _event_matches_condition(self, event: SecurityEvent, condition: Dict[str, Any]) -> bool:
        """Check if event matches condition."""
        for key, value in condition.items():
            if key == "severity":
                if event.severity.value != value:
                    return False
            elif key == "category":
                if event.category.value != value:
                    return False
            elif key == "source_ip":
                if not any(ti.value == value for ti in event.technical_indicators if ti.indicator_type == "ip"):
                    return False
            elif key == "contains":
                if value.lower() not in event.description.lower():
                    return False
        return True


@dataclass
class PatternMatch:
    """Represents a matched CEP pattern."""
    pattern_id: str
    pattern_name: str
    matched_events: List[SecurityEvent]
    match_time: datetime
    confidence: float
    severity: Severity
    description: str


class StreamMetrics(BaseModel):
    """Streaming analytics metrics."""
    events_processed: int = 0
    events_per_second: float = 0.0
    patterns_detected: int = 0
    correlations_found: int = 0
    windows_processed: int = 0
    avg_processing_latency_ms: float = 0.0
    max_processing_latency_ms: float = 0.0
    backpressure_events: int = 0
    dropped_events: int = 0
    uptime_seconds: float = 0.0


class StreamAggregation(BaseModel):
    """Aggregated statistics for a stream window."""
    window_id: str
    start_time: datetime
    end_time: datetime
    event_count: int
    severity_distribution: Dict[str, int]
    category_distribution: Dict[str, int]
    unique_sources: int
    unique_targets: int
    top_sources: List[Tuple[str, int]]
    top_targets: List[Tuple[str, int]]
    avg_risk_score: float
    max_severity: str


# ============================================================================
# Event Stream Processor
# ============================================================================

class EventStreamProcessor:
    """
    Real-time event stream processor with sliding windows and aggregations.

    Features:
    - Multiple window types (tumbling, sliding, session, count)
    - Real-time aggregations
    - Backpressure handling
    - Event buffering
    - Latency tracking
    """

    def __init__(
        self,
        window_size: timedelta = timedelta(minutes=5),
        window_type: WindowType = WindowType.TUMBLING,
        max_buffer_size: int = 10000,
        processing_batch_size: int = 100
    ):
        """Initialize event stream processor."""
        self.window_size = window_size
        self.window_type = window_type
        self.max_buffer_size = max_buffer_size
        self.processing_batch_size = processing_batch_size

        # Event buffer and windows
        self.event_buffer: Deque[SecurityEvent] = deque(maxlen=max_buffer_size)
        self.active_windows: Dict[str, StreamWindow] = {}
        self.completed_windows: Deque[StreamWindow] = deque(maxlen=1000)

        # Metrics
        self.metrics = StreamMetrics()
        self.start_time = time.time()
        self.last_metrics_update = time.time()
        self.processing_times: Deque[float] = deque(maxlen=1000)

        # State
        self.state = StreamState.RUNNING
        self.event_handlers: List[Callable] = []

        logger.info(f"EventStreamProcessor initialized: window_size={window_size}, type={window_type}")

    async def process_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """
        Process a single event through the stream.

        Returns processing result with latency and window assignment.
        """
        start_time = time.time()

        try:
            # Check backpressure
            if len(self.event_buffer) >= self.max_buffer_size * 0.9:
                self.metrics.backpressure_events += 1
                logger.warning(f"Backpressure detected: buffer at {len(self.event_buffer)}/{self.max_buffer_size}")

            # Add to buffer
            self.event_buffer.append(event)

            # Assign to window(s)
            windows = self._assign_to_windows(event)

            # Update metrics
            self.metrics.events_processed += 1
            processing_time = (time.time() - start_time) * 1000  # ms
            self.processing_times.append(processing_time)
            self._update_metrics(processing_time)

            # Call event handlers
            for handler in self.event_handlers:
                try:
                    await handler(event)
                except Exception as e:
                    logger.error(f"Event handler error: {e}")

            return {
                "status": "processed",
                "event_id": event.event_id,
                "windows": [w.window_id for w in windows],
                "processing_latency_ms": processing_time,
                "buffer_size": len(self.event_buffer)
            }

        except Exception as e:
            logger.error(f"Error processing event: {e}")
            self.metrics.dropped_events += 1
            return {
                "status": "error",
                "event_id": event.event_id,
                "error": str(e)
            }

    def _assign_to_windows(self, event: SecurityEvent) -> List[StreamWindow]:
        """Assign event to appropriate windows."""
        assigned_windows = []
        current_time = event.timestamp

        if self.window_type == WindowType.TUMBLING:
            # Create or get tumbling window
            window_start = self._get_window_start(current_time)
            window_id = f"tumbling_{window_start.isoformat()}"

            if window_id not in self.active_windows:
                self.active_windows[window_id] = StreamWindow(
                    window_id=window_id,
                    window_type=WindowType.TUMBLING,
                    start_time=window_start,
                    end_time=window_start + self.window_size
                )

            window = self.active_windows[window_id]
            window.add_event(event)
            assigned_windows.append(window)

            # Check if window is complete
            if window.is_complete(current_time, self.window_size):
                self._complete_window(window_id)

        elif self.window_type == WindowType.SLIDING:
            # Sliding windows overlap - event may belong to multiple windows
            window_start = current_time - self.window_size

            # Create new sliding window
            window_id = f"sliding_{current_time.isoformat()}"
            window = StreamWindow(
                window_id=window_id,
                window_type=WindowType.SLIDING,
                start_time=window_start,
                end_time=current_time
            )

            # Add all events in time range
            for buffered_event in self.event_buffer:
                if window_start <= buffered_event.timestamp <= current_time:
                    window.add_event(buffered_event)

            self.active_windows[window_id] = window
            assigned_windows.append(window)

            # Limit active sliding windows
            if len(self.active_windows) > 100:
                oldest_window = min(self.active_windows.keys())
                self._complete_window(oldest_window)

        return assigned_windows

    def _get_window_start(self, timestamp: datetime) -> datetime:
        """Get window start time for tumbling windows."""
        # Align to window boundaries
        seconds = int(self.window_size.total_seconds())
        epoch = int(timestamp.timestamp())
        window_epoch = (epoch // seconds) * seconds
        return datetime.fromtimestamp(window_epoch)

    def _complete_window(self, window_id: str) -> None:
        """Complete a window and compute aggregations."""
        if window_id not in self.active_windows:
            return

        window = self.active_windows.pop(window_id)

        # Compute aggregations
        window.aggregations = self._compute_aggregations(window)

        # Store completed window
        self.completed_windows.append(window)
        self.metrics.windows_processed += 1

        logger.debug(f"Completed window {window_id}: {window.event_count} events")

    def _compute_aggregations(self, window: StreamWindow) -> Dict[str, Any]:
        """Compute aggregations for a window."""
        if not window.events:
            return {}

        # Severity distribution
        severity_dist = defaultdict(int)
        for event in window.events:
            severity_dist[event.severity.value] += 1

        # Category distribution
        category_dist = defaultdict(int)
        for event in window.events:
            category_dist[event.category.value] += 1

        # Source/target analysis
        sources = defaultdict(int)
        targets = defaultdict(int)

        for event in window.events:
            for ti in event.technical_indicators:
                if ti.indicator_type == "ip":
                    sources[ti.value] += 1
                elif ti.indicator_type == "hostname":
                    targets[ti.value] += 1

        # Risk scores
        risk_scores = [5.0] * len(window.events)  # Default risk score
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

        return {
            "severity_distribution": dict(severity_dist),
            "category_distribution": dict(category_dist),
            "unique_sources": len(sources),
            "unique_targets": len(targets),
            "top_sources": sorted(sources.items(), key=lambda x: x[1], reverse=True)[:5],
            "top_targets": sorted(targets.items(), key=lambda x: x[1], reverse=True)[:5],
            "avg_risk_score": avg_risk,
            "max_severity": max(severity_dist.keys(), key=lambda k: Severity[k].value) if severity_dist else "INFO"
        }

    def _update_metrics(self, processing_time: float) -> None:
        """Update streaming metrics."""
        current_time = time.time()

        # Update latency metrics
        if self.processing_times:
            self.metrics.avg_processing_latency_ms = sum(self.processing_times) / len(self.processing_times)
            self.metrics.max_processing_latency_ms = max(self.processing_times)

        # Update throughput (events per second)
        time_delta = current_time - self.last_metrics_update
        if time_delta >= 1.0:  # Update every second
            events_in_period = self.metrics.events_processed
            self.metrics.events_per_second = events_in_period / time_delta
            self.last_metrics_update = current_time

        # Update uptime
        self.metrics.uptime_seconds = current_time - self.start_time

    def get_window_aggregations(self, window_id: Optional[str] = None) -> List[StreamAggregation]:
        """Get aggregations for completed windows."""
        aggregations = []

        windows = [w for w in self.completed_windows if not window_id or w.window_id == window_id]

        for window in windows:
            if window.aggregations:
                agg = StreamAggregation(
                    window_id=window.window_id,
                    start_time=window.start_time,
                    end_time=window.end_time or datetime.now(),
                    event_count=window.event_count,
                    severity_distribution=window.aggregations.get("severity_distribution", {}),
                    category_distribution=window.aggregations.get("category_distribution", {}),
                    unique_sources=window.aggregations.get("unique_sources", 0),
                    unique_targets=window.aggregations.get("unique_targets", 0),
                    top_sources=window.aggregations.get("top_sources", []),
                    top_targets=window.aggregations.get("top_targets", []),
                    avg_risk_score=window.aggregations.get("avg_risk_score", 0.0),
                    max_severity=window.aggregations.get("max_severity", "INFO")
                )
                aggregations.append(agg)

        return aggregations

    def register_event_handler(self, handler: Callable) -> None:
        """Register a handler to be called for each event."""
        self.event_handlers.append(handler)

    def get_metrics(self) -> StreamMetrics:
        """Get current streaming metrics."""
        return self.metrics

    def pause(self) -> None:
        """Pause stream processing."""
        self.state = StreamState.PAUSED
        logger.info("Stream processor paused")

    def resume(self) -> None:
        """Resume stream processing."""
        self.state = StreamState.RUNNING
        logger.info("Stream processor resumed")

    def stop(self) -> None:
        """Stop stream processing."""
        self.state = StreamState.STOPPED
        logger.info("Stream processor stopped")


# ============================================================================
# Complex Event Processing (CEP) Engine
# ============================================================================

class CEPEngine:
    """
    Complex Event Processing engine for pattern detection.

    Features:
    - Multiple pattern types (sequence, conjunction, iteration, temporal)
    - Pattern matching across event streams
    - Confidence scoring
    - Pattern library management
    """

    def __init__(self):
        """Initialize CEP engine."""
        self.patterns: Dict[str, CEPPattern] = {}
        self.pattern_matches: Deque[PatternMatch] = deque(maxlen=1000)
        self.event_buffer: Deque[SecurityEvent] = deque(maxlen=10000)
        self.matches_found = 0

        # Load default patterns
        self._load_default_patterns()

        logger.info(f"CEP Engine initialized with {len(self.patterns)} patterns")

    def _load_default_patterns(self) -> None:
        """Load default CEP patterns."""

        # Pattern 1: Brute Force Attack (multiple failed logins followed by success)
        self.add_pattern(CEPPattern(
            pattern_id="brute_force_sequence",
            pattern_name="Brute Force Attack Sequence",
            pattern_type=PatternType.SEQUENCE,
            conditions=[
                {"category": "UNAUTHORIZED_ACCESS", "contains": "failed"},
                {"category": "UNAUTHORIZED_ACCESS", "contains": "failed"},
                {"category": "UNAUTHORIZED_ACCESS", "contains": "failed"},
                {"category": "UNAUTHORIZED_ACCESS", "contains": "success"}
            ],
            time_window=timedelta(minutes=5),
            min_occurrences=4,
            description="Multiple failed login attempts followed by successful authentication",
            severity=Severity.HIGH
        ))

        # Pattern 2: Data Exfiltration (large data transfer after privilege escalation)
        self.add_pattern(CEPPattern(
            pattern_id="data_exfil_after_privesc",
            pattern_name="Data Exfiltration After Privilege Escalation",
            pattern_type=PatternType.SEQUENCE,
            conditions=[
                {"category": "PRIVILEGE_ESCALATION"},
                {"category": "DATA_EXFILTRATION"}
            ],
            time_window=timedelta(hours=1),
            min_occurrences=2,
            description="Privilege escalation followed by data exfiltration",
            severity=Severity.CRITICAL
        ))

        # Pattern 3: Lateral Movement Pattern
        self.add_pattern(CEPPattern(
            pattern_id="lateral_movement_pattern",
            pattern_name="Lateral Movement Pattern",
            pattern_type=PatternType.CONJUNCTION,
            conditions=[
                {"category": "LATERAL_MOVEMENT"},
                {"category": "UNAUTHORIZED_ACCESS"},
                {"category": "RECONNAISSANCE"}
            ],
            time_window=timedelta(hours=2),
            min_occurrences=3,
            description="Combination of lateral movement, credential access, and discovery",
            severity=Severity.HIGH
        ))

        # Pattern 4: Repeated Failed Access (iteration pattern)
        self.add_pattern(CEPPattern(
            pattern_id="repeated_failed_access",
            pattern_name="Repeated Failed Access Attempts",
            pattern_type=PatternType.ITERATION,
            conditions=[
                {"severity": "MEDIUM", "contains": "denied"}
            ],
            time_window=timedelta(minutes=10),
            min_occurrences=10,
            max_occurrences=None,
            description="Repeated access denied events indicating potential scanning or probing",
            severity=Severity.MEDIUM
        ))

        # Pattern 5: APT Kill Chain
        self.add_pattern(CEPPattern(
            pattern_id="apt_kill_chain",
            pattern_name="APT Kill Chain Sequence",
            pattern_type=PatternType.SEQUENCE,
            conditions=[
                {"category": "UNAUTHORIZED_ACCESS"},
                {"category": "MALWARE"},
                {"category": "PERSISTENCE"},
                {"category": "PRIVILEGE_ESCALATION"},
                {"category": "LATERAL_MOVEMENT"}
            ],
            time_window=timedelta(days=1),
            min_occurrences=5,
            description="Complete APT kill chain from initial access to lateral movement",
            severity=Severity.CRITICAL
        ))

    def add_pattern(self, pattern: CEPPattern) -> None:
        """Add a CEP pattern to the engine."""
        self.patterns[pattern.pattern_id] = pattern
        logger.debug(f"Added CEP pattern: {pattern.pattern_name}")

    def remove_pattern(self, pattern_id: str) -> bool:
        """Remove a CEP pattern."""
        if pattern_id in self.patterns:
            del self.patterns[pattern_id]
            logger.debug(f"Removed CEP pattern: {pattern_id}")
            return True
        return False

    async def process_event(self, event: SecurityEvent) -> List[PatternMatch]:
        """
        Process event and check for pattern matches.

        Returns list of matched patterns.
        """
        # Add to buffer
        self.event_buffer.append(event)

        # Check all patterns
        matches = []
        for pattern in self.patterns.values():
            match = self._check_pattern(pattern, event)
            if match:
                matches.append(match)
                self.pattern_matches.append(match)
                self.matches_found += 1
                logger.info(f"Pattern matched: {pattern.pattern_name}")

        return matches

    def _check_pattern(self, pattern: CEPPattern, new_event: SecurityEvent) -> Optional[PatternMatch]:
        """Check if pattern matches recent events."""
        # Get events within time window
        cutoff_time = new_event.timestamp - pattern.time_window
        recent_events = [e for e in self.event_buffer if e.timestamp >= cutoff_time]

        if not recent_events:
            return None

        # Check if pattern matches
        if pattern.matches(recent_events):
            # Calculate confidence based on how well events match
            confidence = self._calculate_match_confidence(pattern, recent_events)

            return PatternMatch(
                pattern_id=pattern.pattern_id,
                pattern_name=pattern.pattern_name,
                matched_events=recent_events.copy(),
                match_time=new_event.timestamp,
                confidence=confidence,
                severity=pattern.severity,
                description=pattern.description
            )

        return None

    def _calculate_match_confidence(self, pattern: CEPPattern, events: List[SecurityEvent]) -> float:
        """Calculate confidence score for pattern match."""
        base_confidence = 0.7

        # Increase confidence if more events match
        if len(events) > pattern.min_occurrences:
            base_confidence += 0.1

        # Increase confidence if events are closer in time
        if len(events) > 1:
            time_span = events[-1].timestamp - events[0].timestamp
            time_ratio = time_span / pattern.time_window
            if time_ratio < 0.5:  # Events clustered in first half of window
                base_confidence += 0.1

        # Increase confidence for high severity events
        high_severity_count = sum(1 for e in events if e.severity in [Severity.HIGH, Severity.CRITICAL])
        if high_severity_count > len(events) * 0.5:
            base_confidence += 0.1

        return min(base_confidence, 1.0)

    def get_pattern_matches(self, pattern_id: Optional[str] = None, limit: int = 100) -> List[PatternMatch]:
        """Get recent pattern matches."""
        if pattern_id:
            matches = [m for m in self.pattern_matches if m.pattern_id == pattern_id]
        else:
            matches = list(self.pattern_matches)

        return matches[-limit:]

    def get_patterns(self) -> List[CEPPattern]:
        """Get all registered patterns."""
        return list(self.patterns.values())

    def get_statistics(self) -> Dict[str, Any]:
        """Get CEP engine statistics."""
        pattern_stats = {}
        for pattern_id, pattern in self.patterns.items():
            matches = [m for m in self.pattern_matches if m.pattern_id == pattern_id]
            pattern_stats[pattern_id] = {
                "pattern_name": pattern.pattern_name,
                "total_matches": len(matches),
                "avg_confidence": sum(m.confidence for m in matches) / len(matches) if matches else 0.0,
                "last_match": matches[-1].match_time.isoformat() if matches else None
            }

        return {
            "total_patterns": len(self.patterns),
            "total_matches": self.matches_found,
            "events_buffered": len(self.event_buffer),
            "pattern_statistics": pattern_stats
        }


# ============================================================================
# Streaming Correlation Engine
# ============================================================================

@dataclass
class StreamCorrelation:
    """Represents a correlation between events in the stream."""
    correlation_id: str
    correlation_type: str
    correlated_events: List[SecurityEvent]
    correlation_score: float
    detected_at: datetime
    description: str


class StreamingCorrelationEngine:
    """
    Real-time correlation engine for event streams.

    Features:
    - Real-time correlation across multiple event streams
    - Multiple correlation types (temporal, asset, IOC, behavioral)
    - Correlation scoring
    - Correlation graph building
    """

    def __init__(self, correlation_window: timedelta = timedelta(minutes=10)):
        """Initialize streaming correlation engine."""
        self.correlation_window = correlation_window
        self.event_buffer: Deque[SecurityEvent] = deque(maxlen=5000)
        self.correlations: Deque[StreamCorrelation] = deque(maxlen=1000)
        self.correlations_found = 0

        logger.info(f"Streaming Correlation Engine initialized: window={correlation_window}")

    async def process_event(self, event: SecurityEvent) -> List[StreamCorrelation]:
        """Process event and find correlations with recent events."""
        self.event_buffer.append(event)

        # Find correlations
        correlations = []

        # Get events within correlation window
        cutoff_time = event.timestamp - self.correlation_window
        recent_events = [e for e in self.event_buffer if e.timestamp >= cutoff_time and e.event_id != event.event_id]

        # Check different correlation types
        correlations.extend(self._find_temporal_correlations(event, recent_events))
        correlations.extend(self._find_asset_correlations(event, recent_events))
        correlations.extend(self._find_ioc_correlations(event, recent_events))
        correlations.extend(self._find_behavioral_correlations(event, recent_events))

        # Store correlations
        for corr in correlations:
            self.correlations.append(corr)
            self.correlations_found += 1

        return correlations

    def _find_temporal_correlations(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> List[StreamCorrelation]:
        """Find events that occurred close in time."""
        correlations = []

        for other_event in recent_events:
            try:
                # Ensure timestamps are datetime objects
                event_time = event.timestamp if isinstance(event.timestamp, datetime) else datetime.fromisoformat(str(event.timestamp))
                other_time = other_event.timestamp if isinstance(other_event.timestamp, datetime) else datetime.fromisoformat(str(other_event.timestamp))

                time_diff = abs((event_time - other_time).total_seconds())

                # Events within 60 seconds are temporally correlated
                if time_diff <= 60:
                    score = 1.0 - (time_diff / 60.0)

                    correlation = StreamCorrelation(
                        correlation_id=f"temporal_{event.event_id}_{other_event.event_id}",
                        correlation_type="temporal",
                        correlated_events=[event, other_event],
                        correlation_score=score,
                        detected_at=datetime.now(),
                        description=f"Events occurred within {time_diff:.0f} seconds"
                    )
                    correlations.append(correlation)
            except (TypeError, ValueError, AttributeError):
                # Skip if timestamp comparison fails
                continue

        return correlations

    def _find_asset_correlations(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> List[StreamCorrelation]:
        """Find events affecting the same assets."""
        correlations = []

        # Get assets from current event
        event_assets = set()
        for ti in event.technical_indicators:
            if ti.indicator_type in ["ip", "hostname", "username"]:
                event_assets.add(ti.value)

        if not event_assets:
            return correlations

        for other_event in recent_events:
            # Get assets from other event
            other_assets = set()
            for ti in other_event.technical_indicators:
                if ti.indicator_type in ["ip", "hostname", "username"]:
                    other_assets.add(ti.value)

            # Check for overlap
            common_assets = event_assets & other_assets
            if common_assets:
                score = len(common_assets) / max(len(event_assets), len(other_assets))

                correlation = StreamCorrelation(
                    correlation_id=f"asset_{event.event_id}_{other_event.event_id}",
                    correlation_type="asset",
                    correlated_events=[event, other_event],
                    correlation_score=score,
                    detected_at=datetime.now(),
                    description=f"Events share {len(common_assets)} common asset(s): {', '.join(list(common_assets)[:3])}"
                )
                correlations.append(correlation)

        return correlations

    def _find_ioc_correlations(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> List[StreamCorrelation]:
        """Find events with common IOCs."""
        correlations = []

        # Get IOCs from current event
        event_iocs = set()
        for ti in event.technical_indicators:
            if ti.indicator_type in ["ip", "domain", "hash", "url"]:
                event_iocs.add(f"{ti.indicator_type}:{ti.value}")

        if not event_iocs:
            return correlations

        for other_event in recent_events:
            # Get IOCs from other event
            other_iocs = set()
            for ti in other_event.technical_indicators:
                if ti.indicator_type in ["ip", "domain", "hash", "url"]:
                    other_iocs.add(f"{ti.indicator_type}:{ti.value}")

            # Check for overlap
            common_iocs = event_iocs & other_iocs
            if common_iocs:
                score = len(common_iocs) / max(len(event_iocs), len(other_iocs))

                correlation = StreamCorrelation(
                    correlation_id=f"ioc_{event.event_id}_{other_event.event_id}",
                    correlation_type="ioc",
                    correlated_events=[event, other_event],
                    correlation_score=score,
                    detected_at=datetime.now(),
                    description=f"Events share {len(common_iocs)} common IOC(s)"
                )
                correlations.append(correlation)

        return correlations

    def _find_behavioral_correlations(self, event: SecurityEvent, recent_events: List[SecurityEvent]) -> List[StreamCorrelation]:
        """Find events with similar behavioral patterns."""
        correlations = []

        for other_event in recent_events:
            # Check if events have same category and similar severity
            if event.category == other_event.category:
                severity_diff = abs(event.severity.value - other_event.severity.value)

                if severity_diff <= 1:  # Similar severity
                    score = 0.8 - (severity_diff * 0.2)

                    correlation = StreamCorrelation(
                        correlation_id=f"behavioral_{event.event_id}_{other_event.event_id}",
                        correlation_type="behavioral",
                        correlated_events=[event, other_event],
                        correlation_score=score,
                        detected_at=datetime.now(),
                        description=f"Events have same category ({event.category.value}) and similar severity"
                    )
                    correlations.append(correlation)

        return correlations

    def get_correlations(self, correlation_type: Optional[str] = None, limit: int = 100) -> List[StreamCorrelation]:
        """Get recent correlations."""
        if correlation_type:
            correlations = [c for c in self.correlations if c.correlation_type == correlation_type]
        else:
            correlations = list(self.correlations)

        return correlations[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get correlation statistics."""
        type_counts = defaultdict(int)
        for corr in self.correlations:
            type_counts[corr.correlation_type] += 1

        return {
            "total_correlations": self.correlations_found,
            "events_buffered": len(self.event_buffer),
            "correlation_window_minutes": self.correlation_window.total_seconds() / 60,
            "correlations_by_type": dict(type_counts)
        }


# ============================================================================
# Event Replay System
# ============================================================================

class EventReplaySystem:
    """
    Event replay and time travel system for testing and analysis.

    Features:
    - Replay historical events
    - Time travel to specific points
    - Speed control (1x, 2x, 10x, etc.)
    - Event filtering during replay
    """

    def __init__(self):
        """Initialize event replay system."""
        self.stored_events: List[SecurityEvent] = []
        self.replay_position = 0
        self.replay_speed = 1.0
        self.is_replaying = False

        logger.info("Event Replay System initialized")

    def store_events(self, events: List[SecurityEvent]) -> None:
        """Store events for replay."""
        self.stored_events.extend(events)
        self.stored_events.sort(key=lambda e: e.timestamp)
        logger.info(f"Stored {len(events)} events for replay (total: {len(self.stored_events)})")

    async def replay_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        speed: float = 1.0,
        event_handler: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Replay events with optional time range and speed control.

        Args:
            start_time: Start replaying from this time
            end_time: Stop replaying at this time
            speed: Replay speed multiplier (1.0 = real-time, 2.0 = 2x speed)
            event_handler: Async function to call for each event

        Returns:
            Replay statistics
        """
        self.is_replaying = True
        self.replay_speed = speed

        # Filter events by time range
        events_to_replay = self.stored_events
        if start_time:
            events_to_replay = [e for e in events_to_replay if e.timestamp >= start_time]
        if end_time:
            events_to_replay = [e for e in events_to_replay if e.timestamp <= end_time]

        logger.info(f"Starting replay of {len(events_to_replay)} events at {speed}x speed")

        start_replay_time = time.time()
        events_replayed = 0

        for i, event in enumerate(events_to_replay):
            if not self.is_replaying:
                break

            # Calculate delay based on time between events and speed
            if i > 0:
                time_diff = (event.timestamp - events_to_replay[i-1].timestamp).total_seconds()
                delay = time_diff / speed
                if delay > 0:
                    await asyncio.sleep(delay)

            # Call event handler
            if event_handler:
                try:
                    await event_handler(event)
                except Exception as e:
                    logger.error(f"Error in event handler during replay: {e}")

            events_replayed += 1
            self.replay_position = i

        replay_duration = time.time() - start_replay_time
        self.is_replaying = False

        return {
            "events_replayed": events_replayed,
            "replay_duration_seconds": replay_duration,
            "replay_speed": speed,
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None
        }

    def stop_replay(self) -> None:
        """Stop ongoing replay."""
        self.is_replaying = False
        logger.info("Replay stopped")

    def get_events_at_time(self, timestamp: datetime, window: timedelta = timedelta(minutes=5)) -> List[SecurityEvent]:
        """Get events around a specific time (time travel)."""
        start_time = timestamp - window
        end_time = timestamp + window

        events = [e for e in self.stored_events if start_time <= e.timestamp <= end_time]
        return events

    def get_statistics(self) -> Dict[str, Any]:
        """Get replay system statistics."""
        return {
            "total_stored_events": len(self.stored_events),
            "replay_position": self.replay_position,
            "is_replaying": self.is_replaying,
            "replay_speed": self.replay_speed,
            "time_range": {
                "start": self.stored_events[0].timestamp.isoformat() if self.stored_events else None,
                "end": self.stored_events[-1].timestamp.isoformat() if self.stored_events else None
            }
        }


# ============================================================================
# Streaming Analytics Manager
# ============================================================================

class StreamingAnalytics:
    """
    Main streaming analytics manager integrating all components.

    Features:
    - Event stream processing with sliding windows
    - Complex event processing (CEP)
    - Real-time correlation
    - Event replay and time travel
    - Unified metrics and monitoring
    """

    def __init__(
        self,
        window_size: timedelta = timedelta(minutes=5),
        window_type: WindowType = WindowType.TUMBLING,
        correlation_window: timedelta = timedelta(minutes=10)
    ):
        """Initialize streaming analytics."""
        self.stream_processor = EventStreamProcessor(
            window_size=window_size,
            window_type=window_type
        )
        self.cep_engine = CEPEngine()
        self.correlation_engine = StreamingCorrelationEngine(
            correlation_window=correlation_window
        )
        self.replay_system = EventReplaySystem()

        # Register CEP and correlation as event handlers
        self.stream_processor.register_event_handler(self._handle_event_for_cep)
        self.stream_processor.register_event_handler(self._handle_event_for_correlation)

        logger.info("Streaming Analytics initialized")

    async def _handle_event_for_cep(self, event: SecurityEvent) -> None:
        """Handle event for CEP engine."""
        await self.cep_engine.process_event(event)

    async def _handle_event_for_correlation(self, event: SecurityEvent) -> None:
        """Handle event for correlation engine."""
        await self.correlation_engine.process_event(event)

    async def process_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """
        Process event through all streaming analytics components.

        Returns comprehensive analysis including:
        - Stream processing results
        - Pattern matches
        - Correlations
        - Window assignments
        """
        # Process through stream processor (which triggers CEP and correlation)
        stream_result = await self.stream_processor.process_event(event)

        # Store for replay
        self.replay_system.store_events([event])

        # Get pattern matches (already processed by handler)
        pattern_matches = self.cep_engine.get_pattern_matches(limit=10)
        recent_patterns = [m for m in pattern_matches if m.match_time >= event.timestamp - timedelta(seconds=10)]

        # Get correlations (already processed by handler)
        correlations = self.correlation_engine.get_correlations(limit=10)
        recent_correlations = [c for c in correlations if c.detected_at >= datetime.now() - timedelta(seconds=10)]

        return {
            "stream_processing": stream_result,
            "pattern_matches": [
                {
                    "pattern_id": m.pattern_id,
                    "pattern_name": m.pattern_name,
                    "confidence": m.confidence,
                    "severity": m.severity.value,
                    "matched_events": len(m.matched_events),
                    "description": m.description
                }
                for m in recent_patterns
            ],
            "correlations": [
                {
                    "correlation_id": c.correlation_id,
                    "correlation_type": c.correlation_type,
                    "correlation_score": c.correlation_score,
                    "correlated_events": len(c.correlated_events),
                    "description": c.description
                }
                for c in recent_correlations
            ],
            "timestamp": datetime.now().isoformat()
        }

    async def process_batch(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Process a batch of events."""
        results = []
        for event in events:
            result = await self.process_event(event)
            results.append(result)

        return {
            "batch_size": len(events),
            "results": results,
            "summary": {
                "total_patterns": sum(len(r["pattern_matches"]) for r in results),
                "total_correlations": sum(len(r["correlations"]) for r in results)
            }
        }

    def get_window_aggregations(self, window_id: Optional[str] = None) -> List[StreamAggregation]:
        """Get window aggregations from stream processor."""
        return self.stream_processor.get_window_aggregations(window_id)

    def get_pattern_matches(self, pattern_id: Optional[str] = None, limit: int = 100) -> List[PatternMatch]:
        """Get pattern matches from CEP engine."""
        return self.cep_engine.get_pattern_matches(pattern_id, limit)

    def get_correlations(self, correlation_type: Optional[str] = None, limit: int = 100) -> List[StreamCorrelation]:
        """Get correlations from correlation engine."""
        return self.correlation_engine.get_correlations(correlation_type, limit)

    def add_cep_pattern(self, pattern: CEPPattern) -> None:
        """Add a CEP pattern."""
        self.cep_engine.add_pattern(pattern)

    def remove_cep_pattern(self, pattern_id: str) -> bool:
        """Remove a CEP pattern."""
        return self.cep_engine.remove_pattern(pattern_id)

    def get_cep_patterns(self) -> List[CEPPattern]:
        """Get all CEP patterns."""
        return self.cep_engine.get_patterns()

    async def replay_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        speed: float = 1.0
    ) -> Dict[str, Any]:
        """Replay historical events."""
        return await self.replay_system.replay_events(
            start_time=start_time,
            end_time=end_time,
            speed=speed,
            event_handler=self.process_event
        )

    def stop_replay(self) -> None:
        """Stop ongoing replay."""
        self.replay_system.stop_replay()

    def get_events_at_time(self, timestamp: datetime, window: timedelta = timedelta(minutes=5)) -> List[SecurityEvent]:
        """Time travel to specific point."""
        return self.replay_system.get_events_at_time(timestamp, window)

    def get_comprehensive_metrics(self) -> Dict[str, Any]:
        """Get comprehensive metrics from all components."""
        return {
            "stream_processor": self.stream_processor.get_metrics().dict(),
            "cep_engine": self.cep_engine.get_statistics(),
            "correlation_engine": self.correlation_engine.get_statistics(),
            "replay_system": self.replay_system.get_statistics(),
            "timestamp": datetime.now().isoformat()
        }

    def pause(self) -> None:
        """Pause all streaming analytics."""
        self.stream_processor.pause()
        logger.info("Streaming analytics paused")

    def resume(self) -> None:
        """Resume all streaming analytics."""
        self.stream_processor.resume()
        logger.info("Streaming analytics resumed")

    def stop(self) -> None:
        """Stop all streaming analytics."""
        self.stream_processor.stop()
        self.replay_system.stop_replay()
        logger.info("Streaming analytics stopped")


# ============================================================================
# Global Singleton
# ============================================================================

_streaming_analytics_instance: Optional[StreamingAnalytics] = None


def get_streaming_analytics(
    window_size: timedelta = timedelta(minutes=5),
    window_type: WindowType = WindowType.TUMBLING,
    correlation_window: timedelta = timedelta(minutes=10)
) -> StreamingAnalytics:
    """
    Get or create global streaming analytics instance.

    Args:
        window_size: Size of processing windows
        window_type: Type of windows (tumbling, sliding, etc.)
        correlation_window: Time window for correlation

    Returns:
        StreamingAnalytics instance
    """
    global _streaming_analytics_instance

    if _streaming_analytics_instance is None:
        _streaming_analytics_instance = StreamingAnalytics(
            window_size=window_size,
            window_type=window_type,
            correlation_window=correlation_window
        )
        logger.info("Created global streaming analytics instance")

    return _streaming_analytics_instance


# ============================================================================
# Utility Functions
# ============================================================================

def create_custom_cep_pattern(
    pattern_id: str,
    pattern_name: str,
    pattern_type: PatternType,
    conditions: List[Dict[str, Any]],
    time_window_minutes: int = 10,
    min_occurrences: int = 1,
    severity: Severity = Severity.MEDIUM,
    description: str = ""
) -> CEPPattern:
    """
    Helper function to create custom CEP patterns.

    Example:
        pattern = create_custom_cep_pattern(
            pattern_id="my_pattern",
            pattern_name="My Custom Pattern",
            pattern_type=PatternType.SEQUENCE,
            conditions=[
                {"category": "AUTHENTICATION", "contains": "failed"},
                {"category": "AUTHENTICATION", "contains": "success"}
            ],
            time_window_minutes=5,
            min_occurrences=2,
            severity=Severity.HIGH,
            description="Failed login followed by success"
        )
    """
    return CEPPattern(
        pattern_id=pattern_id,
        pattern_name=pattern_name,
        pattern_type=pattern_type,
        conditions=conditions,
        time_window=timedelta(minutes=time_window_minutes),
        min_occurrences=min_occurrences,
        description=description,
        severity=severity
    )


def convert_pattern_match_to_dict(match: PatternMatch) -> Dict[str, Any]:
    """Convert PatternMatch to dictionary for JSON serialization."""
    return {
        "pattern_id": match.pattern_id,
        "pattern_name": match.pattern_name,
        "matched_events": [
            {
                "event_id": e.event_id,
                "title": e.title,
                "severity": e.severity.value,
                "timestamp": e.timestamp.isoformat()
            }
            for e in match.matched_events
        ],
        "match_time": match.match_time.isoformat(),
        "confidence": match.confidence,
        "severity": match.severity.value,
        "description": match.description
    }


def convert_correlation_to_dict(correlation: StreamCorrelation) -> Dict[str, Any]:
    """Convert StreamCorrelation to dictionary for JSON serialization."""
    return {
        "correlation_id": correlation.correlation_id,
        "correlation_type": correlation.correlation_type,
        "correlated_events": [
            {
                "event_id": e.event_id,
                "title": e.title,
                "severity": e.severity.value,
                "timestamp": e.timestamp.isoformat()
            }
            for e in correlation.correlated_events
        ],
        "correlation_score": correlation.correlation_score,
        "detected_at": correlation.detected_at.isoformat(),
        "description": correlation.description
    }
