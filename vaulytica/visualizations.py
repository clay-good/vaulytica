import json
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from enum import Enum
import hashlib

from vaulytica.models import SecurityEvent, Severity, EventCategory
from vaulytica.threat_intel import ThreatLevel
from vaulytica.correlation import CorrelationType
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class VisualizationType(str, Enum):
    """Visualization types."""
    ATTACK_GRAPH = "ATTACK_GRAPH"
    THREAT_MAP = "THREAT_MAP"
    NETWORK_TOPOLOGY = "NETWORK_TOPOLOGY"
    TIMELINE = "TIMELINE"
    CORRELATION_MATRIX = "CORRELATION_MATRIX"
    ENTITY_RELATIONSHIP = "ENTITY_RELATIONSHIP"


class NodeType(str, Enum):
    """Node types for graphs."""
    ATTACKER = "ATTACKER"
    VICTIM = "VICTIM"
    ASSET = "ASSET"
    IP_ADDRESS = "IP_ADDRESS"
    USER = "USER"
    PROCESS = "PROCESS"
    FILE = "FILE"
    DOMAIN = "DOMAIN"
    EVENT = "EVENT"
    TECHNIQUE = "TECHNIQUE"


class EdgeType(str, Enum):
    """Edge types for graphs."""
    ATTACK = "ATTACK"
    COMMUNICATION = "COMMUNICATION"
    ACCESS = "ACCESS"
    EXECUTION = "EXECUTION"
    CORRELATION = "CORRELATION"
    TEMPORAL = "TEMPORAL"
    CAUSATION = "CAUSATION"


@dataclass
class GraphNode:
    """Node in a graph visualization."""
    id: str
    label: str
    type: NodeType
    properties: Dict[str, Any] = field(default_factory=dict)
    severity: Optional[Severity] = None
    threat_level: Optional[ThreatLevel] = None
    timestamp: Optional[datetime] = None
    
    # Visual properties
    size: int = 10
    color: Optional[str] = None
    icon: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {
            "id": self.id,
            "label": self.label,
            "type": self.type.value,
            "properties": self.properties,
            "size": self.size
        }
        
        if self.severity:
            data["severity"] = self.severity.value
        if self.threat_level:
            data["threat_level"] = self.threat_level.value
        if self.timestamp:
            data["timestamp"] = self.timestamp.isoformat()
        if self.color:
            data["color"] = self.color
        if self.icon:
            data["icon"] = self.icon
            
        return data


@dataclass
class GraphEdge:
    """Edge in a graph visualization."""
    source: str
    target: str
    type: EdgeType
    label: Optional[str] = None
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    timestamp: Optional[datetime] = None
    
    # Visual properties
    width: int = 2
    color: Optional[str] = None
    dashed: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = {
            "source": self.source,
            "target": self.target,
            "type": self.type.value,
            "weight": self.weight,
            "width": self.width,
            "dashed": self.dashed
        }
        
        if self.label:
            data["label"] = self.label
        if self.properties:
            data["properties"] = self.properties
        if self.timestamp:
            data["timestamp"] = self.timestamp.isoformat()
        if self.color:
            data["color"] = self.color
            
        return data


@dataclass
class Graph:
    """Graph structure for visualization."""
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_node(self, node: GraphNode):
        """Add node to graph."""
        # Check if node already exists
        if not any(n.id == node.id for n in self.nodes):
            self.nodes.append(node)
    
    def add_edge(self, edge: GraphEdge):
        """Add edge to graph."""
        # Check if edge already exists
        if not any(e.source == edge.source and e.target == edge.target and e.type == edge.type 
                   for e in self.edges):
            self.edges.append(edge)
    
    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get node by ID."""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "metadata": self.metadata
        }


@dataclass
class ThreatMapPoint:
    """Point on threat map."""
    latitude: float
    longitude: float
    country: str
    city: Optional[str] = None
    ip_address: Optional[str] = None
    event_count: int = 1
    severity: Severity = Severity.INFO
    threat_level: ThreatLevel = ThreatLevel.LOW
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "country": self.country,
            "city": self.city,
            "ip_address": self.ip_address,
            "event_count": self.event_count,
            "severity": self.severity.value,
            "threat_level": self.threat_level.value,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class TimelineEvent:
    """Event on timeline."""
    timestamp: datetime
    event_id: str
    title: str
    description: str
    severity: Severity
    category: EventCategory
    entities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "entities": self.entities
        }


@dataclass
class CorrelationCell:
    """Cell in correlation matrix."""
    row: str
    column: str
    value: float
    count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "row": self.row,
            "column": self.column,
            "value": self.value,
            "count": self.count
        }


class AttackGraphBuilder:
    """
    Build attack graph visualization.
    
    Creates interactive graph showing attack chains, kill chains,
    and MITRE ATT&CK techniques.
    """
    
    def __init__(self):
        """Initialize attack graph builder."""
        self.graph = Graph()
        logger.info("Attack graph builder initialized")
    
    def build_from_events(self, events: List[SecurityEvent]) -> Graph:
        """
        Build attack graph from security events.
        
        Args:
            events: List of security events
            
        Returns:
            Graph structure
        """
        self.graph = Graph()
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Create nodes for each event
        for event in sorted_events:
            self._add_event_node(event)
        
        # Create edges based on relationships
        self._create_temporal_edges(sorted_events)
        self._create_entity_edges(sorted_events)
        self._create_attack_chain_edges(sorted_events)
        
        # Add metadata
        self.graph.metadata = {
            "total_events": len(events),
            "time_range": {
                "start": sorted_events[0].timestamp.isoformat() if sorted_events else None,
                "end": sorted_events[-1].timestamp.isoformat() if sorted_events else None
            },
            "severity_distribution": self._get_severity_distribution(events)
        }
        
        logger.info(f"Attack graph built: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges")
        return self.graph
    
    def _add_event_node(self, event: SecurityEvent):
        """Add event as node."""
        node = GraphNode(
            id=f"event_{event.event_id}",
            label=event.title[:50],
            type=NodeType.EVENT,
            properties={
                "event_id": event.event_id,
                "category": event.category.value,
                "source_system": event.source_system
            },
            severity=event.severity,
            timestamp=event.timestamp,
            size=self._get_node_size(event.severity),
            color=self._get_severity_color(event.severity),
            icon="alert-circle"
        )
        self.graph.add_node(node)

        # Add entity nodes from metadata
        source_ip = event.metadata.get("source_ip")
        dest_ip = event.metadata.get("destination_ip") or event.metadata.get("target_ip")
        user = event.metadata.get("user")

        if source_ip:
            self._add_ip_node(source_ip, "source")
        if dest_ip:
            self._add_ip_node(dest_ip, "destination")
        if user:
            self._add_user_node(user)
    
    def _add_ip_node(self, ip: str, role: str):
        """Add IP address node."""
        node = GraphNode(
            id=f"ip_{ip}",
            label=ip,
            type=NodeType.IP_ADDRESS,
            properties={"role": role},
            size=8,
            color="#3b82f6",
            icon="globe"
        )
        self.graph.add_node(node)
    
    def _add_user_node(self, user: str):
        """Add user node."""
        node = GraphNode(
            id=f"user_{user}",
            label=user,
            type=NodeType.USER,
            size=8,
            color="#8b5cf6",
            icon="user"
        )
        self.graph.add_node(node)

    def _create_temporal_edges(self, events: List[SecurityEvent]):
        """Create edges based on temporal proximity."""
        for i in range(len(events) - 1):
            current = events[i]
            next_event = events[i + 1]

            # Connect events within 5 minutes
            time_diff = (next_event.timestamp - current.timestamp).total_seconds()
            if time_diff < 300:  # 5 minutes
                edge = GraphEdge(
                    source=f"event_{current.event_id}",
                    target=f"event_{next_event.event_id}",
                    type=EdgeType.TEMPORAL,
                    label=f"{int(time_diff)}s",
                    weight=1.0 / (time_diff + 1),
                    timestamp=next_event.timestamp,
                    color="#94a3b8",
                    dashed=True
                )
                self.graph.add_edge(edge)

    def _create_entity_edges(self, events: List[SecurityEvent]):
        """Create edges based on shared entities."""
        for event in events:
            event_node_id = f"event_{event.event_id}"

            # Get entities from metadata
            source_ip = event.metadata.get("source_ip")
            dest_ip = event.metadata.get("destination_ip") or event.metadata.get("target_ip")
            user = event.metadata.get("user")

            # Connect to IP nodes
            if source_ip:
                edge = GraphEdge(
                    source=f"ip_{source_ip}",
                    target=event_node_id,
                    type=EdgeType.ATTACK,
                    label="from",
                    color="#ef4444"
                )
                self.graph.add_edge(edge)

            if dest_ip:
                edge = GraphEdge(
                    source=event_node_id,
                    target=f"ip_{dest_ip}",
                    type=EdgeType.ATTACK,
                    label="to",
                    color="#ef4444"
                )
                self.graph.add_edge(edge)

            # Connect to user nodes
            if user:
                edge = GraphEdge(
                    source=f"user_{user}",
                    target=event_node_id,
                    type=EdgeType.ACCESS,
                    label="accessed",
                    color="#8b5cf6"
                )
                self.graph.add_edge(edge)

    def _create_attack_chain_edges(self, events: List[SecurityEvent]):
        """Create edges representing attack chains."""
        # Group events by category to identify attack progression
        category_sequence = [e.category for e in events]

        # Common attack chain patterns
        attack_chains = [
            [EventCategory.RECONNAISSANCE, EventCategory.UNAUTHORIZED_ACCESS],
            [EventCategory.UNAUTHORIZED_ACCESS, EventCategory.PRIVILEGE_ESCALATION],
            [EventCategory.PRIVILEGE_ESCALATION, EventCategory.LATERAL_MOVEMENT],
            [EventCategory.LATERAL_MOVEMENT, EventCategory.DATA_EXFILTRATION],
            [EventCategory.MALWARE, EventCategory.PERSISTENCE],
            [EventCategory.PERSISTENCE, EventCategory.DEFENSE_EVASION]
        ]

        # Find matching patterns
        for i in range(len(events) - 1):
            current = events[i]
            for j in range(i + 1, min(i + 5, len(events))):  # Look ahead up to 5 events
                next_event = events[j]

                # Check if this matches an attack chain pattern
                for chain in attack_chains:
                    if current.category == chain[0] and next_event.category == chain[1]:
                        edge = GraphEdge(
                            source=f"event_{current.event_id}",
                            target=f"event_{next_event.event_id}",
                            type=EdgeType.CAUSATION,
                            label="leads to",
                            weight=2.0,
                            color="#f59e0b",
                            width=3
                        )
                        self.graph.add_edge(edge)

    def _get_node_size(self, severity: Severity) -> int:
        """Get node size based on severity."""
        size_map = {
            Severity.CRITICAL: 20,
            Severity.HIGH: 16,
            Severity.MEDIUM: 12,
            Severity.LOW: 10,
            Severity.INFO: 8
        }
        return size_map.get(severity, 10)

    def _get_severity_color(self, severity: Severity) -> str:
        """Get color based on severity."""
        color_map = {
            Severity.CRITICAL: "#dc2626",
            Severity.HIGH: "#f59e0b",
            Severity.MEDIUM: "#3b82f6",
            Severity.LOW: "#64748b",
            Severity.INFO: "#94a3b8"
        }
        return color_map.get(severity, "#94a3b8")

    def _get_severity_distribution(self, events: List[SecurityEvent]) -> Dict[str, int]:
        """Get severity distribution."""
        distribution = Counter(e.severity.value for e in events)
        return dict(distribution)


class ThreatMapBuilder:
    """
    Build threat map visualization.

    Creates geographic map showing attack origins and targets.
    """

    def __init__(self):
        """Initialize threat map builder."""
        self.points: List[ThreatMapPoint] = []
        self.connections: List[Dict[str, Any]] = []
        logger.info("Threat map builder initialized")

    def build_from_events(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """
        Build threat map from security events.

        Args:
            events: List of security events

        Returns:
            Threat map data structure
        """
        self.points = []
        self.connections = []

        # Aggregate events by IP
        ip_events = defaultdict(list)
        for event in events:
            source_ip = event.metadata.get("source_ip")
            if source_ip:
                ip_events[source_ip].append(event)

        # Create points for each IP
        for ip, ip_event_list in ip_events.items():
            point = self._create_threat_point(ip, ip_event_list)
            if point:
                self.points.append(point)

        # Create connections between source and destination IPs
        for event in events:
            source_ip = event.metadata.get("source_ip")
            dest_ip = event.metadata.get("destination_ip") or event.metadata.get("target_ip")
            if source_ip and dest_ip:
                connection = self._create_connection(event)
                if connection:
                    self.connections.append(connection)

        logger.info(f"Threat map built: {len(self.points)} points, {len(self.connections)} connections")

        return {
            "points": [p.to_dict() for p in self.points],
            "connections": self.connections,
            "metadata": {
                "total_events": len(events),
                "unique_ips": len(ip_events),
                "timestamp": datetime.utcnow().isoformat()
            }
        }

    def _create_threat_point(self, ip: str, events: List[SecurityEvent]) -> Optional[ThreatMapPoint]:
        """Create threat point from IP and events."""
        # Get geolocation for IP (simplified - in production use GeoIP database)
        location = self._get_ip_location(ip)
        if not location:
            return None

        # Aggregate severity
        max_severity = max(e.severity for e in events)

        # Determine threat level
        threat_level = ThreatLevel.LOW
        if max_severity == Severity.CRITICAL:
            threat_level = ThreatLevel.CRITICAL
        elif max_severity == Severity.HIGH:
            threat_level = ThreatLevel.HIGH
        elif max_severity == Severity.MEDIUM:
            threat_level = ThreatLevel.MEDIUM

        return ThreatMapPoint(
            latitude=location["latitude"],
            longitude=location["longitude"],
            country=location["country"],
            city=location.get("city"),
            ip_address=ip,
            event_count=len(events),
            severity=max_severity,
            threat_level=threat_level,
            timestamp=events[-1].timestamp
        )

    def _create_connection(self, event: SecurityEvent) -> Optional[Dict[str, Any]]:
        """Create connection between source and destination."""
        source_ip = event.metadata.get("source_ip")
        dest_ip = event.metadata.get("destination_ip") or event.metadata.get("target_ip")

        source_loc = self._get_ip_location(source_ip)
        dest_loc = self._get_ip_location(dest_ip)

        if not source_loc or not dest_loc:
            return None

        return {
            "source": {
                "latitude": source_loc["latitude"],
                "longitude": source_loc["longitude"],
                "ip": source_ip
            },
            "destination": {
                "latitude": dest_loc["latitude"],
                "longitude": dest_loc["longitude"],
                "ip": dest_ip
            },
            "severity": event.severity.value,
            "timestamp": event.timestamp.isoformat()
        }

    def _get_ip_location(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Get geolocation for IP address.

        In production, use MaxMind GeoIP2 or similar service.
        For demo, return sample locations based on IP hash.
        """
        if not ip:
            return None

        # Sample locations for demo
        locations = [
            {"country": "United States", "city": "New York", "latitude": 40.7128, "longitude": -74.0060},
            {"country": "China", "city": "Beijing", "latitude": 39.9042, "longitude": 116.4074},
            {"country": "Russia", "city": "Moscow", "latitude": 55.7558, "longitude": 37.6173},
            {"country": "Germany", "city": "Berlin", "latitude": 52.5200, "longitude": 13.4050},
            {"country": "United Kingdom", "city": "London", "latitude": 51.5074, "longitude": -0.1278},
            {"country": "Japan", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503},
            {"country": "Brazil", "city": "São Paulo", "latitude": -23.5505, "longitude": -46.6333},
            {"country": "India", "city": "Mumbai", "latitude": 19.0760, "longitude": 72.8777},
            {"country": "Australia", "city": "Sydney", "latitude": -33.8688, "longitude": 151.2093},
            {"country": "Canada", "city": "Toronto", "latitude": 43.6532, "longitude": -79.3832}
        ]

        # Use IP hash to consistently map to location
        ip_hash = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        location_idx = ip_hash % len(locations)

        return locations[location_idx]


class NetworkTopologyBuilder:
    """
    Build network topology visualization.

    Creates graph showing network assets and their relationships.
    """

    def __init__(self):
        """Initialize network topology builder."""
        self.graph = Graph()
        logger.info("Network topology builder initialized")

    def build_from_events(self, events: List[SecurityEvent]) -> Graph:
        """
        Build network topology from security events.

        Args:
            events: List of security events

        Returns:
            Graph structure
        """
        self.graph = Graph()

        # Extract all unique assets
        assets = self._extract_assets(events)

        # Create nodes for assets
        for asset_id, asset_info in assets.items():
            self._add_asset_node(asset_id, asset_info)

        # Create edges based on communication
        self._create_communication_edges(events)

        # Add metadata
        self.graph.metadata = {
            "total_assets": len(assets),
            "total_events": len(events),
            "compromised_assets": sum(1 for a in assets.values() if a.get("compromised", False))
        }

        logger.info(f"Network topology built: {len(self.graph.nodes)} nodes, {len(self.graph.edges)} edges")
        return self.graph

    def _extract_assets(self, events: List[SecurityEvent]) -> Dict[str, Dict[str, Any]]:
        """Extract unique assets from events."""
        assets = {}

        for event in events:
            source_ip = event.metadata.get("source_ip")
            dest_ip = event.metadata.get("destination_ip") or event.metadata.get("target_ip")

            # Add source IP as asset
            if source_ip:
                asset_id = f"ip_{source_ip}"
                if asset_id not in assets:
                    assets[asset_id] = {
                        "type": "ip",
                        "value": source_ip,
                        "events": [],
                        "compromised": False,
                        "max_severity": Severity.INFO
                    }
                assets[asset_id]["events"].append(event.event_id)
                if event.severity.value > assets[asset_id]["max_severity"].value:
                    assets[asset_id]["max_severity"] = event.severity
                if event.severity in [Severity.CRITICAL, Severity.HIGH]:
                    assets[asset_id]["compromised"] = True

            # Add destination IP as asset
            if dest_ip:
                asset_id = f"ip_{dest_ip}"
                if asset_id not in assets:
                    assets[asset_id] = {
                        "type": "ip",
                        "value": dest_ip,
                        "events": [],
                        "compromised": False,
                        "max_severity": Severity.INFO
                    }
                assets[asset_id]["events"].append(event.event_id)
                if event.severity.value > assets[asset_id]["max_severity"].value:
                    assets[asset_id]["max_severity"] = event.severity

            # Add affected assets
            for asset in event.affected_assets:
                asset_id = f"asset_{asset.asset_id}"
                if asset_id not in assets:
                    assets[asset_id] = {
                        "type": "asset",
                        "value": asset.asset_id,
                        "events": [],
                        "compromised": False,
                        "max_severity": Severity.INFO
                    }
                assets[asset_id]["events"].append(event.event_id)
                if event.severity.value > assets[asset_id]["max_severity"].value:
                    assets[asset_id]["max_severity"] = event.severity
                if event.severity in [Severity.CRITICAL, Severity.HIGH]:
                    assets[asset_id]["compromised"] = True

        return assets

    def _add_asset_node(self, asset_id: str, asset_info: Dict[str, Any]):
        """Add asset as node."""
        node_type = NodeType.IP_ADDRESS if asset_info["type"] == "ip" else NodeType.ASSET

        # Determine color based on compromise status
        if asset_info["compromised"]:
            color = "#dc2626"  # Red for compromised
            icon = "alert-triangle"
        else:
            color = "#10b981"  # Green for safe
            icon = "shield"

        node = GraphNode(
            id=asset_id,
            label=asset_info["value"],
            type=node_type,
            properties={
                "event_count": len(asset_info["events"]),
                "compromised": asset_info["compromised"]
            },
            severity=asset_info["max_severity"],
            size=10 + len(asset_info["events"]) * 2,
            color=color,
            icon=icon
        )
        self.graph.add_node(node)

    def _create_communication_edges(self, events: List[SecurityEvent]):
        """Create edges based on communication between assets."""
        # Track communication pairs
        communications = defaultdict(int)

        for event in events:
            source_ip = event.metadata.get("source_ip")
            dest_ip = event.metadata.get("destination_ip") or event.metadata.get("target_ip")

            if source_ip and dest_ip:
                source_id = f"ip_{source_ip}"
                dest_id = f"ip_{dest_ip}"
                pair = (source_id, dest_id)
                communications[pair] += 1

        # Create edges
        for (source_id, dest_id), count in communications.items():
            edge = GraphEdge(
                source=source_id,
                target=dest_id,
                type=EdgeType.COMMUNICATION,
                label=f"{count} events",
                weight=count,
                width=min(1 + count, 5),
                color="#3b82f6"
            )
            self.graph.add_edge(edge)


class TimelineBuilder:
    """
    Build timeline visualization.

    Creates interactive timeline showing attack progression.
    """

    def __init__(self):
        """Initialize timeline builder."""
        self.events: List[TimelineEvent] = []
        logger.info("Timeline builder initialized")

    def build_from_events(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """
        Build timeline from security events.

        Args:
            events: List of security events

        Returns:
            Timeline data structure
        """
        self.events = []

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # Create timeline events
        for event in sorted_events:
            # Extract entities from metadata
            source_ip = event.metadata.get("source_ip")
            dest_ip = event.metadata.get("destination_ip") or event.metadata.get("target_ip")
            user = event.metadata.get("user")

            entities = []
            if source_ip:
                entities.append(source_ip)
            if dest_ip:
                entities.append(dest_ip)
            if user:
                entities.append(user)

            timeline_event = TimelineEvent(
                timestamp=event.timestamp,
                event_id=event.event_id,
                title=event.title,
                description=event.description[:200],
                severity=event.severity,
                category=event.category,
                entities=entities
            )
            self.events.append(timeline_event)

        # Group events by time periods
        grouped = self._group_by_time_period(sorted_events)

        logger.info(f"Timeline built: {len(self.events)} events")

        return {
            "events": [e.to_dict() for e in self.events],
            "grouped": grouped,
            "metadata": {
                "total_events": len(events),
                "time_range": {
                    "start": sorted_events[0].timestamp.isoformat() if sorted_events else None,
                    "end": sorted_events[-1].timestamp.isoformat() if sorted_events else None
                }
            }
        }

    def _group_by_time_period(self, events: List[SecurityEvent]) -> Dict[str, List[str]]:
        """Group events by time period (hour, day, etc.)."""
        grouped = defaultdict(list)

        for event in events:
            # Group by hour
            hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
            grouped[hour_key].append(event.event_id)

        return dict(grouped)


class CorrelationMatrixBuilder:
    """
    Build correlation matrix visualization.

    Creates heatmap showing correlations between different dimensions.
    """

    def __init__(self):
        """Initialize correlation matrix builder."""
        self.matrix: List[CorrelationCell] = []
        logger.info("Correlation matrix builder initialized")

    def build_from_events(self, events: List[SecurityEvent],
                         dimension1: str = "source_ip",
                         dimension2: str = "category") -> Dict[str, Any]:
        """
        Build correlation matrix from security events.

        Args:
            events: List of security events
            dimension1: First dimension (e.g., "source_ip", "user", "category")
            dimension2: Second dimension

        Returns:
            Correlation matrix data structure
        """
        self.matrix = []

        # Extract values for each dimension
        dim1_values = self._extract_dimension_values(events, dimension1)
        dim2_values = self._extract_dimension_values(events, dimension2)

        # Count co-occurrences
        co_occurrences = defaultdict(int)
        for event in events:
            val1 = self._get_event_dimension_value(event, dimension1)
            val2 = self._get_event_dimension_value(event, dimension2)
            if val1 and val2:
                co_occurrences[(val1, val2)] += 1

        # Create matrix cells
        for val1 in dim1_values:
            for val2 in dim2_values:
                count = co_occurrences.get((val1, val2), 0)
                # Normalize value (0-1)
                max_count = max(co_occurrences.values()) if co_occurrences else 1
                normalized_value = count / max_count if max_count > 0 else 0

                cell = CorrelationCell(
                    row=val1,
                    column=val2,
                    value=normalized_value,
                    count=count
                )
                self.matrix.append(cell)

        logger.info(f"Correlation matrix built: {len(dim1_values)}x{len(dim2_values)}")

        return {
            "matrix": [c.to_dict() for c in self.matrix],
            "dimensions": {
                "rows": list(dim1_values),
                "columns": list(dim2_values)
            },
            "metadata": {
                "dimension1": dimension1,
                "dimension2": dimension2,
                "total_events": len(events)
            }
        }

    def _extract_dimension_values(self, events: List[SecurityEvent], dimension: str) -> Set[str]:
        """Extract unique values for a dimension."""
        values = set()
        for event in events:
            value = self._get_event_dimension_value(event, dimension)
            if value:
                values.add(value)
        return values

    def _get_event_dimension_value(self, event: SecurityEvent, dimension: str) -> Optional[str]:
        """Get dimension value from event."""
        if dimension == "source_ip":
            return event.metadata.get("source_ip")
        elif dimension == "destination_ip":
            return event.metadata.get("destination_ip") or event.metadata.get("target_ip")
        elif dimension == "user":
            return event.metadata.get("user")
        elif dimension == "category":
            return event.category.value
        elif dimension == "severity":
            return event.severity.value
        elif dimension == "source_system":
            return event.source_system
        return None


class VisualizationEngine:
    """
    Main visualization engine.

    Provides unified interface for all visualization types.
    """

    def __init__(self):
        """Initialize visualization engine."""
        self.attack_graph_builder = AttackGraphBuilder()
        self.threat_map_builder = ThreatMapBuilder()
        self.network_topology_builder = NetworkTopologyBuilder()
        self.timeline_builder = TimelineBuilder()
        self.correlation_matrix_builder = CorrelationMatrixBuilder()

        self.stats = {
            "visualizations_generated": 0,
            "attack_graphs": 0,
            "threat_maps": 0,
            "network_topologies": 0,
            "timelines": 0,
            "correlation_matrices": 0
        }

        logger.info("Visualization engine initialized")

    def generate_attack_graph(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Generate attack graph visualization."""
        graph = self.attack_graph_builder.build_from_events(events)
        self.stats["attack_graphs"] += 1
        self.stats["visualizations_generated"] += 1
        return graph.to_dict()

    def generate_threat_map(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Generate threat map visualization."""
        threat_map = self.threat_map_builder.build_from_events(events)
        self.stats["threat_maps"] += 1
        self.stats["visualizations_generated"] += 1
        return threat_map

    def generate_network_topology(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Generate network topology visualization."""
        graph = self.network_topology_builder.build_from_events(events)
        self.stats["network_topologies"] += 1
        self.stats["visualizations_generated"] += 1
        return graph.to_dict()

    def generate_timeline(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Generate timeline visualization."""
        timeline = self.timeline_builder.build_from_events(events)
        self.stats["timelines"] += 1
        self.stats["visualizations_generated"] += 1
        return timeline

    def generate_correlation_matrix(self, events: List[SecurityEvent],
                                   dimension1: str = "source_ip",
                                   dimension2: str = "category") -> Dict[str, Any]:
        """Generate correlation matrix visualization."""
        matrix = self.correlation_matrix_builder.build_from_events(events, dimension1, dimension2)
        self.stats["correlation_matrices"] += 1
        self.stats["visualizations_generated"] += 1
        return matrix

    def generate_all(self, events: List[SecurityEvent]) -> Dict[str, Any]:
        """Generate all visualizations."""
        return {
            "attack_graph": self.generate_attack_graph(events),
            "threat_map": self.generate_threat_map(events),
            "network_topology": self.generate_network_topology(events),
            "timeline": self.generate_timeline(events),
            "correlation_matrix": self.generate_correlation_matrix(events)
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return self.stats.copy()


# Global instance
_visualization_engine: Optional[VisualizationEngine] = None


def get_visualization_engine() -> VisualizationEngine:
    """Get or create global visualization engine instance."""
    global _visualization_engine

    if _visualization_engine is None:
        _visualization_engine = VisualizationEngine()

    return _visualization_engine


def reset_visualization_engine():
    """Reset global visualization engine instance."""
    global _visualization_engine
    _visualization_engine = None


if __name__ == "__main__":
    # Quick test
    print("Visualization Engine - Quick Test")
    print("="*80)

    # Create engine
    engine = VisualizationEngine()

    print(f"✓ Visualization Engine initialized")
    print(f"  - Attack Graph Builder: Ready")
    print(f"  - Threat Map Builder: Ready")
    print(f"  - Network Topology Builder: Ready")
    print(f"  - Timeline Builder: Ready")
    print(f"  - Correlation Matrix Builder: Ready")

    print("\n✓ Visualization Engine ready!")
    print(f"  Stats: {engine.get_stats()}")
    print("="*80)

