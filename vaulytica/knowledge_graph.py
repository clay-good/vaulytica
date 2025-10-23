"""
Knowledge Graph System for Vaulytica.

Provides entity relationship mapping, attack path visualization, and graph-based threat hunting.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Tuple
from uuid import uuid4
import json

logger = logging.getLogger(__name__)


# ==================== Enums ====================

class EntityType(str, Enum):
    """Types of entities in the knowledge graph."""
    USER = "user"
    HOST = "host"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    FILE = "file"
    PROCESS = "process"
    REGISTRY_KEY = "registry_key"
    NETWORK_CONNECTION = "network_connection"
    VULNERABILITY = "vulnerability"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware"
    ATTACK_TECHNIQUE = "attack_technique"
    ASSET = "asset"
    CREDENTIAL = "credential"
    EMAIL = "email"
    URL = "url"


class RelationshipType(str, Enum):
    """Types of relationships between entities."""
    CONNECTED_TO = "connected_to"
    COMMUNICATED_WITH = "communicated_with"
    EXECUTED = "executed"
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    ACCESSED = "accessed"
    LOGGED_IN = "logged_in"
    EXPLOITED = "exploited"
    INFECTED = "infected"
    EXFILTRATED_FROM = "exfiltrated_from"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


class RiskLevel(str, Enum):
    """Risk levels for entities and paths."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ==================== Data Models ====================

@dataclass
class Entity:
    """Represents an entity in the knowledge graph."""
    entity_id: str
    entity_type: EntityType
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.INFO
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Relationship:
    """Represents a relationship between entities."""
    relationship_id: str
    relationship_type: RelationshipType
    source_entity_id: str
    target_entity_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    evidence: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    """Represents an attack path through the graph."""
    path_id: str
    entities: List[str]  # Entity IDs
    relationships: List[str]  # Relationship IDs
    start_entity_id: str
    end_entity_id: str
    risk_score: float
    risk_level: RiskLevel
    attack_techniques: List[str] = field(default_factory=list)
    description: str = ""
    mitigation_recommendations: List[str] = field(default_factory=list)


@dataclass
class ThreatPattern:
    """Represents a threat pattern detected in the graph."""
    pattern_id: str
    pattern_name: str
    pattern_type: str
    entities: List[str]
    relationships: List[str]
    confidence: float
    severity: RiskLevel
    description: str
    mitre_techniques: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)


@dataclass
class GraphQuery:
    """Represents a graph query for threat hunting."""
    query_id: str
    query_name: str
    description: str
    cypher_query: Optional[str] = None
    entity_types: List[EntityType] = field(default_factory=list)
    relationship_types: List[RelationshipType] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)


# ==================== Knowledge Graph Engine ====================

class KnowledgeGraphEngine:
    """
    Knowledge graph engine for security entity relationship mapping.

    Provides:
    - Entity and relationship management
    - Attack path discovery
    - Graph-based threat hunting
    - Pattern detection
    """

    def __init__(self):
        """Initialize the knowledge graph engine."""
        self.entities: Dict[str, Entity] = {}
        self.relationships: Dict[str, Relationship] = {}
        self.entity_relationships: Dict[str, Set[str]] = {}  # entity_id -> relationship_ids
        logger.info("Knowledge graph engine initialized")

    # ==================== Entity Management ====================

    def add_entity(
        self,
        entity_type: EntityType,
        name: str,
        properties: Optional[Dict[str, Any]] = None,
        risk_score: float = 0.0,
        tags: Optional[List[str]] = None
    ) -> Entity:
        """Add an entity to the knowledge graph."""
        entity_id = str(uuid4())

        # Determine risk level from score
        if risk_score >= 9.0:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 7.0:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 4.0:
            risk_level = RiskLevel.MEDIUM
        elif risk_score >= 1.0:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.INFO

        entity = Entity(
            entity_id=entity_id,
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            risk_score=risk_score,
            risk_level=risk_level,
            tags=tags or []
        )

        self.entities[entity_id] = entity
        self.entity_relationships[entity_id] = set()

        logger.info(f"Added entity: {entity_type} - {name} (risk: {risk_score})")
        return entity

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """Get an entity by ID."""
        return self.entities.get(entity_id)

    def find_entities(
        self,
        entity_type: Optional[EntityType] = None,
        name_pattern: Optional[str] = None,
        min_risk_score: Optional[float] = None,
        tags: Optional[List[str]] = None
    ) -> List[Entity]:
        """Find entities matching criteria."""
        results = []

        for entity in self.entities.values():
            # Filter by type
            if entity_type and entity.entity_type != entity_type:
                continue

            # Filter by name pattern
            if name_pattern and name_pattern.lower() not in entity.name.lower():
                continue

            # Filter by risk score
            if min_risk_score and entity.risk_score < min_risk_score:
                continue

            # Filter by tags
            if tags and not any(tag in entity.tags for tag in tags):
                continue

            results.append(entity)

        return results

    # ==================== Relationship Management ====================

    def add_relationship(
        self,
        relationship_type: RelationshipType,
        source_entity_id: str,
        target_entity_id: str,
        properties: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
        evidence: Optional[List[str]] = None
    ) -> Optional[Relationship]:
        """Add a relationship between entities."""
        # Validate entities exist
        if source_entity_id not in self.entities or target_entity_id not in self.entities:
            logger.warning("Cannot add relationship: entities not found")
            return None

        relationship_id = str(uuid4())

        relationship = Relationship(
            relationship_id=relationship_id,
            relationship_type=relationship_type,
            source_entity_id=source_entity_id,
            target_entity_id=target_entity_id,
            properties=properties or {},
            confidence=confidence,
            evidence=evidence or []
        )

        self.relationships[relationship_id] = relationship
        self.entity_relationships[source_entity_id].add(relationship_id)
        self.entity_relationships[target_entity_id].add(relationship_id)

        logger.info(f"Added relationship: {relationship_type} ({source_entity_id} -> {target_entity_id})")
        return relationship

    def get_entity_relationships(self, entity_id: str) -> List[Relationship]:
        """Get all relationships for an entity."""
        relationship_ids = self.entity_relationships.get(entity_id, set())
        return [self.relationships[rid] for rid in relationship_ids if rid in self.relationships]

    # ==================== Attack Path Discovery ====================

    async def find_attack_paths(
        self,
        start_entity_id: str,
        end_entity_id: Optional[str] = None,
        max_depth: int = 10,
        min_risk_score: float = 5.0
    ) -> List[AttackPath]:
        """Find attack paths from start entity to end entity (or all high-risk paths)."""
        logger.info(f"Finding attack paths from {start_entity_id}")

        paths = []
        visited = set()

        async def dfs(current_id: str, path_entities: List[str], path_relationships: List[str], depth: int):
            """Depth-first search for attack paths."""
            if depth > max_depth:
                return

            if current_id in visited:
                return

            visited.add(current_id)
            current_entity = self.entities.get(current_id)

            if not current_entity:
                return

            # Check if we reached the target
            if end_entity_id and current_id == end_entity_id:
                path_risk = self._calculate_path_risk(path_entities)
                if path_risk >= min_risk_score:
                    paths.append(self._create_attack_path(path_entities, path_relationships, path_risk))
                return

            # Explore relationships
            for relationship in self.get_entity_relationships(current_id):
                next_id = relationship.target_entity_id if relationship.source_entity_id == current_id else relationship.source_entity_id

                if next_id not in path_entities:
                    await dfs(
                        next_id,
                        path_entities + [next_id],
                        path_relationships + [relationship.relationship_id],
                        depth + 1
                    )

            visited.remove(current_id)

        await dfs(start_entity_id, [start_entity_id], [], 0)

        # Sort by risk score
        paths.sort(key=lambda p: p.risk_score, reverse=True)

        logger.info(f"Found {len(paths)} attack paths")
        return paths

    def _calculate_path_risk(self, entity_ids: List[str]) -> float:
        """Calculate risk score for a path."""
        if not entity_ids:
            return 0.0

        total_risk = sum(self.entities[eid].risk_score for eid in entity_ids if eid in self.entities)
        return total_risk / len(entity_ids)

    def _create_attack_path(self, entity_ids: List[str], relationship_ids: List[str], risk_score: float) -> AttackPath:
        """Create an attack path object."""
        # Determine risk level
        if risk_score >= 9.0:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 7.0:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 4.0:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Generate description
        entity_names = [self.entities[eid].name for eid in entity_ids if eid in self.entities]
        description = " -> ".join(entity_names)

        return AttackPath(
            path_id=str(uuid4()),
            entities=entity_ids,
            relationships=relationship_ids,
            start_entity_id=entity_ids[0] if entity_ids else "",
            end_entity_id=entity_ids[-1] if entity_ids else "",
            risk_score=risk_score,
            risk_level=risk_level,
            description=description
        )

    # ==================== Pattern Detection ====================

    async def detect_threat_patterns(self) -> List[ThreatPattern]:
        """Detect known threat patterns in the graph."""
        logger.info("Detecting threat patterns")
        patterns = []

        # Pattern 1: Lateral movement
        lateral_patterns = await self._detect_lateral_movement()
        patterns.extend(lateral_patterns)

        # Pattern 2: Privilege escalation
        privesc_patterns = await self._detect_privilege_escalation()
        patterns.extend(privesc_patterns)

        # Pattern 3: Data exfiltration
        exfil_patterns = await self._detect_data_exfiltration()
        patterns.extend(exfil_patterns)

        # Pattern 4: Persistence mechanisms
        persistence_patterns = await self._detect_persistence()
        patterns.extend(persistence_patterns)

        # Pattern 5: Command and control
        c2_patterns = await self._detect_command_and_control()
        patterns.extend(c2_patterns)

        logger.info(f"Detected {len(patterns)} threat patterns")
        return patterns

    async def _detect_lateral_movement(self) -> List[ThreatPattern]:
        """Detect lateral movement patterns."""
        patterns = []

        # Find chains of lateral movement relationships
        for entity_id, entity in self.entities.items():
            if entity.entity_type in [EntityType.HOST, EntityType.USER]:
                lateral_rels = [
                    r for r in self.get_entity_relationships(entity_id)
                    if r.relationship_type == RelationshipType.LATERAL_MOVEMENT
                ]

                if len(lateral_rels) >= 2:
                    pattern = ThreatPattern(
                        pattern_id=str(uuid4()),
                        pattern_name="Lateral Movement Chain",
                        pattern_type="lateral_movement",
                        entities=[entity_id] + [r.target_entity_id for r in lateral_rels],
                        relationships=[r.relationship_id for r in lateral_rels],
                        confidence=0.8,
                        severity=RiskLevel.HIGH,
                        description=f"Detected lateral movement chain from {entity.name}",
                        mitre_techniques=["T1021", "T1570"]
                    )
                    patterns.append(pattern)

        return patterns

    async def _detect_privilege_escalation(self) -> List[ThreatPattern]:
        """Detect privilege escalation patterns."""
        patterns = []

        for entity_id, entity in self.entities.items():
            if entity.entity_type == EntityType.USER:
                privesc_rels = [
                    r for r in self.get_entity_relationships(entity_id)
                    if r.relationship_type == RelationshipType.PRIVILEGE_ESCALATION
                ]

                if privesc_rels:
                    pattern = ThreatPattern(
                        pattern_id=str(uuid4()),
                        pattern_name="Privilege Escalation",
                        pattern_type="privilege_escalation",
                        entities=[entity_id],
                        relationships=[r.relationship_id for r in privesc_rels],
                        confidence=0.9,
                        severity=RiskLevel.CRITICAL,
                        description=f"Detected privilege escalation for {entity.name}",
                        mitre_techniques=["T1068", "T1078"]
                    )
                    patterns.append(pattern)

        return patterns

    async def _detect_data_exfiltration(self) -> List[ThreatPattern]:
        """Detect data exfiltration patterns."""
        patterns = []

        for entity_id, entity in self.entities.items():
            exfil_rels = [
                r for r in self.get_entity_relationships(entity_id)
                if r.relationship_type == RelationshipType.EXFILTRATED_FROM
            ]

            if exfil_rels:
                pattern = ThreatPattern(
                    pattern_id=str(uuid4()),
                    pattern_name="Data Exfiltration",
                    pattern_type="exfiltration",
                    entities=[entity_id] + [r.target_entity_id for r in exfil_rels],
                    relationships=[r.relationship_id for r in exfil_rels],
                    confidence=0.85,
                    severity=RiskLevel.CRITICAL,
                    description=f"Detected data exfiltration from {entity.name}",
                    mitre_techniques=["T1041", "T1048", "T1567"]
                )
                patterns.append(pattern)

        return patterns

    async def _detect_persistence(self) -> List[ThreatPattern]:
        """Detect persistence mechanism patterns."""
        patterns = []

        for entity_id, entity in self.entities.items():
            persistence_rels = [
                r for r in self.get_entity_relationships(entity_id)
                if r.relationship_type == RelationshipType.PERSISTENCE
            ]

            if persistence_rels:
                pattern = ThreatPattern(
                    pattern_id=str(uuid4()),
                    pattern_name="Persistence Mechanism",
                    pattern_type="persistence",
                    entities=[entity_id],
                    relationships=[r.relationship_id for r in persistence_rels],
                    confidence=0.75,
                    severity=RiskLevel.HIGH,
                    description=f"Detected persistence mechanism on {entity.name}",
                    mitre_techniques=["T1053", "T1543", "T1547"]
                )
                patterns.append(pattern)

        return patterns

    async def _detect_command_and_control(self) -> List[ThreatPattern]:
        """Detect command and control patterns."""
        patterns = []

        for entity_id, entity in self.entities.items():
            c2_rels = [
                r for r in self.get_entity_relationships(entity_id)
                if r.relationship_type == RelationshipType.COMMAND_AND_CONTROL
            ]

            if c2_rels:
                pattern = ThreatPattern(
                    pattern_id=str(uuid4()),
                    pattern_name="Command and Control",
                    pattern_type="command_and_control",
                    entities=[entity_id] + [r.target_entity_id for r in c2_rels],
                    relationships=[r.relationship_id for r in c2_rels],
                    confidence=0.9,
                    severity=RiskLevel.CRITICAL,
                    description=f"Detected C2 communication from {entity.name}",
                    mitre_techniques=["T1071", "T1095", "T1105"]
                )
                patterns.append(pattern)

        return patterns

    # ==================== Graph-Based Threat Hunting ====================

    async def hunt_threats(self, query: GraphQuery) -> List[Dict[str, Any]]:
        """Execute a threat hunting query on the graph."""
        logger.info(f"Executing threat hunt: {query.query_name}")

        results = []

        # Filter entities by type
        candidate_entities = []
        if query.entity_types:
            for entity_type in query.entity_types:
                candidate_entities.extend(self.find_entities(entity_type=entity_type))
        else:
            candidate_entities = list(self.entities.values())

        # Apply filters
        for entity in candidate_entities:
            if self._matches_filters(entity, query.filters):
                # Get related entities and relationships
                relationships = self.get_entity_relationships(entity.entity_id)

                # Filter relationships by type
                if query.relationship_types:
                    relationships = [
                        r for r in relationships
                        if r.relationship_type in query.relationship_types
                    ]

                if relationships:
                    results.append({
                        "entity": entity,
                        "relationships": relationships,
                        "related_entities": [
                            self.entities.get(r.target_entity_id) or self.entities.get(r.source_entity_id)
                            for r in relationships
                        ]
                    })

        logger.info(f"Threat hunt found {len(results)} results")
        return results

    def _matches_filters(self, entity: Entity, filters: Dict[str, Any]) -> bool:
        """Check if entity matches filter criteria."""
        for key, value in filters.items():
            if key == "min_risk_score":
                if entity.risk_score < value:
                    return False
            elif key == "tags":
                if not any(tag in entity.tags for tag in value):
                    return False
            elif key == "name_contains":
                if value.lower() not in entity.name.lower():
                    return False

        return True

    # ==================== Graph Export ====================

    def export_graph(self, format: str = "json") -> str:
        """Export the graph in various formats."""
        if format == "json":
            return self._export_json()
        elif format == "cypher":
            return self._export_cypher()
        elif format == "graphml":
            return self._export_graphml()
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _export_json(self) -> str:
        """Export graph as JSON."""
        data = {
            "entities": [
                {
                    "id": e.entity_id,
                    "type": e.entity_type,
                    "name": e.name,
                    "risk_score": e.risk_score,
                    "properties": e.properties
                }
                for e in self.entities.values()
            ],
            "relationships": [
                {
                    "id": r.relationship_id,
                    "type": r.relationship_type,
                    "source": r.source_entity_id,
                    "target": r.target_entity_id,
                    "confidence": r.confidence
                }
                for r in self.relationships.values()
            ]
        }
        return json.dumps(data, indent=2, default=str)

    def _export_cypher(self) -> str:
        """Export graph as Cypher statements."""
        statements = []

        # Create entities
        for entity in self.entities.values():
            props = json.dumps(entity.properties)
            statements.append(
                f"CREATE (n:{entity.entity_type} {{id: '{entity.entity_id}', name: '{entity.name}', "
                f"risk_score: {entity.risk_score}, properties: {props}}})"
            )

        # Create relationships
        for rel in self.relationships.values():
            statements.append(
                f"MATCH (a {{id: '{rel.source_entity_id}'}}), (b {{id: '{rel.target_entity_id}'}}) "
                f"CREATE (a)-[:{rel.relationship_type} {{confidence: {rel.confidence}}}]->(b)"
            )

        return "\n".join(statements)

    def _export_graphml(self) -> str:
        """Export graph as GraphML."""
        lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        lines.append('<graphml xmlns="https://example.com">')
        lines.append('  <graph id="G" edgedefault="directed">')

        # Add nodes
        for entity in self.entities.values():
            lines.append(f'    <node id="{entity.entity_id}">')
            lines.append(f'      <data key="name">{entity.name}</data>')
            lines.append(f'      <data key="type">{entity.entity_type}</data>')
            lines.append(f'      <data key="risk_score">{entity.risk_score}</data>')
            lines.append('    </node>')

        # Add edges
        for rel in self.relationships.values():
            lines.append(f'    <edge source="{rel.source_entity_id}" target="{rel.target_entity_id}">')
            lines.append(f'      <data key="type">{rel.relationship_type}</data>')
            lines.append(f'      <data key="confidence">{rel.confidence}</data>')
            lines.append('    </edge>')

        lines.append('  </graph>')
        lines.append('</graphml>')

        return "\n".join(lines)


# Global knowledge graph engine instance
_knowledge_graph_engine: Optional[KnowledgeGraphEngine] = None


def get_knowledge_graph_engine() -> KnowledgeGraphEngine:
    """Get the global knowledge graph engine instance."""
    global _knowledge_graph_engine
    if _knowledge_graph_engine is None:
        _knowledge_graph_engine = KnowledgeGraphEngine()
    return _knowledge_graph_engine
