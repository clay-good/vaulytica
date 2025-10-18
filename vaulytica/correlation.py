import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple, Optional, Any
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

from vaulytica.models import SecurityEvent, AnalysisResult, TechnicalIndicator, AssetInfo
from vaulytica.logger import get_logger

logger = get_logger(__name__)


class CorrelationType(str, Enum):
    """Types of event correlations."""
    TEMPORAL = "TEMPORAL"  # Events close in time
    ASSET_BASED = "ASSET_BASED"  # Same asset/IP/hostname
    IOC_BASED = "IOC_BASED"  # Shared IOCs
    TTP_BASED = "TTP_BASED"  # Similar MITRE TTPs
    ATTACK_CHAIN = "ATTACK_CHAIN"  # Sequential attack stages
    CAMPAIGN = "CAMPAIGN"  # Part of larger campaign
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"  # Movement between assets
    DATA_FLOW = "DATA_FLOW"  # Data transfer patterns


class CampaignStatus(str, Enum):
    """Attack campaign status."""
    ACTIVE = "ACTIVE"
    DORMANT = "DORMANT"
    COMPLETED = "COMPLETED"
    MITIGATED = "MITIGATED"


@dataclass
class CorrelationLink:
    """Link between correlated events."""
    event_id_1: str
    event_id_2: str
    correlation_type: CorrelationType
    confidence: float  # 0.0-1.0
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EventCluster:
    """Cluster of correlated events."""
    cluster_id: str
    events: List[SecurityEvent] = field(default_factory=list)
    correlations: List[CorrelationLink] = field(default_factory=list)
    cluster_score: float = 0.0  # Overall correlation strength
    primary_assets: Set[str] = field(default_factory=set)
    shared_iocs: Set[str] = field(default_factory=set)
    attack_stages: List[str] = field(default_factory=list)
    time_span: Optional[timedelta] = None
    
    def add_event(self, event: SecurityEvent):
        """Add event to cluster."""
        self.events.append(event)
        
        # Update primary assets
        for asset in event.affected_assets:
            if asset.hostname:
                self.primary_assets.add(asset.hostname)
            for ip in asset.ip_addresses:
                self.primary_assets.add(ip)
        
        # Update time span
        if len(self.events) > 1:
            timestamps = [e.timestamp for e in self.events]
            self.time_span = max(timestamps) - min(timestamps)


@dataclass
class AttackCampaign:
    """Detected attack campaign across multiple events."""
    campaign_id: str
    campaign_name: str
    status: CampaignStatus
    clusters: List[EventCluster] = field(default_factory=list)
    total_events: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    targeted_assets: Set[str] = field(default_factory=set)
    threat_actors: List[str] = field(default_factory=list)
    ttps: Set[str] = field(default_factory=set)
    iocs: Set[str] = field(default_factory=set)
    confidence: float = 0.0
    severity_score: float = 0.0


class CorrelationEngine:
    """
    Advanced correlation engine for multi-event analysis.
    
    Capabilities:
    - Temporal correlation (time-based)
    - Asset-based correlation (same targets)
    - IOC-based correlation (shared indicators)
    - TTP-based correlation (similar techniques)
    - Attack chain detection (sequential stages)
    - Campaign detection (coordinated attacks)
    - Lateral movement tracking
    - Data flow analysis
    """
    
    def __init__(self, 
                 temporal_window_minutes: int = 60,
                 min_correlation_confidence: float = 0.5,
                 min_campaign_events: int = 3):
        """
        Initialize correlation engine.
        
        Args:
            temporal_window_minutes: Time window for temporal correlation
            min_correlation_confidence: Minimum confidence for correlation
            min_campaign_events: Minimum events to declare a campaign
        """
        self.temporal_window = timedelta(minutes=temporal_window_minutes)
        self.min_confidence = min_correlation_confidence
        self.min_campaign_events = min_campaign_events
        
        # Event storage
        self.events: Dict[str, SecurityEvent] = {}
        self.analyses: Dict[str, AnalysisResult] = {}
        
        # Correlation tracking
        self.correlations: List[CorrelationLink] = []
        self.clusters: Dict[str, EventCluster] = {}
        self.campaigns: Dict[str, AttackCampaign] = {}
        
        # Index structures for fast lookup
        self.asset_index: Dict[str, Set[str]] = defaultdict(set)  # asset -> event_ids
        self.ioc_index: Dict[str, Set[str]] = defaultdict(set)  # ioc -> event_ids
        self.ttp_index: Dict[str, Set[str]] = defaultdict(set)  # ttp -> event_ids
        self.time_index: List[Tuple[datetime, str]] = []  # (timestamp, event_id)
        
        logger.info(f"Correlation engine initialized (window={temporal_window_minutes}m, "
                   f"min_confidence={min_correlation_confidence})")
    
    def add_event(self, event: SecurityEvent, analysis: Optional[AnalysisResult] = None):
        """
        Add event to correlation engine.
        
        Args:
            event: Security event to add
            analysis: Optional analysis result
        """
        self.events[event.event_id] = event
        if analysis:
            self.analyses[event.event_id] = analysis
        
        # Update indices
        self._update_indices(event, analysis)
        
        # Perform correlation
        self._correlate_event(event, analysis)
        
        logger.debug(f"Added event {event.event_id} to correlation engine")
    
    def _update_indices(self, event: SecurityEvent, analysis: Optional[AnalysisResult]):
        """Update index structures with new event."""
        # Asset index
        for asset in event.affected_assets:
            if asset.hostname:
                self.asset_index[asset.hostname].add(event.event_id)
            for ip in asset.ip_addresses:
                self.asset_index[ip].add(event.event_id)
        
        # IOC index
        for indicator in event.technical_indicators:
            ioc_key = f"{indicator.indicator_type}:{indicator.value}"
            self.ioc_index[ioc_key].add(event.event_id)
        
        # TTP index
        for mitre in event.mitre_attack:
            self.ttp_index[mitre.technique_id].add(event.event_id)
        
        if analysis:
            for mitre in analysis.mitre_techniques:
                self.ttp_index[mitre.technique_id].add(event.event_id)
        
        # Time index
        self.time_index.append((event.timestamp, event.event_id))
        self.time_index.sort()  # Keep sorted by time
    
    def _correlate_event(self, event: SecurityEvent, analysis: Optional[AnalysisResult]):
        """Correlate new event with existing events."""
        correlations = []
        
        # Temporal correlation
        correlations.extend(self._find_temporal_correlations(event))
        
        # Asset-based correlation
        correlations.extend(self._find_asset_correlations(event))
        
        # IOC-based correlation
        correlations.extend(self._find_ioc_correlations(event))
        
        # TTP-based correlation
        correlations.extend(self._find_ttp_correlations(event, analysis))
        
        # Attack chain correlation
        if analysis:
            correlations.extend(self._find_attack_chain_correlations(event, analysis))
        
        # Filter by confidence
        correlations = [c for c in correlations if c.confidence >= self.min_confidence]
        
        # Add to correlation list
        self.correlations.extend(correlations)
        
        # Update clusters
        if correlations:
            self._update_clusters(event, correlations)
        
        logger.debug(f"Found {len(correlations)} correlations for event {event.event_id}")
    
    def _find_temporal_correlations(self, event: SecurityEvent) -> List[CorrelationLink]:
        """Find events within temporal window."""
        correlations = []
        
        for ts, event_id in self.time_index:
            if event_id == event.event_id:
                continue
            
            time_diff = abs((event.timestamp - ts).total_seconds())
            
            if time_diff <= self.temporal_window.total_seconds():
                # Calculate confidence based on time proximity
                confidence = 1.0 - (time_diff / self.temporal_window.total_seconds()) * 0.5
                
                correlations.append(CorrelationLink(
                    event_id_1=event.event_id,
                    event_id_2=event_id,
                    correlation_type=CorrelationType.TEMPORAL,
                    confidence=confidence,
                    evidence=[f"Events within {time_diff:.0f} seconds"],
                    metadata={"time_diff_seconds": time_diff}
                ))
        
        return correlations
    
    def _find_asset_correlations(self, event: SecurityEvent) -> List[CorrelationLink]:
        """Find events affecting same assets."""
        correlations = []
        related_events = set()
        
        # Find events with shared assets
        for asset in event.affected_assets:
            if asset.hostname:
                related_events.update(self.asset_index[asset.hostname])
            for ip in asset.ip_addresses:
                related_events.update(self.asset_index[ip])
        
        related_events.discard(event.event_id)
        
        for related_id in related_events:
            related_event = self.events[related_id]
            
            # Calculate shared assets
            shared_assets = self._get_shared_assets(event, related_event)
            
            if shared_assets:
                confidence = min(0.9, 0.5 + len(shared_assets) * 0.1)
                
                correlations.append(CorrelationLink(
                    event_id_1=event.event_id,
                    event_id_2=related_id,
                    correlation_type=CorrelationType.ASSET_BASED,
                    confidence=confidence,
                    evidence=[f"Shared assets: {', '.join(list(shared_assets)[:3])}"],
                    metadata={"shared_assets": list(shared_assets)}
                ))
        
        return correlations
    
    def _find_ioc_correlations(self, event: SecurityEvent) -> List[CorrelationLink]:
        """Find events with shared IOCs."""
        correlations = []
        related_events = set()
        
        # Find events with shared IOCs
        for indicator in event.technical_indicators:
            ioc_key = f"{indicator.indicator_type}:{indicator.value}"
            related_events.update(self.ioc_index[ioc_key])
        
        related_events.discard(event.event_id)
        
        for related_id in related_events:
            related_event = self.events[related_id]
            
            # Calculate shared IOCs
            shared_iocs = self._get_shared_iocs(event, related_event)
            
            if shared_iocs:
                # Higher confidence for IOC matches
                confidence = min(0.95, 0.7 + len(shared_iocs) * 0.1)
                
                correlations.append(CorrelationLink(
                    event_id_1=event.event_id,
                    event_id_2=related_id,
                    correlation_type=CorrelationType.IOC_BASED,
                    confidence=confidence,
                    evidence=[f"Shared IOCs: {', '.join(list(shared_iocs)[:3])}"],
                    metadata={"shared_iocs": list(shared_iocs)}
                ))

        return correlations

    def _find_ttp_correlations(self, event: SecurityEvent,
                               analysis: Optional[AnalysisResult]) -> List[CorrelationLink]:
        """Find events with similar TTPs."""
        correlations = []
        related_events = set()

        # Collect TTPs from event and analysis
        ttps = {m.technique_id for m in event.mitre_attack}
        if analysis:
            ttps.update(m.technique_id for m in analysis.mitre_techniques)

        # Find events with shared TTPs
        for ttp in ttps:
            related_events.update(self.ttp_index[ttp])

        related_events.discard(event.event_id)

        for related_id in related_events:
            related_event = self.events[related_id]
            related_analysis = self.analyses.get(related_id)

            # Calculate shared TTPs
            shared_ttps = self._get_shared_ttps(event, related_event, analysis, related_analysis)

            if shared_ttps:
                confidence = min(0.9, 0.6 + len(shared_ttps) * 0.1)

                correlations.append(CorrelationLink(
                    event_id_1=event.event_id,
                    event_id_2=related_id,
                    correlation_type=CorrelationType.TTP_BASED,
                    confidence=confidence,
                    evidence=[f"Shared TTPs: {', '.join(list(shared_ttps)[:3])}"],
                    metadata={"shared_ttps": list(shared_ttps)}
                ))

        return correlations

    def _find_attack_chain_correlations(self, event: SecurityEvent,
                                       analysis: AnalysisResult) -> List[CorrelationLink]:
        """Find events that form an attack chain."""
        correlations = []

        # MITRE ATT&CK tactic order
        tactic_order = [
            "Initial Access", "Execution", "Persistence", "Privilege Escalation",
            "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
            "Collection", "Command and Control", "Exfiltration", "Impact"
        ]

        # Get tactics from current event
        current_tactics = {m.tactic for m in analysis.mitre_techniques}

        # Find events with preceding or following tactics
        for other_id, other_event in self.events.items():
            if other_id == event.event_id:
                continue

            other_analysis = self.analyses.get(other_id)
            if not other_analysis:
                continue

            other_tactics = {m.tactic for m in other_analysis.mitre_techniques}

            # Check if tactics are sequential
            is_sequential, direction = self._are_tactics_sequential(
                current_tactics, other_tactics, tactic_order
            )

            if is_sequential:
                # Check temporal proximity
                time_diff = abs((event.timestamp - other_event.timestamp).total_seconds())

                if time_diff <= self.temporal_window.total_seconds() * 2:  # Wider window for chains
                    confidence = 0.8 - (time_diff / (self.temporal_window.total_seconds() * 2)) * 0.3

                    correlations.append(CorrelationLink(
                        event_id_1=event.event_id,
                        event_id_2=other_id,
                        correlation_type=CorrelationType.ATTACK_CHAIN,
                        confidence=confidence,
                        evidence=[f"Sequential attack stages: {direction}"],
                        metadata={
                            "direction": direction,
                            "current_tactics": list(current_tactics),
                            "other_tactics": list(other_tactics)
                        }
                    ))

        return correlations

    def _get_shared_assets(self, event1: SecurityEvent, event2: SecurityEvent) -> Set[str]:
        """Get shared assets between two events."""
        assets1 = set()
        assets2 = set()

        for asset in event1.affected_assets:
            if asset.hostname:
                assets1.add(asset.hostname)
            assets1.update(asset.ip_addresses)

        for asset in event2.affected_assets:
            if asset.hostname:
                assets2.add(asset.hostname)
            assets2.update(asset.ip_addresses)

        return assets1 & assets2

    def _get_shared_iocs(self, event1: SecurityEvent, event2: SecurityEvent) -> Set[str]:
        """Get shared IOCs between two events."""
        iocs1 = {f"{i.indicator_type}:{i.value}" for i in event1.technical_indicators}
        iocs2 = {f"{i.indicator_type}:{i.value}" for i in event2.technical_indicators}
        return iocs1 & iocs2

    def _get_shared_ttps(self, event1: SecurityEvent, event2: SecurityEvent,
                        analysis1: Optional[AnalysisResult],
                        analysis2: Optional[AnalysisResult]) -> Set[str]:
        """Get shared TTPs between two events."""
        ttps1 = {m.technique_id for m in event1.mitre_attack}
        ttps2 = {m.technique_id for m in event2.mitre_attack}

        if analysis1:
            ttps1.update(m.technique_id for m in analysis1.mitre_techniques)
        if analysis2:
            ttps2.update(m.technique_id for m in analysis2.mitre_techniques)

        return ttps1 & ttps2

    def _are_tactics_sequential(self, tactics1: Set[str], tactics2: Set[str],
                                tactic_order: List[str]) -> Tuple[bool, str]:
        """Check if tactics are sequential in attack chain."""
        # Get positions in tactic order
        positions1 = [tactic_order.index(t) for t in tactics1 if t in tactic_order]
        positions2 = [tactic_order.index(t) for t in tactics2 if t in tactic_order]

        if not positions1 or not positions2:
            return False, ""

        avg_pos1 = sum(positions1) / len(positions1)
        avg_pos2 = sum(positions2) / len(positions2)

        # Check if sequential (within 3 stages)
        diff = abs(avg_pos1 - avg_pos2)

        if 1 <= diff <= 3:
            if avg_pos1 < avg_pos2:
                return True, "forward"
            else:
                return True, "backward"

        return False, ""

    def _update_clusters(self, event: SecurityEvent, correlations: List[CorrelationLink]):
        """Update event clusters based on correlations."""
        # Find existing clusters this event should join
        related_clusters = set()

        for correlation in correlations:
            other_id = (correlation.event_id_2
                       if correlation.event_id_1 == event.event_id
                       else correlation.event_id_1)

            # Find cluster containing other event
            for cluster_id, cluster in self.clusters.items():
                if any(e.event_id == other_id for e in cluster.events):
                    related_clusters.add(cluster_id)

        if not related_clusters:
            # Create new cluster
            cluster_id = self._generate_cluster_id(event)
            cluster = EventCluster(cluster_id=cluster_id)
            cluster.add_event(event)
            cluster.correlations = correlations
            self.clusters[cluster_id] = cluster
            logger.debug(f"Created new cluster {cluster_id}")

        elif len(related_clusters) == 1:
            # Add to existing cluster
            cluster_id = list(related_clusters)[0]
            cluster = self.clusters[cluster_id]
            cluster.add_event(event)
            cluster.correlations.extend(correlations)
            logger.debug(f"Added event to cluster {cluster_id}")

        else:
            # Merge multiple clusters
            merged_cluster_id = self._generate_cluster_id(event)
            merged_cluster = EventCluster(cluster_id=merged_cluster_id)

            for cluster_id in related_clusters:
                cluster = self.clusters[cluster_id]
                merged_cluster.events.extend(cluster.events)
                merged_cluster.correlations.extend(cluster.correlations)
                del self.clusters[cluster_id]

            merged_cluster.add_event(event)
            merged_cluster.correlations.extend(correlations)
            self.clusters[merged_cluster_id] = merged_cluster
            logger.info(f"Merged {len(related_clusters)} clusters into {merged_cluster_id}")

    def _generate_cluster_id(self, event: SecurityEvent) -> str:
        """Generate unique cluster ID."""
        data = f"{event.event_id}_{event.timestamp.isoformat()}_{len(self.clusters)}"
        return f"cluster_{hashlib.md5(data.encode()).hexdigest()[:12]}"

    def detect_campaigns(self) -> List[AttackCampaign]:
        """
        Detect attack campaigns from event clusters.

        Returns:
            List of detected attack campaigns
        """
        campaigns = []

        for cluster_id, cluster in self.clusters.items():
            # Check if cluster qualifies as campaign
            if len(cluster.events) >= self.min_campaign_events:
                campaign = self._analyze_cluster_as_campaign(cluster)
                if campaign:
                    campaigns.append(campaign)
                    self.campaigns[campaign.campaign_id] = campaign

        logger.info(f"Detected {len(campaigns)} attack campaigns")
        return campaigns

    def _analyze_cluster_as_campaign(self, cluster: EventCluster) -> Optional[AttackCampaign]:
        """Analyze cluster to determine if it's a campaign."""
        # Calculate campaign metrics
        timestamps = [e.timestamp for e in cluster.events]
        first_seen = min(timestamps)
        last_seen = max(timestamps)
        duration = last_seen - first_seen

        # Collect campaign attributes
        targeted_assets = cluster.primary_assets

        # Collect TTPs
        ttps = set()
        for event_id in [e.event_id for e in cluster.events]:
            analysis = self.analyses.get(event_id)
            if analysis:
                ttps.update(m.technique_id for m in analysis.mitre_techniques)

        # Collect IOCs
        iocs = cluster.shared_iocs

        # Collect threat actors
        threat_actors = []
        for event_id in [e.event_id for e in cluster.events]:
            analysis = self.analyses.get(event_id)
            if analysis and hasattr(analysis, 'threat_actors'):
                threat_actors.extend(a.actor_name for a in analysis.threat_actors)
        threat_actors = list(set(threat_actors))

        # Calculate confidence
        avg_correlation_confidence = (
            sum(c.confidence for c in cluster.correlations) / len(cluster.correlations)
            if cluster.correlations else 0.5
        )

        # Calculate severity score
        severity_map = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        severity_score = sum(severity_map.get(e.severity.value, 0) for e in cluster.events) / len(cluster.events)

        # Determine status
        hours_since_last = (datetime.now() - last_seen).total_seconds() / 3600
        if hours_since_last < 24:
            status = CampaignStatus.ACTIVE
        elif hours_since_last < 168:  # 1 week
            status = CampaignStatus.DORMANT
        else:
            status = CampaignStatus.COMPLETED

        # Generate campaign name
        campaign_name = self._generate_campaign_name(cluster, threat_actors, ttps)

        campaign = AttackCampaign(
            campaign_id=f"campaign_{cluster.cluster_id}",
            campaign_name=campaign_name,
            status=status,
            clusters=[cluster],
            total_events=len(cluster.events),
            first_seen=first_seen,
            last_seen=last_seen,
            targeted_assets=targeted_assets,
            threat_actors=threat_actors,
            ttps=ttps,
            iocs=iocs,
            confidence=avg_correlation_confidence,
            severity_score=severity_score
        )

        return campaign

    def _generate_campaign_name(self, cluster: EventCluster,
                                threat_actors: List[str], ttps: Set[str]) -> str:
        """Generate descriptive campaign name."""
        if threat_actors:
            return f"{threat_actors[0]} Campaign"

        # Use primary tactic
        tactic_map = {
            "T1566": "Phishing",
            "T1078": "Valid Accounts",
            "T1059": "Command Execution",
            "T1071": "C2 Communication",
            "T1486": "Ransomware",
            "T1567": "Exfiltration"
        }

        for ttp in ttps:
            for prefix, name in tactic_map.items():
                if ttp.startswith(prefix):
                    return f"{name} Campaign"

        # Fallback to asset-based name
        if cluster.primary_assets:
            asset = list(cluster.primary_assets)[0]
            return f"Campaign targeting {asset}"

        return f"Unknown Campaign {cluster.cluster_id[:8]}"

    def get_correlated_events(self, event_id: str) -> List[SecurityEvent]:
        """
        Get all events correlated with a specific event.

        Args:
            event_id: Event ID to find correlations for

        Returns:
            List of correlated events
        """
        correlated_ids = set()

        for correlation in self.correlations:
            if correlation.event_id_1 == event_id:
                correlated_ids.add(correlation.event_id_2)
            elif correlation.event_id_2 == event_id:
                correlated_ids.add(correlation.event_id_1)

        return [self.events[eid] for eid in correlated_ids if eid in self.events]

    def get_cluster_by_event(self, event_id: str) -> Optional[EventCluster]:
        """Get cluster containing a specific event."""
        for cluster in self.clusters.values():
            if any(e.event_id == event_id for e in cluster.events):
                return cluster
        return None

    def get_campaign_by_event(self, event_id: str) -> Optional[AttackCampaign]:
        """Get campaign containing a specific event."""
        cluster = self.get_cluster_by_event(event_id)
        if not cluster:
            return None

        for campaign in self.campaigns.values():
            if cluster in campaign.clusters:
                return campaign
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get correlation engine statistics.

        Returns:
            Dictionary with statistics
        """
        correlation_types = defaultdict(int)
        for corr in self.correlations:
            correlation_types[corr.correlation_type.value] += 1

        return {
            "total_events": len(self.events),
            "total_correlations": len(self.correlations),
            "correlation_types": dict(correlation_types),
            "total_clusters": len(self.clusters),
            "total_campaigns": len(self.campaigns),
            "active_campaigns": sum(1 for c in self.campaigns.values()
                                   if c.status == CampaignStatus.ACTIVE),
            "avg_cluster_size": (sum(len(c.events) for c in self.clusters.values()) / len(self.clusters)
                                if self.clusters else 0),
            "largest_cluster": max((len(c.events) for c in self.clusters.values()), default=0)
        }

    def generate_correlation_report(self, event_id: str) -> Dict[str, Any]:
        """
        Generate detailed correlation report for an event.

        Args:
            event_id: Event ID to generate report for

        Returns:
            Correlation report dictionary
        """
        if event_id not in self.events:
            return {"error": "Event not found"}

        event = self.events[event_id]
        correlated_events = self.get_correlated_events(event_id)
        cluster = self.get_cluster_by_event(event_id)
        campaign = self.get_campaign_by_event(event_id)

        # Get correlations for this event
        event_correlations = [
            c for c in self.correlations
            if c.event_id_1 == event_id or c.event_id_2 == event_id
        ]

        # Group by type
        correlations_by_type = defaultdict(list)
        for corr in event_correlations:
            correlations_by_type[corr.correlation_type.value].append({
                "other_event_id": (corr.event_id_2 if corr.event_id_1 == event_id
                                  else corr.event_id_1),
                "confidence": corr.confidence,
                "evidence": corr.evidence
            })

        report = {
            "event_id": event_id,
            "event_title": event.title,
            "event_timestamp": event.timestamp.isoformat(),
            "total_correlations": len(event_correlations),
            "correlated_events_count": len(correlated_events),
            "correlations_by_type": dict(correlations_by_type),
            "cluster": {
                "cluster_id": cluster.cluster_id,
                "total_events": len(cluster.events),
                "time_span_hours": cluster.time_span.total_seconds() / 3600 if cluster.time_span else 0,
                "primary_assets": list(cluster.primary_assets)
            } if cluster else None,
            "campaign": {
                "campaign_id": campaign.campaign_id,
                "campaign_name": campaign.campaign_name,
                "status": campaign.status.value,
                "total_events": campaign.total_events,
                "threat_actors": campaign.threat_actors,
                "confidence": campaign.confidence,
                "severity_score": campaign.severity_score
            } if campaign else None
        }

        return report

    def export_graph_data(self) -> Dict[str, Any]:
        """
        Export correlation data in graph format for visualization.

        Returns:
            Graph data with nodes and edges
        """
        nodes = []
        edges = []

        # Create nodes for events
        for event_id, event in self.events.items():
            nodes.append({
                "id": event_id,
                "label": event.title[:50],
                "timestamp": event.timestamp.isoformat(),
                "severity": event.severity.value,
                "category": event.category.value,
                "type": "event"
            })

        # Create edges for correlations
        for i, corr in enumerate(self.correlations):
            edges.append({
                "id": f"corr_{i}",
                "source": corr.event_id_1,
                "target": corr.event_id_2,
                "type": corr.correlation_type.value,
                "confidence": corr.confidence,
                "evidence": corr.evidence[:2]  # Limit evidence
            })

        # Add cluster information
        clusters_data = []
        for cluster_id, cluster in self.clusters.items():
            clusters_data.append({
                "cluster_id": cluster_id,
                "event_ids": [e.event_id for e in cluster.events],
                "size": len(cluster.events),
                "primary_assets": list(cluster.primary_assets)
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "clusters": clusters_data,
            "statistics": self.get_statistics()
        }

