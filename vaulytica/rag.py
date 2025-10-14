"""Enhanced RAG system for historical incident correlation."""

import json
import hashlib
from typing import List, Optional, Dict, Tuple
import chromadb
from chromadb.config import Settings
from vaulytica.models import SecurityEvent, AnalysisResult
from vaulytica.config import VaulyticaConfig


class IncidentRAG:
    """Enhanced Retrieval-Augmented Generation for historical incidents with hybrid search."""

    def __init__(self, config: VaulyticaConfig):
        self.config = config
        self.client = chromadb.PersistentClient(
            path=str(config.chroma_db_path),
            settings=Settings(anonymized_telemetry=False)
        )
        self.collection = self.client.get_or_create_collection(
            name="security_incidents",
            metadata={"description": "Historical security incidents and analyses"}
        )
    
    def store_incident(self, event: SecurityEvent, analysis: AnalysisResult) -> None:
        """Store analyzed incident for future retrieval."""
        
        document = self._create_document(event, analysis)
        metadata = self._create_metadata(event, analysis)
        
        self.collection.add(
            documents=[document],
            metadatas=[metadata],
            ids=[event.event_id]
        )
    
    def find_similar_incidents(
        self,
        event: SecurityEvent,
        max_results: int = 5
    ) -> List[Dict[str, any]]:
        """Find similar historical incidents with enhanced relevance scoring."""

        query_text = self._create_enhanced_query(event)

        results = self.collection.query(
            query_texts=[query_text],
            n_results=max_results * 2,
            where={
                "severity": {"$in": [event.severity.value, "HIGH", "CRITICAL"]}
            } if event.severity.value in ["HIGH", "CRITICAL"] else None
        )

        if not results["documents"] or not results["documents"][0]:
            return []

        scored_results = self._score_and_rank_results(
            event,
            results["documents"][0],
            results["metadatas"][0] if results["metadatas"] else [],
            results["distances"][0] if results["distances"] else []
        )

        return scored_results[:max_results]
    
    def _create_document(self, event: SecurityEvent, analysis: AnalysisResult) -> str:
        """Create searchable document from incident."""
        
        doc_parts = [
            f"Title: {event.title}",
            f"Description: {event.description}",
            f"Severity: {event.severity.value}",
            f"Category: {event.category.value}",
            f"Analysis: {analysis.executive_summary}",
            f"Attack Chain: {' -> '.join(analysis.attack_chain)}",
            f"MITRE Techniques: {', '.join([m.technique_name for m in analysis.mitre_techniques])}",
        ]
        
        if event.technical_indicators:
            indicators = [f"{ti.indicator_type}:{ti.value}" for ti in event.technical_indicators]
            doc_parts.append(f"Indicators: {', '.join(indicators)}")
        
        return "\n".join(doc_parts)
    
    def _create_metadata(self, event: SecurityEvent, analysis: AnalysisResult) -> dict:
        """Create metadata for filtering and retrieval."""
        
        return {
            "event_id": event.event_id,
            "source_system": event.source_system,
            "severity": event.severity.value,
            "category": event.category.value,
            "timestamp": event.timestamp.isoformat(),
            "risk_score": analysis.risk_score,
        }
    
    def _create_enhanced_query(self, event: SecurityEvent) -> str:
        """Create enhanced query with weighted components."""

        query_parts = [
            f"TITLE: {event.title}",
            f"CATEGORY: {event.category.value}",
            f"SEVERITY: {event.severity.value}",
            f"DESCRIPTION: {event.description[:200]}",
        ]

        if event.technical_indicators:
            indicators = " ".join([f"{ti.indicator_type}:{ti.value}"
                                  for ti in event.technical_indicators[:5]])
            query_parts.append(f"INDICATORS: {indicators}")

        if event.mitre_attack:
            techniques = " ".join([m.technique_id for m in event.mitre_attack])
            query_parts.append(f"MITRE: {techniques}")

        return " | ".join(query_parts)

    def _score_and_rank_results(
        self,
        query_event: SecurityEvent,
        documents: List[str],
        metadatas: List[Dict],
        distances: List[float]
    ) -> List[Dict[str, any]]:
        """Score and rank results based on multiple factors."""

        scored_results = []

        for i, (doc, metadata, distance) in enumerate(zip(documents, metadatas, distances)):
            score = self._calculate_relevance_score(
                query_event, metadata, distance
            )

            scored_results.append({
                "document": doc,
                "metadata": metadata,
                "distance": distance,
                "relevance_score": score,
                "rank": i + 1
            })

        scored_results.sort(key=lambda x: x["relevance_score"], reverse=True)

        for i, result in enumerate(scored_results):
            result["rank"] = i + 1

        return scored_results

    def _calculate_relevance_score(
        self,
        query_event: SecurityEvent,
        metadata: Dict,
        distance: float
    ) -> float:
        """Calculate relevance score based on multiple factors."""

        base_score = 1.0 - min(distance, 1.0)

        if metadata.get("category") == query_event.category.value:
            base_score *= 1.3

        if metadata.get("severity") == query_event.severity.value:
            base_score *= 1.2

        risk_diff = abs(metadata.get("risk_score", 5.0) - 5.0)
        if risk_diff < 1.0:
            base_score *= 1.1

        return min(base_score, 1.0)

    def get_collection_stats(self) -> dict:
        """Get statistics about stored incidents."""

        count = self.collection.count()
        return {
            "total_incidents": count,
            "collection_name": self.collection.name,
        }

    def get_incident_by_id(self, event_id: str) -> Optional[Dict]:
        """Retrieve specific incident by ID."""

        try:
            results = self.collection.get(ids=[event_id])
            if results["documents"]:
                return {
                    "document": results["documents"][0],
                    "metadata": results["metadatas"][0] if results["metadatas"] else {}
                }
        except Exception:
            pass

        return None

