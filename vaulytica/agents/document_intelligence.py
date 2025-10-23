"""
Document Intelligence System (RAG) for Vaulytica AI Agent Framework

Retrieval-Augmented Generation (RAG) system for:
- IR plans and procedures
- Historical incident reports
- Standard Operating Procedures (SOPs)
- Playbooks and runbooks
- Compliance documentation
- Security policies

Provides semantic search and retrieval to enrich incident response with
organizational knowledge and historical context.

Version: 0.31.0
"""

import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class DocumentType(str, Enum):
    """Types of documents"""
    IR_PLAN = "ir_plan"
    HISTORICAL_INCIDENT = "historical_incident"
    SOP = "sop"
    PLAYBOOK = "playbook"
    RUNBOOK = "runbook"
    COMPLIANCE_DOC = "compliance_doc"
    SECURITY_POLICY = "security_policy"
    THREAT_REPORT = "threat_report"
    LESSONS_LEARNED = "lessons_learned"


@dataclass
class Document:
    """Document in the knowledge base"""
    document_id: str
    document_type: DocumentType
    title: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "document_id": self.document_id,
            "document_type": self.document_type.value,
            "title": self.title,
            "content": self.content,
            "metadata": self.metadata,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "version": self.version
        }


@dataclass
class DocumentChunk:
    """Chunk of a document for retrieval"""
    chunk_id: str
    document_id: str
    document_type: DocumentType
    content: str
    chunk_index: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SearchResult:
    """Search result from document retrieval"""
    document_id: str
    document_type: DocumentType
    title: str
    content: str
    relevance_score: float
    matched_chunks: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DocumentIntelligence:
    """
    Document Intelligence System using RAG (Retrieval-Augmented Generation).

    Features:
    - Document ingestion and indexing
    - Semantic search (keyword-based for now, can be upgraded to embeddings)
    - Document chunking for better retrieval
    - Relevance scoring
    - Multi-document retrieval
    - Historical incident similarity matching
    """

    def __init__(self, chunk_size: int = 500, chunk_overlap: int = 50):
        self.documents: Dict[str, Document] = {}
        self.chunks: Dict[str, DocumentChunk] = {}
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.index: Dict[str, List[str]] = {}  # keyword -> [chunk_ids]
        logger.info("DocumentIntelligence initialized")

    def add_document(self, document: Document) -> None:
        """
        Add a document to the knowledge base.

        Args:
            document: Document to add
        """
        self.documents[document.document_id] = document

        # Chunk the document
        chunks = self._chunk_document(document)

        # Index chunks
        for chunk in chunks:
            self.chunks[chunk.chunk_id] = chunk
            self._index_chunk(chunk)

        logger.info(f"Added document: {document.title} ({len(chunks)} chunks)")

    def remove_document(self, document_id: str) -> None:
        """Remove a document from the knowledge base"""
        if document_id in self.documents:
            # Remove chunks
            chunks_to_remove = [
                chunk_id for chunk_id, chunk in self.chunks.items()
                if chunk.document_id == document_id
            ]
            for chunk_id in chunks_to_remove:
                del self.chunks[chunk_id]

            # Remove from index
            for keyword in list(self.index.keys()):
                self.index[keyword] = [
                    cid for cid in self.index[keyword]
                    if cid not in chunks_to_remove
                ]
                if not self.index[keyword]:
                    del self.index[keyword]

            del self.documents[document_id]
            logger.info(f"Removed document: {document_id}")

    def search(
        self,
        query: str,
        document_types: Optional[List[DocumentType]] = None,
        tags: Optional[List[str]] = None,
        top_k: int = 5
    ) -> List[SearchResult]:
        """
        Search for relevant documents.

        Args:
            query: Search query
            document_types: Optional filter by document types
            tags: Optional filter by tags
            top_k: Number of results to return

        Returns:
            List of SearchResult ordered by relevance
        """
        # Extract keywords from query
        keywords = self._extract_keywords(query)

        # Find matching chunks
        chunk_scores: Dict[str, float] = {}
        for keyword in keywords:
            if keyword in self.index:
                for chunk_id in self.index[keyword]:
                    chunk = self.chunks[chunk_id]

                    # Apply filters
                    if document_types and chunk.document_type not in document_types:
                        continue

                    document = self.documents[chunk.document_id]
                    if tags and not any(tag in document.tags for tag in tags):
                        continue

                    # Calculate relevance score (simple keyword matching)
                    score = self._calculate_relevance(query, chunk.content)
                    chunk_scores[chunk_id] = max(chunk_scores.get(chunk_id, 0), score)

        # Group chunks by document and aggregate scores
        document_scores: Dict[str, Tuple[float, List[str]]] = {}
        for chunk_id, score in chunk_scores.items():
            chunk = self.chunks[chunk_id]
            doc_id = chunk.document_id

            if doc_id not in document_scores:
                document_scores[doc_id] = (0.0, [])

            current_score, matched_chunks = document_scores[doc_id]
            document_scores[doc_id] = (
                current_score + score,
                matched_chunks + [chunk.content]
            )

        # Create search results
        results = []
        for doc_id, (score, matched_chunks) in document_scores.items():
            document = self.documents[doc_id]
            results.append(SearchResult(
                document_id=doc_id,
                document_type=document.document_type,
                title=document.title,
                content=document.content,
                relevance_score=score,
                matched_chunks=matched_chunks[:3],  # Top 3 matched chunks
                metadata=document.metadata
            ))

        # Sort by relevance and return top_k
        results.sort(key=lambda x: x.relevance_score, reverse=True)
        return results[:top_k]

    def find_similar_incidents(
        self,
        incident_description: str,
        top_k: int = 3
    ) -> List[SearchResult]:
        """
        Find similar historical incidents.

        Args:
            incident_description: Description of current incident
            top_k: Number of similar incidents to return

        Returns:
            List of similar historical incidents
        """
        return self.search(
            query=incident_description,
            document_types=[DocumentType.HISTORICAL_INCIDENT],
            top_k=top_k
        )

    def get_relevant_playbooks(
        self,
        incident_type: str,
        top_k: int = 3
    ) -> List[SearchResult]:
        """
        Get relevant playbooks for an incident type.

        Args:
            incident_type: Type of incident (e.g., "ransomware", "phishing")
            top_k: Number of playbooks to return

        Returns:
            List of relevant playbooks
        """
        return self.search(
            query=incident_type,
            document_types=[DocumentType.PLAYBOOK, DocumentType.RUNBOOK],
            top_k=top_k
        )

    def get_compliance_requirements(
        self,
        regulation: str,
        top_k: int = 5
    ) -> List[SearchResult]:
        """
        Get compliance requirements for a regulation.

        Args:
            regulation: Regulation name (e.g., "GDPR", "HIPAA", "PCI-DSS")
            top_k: Number of documents to return

        Returns:
            List of compliance documents
        """
        return self.search(
            query=regulation,
            document_types=[DocumentType.COMPLIANCE_DOC],
            top_k=top_k
        )

    def _chunk_document(self, document: Document) -> List[DocumentChunk]:
        """
        Chunk a document into smaller pieces for better retrieval.

        Args:
            document: Document to chunk

        Returns:
            List of DocumentChunk
        """
        content = document.content
        chunks = []

        # Simple chunking by character count with overlap
        start = 0
        chunk_index = 0

        while start < len(content):
            end = start + self.chunk_size
            chunk_content = content[start:end]

            chunk_id = f"{document.document_id}-chunk-{chunk_index}"
            chunks.append(DocumentChunk(
                chunk_id=chunk_id,
                document_id=document.document_id,
                document_type=document.document_type,
                content=chunk_content,
                chunk_index=chunk_index,
                metadata={
                    "title": document.title,
                    "tags": document.tags
                }
            ))

            start = end - self.chunk_overlap
            chunk_index += 1

        return chunks

    def _index_chunk(self, chunk: DocumentChunk) -> None:
        """Index a chunk for keyword search"""
        keywords = self._extract_keywords(chunk.content)

        for keyword in keywords:
            if keyword not in self.index:
                self.index[keyword] = []
            if chunk.chunk_id not in self.index[keyword]:
                self.index[keyword].append(chunk.chunk_id)

    def _extract_keywords(self, text: str) -> List[str]:
        """Extract keywords from text"""
        # Convert to lowercase and split
        text = text.lower()

        # Remove punctuation and split
        words = re.findall(r'\b\w+\b', text)

        # Filter out common stop words
        stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'o', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'be',
            'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will',
            'would', 'should', 'could', 'may', 'might', 'must', 'can', 'this',
            'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they'
        }

        keywords = [w for w in words if w not in stop_words and len(w) > 2]

        return keywords

    def _calculate_relevance(self, query: str, content: str) -> float:
        """
        Calculate relevance score between query and content.

        Simple keyword matching for now. Can be upgraded to:
        - TF-IDF scoring
        - BM25 ranking
        - Embedding-based similarity (cosine similarity)
        """
        query_keywords = set(self._extract_keywords(query))
        content_keywords = set(self._extract_keywords(content))

        if not query_keywords:
            return 0.0

        # Jaccard similarity
        intersection = query_keywords & content_keywords
        union = query_keywords | content_keywords

        return len(intersection) / len(union) if union else 0.0


# Global singleton instance
_document_intelligence: Optional[DocumentIntelligence] = None


def get_document_intelligence() -> DocumentIntelligence:
    """Get the global document intelligence instance"""
    global _document_intelligence
    if _document_intelligence is None:
        _document_intelligence = DocumentIntelligence()
    return _document_intelligence
