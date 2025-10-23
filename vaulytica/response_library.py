"""
Response Library Module

Manages approved answers, versioning, and reuse for security questionnaires.
Uses SQLite for persistent storage.

Version: 1.0.0
"""

import sqlite3
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    """Answer approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_REVISION = "needs_revision"


class AnswerCategory(str, Enum):
    """Answer categories for organization"""
    INCIDENT_RESPONSE = "incident_response"
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    COMPLIANCE = "compliance"
    BUSINESS_CONTINUITY = "business_continuity"
    TRAINING = "training"
    NETWORK_SECURITY = "network_security"
    APPLICATION_SECURITY = "application_security"
    PHYSICAL_SECURITY = "physical_security"
    VENDOR_MANAGEMENT = "vendor_management"
    OTHER = "other"


@dataclass
class StoredAnswer:
    """Stored answer in response library"""
    answer_id: str
    question_text: str
    question_hash: str
    answer_text: str
    category: str
    confidence_score: float
    sources: List[str]
    reasoning: str
    approval_status: ApprovalStatus
    version: int
    created_at: datetime
    updated_at: datetime
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AnswerVersion:
    """Answer version history"""
    version_id: str
    answer_id: str
    version: int
    answer_text: str
    confidence_score: float
    sources: List[str]
    reasoning: str
    created_at: datetime
    created_by: Optional[str] = None
    change_notes: Optional[str] = None


@dataclass
class AnswerTemplate:
    """Reusable answer template"""
    template_id: str
    template_name: str
    category: str
    question_pattern: str
    answer_template: str
    variables: List[str]
    created_at: datetime
    updated_at: datetime
    usage_count: int = 0


class ResponseLibrary:
    """
    Response Library for managing approved answers.

    Features:
    - Store and retrieve approved answers
    - Version control for answers
    - Approval workflow
    - Answer templates
    - Search and matching
    """

    def __init__(self, db_path: str = "vaulytica_responses.db"):
        """
        Initialize response library.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._init_database()
        logger.info(f"Response library initialized: {db_path}")

    def _init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Answers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS answers (
                answer_id TEXT PRIMARY KEY,
                question_text TEXT NOT NULL,
                question_hash TEXT NOT NULL,
                answer_text TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                sources TEXT NOT NULL,
                reasoning TEXT,
                approval_status TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                approved_by TEXT,
                approved_at TEXT,
                tags TEXT,
                metadata TEXT
            )
        """)

        # Answer versions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS answer_versions (
                version_id TEXT PRIMARY KEY,
                answer_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                answer_text TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                sources TEXT NOT NULL,
                reasoning TEXT,
                created_at TEXT NOT NULL,
                created_by TEXT,
                change_notes TEXT,
                FOREIGN KEY (answer_id) REFERENCES answers (answer_id)
            )
        """)

        # Answer templates table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS answer_templates (
                template_id TEXT PRIMARY KEY,
                template_name TEXT NOT NULL,
                category TEXT NOT NULL,
                question_pattern TEXT NOT NULL,
                answer_template TEXT NOT NULL,
                variables TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                usage_count INTEGER DEFAULT 0
            )
        """)

        # Create indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_question_hash ON answers (question_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON answers (category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_approval_status ON answers (approval_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_answer_versions ON answer_versions (answer_id, version)")

        conn.commit()
        conn.close()

        logger.info("Database schema initialized")

    def _generate_question_hash(self, question_text: str) -> str:
        """Generate hash for question text (for matching similar questions)"""
        # Normalize question text
        normalized = question_text.lower().strip()
        # Remove punctuation
        normalized = ''.join(c for c in normalized if c.isalnum() or c.isspace())
        # Generate hash
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def store_answer(
        self,
        question_text: str,
        answer_text: str,
        category: str,
        confidence_score: float,
        sources: List[str],
        reasoning: str = "",
        approval_status: ApprovalStatus = ApprovalStatus.PENDING,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> StoredAnswer:
        """
        Store a new answer in the library.

        Args:
            question_text: Question text
            answer_text: Answer text
            category: Answer category
            confidence_score: Confidence score (0-1)
            sources: List of source document titles
            reasoning: Reasoning for the answer
            approval_status: Approval status
            tags: Optional tags
            metadata: Optional metadata

        Returns:
            StoredAnswer object
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Generate IDs and hashes
        answer_id = hashlib.sha256(f"{question_text}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        question_hash = self._generate_question_hash(question_text)

        now = datetime.utcnow().isoformat()

        # Insert answer
        cursor.execute("""
            INSERT INTO answers (
                answer_id, question_text, question_hash, answer_text, category,
                confidence_score, sources, reasoning, approval_status, version,
                created_at, updated_at, tags, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            answer_id,
            question_text,
            question_hash,
            answer_text,
            category,
            confidence_score,
            json.dumps(sources),
            reasoning,
            approval_status.value,
            1,
            now,
            now,
            json.dumps(tags) if tags else None,
            json.dumps(metadata) if metadata else None
        ))

        # Create initial version
        version_id = hashlib.sha256(f"{answer_id}_v1".encode()).hexdigest()[:16]
        cursor.execute("""
            INSERT INTO answer_versions (
                version_id, answer_id, version, answer_text, confidence_score,
                sources, reasoning, created_at, change_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            version_id,
            answer_id,
            1,
            answer_text,
            confidence_score,
            json.dumps(sources),
            reasoning,
            now,
            "Initial version"
        ))

        conn.commit()
        conn.close()

        logger.info(f"Stored answer: {answer_id} (category: {category})")

        return StoredAnswer(
            answer_id=answer_id,
            question_text=question_text,
            question_hash=question_hash,
            answer_text=answer_text,
            category=category,
            confidence_score=confidence_score,
            sources=sources,
            reasoning=reasoning,
            approval_status=approval_status,
            version=1,
            created_at=datetime.fromisoformat(now),
            updated_at=datetime.fromisoformat(now),
            tags=tags,
            metadata=metadata
        )

    def find_similar_answer(
        self,
        question_text: str,
        category: Optional[str] = None,
        approval_status: ApprovalStatus = ApprovalStatus.APPROVED
    ) -> Optional[StoredAnswer]:
        """
        Find similar approved answer for a question.

        Args:
            question_text: Question text to match
            category: Optional category filter
            approval_status: Filter by approval status

        Returns:
            StoredAnswer if found, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        question_hash = self._generate_question_hash(question_text)

        # Try exact hash match first
        query = """
            SELECT * FROM answers
            WHERE question_hash = ? AND approval_status = ?
        """
        params = [question_hash, approval_status.value]

        if category:
            query += " AND category = ?"
            params.append(category)

        query += " ORDER BY updated_at DESC LIMIT 1"

        cursor.execute(query, params)
        row = cursor.fetchone()

        conn.close()

        if row:
            return self._row_to_stored_answer(row)

        return None

    def get_answer(self, answer_id: str) -> Optional[StoredAnswer]:
        """Get answer by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM answers WHERE answer_id = ?", (answer_id,))
        row = cursor.fetchone()

        conn.close()

        if row:
            return self._row_to_stored_answer(row)

        return None

    def update_answer(
        self,
        answer_id: str,
        answer_text: str,
        confidence_score: Optional[float] = None,
        sources: Optional[List[str]] = None,
        reasoning: Optional[str] = None,
        updated_by: Optional[str] = None,
        change_notes: Optional[str] = None
    ) -> StoredAnswer:
        """
        Update an answer and create a new version.

        Args:
            answer_id: Answer ID to update
            answer_text: New answer text
            confidence_score: Optional new confidence score
            sources: Optional new sources
            reasoning: Optional new reasoning
            updated_by: User who made the update
            change_notes: Notes about the change

        Returns:
            Updated StoredAnswer
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get current answer
        cursor.execute("SELECT * FROM answers WHERE answer_id = ?", (answer_id,))
        row = cursor.fetchone()

        if not row:
            conn.close()
            raise ValueError(f"Answer not found: {answer_id}")

        current_version = row[9]  # version column
        new_version = current_version + 1

        # Update values
        new_confidence = confidence_score if confidence_score is not None else row[5]
        new_sources = sources if sources is not None else json.loads(row[6])
        new_reasoning = reasoning if reasoning is not None else row[7]

        now = datetime.utcnow().isoformat()

        # Update answer
        cursor.execute("""
            UPDATE answers
            SET answer_text = ?, confidence_score = ?, sources = ?,
                reasoning = ?, version = ?, updated_at = ?
            WHERE answer_id = ?
        """, (
            answer_text,
            new_confidence,
            json.dumps(new_sources),
            new_reasoning,
            new_version,
            now,
            answer_id
        ))

        # Create version record
        version_id = hashlib.sha256(f"{answer_id}_v{new_version}".encode()).hexdigest()[:16]
        cursor.execute("""
            INSERT INTO answer_versions (
                version_id, answer_id, version, answer_text, confidence_score,
                sources, reasoning, created_at, created_by, change_notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            version_id,
            answer_id,
            new_version,
            answer_text,
            new_confidence,
            json.dumps(new_sources),
            new_reasoning,
            now,
            updated_by,
            change_notes
        ))

        conn.commit()
        conn.close()

        logger.info(f"Updated answer {answer_id} to version {new_version}")

        return self.get_answer(answer_id)

    def approve_answer(
        self,
        answer_id: str,
        approved_by: str,
        notes: Optional[str] = None
    ) -> StoredAnswer:
        """
        Approve an answer.

        Args:
            answer_id: Answer ID to approve
            approved_by: User who approved
            notes: Optional approval notes

        Returns:
            Updated StoredAnswer
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        now = datetime.utcnow().isoformat()

        cursor.execute("""
            UPDATE answers
            SET approval_status = ?, approved_by = ?, approved_at = ?, updated_at = ?
            WHERE answer_id = ?
        """, (ApprovalStatus.APPROVED.value, approved_by, now, now, answer_id))

        conn.commit()
        conn.close()

        logger.info(f"Approved answer {answer_id} by {approved_by}")

        return self.get_answer(answer_id)

    def reject_answer(
        self,
        answer_id: str,
        rejected_by: str,
        reason: Optional[str] = None
    ) -> StoredAnswer:
        """Reject an answer"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        now = datetime.utcnow().isoformat()

        cursor.execute("""
            UPDATE answers
            SET approval_status = ?, updated_at = ?
            WHERE answer_id = ?
        """, (ApprovalStatus.REJECTED.value, now, answer_id))

        conn.commit()
        conn.close()

        logger.info(f"Rejected answer {answer_id} by {rejected_by}")

        return self.get_answer(answer_id)

    def get_answer_versions(self, answer_id: str) -> List[AnswerVersion]:
        """Get all versions of an answer"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM answer_versions
            WHERE answer_id = ?
            ORDER BY version DESC
        """, (answer_id,))

        rows = cursor.fetchall()
        conn.close()

        versions = []
        for row in rows:
            versions.append(AnswerVersion(
                version_id=row[0],
                answer_id=row[1],
                version=row[2],
                answer_text=row[3],
                confidence_score=row[4],
                sources=json.loads(row[5]),
                reasoning=row[6],
                created_at=datetime.fromisoformat(row[7]),
                created_by=row[8],
                change_notes=row[9]
            ))

        return versions

    def search_answers(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        approval_status: Optional[ApprovalStatus] = None,
        tags: Optional[List[str]] = None,
        limit: int = 50
    ) -> List[StoredAnswer]:
        """
        Search answers with filters.

        Args:
            query: Text search query
            category: Filter by category
            approval_status: Filter by approval status
            tags: Filter by tags
            limit: Maximum results

        Returns:
            List of StoredAnswer objects
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        sql = "SELECT * FROM answers WHERE 1=1"
        params = []

        if query:
            sql += " AND (question_text LIKE ? OR answer_text LIKE ?)"
            params.extend([f"%{query}%", f"%{query}%"])

        if category:
            sql += " AND category = ?"
            params.append(category)

        if approval_status:
            sql += " AND approval_status = ?"
            params.append(approval_status.value)

        sql += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(sql, params)
        rows = cursor.fetchall()

        conn.close()

        return [self._row_to_stored_answer(row) for row in rows]

    def get_statistics(self) -> Dict[str, Any]:
        """Get library statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}

        # Total answers
        cursor.execute("SELECT COUNT(*) FROM answers")
        stats["total_answers"] = cursor.fetchone()[0]

        # By approval status
        cursor.execute("""
            SELECT approval_status, COUNT(*)
            FROM answers
            GROUP BY approval_status
        """)
        stats["by_status"] = {row[0]: row[1] for row in cursor.fetchall()}

        # By category
        cursor.execute("""
            SELECT category, COUNT(*)
            FROM answers
            GROUP BY category
        """)
        stats["by_category"] = {row[0]: row[1] for row in cursor.fetchall()}

        # Total versions
        cursor.execute("SELECT COUNT(*) FROM answer_versions")
        stats["total_versions"] = cursor.fetchone()[0]

        conn.close()

        return stats

    def _row_to_stored_answer(self, row: Tuple) -> StoredAnswer:
        """Convert database row to StoredAnswer"""
        return StoredAnswer(
            answer_id=row[0],
            question_text=row[1],
            question_hash=row[2],
            answer_text=row[3],
            category=row[4],
            confidence_score=row[5],
            sources=json.loads(row[6]),
            reasoning=row[7],
            approval_status=ApprovalStatus(row[8]),
            version=row[9],
            created_at=datetime.fromisoformat(row[10]),
            updated_at=datetime.fromisoformat(row[11]),
            approved_by=row[12],
            approved_at=datetime.fromisoformat(row[13]) if row[13] else None,
            tags=json.loads(row[14]) if row[14] else None,
            metadata=json.loads(row[15]) if row[15] else None
        )


def get_response_library(db_path: str = "vaulytica_responses.db") -> ResponseLibrary:
    """Get or create response library instance"""
    return ResponseLibrary(db_path=db_path)

