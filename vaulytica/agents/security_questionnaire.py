"""
Security Questionnaire AI Agent

Automates security questionnaire completion using RAG (Retrieval-Augmented Generation)
and organizational knowledge base.

Key Features:
- Document ingestion (PDF, DOCX, XLSX, CSV, MD, TXT)
- Question answering with confidence scoring
- Source citation for audit trail
- Batch questionnaire processing
- Response library for consistency

Version: 1.0.0
Author: Vaulytica Team
"""

import asyncio
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pathlib import Path

from .framework import (
    BaseAgent,
    AgentCapability,
    AgentStatus,
    AgentContext,
    AgentInput,
    AgentOutput
)
from vaulytica.config import VaulyticaConfig, get_config
from vaulytica.logger import get_logger
from vaulytica.document_ingestion import (
    DocumentIngestionModule,
    ExtractedDocument,
    DocumentType as IngestionDocumentType,
    get_document_ingestion_module
)
from vaulytica.agents.document_intelligence import (
    DocumentIntelligence,
    Document,
    DocumentType as IntelligenceDocumentType,
    SearchResult
)
from vaulytica.questionnaire_parser import (
    QuestionnaireParser,
    ParsedQuestionnaire,
    ParsedQuestion,
    get_questionnaire_parser
)
from vaulytica.response_library import (
    ResponseLibrary,
    ApprovalStatus,
    AnswerCategory,
    get_response_library
)

logger = get_logger(__name__)


class QuestionType(str, Enum):
    """Types of questions in questionnaires"""
    YES_NO = "yes_no"
    MULTIPLE_CHOICE = "multiple_choice"
    FREE_TEXT = "free_text"
    NUMERIC = "numeric"
    DATE = "date"
    UNKNOWN = "unknown"


class QuestionnaireStatus(str, Enum):
    """Status of questionnaire processing"""
    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    SUBMITTED = "submitted"


@dataclass
class Question:
    """Question from a questionnaire"""
    question_id: str
    question_text: str
    question_type: QuestionType = QuestionType.UNKNOWN
    category: Optional[str] = None
    required: bool = False
    options: Optional[List[str]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceCitation:
    """Citation for an answer"""
    document_id: str
    document_title: str
    chunk_id: str
    excerpt: str
    relevance_score: float


@dataclass
class Answer:
    """Generated answer to a question"""
    question_id: str
    answer_text: str
    confidence_score: float  # 0.0 - 1.0
    sources: List[SourceCitation] = field(default_factory=list)
    reasoning: str = ""
    requires_review: bool = False
    approved: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    generated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Questionnaire:
    """Complete questionnaire"""
    questionnaire_id: str
    title: str
    vendor_name: Optional[str] = None
    questions: List[Question] = field(default_factory=list)
    answers: Dict[str, Answer] = field(default_factory=dict)  # question_id -> Answer
    status: QuestionnaireStatus = QuestionnaireStatus.DRAFT
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class SecurityQuestionnaireAgent(BaseAgent):
    """
    Security Questionnaire AI Agent

    Automates security questionnaire completion by:
    1. Ingesting organizational documents (policies, SOPs, etc.)
    2. Building knowledge base with RAG
    3. Answering questions with confidence scoring
    4. Providing source citations for audit trail
    5. Flagging low-confidence answers for review
    """

    def __init__(self, config: Optional[VaulyticaConfig] = None):
        super().__init__(
            agent_name="SecurityQuestionnaireAgent",
            agent_version="1.0.0",
            capabilities=[
                AgentCapability.COMPLIANCE,
                AgentCapability.THREAT_ANALYSIS
            ],
            config=config or get_config()
        )

        # Initialize document ingestion
        self.ingestion_module = get_document_ingestion_module()

        # Initialize document intelligence (RAG)
        self.document_intelligence = DocumentIntelligence(
            chunk_size=getattr(config, 'questionnaire_chunk_size', 500),
            chunk_overlap=getattr(config, 'questionnaire_chunk_overlap', 50)
        )

        # Initialize questionnaire parser
        self.questionnaire_parser = get_questionnaire_parser()

        # Initialize response library
        db_path = getattr(config, 'response_library_db_path', 'vaulytica_responses.db')
        self.response_library = get_response_library(db_path=db_path)
        self.use_response_library = getattr(config, 'use_response_library', True)

        # Configuration
        self.confidence_threshold = getattr(config, 'questionnaire_confidence_threshold', 0.7)
        self.max_sources = getattr(config, 'questionnaire_max_sources', 5)

        # Storage
        self.documents: Dict[str, ExtractedDocument] = {}
        self.questionnaires: Dict[str, Questionnaire] = {}

        # Statistics
        self.statistics = {
            "documents_ingested": 0,
            "questions_answered": 0,
            "questionnaires_processed": 0,
            "high_confidence_answers": 0,
            "low_confidence_answers": 0,
            "total_processing_time": 0.0
        }

        logger.info(f"SecurityQuestionnaireAgent initialized (v{self.agent_version})")

    async def execute(self, input_data: AgentInput) -> AgentOutput:
        """Execute questionnaire agent task"""
        start_time = time.time()

        try:
            self._update_status(AgentStatus.RUNNING)

            # Validate input
            await self.validate_input(input_data)

            task = input_data.task.lower()

            # Route to appropriate handler
            if "ingest" in task or "upload" in task:
                output = await self._ingest_document_task(input_data, start_time)
            elif "answer question" in task or "single question" in task:
                output = await self._answer_single_question_task(input_data, start_time)
            elif "process questionnaire" in task or "batch" in task:
                output = await self._process_questionnaire_task(input_data, start_time)
            else:
                # Default: answer single question
                output = await self._answer_single_question_task(input_data, start_time)

            self._update_status(AgentStatus.COMPLETED)
            logger.info(f"Questionnaire task completed in {output.execution_time:.2f}s")

            return output

        except Exception as e:
            self._update_status(AgentStatus.FAILED)
            logger.error(f"Questionnaire task failed: {e}")

            return AgentOutput(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                status=AgentStatus.FAILED,
                results={},
                confidence=0.0,
                reasoning=[f"Task failed: {str(e)}"],
                data_sources_used=[],
                recommendations=[],
                next_actions=["Review error logs", "Retry with valid input"],
                audit_trail=[],
                execution_time=time.time() - start_time,
                error=str(e)
            )

    async def validate_input(self, input_data: AgentInput) -> bool:
        """Validate input data"""
        if not input_data.task:
            raise ValueError("Task is required")
        return True

    async def ingest_document(
        self,
        file_path: str,
        document_type: IngestionDocumentType = IngestionDocumentType.OTHER,
        title: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> ExtractedDocument:
        """
        Ingest a document into the knowledge base.

        Args:
            file_path: Path to the document file
            document_type: Type of document
            title: Optional title
            tags: Optional tags for categorization

        Returns:
            ExtractedDocument with extracted content
        """
        logger.info(f"Ingesting document: {file_path}")

        # Extract content
        extracted_doc = await self.ingestion_module.ingest_file(
            file_path=file_path,
            document_type=document_type,
            title=title,
            tags=tags
        )

        # Store document
        self.documents[extracted_doc.document_id] = extracted_doc

        # Add to document intelligence (RAG)
        doc = Document(
            document_id=extracted_doc.document_id,
            document_type=self._map_document_type(document_type),
            title=extracted_doc.title,
            content=extracted_doc.content,
            metadata=extracted_doc.metadata,
            tags=extracted_doc.tags
        )
        self.document_intelligence.add_document(doc)

        self.statistics["documents_ingested"] += 1

        logger.info(f"Document ingested: {extracted_doc.title} ({extracted_doc.word_count} words)")
        return extracted_doc

    async def answer_question(
        self,
        question_text: str,
        question_type: QuestionType = QuestionType.FREE_TEXT,
        category: Optional[str] = None,
        use_library: bool = True
    ) -> Answer:
        """
        Answer a single question using the knowledge base.

        First checks response library for approved answers, then generates new answer if needed.

        Args:
            question_text: The question to answer
            question_type: Type of question
            category: Optional category for filtering
            use_library: Whether to check response library first

        Returns:
            Answer with confidence score and sources
        """
        logger.info(f"Answering question: {question_text[:100]}...")

        # Check response library first
        if use_library and self.use_response_library:
            stored_answer = self.response_library.find_similar_answer(
                question_text=question_text,
                category=category,
                approval_status=ApprovalStatus.APPROVED
            )

            if stored_answer:
                logger.info(f"Found approved answer in library (v{stored_answer.version})")
                return Answer(
                    question_id=self._generate_question_id(question_text),
                    answer_text=stored_answer.answer_text,
                    confidence_score=stored_answer.confidence_score,
                    sources=[
                        SourceCitation(
                            document_id="",
                            document_title=source,
                            chunk_id="",
                            excerpt="",
                            relevance_score=1.0
                        ) for source in stored_answer.sources
                    ],
                    reasoning=f"Reused approved answer (v{stored_answer.version}): {stored_answer.reasoning}",
                    requires_review=False,
                    metadata={"from_library": True, "answer_id": stored_answer.answer_id}
                )

        # Search for relevant documents
        search_results = self.document_intelligence.search(
            query=question_text,
            max_results=self.max_sources
        )

        if not search_results:
            logger.warning("No relevant documents found")
            return Answer(
                question_id=self._generate_question_id(question_text),
                answer_text="Unable to answer - no relevant information found in knowledge base.",
                confidence_score=0.0,
                sources=[],
                reasoning="No relevant documents found in knowledge base",
                requires_review=True
            )

        # Generate answer using Claude
        answer_text, reasoning = await self._generate_answer_with_llm(
            question_text=question_text,
            search_results=search_results,
            question_type=question_type
        )

        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(search_results, answer_text)

        # Create source citations
        sources = [
            SourceCitation(
                document_id=result.document_id,
                document_title=result.title,
                chunk_id=result.matched_chunks[0] if result.matched_chunks else "",
                excerpt=result.content[:200],
                relevance_score=result.relevance_score
            )
            for result in search_results[:self.max_sources]
        ]

        # Create answer
        answer = Answer(
            question_id=self._generate_question_id(question_text),
            answer_text=answer_text,
            confidence_score=confidence_score,
            sources=sources,
            reasoning=reasoning,
            requires_review=confidence_score < self.confidence_threshold
        )

        self.statistics["questions_answered"] += 1
        if confidence_score >= self.confidence_threshold:
            self.statistics["high_confidence_answers"] += 1
        else:
            self.statistics["low_confidence_answers"] += 1

        # Auto-save high-confidence answers to library
        if self.use_response_library and confidence_score >= self.confidence_threshold:
            try:
                self.response_library.store_answer(
                    question_text=question_text,
                    answer_text=answer_text,
                    category=category or "other",
                    confidence_score=confidence_score,
                    sources=[s.document_title for s in sources],
                    reasoning=reasoning,
                    approval_status=ApprovalStatus.PENDING
                )
                logger.info("Answer saved to response library (pending approval)")
            except Exception as e:
                logger.warning(f"Failed to save answer to library: {e}")

        logger.info(f"Answer generated (confidence: {confidence_score:.2%})")
        return answer

    def save_answer_to_library(
        self,
        question_text: str,
        answer: Answer,
        category: str,
        approval_status: ApprovalStatus = ApprovalStatus.PENDING
    ) -> str:
        """
        Manually save an answer to the response library.

        Args:
            question_text: Question text
            answer: Answer object
            category: Answer category
            approval_status: Initial approval status

        Returns:
            Answer ID
        """
        stored = self.response_library.store_answer(
            question_text=question_text,
            answer_text=answer.answer_text,
            category=category,
            confidence_score=answer.confidence_score,
            sources=[s.document_title for s in answer.sources],
            reasoning=answer.reasoning,
            approval_status=approval_status
        )

        logger.info(f"Answer saved to library: {stored.answer_id}")
        return stored.answer_id

    def approve_library_answer(
        self,
        answer_id: str,
        approved_by: str
    ) -> None:
        """
        Approve an answer in the response library.

        Args:
            answer_id: Answer ID to approve
            approved_by: User who approved
        """
        self.response_library.approve_answer(
            answer_id=answer_id,
            approved_by=approved_by
        )
        logger.info(f"Answer approved: {answer_id}")

    def get_library_statistics(self) -> Dict[str, Any]:
        """Get response library statistics"""
        return self.response_library.get_statistics()

    async def _generate_answer_with_llm(
        self,
        question_text: str,
        search_results: List[SearchResult],
        question_type: QuestionType
    ) -> tuple[str, str]:
        """Generate answer using Claude LLM"""
        # Build context from search results
        context_parts = []
        for i, result in enumerate(search_results[:5], 1):
            context_parts.append(f"[Source {i}: {result.title}]\n{result.content[:500]}")

        context = "\n\n".join(context_parts)

        # Build prompt
        prompt = f"""You are a security expert helping to complete a security questionnaire.

Question: {question_text}

Relevant information from our knowledge base:
{context}

Based on the information provided, answer the question accurately and concisely.
If the question type is yes/no, provide a clear yes or no answer followed by explanation.
If information is insufficient, state that clearly.

Provide your answer in this format:
ANSWER: [your answer here]
REASONING: [brief explanation of how you arrived at this answer]"""

        try:
            # Call Claude API
            import anthropic

            client = anthropic.Anthropic(api_key=self.config.anthropic_api_key)

            message = client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text

            # Parse response
            answer_match = re.search(r'ANSWER:\s*(.+?)(?=REASONING:|$)', response_text, re.DOTALL)
            reasoning_match = re.search(r'REASONING:\s*(.+)', response_text, re.DOTALL)

            answer = answer_match.group(1).strip() if answer_match else response_text
            reasoning = reasoning_match.group(1).strip() if reasoning_match else "Generated from knowledge base"

            return answer, reasoning

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            # Fallback: use first search result
            if search_results:
                return search_results[0].content[:500], "Fallback: using top search result"
            return "Unable to generate answer", f"Error: {str(e)}"

    def _calculate_confidence_score(
        self,
        search_results: List[SearchResult],
        answer_text: str
    ) -> float:
        """Calculate confidence score for an answer"""
        if not search_results:
            return 0.0

        # Base score on top result relevance
        top_relevance = search_results[0].relevance_score

        # Boost if multiple high-relevance results
        high_relevance_count = sum(1 for r in search_results if r.relevance_score > 0.7)
        boost = min(high_relevance_count * 0.1, 0.3)

        # Penalize very short answers (likely insufficient info)
        if len(answer_text) < 50:
            penalty = 0.2
        else:
            penalty = 0.0

        confidence = min(top_relevance + boost - penalty, 1.0)
        return max(confidence, 0.0)

    def _map_document_type(self, ingestion_type: IngestionDocumentType) -> IntelligenceDocumentType:
        """Map ingestion document type to intelligence document type"""
        mapping = {
            IngestionDocumentType.SECURITY_POLICY: IntelligenceDocumentType.SECURITY_POLICY,
            IngestionDocumentType.SOP: IntelligenceDocumentType.SOP,
            IngestionDocumentType.COMPLIANCE_DOC: IntelligenceDocumentType.COMPLIANCE_DOC,
            IngestionDocumentType.QUESTIONNAIRE: IntelligenceDocumentType.HISTORICAL_INCIDENT,
            IngestionDocumentType.RUNBOOK: IntelligenceDocumentType.RUNBOOK,
        }
        return mapping.get(ingestion_type, IntelligenceDocumentType.SECURITY_POLICY)

    def _generate_question_id(self, question_text: str) -> str:
        """Generate unique question ID"""
        import hashlib
        return hashlib.sha256(question_text.encode()).hexdigest()[:16]

    async def _ingest_document_task(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Handle document ingestion task"""
        context = input_data.context
        file_path = context.data_sources.get("file_path")
        document_type = context.data_sources.get("document_type", "other")

        extracted_doc = await self.ingest_document(
            file_path=file_path,
            document_type=IngestionDocumentType(document_type)
        )

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={"document": extracted_doc.__dict__},
            confidence=1.0,
            reasoning=["Document successfully ingested"],
            data_sources_used=[file_path],
            recommendations=[],
            next_actions=["Answer questions using this document"],
            audit_trail=[],
            execution_time=time.time() - start_time
        )

    async def _answer_single_question_task(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Handle single question answering task"""
        context = input_data.context
        question_text = context.data_sources.get("question")

        answer = await self.answer_question(question_text)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={"answer": answer.__dict__},
            confidence=answer.confidence_score,
            reasoning=[answer.reasoning],
            data_sources_used=[s.document_title for s in answer.sources],
            recommendations=["Review answer" if answer.requires_review else "Answer approved"],
            next_actions=[],
            audit_trail=[],
            execution_time=time.time() - start_time
        )

    async def process_questionnaire(
        self,
        file_path: str,
        title: Optional[str] = None,
        vendor_name: Optional[str] = None,
        sheet_name: Optional[str] = None
    ) -> Questionnaire:
        """
        Process a complete questionnaire from CSV or Excel file.

        Args:
            file_path: Path to questionnaire file (CSV or Excel)
            title: Optional questionnaire title
            vendor_name: Optional vendor name
            sheet_name: Optional sheet name (for Excel files)

        Returns:
            Questionnaire with all questions answered
        """
        logger.info(f"Processing questionnaire: {file_path}")

        # Parse questionnaire
        file_ext = Path(file_path).suffix.lower()
        if file_ext == '.csv':
            parsed = await self.questionnaire_parser.parse_csv(
                file_path=file_path,
                title=title,
                vendor_name=vendor_name
            )
        elif file_ext in ['.xlsx', '.xls']:
            parsed = await self.questionnaire_parser.parse_excel(
                file_path=file_path,
                sheet_name=sheet_name,
                title=title,
                vendor_name=vendor_name
            )
        else:
            raise ValueError(f"Unsupported file format: {file_ext}")

        logger.info(f"Parsed {len(parsed.questions)} questions")

        # Create questionnaire
        questionnaire = Questionnaire(
            questionnaire_id=parsed.questionnaire_id,
            title=parsed.title,
            vendor_name=parsed.vendor_name,
            questions=[],
            answers={},
            status=QuestionnaireStatus.IN_PROGRESS,
            metadata=parsed.metadata
        )

        # Answer each question
        for parsed_question in parsed.questions:
            logger.info(f"Answering question {parsed_question.question_number}: {parsed_question.question_text[:50]}...")

            # Convert ParsedQuestion to Question
            question = Question(
                question_id=parsed_question.question_id,
                question_text=parsed_question.question_text,
                question_type=QuestionType(parsed_question.question_type.value),
                category=parsed_question.category,
                required=parsed_question.required,
                options=parsed_question.options,
                metadata=parsed_question.metadata
            )
            questionnaire.questions.append(question)

            # Answer question
            try:
                answer = await self.answer_question(
                    question_text=parsed_question.question_text,
                    question_type=QuestionType(parsed_question.question_type.value),
                    category=parsed_question.category
                )
                questionnaire.answers[question.question_id] = answer
            except Exception as e:
                logger.error(f"Failed to answer question {parsed_question.question_number}: {e}")
                # Create error answer
                questionnaire.answers[question.question_id] = Answer(
                    question_id=question.question_id,
                    answer_text=f"Error: {str(e)}",
                    confidence_score=0.0,
                    sources=[],
                    reasoning=f"Failed to generate answer: {str(e)}",
                    requires_review=True
                )

        # Update status
        questionnaire.status = QuestionnaireStatus.IN_REVIEW
        questionnaire.completed_at = datetime.utcnow()

        # Store questionnaire
        self.questionnaires[questionnaire.questionnaire_id] = questionnaire
        self.statistics["questionnaires_processed"] += 1

        logger.info(f"Questionnaire processing complete: {len(questionnaire.answers)} answers generated")
        return questionnaire

    async def export_questionnaire_to_csv(
        self,
        questionnaire_id: str,
        output_path: str
    ) -> str:
        """
        Export questionnaire answers to CSV file.

        Args:
            questionnaire_id: ID of questionnaire to export
            output_path: Path to output CSV file

        Returns:
            Path to exported file
        """
        try:
            import pandas as pd

            questionnaire = self.questionnaires.get(questionnaire_id)
            if not questionnaire:
                raise ValueError(f"Questionnaire not found: {questionnaire_id}")

            logger.info(f"Exporting questionnaire to CSV: {output_path}")

            # Build export data
            export_data = []
            for question in questionnaire.questions:
                answer = questionnaire.answers.get(question.question_id)

                row = {
                    "Question Number": question.metadata.get("question_number", ""),
                    "Category": question.category or "",
                    "Question": question.question_text,
                    "Answer": answer.answer_text if answer else "",
                    "Confidence": f"{answer.confidence_score:.2%}" if answer else "",
                    "Requires Review": "Yes" if (answer and answer.requires_review) else "No",
                    "Sources": ", ".join([s.document_title for s in answer.sources]) if answer else ""
                }
                export_data.append(row)

            # Create DataFrame and export
            df = pd.DataFrame(export_data)
            df.to_csv(output_path, index=False)

            logger.info(f"Exported {len(export_data)} answers to {output_path}")
            return output_path

        except ImportError:
            logger.error("pandas not installed. Install with: pip install pandas")
            raise
        except Exception as e:
            logger.error(f"Export failed: {e}")
            raise

    async def export_questionnaire_to_excel(
        self,
        questionnaire_id: str,
        output_path: str
    ) -> str:
        """
        Export questionnaire answers to Excel file with formatting.

        Args:
            questionnaire_id: ID of questionnaire to export
            output_path: Path to output Excel file

        Returns:
            Path to exported file
        """
        try:

            questionnaire = self.questionnaires.get(questionnaire_id)
            if not questionnaire:
                raise ValueError(f"Questionnaire not found: {questionnaire_id}")

            logger.info(f"Exporting questionnaire to Excel: {output_path}")

            # Build export data
            export_data = []
            for question in questionnaire.questions:
                answer = questionnaire.answers.get(question.question_id)

                row = {
                    "Question Number": question.metadata.get("question_number", ""),
                    "Category": question.category or "",
                    "Question": question.question_text,
                    "Answer": answer.answer_text if answer else "",
                    "Confidence": answer.confidence_score if answer else 0.0,
                    "Requires Review": "Yes" if (answer and answer.requires_review) else "No",
                    "Sources": ", ".join([s.document_title for s in answer.sources]) if answer else "",
                    "Reasoning": answer.reasoning if answer else ""
                }
                export_data.append(row)

            # Create DataFrame and export
            df = pd.DataFrame(export_data)

            # Export with formatting
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Questionnaire', index=False)

                # Get workbook and worksheet
                workbook = writer.book
                worksheet = writer.sheets['Questionnaire']

                # Auto-adjust column widths
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except (TypeError, AttributeError):
                            # Skip cells with invalid values
                            continue
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width

            logger.info(f"Exported {len(export_data)} answers to {output_path}")
            return output_path

        except ImportError:
            logger.error("pandas/openpyxl not installed. Install with: pip install pandas openpyxl")
            raise
        except Exception as e:
            logger.error(f"Export failed: {e}")
            raise

    async def _process_questionnaire_task(
        self,
        input_data: AgentInput,
        start_time: float
    ) -> AgentOutput:
        """Handle batch questionnaire processing task"""
        context = input_data.context
        file_path = context.data_sources.get("file_path")
        title = context.data_sources.get("title")
        vendor_name = context.data_sources.get("vendor_name")

        questionnaire = await self.process_questionnaire(
            file_path=file_path,
            title=title,
            vendor_name=vendor_name
        )

        # Calculate statistics
        total_questions = len(questionnaire.questions)
        answered_questions = len(questionnaire.answers)
        high_confidence = sum(1 for a in questionnaire.answers.values() if a.confidence_score >= self.confidence_threshold)
        low_confidence = sum(1 for a in questionnaire.answers.values() if a.confidence_score < self.confidence_threshold)

        return AgentOutput(
            agent_id=self.agent_id,
            agent_name=self.agent_name,
            status=AgentStatus.COMPLETED,
            results={
                "questionnaire_id": questionnaire.questionnaire_id,
                "title": questionnaire.title,
                "total_questions": total_questions,
                "answered_questions": answered_questions,
                "high_confidence_answers": high_confidence,
                "low_confidence_answers": low_confidence,
                "completion_rate": f"{(answered_questions / total_questions * 100):.1f}%"
            },
            confidence=high_confidence / total_questions if total_questions > 0 else 0.0,
            reasoning=[f"Processed {total_questions} questions with {high_confidence} high-confidence answers"],
            data_sources_used=[file_path],
            recommendations=[
                f"Review {low_confidence} low-confidence answers",
                "Export to CSV/Excel for review",
                "Approve high-confidence answers"
            ],
            next_actions=[
                "Review flagged answers",
                "Export questionnaire",
                "Submit to vendor"
            ],
            audit_trail=[],
            execution_time=time.time() - start_time
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get agent statistics"""
        return self.statistics.copy()


# Singleton instance
_security_questionnaire_agent: Optional[SecurityQuestionnaireAgent] = None


def get_security_questionnaire_agent(config: Optional[VaulyticaConfig] = None) -> SecurityQuestionnaireAgent:
    """Get singleton instance of SecurityQuestionnaireAgent"""
    global _security_questionnaire_agent
    if _security_questionnaire_agent is None:
        _security_questionnaire_agent = SecurityQuestionnaireAgent(config)
    return _security_questionnaire_agent

