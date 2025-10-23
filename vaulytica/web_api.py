"""
Vaulytica Web API

FastAPI-based web interface for Security Questionnaire Agent.

Features:
- Document upload and management
- Questionnaire processing
- Answer review and approval
- Response library management
- Analytics dashboard

Version: 1.0.0
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Form
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from pathlib import Path
import logging
import asyncio
from datetime import datetime
import tempfile
import os

from vaulytica.config import VaulyticaConfig, get_config
from vaulytica.agents import SecurityQuestionnaireAgent
from vaulytica.document_ingestion import DocumentType
from vaulytica.response_library import ApprovalStatus, AnswerCategory
from vaulytica.models import QuestionType

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Vaulytica Security Questionnaire API",
    description="AI-powered security questionnaire automation",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Global agent instance
agent: Optional[SecurityQuestionnaireAgent] = None


# Pydantic models for API
class DocumentUploadResponse(BaseModel):
    document_id: str
    title: str
    word_count: int
    status: str


class QuestionRequest(BaseModel):
    question_text: str
    question_type: str = "free_text"
    category: Optional[str] = None


class AnswerResponse(BaseModel):
    question_id: str
    answer_text: str
    confidence_score: float
    sources: List[Dict[str, Any]]
    reasoning: str
    requires_review: bool
    from_library: bool = False


class QuestionnaireProcessRequest(BaseModel):
    title: str
    vendor_name: Optional[str] = None


class QuestionnaireStatusResponse(BaseModel):
    questionnaire_id: str
    title: str
    vendor_name: Optional[str]
    total_questions: int
    answered_questions: int
    high_confidence_answers: int
    low_confidence_answers: int
    status: str


class ApprovalRequest(BaseModel):
    answer_id: str
    approved_by: str
    notes: Optional[str] = None


class LibrarySearchRequest(BaseModel):
    query: Optional[str] = None
    category: Optional[str] = None
    approval_status: Optional[str] = None
    limit: int = 50


# Startup and shutdown
@app.on_event("startup")
async def startup_event():
    """Initialize agent on startup"""
    global agent
    config = get_config()
    agent = SecurityQuestionnaireAgent(config)
    logger.info("Vaulytica Web API started")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Vaulytica Web API shutting down")


# Root endpoint - serve web UI
@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve web UI"""
    index_path = Path(__file__).parent / "static" / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text())
    return HTMLResponse(content="<h1>Vaulytica API</h1><p>Web UI not found. API is running at /api</p>")


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "agent": agent.agent_name if agent else None,
        "version": agent.agent_version if agent else None
    }


# Document management endpoints
@app.post("/api/documents/upload", response_model=DocumentUploadResponse)
async def upload_document(
    file: UploadFile = File(...),
    document_type: str = Form("other"),
    title: Optional[str] = Form(None),
    tags: Optional[str] = Form(None)
):
    """
    Upload a document to the knowledge base.

    Supported formats: PDF, DOCX, TXT, MD, CSV, XLSX
    """
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    try:
        # Save uploaded file temporarily
        suffix = Path(file.filename).suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name

        # Parse tags
        tag_list = [t.strip() for t in tags.split(",")] if tags else None

        # Ingest document
        doc_type = DocumentType(document_type) if document_type else DocumentType.OTHER
        extracted_doc = await agent.ingest_document(
            file_path=tmp_path,
            document_type=doc_type,
            title=title or file.filename,
            tags=tag_list
        )

        # Cleanup temp file
        os.unlink(tmp_path)

        return DocumentUploadResponse(
            document_id=extracted_doc.document_id,
            title=extracted_doc.title,
            word_count=extracted_doc.word_count,
            status="success"
        )

    except Exception as e:
        logger.error(f"Document upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/documents")
async def list_documents():
    """List all uploaded documents"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    documents = []
    for doc_id, doc in agent.documents.items():
        documents.append({
            "document_id": doc.document_id,
            "title": doc.title,
            "document_type": doc.document_type.value,
            "word_count": doc.word_count,
            "created_at": doc.created_at.isoformat(),
            "tags": doc.tags
        })

    return {"documents": documents, "total": len(documents)}


# Question answering endpoints
@app.post("/api/questions/answer", response_model=AnswerResponse)
async def answer_question(request: QuestionRequest):
    """Answer a single question"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    try:
        question_type = QuestionType(request.question_type)
        answer = await agent.answer_question(
            question_text=request.question_text,
            question_type=question_type,
            category=request.category
        )

        return AnswerResponse(
            question_id=answer.question_id,
            answer_text=answer.answer_text,
            confidence_score=answer.confidence_score,
            sources=[{
                "document_title": s.document_title,
                "excerpt": s.excerpt,
                "relevance_score": s.relevance_score
            } for s in answer.sources],
            reasoning=answer.reasoning,
            requires_review=answer.requires_review,
            from_library=answer.metadata.get("from_library", False) if answer.metadata else False
        )

    except Exception as e:
        logger.error(f"Question answering failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Questionnaire processing endpoints
@app.post("/api/questionnaires/upload")
async def upload_questionnaire(
    file: UploadFile = File(...),
    title: str = Form(...),
    vendor_name: Optional[str] = Form(None),
    background_tasks: BackgroundTasks = None
):
    """
    Upload and process a questionnaire (CSV or Excel).

    Processing happens in the background.
    """
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    try:
        # Save uploaded file temporarily
        suffix = Path(file.filename).suffix
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
            content = await file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name

        # Process questionnaire
        questionnaire = await agent.process_questionnaire(
            file_path=tmp_path,
            title=title,
            vendor_name=vendor_name
        )

        # Cleanup temp file
        os.unlink(tmp_path)

        # Calculate statistics
        high_confidence = sum(
            1 for a in questionnaire.answers.values()
            if a.confidence_score >= agent.confidence_threshold
        )
        low_confidence = len(questionnaire.answers) - high_confidence

        return {
            "questionnaire_id": questionnaire.questionnaire_id,
            "title": questionnaire.title,
            "vendor_name": questionnaire.vendor_name,
            "total_questions": len(questionnaire.questions),
            "answered_questions": len(questionnaire.answers),
            "high_confidence_answers": high_confidence,
            "low_confidence_answers": low_confidence,
            "status": questionnaire.status.value
        }

    except Exception as e:
        logger.error(f"Questionnaire upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/questionnaires/{questionnaire_id}")
async def get_questionnaire(questionnaire_id: str):
    """Get questionnaire details"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    questionnaire = agent.questionnaires.get(questionnaire_id)
    if not questionnaire:
        raise HTTPException(status_code=404, detail="Questionnaire not found")

    # Build response
    questions_with_answers = []
    for question in questionnaire.questions:
        answer = questionnaire.answers.get(question.question_id)
        questions_with_answers.append({
            "question_id": question.question_id,
            "question_text": question.question_text,
            "question_type": question.question_type.value,
            "category": question.category,
            "answer": {
                "answer_text": answer.answer_text if answer else None,
                "confidence_score": answer.confidence_score if answer else None,
                "requires_review": answer.requires_review if answer else None,
                "sources": [s.document_title for s in answer.sources] if answer else []
            } if answer else None
        })

    return {
        "questionnaire_id": questionnaire.questionnaire_id,
        "title": questionnaire.title,
        "vendor_name": questionnaire.vendor_name,
        "status": questionnaire.status.value,
        "questions": questions_with_answers,
        "created_at": questionnaire.created_at.isoformat() if questionnaire.created_at else None,
        "completed_at": questionnaire.completed_at.isoformat() if questionnaire.completed_at else None
    }


@app.get("/api/questionnaires/{questionnaire_id}/export/csv")
async def export_questionnaire_csv(questionnaire_id: str):
    """Export questionnaire to CSV"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    questionnaire = agent.questionnaires.get(questionnaire_id)
    if not questionnaire:
        raise HTTPException(status_code=404, detail="Questionnaire not found")

    try:
        # Export to temp file
        output_path = f"/tmp/questionnaire_{questionnaire_id}.csv"
        await agent.export_questionnaire_to_csv(
            questionnaire_id=questionnaire_id,
            output_path=output_path
        )

        return FileResponse(
            path=output_path,
            filename=f"{questionnaire.title.replace(' ', '_')}.csv",
            media_type="text/csv"
        )

    except Exception as e:
        logger.error(f"CSV export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/questionnaires/{questionnaire_id}/export/excel")
async def export_questionnaire_excel(questionnaire_id: str):
    """Export questionnaire to Excel"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    questionnaire = agent.questionnaires.get(questionnaire_id)
    if not questionnaire:
        raise HTTPException(status_code=404, detail="Questionnaire not found")

    try:
        # Export to temp file
        output_path = f"/tmp/questionnaire_{questionnaire_id}.xlsx"
        await agent.export_questionnaire_to_excel(
            questionnaire_id=questionnaire_id,
            output_path=output_path
        )

        return FileResponse(
            path=output_path,
            filename=f"{questionnaire.title.replace(' ', '_')}.xlsx",
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )

    except Exception as e:
        logger.error(f"Excel export failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Response library endpoints
@app.post("/api/library/approve")
async def approve_answer(request: ApprovalRequest):
    """Approve an answer in the response library"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    try:
        agent.approve_library_answer(
            answer_id=request.answer_id,
            approved_by=request.approved_by
        )

        return {"status": "success", "message": "Answer approved"}

    except Exception as e:
        logger.error(f"Answer approval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/library/search")
async def search_library(request: LibrarySearchRequest):
    """Search response library"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    try:
        approval_status = ApprovalStatus(request.approval_status) if request.approval_status else None

        answers = agent.response_library.search_answers(
            query=request.query,
            category=request.category,
            approval_status=approval_status,
            limit=request.limit
        )

        results = []
        for answer in answers:
            results.append({
                "answer_id": answer.answer_id,
                "question_text": answer.question_text,
                "answer_text": answer.answer_text,
                "category": answer.category,
                "confidence_score": answer.confidence_score,
                "approval_status": answer.approval_status.value,
                "version": answer.version,
                "sources": answer.sources,
                "created_at": answer.created_at.isoformat(),
                "updated_at": answer.updated_at.isoformat(),
                "approved_by": answer.approved_by,
                "approved_at": answer.approved_at.isoformat() if answer.approved_at else None
            })

        return {"answers": results, "total": len(results)}

    except Exception as e:
        logger.error(f"Library search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/library/statistics")
async def get_library_statistics():
    """Get response library statistics"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    try:
        stats = agent.get_library_statistics()
        return stats

    except Exception as e:
        logger.error(f"Statistics retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/library/answers/{answer_id}/versions")
async def get_answer_versions(answer_id: str):
    """Get version history for an answer"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    try:
        versions = agent.response_library.get_answer_versions(answer_id)

        results = []
        for version in versions:
            results.append({
                "version_id": version.version_id,
                "version": version.version,
                "answer_text": version.answer_text,
                "confidence_score": version.confidence_score,
                "sources": version.sources,
                "reasoning": version.reasoning,
                "created_at": version.created_at.isoformat(),
                "created_by": version.created_by,
                "change_notes": version.change_notes
            })

        return {"versions": results, "total": len(results)}

    except Exception as e:
        logger.error(f"Version history retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Statistics and analytics endpoints
@app.get("/api/statistics")
async def get_statistics():
    """Get agent statistics"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    stats = agent.get_statistics()
    library_stats = agent.get_library_statistics()

    return {
        "agent": stats,
        "library": library_stats,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/questionnaires")
async def list_questionnaires():
    """List all questionnaires"""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized")

    questionnaires = []
    for q_id, q in agent.questionnaires.items():
        high_confidence = sum(
            1 for a in q.answers.values()
            if a.confidence_score >= agent.confidence_threshold
        )

        questionnaires.append({
            "questionnaire_id": q.questionnaire_id,
            "title": q.title,
            "vendor_name": q.vendor_name,
            "status": q.status.value,
            "total_questions": len(q.questions),
            "answered_questions": len(q.answers),
            "high_confidence_answers": high_confidence,
            "low_confidence_answers": len(q.answers) - high_confidence,
            "created_at": q.created_at.isoformat() if q.created_at else None,
            "completed_at": q.completed_at.isoformat() if q.completed_at else None
        })

    return {"questionnaires": questionnaires, "total": len(questionnaires)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

