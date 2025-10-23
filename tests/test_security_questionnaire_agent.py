"""
Test Suite for Security Questionnaire Agent

Tests document ingestion, question answering, and questionnaire processing.

Version: 1.0.0
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.config import VaulyticaConfig
from vaulytica.agents import (
    SecurityQuestionnaireAgent,
    QuestionType,
    QuestionnaireStatus,
    Question,
    Answer
)
from vaulytica.agents.framework import AgentInput, AgentContext
from vaulytica.document_ingestion import (
    DocumentIngestionModule,
    DocumentType,
    ExtractedDocument
)


def create_test_config():
    """Create test configuration"""
    return VaulyticaConfig(
        anthropic_api_key="test-key",
        questionnaire_confidence_threshold=0.7,
        questionnaire_chunk_size=500,
        questionnaire_chunk_overlap=50,
        questionnaire_max_sources=5
    )


def create_test_document(content: str, title: str = "Test Document") -> ExtractedDocument:
    """Create a test document"""
    return ExtractedDocument(
        document_id="test-doc-001",
        file_path="/tmp/test.txt",
        file_name="test.txt",
        file_format="txt",
        document_type=DocumentType.SECURITY_POLICY,
        title=title,
        content=content,
        metadata={},
        tags=["test"],
        word_count=len(content.split()),
        extracted_at=datetime.utcnow()
    )


async def test_agent_initialization():
    """Test agent initialization"""
    print("\n" + "="*80)
    print("TEST: Agent Initialization")
    print("="*80)
    
    config = create_test_config()
    agent = SecurityQuestionnaireAgent(config)
    
    assert agent.agent_name == "SecurityQuestionnaireAgent"
    assert agent.agent_version == "1.0.0"
    assert agent.confidence_threshold == 0.7
    
    print("✅ Agent initialized successfully")
    print(f"   Agent Name: {agent.agent_name}")
    print(f"   Version: {agent.agent_version}")
    print(f"   Confidence Threshold: {agent.confidence_threshold}")
    
    return agent


async def test_document_ingestion_text():
    """Test text document ingestion"""
    print("\n" + "="*80)
    print("TEST: Text Document Ingestion")
    print("="*80)
    
    # Create test text file
    test_file = Path("/tmp/test_security_policy.txt")
    test_content = """
    Information Security Policy
    
    1. Access Control
    Our organization implements role-based access control (RBAC) for all systems.
    Multi-factor authentication (MFA) is required for all user accounts.
    
    2. Incident Response
    We have a formal incident response plan that is tested quarterly.
    Our incident response team is available 24/7.
    
    3. Data Encryption
    All data at rest is encrypted using AES-256.
    All data in transit is encrypted using TLS 1.3.
    
    4. Backup and Recovery
    Daily backups are performed and stored in geographically distributed locations.
    Recovery time objective (RTO) is 4 hours.
    Recovery point objective (RPO) is 1 hour.
    """
    
    test_file.write_text(test_content)
    
    # Test ingestion
    module = DocumentIngestionModule()
    extracted_doc = await module.ingest_file(
        file_path=test_file,
        document_type=DocumentType.SECURITY_POLICY,
        title="Information Security Policy",
        tags=["policy", "security"]
    )
    
    assert extracted_doc.document_id is not None
    assert extracted_doc.file_format.value == "txt"
    assert extracted_doc.word_count > 0
    assert "Access Control" in extracted_doc.content
    
    print("✅ Text document ingested successfully")
    print(f"   Document ID: {extracted_doc.document_id}")
    print(f"   Title: {extracted_doc.title}")
    print(f"   Word Count: {extracted_doc.word_count}")
    print(f"   Tags: {extracted_doc.tags}")
    
    # Cleanup
    test_file.unlink()
    
    return extracted_doc


async def test_document_ingestion_markdown():
    """Test markdown document ingestion"""
    print("\n" + "="*80)
    print("TEST: Markdown Document Ingestion")
    print("="*80)
    
    # Create test markdown file
    test_file = Path("/tmp/test_sop.md")
    test_content = """
# Incident Response SOP

## Overview
This document describes our incident response procedures.

## Phases

### 1. Detection
- Monitor security alerts 24/7
- Use SIEM for correlation
- Automated alerting via PagerDuty

### 2. Containment
- Isolate affected systems
- Preserve evidence
- Document all actions

### 3. Eradication
- Remove malware
- Patch vulnerabilities
- Update security controls

### 4. Recovery
- Restore from clean backups
- Validate system integrity
- Monitor for reinfection

### 5. Post-Mortem
- Document lessons learned
- Update procedures
- Train team members
"""
    
    test_file.write_text(test_content)
    
    # Test ingestion
    module = DocumentIngestionModule()
    extracted_doc = await module.ingest_file(
        file_path=test_file,
        document_type=DocumentType.SOP,
        title="Incident Response SOP",
        tags=["sop", "incident-response"]
    )
    
    assert extracted_doc.document_id is not None
    assert extracted_doc.file_format.value == "md"
    assert "Detection" in extracted_doc.content
    assert "Post-Mortem" in extracted_doc.content
    
    print("✅ Markdown document ingested successfully")
    print(f"   Document ID: {extracted_doc.document_id}")
    print(f"   Title: {extracted_doc.title}")
    print(f"   Headers: {extracted_doc.metadata.get('header_count', 0)}")
    
    # Cleanup
    test_file.unlink()
    
    return extracted_doc


async def test_question_answering():
    """Test question answering with mock data"""
    print("\n" + "="*80)
    print("TEST: Question Answering")
    print("="*80)
    
    config = create_test_config()
    agent = SecurityQuestionnaireAgent(config)
    
    # Add test document to knowledge base
    test_content = """
    Information Security Policy
    
    Access Control:
    - We implement role-based access control (RBAC)
    - Multi-factor authentication (MFA) is required for all users
    - Access reviews are conducted quarterly
    
    Incident Response:
    - We have a formal incident response plan
    - The plan is tested quarterly through tabletop exercises
    - Our incident response team is available 24/7
    - We have a documented escalation process
    
    Data Encryption:
    - All data at rest is encrypted using AES-256
    - All data in transit is encrypted using TLS 1.3
    - Encryption keys are managed using AWS KMS
    """
    
    # Create and add document
    from vaulytica.agents.document_intelligence import Document, DocumentType as IntelDocType
    
    doc = Document(
        document_id="test-policy-001",
        document_type=IntelDocType.SECURITY_POLICY,
        title="Information Security Policy",
        content=test_content,
        tags=["policy", "security"]
    )
    agent.document_intelligence.add_document(doc)
    
    # Test questions
    questions = [
        "Does your organization have a formal incident response plan?",
        "Do you use multi-factor authentication?",
        "How often do you test your incident response plan?",
        "What encryption standard do you use for data at rest?"
    ]
    
    for question in questions:
        print(f"\n📝 Question: {question}")
        
        # Search for relevant info (simulating answer generation)
        search_results = agent.document_intelligence.search(question, max_results=3)
        
        if search_results:
            print(f"   ✅ Found {len(search_results)} relevant sources")
            print(f"   Top Result: {search_results[0].title}")
            print(f"   Relevance: {search_results[0].relevance_score:.2%}")
            print(f"   Excerpt: {search_results[0].content[:150]}...")
        else:
            print(f"   ❌ No relevant sources found")
    
    print("\n✅ Question answering test completed")
    
    return agent


async def test_confidence_scoring():
    """Test confidence score calculation"""
    print("\n" + "="*80)
    print("TEST: Confidence Scoring")
    print("="*80)
    
    config = create_test_config()
    agent = SecurityQuestionnaireAgent(config)
    
    # Test scenarios
    from vaulytica.agents.document_intelligence import SearchResult, DocumentType as IntelDocType
    
    scenarios = [
        {
            "name": "High confidence (high relevance, multiple sources)",
            "results": [
                SearchResult("doc1", IntelDocType.SECURITY_POLICY, "Policy", "content", 0.9, ["chunk1"]),
                SearchResult("doc2", IntelDocType.SOP, "SOP", "content", 0.85, ["chunk2"]),
                SearchResult("doc3", IntelDocType.COMPLIANCE_DOC, "Compliance", "content", 0.8, ["chunk3"])
            ],
            "answer": "Yes, we have a formal incident response plan that is tested quarterly."
        },
        {
            "name": "Medium confidence (medium relevance)",
            "results": [
                SearchResult("doc1", IntelDocType.SECURITY_POLICY, "Policy", "content", 0.6, ["chunk1"])
            ],
            "answer": "We implement security controls."
        },
        {
            "name": "Low confidence (low relevance, short answer)",
            "results": [
                SearchResult("doc1", IntelDocType.SECURITY_POLICY, "Policy", "content", 0.3, ["chunk1"])
            ],
            "answer": "Yes"
        }
    ]
    
    for scenario in scenarios:
        confidence = agent._calculate_confidence_score(scenario["results"], scenario["answer"])
        print(f"\n{scenario['name']}")
        print(f"   Confidence Score: {confidence:.2%}")
        print(f"   Requires Review: {confidence < agent.confidence_threshold}")
    
    print("\n✅ Confidence scoring test completed")


async def test_statistics_tracking():
    """Test statistics tracking"""
    print("\n" + "="*80)
    print("TEST: Statistics Tracking")
    print("="*80)
    
    config = create_test_config()
    agent = SecurityQuestionnaireAgent(config)
    
    # Simulate some operations
    agent.statistics["documents_ingested"] = 5
    agent.statistics["questions_answered"] = 20
    agent.statistics["high_confidence_answers"] = 15
    agent.statistics["low_confidence_answers"] = 5
    
    stats = agent.get_statistics()
    
    print(f"   Documents Ingested: {stats['documents_ingested']}")
    print(f"   Questions Answered: {stats['questions_answered']}")
    print(f"   High Confidence: {stats['high_confidence_answers']}")
    print(f"   Low Confidence: {stats['low_confidence_answers']}")
    print(f"   Success Rate: {stats['high_confidence_answers'] / stats['questions_answered']:.1%}")
    
    print("\n✅ Statistics tracking test completed")


async def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("SECURITY QUESTIONNAIRE AGENT - TEST SUITE")
    print("="*80)
    
    try:
        # Test 1: Agent initialization
        agent = await test_agent_initialization()
        
        # Test 2: Document ingestion (text)
        await test_document_ingestion_text()
        
        # Test 3: Document ingestion (markdown)
        await test_document_ingestion_markdown()
        
        # Test 4: Question answering
        await test_question_answering()
        
        # Test 5: Confidence scoring
        await test_confidence_scoring()
        
        # Test 6: Statistics tracking
        await test_statistics_tracking()
        
        print("\n" + "="*80)
        print("✅ ALL TESTS PASSED")
        print("="*80)
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

