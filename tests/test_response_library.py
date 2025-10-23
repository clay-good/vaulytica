"""
Test Suite for Response Library

Tests answer storage, versioning, approval workflow, and search.

Version: 1.0.0
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime
import os

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.response_library import (
    ResponseLibrary,
    ApprovalStatus,
    AnswerCategory,
    StoredAnswer,
    AnswerVersion
)


def test_database_initialization():
    """Test database initialization"""
    print("\n" + "="*80)
    print("TEST: Database Initialization")
    print("="*80)
    
    # Create test database
    db_path = "/tmp/test_response_library.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    library = ResponseLibrary(db_path=db_path)
    
    assert os.path.exists(db_path)
    print("   ✅ Database created successfully")
    
    # Check statistics
    stats = library.get_statistics()
    assert stats["total_answers"] == 0
    assert stats["total_versions"] == 0
    print("   ✅ Database initialized with empty tables")
    
    # Cleanup
    os.remove(db_path)
    
    return library


def test_store_answer():
    """Test storing answers"""
    print("\n" + "="*80)
    print("TEST: Store Answer")
    print("="*80)
    
    db_path = "/tmp/test_response_library.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    library = ResponseLibrary(db_path=db_path)
    
    # Store answer
    stored = library.store_answer(
        question_text="Does your organization have a formal incident response plan?",
        answer_text="Yes, we maintain a formal incident response plan that is documented, tested quarterly, and reviewed annually.",
        category=AnswerCategory.INCIDENT_RESPONSE.value,
        confidence_score=0.95,
        sources=["Information Security Policy", "Incident Response SOP"],
        reasoning="Found explicit documentation in security policy",
        approval_status=ApprovalStatus.PENDING,
        tags=["incident-response", "policy"]
    )
    
    assert stored.answer_id is not None
    assert stored.version == 1
    assert stored.approval_status == ApprovalStatus.PENDING
    print(f"   ✅ Answer stored: {stored.answer_id}")
    print(f"      Category: {stored.category}")
    print(f"      Confidence: {stored.confidence_score:.2%}")
    print(f"      Version: {stored.version}")
    
    # Verify storage
    retrieved = library.get_answer(stored.answer_id)
    assert retrieved is not None
    assert retrieved.answer_text == stored.answer_text
    print("   ✅ Answer retrieved successfully")
    
    # Cleanup
    os.remove(db_path)
    
    return stored


def test_find_similar_answer():
    """Test finding similar answers"""
    print("\n" + "="*80)
    print("TEST: Find Similar Answer")
    print("="*80)
    
    db_path = "/tmp/test_response_library.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    library = ResponseLibrary(db_path=db_path)
    
    # Store and approve answer
    stored = library.store_answer(
        question_text="Does your organization have a formal incident response plan?",
        answer_text="Yes, we have a formal IR plan.",
        category=AnswerCategory.INCIDENT_RESPONSE.value,
        confidence_score=0.95,
        sources=["Security Policy"],
        reasoning="Found in policy"
    )
    
    library.approve_answer(stored.answer_id, approved_by="user@example.com")
    
    # Try to find with similar question
    similar_questions = [
        "Does your organization have a formal incident response plan?",  # Exact match
        "Do you have a formal incident response plan?",  # Similar
        "Does your company have a formal incident response plan?",  # Similar
    ]
    
    for question in similar_questions:
        found = library.find_similar_answer(
            question_text=question,
            approval_status=ApprovalStatus.APPROVED
        )
        
        if found:
            print(f"   ✅ Found match for: {question[:60]}...")
            print(f"      Answer: {found.answer_text[:60]}...")
        else:
            print(f"   ❌ No match for: {question[:60]}...")
    
    # Cleanup
    os.remove(db_path)


def test_answer_versioning():
    """Test answer versioning"""
    print("\n" + "="*80)
    print("TEST: Answer Versioning")
    print("="*80)
    
    db_path = "/tmp/test_response_library.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    library = ResponseLibrary(db_path=db_path)
    
    # Store initial answer
    stored = library.store_answer(
        question_text="What encryption standard do you use for data at rest?",
        answer_text="We use AES-128 encryption.",
        category=AnswerCategory.DATA_PROTECTION.value,
        confidence_score=0.85,
        sources=["Security Policy"],
        reasoning="Initial answer"
    )
    
    print(f"   ✅ Initial answer stored (v{stored.version})")
    
    # Update answer
    updated = library.update_answer(
        answer_id=stored.answer_id,
        answer_text="We use AES-256 encryption for all data at rest.",
        confidence_score=0.95,
        updated_by="user@example.com",
        change_notes="Updated to reflect current encryption standard"
    )
    
    assert updated.version == 2
    assert updated.answer_text != stored.answer_text
    print(f"   ✅ Answer updated to v{updated.version}")
    
    # Get version history
    versions = library.get_answer_versions(stored.answer_id)
    assert len(versions) == 2
    print(f"   ✅ Version history retrieved: {len(versions)} versions")
    
    for version in versions:
        print(f"      v{version.version}: {version.answer_text[:50]}...")
    
    # Cleanup
    os.remove(db_path)


def test_approval_workflow():
    """Test approval workflow"""
    print("\n" + "="*80)
    print("TEST: Approval Workflow")
    print("="*80)
    
    db_path = "/tmp/test_response_library.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    library = ResponseLibrary(db_path=db_path)
    
    # Store answer (pending)
    stored = library.store_answer(
        question_text="Do you use multi-factor authentication?",
        answer_text="Yes, MFA is required for all users.",
        category=AnswerCategory.ACCESS_CONTROL.value,
        confidence_score=0.92,
        sources=["Access Control Policy"],
        reasoning="Found in policy",
        approval_status=ApprovalStatus.PENDING
    )
    
    assert stored.approval_status == ApprovalStatus.PENDING
    print(f"   ✅ Answer created with status: {stored.approval_status.value}")
    
    # Approve answer
    approved = library.approve_answer(
        answer_id=stored.answer_id,
        approved_by="user@example.com"
    )
    
    assert approved.approval_status == ApprovalStatus.APPROVED
    assert approved.approved_by == "user@example.com"
    assert approved.approved_at is not None
    print(f"   ✅ Answer approved by: {approved.approved_by}")
    
    # Try to find approved answer
    found = library.find_similar_answer(
        question_text="Do you use multi-factor authentication?",
        approval_status=ApprovalStatus.APPROVED
    )
    
    assert found is not None
    print("   ✅ Approved answer can be found and reused")
    
    # Cleanup
    os.remove(db_path)


def test_search_answers():
    """Test searching answers"""
    print("\n" + "="*80)
    print("TEST: Search Answers")
    print("="*80)
    
    db_path = "/tmp/test_response_library.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    library = ResponseLibrary(db_path=db_path)
    
    # Store multiple answers
    test_answers = [
        ("Does your organization have a formal incident response plan?", AnswerCategory.INCIDENT_RESPONSE, "Yes, we have an IR plan."),
        ("Do you use multi-factor authentication?", AnswerCategory.ACCESS_CONTROL, "Yes, MFA is required."),
        ("What encryption standard do you use?", AnswerCategory.DATA_PROTECTION, "We use AES-256."),
        ("Are you SOC 2 certified?", AnswerCategory.COMPLIANCE, "Yes, SOC 2 Type II."),
        ("Do you perform daily backups?", AnswerCategory.BUSINESS_CONTINUITY, "Yes, daily backups."),
    ]
    
    for question, category, answer in test_answers:
        library.store_answer(
            question_text=question,
            answer_text=answer,
            category=category.value,
            confidence_score=0.9,
            sources=["Policy"],
            reasoning="Test",
            approval_status=ApprovalStatus.APPROVED
        )
    
    print(f"   ✅ Stored {len(test_answers)} test answers")
    
    # Search by category
    incident_answers = library.search_answers(
        category=AnswerCategory.INCIDENT_RESPONSE.value,
        approval_status=ApprovalStatus.APPROVED
    )
    
    assert len(incident_answers) == 1
    print(f"   ✅ Found {len(incident_answers)} incident response answers")
    
    # Search by query
    encryption_answers = library.search_answers(
        query="encryption",
        approval_status=ApprovalStatus.APPROVED
    )
    
    assert len(encryption_answers) >= 1
    print(f"   ✅ Found {len(encryption_answers)} answers matching 'encryption'")
    
    # Get all approved
    all_approved = library.search_answers(
        approval_status=ApprovalStatus.APPROVED
    )
    
    assert len(all_approved) == len(test_answers)
    print(f"   ✅ Found {len(all_approved)} total approved answers")
    
    # Cleanup
    os.remove(db_path)


def test_statistics():
    """Test statistics"""
    print("\n" + "="*80)
    print("TEST: Statistics")
    print("="*80)
    
    db_path = "/tmp/test_response_library.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    library = ResponseLibrary(db_path=db_path)
    
    # Store answers with different statuses
    for i in range(3):
        library.store_answer(
            question_text=f"Question {i}?",
            answer_text=f"Answer {i}",
            category=AnswerCategory.COMPLIANCE.value,
            confidence_score=0.9,
            sources=["Policy"],
            reasoning="Test",
            approval_status=ApprovalStatus.APPROVED
        )
    
    for i in range(2):
        library.store_answer(
            question_text=f"Pending Question {i}?",
            answer_text=f"Pending Answer {i}",
            category=AnswerCategory.ACCESS_CONTROL.value,
            confidence_score=0.8,
            sources=["Policy"],
            reasoning="Test",
            approval_status=ApprovalStatus.PENDING
        )
    
    # Get statistics
    stats = library.get_statistics()
    
    print(f"\n   Total Answers: {stats['total_answers']}")
    print(f"   By Status:")
    for status, count in stats['by_status'].items():
        print(f"      {status}: {count}")
    print(f"   By Category:")
    for category, count in stats['by_category'].items():
        print(f"      {category}: {count}")
    print(f"   Total Versions: {stats['total_versions']}")
    
    assert stats['total_answers'] == 5
    assert stats['by_status']['approved'] == 3
    assert stats['by_status']['pending'] == 2
    print("\n   ✅ Statistics calculated correctly")
    
    # Cleanup
    os.remove(db_path)


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("RESPONSE LIBRARY - TEST SUITE")
    print("="*80)
    
    try:
        # Test 1: Database initialization
        test_database_initialization()
        
        # Test 2: Store answer
        test_store_answer()
        
        # Test 3: Find similar answer
        test_find_similar_answer()
        
        # Test 4: Answer versioning
        test_answer_versioning()
        
        # Test 5: Approval workflow
        test_approval_workflow()
        
        # Test 6: Search answers
        test_search_answers()
        
        # Test 7: Statistics
        test_statistics()
        
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
    exit_code = main()
    sys.exit(exit_code)

