"""
End-to-End Test for Security Questionnaire Agent

Tests complete workflow: document ingestion → questionnaire processing → export

Version: 1.0.0
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.config import VaulyticaConfig
from vaulytica.agents import SecurityQuestionnaireAgent
from vaulytica.document_ingestion import DocumentType


def create_test_config():
    """Create test configuration"""
    return VaulyticaConfig(
        anthropic_api_key="test-key",
        questionnaire_confidence_threshold=0.7,
        questionnaire_chunk_size=500,
        questionnaire_chunk_overlap=50,
        questionnaire_max_sources=5
    )


async def test_complete_workflow():
    """Test complete questionnaire workflow"""
    print("\n" + "="*80)
    print("END-TO-END TEST: Complete Questionnaire Workflow")
    print("="*80)
    
    # Step 1: Initialize agent
    print("\n📋 Step 1: Initialize Agent")
    config = create_test_config()
    agent = SecurityQuestionnaireAgent(config)
    print(f"   ✅ Agent initialized: {agent.agent_name} v{agent.agent_version}")
    
    # Step 2: Create test documents
    print("\n📋 Step 2: Create Test Documents")
    
    # Security Policy
    policy_file = Path("/tmp/security_policy.txt")
    policy_content = """
    INFORMATION SECURITY POLICY
    
    1. INCIDENT RESPONSE
    Our organization maintains a formal incident response plan that is:
    - Documented and approved by executive leadership
    - Tested quarterly through tabletop exercises
    - Reviewed and updated annually
    - Supported by a 24/7 security operations center (SOC)
    
    The incident response team includes:
    - Chief Information Security Officer (CISO)
    - Security Operations Manager
    - Incident Response Analysts
    - Legal and Compliance representatives
    
    2. ACCESS CONTROL
    We implement comprehensive access controls:
    - Role-based access control (RBAC) for all systems
    - Multi-factor authentication (MFA) required for all users
    - Access reviews conducted quarterly
    - Privileged access management (PAM) for administrative accounts
    - Just-in-time (JIT) access for temporary elevated privileges
    
    3. DATA PROTECTION
    All data is protected using industry-standard encryption:
    - Data at rest: AES-256 encryption
    - Data in transit: TLS 1.3
    - Encryption key management: AWS KMS with automatic rotation
    - Database encryption: Transparent Data Encryption (TDE)
    
    4. COMPLIANCE
    Our organization maintains the following certifications:
    - SOC 2 Type II (last audit: January 2024)
    - ISO 27001:2013 (certified since 2020)
    - PCI DSS Level 1 (for payment processing)
    - HIPAA compliance (for healthcare data)
    
    5. BUSINESS CONTINUITY
    We maintain robust business continuity capabilities:
    - Daily automated backups to geographically distributed locations
    - Recovery Time Objective (RTO): 4 hours
    - Recovery Point Objective (RPO): 1 hour
    - Disaster recovery plan tested semi-annually
    - Hot standby infrastructure in multiple regions
    
    6. SECURITY AWARENESS
    All employees receive security awareness training:
    - Initial training during onboarding
    - Quarterly refresher training
    - Annual phishing simulation exercises
    - Specialized training for developers and administrators
    """
    policy_file.write_text(policy_content)
    print(f"   ✅ Created security policy document")
    
    # Step 3: Ingest documents
    print("\n📋 Step 3: Ingest Documents into Knowledge Base")
    
    extracted_doc = await agent.ingest_document(
        file_path=str(policy_file),
        document_type=DocumentType.SECURITY_POLICY,
        title="Information Security Policy",
        tags=["policy", "security", "compliance"]
    )
    
    print(f"   ✅ Ingested: {extracted_doc.title}")
    print(f"      Word Count: {extracted_doc.word_count}")
    print(f"      Document ID: {extracted_doc.document_id}")
    
    # Step 4: Create test questionnaire
    print("\n📋 Step 4: Create Test Questionnaire")
    
    questionnaire_file = Path("/tmp/vendor_questionnaire.csv")
    questionnaire_content = """Category,Question,Answer
Incident Response,Does your organization have a formal incident response plan?,
Incident Response,How often is your incident response plan tested?,
Incident Response,Do you have a 24/7 security operations center?,
Access Control,Do you implement role-based access control (RBAC)?,
Access Control,Is multi-factor authentication required for all users?,
Access Control,How often are access rights reviewed?,
Data Protection,What encryption standard do you use for data at rest?,
Data Protection,Is all data in transit encrypted?,
Data Protection,How do you manage encryption keys?,
Compliance,Are you SOC 2 Type II certified?,
Compliance,When was your last SOC 2 audit?,
Compliance,Are you ISO 27001 certified?,
Business Continuity,Do you perform daily backups?,
Business Continuity,What is your Recovery Time Objective (RTO)?,
Business Continuity,What is your Recovery Point Objective (RPO)?,
Training,Do all employees receive security awareness training?,
Training,How often is security training provided?,
"""
    questionnaire_file.write_text(questionnaire_content)
    print(f"   ✅ Created questionnaire with 17 questions")
    
    # Step 5: Process questionnaire
    print("\n📋 Step 5: Process Questionnaire (Answer All Questions)")
    print("   This may take a moment...")
    
    try:
        questionnaire = await agent.process_questionnaire(
            file_path=str(questionnaire_file),
            title="Vendor Security Assessment",
            vendor_name="Acme Corp"
        )
        
        print(f"\n   ✅ Questionnaire processed successfully")
        print(f"      Questionnaire ID: {questionnaire.questionnaire_id}")
        print(f"      Title: {questionnaire.title}")
        print(f"      Vendor: {questionnaire.vendor_name}")
        print(f"      Total Questions: {len(questionnaire.questions)}")
        print(f"      Answers Generated: {len(questionnaire.answers)}")
        print(f"      Status: {questionnaire.status.value}")
        
        # Step 6: Analyze results
        print("\n📋 Step 6: Analyze Results")
        
        high_confidence = sum(1 for a in questionnaire.answers.values() 
                            if a.confidence_score >= agent.confidence_threshold)
        low_confidence = sum(1 for a in questionnaire.answers.values() 
                           if a.confidence_score < agent.confidence_threshold)
        
        print(f"   High Confidence Answers: {high_confidence}")
        print(f"   Low Confidence Answers: {low_confidence}")
        print(f"   Completion Rate: {len(questionnaire.answers) / len(questionnaire.questions) * 100:.1f}%")
        
        # Show sample answers
        print("\n   📝 Sample Answers:")
        for i, (question, answer) in enumerate(list(questionnaire.answers.items())[:3], 1):
            q = next(q for q in questionnaire.questions if q.question_id == question)
            print(f"\n   Q{i}: {q.question_text}")
            print(f"   A{i}: {answer.answer_text[:100]}...")
            print(f"   Confidence: {answer.confidence_score:.2%}")
            print(f"   Sources: {len(answer.sources)}")
        
        # Step 7: Export to CSV
        print("\n📋 Step 7: Export to CSV")
        
        csv_output = Path("/tmp/questionnaire_export.csv")
        await agent.export_questionnaire_to_csv(
            questionnaire_id=questionnaire.questionnaire_id,
            output_path=str(csv_output)
        )
        
        print(f"   ✅ Exported to: {csv_output}")
        print(f"      File size: {csv_output.stat().st_size} bytes")
        
        # Step 8: Export to Excel
        print("\n📋 Step 8: Export to Excel")
        
        try:
            excel_output = Path("/tmp/questionnaire_export.xlsx")
            await agent.export_questionnaire_to_excel(
                questionnaire_id=questionnaire.questionnaire_id,
                output_path=str(excel_output)
            )
            
            print(f"   ✅ Exported to: {excel_output}")
            print(f"      File size: {excel_output.stat().st_size} bytes")
        except ImportError:
            print("   ⚠️  openpyxl not installed - skipping Excel export")
        
        # Step 9: Show statistics
        print("\n📋 Step 9: Agent Statistics")
        
        stats = agent.get_statistics()
        print(f"   Documents Ingested: {stats['documents_ingested']}")
        print(f"   Questions Answered: {stats['questions_answered']}")
        print(f"   Questionnaires Processed: {stats['questionnaires_processed']}")
        print(f"   High Confidence Answers: {stats['high_confidence_answers']}")
        print(f"   Low Confidence Answers: {stats['low_confidence_answers']}")
        
        if stats['questions_answered'] > 0:
            success_rate = stats['high_confidence_answers'] / stats['questions_answered'] * 100
            print(f"   Success Rate: {success_rate:.1f}%")
        
        # Cleanup
        print("\n📋 Step 10: Cleanup")
        policy_file.unlink()
        questionnaire_file.unlink()
        if csv_output.exists():
            csv_output.unlink()
        if excel_output.exists():
            excel_output.unlink()
        print("   ✅ Test files cleaned up")
        
        return True
        
    except Exception as e:
        print(f"\n   ❌ Error during questionnaire processing: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_multiple_documents():
    """Test with multiple knowledge base documents"""
    print("\n" + "="*80)
    print("TEST: Multiple Knowledge Base Documents")
    print("="*80)
    
    config = create_test_config()
    agent = SecurityQuestionnaireAgent(config)
    
    # Create multiple documents
    docs = [
        ("security_policy.txt", "Security Policy", """
        Our security policy requires MFA for all users.
        We perform quarterly access reviews.
        """),
        ("incident_response.md", "Incident Response SOP", """
        # Incident Response
        
        Our IR plan is tested quarterly.
        We have a 24/7 SOC.
        """),
        ("compliance.txt", "Compliance Documentation", """
        SOC 2 Type II certified (last audit: Jan 2024)
        ISO 27001 certified since 2020
        """)
    ]
    
    print("\n📋 Ingesting multiple documents:")
    for filename, title, content in docs:
        file_path = Path(f"/tmp/{filename}")
        file_path.write_text(content)
        
        await agent.ingest_document(
            file_path=str(file_path),
            document_type=DocumentType.SECURITY_POLICY,
            title=title
        )
        
        print(f"   ✅ {title}")
        file_path.unlink()
    
    stats = agent.get_statistics()
    print(f"\n   Total Documents: {stats['documents_ingested']}")
    print("   ✅ Multiple document ingestion successful")


async def main():
    """Run all end-to-end tests"""
    print("\n" + "="*80)
    print("SECURITY QUESTIONNAIRE AGENT - END-TO-END TEST SUITE")
    print("="*80)
    
    try:
        # Test 1: Complete workflow
        success = await test_complete_workflow()
        
        if not success:
            print("\n❌ Complete workflow test failed")
            return 1
        
        # Test 2: Multiple documents
        await test_multiple_documents()
        
        print("\n" + "="*80)
        print("✅ ALL END-TO-END TESTS PASSED")
        print("="*80)
        print("\n💡 Note: This test uses mock data and does not call the actual Claude API.")
        print("   For production testing, configure a valid ANTHROPIC_API_KEY.")
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

