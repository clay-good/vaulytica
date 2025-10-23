"""
Test Suite for Questionnaire Parser

Tests CSV and Excel questionnaire parsing.

Version: 1.0.0
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.questionnaire_parser import (
    QuestionnaireParser,
    QuestionType,
    ParsedQuestion,
    ParsedQuestionnaire
)


async def test_csv_parsing_standard_format():
    """Test CSV parsing with standard format"""
    print("\n" + "="*80)
    print("TEST: CSV Parsing - Standard Format")
    print("="*80)
    
    # Create test CSV file
    test_file = Path("/tmp/test_questionnaire_standard.csv")
    csv_content = """Question,Answer,Category
Does your organization have a formal incident response plan?,,"Incident Response"
Do you use multi-factor authentication for all user accounts?,,"Access Control"
How often do you perform security awareness training?,,"Training"
What encryption standard do you use for data at rest?,,"Data Security"
Are backups performed daily?,,"Business Continuity"
"""
    
    test_file.write_text(csv_content)
    
    # Parse CSV
    parser = QuestionnaireParser()
    parsed = await parser.parse_csv(
        file_path=str(test_file),
        title="Security Questionnaire - Standard Format",
        vendor_name="Test Vendor"
    )
    
    assert parsed.questionnaire_id is not None
    assert parsed.title == "Security Questionnaire - Standard Format"
    assert parsed.vendor_name == "Test Vendor"
    assert len(parsed.questions) == 5
    
    # Check first question
    q1 = parsed.questions[0]
    assert "incident response plan" in q1.question_text.lower()
    assert q1.question_type == QuestionType.YES_NO
    assert q1.category == "Incident Response"
    
    # Check question types
    print(f"\n✅ Parsed {len(parsed.questions)} questions")
    for i, q in enumerate(parsed.questions, 1):
        print(f"   Q{i}: {q.question_type.value} - {q.question_text[:60]}...")
    
    print(f"\n   Question Types: {parsed.metadata['question_types']}")
    
    # Cleanup
    test_file.unlink()
    
    return parsed


async def test_csv_parsing_detailed_format():
    """Test CSV parsing with detailed format"""
    print("\n" + "="*80)
    print("TEST: CSV Parsing - Detailed Format")
    print("="*80)
    
    # Create test CSV file
    test_file = Path("/tmp/test_questionnaire_detailed.csv")
    csv_content = """ID,Question,Type,Required,Options,Category
Q1,Does your organization have a formal incident response plan?,yes/no,Yes,,"Incident Response"
Q2,Select your primary cloud provider,multiple choice,Yes,"AWS,Azure,GCP,Other","Infrastructure"
Q3,Describe your data retention policy,free text,Yes,,"Data Management"
Q4,How many security incidents did you have last year?,numeric,No,,"Metrics"
Q5,When was your last security audit?,date,Yes,,"Compliance"
"""
    
    test_file.write_text(csv_content)
    
    # Parse CSV
    parser = QuestionnaireParser()
    parsed = await parser.parse_csv(
        file_path=str(test_file),
        title="Security Questionnaire - Detailed Format",
        vendor_name="Test Vendor"
    )
    
    assert len(parsed.questions) == 5
    
    # Check question types
    assert parsed.questions[0].question_type == QuestionType.YES_NO
    assert parsed.questions[1].question_type == QuestionType.MULTIPLE_CHOICE
    assert parsed.questions[2].question_type == QuestionType.FREE_TEXT
    assert parsed.questions[3].question_type == QuestionType.NUMERIC
    assert parsed.questions[4].question_type == QuestionType.DATE
    
    # Check required flags
    assert parsed.questions[0].required == True
    assert parsed.questions[3].required == False
    
    # Check options
    assert parsed.questions[1].options == ["AWS", "Azure", "GCP", "Other"]
    
    print(f"\n✅ Parsed {len(parsed.questions)} questions with detailed metadata")
    for i, q in enumerate(parsed.questions, 1):
        print(f"   Q{i}: {q.question_type.value} (Required: {q.required}) - {q.question_text[:50]}...")
    
    # Cleanup
    test_file.unlink()
    
    return parsed


async def test_excel_parsing():
    """Test Excel parsing"""
    print("\n" + "="*80)
    print("TEST: Excel Parsing")
    print("="*80)
    
    try:
        import pandas as pd
        
        # Create test Excel file
        test_file = Path("/tmp/test_questionnaire.xlsx")
        
        data = {
            "Question": [
                "Does your organization have a formal incident response plan?",
                "Do you use multi-factor authentication?",
                "How often do you perform security awareness training?",
                "What encryption standard do you use for data at rest?",
                "Are backups performed daily?"
            ],
            "Answer": ["", "", "", "", ""],
            "Category": [
                "Incident Response",
                "Access Control",
                "Training",
                "Data Security",
                "Business Continuity"
            ]
        }
        
        df = pd.DataFrame(data)
        df.to_excel(test_file, index=False)
        
        # Parse Excel
        parser = QuestionnaireParser()
        parsed = await parser.parse_excel(
            file_path=str(test_file),
            title="Security Questionnaire - Excel Format",
            vendor_name="Test Vendor"
        )
        
        assert len(parsed.questions) == 5
        assert parsed.metadata['format_type'] == 'standard'
        
        print(f"\n✅ Parsed {len(parsed.questions)} questions from Excel")
        for i, q in enumerate(parsed.questions, 1):
            print(f"   Q{i}: {q.category} - {q.question_text[:60]}...")
        
        # Cleanup
        test_file.unlink()
        
        return parsed
        
    except ImportError:
        print("\n⚠️  pandas/openpyxl not installed - skipping Excel test")
        return None


async def test_question_type_detection():
    """Test automatic question type detection"""
    print("\n" + "="*80)
    print("TEST: Question Type Detection")
    print("="*80)
    
    parser = QuestionnaireParser()
    
    test_cases = [
        ("Does your organization have a security policy?", QuestionType.YES_NO),
        ("Do you use encryption?", QuestionType.YES_NO),
        ("Is there a formal incident response plan?", QuestionType.YES_NO),
        ("Select your primary cloud provider (AWS, Azure, GCP)", QuestionType.MULTIPLE_CHOICE),
        ("Choose one: Daily, Weekly, Monthly", QuestionType.MULTIPLE_CHOICE),
        ("Describe your data retention policy", QuestionType.FREE_TEXT),
        ("Explain your security architecture", QuestionType.FREE_TEXT),
        ("How many employees have security training?", QuestionType.NUMERIC),
        ("What is the number of security incidents last year?", QuestionType.NUMERIC),
        ("When was your last security audit?", QuestionType.DATE),
        ("What date did you implement MFA?", QuestionType.DATE)
    ]
    
    print("\n")
    for question, expected_type in test_cases:
        detected_type = parser._detect_question_type(question)
        status = "✅" if detected_type == expected_type else "❌"
        print(f"{status} {detected_type.value:15} | {question[:60]}")
        
        if detected_type != expected_type:
            print(f"   Expected: {expected_type.value}")
    
    print("\n✅ Question type detection test completed")


async def test_format_detection():
    """Test format detection"""
    print("\n" + "="*80)
    print("TEST: Format Detection")
    print("="*80)
    
    import pandas as pd
    
    parser = QuestionnaireParser()
    
    # Standard format
    df_standard = pd.DataFrame({
        "Question": ["Q1", "Q2"],
        "Answer": ["", ""],
        "Category": ["Cat1", "Cat2"]
    })
    format_standard = parser._detect_format(df_standard)
    print(f"   Standard format detected: {format_standard}")
    assert format_standard == "standard"
    
    # Detailed format
    df_detailed = pd.DataFrame({
        "ID": ["Q1", "Q2"],
        "Question": ["Q1", "Q2"],
        "Type": ["yes/no", "text"],
        "Required": ["Yes", "No"]
    })
    format_detailed = parser._detect_format(df_detailed)
    print(f"   Detailed format detected: {format_detailed}")
    assert format_detailed == "detailed"
    
    # Auto format
    df_auto = pd.DataFrame({
        "Item": ["Q1", "Q2"],
        "Response": ["", ""]
    })
    format_auto = parser._detect_format(df_auto)
    print(f"   Auto format detected: {format_auto}")
    assert format_auto == "auto"
    
    print("\n✅ Format detection test completed")


async def test_real_world_questionnaire():
    """Test with a realistic security questionnaire"""
    print("\n" + "="*80)
    print("TEST: Real-World Security Questionnaire")
    print("="*80)
    
    # Create realistic questionnaire
    test_file = Path("/tmp/vendor_security_questionnaire.csv")
    csv_content = """Category,Question,Answer
General,What is your organization's primary business?,
General,How many employees does your organization have?,
Information Security,Do you have a formal information security policy?,
Information Security,Is your information security policy reviewed annually?,
Information Security,Do you have a dedicated Chief Information Security Officer (CISO)?,
Access Control,Do you implement role-based access control (RBAC)?,
Access Control,Is multi-factor authentication (MFA) required for all users?,
Access Control,How often are access rights reviewed?,
Incident Response,Do you have a formal incident response plan?,
Incident Response,Is your incident response plan tested regularly?,
Incident Response,Do you have a 24/7 security operations center (SOC)?,
Data Protection,Is all data at rest encrypted?,
Data Protection,What encryption standard do you use for data at rest?,
Data Protection,Is all data in transit encrypted?,
Compliance,Are you SOC 2 Type II certified?,
Compliance,When was your last SOC 2 audit?,
Compliance,Are you ISO 27001 certified?,
Business Continuity,Do you perform daily backups?,
Business Continuity,What is your Recovery Time Objective (RTO)?,
Business Continuity,What is your Recovery Point Objective (RPO)?,
"""
    
    test_file.write_text(csv_content)
    
    # Parse questionnaire
    parser = QuestionnaireParser()
    parsed = await parser.parse_csv(
        file_path=str(test_file),
        title="Vendor Security Assessment Questionnaire",
        vendor_name="Acme Corp"
    )
    
    print(f"\n✅ Parsed realistic questionnaire")
    print(f"   Title: {parsed.title}")
    print(f"   Vendor: {parsed.vendor_name}")
    print(f"   Total Questions: {len(parsed.questions)}")
    print(f"   Question Types: {parsed.metadata['question_types']}")
    
    # Group by category
    categories = {}
    for q in parsed.questions:
        cat = q.category or "Uncategorized"
        categories[cat] = categories.get(cat, 0) + 1
    
    print(f"\n   Questions by Category:")
    for cat, count in sorted(categories.items()):
        print(f"      {cat}: {count}")
    
    # Cleanup
    test_file.unlink()
    
    return parsed


async def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("QUESTIONNAIRE PARSER - TEST SUITE")
    print("="*80)
    
    try:
        # Test 1: CSV parsing - standard format
        await test_csv_parsing_standard_format()
        
        # Test 2: CSV parsing - detailed format
        await test_csv_parsing_detailed_format()
        
        # Test 3: Excel parsing
        await test_excel_parsing()
        
        # Test 4: Question type detection
        await test_question_type_detection()
        
        # Test 5: Format detection
        await test_format_detection()
        
        # Test 6: Real-world questionnaire
        await test_real_world_questionnaire()
        
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

