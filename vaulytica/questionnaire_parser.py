"""
Questionnaire Parser Module

Parses security questionnaires from CSV and Excel files.
Supports various questionnaire formats and automatically detects question types.

Version: 1.0.0
Author: Vaulytica Team
"""

import re
import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class QuestionType(str, Enum):
    """Types of questions in questionnaires"""
    YES_NO = "yes_no"
    MULTIPLE_CHOICE = "multiple_choice"
    FREE_TEXT = "free_text"
    NUMERIC = "numeric"
    DATE = "date"
    UNKNOWN = "unknown"


@dataclass
class ParsedQuestion:
    """Parsed question from questionnaire"""
    question_id: str
    question_number: Optional[str]
    question_text: str
    question_type: QuestionType
    category: Optional[str] = None
    subcategory: Optional[str] = None
    required: bool = False
    options: Optional[List[str]] = None
    help_text: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class ParsedQuestionnaire:
    """Parsed questionnaire with all questions"""
    questionnaire_id: str
    title: str
    vendor_name: Optional[str] = None
    description: Optional[str] = None
    questions: List[ParsedQuestion] = None
    metadata: Dict[str, Any] = None
    parsed_at: datetime = None

    def __post_init__(self):
        if self.questions is None:
            self.questions = []
        if self.metadata is None:
            self.metadata = {}
        if self.parsed_at is None:
            self.parsed_at = datetime.utcnow()


class QuestionnaireParser:
    """
    Parser for security questionnaires in CSV and Excel formats.

    Supports various formats:
    - Standard format: Question, Answer, Category
    - Detailed format: ID, Question, Type, Required, Options, Category
    - Vendor formats: Custom columns with auto-detection
    """

    def __init__(self):
        self.yes_no_patterns = [
            r'\b(yes|no)\b',
            r'\b(y/n)\b',
            r'\b(true|false)\b',
            r'\b(do you|does your|is there|are there|have you|has your)\b'
        ]

        self.multiple_choice_indicators = [
            'select one',
            'choose one',
            'pick one',
            'select all',
            'choose all',
            'options:',
            'choices:'
        ]

        logger.info("QuestionnaireParser initialized")

    async def parse_csv(
        self,
        file_path: str,
        title: Optional[str] = None,
        vendor_name: Optional[str] = None
    ) -> ParsedQuestionnaire:
        """
        Parse questionnaire from CSV file.

        Args:
            file_path: Path to CSV file
            title: Optional questionnaire title
            vendor_name: Optional vendor name

        Returns:
            ParsedQuestionnaire with all questions
        """
        try:
            import pandas as pd

            logger.info(f"Parsing CSV questionnaire: {file_path}")

            # Read CSV
            df = pd.read_csv(file_path)

            # Detect format
            format_type = self._detect_format(df)
            logger.info(f"Detected format: {format_type}")

            # Parse based on format
            if format_type == "standard":
                questions = self._parse_standard_format(df)
            elif format_type == "detailed":
                questions = self._parse_detailed_format(df)
            else:
                questions = self._parse_auto_detect(df)

            # Generate questionnaire ID
            questionnaire_id = self._generate_questionnaire_id(file_path, title)

            # Create parsed questionnaire
            parsed = ParsedQuestionnaire(
                questionnaire_id=questionnaire_id,
                title=title or Path(file_path).stem,
                vendor_name=vendor_name,
                questions=questions,
                metadata={
                    "source_file": file_path,
                    "format_type": format_type,
                    "total_questions": len(questions),
                    "question_types": self._count_question_types(questions)
                }
            )

            logger.info(f"Parsed {len(questions)} questions from CSV")
            return parsed

        except ImportError:
            logger.error("pandas not installed. Install with: pip install pandas")
            raise
        except Exception as e:
            logger.error(f"CSV parsing failed: {e}")
            raise

    async def parse_excel(
        self,
        file_path: str,
        sheet_name: Optional[str] = None,
        title: Optional[str] = None,
        vendor_name: Optional[str] = None
    ) -> ParsedQuestionnaire:
        """
        Parse questionnaire from Excel file.

        Args:
            file_path: Path to Excel file
            sheet_name: Optional sheet name (defaults to first sheet)
            title: Optional questionnaire title
            vendor_name: Optional vendor name

        Returns:
            ParsedQuestionnaire with all questions
        """
        try:

            logger.info(f"Parsing Excel questionnaire: {file_path}")

            # Read Excel
            if sheet_name:
                df = pd.read_excel(file_path, sheet_name=sheet_name)
            else:
                df = pd.read_excel(file_path)

            # Detect format
            format_type = self._detect_format(df)
            logger.info(f"Detected format: {format_type}")

            # Parse based on format
            if format_type == "standard":
                questions = self._parse_standard_format(df)
            elif format_type == "detailed":
                questions = self._parse_detailed_format(df)
            else:
                questions = self._parse_auto_detect(df)

            # Generate questionnaire ID
            questionnaire_id = self._generate_questionnaire_id(file_path, title)

            # Create parsed questionnaire
            parsed = ParsedQuestionnaire(
                questionnaire_id=questionnaire_id,
                title=title or Path(file_path).stem,
                vendor_name=vendor_name,
                questions=questions,
                metadata={
                    "source_file": file_path,
                    "sheet_name": sheet_name,
                    "format_type": format_type,
                    "total_questions": len(questions),
                    "question_types": self._count_question_types(questions)
                }
            )

            logger.info(f"Parsed {len(questions)} questions from Excel")
            return parsed

        except ImportError:
            logger.error("pandas/openpyxl not installed. Install with: pip install pandas openpyxl")
            raise
        except Exception as e:
            logger.error(f"Excel parsing failed: {e}")
            raise

    def _detect_format(self, df) -> str:
        """Detect questionnaire format from DataFrame columns"""
        columns = [col.lower() for col in df.columns]

        # Detailed format: has ID, Type, Required, Options
        if any('id' in col for col in columns) and any('type' in col for col in columns):
            return "detailed"

        # Standard format: has Question, Answer, Category
        if any('question' in col for col in columns) and any('answer' in col for col in columns):
            return "standard"

        # Auto-detect
        return "auto"

    def _parse_standard_format(self, df) -> List[ParsedQuestion]:
        """Parse standard format: Question, Answer, Category"""
        questions = []

        # Find column names
        question_col = self._find_column(df, ['question', 'q', 'query'])
        category_col = self._find_column(df, ['category', 'section', 'domain'])

        if not question_col:
            raise ValueError("Could not find question column")

        for idx, row in df.iterrows():
            question_text = str(row[question_col]).strip()

            # Skip empty rows
            if not question_text or question_text.lower() in ['nan', 'none', '']:
                continue

            # Detect question type
            question_type = self._detect_question_type(question_text)

            # Extract category
            category = None
            if category_col:
                category = str(row[category_col]).strip()
                if category.lower() in ['nan', 'none', '']:
                    category = None

            # Create question
            question = ParsedQuestion(
                question_id=self._generate_question_id(question_text),
                question_number=str(idx + 1),
                question_text=question_text,
                question_type=question_type,
                category=category
            )

            questions.append(question)

        return questions

    def _parse_detailed_format(self, df) -> List[ParsedQuestion]:
        """Parse detailed format: ID, Question, Type, Required, Options, Category"""
        questions = []

        # Find column names
        id_col = self._find_column(df, ['id', 'question_id', 'qid'])
        question_col = self._find_column(df, ['question', 'q', 'query'])
        type_col = self._find_column(df, ['type', 'question_type', 'qtype'])
        required_col = self._find_column(df, ['required', 'mandatory'])
        options_col = self._find_column(df, ['options', 'choices'])
        category_col = self._find_column(df, ['category', 'section', 'domain'])

        if not question_col:
            raise ValueError("Could not find question column")

        for idx, row in df.iterrows():
            question_text = str(row[question_col]).strip()

            # Skip empty rows
            if not question_text or question_text.lower() in ['nan', 'none', '']:
                continue

            # Extract question ID
            question_id = None
            if id_col:
                question_id = str(row[id_col]).strip()
            if not question_id or question_id.lower() in ['nan', 'none', '']:
                question_id = self._generate_question_id(question_text)

            # Extract question type
            question_type = QuestionType.UNKNOWN
            if type_col:
                type_str = str(row[type_col]).strip().lower()
                question_type = self._parse_question_type(type_str)
            if question_type == QuestionType.UNKNOWN:
                question_type = self._detect_question_type(question_text)

            # Extract required flag
            required = False
            if required_col:
                required_str = str(row[required_col]).strip().lower()
                required = required_str in ['yes', 'true', '1', 'required', 'mandatory']

            # Extract options
            options = None
            if options_col:
                options_str = str(row[options_col]).strip()
                if options_str and options_str.lower() not in ['nan', 'none', '']:
                    options = [opt.strip() for opt in options_str.split(',')]

            # Extract category
            category = None
            if category_col:
                category = str(row[category_col]).strip()
                if category.lower() in ['nan', 'none', '']:
                    category = None

            # Create question
            question = ParsedQuestion(
                question_id=question_id,
                question_number=str(idx + 1),
                question_text=question_text,
                question_type=question_type,
                category=category,
                required=required,
                options=options
            )

            questions.append(question)

        return questions

    def _parse_auto_detect(self, df) -> List[ParsedQuestion]:
        """Auto-detect format and parse"""
        # Try to find question column
        question_col = self._find_column(df, ['question', 'q', 'query', 'item'])

        if not question_col:
            # Use first column as questions
            question_col = df.columns[0]

        questions = []

        for idx, row in df.iterrows():
            question_text = str(row[question_col]).strip()

            # Skip empty rows
            if not question_text or question_text.lower() in ['nan', 'none', '']:
                continue

            # Detect question type
            question_type = self._detect_question_type(question_text)

            # Create question
            question = ParsedQuestion(
                question_id=self._generate_question_id(question_text),
                question_number=str(idx + 1),
                question_text=question_text,
                question_type=question_type
            )

            questions.append(question)

        return questions

    def _find_column(self, df, possible_names: List[str]) -> Optional[str]:
        """Find column by possible names"""
        columns = df.columns
        for col in columns:
            col_lower = col.lower()
            for name in possible_names:
                if name in col_lower:
                    return col
        return None

    def _detect_question_type(self, question_text: str) -> QuestionType:
        """Detect question type from question text"""
        question_lower = question_text.lower()

        # Check for yes/no patterns
        for pattern in self.yes_no_patterns:
            if re.search(pattern, question_lower):
                return QuestionType.YES_NO

        # Check for multiple choice indicators
        for indicator in self.multiple_choice_indicators:
            if indicator in question_lower:
                return QuestionType.MULTIPLE_CHOICE

        # Check for numeric patterns
        if re.search(r'\b(how many|number of|count|quantity)\b', question_lower):
            return QuestionType.NUMERIC

        # Check for date patterns
        if re.search(r'\b(when|date|year|month)\b', question_lower):
            return QuestionType.DATE

        # Default to free text
        return QuestionType.FREE_TEXT

    def _parse_question_type(self, type_str: str) -> QuestionType:
        """Parse question type from string"""
        type_mapping = {
            'yes/no': QuestionType.YES_NO,
            'yesno': QuestionType.YES_NO,
            'boolean': QuestionType.YES_NO,
            'bool': QuestionType.YES_NO,
            'multiple choice': QuestionType.MULTIPLE_CHOICE,
            'multichoice': QuestionType.MULTIPLE_CHOICE,
            'choice': QuestionType.MULTIPLE_CHOICE,
            'select': QuestionType.MULTIPLE_CHOICE,
            'free text': QuestionType.FREE_TEXT,
            'freetext': QuestionType.FREE_TEXT,
            'text': QuestionType.FREE_TEXT,
            'string': QuestionType.FREE_TEXT,
            'numeric': QuestionType.NUMERIC,
            'number': QuestionType.NUMERIC,
            'integer': QuestionType.NUMERIC,
            'date': QuestionType.DATE,
            'datetime': QuestionType.DATE
        }

        return type_mapping.get(type_str, QuestionType.UNKNOWN)

    def _generate_question_id(self, question_text: str) -> str:
        """Generate unique question ID"""
        return hashlib.sha256(question_text.encode()).hexdigest()[:16]

    def _generate_questionnaire_id(self, file_path: str, title: Optional[str]) -> str:
        """Generate unique questionnaire ID"""
        unique_string = f"{file_path}_{title}_{datetime.utcnow().isoformat()}"
        return hashlib.sha256(unique_string.encode()).hexdigest()[:16]

    def _count_question_types(self, questions: List[ParsedQuestion]) -> Dict[str, int]:
        """Count questions by type"""
        counts = {}
        for question in questions:
            type_name = question.question_type.value
            counts[type_name] = counts.get(type_name, 0) + 1
        return counts


# Singleton instance
_questionnaire_parser: Optional[QuestionnaireParser] = None


def get_questionnaire_parser() -> QuestionnaireParser:
    """Get singleton instance of QuestionnaireParser"""
    global _questionnaire_parser
    if _questionnaire_parser is None:
        _questionnaire_parser = QuestionnaireParser()
    return _questionnaire_parser

