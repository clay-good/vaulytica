"""Output formatting and report generation."""

import json
from pathlib import Path
from typing import Optional, Dict, Any
from vaulytica.models import AnalysisResult, SecurityEvent


class OutputFormatter:
    """Format analysis results for file outputs only (JSON, Markdown, HTML)."""

    def __init__(self):
        pass

    def save_json(self, event: SecurityEvent, result: AnalysisResult, output_path: Path) -> None:
        """Save analysis as JSON."""

        output_data = {
            "event": json.loads(event.model_dump_json()),
            "analysis": json.loads(result.model_dump_json()),
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)

    def save_markdown(self, event: SecurityEvent, result: AnalysisResult, output_path: Path) -> None:
        """Save analysis as Markdown."""

        md_content = """# Security Analysis Report

**Event ID:** {result.event_id}
**Analyzed:** {result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
**Source:** {event.source_system}
**Severity:** {event.severity.value}

## 5W1H Quick Summary

| Question | Answer |
|----------|--------|
| **WHO** | {result.five_w1h.who} |
| **WHAT** | {result.five_w1h.what} |
| **WHEN** | {result.five_w1h.when} |
| **WHERE** | {result.five_w1h.where} |
| **WHY** | {result.five_w1h.why} |
| **HOW** | {result.five_w1h.how} |

## Executive Summary

{result.executive_summary}

## Risk Assessment

- **Risk Score:** {result.risk_score:.1f}/10
- **Confidence:** {result.confidence*100:.0f}%

## Attack Chain

{chr(10).join([f"{i}. {step}" for i, step in enumerate(result.attack_chain, 1)])}

## MITRE ATT&CK Techniques

| ID | Technique | Tactic | Confidence |
|----|-----------|--------|------------|
{chr(10).join([f"| {mt.technique_id} | {mt.technique_name} | {mt.tactic} | {mt.confidence*100:.0f}% |" for mt in result.mitre_techniques])}

## Immediate Actions Required

{chr(10).join([f"{i}. {action}" for i, action in enumerate(result.immediate_actions, 1)])}

## Short-Term Recommendations

{chr(10).join([f"{i}. {rec}" for i, rec in enumerate(result.short_term_recommendations, 1)])}

## Long-Term Recommendations

{chr(10).join([f"{i}. {rec}" for i, rec in enumerate(result.long_term_recommendations, 1)])}

## Investigation Queries

{chr(10).join([f"{i}. {query}" for i, query in enumerate(result.investigation_queries, 1)])}

---

*Processing time: {result.processing_time_seconds:.2f}s | Tokens used: {result.tokens_used}*
"""

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(md_content)
