"""Professional HTML report generator."""

from pathlib import Path
from datetime import datetime
from typing import Optional
from vaulytica.models import SecurityEvent, AnalysisResult


class HTMLReportGenerator:
    """Generate professional HTML reports with styling and charts."""

    def __init__(self):
        self.template = self._load_template()

    def _load_template(self) -> str:
        """Load HTML template with embedded CSS."""

        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report - {event_id}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
        }}
        .header h1 {{
            font-size: 32px;
            margin-bottom: 10px;
        }}
        .header .meta {{
            opacity: 0.9;
            font-size: 14px;
        }}
        .content {{
            padding: 40px;
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #667eea;
            font-size: 24px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        .risk-score {{
            display: inline-block;
            padding: 20px 40px;
            background: {risk_color};
            color: white;
            border-radius: 8px;
            font-size: 48px;
            font-weight: bold;
            margin: 20px 0;
        }}
        .confidence {{
            display: inline-block;
            padding: 10px 20px;
            background: #4CAF50;
            color: white;
            border-radius: 4px;
            margin-left: 20px;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            background: {severity_color};
            color: white;
            border-radius: 4px;
            font-weight: bold;
            font-size: 14px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #667eea;
        }}
        .attack-chain {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .attack-chain ol {{
            margin-left: 20px;
        }}
        .attack-chain li {{
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 4px;
        }}
        .action-list {{
            list-style: none;
        }}
        .action-list li {{
            padding: 15px;
            margin: 10px 0;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            border-radius: 4px;
        }}
        .action-list.immediate li {{
            background: #f8d7da;
            border-left-color: #dc3545;
        }}
        .action-list.short-term li {{
            background: #d1ecf1;
            border-left-color: #17a2b8;
        }}
        .action-list.long-term li {{
            background: #d4edda;
            border-left-color: #28a745;
        }}
        .query-box {{
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            margin: 10px 0;
            overflow-x: auto;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px 40px;
            text-align: center;
            color: #666;
            font-size: 14px;
        }}
        .indicator {{
            display: inline-block;
            padding: 5px 10px;
            background: #e9ecef;
            border-radius: 4px;
            margin: 5px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Analysis Report</h1>
            <div class="meta">
                <strong>Event ID:</strong> {event_id}<br>
                <strong>Source:</strong> {source_system}<br>
                <strong>Analyzed:</strong> {analysis_timestamp}<br>
                <strong>Severity:</strong> <span class="severity-badge">{severity}</span>
            </div>
        </div>

        <div class="content">
            <div class="section">
                <h2>5W1H Quick Summary</h2>
                <table>
                    <tr><th style="width: 100px;">WHO</th><td>{five_w1h_who}</td></tr>
                    <tr><th>WHAT</th><td>{five_w1h_what}</td></tr>
                    <tr><th>WHEN</th><td>{five_w1h_when}</td></tr>
                    <tr><th>WHERE</th><td>{five_w1h_where}</td></tr>
                    <tr><th>WHY</th><td>{five_w1h_why}</td></tr>
                    <tr><th>HOW</th><td>{five_w1h_how}</td></tr>
                </table>
            </div>

            <div class="section">
                <h2>Executive Summary</h2>
                <p>{executive_summary}</p>
            </div>

            <div class="section">
                <h2>Risk Assessment</h2>
                <div class="risk-score">{risk_score}/10</div>
                <div class="confidence">Confidence: {confidence}%</div>
                <p style="margin-top: 20px;"><strong>Event Description:</strong> {description}</p>
            </div>

            {attack_chain_section}

            {mitre_section}

            {indicators_section}

            {immediate_actions_section}

            {short_term_section}

            {long_term_section}

            {investigation_section}
        </div>

        <div class="footer">
            <p>Processing Time: {processing_time}s | Tokens Used: {tokens_used}</p>
            <p>Generated by Vaulytica Security Analysis Framework</p>
        </div>
    </div>
</body>
</html>"""

    def generate(
        self,
        event: SecurityEvent,
        result: AnalysisResult,
        output_path: Path
    ) -> None:
        """Generate HTML report."""

        risk_color = self._get_risk_color(result.risk_score)
        severity_color = self._get_severity_color(event.severity.value)

        attack_chain_html = ""
        if result.attack_chain:
            chain_items = "".join([f"<li>{step}</li>" for step in result.attack_chain])
            attack_chain_html = """
            <div class="section">
                <h2>Attack Chain</h2>
                <div class="attack-chain">
                    <ol>{chain_items}</ol>
                </div>
            </div>"""

        mitre_html = ""
        if result.mitre_techniques:
            rows = "".join([
                f"<tr><td>{m.technique_id}</td><td>{m.technique_name}</td><td>{m.tactic}</td><td>{int(m.confidence*100)}%</td></tr>"
                for m in result.mitre_techniques
            ])
            mitre_html = """
            <div class="section">
                <h2>MITRE ATT&CK Techniques</h2>
                <table>
                    <thead>
                        <tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Confidence</th></tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>"""

        indicators_html = ""
        if event.technical_indicators:
            indicators = "".join([
                f'<span class="indicator">{ti.indicator_type}: {ti.value}</span>'
                for ti in event.technical_indicators
            ])
            indicators_html = """
            <div class="section">
                <h2>Technical Indicators</h2>
                <div>{indicators}</div>
            </div>"""

        immediate_html = self._generate_action_section(
            "Immediate Actions Required",
            result.immediate_actions,
            "immediate"
        )

        short_term_html = self._generate_action_section(
            "Short-Term Recommendations",
            result.short_term_recommendations,
            "short-term"
        )

        long_term_html = self._generate_action_section(
            "Long-Term Recommendations",
            result.long_term_recommendations,
            "long-term"
        )

        investigation_html = ""
        if result.investigation_queries:
            queries = "".join([
                f'<div class="query-box">{query}</div>'
                for query in result.investigation_queries
            ])
            investigation_html = """
            <div class="section">
                <h2>Investigation Queries</h2>
                {queries}
            </div>"""

        html_content = self.template.format(
            event_id=result.event_id,
            source_system=event.source_system,
            analysis_timestamp=result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            severity=event.severity.value,
            severity_color=severity_color,
            five_w1h_who=result.five_w1h.who,
            five_w1h_what=result.five_w1h.what,
            five_w1h_when=result.five_w1h.when,
            five_w1h_where=result.five_w1h.where,
            five_w1h_why=result.five_w1h.why,
            five_w1h_how=result.five_w1h.how,
            executive_summary=result.executive_summary,
            risk_score=f"{result.risk_score:.1f}",
            risk_color=risk_color,
            confidence=int(result.confidence * 100),
            description=event.description,
            attack_chain_section=attack_chain_html,
            mitre_section=mitre_html,
            indicators_section=indicators_html,
            immediate_actions_section=immediate_html,
            short_term_section=short_term_html,
            long_term_section=long_term_html,
            investigation_section=investigation_html,
            processing_time=f"{result.processing_time_seconds:.2f}",
            tokens_used=result.tokens_used
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(html_content)

    def _generate_action_section(self, title: str, actions: list, css_class: str) -> str:
        """Generate action list section."""

        if not actions:
            return ""

        items = "".join([f"<li>{action}</li>" for action in actions])
        return """
        <div class="section">
            <h2>{title}</h2>
            <ul class="action-list {css_class}">{items}</ul>
        </div>"""

    def _get_risk_color(self, risk_score: float) -> str:
        """Get color based on risk score."""

        if risk_score >= 8.0:
            return "#dc3545"
        elif risk_score >= 6.0:
            return "#fd7e14"
        elif risk_score >= 4.0:
            return "#ffc107"
        else:
            return "#28a745"

    def _get_severity_color(self, severity: str) -> str:
        """Get color based on severity."""

        colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#17a2b8",
            "INFO": "#6c757d"
        }
        return colors.get(severity, "#6c757d")
