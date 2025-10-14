"""Enhanced security analyst AI agent with advanced threat analysis."""

import json
import time
import hashlib
from datetime import datetime
from typing import List, Optional, Dict
from anthropic import Anthropic
from vaulytica.models import SecurityEvent, AnalysisResult, MitreAttack, FiveW1H
from vaulytica.config import VaulyticaConfig
from .base import BaseAgent


class SecurityAnalystAgent(BaseAgent):
    """Enhanced AI agent specialized in security incident analysis with threat intelligence."""

    def __init__(self, config: VaulyticaConfig):
        super().__init__(config)
        self.client = Anthropic(api_key=config.anthropic_api_key)
        self.threat_intel_db = self._load_threat_intelligence()
    
    def _load_threat_intelligence(self) -> Dict:
        """Load threat intelligence database."""
        return {
            "apt_groups": {
                "APT28": ["Fancy Bear", "Sofacy", "Sednit"],
                "APT29": ["Cozy Bear", "The Dukes"],
                "Lazarus": ["Hidden Cobra", "Guardians of Peace"],
            },
            "malware_families": {
                "cryptominer": ["XMRig", "Minergate", "Coinhive"],
                "ransomware": ["Ryuk", "Conti", "LockBit", "BlackCat"],
                "backdoor": ["Cobalt Strike", "Meterpreter", "Empire"],
            },
            "attack_patterns": {
                "cryptojacking": ["T1496", "T1059", "T1053"],
                "ransomware": ["T1486", "T1490", "T1489"],
                "data_exfiltration": ["T1048", "T1041", "T1567"],
            }
        }

    async def analyze(
        self,
        events: List[SecurityEvent],
        historical_context: Optional[List[Dict]] = None
    ) -> AnalysisResult:
        """Analyze security events with enhanced threat intelligence."""

        start_time = time.time()

        enriched_events = self._enrich_with_threat_intel(events)

        prompt = self._build_enhanced_analysis_prompt(
            enriched_events,
            historical_context
        )

        response = self.client.messages.create(
            model=self.config.model_name,
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature,
            messages=[{"role": "user", "content": prompt}]
        )

        raw_response = response.content[0].text
        tokens_used = response.usage.input_tokens + response.usage.output_tokens

        result = self._parse_llm_response(events[0], raw_response, tokens_used)
        result.processing_time_seconds = time.time() - start_time

        return result

    def _enrich_with_threat_intel(self, events: List[SecurityEvent]) -> List[SecurityEvent]:
        """Enrich events with threat intelligence context."""

        for event in events:
            for indicator in event.technical_indicators:
                if indicator.indicator_type == "domain":
                    for family, patterns in self.threat_intel_db["malware_families"].items():
                        if any(p.lower() in indicator.value.lower() for p in patterns):
                            if not indicator.context:
                                indicator.context = f"Associated with {family}"
                            else:
                                indicator.context += f" | {family}"

        return events
    
    def _build_enhanced_analysis_prompt(
        self,
        events: List[SecurityEvent],
        historical_context: Optional[List[Dict]] = None
    ) -> str:
        """Build enhanced analysis prompt with threat intelligence."""

        events_json = json.dumps([e.model_dump(mode='json') for e in events], indent=2, default=str)

        prompt = f"""You are a senior security analyst with 15+ years of experience in incident response, threat hunting, and vulnerability assessment. Analyze the following security event(s) with systematic, expert-level reasoning.

SECURITY EVENT DATA:
{events_json}

"""

        if historical_context:
            context_str = "\n".join([
                f"- {ctx.get('document', '')} (Relevance: {ctx.get('relevance_score', 0):.2f})"
                for ctx in historical_context
            ])
            prompt += f"""HISTORICAL CONTEXT (Similar Past Incidents):
{context_str}

"""
        
        prompt += """ANALYSIS FRAMEWORK:

CRITICAL: Start with 5W1H Quick Summary for rapid incident understanding.

0. FIVE W1H SUMMARY (Quick Reference)
   WHO: Identify all actors (attacker identity/type, victim accounts, affected users)
   WHAT: Describe the attack type and specific actions taken
   WHEN: Provide timeline (start time, duration, detection time)
   WHERE: List affected systems, networks, geographic locations
   WHY: Assess attacker motivation and objectives
   HOW: Explain techniques, tools, and methods used

1. EXECUTIVE SUMMARY (2-3 sentences)
   - Business-focused impact statement
   - Primary systems/assets affected
   - Recommended priority level

2. TECHNICAL INDICATORS & EVIDENCE
   - All observables (IPs, domains, files, processes, accounts)
   - Behavioral patterns and anomalies
   - Data volume, timing, and access patterns
   - Missing critical information that should be investigated

3. MITRE ATT&CK MAPPING (Detailed)
   - Map each observed behavior to specific techniques with confidence
   - Identify full attack lifecycle stages
   - Assess threat actor sophistication and TTPs
   - Note any advanced or unusual techniques

4. ATTACK CHAIN RECONSTRUCTION
   - Step-by-step progression of the attack
   - Initial access method with evidence
   - Persistence mechanisms identified
   - Lateral movement or privilege escalation
   - Data access or exfiltration activities
   - Command and control infrastructure

5. THREAT INTELLIGENCE CORRELATION
   - Known malware families or APT groups
   - Similar attack patterns from historical incidents
   - Threat actor attribution indicators
   - Campaign or operation linkages

6. RISK ASSESSMENT (Comprehensive)
   - Asset criticality (data classification, business function)
   - Likelihood of successful exploitation (0-100%)
   - Potential business impact (financial, operational, reputational)
   - Regulatory or compliance implications
   - Overall risk score (0-10 scale) with justification
   - Confidence level in assessment (0-100%) with reasoning

7. IMMEDIATE ACTIONS (Next 1-4 Hours)
   - Containment steps to prevent spread
   - Evidence preservation requirements
   - Critical systems to isolate or monitor
   - Stakeholders to notify immediately

8. SHORT-TERM RECOMMENDATIONS (Next 1-7 Days)
   - Remediation steps with specific priority
   - Additional investigation queries to run
   - Security control improvements
   - Vulnerability patching requirements

9. LONG-TERM RECOMMENDATIONS (Next 30-90 Days)
   - Architectural security improvements
   - Process and policy enhancements
   - Detection rule development
   - Security awareness training needs

10. INVESTIGATION QUERIES (SIEM/Log Analysis)
    - Specific searches to run with exact syntax
    - Additional data sources to check
    - Indicators to hunt for across environment
    - Timeline expansion queries

OUTPUT FORMAT (JSON):
{
  "five_w1h": {
    "who": "Detailed actor information",
    "what": "Specific attack description",
    "when": "Timeline with timestamps",
    "where": "Systems and locations",
    "why": "Motivation assessment",
    "how": "Technical execution methods"
  },
  "executive_summary": "Business-focused summary for leadership",
  "risk_score": 7.5,
  "confidence": 0.85,
  "attack_chain": ["Step 1: Initial Access via...", "Step 2: Persistence through...", "Step 3: ..."],
  "mitre_techniques": [
    {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Initial Access", "confidence": 0.8}
  ],
  "immediate_actions": ["Action 1 with specific steps", "Action 2 with timeline"],
  "short_term_recommendations": ["Rec 1 with priority", "Rec 2 with owner"],
  "long_term_recommendations": ["Rec 1 with timeline", "Rec 2 with resources"],
  "investigation_queries": ["SIEM query 1", "Log search 2"],
  "detailed_analysis": "Full technical analysis with evidence citations and reasoning"
}

Provide your analysis in valid JSON format. Be extremely specific, cite all evidence, explain your reasoning with confidence levels, and provide actionable recommendations."""
        
        return prompt
    
    def _parse_llm_response(
        self,
        event: SecurityEvent,
        raw_response: str,
        tokens_used: int
    ) -> AnalysisResult:
        """Parse LLM response into structured AnalysisResult."""

        import re
        cleaned_response = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', raw_response)

        try:
            response_json = json.loads(cleaned_response)
        except json.JSONDecodeError:
            start = cleaned_response.find('{')
            end = cleaned_response.rfind('}') + 1
            if start != -1 and end > start:
                response_json = json.loads(cleaned_response[start:end])
            else:
                raise ValueError("Could not parse LLM response as JSON")
        
        mitre_techniques = []
        for mt in response_json.get("mitre_techniques", []):
            mitre_techniques.append(MitreAttack(
                technique_id=mt["technique_id"],
                technique_name=mt["technique_name"],
                tactic=mt["tactic"],
                confidence=mt.get("confidence", 0.7)
            ))

        five_w1h_data = response_json.get("five_w1h", {})
        five_w1h = FiveW1H(
            who=five_w1h_data.get("who", "Unknown actors"),
            what=five_w1h_data.get("what", "Security event detected"),
            when=five_w1h_data.get("when", "Timestamp in event data"),
            where=five_w1h_data.get("where", "Systems listed in event"),
            why=five_w1h_data.get("why", "Motivation unclear"),
            how=five_w1h_data.get("how", "Techniques listed in MITRE mapping")
        )

        return AnalysisResult(
            event_id=event.event_id,
            five_w1h=five_w1h,
            executive_summary=response_json.get("executive_summary", ""),
            risk_score=float(response_json.get("risk_score", 5.0)),
            confidence=float(response_json.get("confidence", 0.7)),
            attack_chain=response_json.get("attack_chain", []),
            mitre_techniques=mitre_techniques,
            immediate_actions=response_json.get("immediate_actions", []),
            short_term_recommendations=response_json.get("short_term_recommendations", []),
            long_term_recommendations=response_json.get("long_term_recommendations", []),
            investigation_queries=response_json.get("investigation_queries", []),
            raw_llm_response=raw_response,
            tokens_used=tokens_used,
        )

