"""Enhanced security analyst AI agent with advanced threat analysis.

Version: 1.1.0
Features:
- Multi-layered threat intelligence enrichment
- Behavioral anomaly detection with ML
- Attack pattern recognition and attribution
- URLScan.io and WHOIS integration
- Cross-platform investigation queries
- Intelligent caching and retry logic
- Comprehensive error handling
"""

import json
import time
import hashlib
import asyncio
from datetime import datetime
from typing import List, Optional, Dict, Tuple, Any
from anthropic import Anthropic, APIError, APIConnectionError, RateLimitError
from vaulytica.models import (
    SecurityEvent, AnalysisResult, MitreAttack, FiveW1H,
    ThreatActorProfile, BehavioralInsight, AttackGraphNode
)
from vaulytica.config import VaulyticaConfig
from vaulytica.logger import get_logger
from vaulytica.threat_intel import ThreatIntelligenceEngine, IOCEnrichment
from vaulytica.behavioral_analysis import BehavioralAnalysisEngine, BehavioralAnomaly, AttackPattern
from vaulytica.threat_feeds import ThreatFeedIntegration, AggregatedThreatIntel
from vaulytica.ml_engine import MLEngine, AnomalyDetection, ThreatPrediction
from vaulytica.urlscan_integration import URLScanIntegration, URLScanResult
from vaulytica.whois_integration import WHOISIntegration, WHOISResult
from vaulytica.investigation_queries import InvestigationQueryGenerator, InvestigationQuery
from .base import BaseAgent

logger = get_logger(__name__)

# Constants
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 2
CACHE_TTL_SECONDS = 3600


def retry_on_error(max_retries: int = MAX_RETRIES, delay: float = RETRY_DELAY_SECONDS):
    """Decorator for retrying functions on transient errors."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except (APIConnectionError, RateLimitError) as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        wait_time = delay * (2 ** attempt)  # Exponential backoff
                        logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait_time}s...")
                        await asyncio.sleep(wait_time)
                    else:
                        logger.error(f"All {max_retries} attempts failed: {e}")
                except Exception as e:
                    logger.error(f"Non-retryable error in {func.__name__}: {e}")
                    raise
            raise last_exception
        return wrapper
    return decorator


class SecurityAnalystAgent(BaseAgent):
    """
    Enhanced AI agent specialized in security incident analysis.

    Features:
    - Multi-layered threat intelligence enrichment
    - Behavioral anomaly detection
    - Attack pattern recognition
    - Threat actor attribution
    - Attack graph construction
    - Confidence-based scoring
    """

    def __init__(self, config: VaulyticaConfig):
        super().__init__(config)
        self.client = Anthropic(api_key=config.anthropic_api_key)
        self.threat_intel_db = self._load_threat_intelligence()

        # Initialize advanced analysis engines
        self.threat_intel_engine = ThreatIntelligenceEngine()
        self.behavioral_engine = BehavioralAnalysisEngine()

        # Initialize ML engine (v0.10.0)
        self.ml_engine = MLEngine(enable_training=True)
        logger.info("ML engine initialized for threat detection and prediction")

        # Initialize real-time threat feed integration (v0.9.0)
        if config.enable_threat_feeds:
            self.threat_feeds = ThreatFeedIntegration(
                virustotal_api_key=config.virustotal_api_key,
                otx_api_key=config.alienvault_otx_api_key,
                abuseipdb_api_key=config.abuseipdb_api_key,
                shodan_api_key=config.shodan_api_key,
                enable_cache=True,
                cache_ttl_hours=config.threat_feed_cache_ttl,
                timeout_seconds=config.threat_feed_timeout
            )
            logger.info("Real-time threat feed integration enabled")
        else:
            self.threat_feeds = None
            logger.info("Threat feed integration disabled")

        # Initialize URLScan.io integration (v1.0.0)
        self.urlscan = URLScanIntegration(
            api_key=config.urlscan_api_key,
            timeout=config.threat_feed_timeout,
            max_wait_seconds=config.urlscan_max_wait_seconds
        )
        logger.info("URLScan.io integration initialized")

        # Initialize WHOIS integration (v1.0.0)
        if config.enable_whois:
            self.whois = WHOISIntegration(
                timeout=config.threat_feed_timeout,
                recently_registered_threshold_days=config.whois_recently_registered_threshold_days
            )
            logger.info("WHOIS integration enabled")
        else:
            self.whois = None
            logger.info("WHOIS integration disabled")

        # Initialize investigation query generator (v1.0.0)
        if config.enable_investigation_queries:
            self.query_generator = InvestigationQueryGenerator()
            logger.info("Investigation query generator enabled")
        else:
            self.query_generator = None
            logger.info("Investigation query generator disabled")

        logger.info("SecurityAnalystAgent initialized with advanced capabilities")

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
        """
        Perform comprehensive security analysis with multi-layered intelligence.

        Analysis Pipeline:
        1. IOC Enrichment - Enrich indicators with threat intelligence
        2. URLScan.io Enrichment - Screenshot capture and phishing detection
        3. WHOIS Enrichment - Domain registration analysis
        4. Behavioral Analysis - Detect anomalies and patterns
        5. ML-Powered Analysis - Anomaly detection and threat prediction
        6. Threat Actor Attribution - Correlate with known APT groups
        7. AI Analysis - Deep reasoning with Claude
        8. Cross-Platform Investigation Queries - Generate recommended queries
        9. Attack Graph Construction - Build visual attack path
        10. Confidence Scoring - Calculate evidence-based confidence
        """
        start_time = time.time()
        logger.info(f"Starting enhanced analysis for {len(events)} event(s)")

        # Phase 1: IOC Enrichment
        logger.debug("Phase 1: IOC Enrichment")
        ioc_enrichments = self._enrich_iocs(events)

        # Phase 2: URLScan.io Enrichment (NEW - v1.0.0)
        logger.debug("Phase 2: URLScan.io Enrichment")
        urlscan_results = await self._enrich_with_urlscan(events, ioc_enrichments)

        # Phase 3: WHOIS Enrichment (NEW - v1.0.0)
        logger.debug("Phase 3: WHOIS Enrichment")
        whois_results = await self._enrich_with_whois(events, ioc_enrichments)

        # Phase 4: Behavioral Analysis
        logger.debug("Phase 4: Behavioral Analysis")
        behavioral_results = self._perform_behavioral_analysis(events)
        anomalies, attack_patterns = behavioral_results

        # Phase 5: ML-Powered Analysis (v0.10.0)
        logger.debug("Phase 5: ML-Powered Analysis")
        ml_anomalies, ml_predictions = self._perform_ml_analysis(events)

        # Phase 6: Threat Intelligence Enrichment
        logger.debug("Phase 6: Threat Intelligence Enrichment")
        enriched_events = self._enrich_with_threat_intel(events)

        # Phase 7: Build Enhanced Prompt with all context
        logger.debug("Phase 7: Building enhanced analysis prompt")
        prompt = self._build_enhanced_analysis_prompt(
            enriched_events,
            historical_context,
            ioc_enrichments,
            anomalies,
            attack_patterns,
            ml_anomalies,
            ml_predictions,
            urlscan_results,
            whois_results
        )

        # Phase 8: AI Analysis with retry logic
        logger.debug("Phase 8: Calling AI for deep analysis")
        response = self._call_api_with_retry(prompt)
        raw_response = response.content[0].text
        tokens_used = response.usage.input_tokens + response.usage.output_tokens

        # Phase 9: Parse and Enhance Results
        logger.debug("Phase 9: Parsing and enhancing results")
        result = self._parse_llm_response(events[0], raw_response, tokens_used)

        # Phase 10: Add Advanced Analysis Results
        logger.debug("Phase 10: Adding advanced analysis results")
        result = self._enhance_analysis_result(
            result,
            ioc_enrichments,
            anomalies,
            attack_patterns,
            events[0],
            ml_anomalies,
            ml_predictions,
            urlscan_results,
            whois_results
        )

        # Phase 11: Generate Cross-Platform Investigation Queries (NEW - v1.0.0)
        logger.debug("Phase 11: Generating investigation queries")
        if self.query_generator:
            investigation_queries = self.query_generator.generate_queries(events[0], ioc_enrichments)
            result.investigation_queries_by_platform = self._format_investigation_queries(investigation_queries)

        result.processing_time_seconds = time.time() - start_time
        logger.info(f"Analysis complete in {result.processing_time_seconds:.2f}s - Risk: {result.risk_score:.1f}/10")

        return result

    def _call_api_with_retry(self, prompt: str, max_retries: int = 3):
        """Call Anthropic API with exponential backoff retry logic."""

        for attempt in range(max_retries):
            try:
                logger.debug(f"API call attempt {attempt + 1}/{max_retries}")

                response = self.client.messages.create(
                    model=self.config.model_name,
                    max_tokens=self.config.max_tokens,
                    temperature=self.config.temperature,
                    messages=[{"role": "user", "content": prompt}]
                )

                logger.debug("API call successful")
                return response

            except RateLimitError as e:
                logger.warning(f"Rate limit hit on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt) * 2  # Exponential backoff: 2, 4, 8 seconds
                    logger.info(f"Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                else:
                    logger.error("Max retries reached for rate limit")
                    raise

            except APIConnectionError as e:
                logger.warning(f"Connection error on attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    wait_time = (2 ** attempt)  # Exponential backoff: 1, 2, 4 seconds
                    logger.info(f"Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                else:
                    logger.error("Max retries reached for connection error")
                    raise

            except APIError as e:
                logger.error(f"API error on attempt {attempt + 1}: {e}")
                # Don't retry on general API errors (likely client-side issues)
                raise

            except Exception as e:
                logger.error(f"Unexpected error on attempt {attempt + 1}: {e}")
                raise

        raise Exception("Failed to call API after all retries")

    def _enrich_iocs(self, events: List[SecurityEvent]) -> Dict[str, IOCEnrichment]:
        """
        Enrich all IOCs in events with threat intelligence.

        Now uses real-time threat feeds when available (v0.9.0).

        Returns:
            Dictionary mapping IOC values to enrichment data
        """
        enrichments = {}

        for event in events:
            for indicator in event.technical_indicators:
                ioc_key = f"{indicator.indicator_type}:{indicator.value}"

                if ioc_key not in enrichments:
                    # Use local threat intel engine
                    enrichment = self.threat_intel_engine.enrich_ioc(
                        indicator.value,
                        indicator.indicator_type
                    )

                    # Enhance with real-time threat feeds if available
                    if self.threat_feeds:
                        try:
                            feed_result = self.threat_feeds.enrich_ioc(
                                indicator.value,
                                indicator.indicator_type
                            )

                            # Merge threat feed data into enrichment
                            if feed_result.is_malicious:
                                enrichment.reputation_score = max(
                                    enrichment.reputation_score,
                                    feed_result.overall_threat_score / 100.0
                                )
                                enrichment.tags.extend(list(feed_result.tags)[:5])
                                enrichment.associated_malware.extend(
                                    list(feed_result.malware_families)[:3]
                                )
                                enrichment.threat_actors.extend(
                                    list(feed_result.threat_actors)[:3]
                                )

                                # Update threat level based on consensus
                                if feed_result.consensus_verdict == "MALICIOUS":
                                    from vaulytica.threat_intel import ThreatLevel
                                    if feed_result.overall_threat_score >= 80:
                                        enrichment.threat_level = ThreatLevel.CRITICAL
                                    elif feed_result.overall_threat_score >= 60:
                                        enrichment.threat_level = ThreatLevel.HIGH

                                logger.info(
                                    f"Enhanced {ioc_key} with real-time feeds: "
                                    f"{feed_result.sources_flagged}/{feed_result.sources_checked} "
                                    f"sources flagged as {feed_result.consensus_verdict}"
                                )
                        except Exception as e:
                            logger.warning(f"Error enriching {ioc_key} with threat feeds: {e}")

                    enrichments[ioc_key] = enrichment

                    logger.debug(f"Enriched {ioc_key}: threat_level={enrichment.threat_level}, "
                               f"reputation={enrichment.reputation_score:.2f}")

        return enrichments

    async def _enrich_with_urlscan(
        self,
        events: List[SecurityEvent],
        ioc_enrichments: Dict[str, IOCEnrichment]
    ) -> Dict[str, URLScanResult]:
        """
        Enrich URLs and domains with URLScan.io analysis.

        Returns:
            Dictionary mapping URLs/domains to URLScan results
        """
        urlscan_results = {}

        # Extract URLs and domains from events
        urls_to_scan = set()
        domains_to_scan = set()

        for event in events:
            for indicator in event.technical_indicators:
                if indicator.indicator_type == "url":
                    urls_to_scan.add(indicator.value)
                elif indicator.indicator_type == "domain":
                    domains_to_scan.add(indicator.value)

        # Scan URLs
        for url in urls_to_scan:
            try:
                result = await self.urlscan.scan_url(url)
                if result:
                    urlscan_results[url] = result
                    logger.info(f"URLScan result for {url}: {result.verdict}, phishing={result.is_phishing}")
            except Exception as e:
                logger.warning(f"URLScan error for {url}: {e}")

        # Scan domains (convert to http:// URLs)
        for domain in domains_to_scan:
            url = f"http://{domain}"
            try:
                result = await self.urlscan.scan_url(url)
                if result:
                    urlscan_results[domain] = result
                    logger.info(f"URLScan result for {domain}: {result.verdict}, phishing={result.is_phishing}")
            except Exception as e:
                logger.warning(f"URLScan error for {domain}: {e}")

        logger.info(f"URLScan enrichment complete: {len(urlscan_results)} results")
        return urlscan_results

    async def _enrich_with_whois(
        self,
        events: List[SecurityEvent],
        ioc_enrichments: Dict[str, IOCEnrichment]
    ) -> Dict[str, WHOISResult]:
        """
        Enrich domains with WHOIS registration data.

        Returns:
            Dictionary mapping domains to WHOIS results
        """
        if not self.whois:
            return {}

        whois_results = {}

        # Extract domains from events
        domains_to_lookup = set()

        for event in events:
            for indicator in event.technical_indicators:
                if indicator.indicator_type == "domain":
                    domains_to_lookup.add(indicator.value)
                elif indicator.indicator_type == "url":
                    # Extract domain from URL
                    try:
                        domain = indicator.value.split("://")[1].split("/")[0]
                        domains_to_lookup.add(domain)
                    except (IndexError, AttributeError) as e:
                        logger.debug(f"Failed to extract domain from URL {indicator.value}: {e}")

        # Perform WHOIS lookups
        for domain in domains_to_lookup:
            try:
                result = await self.whois.lookup(domain)
                if result:
                    whois_results[domain] = result
                    logger.info(
                        f"WHOIS result for {domain}: age={result.age_days} days, "
                        f"recently_registered={result.is_recently_registered}, "
                        f"risk_indicators={len(result.risk_indicators)}"
                    )
            except Exception as e:
                logger.warning(f"WHOIS error for {domain}: {e}")

        logger.info(f"WHOIS enrichment complete: {len(whois_results)} results")
        return whois_results

    def _perform_behavioral_analysis(
        self,
        events: List[SecurityEvent]
    ) -> Tuple[List[BehavioralAnomaly], List[AttackPattern]]:
        """
        Perform behavioral analysis on events.

        Returns:
            Tuple of (anomalies, attack_patterns)
        """
        all_anomalies = []
        all_patterns = []

        for event in events:
            anomalies, patterns = self.behavioral_engine.analyze_event(event)
            all_anomalies.extend(anomalies)
            all_patterns.extend(patterns)

        logger.info(f"Behavioral analysis: {len(all_anomalies)} anomalies, {len(all_patterns)} patterns")
        return all_anomalies, all_patterns

    def _enrich_with_threat_intel(self, events: List[SecurityEvent]) -> List[SecurityEvent]:
        """Enrich events with threat intelligence context (legacy method enhanced)."""

        # Optimize: Pre-process malware families into a single lookup structure
        malware_lookup = {}
        for family, patterns in self.threat_intel_db["malware_families"].items():
            for pattern in patterns:
                malware_lookup[pattern.lower()] = family

        for event in events:
            for indicator in event.technical_indicators:
                if indicator.indicator_type == "domain":
                    indicator_lower = indicator.value.lower()
                    # Optimize: Single pass through lookup instead of nested loops
                    for pattern, family in malware_lookup.items():
                        if pattern in indicator_lower:
                            if not indicator.context:
                                indicator.context = f"Associated with {family}"
                            else:
                                indicator.context += f" | {family}"
                            break  # Found match, no need to continue

        return events

    def _format_ioc_enrichment_section(self, ioc_enrichments: Dict[str, IOCEnrichment]) -> str:
        """Format IOC enrichment data for prompt."""
        ioc_summary = []
        for ioc_key, enrichment in ioc_enrichments.items():
            if enrichment.reputation_score > 0.6:  # Only include suspicious/malicious IOCs
                ioc_summary.append(
                    f"- {ioc_key}: Threat Level={enrichment.threat_level.value}, "
                    f"Reputation={enrichment.reputation_score:.2f}, "
                    f"Confidence={enrichment.confidence:.2f}"
                )
                if enrichment.associated_malware:
                    ioc_summary.append(f"  Associated Malware: {', '.join(enrichment.associated_malware)}")
                if enrichment.associated_actors:
                    ioc_summary.append(f"  Associated Actors: {', '.join(enrichment.associated_actors)}")

        if ioc_summary:
            return """THREAT INTELLIGENCE - IOC ENRICHMENT:
{chr(10).join(ioc_summary)}

"""
        return ""

    def _format_urlscan_section(self, urlscan_results: Dict[str, URLScanResult]) -> str:
        """Format URLScan.io results for prompt."""
        urlscan_summary = []

        for url, result in urlscan_results.items():
            urlscan_summary.append(f"- URL: {url}")
            urlscan_summary.append(f"  Verdict: {result.verdict.value.upper()}")
            urlscan_summary.append(f"  Phishing: {result.is_phishing}")

            if result.brands_detected:
                urlscan_summary.append(f"  Brands Detected: {', '.join(result.brands_detected)}")

            if result.malicious_indicators:
                urlscan_summary.append(f"  Malicious Indicators:")
                for indicator in result.malicious_indicators:
                    urlscan_summary.append(f"    - {indicator}")

            if result.screenshot_url:
                urlscan_summary.append(f"  Screenshot: {result.screenshot_url}")

            if result.ip_address:
                urlscan_summary.append(f"  IP: {result.ip_address} ({result.country or 'Unknown'})")

            if result.technologies:
                urlscan_summary.append(f"  Technologies: {', '.join(result.technologies[:5])}")

            urlscan_summary.append("")  # Blank line between results

        if urlscan_summary:
            return """URLSCAN.IO ANALYSIS:
{chr(10).join(urlscan_summary)}

"""
        return ""

    def _format_whois_section(self, whois_results: Dict[str, WHOISResult]) -> str:
        """Format WHOIS results for prompt."""
        whois_summary = []

        for domain, result in whois_results.items():
            whois_summary.append(f"- Domain: {domain}")

            if result.age_days is not None:
                whois_summary.append(f"  Age: {result.age_days} days")
                whois_summary.append(f"  Recently Registered: {result.is_recently_registered}")

            if result.registrar:
                whois_summary.append(f"  Registrar: {result.registrar}")

            if result.registration_date:
                whois_summary.append(f"  Registration Date: {result.registration_date.strftime('%Y-%m-%d')}")

            if result.registrant_organization:
                whois_summary.append(f"  Registrant Org: {result.registrant_organization}")

            if result.registrant_country:
                whois_summary.append(f"  Country: {result.registrant_country}")

            if result.risk_indicators:
                whois_summary.append(f"  Risk Indicators:")
                for indicator in result.risk_indicators:
                    whois_summary.append(f"    - {indicator}")

            whois_summary.append("")  # Blank line between results

        if whois_summary:
            return """WHOIS DOMAIN ANALYSIS:
{chr(10).join(whois_summary)}

"""
        return ""

    def _format_behavioral_anomalies_section(self, anomalies: List[BehavioralAnomaly]) -> str:
        """Format behavioral anomalies for prompt."""
        anomaly_summary = []
        for anomaly in anomalies:
            if anomaly.confidence >= 0.6:
                anomaly_summary.append(
                    f"- [{anomaly.severity}] {anomaly.description} "
                    f"(Confidence: {anomaly.confidence:.2f}, Deviation: {anomaly.baseline_deviation:.2f})"
                )

        if anomaly_summary:
            return """BEHAVIORAL ANALYSIS - DETECTED ANOMALIES:
{chr(10).join(anomaly_summary)}

"""
        return ""

    def _format_attack_patterns_section(self, attack_patterns: List[AttackPattern]) -> str:
        """Format attack patterns for prompt."""
        pattern_summary = []
        for pattern in attack_patterns:
            pattern_summary.append(
                f"- {pattern.pattern_name.replace('_', ' ').title()}: "
                f"Confidence={pattern.confidence:.2f}, "
                f"MITRE TTPs={', '.join(pattern.mitre_ttps)}"
            )

        if pattern_summary:
            return """ATTACK PATTERN RECOGNITION:
{chr(10).join(pattern_summary)}

"""
        return ""

    def _format_ml_anomalies_section(self, ml_anomalies: List[AnomalyDetection]) -> str:
        """Format ML anomaly detection results for prompt."""
        if not any(a.is_anomaly for a in ml_anomalies):
            return ""

        ml_summary = []
        for i, anomaly in enumerate(ml_anomalies):
            if anomaly.is_anomaly:
                ml_summary.append(
                    f"- Event {i+1}: Anomaly Score={anomaly.anomaly_score:.2f}, "
                    f"Types={', '.join(a.value for a in anomaly.anomaly_types)}, "
                    f"Confidence={anomaly.confidence:.2f}"
                )

        if ml_summary:
            return """ML-POWERED ANOMALY DETECTION:
{chr(10).join(ml_summary)}

"""
        return ""

    def _format_ml_predictions_section(self, ml_predictions: List[ThreatPrediction]) -> str:
        """Format ML threat predictions for prompt."""
        pred_summary = []
        for i, pred in enumerate(ml_predictions):
            if pred.probability > 0.5:
                pred_summary.append(
                    f"- Event {i+1}: Predicted Threat={pred.predicted_threat_level.value}, "
                    f"Probability={pred.probability:.2f}, "
                    f"Attack Types={', '.join(pred.predicted_attack_types[:2])}"
                )

        if pred_summary:
            return """ML-POWERED THREAT PREDICTION:
{chr(10).join(pred_summary)}

"""
        return ""

    def _format_historical_context_section(self, historical_context: List[Dict]) -> str:
        """Format historical context for prompt."""
        context_str = "\n".join([
            f"- {ctx.get('document', '')} (Relevance: {ctx.get('relevance_score', 0):.2f})"
            for ctx in historical_context
        ])
        return """HISTORICAL CONTEXT (Similar Past Incidents):
{context_str}

"""

    def _get_analysis_framework_template(self) -> str:
        """Get the analysis framework template."""
        return """ANALYSIS FRAMEWORK:

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

    def _build_enhanced_analysis_prompt(
        self,
        events: List[SecurityEvent],
        historical_context: Optional[List[Dict]] = None,
        ioc_enrichments: Optional[Dict[str, IOCEnrichment]] = None,
        anomalies: Optional[List[BehavioralAnomaly]] = None,
        attack_patterns: Optional[List[AttackPattern]] = None,
        ml_anomalies: Optional[List[AnomalyDetection]] = None,
        ml_predictions: Optional[List[ThreatPrediction]] = None,
        urlscan_results: Optional[Dict[str, URLScanResult]] = None,
        whois_results: Optional[Dict[str, WHOISResult]] = None
    ) -> str:
        """Build comprehensive analysis prompt with all intelligence layers."""

        # Build base prompt with event data
        events_json = json.dumps([e.model_dump(mode='json') for e in events], indent=2, default=str)
        prompt = """You are an elite security analyst with 20+ years of experience in advanced threat hunting, incident response, malware analysis, and threat intelligence. You have deep expertise in APT operations, MITRE ATT&CK framework, and cyber threat attribution.

Analyze the following security event(s) with systematic, expert-level reasoning, incorporating all available threat intelligence and behavioral analysis.

SECURITY EVENT DATA:
{events_json}

"""

        # Add intelligence sections using helper methods
        if ioc_enrichments:
            prompt += self._format_ioc_enrichment_section(ioc_enrichments)

        if urlscan_results:
            prompt += self._format_urlscan_section(urlscan_results)

        if whois_results:
            prompt += self._format_whois_section(whois_results)

        if anomalies:
            prompt += self._format_behavioral_anomalies_section(anomalies)

        if attack_patterns:
            prompt += self._format_attack_patterns_section(attack_patterns)

        if ml_anomalies:
            prompt += self._format_ml_anomalies_section(ml_anomalies)

        if ml_predictions:
            prompt += self._format_ml_predictions_section(ml_predictions)

        if historical_context:
            prompt += self._format_historical_context_section(historical_context)

        # Add analysis framework
        prompt += self._get_analysis_framework_template()

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

    def _enhance_analysis_result(
        self,
        result: AnalysisResult,
        ioc_enrichments: Dict[str, IOCEnrichment],
        anomalies: List[BehavioralAnomaly],
        attack_patterns: List[AttackPattern],
        event: SecurityEvent,
        ml_anomalies: Optional[List[AnomalyDetection]] = None,
        ml_predictions: Optional[List[ThreatPrediction]] = None,
        urlscan_results: Optional[Dict[str, URLScanResult]] = None,
        whois_results: Optional[Dict[str, WHOISResult]] = None
    ) -> AnalysisResult:
        """
        Enhance analysis result with advanced intelligence.

        Adds:
        - Threat actor profiles
        - Behavioral insights
        - Attack graph
        - Anomaly scores
        - IOC enrichment data
        - ML-powered anomaly detection
        - ML-powered threat predictions
        - URLScan.io results
        - WHOIS results
        """
        # Add threat actor attribution
        result.threat_actors = self._attribute_threat_actors(result, attack_patterns)

        # Add behavioral insights
        result.behavioral_insights = self._convert_anomalies_to_insights(anomalies)

        # Build attack graph
        result.attack_graph = self._build_attack_graph(result, event)

        # Calculate anomaly score
        result.anomaly_score = self.behavioral_engine.calculate_anomaly_score(anomalies)

        # Add IOC enrichments
        result.ioc_enrichments = {
            key: {
                "threat_level": enrich.threat_level.value,
                "reputation_score": enrich.reputation_score,
                "confidence": enrich.confidence,
                "tags": enrich.tags,
                "associated_malware": enrich.associated_malware,
                "associated_actors": enrich.associated_actors
            }
            for key, enrich in ioc_enrichments.items()
        }

        # Add URLScan.io results (v1.0.0)
        if urlscan_results:
            result.urlscan_results = {
                url: {
                    "verdict": scan.verdict.value,
                    "is_phishing": scan.is_phishing,
                    "brands_detected": scan.brands_detected,
                    "screenshot_url": scan.screenshot_url,
                    "malicious_indicators": scan.malicious_indicators,
                    "ip_address": scan.ip_address,
                    "country": scan.country,
                    "technologies": scan.technologies
                }
                for url, scan in urlscan_results.items()
            }

        # Add WHOIS results (v1.0.0)
        if whois_results:
            result.whois_results = {
                domain: {
                    "age_days": whois.age_days,
                    "is_recently_registered": whois.is_recently_registered,
                    "registrar": whois.registrar,
                    "registration_date": whois.registration_date.isoformat() if whois.registration_date else None,
                    "registrant_organization": whois.registrant_organization,
                    "registrant_country": whois.registrant_country,
                    "risk_indicators": whois.risk_indicators
                }
                for domain, whois in whois_results.items()
            }

        # Add ML analysis results (v0.10.0)
        if ml_anomalies:
            ml_anomaly_summary = []
            for anomaly in ml_anomalies:
                if anomaly.is_anomaly:
                    ml_anomaly_summary.append({
                        "anomaly_score": anomaly.anomaly_score,
                        "anomaly_types": [a.value for a in anomaly.anomaly_types],
                        "confidence": anomaly.confidence,
                        "explanation": anomaly.explanation
                    })
            if ml_anomaly_summary:
                result.metadata["ml_anomalies"] = ml_anomaly_summary

        if ml_predictions:
            ml_prediction_summary = []
            for pred in ml_predictions:
                ml_prediction_summary.append({
                    "predicted_threat_level": pred.predicted_threat_level.value,
                    "probability": pred.probability,
                    "confidence": pred.confidence,
                    "predicted_attack_types": pred.predicted_attack_types,
                    "risk_factors": pred.risk_factors,
                    "mitigation_recommendations": pred.mitigation_recommendations
                })
            if ml_prediction_summary:
                result.metadata["ml_predictions"] = ml_prediction_summary

        logger.debug(f"Enhanced result: {len(result.threat_actors)} threat actors, "
                    f"{len(result.behavioral_insights)} insights, "
                    f"{len(result.attack_graph)} graph nodes")

        return result

    def _attribute_threat_actors(
        self,
        result: AnalysisResult,
        attack_patterns: List[AttackPattern]
    ) -> List[ThreatActorProfile]:
        """Attribute threat actors based on TTPs and patterns."""
        threat_actors = []

        # Extract TTPs from result
        ttps = [mt.technique_id for mt in result.mitre_techniques]

        # Extract tools from attack chain and description
        # Optimize: Build tool lookup set once instead of nested loops
        all_tools = set()
        for apt_data in self.threat_intel_engine.apt_database.values():
            all_tools.update(tool.lower() for tool in apt_data["tools"])

        tools = []
        for step in result.attack_chain:
            step_lower = step.lower()
            # Optimize: Check each tool once against the step
            for tool in all_tools:
                if tool in step_lower:
                    tools.append(tool)

        # Correlate with APT groups
        apt_matches = self.threat_intel_engine.correlate_apt_group(ttps, tools, [])

        for apt_name, confidence in apt_matches:
            apt_data = self.threat_intel_engine.apt_database[apt_name]
            threat_actors.append(ThreatActorProfile(
                actor_name=apt_name,
                confidence=confidence,
                origin=apt_data.get("origin"),
                motivation=apt_data.get("motivation"),
                sophistication=apt_data.get("sophistication"),
                ttps_matched=list(set(ttps) & set(apt_data["ttps"]))
            ))

        return threat_actors

    def _convert_anomalies_to_insights(
        self,
        anomalies: List[BehavioralAnomaly]
    ) -> List[BehavioralInsight]:
        """Convert behavioral anomalies to insights."""
        insights = []

        for anomaly in anomalies:
            insights.append(BehavioralInsight(
                insight_type=anomaly.anomaly_type.value,
                description=anomaly.description,
                severity=anomaly.severity,
                confidence=anomaly.confidence,
                evidence=anomaly.evidence
            ))

        return insights

    def _build_attack_graph(
        self,
        result: AnalysisResult,
        event: SecurityEvent
    ) -> List[AttackGraphNode]:
        """Build attack graph from analysis result."""
        graph_nodes = []
        node_id = 0

        # Map MITRE tactics to graph nodes
        tactic_order = [
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Command and Control",
            "Exfiltration",
            "Impact"
        ]

        # Group techniques by tactic
        techniques_by_tactic = {}
        for mt in result.mitre_techniques:
            if mt.tactic not in techniques_by_tactic:
                techniques_by_tactic[mt.tactic] = []
            techniques_by_tactic[mt.tactic].append(mt)

        # Create nodes in tactic order
        for tactic in tactic_order:
            if tactic in techniques_by_tactic:
                for mt in techniques_by_tactic[tactic]:
                    graph_nodes.append(AttackGraphNode(
                        node_id=f"node_{node_id}",
                        node_type=tactic.lower().replace(" ", "_"),
                        technique_id=mt.technique_id,
                        description=f"{mt.technique_name} ({mt.technique_id})",
                        timestamp=event.timestamp.isoformat(),
                        confidence=mt.confidence
                    ))
                    node_id += 1

        return graph_nodes

    def _format_investigation_queries(
        self,
        investigation_queries: Dict[str, List[InvestigationQuery]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Format investigation queries for AnalysisResult."""
        formatted_queries = {}

        for platform, queries in investigation_queries.items():
            formatted_queries[platform] = [
                {
                    "query": q.query,
                    "description": q.description,
                    "timeframe": q.timeframe,
                    "service": q.service,
                    "log_type": q.log_type,
                    "application": q.application,
                    "priority": q.priority
                }
                for q in queries
            ]

        return formatted_queries

    def _perform_ml_analysis(self, events: List[SecurityEvent]) -> Tuple[List[AnomalyDetection], List[ThreatPrediction]]:
        """Perform ML-powered anomaly detection and threat prediction."""
        ml_anomalies = []
        ml_predictions = []

        for event in events:
            # Detect anomalies
            anomaly_result = self.ml_engine.detect_anomaly(event, events)
            ml_anomalies.append(anomaly_result)

            # Predict threats
            prediction_result = self.ml_engine.predict_threat(event, events)
            ml_predictions.append(prediction_result)

        return ml_anomalies, ml_predictions
