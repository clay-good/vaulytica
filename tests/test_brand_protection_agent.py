"""
Test suite for Brand Protection Agent

Tests domain permutation generation, registration checking,
malicious intent validation, and C&D letter generation.
"""

import asyncio
import pytest
from datetime import datetime
from vaulytica.agents.brand_protection import (
    BrandProtectionAgent,
    ThreatLevel,
    TakedownStatus,
    PermutationTechnique,
    DomainPermutation,
    MaliciousIntentEvidence,
    ThreatValidation
)
from vaulytica.agents.framework import AgentInput, AgentContext, AgentStatus
from vaulytica.config import get_config


@pytest.fixture
def agent():
    """Create Brand Protection Agent for testing"""
    config = get_config()
    return BrandProtectionAgent(config)


@pytest.fixture
def sample_domain():
    """Sample domain for testing"""
    return "example.com"


class TestDomainPermutations:
    """Test domain permutation generation"""
    
    def test_generate_omissions(self, agent, sample_domain):
        """Test omission permutations"""
        domain_name = "example"
        tld = "com"
        
        omissions = agent._generate_omissions(domain_name, tld)
        
        assert len(omissions) > 0
        assert "exampl.com" in omissions  # Missing 'e'
        assert "exmple.com" in omissions  # Missing 'a'
        print(f"✅ Generated {len(omissions)} omission permutations")
    
    def test_generate_repetitions(self, agent, sample_domain):
        """Test repetition permutations"""
        domain_name = "example"
        tld = "com"
        
        repetitions = agent._generate_repetitions(domain_name, tld)
        
        assert len(repetitions) > 0
        assert "eexample.com" in repetitions  # Double 'e'
        assert "exaample.com" in repetitions  # Double 'a'
        print(f"✅ Generated {len(repetitions)} repetition permutations")
    
    def test_generate_transpositions(self, agent, sample_domain):
        """Test transposition permutations"""
        domain_name = "example"
        tld = "com"
        
        transpositions = agent._generate_transpositions(domain_name, tld)
        
        assert len(transpositions) > 0
        assert "xeample.com" in transpositions  # 'e' and 'x' swapped
        print(f"✅ Generated {len(transpositions)} transposition permutations")
    
    def test_generate_homoglyphs(self, agent, sample_domain):
        """Test homoglyph permutations"""
        domain_name = "example"
        tld = "com"
        
        homoglyphs = agent._generate_homoglyphs(domain_name, tld)
        
        assert len(homoglyphs) > 0
        # Check for some homoglyph replacements
        assert any("3" in h or "1" in h or "0" in h for h in homoglyphs)
        print(f"✅ Generated {len(homoglyphs)} homoglyph permutations")
    
    def test_generate_tld_variations(self, agent, sample_domain):
        """Test TLD variation permutations"""
        domain_name = "example"
        
        tld_variations = agent._generate_tld_variations(domain_name)
        
        assert len(tld_variations) > 0
        assert "example.net" in tld_variations
        assert "example.org" in tld_variations
        assert "example.io" in tld_variations
        print(f"✅ Generated {len(tld_variations)} TLD variations")
    
    def test_generate_subdomains(self, agent, sample_domain):
        """Test subdomain permutations"""
        domain_name = "example"
        tld = "com"
        
        subdomains = agent._generate_subdomains(domain_name, tld)
        
        assert len(subdomains) > 0
        assert "login-example.com" in subdomains
        assert "secure-example.com" in subdomains
        print(f"✅ Generated {len(subdomains)} subdomain permutations")
    
    def test_generate_hyphenations(self, agent, sample_domain):
        """Test hyphenation permutations"""
        domain_name = "example"
        tld = "com"
        
        hyphenations = agent._generate_hyphenations(domain_name, tld)
        
        assert len(hyphenations) > 0
        assert "e-xample.com" in hyphenations
        assert "ex-ample.com" in hyphenations
        print(f"✅ Generated {len(hyphenations)} hyphenation permutations")


class TestPermutationGeneration:
    """Test full permutation generation workflow"""
    
    @pytest.mark.asyncio
    async def test_generate_permutations_action(self, agent, sample_domain):
        """Test generate_permutations action"""
        input_data = AgentInput(
            task="generate_permutations",
            context=AgentContext(
                incident_id="test_001",
                workflow_id="test_workflow"
            ),
            parameters={
                "domain": sample_domain,
                "techniques": ["omission", "repetition", "homoglyph"]
            }
        )
        
        output = await agent.execute(input_data)
        
        assert output.status == AgentStatus.COMPLETED
        assert output.results["original_domain"] == sample_domain
        assert output.results["total_permutations"] > 0
        assert "omission" in output.results["permutations_by_technique"]
        assert "repetition" in output.results["permutations_by_technique"]
        assert "homoglyph" in output.results["permutations_by_technique"]
        
        print(f"✅ Generated {output.results['total_permutations']} total permutations")
        print(f"   - Omissions: {len(output.results['permutations_by_technique']['omission'])}")
        print(f"   - Repetitions: {len(output.results['permutations_by_technique']['repetition'])}")
        print(f"   - Homoglyphs: {len(output.results['permutations_by_technique']['homoglyph'])}")


class TestThreatScoring:
    """Test threat scoring algorithm"""
    
    def test_calculate_threat_score_high(self, agent):
        """Test high threat score calculation"""
        evidence = MaliciousIntentEvidence()
        
        # Mock URLScan result
        from vaulytica.urlscan_integration import URLScanResult, URLScanVerdict
        evidence.urlscan_result = URLScanResult(
            scan_id="test",
            url="https://example.com",
            verdict=URLScanVerdict.MALICIOUS,
            is_phishing=True,
            screenshot_url="https://example.com",
            brands_detected=["Example"],
            malicious_indicators=["Fake login form", "Credential harvesting"],
            scan_time=datetime.utcnow()
        )
        evidence.content_similarity = 0.9
        evidence.brand_impersonation = True
        
        # Mock WHOIS result
        from vaulytica.whois_integration import WHOISResult
        evidence.whois_result = WHOISResult(
            domain="test.com",
            registrar="Test Registrar",
            registration_date=datetime.utcnow(),
            age_days=5,
            is_recently_registered=True,
            registrant_name=None,  # Privacy protected
            risk_indicators=["Recently registered", "Privacy protected"]
        )
        
        score = agent._calculate_threat_score(evidence, "example.com")
        
        assert score >= 80  # Should be high threat
        print(f"✅ High threat score: {score}/100")
    
    def test_calculate_threat_score_low(self, agent):
        """Test low threat score calculation"""
        evidence = MaliciousIntentEvidence()
        
        # No URLScan or WHOIS data
        score = agent._calculate_threat_score(evidence, "example.com")
        
        assert score < 30  # Should be low threat
        print(f"✅ Low threat score: {score}/100")


class TestValidation:
    """Test input validation"""
    
    @pytest.mark.asyncio
    async def test_validate_input_missing_domain(self, agent):
        """Test validation with missing domain"""
        input_data = AgentInput(
            task="generate_permutations",
            context=AgentContext(
                incident_id="test_002",
                workflow_id="test_workflow"
            ),
            parameters={}  # Missing domain
        )

        with pytest.raises(ValueError, match="Domain parameter is required"):
            await agent.validate_input(input_data)

        print("✅ Validation correctly rejects missing domain")

    @pytest.mark.asyncio
    async def test_validate_input_missing_context(self, agent):
        """Test validation with missing context"""
        input_data = AgentInput(
            task="generate_permutations",
            context=None,  # Missing context
            parameters={"domain": "example.com"}
        )

        with pytest.raises(ValueError, match="AgentContext is required"):
            await agent.validate_input(input_data)

        print("✅ Validation correctly rejects missing context")


class TestStatistics:
    """Test agent statistics"""
    
    def test_get_statistics(self, agent):
        """Test statistics retrieval"""
        stats = agent.get_statistics()
        
        assert "permutations_generated" in stats
        assert "domains_checked" in stats
        assert "registered_domains_found" in stats
        assert "malicious_domains_detected" in stats
        assert "c_and_d_letters_generated" in stats
        assert "jira_tickets_created" in stats
        assert "domains_taken_down" in stats
        assert "cache_size" in stats
        assert "validation_cache_size" in stats
        assert "monitored_domains" in stats
        
        print("✅ Statistics structure is correct")
        print(f"   Cache size: {stats['cache_size']}")
        print(f"   Validation cache size: {stats['validation_cache_size']}")


class TestCeaseAndDesistGeneration:
    """Test C&D letter generation"""
    
    def test_build_cease_and_desist_letter(self, agent):
        """Test C&D letter building"""
        domain = "test-phishing.com"
        whois_info = {
            "registrar": "Test Registrar Inc.",
            "registration_date": "2025-10-15",
            "age_days": 6
        }
        urlscan_info = {
            "verdict": "malicious",
            "phishing_indicators": ["Fake login form", "Credential harvesting", "Brand mimicry"]
        }
        threat_score = 95.0
        content_similarity = 0.92
        
        letter = agent._build_cease_and_desist_letter(
            domain=domain,
            whois_info=whois_info,
            urlscan_info=urlscan_info,
            threat_score=threat_score,
            content_similarity=content_similarity
        )
        
        assert "CEASE AND DESIST LETTER" in letter
        assert domain in letter
        assert "Test Registrar Inc." in letter
        assert "Threat Score: 95/100" in letter
        assert "Content similarity: 92%" in letter
        assert "10 business days" in letter
        assert "trademark infringement" in letter.lower()
        
        print("✅ C&D letter generated successfully")
        print(f"   Letter length: {len(letter)} characters")


def run_tests():
    """Run all tests"""
    print("\n" + "="*60)
    print("BRAND PROTECTION AGENT - TEST SUITE")
    print("="*60 + "\n")
    
    config = get_config()
    agent = BrandProtectionAgent(config)
    sample_domain = "example.com"
    
    # Test domain permutations
    print("\n📋 Testing Domain Permutations...")
    test_perms = TestDomainPermutations()
    test_perms.test_generate_omissions(agent, sample_domain)
    test_perms.test_generate_repetitions(agent, sample_domain)
    test_perms.test_generate_transpositions(agent, sample_domain)
    test_perms.test_generate_homoglyphs(agent, sample_domain)
    test_perms.test_generate_tld_variations(agent, sample_domain)
    test_perms.test_generate_subdomains(agent, sample_domain)
    test_perms.test_generate_hyphenations(agent, sample_domain)
    
    # Test threat scoring
    print("\n🎯 Testing Threat Scoring...")
    test_scoring = TestThreatScoring()
    test_scoring.test_calculate_threat_score_high(agent)
    test_scoring.test_calculate_threat_score_low(agent)
    
    # Test validation
    print("\n✅ Testing Input Validation...")
    test_validation = TestValidation()
    asyncio.run(test_validation.test_validate_input_missing_domain(agent))
    asyncio.run(test_validation.test_validate_input_missing_context(agent))
    
    # Test statistics
    print("\n📊 Testing Statistics...")
    test_stats = TestStatistics()
    test_stats.test_get_statistics(agent)
    
    # Test C&D generation
    print("\n📄 Testing C&D Letter Generation...")
    test_cd = TestCeaseAndDesistGeneration()
    test_cd.test_build_cease_and_desist_letter(agent)
    
    print("\n" + "="*60)
    print("✅ ALL TESTS PASSED")
    print("="*60 + "\n")


if __name__ == "__main__":
    run_tests()

