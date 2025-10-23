"""
Tests for Detection Engineering Agent

Tests detection analysis, tuning recommendations, TEST detection creation,
and detection gap analysis.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from vaulytica.agents.detection_engineering import (
    DetectionEngineeringAgent,
    DetectionPlatform,
    AlertOutcome,
    TuningAction,
    DetectionStatus,
    DetectionRule,
    AlertInstance,
    FalsePositivePattern,
    TuningRecommendation,
    DetectionAnalysis
)
from vaulytica.agents.framework import AgentInput, AgentContext, AgentStatus
from vaulytica.config import VaulyticaConfig


@pytest.fixture
def config():
    """Create test configuration"""
    return VaulyticaConfig(
        anthropic_api_key="sk-ant-test-key-12345678901234567890123456789012345678901234567890",
        datadog_api_key="test-dd-key",
        datadog_app_key="test-dd-app-key"
    )


@pytest.fixture
def agent(config):
    """Create Detection Engineering Agent"""
    return DetectionEngineeringAgent(config)


@pytest.fixture
def sample_detection():
    """Sample detection rule"""
    return {
        "id": "det-123",
        "name": "Suspicious API Access Pattern",
        "platform": "datadog",
        "query": "source:api-gateway @http.status_code:401 | count() > 5",
        "severity": "high",
        "threshold": 5,
        "timeframe_minutes": 5
    }


@pytest.fixture
def sample_alerts():
    """Sample alert data with outcomes"""
    alerts = []
    
    # 10 false positives from health checks
    for i in range(10):
        alerts.append({
            "id": f"alert-fp-{i}",
            "detection_name": "Suspicious API Access Pattern",
            "timestamp": (datetime.utcnow() - timedelta(days=i)).isoformat(),
            "outcome": "false_positive",
            "context": {
                "user_agent": "HealthCheck/1.0",
                "source_ip": "10.0.0.5"
            },
            "raw_logs": [
                {
                    "http.user_agent": "HealthCheck/1.0",
                    "network.client.ip": "10.0.0.5",
                    "http.status_code": 401
                }
            ],
            "analyst_notes": "Health check endpoint"
        })
    
    # 5 false positives from internal monitoring
    for i in range(5):
        alerts.append({
            "id": f"alert-fp-internal-{i}",
            "detection_name": "Suspicious API Access Pattern",
            "timestamp": (datetime.utcnow() - timedelta(days=i+10)).isoformat(),
            "outcome": "false_positive",
            "context": {
                "user_agent": "InternalMonitor/2.0",
                "source_ip": "10.0.1.10"
            },
            "raw_logs": [
                {
                    "http.user_agent": "InternalMonitor/2.0",
                    "network.client.ip": "10.0.1.10",
                    "http.status_code": 401
                }
            ],
            "analyst_notes": "Internal monitoring"
        })
    
    # 3 true positives
    for i in range(3):
        alerts.append({
            "id": f"alert-tp-{i}",
            "detection_name": "Suspicious API Access Pattern",
            "timestamp": (datetime.utcnow() - timedelta(days=i+15)).isoformat(),
            "outcome": "true_positive",
            "context": {
                "user_agent": "curl/7.68.0",
                "source_ip": "203.0.113.45"
            },
            "raw_logs": [
                {
                    "http.user_agent": "curl/7.68.0",
                    "network.client.ip": "203.0.113.45",
                    "http.status_code": 401
                }
            ],
            "analyst_notes": "Confirmed brute force attempt"
        })
    
    # 2 duplicates
    for i in range(2):
        alerts.append({
            "id": f"alert-dup-{i}",
            "detection_name": "Suspicious API Access Pattern",
            "timestamp": (datetime.utcnow() - timedelta(days=i+20)).isoformat(),
            "outcome": "duplicate",
            "context": {},
            "raw_logs": [],
            "analyst_notes": "Duplicate of previous alert"
        })
    
    return alerts


@pytest.mark.asyncio
async def test_analyze_detection(agent, sample_detection, sample_alerts):
    """Test detection analysis"""
    context = AgentContext(
        incident_id="test-001",
        workflow_id="workflow-001"
    )
    
    input_data = AgentInput(
        task="analyze_detection",
        context=context,
        parameters={
            "detection_id": "det-123",
            "timeframe_days": 30,
            "alerts": sample_alerts,
            "detection_rule": sample_detection
        }
    )
    
    result = await agent.execute(input_data)
    
    assert result.status == AgentStatus.COMPLETED
    assert "analysis" in result.results
    
    analysis = result.results["analysis"]
    assert analysis["detection_id"] == "det-123"
    assert analysis["statistics"]["total_alerts"] == 20
    assert analysis["statistics"]["true_positives"] == 3
    assert analysis["statistics"]["false_positives"] == 15
    assert analysis["statistics"]["false_positive_rate"] == 0.75  # 15/20
    
    # Should have identified FP patterns
    assert len(analysis["false_positive_patterns"]) > 0
    
    # Should have recommendations due to high FP rate
    assert analysis["recommendations_count"] > 0


@pytest.mark.asyncio
async def test_identify_fp_patterns(agent, sample_alerts):
    """Test false positive pattern identification"""
    # Parse alerts
    fp_alerts = []
    for alert_data in sample_alerts:
        if alert_data["outcome"] == "false_positive":
            alert = AlertInstance(
                id=alert_data["id"],
                detection_id="det-123",
                detection_name=alert_data["detection_name"],
                timestamp=datetime.fromisoformat(alert_data["timestamp"]),
                outcome=AlertOutcome.FALSE_POSITIVE,
                raw_logs=alert_data["raw_logs"],
                context=alert_data["context"],
                analyst_notes=alert_data["analyst_notes"]
            )
            fp_alerts.append(alert)
    
    patterns = await agent._identify_fp_patterns(fp_alerts)
    
    assert len(patterns) > 0
    
    # Should identify HealthCheck pattern (10 occurrences)
    health_check_pattern = next(
        (p for p in patterns if "HealthCheck" in str(p.field_value)),
        None
    )
    assert health_check_pattern is not None
    assert health_check_pattern.occurrences == 10
    assert health_check_pattern.percentage == 10/15  # 10 out of 15 FPs


@pytest.mark.asyncio
async def test_generate_recommendations(agent, sample_detection, sample_alerts):
    """Test tuning recommendation generation"""
    # First analyze
    context = AgentContext(
        incident_id="test-001",
        workflow_id="workflow-001"
    )
    
    analyze_input = AgentInput(
        task="analyze_detection",
        context=context,
        parameters={
            "detection_id": "det-123",
            "timeframe_days": 30,
            "alerts": sample_alerts,
            "detection_rule": sample_detection
        }
    )
    
    await agent.execute(analyze_input)
    
    # Then generate recommendations
    rec_input = AgentInput(
        task="generate_recommendations",
        context=context,
        parameters={
            "detection_id": "det-123"
        }
    )
    
    result = await agent.execute(rec_input)
    
    assert result.status == AgentStatus.COMPLETED
    assert "recommendations" in result.results
    
    recommendations = result.results["recommendations"]
    assert len(recommendations) > 0
    
    # Should have exclusion recommendations
    exclusion_recs = [r for r in recommendations if r["action"] == "add_exclusion"]
    assert len(exclusion_recs) > 0
    
    # Check recommendation structure
    rec = recommendations[0]
    assert "description" in rec
    assert "proposed_query" in rec
    assert "rationale" in rec
    assert "impact" in rec
    assert "confidence" in rec


@pytest.mark.asyncio
async def test_create_test_detection(agent, sample_detection, sample_alerts):
    """Test TEST detection creation"""
    context = AgentContext(
        incident_id="test-001",
        workflow_id="workflow-001"
    )
    
    # First analyze
    analyze_input = AgentInput(
        task="analyze_detection",
        context=context,
        parameters={
            "detection_id": "det-123",
            "timeframe_days": 30,
            "alerts": sample_alerts,
            "detection_rule": sample_detection
        }
    )
    
    await agent.execute(analyze_input)
    
    # Get recommendations
    rec_input = AgentInput(
        task="generate_recommendations",
        context=context,
        parameters={
            "detection_id": "det-123"
        }
    )
    
    rec_result = await agent.execute(rec_input)
    recommendations = rec_result.results["recommendations"]
    
    # Create TEST detection
    test_input = AgentInput(
        task="create_test_detection",
        context=context,
        parameters={
            "detection_id": "det-123",
            "recommendations": recommendations
        }
    )
    
    result = await agent.execute(test_input)
    
    assert result.status == AgentStatus.COMPLETED
    assert "test_detection" in result.results
    
    test_detection = result.results["test_detection"]
    assert test_detection["id"] == "det-123_TEST"
    assert "(TEST)" in test_detection["name"]
    assert test_detection["severity"] == "info"
    assert test_detection["status"] == "test"
    assert "test" in test_detection["tags"]


@pytest.mark.asyncio
async def test_compare_test_results(agent):
    """Test TEST vs PROD comparison"""
    context = AgentContext(
        incident_id="test-001",
        workflow_id="workflow-001"
    )
    
    # Simulate TEST alerts (fewer, better quality)
    test_alerts = [
        {"id": f"test-{i}", "outcome": "true_positive"}
        for i in range(3)
    ] + [
        {"id": f"test-fp-{i}", "outcome": "false_positive"}
        for i in range(2)
    ]
    
    # Simulate PROD alerts (more, worse quality)
    prod_alerts = [
        {"id": f"prod-{i}", "outcome": "true_positive"}
        for i in range(3)
    ] + [
        {"id": f"prod-fp-{i}", "outcome": "false_positive"}
        for i in range(15)
    ]
    
    input_data = AgentInput(
        task="compare_test_results",
        context=context,
        parameters={
            "test_detection_id": "det-123_TEST",
            "prod_detection_id": "det-123",
            "test_period_days": 14,
            "test_alerts": test_alerts,
            "prod_alerts": prod_alerts
        }
    )
    
    result = await agent.execute(input_data)
    
    assert result.status == AgentStatus.COMPLETED
    assert "comparison" in result.results
    
    comparison = result.results["comparison"]
    
    # TEST should have fewer alerts
    assert comparison["test_stats"]["total_alerts"] < comparison["prod_stats"]["total_alerts"]
    
    # TEST should have lower FP rate
    assert comparison["test_stats"]["fp_rate"] < comparison["prod_stats"]["fp_rate"]
    
    # Should recommend promotion
    assert comparison["recommendation"]["promote"] == True
    assert comparison["improvements"]["alert_reduction_percentage"] > 20


@pytest.mark.asyncio
async def test_detection_gap_analysis(agent):
    """Test detection gap analysis"""
    context = AgentContext(
        incident_id="test-001",
        workflow_id="workflow-001"
    )
    
    incidents = [
        {
            "id": "inc-001",
            "title": "Brute Force Attack",
            "severity": "high",
            "technique": "Brute Force",
            "tactic": "Credential Access",
            "description": "Multiple failed login attempts",
            "detected": False
        },
        {
            "id": "inc-002",
            "title": "Data Exfiltration",
            "severity": "critical",
            "technique": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "description": "Large data transfer to external IP",
            "detected": False
        },
        {
            "id": "inc-003",
            "title": "Malware Execution",
            "severity": "high",
            "technique": "User Execution",
            "tactic": "Execution",
            "description": "Suspicious process execution",
            "detected": True  # This one was detected
        }
    ]
    
    input_data = AgentInput(
        task="analyze_detection_gaps",
        context=context,
        parameters={
            "incidents": incidents,
            "existing_detections": []
        }
    )
    
    result = await agent.execute(input_data)
    
    assert result.status == AgentStatus.COMPLETED
    assert "gaps_found" in result.results
    
    # Should find 2 gaps (inc-001 and inc-002 were not detected)
    assert result.results["gaps_found"] == 2
    
    gaps = result.results["gaps"]
    assert len(gaps) == 2
    
    # Check gap structure
    gap = gaps[0]
    assert "incident_id" in gap
    assert "proposed_detection_name" in gap
    assert "proposed_detection_query" in gap
    assert "priority" in gap


def test_exclusion_query_generation_datadog(agent):
    """Test Datadog exclusion query generation"""
    current_query = "source:api-gateway @http.status_code:401 | count() > 5"
    
    exclusion_query = agent._generate_exclusion_query(
        current_query,
        "http.user_agent",
        "HealthCheck/1.0",
        DetectionPlatform.DATADOG
    )

    assert "-@http.user_agent:HealthCheck/1.0" in exclusion_query
    assert "count() > 5" in exclusion_query


def test_exclusion_query_generation_splunk(agent):
    """Test Splunk exclusion query generation"""
    current_query = "search source=auth action=login_failed | stats count by user"
    
    exclusion_query = agent._generate_exclusion_query(
        current_query,
        "user_agent",
        "HealthCheck",
        DetectionPlatform.SPLUNK
    )
    
    assert 'NOT user_agent="HealthCheck"' in exclusion_query


def test_threshold_increase(agent):
    """Test threshold increase"""
    current_query = "source:api-gateway @http.status_code:401 | count() > 5"
    
    increased_query = agent._increase_threshold_query(
        current_query,
        DetectionPlatform.DATADOG
    )
    
    # Should increase from 5 to 7 (5 * 1.5 = 7.5, rounded to 7)
    assert "count() > 7" in increased_query


def test_agent_statistics(agent):
    """Test agent statistics tracking"""
    stats = agent.get_statistics()
    
    assert "detections_analyzed" in stats
    assert "recommendations_generated" in stats
    assert "test_detections_created" in stats
    assert "detections_promoted" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

