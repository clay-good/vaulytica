# Detection Engineering AI Agent

**Version**: 1.0.0 (Planned)
**Status**: Design Phase
**Target Release**: Q2 2026
**Last Updated**: 2025-10-21

---

## Overview

The Detection Engineering Agent analyzes Datadog security detections, raw logs, and resulting alerts to reduce alert fatigue and improve detection quality. It automatically tunes detections, creates TEST/DRAFT rules, and identifies detection gaps.

### Key Insight

**Alert Fatigue Reduction = Detection Engineering**

Rather than just suppressing alerts, this agent improves the underlying detection logic to reduce false positives while maintaining (or improving) true positive detection rates.

### Key Capabilities

- **Detection Analysis**: Analyze Datadog detection rules, raw logs, and alert outcomes
- **False Positive Reduction**: Identify patterns in false positives and recommend tuning
- **Automatic Test Detection Creation**: Generate TEST detections with proposed improvements
- **A/B Testing**: Run TEST detections in parallel with production for validation
- **Detection Gap Analysis**: Identify incidents that weren't detected and recommend new rules
- **Alert Outcome Tracking**: Learn from analyst decisions (true positive, false positive, duplicate)
- **Automated Tuning**: Apply approved tuning recommendations to production detections

---

## Architecture

### Detection Engineering Workflow

```
Datadog Detection Fires
    ↓
Alert Generated
    ↓
Security Analyst Reviews Alert
    ↓
Analyst Marks Outcome (TP/FP/Duplicate)
    ↓
AI Agent Learns from Outcome
    ↓
1. Analysis Phase
   - Analyze detection rule (query, threshold, conditions)
   - Analyze raw logs that triggered detection
   - Analyze alert metadata (severity, tags, context)
   - Track historical outcomes for this detection
    ↓
2. Pattern Recognition Phase
   - Identify false positive patterns
   - Identify true positive patterns
   - Calculate false positive rate
   - Identify common exclusion candidates
    ↓
3. Tuning Recommendation Phase
   - Generate tuning recommendations
   - Estimate impact (alerts reduced, TPs preserved)
   - Create TEST detection with proposed changes
    ↓
4. A/B Testing Phase
   - Deploy TEST detection in parallel
   - Run for 7-14 days
   - Compare results (TEST vs PROD)
   - Validate no missed true positives
    ↓
5. Approval & Deployment Phase
   - Present results to security team
   - Get approval for promotion
   - Promote TEST to PROD
   - Archive old detection
    ↓
6. Detection Gap Analysis Phase
   - Analyze incidents without detections
   - Recommend new detection rules
   - Generate draft detection queries
    ↓
Improved Detection Quality
```

---

## Detection Analysis

### Analyze Datadog Detection

```python
from vaulytica.agents.detection_engineering import DetectionEngineeringAgent

agent = DetectionEngineeringAgent(config)

# Analyze a specific detection
analysis = await agent.analyze_detection(
    detection_id="det-123",
    timeframe_days=30
)

# Output:
{
  "detection_id": "det-123",
  "detection_name": "Suspicious API Access Pattern",
  "query": "source:api-gateway @http.status_code:401 | count() > 5",
  "threshold": 5,
  "timeframe": "5 minutes",
  "severity": "HIGH",
  
  "statistics": {
    "total_alerts": 1250,
    "true_positives": 15,
    "false_positives": 1200,
    "duplicates": 35,
    "false_positive_rate": 0.96,  # 96% FP rate!
    "alerts_per_day": 41.7
  },
  
  "false_positive_patterns": [
    {
      "pattern": "user_agent contains 'HealthCheck'",
      "occurrences": 800,
      "percentage": 0.67
    },
    {
      "pattern": "source_ip in ['10.0.0.0/8']",
      "occurrences": 300,
      "percentage": 0.25
    }
  ],
  
  "true_positive_patterns": [
    {
      "pattern": "source_ip NOT in ['10.0.0.0/8', '172.16.0.0/12']",
      "occurrences": 15,
      "percentage": 1.0
    }
  ],
  
  "recommendation": {
    "action": "ADD_EXCLUSIONS",
    "estimated_alert_reduction": 0.92,  # 92% fewer alerts
    "estimated_tp_preservation": 1.0,   # 100% TPs preserved
    "confidence": 0.95
  }
}
```

---

## Tuning Recommendations

### Automatic Exclusion Generation

```python
# Generate tuning recommendations
recommendations = await agent.generate_tuning_recommendations(
    detection_id="det-123"
)

# Output:
{
  "detection_id": "det-123",
  "current_query": "source:api-gateway @http.status_code:401 | count() > 5",
  
  "recommendations": [
    {
      "type": "ADD_EXCLUSION",
      "description": "Exclude health check requests",
      "proposed_query": """
        source:api-gateway 
        @http.status_code:401 
        user@example.com_agent:*HealthCheck* 
        | count() > 5
      """,
      "impact": {
        "alerts_reduced": 800,
        "reduction_percentage": 0.64,
        "true_positives_affected": 0,
        "false_positives_reduced": 800
      },
      "confidence": 0.98
    },
    {
      "type": "ADD_EXCLUSION",
      "description": "Exclude internal network traffic",
      "proposed_query": """
        source:api-gateway 
        @http.status_code:401 
        user@example.com_agent:*HealthCheck*
        user@example.com:[10.0.0.0 TO 10.255.255.255]
        | count() > 5
      """,
      "impact": {
        "alerts_reduced": 300,
        "reduction_percentage": 0.24,
        "true_positives_affected": 0,
        "false_positives_reduced": 300
      },
      "confidence": 0.95
    },
    {
      "type": "INCREASE_THRESHOLD",
      "description": "Increase threshold from 5 to 10 failed attempts",
      "proposed_query": """
        source:api-gateway 
        @http.status_code:401 
        user@example.com_agent:*HealthCheck*
        user@example.com:[10.0.0.0 TO 10.255.255.255]
        | count() > 10
      """,
      "impact": {
        "alerts_reduced": 100,
        "reduction_percentage": 0.08,
        "true_positives_affected": 0,
        "false_positives_reduced": 100
      },
      "confidence": 0.85
    }
  ],
  
  "combined_impact": {
    "total_alerts_reduced": 1200,
    "reduction_percentage": 0.96,  # 96% fewer alerts
    "true_positives_preserved": 15,
    "false_positives_reduced": 1200,
    "new_false_positive_rate": 0.0  # 0% FP rate after tuning
  }
}
```

---

## Test Detection Creation

### Automatic TEST Detection Generation

```python
# Create TEST detection with proposed changes
test_detection = await agent.create_test_detection(
    detection_id="det-123",
    recommendations=recommendations
)

# Actions taken:
# 1. Create new detection in Datadog with "_TEST" suffix
# 2. Apply all recommended tuning changes
# 3. Set severity to INFO (don't page on-call)
# 4. Add tags: ["test", "detection-engineering", "original:det-123"]
# 5. Enable detection

# Output:
{
  "test_detection_id": "det-123-test",
  "test_detection_name": "Suspicious API Access Pattern_TEST",
  "status": "enabled",
  "severity": "INFO",
  "query": """
    source:api-gateway 
    @http.status_code:401 
    user@example.com_agent:*HealthCheck*
    user@example.com:[10.0.0.0 TO 10.255.255.255]
    | count() > 10
  """,
  "test_duration_days": 7,
  "comparison_url": "https://example.com"
}
```

---

## A/B Testing & Validation

### Compare TEST vs PROD Detection

```python
# Run A/B test for 7 days
comparison = await agent.compare_detections(
    original_detection_id="det-123",
    test_detection_id="det-123-test",
    duration_days=7
)

# Output:
{
  "test_duration_days": 7,
  "start_date": "2025-10-21",
  "end_date": "2025-10-28",
  
  "original_detection": {
    "detection_id": "det-123",
    "total_alerts": 292,
    "alerts_per_day": 41.7,
    "true_positives": 3,
    "false_positives": 285,
    "false_positive_rate": 0.97
  },
  
  "test_detection": {
    "detection_id": "det-123-test",
    "total_alerts": 5,
    "alerts_per_day": 0.7,
    "true_positives": 3,
    "false_positives": 2,
    "false_positive_rate": 0.40
  },
  
  "comparison": {
    "alert_reduction": 0.98,  # 98% fewer alerts
    "true_positives_preserved": 1.0,  # 100% TPs preserved
    "false_positives_reduced": 0.99,  # 99% FPs eliminated
    "missed_true_positives": 0,
    "new_false_positives": 2
  },
  
  "recommendation": {
    "action": "PROMOTE_TO_PRODUCTION",
    "confidence": 0.98,
    "reasoning": "Test detection reduced alerts by 98% while preserving all true positives. The 2 new false positives are acceptable given the massive reduction in alert volume."
  }
}
```

---

## Detection Gap Analysis

### Identify Missing Detections

```python
# Analyze incidents that weren't detected
gaps = await agent.analyze_detection_gaps(
    timeframe_days=90
)

# Output:
{
  "incidents_analyzed": 45,
  "incidents_with_detections": 38,
  "incidents_without_detections": 7,
  
  "detection_gaps": [
    {
      "incident_id": "inc-789",
      "incident_type": "credential_stuffing",
      "description": "Credential stuffing attack from distributed IPs",
      "why_not_detected": "No detection for distributed brute force attacks",
      "affected_systems": ["api-gateway", "auth-service"],
      
      "recommended_detection": {
        "name": "Distributed Credential Stuffing Attack",
        "query": """
          source:api-gateway 
          @http.status_code:401 
          @usr.id:* 
          | count_unique(@network.client.ip) > 10 
          AND count() > 50
        """,
        "description": "Detect credential stuffing from multiple IPs targeting same user",
        "severity": "HIGH",
        "threshold": "50 failed attempts from 10+ IPs in 5 minutes",
        "mitre_attack": ["T1110.004"],
        "confidence": 0.90
      }
    },
    {
      "incident_id": "inc-790",
      "incident_type": "data_exfiltration",
      "description": "Large data download from compromised account",
      "why_not_detected": "No detection for anomalous data transfer volume",
      
      "recommended_detection": {
        "name": "Anomalous Data Exfiltration",
        "query": """
          source:api-gateway 
          @http.method:GET 
          @http.response_size:>10000000 
          | sum(@http.response_size) > 100000000
        """,
        "description": "Detect unusually large data downloads (>100MB in 5 minutes)",
        "severity": "CRITICAL",
        "threshold": "100MB downloaded in 5 minutes",
        "mitre_attack": ["T1567"],
        "confidence": 0.85
      }
    }
  ]
}
```

---

## Alert Outcome Tracking

### Learn from Analyst Decisions

```python
# Track alert outcomes
await agent.record_alert_outcome(
    alert_id="alert-456",
    detection_id="det-123",
    outcome="FALSE_POSITIVE",
    analyst="user@example.com",
    reason="Health check traffic",
    tags=["health-check", "internal-traffic"]
)

# Agent learns:
# - This detection generates false positives for health checks
# - Analyst Alice consistently marks health check alerts as FP
# - Pattern: user_agent contains "HealthCheck" → FP
# - Recommendation: Add exclusion for health check traffic

# After 30 days of learning:
learning_summary = await agent.get_learning_summary(
    detection_id="det-123",
    timeframe_days=30
)

# Output:
{
  "detection_id": "det-123",
  "total_outcomes_recorded": 1250,
  "outcome_breakdown": {
    "true_positive": 15,
    "false_positive": 1200,
    "duplicate": 35
  },
  
  "learned_patterns": {
    "false_positive_indicators": [
      "user_agent contains 'HealthCheck'",
      "source_ip in internal_network",
      "time_of_day between 02:00-04:00 (maintenance window)"
    ],
    "true_positive_indicators": [
      "source_ip NOT in internal_network",
      "multiple_users_affected",
      "followed_by_successful_login"
    ]
  },
  
  "confidence_in_recommendations": 0.95
}
```

---

## Automated Tuning Workflow

### End-to-End Automation

```python
# Complete detection engineering workflow

# 1. Analyze all detections
all_detections = await agent.analyze_all_detections(
    min_alerts=100,  # Only analyze detections with >100 alerts
    min_fp_rate=0.5  # Only analyze detections with >50% FP rate
)

# 2. Generate recommendations for high-FP detections
for detection in all_detections:
    if detection.false_positive_rate > 0.5:
        recommendations = await agent.generate_tuning_recommendations(
            detection_id=detection.detection_id
        )
        
        # 3. Create TEST detection
        test_detection = await agent.create_test_detection(
            detection_id=detection.detection_id,
            recommendations=recommendations
        )
        
        # 4. Wait 7 days for A/B testing
        await asyncio.sleep(7 * 24 * 3600)
        
        # 5. Compare results
        comparison = await agent.compare_detections(
            original_detection_id=detection.detection_id,
            test_detection_id=test_detection.test_detection_id,
            duration_days=7
        )
        
        # 6. If successful, request approval
        if comparison.recommendation.action == "PROMOTE_TO_PRODUCTION":
            approval = await agent.request_approval(
                detection_id=detection.detection_id,
                test_detection_id=test_detection.test_detection_id,
                comparison=comparison,
                approvers=["user@example.com"]
            )
            
            # 7. If approved, promote to production
            if approval.approved:
                await agent.promote_test_detection(
                    test_detection_id=test_detection.test_detection_id,
                    original_detection_id=detection.detection_id
                )
```

---

## Configuration

```python
from vaulytica.agents.detection_engineering import DetectionEngineeringAgent

agent = DetectionEngineeringAgent(
    config=config,
    datadog_api_key="your-dd-api-key",
    datadog_app_key="your-dd-app-key",
    datadog_site="datadoghq.com",
    
    # Tuning parameters
    min_alerts_for_analysis=100,  # Minimum alerts before analyzing
    min_fp_rate_for_tuning=0.5,   # Minimum FP rate to trigger tuning
    test_duration_days=7,          # How long to run A/B tests
    auto_promote=False,            # Require human approval before promoting
    
    # Learning parameters
    learning_window_days=30,       # How far back to analyze outcomes
    min_confidence=0.85            # Minimum confidence for recommendations
)
```

---

## Metrics & Reporting

```python
# Get detection engineering metrics
metrics = await agent.get_metrics(timeframe_days=90)

# Output:
{
  "detections_analyzed": 45,
  "detections_tuned": 12,
  "test_detections_created": 12,
  "test_detections_promoted": 10,
  "test_detections_rejected": 2,
  
  "alert_volume_reduction": {
    "before_tuning": 15000,
    "after_tuning": 2500,
    "reduction_percentage": 0.83  # 83% fewer alerts
  },
  
  "false_positive_reduction": {
    "before_tuning": 14250,
    "after_tuning": 500,
    "reduction_percentage": 0.96  # 96% fewer false positives
  },
  
  "true_positive_preservation": {
    "before_tuning": 750,
    "after_tuning": 745,
    "preservation_rate": 0.99  # 99% TPs preserved
  },
  
  "time_saved": {
    "alerts_eliminated": 12500,
    "minutes_per_alert": 5,
    "total_hours_saved": 1041.7  # 1000+ hours saved
  }
}
```

---

## Best Practices

1. **Start with High-FP Detections**: Focus on detections with >50% false positive rate
2. **Run A/B Tests for 7-14 Days**: Ensure sufficient data for validation
3. **Require Human Approval**: Set auto_promote=False for safety
4. **Track Alert Outcomes**: Consistently mark alerts as TP/FP/Duplicate
5. **Monitor True Positive Rate**: Ensure tuning doesn't reduce detection capability
6. **Document Tuning Decisions**: Keep audit trail of all changes

---

## Support

For questions or feedback:
- GitHub Issues: https://example.com
- Documentation: https://docs.vaulytica.com

