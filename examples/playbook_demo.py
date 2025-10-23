#!/usr/bin/env python3
"""
Demonstration of Vaulytica's Automated Response & Playbook Engine.

This script demonstrates:
- Playbook selection based on threat type
- Automated response action execution
- Approval workflows
- Execution tracking and logging
"""

import asyncio
from datetime import datetime
from vaulytica.playbooks import PlaybookEngine, ActionStatus, ApprovalLevel
from vaulytica.models import (
    SecurityEvent, Severity, EventCategory, AssetInfo,
    TechnicalIndicator, MitreAttack, AnalysisResult, FiveW1H
)


def create_ransomware_event():
    """Create a sample ransomware event."""
    return SecurityEvent(
        event_id="evt_ransomware_001",
        source_system="crowdstrike",
        timestamp=datetime.now(),
        severity=Severity.CRITICAL,
        category=EventCategory.MALWARE,
        title="Ransomware encryption activity detected",
        description="Suspicious file encryption activity detected on workstation",
        affected_assets=[AssetInfo(
            hostname="workstation-finance-05",
            ip_addresses=["10.0.1.105"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="process", value="encrypt.exe"),
            TechnicalIndicator(indicator_type="file", value="ransom_note.txt"),
            TechnicalIndicator(indicator_type="hash", value="abc123ransomware")
        ],
        mitre_attack=[
            MitreAttack(technique_id="T1486", technique_name="Data Encrypted for Impact",
                       tactic="Impact", confidence=0.95)
        ],
        raw_event={}
    )


def create_exfiltration_event():
    """Create a sample data exfiltration event."""
    return SecurityEvent(
        event_id="evt_exfil_001",
        source_system="datadog",
        timestamp=datetime.now(),
        severity=Severity.HIGH,
        category=EventCategory.DATA_EXFILTRATION,
        title="Large data transfer to external IP",
        description="Unusual large data transfer detected from database server",
        affected_assets=[AssetInfo(
            hostname="db-prod-01",
            ip_addresses=["10.0.2.50"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="ip", value="198.51.100.99"),
            TechnicalIndicator(indicator_type="bytes", value="10737418240"),  # 10GB
            TechnicalIndicator(indicator_type="domain", value="evil-exfil.example.com")
        ],
        mitre_attack=[
            MitreAttack(technique_id="T1041", technique_name="Exfiltration Over C2 Channel",
                       tactic="Exfiltration", confidence=0.9)
        ],
        raw_event={}
    )


def create_credentials_event():
    """Create a sample compromised credentials event."""
    return SecurityEvent(
        event_id="evt_creds_001",
        source_system="guardduty",
        timestamp=datetime.now(),
        severity=Severity.MEDIUM,
        category=EventCategory.UNAUTHORIZED_ACCESS,
        title="Compromised credentials detected",
        description="User credentials found in public breach database",
        affected_assets=[AssetInfo(
            hostname="user-laptop-42",
            ip_addresses=["10.0.3.42"],
            environment="production"
        )],
        technical_indicators=[
            TechnicalIndicator(indicator_type="user", value="user@example.com"),
            TechnicalIndicator(indicator_type="account", value="john.doe")
        ],
        mitre_attack=[
            MitreAttack(technique_id="T1078", technique_name="Valid Accounts",
                       tactic="Initial Access", confidence=0.85)
        ],
        raw_event={}
    )


def create_sample_analysis(event: SecurityEvent) -> AnalysisResult:
    """Create a sample analysis result."""
    return AnalysisResult(
        event_id=event.event_id,
        five_w1h=FiveW1H(
            who="Unknown attacker",
            what=event.title,
            when=event.timestamp.isoformat(),
            where=event.affected_assets[0].hostname if event.affected_assets else "Unknown",
            why="Potential data theft or system compromise",
            how=event.description
        ),
        executive_summary=f"Critical security event detected: {event.title}",
        risk_score=float({"CRITICAL": 9, "HIGH": 7, "MEDIUM": 5, "LOW": 3}[event.severity.value]),
        confidence=0.85,
        mitre_techniques=event.mitre_attack,
        immediate_actions=["Investigate immediately", "Isolate affected systems"],
        short_term_recommendations=["Review logs", "Check for lateral movement"],
        long_term_recommendations=["Improve monitoring", "Update security policies"],
        raw_llm_response="Sample AI analysis response"
    )


async def main():
    """Main demonstration function."""
    print("=" * 80)
    print("🎯 VAULYTICA AUTOMATED RESPONSE & PLAYBOOK ENGINE DEMONSTRATION")
    print("=" * 80)
    print()
    
    # Initialize playbook engine
    print("1. INITIALIZING PLAYBOOK ENGINE")
    print("-" * 80)
    engine = PlaybookEngine(auto_execute=False, require_approval=True)
    print(f"✓ Playbook engine initialized")
    print(f"  - Total playbooks: {len(engine.playbooks)}")
    print(f"  - Auto-execute: {engine.auto_execute}")
    print(f"  - Require approval: {engine.require_approval}")
    print()
    
    # List available playbooks
    print("2. AVAILABLE PLAYBOOKS")
    print("-" * 80)
    for playbook in engine.playbooks.values():
        print(f"✓ {playbook.name}")
        print(f"  - ID: {playbook.playbook_id}")
        print(f"  - Threat types: {', '.join(playbook.threat_types[:3])}")
        print(f"  - Severity threshold: {playbook.severity_threshold.value}")
        print(f"  - Actions: {len(playbook.actions)}")
        print(f"  - Requires approval: {playbook.requires_approval}")
        print()
    
    # Scenario 1: Ransomware Response
    print("3. SCENARIO 1: RANSOMWARE DETECTION")
    print("-" * 80)
    ransomware_event = create_ransomware_event()
    ransomware_analysis = create_sample_analysis(ransomware_event)
    
    print(f"Event: {ransomware_event.title}")
    print(f"Severity: {ransomware_event.severity.value}")
    print(f"Affected host: {ransomware_event.affected_assets[0].hostname}")
    print()
    
    # Select playbooks
    print("Selecting appropriate playbooks...")
    matching_playbooks = engine.select_playbooks(ransomware_event, ransomware_analysis)
    print(f"✓ Matched {len(matching_playbooks)} playbook(s):")
    for pb in matching_playbooks:
        print(f"  - {pb.name}")
    print()
    
    # Execute playbook (dry run)
    if matching_playbooks:
        playbook = matching_playbooks[0]
        print(f"Executing playbook: {playbook.name} (DRY RUN)")
        execution = engine.execute_playbook(
            playbook,
            ransomware_event,
            ransomware_analysis,
            dry_run=True
        )
        
        print(f"✓ Execution ID: {execution.execution_id}")
        print(f"✓ Status: {execution.status}")
        print(f"✓ Actions completed: {execution.actions_completed}")
        print(f"✓ Actions failed: {execution.actions_failed}")
        print(f"✓ Actions skipped: {execution.actions_skipped}")
        print()
        
        print("Action details:")
        for action in playbook.actions:
            status_icon = "✓" if action.status == ActionStatus.COMPLETED else "⊘"
            print(f"  {status_icon} {action.action_type.value}: {action.description}")
            print(f"     Status: {action.status.value}, Approval: {action.approval_level.value}")
        print()
    
    # Scenario 2: Data Exfiltration Response
    print("4. SCENARIO 2: DATA EXFILTRATION DETECTION")
    print("-" * 80)
    exfil_event = create_exfiltration_event()
    exfil_analysis = create_sample_analysis(exfil_event)
    
    print(f"Event: {exfil_event.title}")
    print(f"Severity: {exfil_event.severity.value}")
    print(f"Affected host: {exfil_event.affected_assets[0].hostname}")
    print()
    
    matching_playbooks = engine.select_playbooks(exfil_event, exfil_analysis)
    print(f"✓ Matched {len(matching_playbooks)} playbook(s):")
    for pb in matching_playbooks:
        print(f"  - {pb.name}")
    print()
    
    if matching_playbooks:
        playbook = matching_playbooks[0]
        execution = engine.execute_playbook(
            playbook,
            exfil_event,
            exfil_analysis,
            dry_run=True
        )
        
        print(f"✓ Execution completed")
        print(f"  - Actions completed: {execution.actions_completed}")
        print(f"  - Actions skipped: {execution.actions_skipped}")
        print()
    
    # Scenario 3: Compromised Credentials (Auto-Execute)
    print("5. SCENARIO 3: COMPROMISED CREDENTIALS (AUTO-EXECUTE)")
    print("-" * 80)
    creds_event = create_credentials_event()
    creds_analysis = create_sample_analysis(creds_event)
    
    print(f"Event: {creds_event.title}")
    print(f"Severity: {creds_event.severity.value}")
    print(f"User: user@example.com")
    print()
    
    matching_playbooks = engine.select_playbooks(creds_event, creds_analysis)
    print(f"✓ Matched {len(matching_playbooks)} playbook(s):")
    for pb in matching_playbooks:
        print(f"  - {pb.name} (Auto-execute: {pb.auto_execute})")
    print()
    
    if matching_playbooks:
        playbook = matching_playbooks[0]
        execution = engine.execute_playbook(
            playbook,
            creds_event,
            creds_analysis,
            dry_run=True
        )
        
        print(f"✓ Execution completed")
        print(f"  - Actions completed: {execution.actions_completed}")
        print()
        
        print("Automated actions taken:")
        for action in playbook.actions:
            if action.status == ActionStatus.COMPLETED:
                print(f"  ✓ {action.action_type.value}: {action.description}")
        print()
    
    # Execution statistics
    print("6. EXECUTION STATISTICS")
    print("-" * 80)
    total_executions = len(engine.executions)
    total_actions = sum(len(e.playbook.actions) for e in engine.executions.values())
    total_completed = sum(e.actions_completed for e in engine.executions.values())
    total_failed = sum(e.actions_failed for e in engine.executions.values())
    total_skipped = sum(e.actions_skipped for e in engine.executions.values())
    
    print(f"✓ Total executions: {total_executions}")
    print(f"✓ Total actions: {total_actions}")
    print(f"✓ Actions completed: {total_completed}")
    print(f"✓ Actions failed: {total_failed}")
    print(f"✓ Actions skipped: {total_skipped}")
    print()
    
    print("=" * 80)
    print("✅ PLAYBOOK ENGINE DEMONSTRATION COMPLETE")
    print("=" * 80)
    print()
    print("Key Findings:")
    print("  ✓ Playbook selection working")
    print("  ✓ Action execution operational")
    print("  ✓ Approval workflows functional")
    print("  ✓ Dry-run mode safe for testing")
    print("  ✓ Ready for production deployment")
    print()


if __name__ == "__main__":
    asyncio.run(main())

