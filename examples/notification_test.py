#!/usr/bin/env python3
"""
Test script for Vaulytica notification integrations.

This script demonstrates how to configure and test Slack, Teams, and Email notifications.
"""

import asyncio
import json
from pathlib import Path

from vaulytica.config import load_config
from vaulytica.parsers import GuardDutyParser
from vaulytica.agents import SecurityAnalystAgent
from vaulytica.notifications import NotificationManager, NotificationConfig
from vaulytica.models import AnalysisResult


async def test_notifications():
    """Test notification integrations."""
    
    print("🔔 Vaulytica Notification Test\n")
    print("=" * 60)
    
    # Load configuration
    try:
        config = load_config()
        print("✓ Configuration loaded")
    except Exception as e:
        print(f"✗ Failed to load configuration: {e}")
        return
    
    # Create notification config
    notification_config = NotificationConfig(
        slack_webhook_url=config.slack_webhook_url,
        slack_channel=config.slack_channel,
        teams_webhook_url=config.teams_webhook_url,
        smtp_host=config.smtp_host,
        smtp_port=config.smtp_port,
        smtp_username=config.smtp_username,
        smtp_password=config.smtp_password,
        smtp_from=config.smtp_from,
        smtp_to=config.smtp_to,
        min_risk_score=3,  # Lower threshold for testing
        notify_on_cache_hit=True
    )
    
    # Initialize notification manager
    notification_manager = NotificationManager(notification_config)
    print("✓ Notification manager initialized\n")
    
    # Check which channels are configured
    channels = []
    if notification_config.slack_webhook_url:
        channels.append("Slack")
    if notification_config.teams_webhook_url:
        channels.append("Microsoft Teams")
    if notification_config.smtp_host and notification_config.smtp_to:
        channels.append("Email")
    
    if not channels:
        print("⚠️  No notification channels configured!")
        print("\nTo configure notifications, set environment variables:")
        print("  - VAULYTICA_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...")
        print("  - VAULYTICA_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...")
        print("  - VAULYTICA_SMTP_HOST=smtp.gmail.com")
        print("  - VAULYTICA_SMTP_FROM=alerts@example.com")
        print("  - VAULYTICA_SMTP_TO=security@example.com")
        return
    
    print(f"📡 Configured channels: {', '.join(channels)}\n")
    
    # Create a mock analysis result for testing
    mock_result = AnalysisResult(
        event_id="test-event-12345",
        summary="Test security event: Cryptocurrency mining activity detected from EC2 instance i-1234567890abcdef0",
        risk_score=8.5,
        confidence=0.95,
        mitre_attack_techniques=[
            "T1496 - Resource Hijacking",
            "T1078 - Valid Accounts",
            "T1190 - Exploit Public-Facing Application"
        ],
        immediate_actions=[
            "Isolate the affected EC2 instance immediately",
            "Review CloudTrail logs for unauthorized API calls",
            "Check for additional compromised instances"
        ],
        short_term_recommendations=[
            "Implement network segmentation",
            "Enable GuardDuty threat detection",
            "Review IAM policies and permissions"
        ],
        long_term_recommendations=[
            "Implement zero-trust architecture",
            "Deploy EDR solution across all instances",
            "Conduct security awareness training"
        ],
        investigation_queries=[
            "SELECT * FROM cloudtrail WHERE instance_id = 'i-1234567890abcdef0'",
            "SELECT * FROM vpc_flow_logs WHERE src_ip = '10.0.1.50'"
        ],
        processing_time_seconds=2.5
    )
    
    print("📤 Sending test notification...\n")
    
    # Send notification
    try:
        results = await notification_manager.send_notification(
            result=mock_result,
            event_source="guardduty",
            cached=False
        )
        
        print("📊 Notification Results:")
        print("-" * 60)
        for channel, success in results.items():
            status = "✓ Success" if success else "✗ Failed"
            print(f"  {channel.capitalize()}: {status}")
        
        if not results:
            print("  No notifications sent (risk score below threshold or no channels configured)")
        
        print("\n" + "=" * 60)
        print("✅ Notification test complete!")
        
    except Exception as e:
        print(f"✗ Notification test failed: {e}")
    finally:
        await notification_manager.close()


async def test_with_real_analysis():
    """Test notifications with real analysis."""
    
    print("\n🔬 Testing with Real Analysis\n")
    print("=" * 60)
    
    # Load test data
    test_file = Path("test_data/guardduty_crypto_mining.json")
    if not test_file.exists():
        print(f"✗ Test file not found: {test_file}")
        return
    
    with open(test_file) as f:
        raw_event = json.load(f)
    
    print(f"✓ Loaded test event from {test_file}")
    
    # Parse event
    parser = GuardDutyParser()
    event = parser.parse(raw_event)
    print(f"✓ Parsed event: {event.event_id}")
    
    # Load configuration
    config = load_config()
    
    # Analyze event
    print("🤖 Analyzing event with Claude AI...")
    agent = SecurityAnalystAgent(config)
    result = await agent.analyze([event])
    print(f"✓ Analysis complete - Risk: {result.risk_score}/10")
    
    # Send notification
    notification_config = NotificationConfig(
        slack_webhook_url=config.slack_webhook_url,
        slack_channel=config.slack_channel,
        teams_webhook_url=config.teams_webhook_url,
        smtp_host=config.smtp_host,
        smtp_port=config.smtp_port,
        smtp_username=config.smtp_username,
        smtp_password=config.smtp_password,
        smtp_from=config.smtp_from,
        smtp_to=config.smtp_to,
        min_risk_score=3,
        notify_on_cache_hit=True
    )
    
    notification_manager = NotificationManager(notification_config)
    
    print("📤 Sending notification with real analysis...")
    results = await notification_manager.send_notification(
        result=result,
        event_source="guardduty",
        cached=False
    )
    
    print("\n📊 Notification Results:")
    print("-" * 60)
    for channel, success in results.items():
        status = "✓ Success" if success else "✗ Failed"
        print(f"  {channel.capitalize()}: {status}")
    
    await notification_manager.close()
    
    print("\n" + "=" * 60)
    print("✅ Real analysis notification test complete!")


def main():
    """Main entry point."""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--real":
        asyncio.run(test_with_real_analysis())
    else:
        asyncio.run(test_notifications())
        print("\n💡 Tip: Run with --real flag to test with actual AI analysis")


if __name__ == "__main__":
    main()

