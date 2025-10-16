#!/usr/bin/env python3
"""
Test script for Vaulytica webhook endpoints.

This script sends test events to webhook endpoints to verify they're working correctly.
"""

import json
import sys
import time
from pathlib import Path
import requests
from typing import Dict, Any


class WebhookTester:
    """Test webhook endpoints."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        """Initialize tester with API base URL."""
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "VaulyticaWebhookTester/0.3.0"
        })
    
    def test_health(self) -> bool:
        """Test API health."""
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=5)
            response.raise_for_status()
            health = response.json()
            print(f"✓ API is {health['status']}")
            print(f"  Version: {health['version']}")
            return True
        except Exception as e:
            print(f"✗ Health check failed: {e}")
            return False
    
    def test_guardduty_webhook(self, event_file: Path) -> bool:
        """Test GuardDuty webhook."""
        print("\n" + "=" * 60)
        print("Testing GuardDuty Webhook")
        print("=" * 60)
        
        try:
            with open(event_file) as f:
                event_data = json.load(f)
            
            response = self.session.post(
                f"{self.base_url}/webhooks/guardduty",
                json=event_data,
                headers={"x-amz-sns-message-type": "Notification"},
                timeout=10
            )
            response.raise_for_status()
            result = response.json()
            
            print(f"✓ Webhook accepted")
            print(f"  Status: {result['status']}")
            print(f"  Webhook ID: {result['webhook_id']}")
            print(f"  Events received: {result['events_received']}")
            print(f"  Message: {result['message']}")
            return True
            
        except requests.exceptions.HTTPError as e:
            print(f"✗ Webhook failed: {e}")
            if e.response is not None:
                try:
                    error = e.response.json()
                    print(f"  Detail: {error.get('detail', 'Unknown error')}")
                except:
                    print(f"  Response: {e.response.text}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
    
    def test_datadog_webhook(self) -> bool:
        """Test Datadog webhook."""
        print("\n" + "=" * 60)
        print("Testing Datadog Webhook")
        print("=" * 60)
        
        try:
            event_data = {
                "id": "test-signal-123",
                "title": "Suspicious activity detected",
                "message": "Multiple failed login attempts from unusual location",
                "severity": "high",
                "timestamp": int(time.time()),
                "tags": ["security", "authentication"],
                "source": "security_monitoring"
            }
            
            response = self.session.post(
                f"{self.base_url}/webhooks/datadog",
                json=event_data,
                timeout=10
            )
            response.raise_for_status()
            result = response.json()
            
            print(f"✓ Webhook accepted")
            print(f"  Status: {result['status']}")
            print(f"  Webhook ID: {result['webhook_id']}")
            print(f"  Events received: {result['events_received']}")
            print(f"  Message: {result['message']}")
            return True
            
        except requests.exceptions.HTTPError as e:
            print(f"✗ Webhook failed: {e}")
            if e.response is not None:
                try:
                    error = e.response.json()
                    print(f"  Detail: {error.get('detail', 'Unknown error')}")
                except:
                    print(f"  Response: {e.response.text}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
    
    def test_crowdstrike_webhook(self) -> bool:
        """Test CrowdStrike webhook."""
        print("\n" + "=" * 60)
        print("Testing CrowdStrike Webhook")
        print("=" * 60)
        
        try:
            event_data = {
                "event_type": "DetectionSummaryEvent",
                "severity": 4,
                "detection_id": "ldt:abc123def456",
                "timestamp": int(time.time()),
                "device": {
                    "device_id": "abc123",
                    "hostname": "workstation-01"
                },
                "behaviors": [
                    {
                        "behavior_id": "12345",
                        "tactic": "Execution",
                        "technique": "Command and Scripting Interpreter"
                    }
                ]
            }
            
            response = self.session.post(
                f"{self.base_url}/webhooks/crowdstrike",
                json=event_data,
                timeout=10
            )
            response.raise_for_status()
            result = response.json()
            
            print(f"✓ Webhook accepted")
            print(f"  Status: {result['status']}")
            print(f"  Webhook ID: {result['webhook_id']}")
            print(f"  Events received: {result['events_received']}")
            print(f"  Message: {result['message']}")
            return True
            
        except requests.exceptions.HTTPError as e:
            print(f"✗ Webhook failed: {e}")
            if e.response is not None:
                try:
                    error = e.response.json()
                    print(f"  Detail: {error.get('detail', 'Unknown error')}")
                except:
                    print(f"  Response: {e.response.text}")
            return False
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
    
    def wait_for_processing(self, seconds: int = 5):
        """Wait for background processing."""
        print(f"\nWaiting {seconds}s for background processing...")
        time.sleep(seconds)
    
    def check_stats(self):
        """Check system statistics."""
        print("\n" + "=" * 60)
        print("System Statistics")
        print("=" * 60)
        
        try:
            response = self.session.get(f"{self.base_url}/stats", timeout=5)
            response.raise_for_status()
            stats = response.json()
            
            print(f"RAG Database:")
            print(f"  Total incidents: {stats['rag_stats'].get('total_incidents', 0)}")
            
            print(f"\nCache:")
            print(f"  Total entries: {stats['cache_stats'].get('total_entries', 0)}")
            print(f"  Total size: {stats['cache_stats'].get('total_size_mb', 0):.2f} MB")
            
        except Exception as e:
            print(f"✗ Failed to get stats: {e}")


def main():
    """Main function."""
    print("\n" + "=" * 60)
    print("  VAULYTICA WEBHOOK TESTER")
    print("=" * 60)
    
    # Parse arguments
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    
    # Initialize tester
    tester = WebhookTester(base_url)
    
    # Test health
    print(f"\nTesting API at: {base_url}")
    if not tester.test_health():
        print("\n✗ API is not healthy. Make sure the server is running:")
        print("  python -m vaulytica.cli serve")
        sys.exit(1)
    
    # Run tests
    results = []
    
    # Test GuardDuty webhook
    guardduty_file = Path("test_data/webhook_guardduty_sns.json")
    if guardduty_file.exists():
        results.append(("GuardDuty", tester.test_guardduty_webhook(guardduty_file)))
    else:
        print(f"\n⚠ Skipping GuardDuty test: {guardduty_file} not found")
    
    # Test Datadog webhook
    results.append(("Datadog", tester.test_datadog_webhook()))
    
    # Test CrowdStrike webhook
    results.append(("CrowdStrike", tester.test_crowdstrike_webhook()))
    
    # Wait for processing
    tester.wait_for_processing(10)
    
    # Check stats
    tester.check_stats()
    
    # Summary
    print("\n" + "=" * 60)
    print("  TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    print("=" * 60)
    
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()

