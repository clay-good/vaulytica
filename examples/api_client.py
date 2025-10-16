#!/usr/bin/env python3
"""
Example client for Vaulytica REST API.

This script demonstrates how to interact with the Vaulytica API
for security event analysis.
"""

import json
import sys
from pathlib import Path
import requests
from typing import Dict, Any


class VaulyticaClient:
    """Client for Vaulytica REST API."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        """Initialize client with API base URL."""
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "VaulyticaClient/0.3.0"
        })
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health status."""
        response = self.session.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get system statistics."""
        response = self.session.get(f"{self.base_url}/stats")
        response.raise_for_status()
        return response.json()
    
    def analyze_event(
        self,
        source: str,
        event: Dict[str, Any],
        enable_rag: bool = True,
        enable_cache: bool = True,
        store_result: bool = True,
        timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Analyze a security event.
        
        Args:
            source: Source system type (guardduty, gcp-scc, datadog, crowdstrike, snowflake)
            event: Raw event data
            enable_rag: Enable historical incident correlation
            enable_cache: Enable analysis caching
            store_result: Store result in RAG database
            timeout: Request timeout in seconds
            
        Returns:
            Analysis result dictionary
        """
        payload = {
            "source": source,
            "event": event,
            "enable_rag": enable_rag,
            "enable_cache": enable_cache,
            "store_result": store_result
        }
        
        response = self.session.post(
            f"{self.base_url}/analyze",
            json=payload,
            timeout=timeout
        )
        response.raise_for_status()
        return response.json()


def print_analysis_result(result: Dict[str, Any]):
    """Pretty print analysis result."""
    print("\n" + "=" * 60)
    print("  VAULYTICA ANALYSIS RESULT")
    print("=" * 60)
    print()
    
    print(f"Event ID: {result['event_id']}")
    print(f"Risk Score: {result['risk_score']}/10")
    print(f"Confidence: {result['confidence'] * 100:.1f}%")
    print(f"Processing Time: {result['processing_time_seconds']:.2f}s")
    print(f"Cached: {'Yes' if result['cached'] else 'No'}")
    print()
    
    print("5W1H SUMMARY")
    print("-" * 60)
    for key, value in result['five_w1h'].items():
        print(f"  {key.upper()}: {value}")
    print()
    
    print("EXECUTIVE SUMMARY")
    print("-" * 60)
    print(f"  {result['executive_summary']}")
    print()
    
    if result['attack_chain']:
        print("ATTACK CHAIN")
        print("-" * 60)
        for i, step in enumerate(result['attack_chain'], 1):
            print(f"  {i}. {step}")
        print()
    
    if result['mitre_techniques']:
        print("MITRE ATT&CK TECHNIQUES")
        print("-" * 60)
        for technique in result['mitre_techniques']:
            print(f"  {technique['technique_id']}: {technique['technique_name']}")
            print(f"    Tactic: {technique['tactic']}")
            print(f"    Confidence: {technique['confidence'] * 100:.1f}%")
        print()
    
    if result['immediate_actions']:
        print("IMMEDIATE ACTIONS")
        print("-" * 60)
        for i, action in enumerate(result['immediate_actions'], 1):
            print(f"  {i}. {action}")
        print()
    
    print("=" * 60)


def main():
    """Main function."""
    if len(sys.argv) < 3:
        print("Usage: python api_client.py <source> <event_file>")
        print()
        print("Sources: guardduty, gcp-scc, datadog, crowdstrike, snowflake")
        print()
        print("Example:")
        print("  python api_client.py guardduty ../test_data/guardduty_crypto_mining.json")
        sys.exit(1)
    
    source = sys.argv[1]
    event_file = Path(sys.argv[2])
    
    if not event_file.exists():
        print(f"Error: File not found: {event_file}")
        sys.exit(1)
    
    # Load event data
    with open(event_file) as f:
        event_data = json.load(f)
    
    # Initialize client
    client = VaulyticaClient()
    
    # Check API health
    print("Checking API health...")
    try:
        health = client.health_check()
        print(f"✓ API is {health['status']}")
        print(f"  Version: {health['version']}")
        print(f"  RAG Incidents: {health['rag_incidents']}")
        print(f"  Cache Entries: {health['cache_entries']}")
    except requests.exceptions.RequestException as e:
        print(f"✗ API health check failed: {e}")
        print("  Make sure the API server is running:")
        print("  python -m vaulytica.cli serve")
        sys.exit(1)
    
    # Analyze event
    print(f"\nAnalyzing {source} event from {event_file}...")
    try:
        result = client.analyze_event(source, event_data)
        print_analysis_result(result)
        
        # Save result
        output_file = event_file.parent / f"{event_file.stem}_analysis.json"
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"\n✓ Analysis saved to: {output_file}")
        
    except requests.exceptions.HTTPError as e:
        print(f"\n✗ Analysis failed: {e}")
        if e.response is not None:
            try:
                error_detail = e.response.json()
                print(f"  Detail: {error_detail.get('detail', 'Unknown error')}")
            except:
                print(f"  Response: {e.response.text}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

