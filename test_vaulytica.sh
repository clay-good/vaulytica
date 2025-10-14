#!/bin/bash

# Vaulytica Production Test Suite
# Comprehensive testing of all features and parsers

set -e

# Configuration
export ANTHROPIC_API_KEY=""
export TOKENIZERS_PARALLELISM=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Helper functions
print_header() {
    echo ""
    echo "========================================="
    echo "$1"
    echo "========================================="
    echo ""
}

print_test() {
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo -e "${BLUE}Test $TESTS_TOTAL: $1${NC}"
}

print_success() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}✓ PASS${NC}"
    echo ""
}

print_failure() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo -e "${RED}✗ FAIL: $1${NC}"
    echo ""
}

# Main test suite
print_header "VAULYTICA PRODUCTION TEST SUITE"

echo "Testing all features:"
echo "  - All 5 parsers (GuardDuty, GCP SCC, Datadog, CrowdStrike, Snowflake)"
echo "  - 5W1H quick summary"
echo "  - Output formats (JSON, Markdown, HTML)"
echo "  - Caching system"
echo "  - Batch processing"
echo "  - Error handling"
echo ""

# Test 1: GuardDuty Crypto Mining
print_test "GuardDuty Crypto Mining Detection"
if python3 -m vaulytica.cli analyze test_data/guardduty_crypto_mining.json \
    --source guardduty \
    --output-html outputs/test1_guardduty_crypto.html \
    --output-json outputs/test1_guardduty_crypto.json > /dev/null 2>&1; then
    if [ -f outputs/test1_guardduty_crypto.html ] && [ -f outputs/test1_guardduty_crypto.json ]; then
        print_success
    else
        print_failure "Output files not created"
    fi
else
    print_failure "Analysis failed"
fi

# Test 2: GuardDuty Ransomware
print_test "GuardDuty Ransomware Detection"
if python3 -m vaulytica.cli analyze test_data/guardduty_ransomware.json \
    --source guardduty \
    --output-html outputs/test2_guardduty_ransomware.html \
    --output-markdown outputs/test2_guardduty_ransomware.md > /dev/null 2>&1; then
    if grep -q "5W1H Quick Summary" outputs/test2_guardduty_ransomware.md; then
        print_success
    else
        print_failure "5W1H summary not found in Markdown"
    fi
else
    print_failure "Analysis failed"
fi

# Test 3: GCP SCC Privilege Escalation
print_test "GCP Security Command Center Privilege Escalation"
if python3 -m vaulytica.cli analyze test_data/gcp_scc_privilege_escalation.json \
    --source gcp-scc \
    --output-html outputs/test3_gcp_privesc.html > /dev/null 2>&1; then
    print_success
else
    print_failure "Analysis failed"
fi

# Test 4: Datadog Data Exfiltration
print_test "Datadog Data Exfiltration Detection"
if python3 -m vaulytica.cli analyze test_data/datadog_data_exfiltration.json \
    --source datadog \
    --output-html outputs/test4_datadog_exfil.html > /dev/null 2>&1; then
    print_success
else
    print_failure "Analysis failed"
fi

# Test 5: CrowdStrike Insider Threat
print_test "CrowdStrike Insider Threat Detection"
if python3 -m vaulytica.cli analyze test_data/crowdstrike_insider_threat.json \
    --source crowdstrike \
    --output-html outputs/test5_crowdstrike_insider.html > /dev/null 2>&1; then
    print_success
else
    print_failure "Analysis failed"
fi

# Test 6: Snowflake Data Exfiltration
print_test "Snowflake Data Exfiltration Detection"
if python3 -m vaulytica.cli analyze test_data/snowflake_data_exfiltration.json \
    --source snowflake \
    --output-html outputs/test6_snowflake_exfil.html \
    --output-json outputs/test6_snowflake_exfil.json > /dev/null 2>&1; then
    if grep -q "five_w1h" outputs/test6_snowflake_exfil.json; then
        print_success
    else
        print_failure "5W1H not found in JSON output"
    fi
else
    print_failure "Analysis failed"
fi

# Test 7: Snowflake Privilege Escalation
print_test "Snowflake Privilege Escalation Detection"
if python3 -m vaulytica.cli analyze test_data/snowflake_privilege_escalation.json \
    --source snowflake \
    --output-html outputs/test7_snowflake_privesc.html > /dev/null 2>&1; then
    print_success
else
    print_failure "Analysis failed"
fi

# Test 8: Snowflake Unauthorized Access
print_test "Snowflake Unauthorized Access Detection"
if python3 -m vaulytica.cli analyze test_data/snowflake_unauthorized_access.json \
    --source snowflake \
    --output-html outputs/test8_snowflake_unauth.html > /dev/null 2>&1; then
    print_success
else
    print_failure "Analysis failed"
fi

# Test 9: Cache Performance
print_test "Cache Performance (Re-analyze same event)"
START_TIME=$(date +%s)
if python3 -m vaulytica.cli analyze test_data/snowflake_data_exfiltration.json \
    --source snowflake \
    --output-html outputs/test9_cached.html > /dev/null 2>&1; then
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    if [ $DURATION -lt 5 ]; then
        echo "  Cache hit detected (${DURATION}s < 5s)"
        print_success
    else
        print_failure "Cache miss or slow performance (${DURATION}s)"
    fi
else
    print_failure "Analysis failed"
fi

# Test 10: Batch Processing
print_test "Batch Processing (GuardDuty events)"
if python3 -m vaulytica.cli batch test_data \
    --source guardduty \
    --pattern "guardduty*.json" \
    --output-report outputs/test10_batch_guardduty.json > /dev/null 2>&1; then
    if [ -f outputs/test10_batch_guardduty.json ]; then
        print_success
    else
        print_failure "Batch report not created"
    fi
else
    print_failure "Batch processing failed"
fi

# Test 11: Batch Processing (Snowflake events)
print_test "Batch Processing (Snowflake events)"
if python3 -m vaulytica.cli batch test_data \
    --source snowflake \
    --pattern "snowflake*.json" \
    --output-report outputs/test11_batch_snowflake.json > /dev/null 2>&1; then
    print_success
else
    print_failure "Batch processing failed"
fi

# Test 12: System Statistics
print_test "System Statistics"
if python3 -m vaulytica.cli stats > /dev/null 2>&1; then
    print_success
else
    print_failure "Stats command failed"
fi

# Test 13: Error Handling - Invalid File
print_test "Error Handling (Invalid file path)"
if python3 -m vaulytica.cli analyze nonexistent.json \
    --source guardduty \
    --output-html outputs/test13.html > /dev/null 2>&1; then
    print_failure "Should have failed with invalid file"
else
    echo "  Correctly handled invalid file"
    print_success
fi

# Test 14: Error Handling - Invalid Source
print_test "Error Handling (Invalid source type)"
if python3 -m vaulytica.cli analyze test_data/guardduty_crypto_mining.json \
    --source invalid_source \
    --output-html outputs/test14.html > /dev/null 2>&1; then
    print_failure "Should have failed with invalid source"
else
    echo "  Correctly handled invalid source"
    print_success
fi

# Test 15: All Output Formats
print_test "All Output Formats (JSON, Markdown, HTML)"
if python3 -m vaulytica.cli analyze test_data/guardduty_cryptojacking_advanced.json \
    --source guardduty \
    --output-json outputs/test15_all.json \
    --output-markdown outputs/test15_all.md \
    --output-html outputs/test15_all.html > /dev/null 2>&1; then
    if [ -f outputs/test15_all.json ] && \
       [ -f outputs/test15_all.md ] && \
       [ -f outputs/test15_all.html ]; then
        print_success
    else
        print_failure "Not all output files created"
    fi
else
    print_failure "Analysis failed"
fi

# Summary
print_header "TEST SUMMARY"

echo "Total Tests: $TESTS_TOTAL"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED!${NC}"
    echo ""
    echo "Generated Reports:"
    echo "  - outputs/test*.html (HTML reports)"
    echo "  - outputs/test*.json (JSON reports)"
    echo "  - outputs/test*.md (Markdown reports)"
    echo "  - outputs/test*_batch*.json (Batch reports)"
    echo ""
    echo "Open any HTML file in your browser to view professional reports."
    exit 0
else
    echo -e "${RED}SOME TESTS FAILED${NC}"
    echo "Check the output above for details."
    exit 1
fi

