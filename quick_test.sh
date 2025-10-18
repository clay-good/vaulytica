#!/bin/bash
# Quick validation test for Vaulytica

echo "================================================================================"
echo "VAULYTICA v0.17.0 - QUICK VALIDATION TEST"
echo "================================================================================"
echo ""

# Test 1: Check Python version
echo "TEST 1: Python Version"
python3 --version
echo ""

# Test 2: Check file structure
echo "TEST 2: File Structure"
echo "Checking critical files..."
files=(
    "vaulytica/__init__.py"
    "vaulytica/models.py"
    "vaulytica/config.py"
    "vaulytica/api.py"
    "vaulytica/cli.py"
    "requirements.txt"
    "setup.py"
    "Dockerfile"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file - MISSING"
    fi
done
echo ""

# Test 3: Check Python syntax
echo "TEST 3: Python Syntax Check"
echo "Checking Python files for syntax errors..."
python3 -m py_compile vaulytica/models.py 2>&1 && echo "✅ models.py" || echo "❌ models.py"
python3 -m py_compile vaulytica/config.py 2>&1 && echo "✅ config.py" || echo "❌ config.py"
python3 -m py_compile vaulytica/api.py 2>&1 && echo "✅ api.py" || echo "❌ api.py"
echo ""

# Test 4: Test basic imports
echo "TEST 4: Basic Imports"
python3 << 'EOF'
import sys
try:
    from vaulytica.models import SecurityEvent, Severity, EventCategory
    print("✅ Import models")
except Exception as e:
    print(f"❌ Import models: {e}")
    sys.exit(1)

try:
    from vaulytica.config import VaulyticaConfig
    print("✅ Import config")
except Exception as e:
    print(f"❌ Import config: {e}")
    sys.exit(1)

try:
    from vaulytica.logger import get_logger
    print("✅ Import logger")
except Exception as e:
    print(f"❌ Import logger: {e}")
    sys.exit(1)
EOF
echo ""

# Test 5: Test parser imports
echo "TEST 5: Parser Imports"
python3 << 'EOF'
import sys
try:
    from vaulytica.parsers.guardduty import GuardDutyParser
    print("✅ GuardDuty parser")
except Exception as e:
    print(f"❌ GuardDuty parser: {e}")

try:
    from vaulytica.parsers.gcp_scc import GCPSCCParser
    print("✅ GCP SCC parser")
except Exception as e:
    print(f"❌ GCP SCC parser: {e}")

try:
    from vaulytica.parsers.snowflake import SnowflakeParser
    print("✅ Snowflake parser")
except Exception as e:
    print(f"❌ Snowflake parser: {e}")
EOF
echo ""

# Test 6: Count lines of code
echo "TEST 6: Code Statistics"
echo "Lines of code:"
find vaulytica -name "*.py" -exec wc -l {} + | tail -1
echo ""

# Test 7: Check test data
echo "TEST 7: Test Data Files"
test_files=$(ls test_data/*.json 2>/dev/null | wc -l)
echo "Test data files found: $test_files"
if [ $test_files -gt 0 ]; then
    ls test_data/*.json | head -5
fi
echo ""

# Test 8: Check documentation
echo "TEST 8: Documentation"
docs=(
    "README.md"
    "DEPLOYMENT.md"
    "PRODUCTION_READY.md"
    "TESTING_REPORT.md"
    "VALIDATION_REPORT.md"
)

for doc in "${docs[@]}"; do
    if [ -f "$doc" ]; then
        size=$(wc -c < "$doc" | awk '{print int($1/1024)"KB"}')
        echo "✅ $doc ($size)"
    else
        echo "❌ $doc - MISSING"
    fi
done
echo ""

echo "================================================================================"
echo "VALIDATION COMPLETE"
echo "================================================================================"

