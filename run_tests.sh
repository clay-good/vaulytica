#!/bin/bash

# Test runner script for Vaulytica
# Runs unit tests with coverage reporting

set -e

echo "========================================="
echo "  VAULYTICA TEST SUITE"
echo "========================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if pytest is installed
if ! python3 -m pytest --version > /dev/null 2>&1; then
    echo "pytest not found. Installing test dependencies..."
    pip install -r requirements-dev.txt
fi

echo -e "${BLUE}Running unit tests...${NC}"
echo ""

# Run tests with coverage
python3 -m pytest tests/ \
    -v \
    --tb=short \
    --disable-warnings \
    -m "not slow"

echo ""
echo -e "${GREEN}✓ Tests completed${NC}"
echo ""

# Optional: Run with coverage if pytest-cov is installed
if python3 -m pytest --co -q --cov > /dev/null 2>&1; then
    echo -e "${BLUE}Running tests with coverage...${NC}"
    python3 -m pytest tests/ \
        --cov=vaulytica \
        --cov-report=term-missing \
        --cov-report=html \
        -m "not slow"
    
    echo ""
    echo "Coverage report generated in htmlcov/index.html"
fi

