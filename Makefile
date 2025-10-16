.PHONY: help install install-dev test test-cov lint format clean run-example

help:
	@echo "Vaulytica Development Commands"
	@echo "==============================="
	@echo ""
	@echo "  make install       - Install production dependencies"
	@echo "  make install-dev   - Install development dependencies"
	@echo "  make test          - Run unit tests"
	@echo "  make test-cov      - Run tests with coverage"
	@echo "  make lint          - Run code linters"
	@echo "  make format        - Format code with black"
	@echo "  make clean         - Clean build artifacts and cache"
	@echo "  make run-example   - Run example analysis"
	@echo ""

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt -r requirements-dev.txt

test:
	python3 -m pytest tests/ -v --tb=short --disable-warnings

test-cov:
	python3 -m pytest tests/ --cov=vaulytica --cov-report=term-missing --cov-report=html

lint:
	python3 -m ruff check vaulytica/
	python3 -m flake8 vaulytica/ --max-line-length=100 --ignore=E203,W503

format:
	python3 -m black vaulytica/ tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .pytest_cache/ .coverage htmlcov/
	rm -rf outputs/cache/*

run-example:
	@echo "Running example analysis..."
	python3 -m vaulytica.cli analyze test_data/guardduty_crypto_mining.json \
		--source guardduty \
		--output-html outputs/example.html \
		--output-json outputs/example.json
	@echo "✓ Analysis complete. Open outputs/example.html to view results."

