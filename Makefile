.PHONY: help install dev-install test lint format type-check clean build docs

help:
	@echo "Vaulytica Development Commands"
	@echo "=================================="
	@echo "install        - Install package dependencies"
	@echo "dev-install    - Install package with dev dependencies"
	@echo "test           - Run tests with coverage"
	@echo "test-fast      - Run tests without coverage"
	@echo "lint           - Run linters (ruff)"
	@echo "format         - Format code with black"
	@echo "type-check     - Run type checking with mypy"
	@echo "check-all      - Run all checks (format, lint, type-check, test)"
	@echo "clean          - Remove build artifacts and cache"
	@echo "build          - Build package"
	@echo "docs           - Generate documentation"

install:
	poetry install --no-dev

dev-install:
	poetry install
	poetry run pre-commit install

test:
	poetry run pytest -v --cov=vaulytica --cov-report=term-missing --cov-report=html

test-fast:
	poetry run pytest -v

lint:
	poetry run ruff check vaulytica tests

format:
	poetry run black vaulytica tests
	poetry run ruff check --fix vaulytica tests

type-check:
	poetry run mypy vaulytica

check-all: format lint type-check test

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf .ruff_cache
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	poetry build

docs:
	@echo "Documentation generation coming soon..."

run-example:
	poetry run vaulytica --help

