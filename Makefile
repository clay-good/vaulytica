.PHONY: help install install-dev test test-cov lint format clean run-example docker-build docker-run docker-stop compose-up compose-down k8s-deploy k8s-delete health

# Variables
IMAGE_NAME := vaulytica
IMAGE_TAG := 0.17.0
REGISTRY := your-registry.com
NAMESPACE := security

help:
	@echo "Vaulytica Development Commands"
	@echo "==============================="
	@echo ""
	@echo "Development:"
	@echo "  make install       - Install production dependencies"
	@echo "  make install-dev   - Install development dependencies"
	@echo "  make test          - Run unit tests"
	@echo "  make test-cov      - Run tests with coverage"
	@echo "  make lint          - Run code linters"
	@echo "  make format        - Format code with black"
	@echo "  make clean         - Clean build artifacts and cache"
	@echo "  make run-example   - Run example analysis"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build  - Build Docker image"
	@echo "  make docker-run    - Run Docker container"
	@echo "  make docker-stop   - Stop Docker container"
	@echo "  make docker-push   - Push to registry"
	@echo ""
	@echo "Docker Compose:"
	@echo "  make compose-up    - Start all services"
	@echo "  make compose-down  - Stop all services"
	@echo "  make compose-logs  - View logs"
	@echo ""
	@echo "Kubernetes:"
	@echo "  make k8s-deploy    - Deploy to Kubernetes"
	@echo "  make k8s-delete    - Delete from Kubernetes"
	@echo "  make k8s-status    - Check deployment status"
	@echo "  make k8s-logs      - View logs"
	@echo ""
	@echo "Health Checks:"
	@echo "  make health        - Check application health"
	@echo "  make ready         - Check readiness"
	@echo "  make metrics       - View metrics"
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

# Docker commands
docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_NAME):latest

docker-run:
	docker run -d \
		--name vaulytica \
		-p 8000:8000 \
		-e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
		-v $(PWD)/outputs:/app/outputs \
		-v $(PWD)/chroma_db:/app/chroma_db \
		$(IMAGE_NAME):$(IMAGE_TAG)

docker-stop:
	docker stop vaulytica || true
	docker rm vaulytica || true

docker-logs:
	docker logs -f vaulytica

docker-push:
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

# Docker Compose commands
compose-up:
	docker-compose up -d

compose-down:
	docker-compose down

compose-logs:
	docker-compose logs -f

compose-restart:
	docker-compose restart

# Kubernetes commands
k8s-create-namespace:
	kubectl create namespace $(NAMESPACE) || true

k8s-create-secrets:
	@echo "Creating secrets..."
	kubectl create secret generic vaulytica-secrets \
		--from-literal=anthropic-api-key="${ANTHROPIC_API_KEY}" \
		--namespace=$(NAMESPACE) \
		--dry-run=client -o yaml | kubectl apply -f -

k8s-deploy: k8s-create-namespace k8s-create-secrets
	kubectl apply -f k8s/ --namespace=$(NAMESPACE)

k8s-delete:
	kubectl delete -f k8s/ --namespace=$(NAMESPACE) || true

k8s-status:
	kubectl get all -n $(NAMESPACE)

k8s-logs:
	kubectl logs -f deployment/vaulytica -n $(NAMESPACE)

k8s-describe:
	kubectl describe deployment vaulytica -n $(NAMESPACE)

k8s-scale:
	kubectl scale deployment vaulytica --replicas=$(REPLICAS) -n $(NAMESPACE)

k8s-restart:
	kubectl rollout restart deployment/vaulytica -n $(NAMESPACE)

k8s-port-forward:
	kubectl port-forward -n $(NAMESPACE) deployment/vaulytica 8000:8000

# Health check commands
health:
	@curl -s http://localhost:8000/health | python3 -m json.tool

ready:
	@curl -s http://localhost:8000/ready | python3 -m json.tool

metrics:
	@curl -s http://localhost:8000/metrics

# Development server
dev:
	python3 -m vaulytica.cli serve --reload

# Backup
backup:
	@mkdir -p backups
	@tar czf backups/vaulytica-backup-$$(date +%Y%m%d-%H%M%S).tar.gz outputs/ chroma_db/
	@echo "Backup created in backups/"

