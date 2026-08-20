.PHONY: help install test lint up down demo kill clean logs

PYTHON := python3
PYTEST := $(PYTHON) -m pytest
COMPOSE := docker compose

help:
	@echo "Agentic Endpoint Security - Development Commands"
	@echo ""
	@echo "  make install    Install dependencies"
	@echo "  make test       Run pytest test suite"
	@echo "  make lint       Run ruff linter"
	@echo "  make up         Start all services with docker compose"
	@echo "  make down       Stop all services"
	@echo "  make demo       Run demonstration scenarios"
	@echo "  make kill       Trigger kill switch demonstration"
	@echo "  make logs       Tail logs from all services"
	@echo "  make clean      Remove generated files and caches"

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTEST) -v --tb=short

test-cov:
	$(PYTEST) -v --cov=services --cov=packages --cov-report=term-missing

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

up:
	$(COMPOSE) up -d --build
	@echo "Services starting..."
	@echo "  Registry:    http://localhost:8081"
	@echo "  PDP:         http://localhost:8082"
	@echo "  Identity:    http://localhost:8083"
	@echo "  Broker:      http://localhost:8080"
	@echo "  Approval:    http://localhost:8084"
	@echo "  Telemetry:   http://localhost:8085"
	@echo "  Kill Switch: http://localhost:8086"
	@echo "  Demo Agent:  http://localhost:8090"

down:
	$(COMPOSE) down

demo:
	@./scripts/demo.sh

kill:
	@echo "Triggering kill switch for demo-coder agent..."
	@curl -s -X POST http://localhost:8086/v1/kill \
		-H "Content-Type: application/json" \
		-d '{"agent_id": "agent:demo-coder", "reason": "manual kill switch test"}' | jq .

logs:
	$(COMPOSE) logs -f

clean:
	rm -rf __pycache__ .pytest_cache .ruff_cache .coverage htmlcov dist build *.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
