.PHONY: help install test lint up down demo kill clean logs certs

PYTHON := python3
PYTEST := $(PYTHON) -m pytest
COMPOSE := docker compose

help:
	@echo "Agentic Endpoint Security - Development Commands"
	@echo ""
	@echo "  make install    Install dependencies"
	@echo "  make test       Run pytest test suite"
	@echo "  make lint       Run ruff linter"
	@echo "  make certs      Generate TLS certificates for dev"
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

certs:
	@echo "Generating TLS certificates..."
	@./scripts/generate-certs.sh
	@echo "Certificates generated in ./certs/"
	@echo "To replace with org CA, see ./certs/README.md"

up:
	$(COMPOSE) up -d --build
	@echo ""
	@echo "Services starting..."
	@echo ""
	@echo "  Core Services:"
	@echo "    Registry:         http://localhost:8081"
	@echo "    PDP (HA LB):      http://localhost:8082"
	@echo "    Identity:         http://localhost:8083"
	@echo "    Broker (PEP):     http://localhost:8080"
	@echo "    Approval:         http://localhost:8084"
	@echo "    Telemetry:        http://localhost:8085"
	@echo "    Kill Switch:      http://localhost:8086"
	@echo ""
	@echo "  New Services:"
	@echo "    IdP (JWKS):       http://localhost:8443"
	@echo "    Egress Proxy:     http://localhost:8087"
	@echo "    EDR Sensor:       http://localhost:8088"
	@echo "    Isolated Desktop: http://localhost:8089"
	@echo ""
	@echo "  Infrastructure:"
	@echo "    Redis:            redis://localhost:6379"
	@echo ""
	@echo "  Demo:"
	@echo "    Demo Agent:       http://localhost:8090"
	@echo ""
	@echo "Run 'make demo' to execute demonstration scenarios"

down:
	$(COMPOSE) down -v

demo:
	@./scripts/demo.sh

kill:
	@echo "Triggering kill switch for demo-coder agent..."
	@echo "This will:"
	@echo "  1. Suspend component in registry"
	@echo "  2. Revoke all tokens"
	@echo "  3. Terminate active tasks"
	@echo "  4. ISOLATE via EDR sensor (real container isolation)"
	@echo "  5. BLOCK egress via proxy (real deny)"
	@echo ""
	@curl -s -X POST http://localhost:8086/v1/kill \
		-H "Content-Type: application/json" \
		-d '{"agent_id": "agent:demo-coder", "reason": "manual kill switch test", "task_ids": []}' | jq .

logs:
	$(COMPOSE) logs -f

logs-pdp:
	$(COMPOSE) logs -f pdp

logs-broker:
	$(COMPOSE) logs -f broker

logs-killswitch:
	$(COMPOSE) logs -f killswitch

logs-edr:
	$(COMPOSE) logs -f edr-sensor

health:
	@echo "Checking service health..."
	@curl -sf http://localhost:8081/health && echo "  Registry: OK" || echo "  Registry: FAIL"
	@curl -sf http://localhost:8082/health && echo "  PDP (LB): OK" || echo "  PDP (LB): FAIL"
	@curl -sf http://localhost:8083/health && echo "  Identity: OK" || echo "  Identity: FAIL"
	@curl -sf http://localhost:8080/health && echo "  Broker:   OK" || echo "  Broker:   FAIL"
	@curl -sf http://localhost:8084/health && echo "  Approval: OK" || echo "  Approval: FAIL"
	@curl -sf http://localhost:8085/health && echo "  Telemetry: OK" || echo "  Telemetry: FAIL"
	@curl -sf http://localhost:8086/health && echo "  Killswitch: OK" || echo "  Killswitch: FAIL"
	@curl -sf http://localhost:8443/health && echo "  IdP:      OK" || echo "  IdP:      FAIL"
	@curl -sf http://localhost:8087/health && echo "  Egress:   OK" || echo "  Egress:   FAIL"
	@curl -sf http://localhost:8088/health && echo "  EDR:      OK" || echo "  EDR:      FAIL"
	@curl -sf http://localhost:8089/health && echo "  Desktop:  OK" || echo "  Desktop:  FAIL"
	@curl -sf http://localhost:8090/health && echo "  Demo:     OK" || echo "  Demo:     FAIL"

clean:
	rm -rf __pycache__ .pytest_cache .ruff_cache .coverage htmlcov dist build *.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

clean-all: clean
	rm -rf certs/
	$(COMPOSE) down -v --rmi local
