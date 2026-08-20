# 05 - Deployment Guide

## Local Development

### Prerequisites

- Python 3.12+
- pip or uv package manager
- Docker and Docker Compose (optional, for containerized deployment)

### Install Dependencies

```bash
# Using pip
pip install -e ".[dev]"

# Or using make
make install
```

### Run Tests

```bash
make test
```

### Run Services Locally

```bash
# Start individual services (in separate terminals)
uvicorn services.registry.app:app --port 8081
uvicorn services.pdp.app:app --port 8082
uvicorn services.identity.app:app --port 8083
uvicorn services.broker.app:app --port 8080
uvicorn services.approval.app:app --port 8084
uvicorn services.telemetry.app:app --port 8085
uvicorn services.killswitch.app:app --port 8086
uvicorn services.demo_agent.app:app --port 8090
```

## Docker Compose

### Start All Services

```bash
make up
```

This builds and starts all services:

| Service | Port | URL |
|---------|------|-----|
| Registry | 8081 | http://localhost:8081 |
| PDP | 8082 | http://localhost:8082 |
| Identity | 8083 | http://localhost:8083 |
| Broker | 8080 | http://localhost:8080 |
| Approval | 8084 | http://localhost:8084 |
| Telemetry | 8085 | http://localhost:8085 |
| Kill Switch | 8086 | http://localhost:8086 |
| Demo Agent | 8090 | http://localhost:8090 |

### View Logs

```bash
make logs
```

### Stop Services

```bash
make down
```

### Run Demo

```bash
make demo
```

## Staging Environment

### Additional Requirements

For staging, add:

- TLS certificates (self-signed or Let's Encrypt)
- External PostgreSQL or Redis (for persistent storage)
- Monitoring stack (Prometheus + Grafana)

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
# Staging environment
JWT_SECRET=<strong-random-secret>
APPROVAL_HMAC_SECRET=<strong-random-secret>
LOG_LEVEL=INFO
LOG_FORMAT=json
```

### Docker Compose Override

Create `docker-compose.staging.yml`:

```yaml
version: '3.8'

services:
  broker:
    environment:
      - LOG_LEVEL=INFO
      - PDP_TIMEOUT_SECONDS=10
    deploy:
      replicas: 2

  pdp:
    deploy:
      replicas: 2
```

Run with:

```bash
docker compose -f docker-compose.yml -f docker-compose.staging.yml up -d
```

## Production Environment

### Critical Requirements

| Requirement | Reference Implementation | Production |
|-------------|-------------------------|------------|
| TLS | None | Required (TLS 1.3) |
| IdP Integration | In-memory JWT | RFC 8693 token exchange |
| Token Revocation | In-memory set | Redis with TTL |
| Persistence | In-memory | PostgreSQL/Redis |
| HA | Single instance | Multi-instance + load balancer |
| Secrets | .env file | Vault/K8s secrets |
| Observability | Basic logging | OTEL + Prometheus + Grafana |
| EDR Integration | Logged | Real EDR API |
| Egress Control | Logged | Real firewall rules |

### TLS Configuration

All inter-service communication must use TLS:

```yaml
# Example nginx config for TLS termination
server {
    listen 443 ssl http2;
    server_name broker.internal.example;
    
    ssl_certificate /etc/ssl/certs/broker.crt;
    ssl_certificate_key /etc/ssl/private/broker.key;
    ssl_protocols TLSv1.3;
    
    location / {
        proxy_pass http://broker:8080;
    }
}
```

### IdP Integration

Replace the identity service with org IdP integration:

1. Configure RFC 8693 token exchange
2. Set up agent identity claims in IdP
3. Configure audience and scope validation
4. Enable token revocation via IdP

### Redis for Token Revocation

```python
# Production revocation with Redis
import redis

redis_client = redis.Redis(host='redis', port=6379, db=0)

def revoke_token(jti: str, ttl: int = 300):
    redis_client.setex(f"revoked:{jti}", ttl, "1")

def is_token_revoked(jti: str) -> bool:
    return redis_client.exists(f"revoked:{jti}")
```

### High Availability

For HA deployment:

1. Run multiple instances of each service
2. Use load balancer with health checks
3. Configure shared state (Redis/PostgreSQL)
4. Set up cross-datacenter replication

```yaml
# Kubernetes example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: broker
spec:
  replicas: 3
  selector:
    matchLabels:
      app: broker
  template:
    spec:
      containers:
      - name: broker
        image: agentic-security/broker:latest
        ports:
        - containerPort: 8080
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
```

### Secrets Management

Use Vault or Kubernetes secrets:

```yaml
# Kubernetes secret example
apiVersion: v1
kind: Secret
metadata:
  name: agentic-secrets
type: Opaque
data:
  JWT_SECRET: <base64-encoded>
  APPROVAL_HMAC_SECRET: <base64-encoded>
```

### Observability

Deploy full observability stack:

1. **Metrics**: Prometheus + Grafana
2. **Traces**: Jaeger/Zipkin (via OpenTelemetry)
3. **Logs**: Loki or Elasticsearch
4. **Alerts**: Alertmanager

### EDR Integration

Replace logged hooks with real EDR API calls:

```python
# Production EDR integration
async def edr_isolate(endpoint_id: str, reason: str):
    async with httpx.AsyncClient() as client:
        await client.post(
            f"{EDR_API_URL}/v1/endpoints/{endpoint_id}/isolate",
            json={"reason": reason},
            headers={"Authorization": f"Bearer {EDR_API_TOKEN}"}
        )
```

## Demo vs. Production Checklist

| Feature | Demo | Production |
|---------|------|------------|
| TLS | ❌ | ✅ Required |
| Real IdP | ❌ | ✅ Required |
| Redis revocation | ❌ | ✅ Required |
| Persistent storage | ❌ | ✅ Required |
| HA / clustering | ❌ | ✅ Required |
| Real EDR hooks | ❌ | ✅ Required |
| Real egress control | ❌ | ✅ Required |
| Secrets management | .env | Vault |
| Observability | Basic | Full stack |
| Backup/recovery | ❌ | ✅ Required |

## Rollback Procedures

### Service Rollback

```bash
# Tag current working version
docker tag broker:latest broker:last-known-good

# If deployment fails
docker compose down
docker tag broker:last-known-good broker:latest
docker compose up -d
```

### Database Rollback

For schema changes, use migration tools:

```bash
# Alembic example
alembic downgrade -1
```

### Kill Switch Rollback

If kill switch was activated incorrectly:

1. Reactivate component in registry
2. Clear revocation list (if using Redis, keys expire)
3. Clear terminated tasks in broker
4. Restart affected agent instances

## Limitations

### Reference Implementation Limitations

- No real file operations (simulated)
- No real network egress (simulated)
- No real EDR integration (logged)
- No persistent storage (in-memory)
- Single instance (no HA)
- No TLS (HTTP only)

### Out of Scope for MVP

- Computer-use / GUI automation
- Clipboard monitoring
- Screenshot controls
- Multi-tenant deployment
- Billing/metering
- UI for approval workflow

### Known Issues

1. Token revocation is in-memory (production needs Redis)
2. Approval service has no notification system
3. Telemetry has no retention/archival
4. Registry has no versioned component history
