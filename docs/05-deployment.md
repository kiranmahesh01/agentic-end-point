# 05 - Deployment Guide

## Deploy Honestly

This reference implementation now includes **real working integrations**, not just logged hooks:

| Feature | This Repo | Production Swap-In |
|---------|-----------|-------------------|
| TLS | ✅ Dev CA + mTLS (make certs) | Org CA |
| IdP | ✅ Local IdP with RS256/JWKS | Org IdP via RFC 8693 |
| Token Revocation | ✅ Redis-backed | Same Redis or org IdP |
| Egress Control | ✅ Real proxy with default-deny | Org firewall API |
| EDR Isolation | ✅ Real container isolation via Docker API | Vendor EDR API |
| HA | ✅ PDP replicas + Redis shared state | K8s/ECS + managed Redis |
| Offline Mode | ✅ Class D fail-closed | Same |
| Computer-Use | ✅ Isolated Xvfb sandbox | Same (never operator desktop) |

**Vendor EDR/IdP/firewall are still swap-in points**, but this repo now actually:
- Issues RS256 JWTs from a local IdP with JWKS endpoint
- Denies egress at the proxy level (not just logs)
- Isolates containers via Docker API (not just logs)
- Fails closed when PDP is unreachable
- Shares revocation/approval/kill state via Redis

## Quick Start

```bash
# Generate TLS certificates
make certs

# Start all services (with TLS stack)
make up

# Run demo scenarios
make demo

# Test kill switch (real isolation + egress block)
make kill

# Check all service health
make health
```

## Local Development

### Prerequisites

- Python 3.12+
- pip or uv package manager
- Docker and Docker Compose
- OpenSSL (for certificate generation)

### Install Dependencies

```bash
make install
```

### Generate TLS Certificates

```bash
make certs
```

This creates a dev CA and per-service certificates in `./certs/`.

To replace with organization CA:
1. Replace `certs/ca.crt` with your org's CA certificate
2. Generate new service certs signed by your CA
3. Update SAN entries as needed for your DNS

### Run Tests

```bash
make test
```

### Run Services with Docker Compose

```bash
make up
```

This starts all services:

| Service | Port | URL | Description |
|---------|------|-----|-------------|
| Registry | 8081 | http://localhost:8081 | Component inventory |
| PDP (HA LB) | 8082 | http://localhost:8082 | Policy Decision Point |
| Identity | 8083 | http://localhost:8083 | Token management |
| Broker | 8080 | http://localhost:8080 | Policy Enforcement Point |
| Approval | 8084 | http://localhost:8084 | OOB approvals |
| Telemetry | 8085 | http://localhost:8085 | Event collection |
| Kill Switch | 8086 | http://localhost:8086 | Emergency termination |
| **IdP** | 8443 | http://localhost:8443 | Local IdP with JWKS |
| **Egress Proxy** | 8087 | http://localhost:8087 | Real egress deny |
| **EDR Sensor** | 8088 | http://localhost:8088 | Real container isolation |
| **Isolated Desktop** | 8089 | http://localhost:8089 | Xvfb sandbox |
| Demo Agent | 8090 | http://localhost:8090 | Test agent |
| **Redis** | 6379 | redis://localhost:6379 | Shared state |

### View Logs

```bash
make logs
# Or specific services:
make logs-pdp
make logs-broker
make logs-killswitch
make logs-edr
```

### Stop Services

```bash
make down
```

## Architecture with Real Integrations

```
┌─────────────────────────────────────────────────────────────────┐
│                        AGENTIC-NET (Docker)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐                      │
│  │  IdP    │    │ Redis   │    │ PDP x2  │◄─── Nginx LB         │
│  │ (JWKS)  │    │(shared) │    │  (HA)   │                      │
│  └────┬────┘    └────┬────┘    └────┬────┘                      │
│       │              │              │                            │
│  ┌────┴──────────────┴──────────────┴────┐                      │
│  │              BROKER (PEP)             │                      │
│  │  - Typed adapters only                │                      │
│  │  - Offline fail-closed                │                      │
│  │  - Policy cache for Class A           │                      │
│  └───────────────────┬───────────────────┘                      │
│                      │                                           │
│  ┌───────────────────┼───────────────────┐                      │
│  │                   │                   │                      │
│  ▼                   ▼                   ▼                      │
│  ┌─────────┐    ┌─────────┐    ┌─────────────┐                  │
│  │ Egress  │    │  EDR    │    │  Isolated   │                  │
│  │ Proxy   │    │ Sensor  │    │   Desktop   │                  │
│  │ (deny)  │    │(Docker) │    │   (Xvfb)    │                  │
│  └─────────┘    └─────────┘    └─────────────┘                  │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      DEMO-AGENT                              ││
│  │  (uses broker for all actions, can be isolated by kill)     ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## TLS Configuration

### Certificate Generation

The `make certs` command generates:
- CA certificate (`certs/ca.crt`)
- Per-service certificates and keys
- SAN entries for Docker DNS names

### mTLS Between Services

All internal communication uses mTLS when `TLS_ENABLED=true`:

```bash
TLS_ENABLED=true make up
```

### Replacing with Organization CA

1. Generate certificates signed by your org CA
2. Place them in `./certs/` with same naming convention
3. Update SAN entries for your DNS names
4. Restart services

## IdP Configuration

### Local IdP (Default)

The local IdP service provides:
- RS256-signed JWTs (5-minute expiry)
- JWKS endpoint at `/.well-known/jwks.json`
- OpenID Connect discovery at `/.well-known/openid-configuration`
- Token exchange endpoint (RFC 8693-compatible)

### Production IdP Integration

For production, configure RFC 8693 token exchange:

```python
# In production identity service
async def exchange_token(user_token: str, agent_identity: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{ORG_IDP_URL}/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token": user_token,
                "actor_token": agent_identity,
                "audience": "agentic-endpoint-security",
            }
        )
        return response.json()
```

## High Availability

### PDP Replicas

The compose file includes:
- 2 PDP replicas
- Nginx load balancer with health checks
- Automatic failover (broker retries other replica)

```yaml
pdp:
  deploy:
    replicas: 2
```

### Redis Shared State

All stateful services use Redis for:
- Token revocation list
- Approval queue
- Kill switch state
- Agent block list (egress proxy)

### Testing HA

```bash
# Kill one PDP replica
docker compose stop pdp-1

# Verify decisions still work
curl http://localhost:8082/health
```

## Egress Proxy

### Default Deny

The egress proxy enforces:
- Allowlist only (default: `reports.internal.example`)
- Per-agent blocking (kill switch integration)
- Real 403 denials (not just logs)

### Testing Egress Deny

```bash
# Check if destination is allowed
curl "http://localhost:8087/v1/check?destination=evil.com&agent_id=test"
# Returns: {"allowed": false, "reason": "Not in allowlist"}

# Block an agent
curl -X POST "http://localhost:8087/v1/block-agent?agent_id=agent:demo-coder"
```

## EDR Sensor

### Container Isolation

The EDR sensor can:
- Pause/stop containers via Docker API
- Disconnect containers from networks
- Log all isolation events

### Requirements

Requires Docker socket mount (in compose):

```yaml
edr-sensor:
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock
  privileged: true
```

### Testing Isolation

```bash
# Isolate a container
curl -X POST "http://localhost:8088/v1/isolate?agent_id=agent:demo-coder&container_name=demo-agent"

# Check container status
curl "http://localhost:8088/v1/status?container_name=demo-agent"
```

## Computer-Use (Isolated Desktop)

### Safety Guarantees

The isolated desktop service:
- Runs in Xvfb (virtual framebuffer)
- **NEVER** accesses the operator's real desktop
- No `/dev/input` access
- No host DISPLAY variable
- Templated RPA only (no raw click/keystream)

### High-Impact Templates

Require OOB approval:
- `submit_form`
- `close_window`
- `download_file`
- `execute_script`

### Testing

```bash
# List available templates
curl http://localhost:8089/v1/templates

# Execute a safe action
curl -X POST http://localhost:8089/v1/execute \
  -H "Content-Type: application/json" \
  -d '{"template_id": "click_button", "target_descriptor": "Submit"}'
```

## Offline Mode (Class D)

### Fail-Closed Behavior

When PDP/identity is unreachable:
- Class A reads from approved roots: **MAY proceed from cache**
- All Class B/C operations: **FAIL CLOSED**
  - No writes
  - No egress
  - No commands
  - No model load
  - No computer-use

### Testing Offline Mode

```bash
# Stop PDP
docker compose stop pdp

# Try a write (should fail)
# Try a read from approved root (should work from cache)
```

## Production Swap-In Points

| This Repo | Production Replacement |
|-----------|----------------------|
| Local IdP | Okta/Azure AD/Google via RFC 8693 |
| Redis | AWS ElastiCache / Azure Cache |
| Egress Proxy | Palo Alto / Zscaler API |
| EDR Sensor | CrowdStrike / Defender API |
| Xvfb Sandbox | Same (isolated container) |
| Docker Compose | Kubernetes / ECS |

## Demo vs. Production Checklist

| Feature | This Repo | Production |
|---------|-----------|------------|
| TLS/mTLS | ✅ Dev CA | ✅ Org CA |
| IdP (RS256/JWKS) | ✅ Local | ✅ Org IdP |
| Redis state | ✅ Local Redis | ✅ Managed Redis |
| HA (PDP replicas) | ✅ 2 replicas | ✅ 3+ replicas |
| Egress deny | ✅ Real proxy | ✅ Org firewall |
| EDR isolate | ✅ Docker API | ✅ Vendor API |
| Offline fail-closed | ✅ | ✅ |
| Computer-use sandbox | ✅ | ✅ |
| File operations | ❌ Simulated | ✅ Real |
| Persistent storage | ❌ In-memory | ✅ Database |

## Limitations

### Reference Implementation Limitations

- File operations are simulated (no real file I/O)
- Network egress through proxy is simulated (real deny, simulated forward)
- No UI for approval workflow
- No persistent database (Redis for state only)

### Out of Scope

- Multi-tenant deployment
- Billing/metering
- Clipboard monitoring
- Screenshot controls on operator desktop (computer-use is isolated only)
