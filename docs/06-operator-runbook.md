# 06 - Operator Runbook

## Daily Operations

### Health Checks

Verify all services are healthy:

```bash
# Check all service health endpoints
for port in 8080 8081 8082 8083 8084 8085 8086; do
  echo "Port $port: $(curl -s http://localhost:$port/health | jq -r '.status')"
done
```

Expected output:
```
Port 8080: healthy
Port 8081: healthy
Port 8082: healthy
Port 8083: healthy
Port 8084: healthy
Port 8085: healthy
Port 8086: healthy
```

### Check Pending Approvals

Review approval queue:

```bash
curl -s http://localhost:8084/v1/approvals?status=pending | jq '.count'
```

### Review Recent Events

Check telemetry for anomalies:

```bash
# Last 100 events
curl -s http://localhost:8085/v1/events?limit=100 | jq '.events[] | {type: .event_type, decision: .decision, agent: .agent_identity}'
```

## Component Inventory

### List All Components

```bash
curl -s http://localhost:8081/v1/components | jq '.components[] | {id, type, lifecycle, risk_tier}'
```

### View Component Details

```bash
curl -s http://localhost:8081/v1/components/agent:demo-coder | jq '.component'
```

### Register New Component

```bash
curl -X POST http://localhost:8081/v1/components \
  -H "Content-Type: application/json" \
  -d '{
    "id": "agent:new-agent",
    "type": "agent",
    "owner": "team-security",
    "purpose": "New coding assistant",
    "publisher": "internal",
    "version": "1.0.0",
    "content_hash": "sha256:abc123...",
    "definition_hash": "sha256:def456...",
    "risk_tier": 2,
    "permissions": {
      "files_read": ["/approved/workspace"],
      "files_write": ["/approved/output"],
      "shell": false,
      "network_allowlist": ["api.internal.example"]
    }
  }'
```

### Approve Component

```bash
curl -X PATCH http://localhost:8081/v1/components/agent:new-agent \
  -H "Content-Type: application/json" \
  -d '{"approval_status": "approved"}'
```

### Activate Component

```bash
curl -X POST http://localhost:8081/v1/components/agent:new-agent/activate
```

### Suspend Component

```bash
curl -X POST "http://localhost:8081/v1/components/agent:new-agent/suspend?reason=Security%20review%20required"
```

## Token Management

### List Active Tokens

```bash
curl -s http://localhost:8083/v1/tokens | jq '.tokens[] | {jti: .jti[:8], agent: .agent_identity, task: .task_id, revoked}'
```

### Revoke Token

```bash
curl -X POST http://localhost:8083/v1/revoke \
  -H "Content-Type: application/json" \
  -d '{"jti": "token-id-here", "reason": "Compromised agent"}'
```

### Revoke All Agent Tokens

```bash
curl -X POST "http://localhost:8083/v1/revoke-agent?agent_identity=agent:compromised&reason=Emergency%20revocation"
```

## Approval Workflow

### View Pending Approval

```bash
curl -s http://localhost:8084/v1/approvals/apr-abc-123 | jq '.'
```

### Approve Request

```bash
curl -X POST http://localhost:8084/v1/approvals/apr-abc-123/decide \
  -H "Content-Type: application/json" \
  -d '{
    "approved": true,
    "decided_by": "security-admin@example.com",
    "reason": "Verified safe operation after review"
  }'
```

### Deny Request

```bash
curl -X POST http://localhost:8084/v1/approvals/apr-abc-123/decide \
  -H "Content-Type: application/json" \
  -d '{
    "approved": false,
    "decided_by": "security-admin@example.com",
    "reason": "Suspicious destination - denied pending investigation"
  }'
```

## Kill Switch

### Activate Kill Switch

```bash
curl -X POST http://localhost:8086/v1/kill \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent:compromised",
    "task_ids": ["task-123", "task-456"],
    "reason": "Detected malicious behavior",
    "initiated_by": "security-ops"
  }'
```

### Check Kill Status

```bash
curl -s http://localhost:8086/v1/status/kill-abc123 | jq '.'
```

### View Kill History

```bash
curl -s http://localhost:8086/v1/status | jq '.kills'
```

## Incident Investigation

### Trace an Action

Get all events for a specific trace:

```bash
curl -s http://localhost:8085/v1/trace/trace-xyz789 | jq '.events'
```

### Find Events by Agent

```bash
curl -s "http://localhost:8085/v1/events?agent_identity=agent:suspicious" | jq '.events'
```

### Find Events by Task

```bash
curl -s "http://localhost:8085/v1/events?task_id=task-123" | jq '.events'
```

### Find Denied Actions

```bash
curl -s "http://localhost:8085/v1/events?event_type=read_file_denied" | jq '.events'
curl -s "http://localhost:8085/v1/events?event_type=write_file_denied" | jq '.events'
```

## Threat Hunting

### Find Path Traversal Attempts

Look for DENY decisions with "traversal" in reason:

```bash
curl -s http://localhost:8085/v1/events?limit=1000 | \
  jq '.events[] | select(.reason | contains("traversal"))'
```

### Find Unknown Components

```bash
curl -s http://localhost:8085/v1/events?limit=1000 | \
  jq '.events[] | select(.reason | contains("Unknown component"))'
```

### Find Untrusted Input Attempts

```bash
curl -s http://localhost:8085/v1/events?limit=1000 | \
  jq '.events[] | select(.reason | contains("untrusted"))'
```

### Find Shell Attempts

```bash
curl -s http://localhost:8085/v1/events?limit=1000 | \
  jq '.events[] | select(.operation == "run_command")'
```

### Find Egress Denials

```bash
curl -s http://localhost:8085/v1/events?limit=1000 | \
  jq '.events[] | select(.reason | contains("Egress denied"))'
```

## Common Scenarios

### Scenario: New Agent Deployment

1. Register component with proposed status
2. Review permissions and risk tier
3. Approve component
4. Activate component
5. Monitor initial operations

```bash
# 1. Register
curl -X POST http://localhost:8081/v1/components -d '...'

# 2. Review (manual)

# 3. Approve
curl -X PATCH http://localhost:8081/v1/components/agent:new -d '{"approval_status": "approved"}'

# 4. Activate
curl -X POST http://localhost:8081/v1/components/agent:new/activate

# 5. Monitor
watch -n 5 'curl -s "http://localhost:8085/v1/events?agent_identity=agent:new&limit=10" | jq -c ".events[]"'
```

### Scenario: Security Incident

1. Activate kill switch
2. Investigate events
3. Identify root cause
4. Remediate
5. Document and report

```bash
# 1. Kill switch
curl -X POST http://localhost:8086/v1/kill -d '{"agent_id": "agent:compromised", "reason": "Security incident", "initiated_by": "soc-analyst"}'

# 2. Get all events
curl -s "http://localhost:8085/v1/events?agent_identity=agent:compromised" > incident-events.json

# 3-5. Manual investigation
```

### Scenario: Maintenance Window

1. Suspend affected components
2. Perform maintenance
3. Reactivate components

```bash
# 1. Suspend
for agent in agent:a agent:b agent:c; do
  curl -X POST "http://localhost:8081/v1/components/$agent/suspend?reason=Maintenance"
done

# 2. Perform maintenance

# 3. Reactivate
for agent in agent:a agent:b agent:c; do
  curl -X POST "http://localhost:8081/v1/components/$agent/activate"
done
```

## Alerts

### Critical Alerts

| Condition | Action |
|-----------|--------|
| Kill switch activated | Investigate immediately |
| Multiple unknown agents | Review component inventory |
| Path traversal attempts | Block source, investigate |
| Shell execution attempts | Review agent permissions |
| Mass token revocation | Verify legitimate, check for attack |

### Warning Alerts

| Condition | Action |
|-----------|--------|
| Approval queue > 100 | Scale approval operators |
| PDP latency > 100ms | Check PDP resources |
| Registry unreachable | Fail closed, investigate |
| High denial rate | Review policies |

### Info Alerts

| Condition | Action |
|-----------|--------|
| New component registered | Review for approval |
| Component activated | Verify authorized |
| Token issued | Normal operation |

## Backup and Recovery

### Export Registry

```bash
curl -s http://localhost:8081/v1/components | jq '.' > registry-backup.json
```

### Export Telemetry

```bash
curl -s http://localhost:8085/v1/events?limit=10000 | jq '.' > telemetry-backup.json
```

### Restore Registry

For production, implement import endpoints or use database restore.

## Performance Tuning

### Cache TTL

Adjust Class A cache TTL:

```bash
LOCAL_CACHE_TTL_SECONDS=10  # Increase for lower PDP load
```

### PDP Timeout

Adjust PDP timeout for network conditions:

```bash
PDP_TIMEOUT_SECONDS=10  # Increase for high-latency networks
```

### Connection Pools

For production, configure httpx connection pools:

```python
limits = httpx.Limits(max_keepalive_connections=20, max_connections=100)
async with httpx.AsyncClient(limits=limits) as client:
    ...
```
