# 03 - Data Safety

## Core Principles

1. **No raw long-lived secrets** — Agents receive attenuated, short-lived credentials
2. **Default-deny egress** — Network access requires explicit allowlist entry
3. **Input provenance tracking** — Trusted vs. untrusted input is labeled
4. **Classification-aware controls** — Data sensitivity affects allowed operations
5. **Audit everything** — Every decision is logged (with secrets redacted)

## Credential Management

### No PAT Passthrough

The identity service does NOT relay existing credentials:

```
❌ WRONG: User PAT → Agent → API
   Agent has user's long-lived token
   Compromise = full user access

✓ RIGHT: User PAT → Identity Service → Scoped Token → Agent → Broker → API
   Agent has short-lived, scoped token
   Compromise = limited, time-bounded access
```

### Token Structure

Tokens are short-lived (5 minutes / 300 seconds) and scoped:

```json
{
  "iss": "agentic-endpoint-security",
  "sub": "user@example.com",
  "act": {
    "sub": "agent:demo-coder"
  },
  "aud": "agentic-endpoint-security",
  "scope": ["read:/approved/workspace", "write:/approved/output"],
  "device_id": "device-001",
  "agent_instance_id": "instance-abc",
  "task_id": "task-123",
  "intent_hash": "a1b2c3d4",
  "jti": "unique-token-id",
  "iat": 1724155200,
  "exp": 1724155500
}
```

Key properties:
- **5-minute expiry** — Limits exposure window
- **Scoped to task** — Cannot be reused for other tasks
- **Intent hash** — Links to declared goal
- **Revocable** — In-memory revocation list (Redis for production)

### Production: RFC 8693 Token Exchange

In production, use your organization's IdP with RFC 8693:

1. User authenticates to IdP
2. Agent requests token exchange
3. IdP issues scoped, short-lived token for agent
4. Token includes agent identity in `act` claim

## Egress Controls

### Default Deny

All network egress is denied unless explicitly allowed:

```yaml
egress_rules:
  default: deny
  require_allowlist: true
```

### Per-Component Allowlist

Each component specifies allowed destinations:

```json
{
  "id": "agent:demo-coder",
  "permissions": {
    "network_allowlist": ["reports.internal.example"]
  }
}
```

### Egress Decision Flow

```
Agent wants to access api.external.com
          │
          ▼
┌─────────────────────────┐
│ Is destination in       │
│ component's allowlist?  │
└────────┬────────────────┘
         │
    ┌────┴────┐
    │ YES     │ NO
    ▼         ▼
  ALLOW     DENY
```

## Data Classification

Actions include a `data_classification` field:

| Classification | Examples | Controls |
|---------------|----------|----------|
| `public` | Marketing content | Standard egress |
| `internal` | Employee directory | Internal egress only |
| `confidential` | Financial data | Approved egress only |
| `restricted` | PII, secrets | Requires approval |
| `unclassified` | Default | Treated as internal |

### Classification-Aware Rules

```yaml
# Example: Restricted data requires approval for egress
if data_classification == "restricted" and operation == "http_request":
    decision = REQUIRE_APPROVAL
```

## Input Trust Tracking

### Input Sources

The `input_source` field tracks where input came from:

- `user_direct` — Typed by authenticated user
- `user_file` — From user's file system
- `internal_api` — From internal systems
- `external_api` — From external systems
- `web_content` — From web pages
- `email_content` — From emails
- `clipboard` — From clipboard

### Trust Levels

The `input_trust` field summarizes trustworthiness:

| Trust Level | Sources | Allowed Operations |
|-------------|---------|-------------------|
| `trusted` | `user_direct` | All |
| `internal` | `internal_api`, `user_file` | All |
| `untrusted` | `web_content`, `email_content`, `external_api` | Read only |

### Untrusted Input + Operations

| Operation | Untrusted Input | Decision |
|-----------|-----------------|----------|
| `read_file` | Allowed | ALLOW |
| `write_file` | Requires human | REQUIRE_APPROVAL |
| `run_command` | Never | DENY |
| `http_request` | Requires human | REQUIRE_APPROVAL |
| `load_model` | Never | DENY |

## Memory and Context Isolation

### Task Isolation

Each task has its own context:
- Separate task ID
- Separate token
- Cannot access other tasks' data

### Agent Instance Isolation

Each agent instance:
- Has unique instance ID
- Cannot impersonate other instances
- Tokens are bound to instance

## Clipboard and Screenshot (Future)

> **Note**: GUI automation is out of scope for MVP

Future controls for GUI interaction:
- Clipboard access requires approval
- Screenshot data is classified as `restricted`
- Screen recording requires human approval

## Personal vs. Work Accounts

### Account Separation

Agents should use work accounts, not personal:

| Account Type | Access |
|--------------|--------|
| Work | Enterprise resources |
| Personal | Denied for enterprise use |

### Enforcement

The identity service validates account type:

```python
if account.type == "personal" and resource.type == "enterprise":
    return DENY("Personal accounts cannot access enterprise resources")
```

## Operator Checklist

### Data Safety Configuration

- [ ] Configure approved read/write roots
- [ ] Set up egress allowlist per component
- [ ] Define data classification rules
- [ ] Configure input trust mappings
- [ ] Set up token expiry (default 300s)
- [ ] Configure Redis for production revocation list

### Monitoring

- [ ] Alert on untrusted input + write attempts
- [ ] Alert on egress to non-allowed destinations
- [ ] Monitor token issuance rates
- [ ] Track approval queue depth
- [ ] Audit data classification usage

### Incident Response

- [ ] Document kill switch procedures
- [ ] Practice token revocation
- [ ] Test egress deny hooks
- [ ] Verify EDR isolate integration
- [ ] Maintain runbook for data breaches

## Secrets Handling

### Never in Telemetry

The telemetry service automatically redacts:

```python
REDACT_KEYS = {
    "password", "secret", "token", "api_key",
    "authorization", "credential", "private_key",
    "chain_of_thought", "reasoning", "thinking"
}
```

### Never in Logs

Application logs must not contain:
- Credentials of any kind
- API keys or tokens
- Private keys
- Model chain of thought
- Raw PII

### Secrets in Transit

All secrets should be:
- Encrypted in transit (TLS 1.3)
- Short-lived where possible
- Scoped to minimal permissions
- Revocable immediately

## DLP Integration (Future)

> **Note**: Full DLP integration is out of scope for MVP

Future DLP features:
- Content inspection before egress
- Pattern matching for sensitive data
- Automatic classification based on content
- Integration with enterprise DLP systems
