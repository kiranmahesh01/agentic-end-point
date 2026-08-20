# 04 - Architecture

## System Components

### Registry (:8081)

**Purpose**: Component inventory. Unknown component = DENY.

**Responsibilities**:
- Maintain inventory of all known components
- Store component metadata (type, owner, permissions, risk tier)
- Track lifecycle status (proposed, approved, active, suspended, retired)
- Verify component hash for capability integrity
- Provide quick verification endpoint for PDP

**Key Data**:
```json
{
  "id": "agent:demo-coder",
  "type": "agent",
  "owner": "demo-user",
  "purpose": "Demonstration coding agent",
  "publisher": "agentic-endpoint-security",
  "version": "1.0.0",
  "content_hash": "sha256:...",
  "definition_hash": "sha256:...",
  "risk_tier": 1,
  "approval_status": "approved",
  "lifecycle": "active",
  "permissions": {
    "files_read": ["/approved/workspace"],
    "files_write": ["/approved/output"],
    "shell": false,
    "network_allowlist": ["reports.internal.example"]
  }
}
```

### Policy Decision Point (PDP) (:8082)

**Purpose**: Evaluate action requests against policy.

**Responsibilities**:
- Receive action requests from broker
- Check required fields (fail closed on missing)
- Verify component with registry
- Evaluate path safety
- Check input trust rules
- Check permission boundaries
- Return decision (ALLOW, DENY, REQUIRE_APPROVAL, etc.)

**Policy Sources**:
- `policies/default.yaml` — Runtime configuration
- `policies/examples.rego` — OPA Rego documentation (not runtime)

### Identity Service (:8083)

**Purpose**: Issue and manage agent identity tokens.

**Responsibilities**:
- Issue short-lived (5 min) JWT tokens
- Bind tokens to user, agent, task, and intent
- Maintain revocation list
- Verify tokens on request
- Revoke all tokens for an agent (kill switch)

**Token Lifetime**: 300 seconds (5 minutes)

**Production**: Use RFC 8693 token exchange with org IdP

### Broker (:8080)

**Purpose**: Policy Enforcement Point (PEP). All actions flow through here.

**Responsibilities**:
- Receive typed adapter requests from agents
- Canonicalize paths and validate inputs
- Check for terminated tasks
- Consult PDP for authorization
- Execute allowed actions (simulated in reference impl)
- Cache Class A decisions (5 second TTL)
- Emit telemetry on every decision

**Typed Adapters**:
| Adapter | Operation | Class |
|---------|-----------|-------|
| `read_file` | Read a file | A |
| `write_file` | Write a file | B |
| `run_command` | Run a registered command | B |
| `http_request` | Make HTTP request | B |
| `load_model` | Load model artifact | B |

### Approval Service (:8084)

**Purpose**: Out-of-band human approval for sensitive operations.

**Responsibilities**:
- Create approval requests
- Store pending approvals
- Provide approval UI (external integration)
- Record decisions
- Generate HMAC-signed approval IDs

**Required Display Fields**:
- User
- Agent identity and version
- Endpoint
- Task
- Requested action
- Target resource
- Data classification
- Destination
- Diff (for write operations)

**Critical**: In-agent UI prompts do NOT count as approval.

### Telemetry Service (:8085)

**Purpose**: Collect and store audit events.

**Responsibilities**:
- Receive events from all services
- Redact sensitive data (secrets, chain of thought)
- Store events for querying
- Support trace-based queries
- Support filtering by agent, task, event type

**Redaction**: Automatic for passwords, secrets, tokens, API keys, chain of thought.

**OpenTelemetry**: GenAI semantic conventions (Development status, not stable).

### Kill Switch (:8086)

**Purpose**: Emergency agent termination.

**Responsibilities**:
- Suspend component in registry
- Revoke all tokens for agent
- Terminate active tasks in broker
- Log EDR isolate hook
- Log egress deny hook
- Record kill switch activation

**Order**: Registry → Identity → Broker → EDR → Egress

**Critical**: Does NOT send polite stop to agent.

## Risk Tiers

Components are assigned risk tiers 0-4:

| Tier | Risk Level | Autonomy | Approval | Monitoring |
|------|------------|----------|----------|------------|
| 0 | Minimal | High | Auto-approve reads | Standard |
| 1 | Low | Medium | Auto-approve reads | Standard |
| 2 | Medium | Low | Auto-approve reads | Enhanced |
| 3 | High | None | Require for writes | Enhanced |
| 4 | Critical | None | Require for all | Full audit |

## Component Lifecycle

```
proposed ──► approved ──► active ──► suspended ──► retired
    │            │           │           │
    │            │           │           └──► (can reactivate)
    │            │           │
    │            │           └──► (normal operation)
    │            │
    │            └──► (awaiting activation)
    │
    └──► (awaiting approval)
```

| State | Can Execute | Notes |
|-------|-------------|-------|
| `proposed` | No | Awaiting review |
| `approved` | No | Approved but not activated |
| `active` | Yes | Normal operation |
| `suspended` | No | Temporarily disabled |
| `retired` | No | Permanently disabled |

## Failure Modes

### Registry Unreachable

| Scenario | Behavior |
|----------|----------|
| Class A operation | Use cache if valid, else DENY |
| Class B operation | DENY (fail closed) |
| Class C operation | Queue if possible, else DENY |

### PDP Unreachable

| Scenario | Behavior |
|----------|----------|
| Class A operation | Use cache if valid, else DENY |
| Class B operation | DENY (fail closed) |
| Timeout | DENY after 5 seconds |

### Identity Service Unreachable

| Scenario | Behavior |
|----------|----------|
| Token request | Fail (agent cannot operate) |
| Token verification | Use cached verification if valid |
| Revocation | Queue for retry |

### Approval Service Unreachable

| Scenario | Behavior |
|----------|----------|
| Create approval | Queue request |
| Check approval | Return pending |
| Never auto-approve | Critical: degraded = queue |

### Telemetry Service Unreachable

| Scenario | Behavior |
|----------|----------|
| Event emission | Best effort, non-blocking |
| Failure | Log locally, retry later |
| Critical: Never block operations |

## Network Topology

```
                    ┌─────────────────────────────────────┐
                    │           Internal Network          │
                    │                                     │
  ┌─────────┐       │  ┌────────┐   ┌────────┐           │
  │  Agent  │ ──────┼──►  Broker  │───►  PDP   │           │
  └─────────┘       │  └────┬───┘   └────┬───┘           │
                    │       │            │                │
                    │       ▼            ▼                │
                    │  ┌────────┐   ┌────────┐           │
                    │  │Telemetry│   │Registry│           │
                    │  └────────┘   └────────┘           │
                    │                                     │
                    │  ┌────────┐   ┌────────┐           │
                    │  │Identity│   │Approval│           │
                    │  └────────┘   └────────┘           │
                    │                                     │
                    │  ┌────────┐                        │
                    │  │  Kill  │                        │
                    │  │ Switch │                        │
                    │  └────────┘                        │
                    │                                     │
                    └─────────────────────────────────────┘
                                    │
                                    ▼
                    ┌─────────────────────────────────────┐
                    │         External Network            │
                    │     (Egress via allowlist only)     │
                    └─────────────────────────────────────┘
```

## Data Flow

### Read Operation

```
Agent → Broker → (cache?) → PDP → Registry → Broker → Agent
                              ↓
                          Telemetry
```

### Write Operation (Approved)

```
Agent → Broker → PDP → Registry → Broker → Execute → Agent
                  ↓
              Telemetry
```

### Write Operation (Requires Approval)

```
Agent → Broker → PDP → REQUIRE_APPROVAL → Broker → Approval → (wait)
                  ↓                                    ↓
              Telemetry                           Telemetry
```

### Kill Switch

```
Operator → Kill Switch → Registry (suspend)
                      → Identity (revoke)
                      → Broker (terminate)
                      → EDR (hook)
                      → Firewall (hook)
                      → Telemetry (audit)
```
