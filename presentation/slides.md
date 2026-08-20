---
marp: true
theme: default
paginate: true
backgroundColor: #1a1a2e
color: #eaeaea
style: |
  section {
    font-family: 'Segoe UI', system-ui, sans-serif;
  }
  h1, h2 {
    color: #4fc3f7;
  }
  code {
    background-color: #2d2d44;
    color: #4fc3f7;
  }
  strong {
    color: #ff6b6b;
  }
  table {
    font-size: 0.8em;
  }
  th {
    background-color: #4fc3f7;
    color: #1a1a2e;
  }
---

# Agentic Endpoint Security

## Independent Execution Broker for AI Agents

**The agent proposes. The broker decides.**

---

<!-- _class: lead -->

# The Problem

Agents on endpoints misuse legitimate tools and valid credentials.

**The exploit is often a sentence—not malware.**

<!--
Speaker notes:
- Goal hijack, poisoned skill, inherited token
- Uses the same tools and APIs the user would
- EDR sees normal behavior from user's process
- This is not binary malware detection
-->

---

# Why Now?

- **Coding agents** in every IDE
- **Browser extensions** with full page access
- **MCP servers** exposing tools locally
- **Skills and plugins** extending capabilities
- **Local models** processing sensitive data

All acting as the user. All inheriting credentials.

<!--
Speaker notes:
- This isn't theoretical - agents are deployed today
- Each agent is a potential attack surface
- The human can't review every action
- We need automated controls
-->

---

# Threat Examples

| Attack | Vector | Impact |
|--------|--------|--------|
| **Goal Hijacking** | Prompt injection in data | Agent works for attacker |
| **Tool Poisoning** | Malicious skill definition | Arbitrary code execution |
| **Token Inheritance** | Over-delegated PAT | Full account compromise |
| **Confused Deputy** | Trusted agent, bad input | Secrets sent to attacker |

**CVE-2025-32711 (EchoLeak)**: Patched zero-click vuln in Copilot
*(Not a confirmed in-the-wild breach)*

<!--
Speaker notes:
- Goal hijacking: agent reads malicious doc, follows attacker instructions
- Tool poisoning: agent loads modified skill, executes backdoor
- EchoLeak was patched; demonstrates the attack class
-->

---

# Why EDR Is Not Enough

EDR stays mandatory. EDR sees the user's process.
EDR cannot see:

- Which **agent** performed the action
- The agent's **declared goal**
- Whether **input was trusted**
- If the **tool definition was modified**
- Whether action was **within scope**

<!--
Speaker notes:
- EDR monitors process behavior: files, network, registry
- But all agent actions look like user actions
- No visibility into agent identity or intent
- EDR is necessary, not sufficient
-->

---

# Architecture Thesis

> The agent **PROPOSES** actions.
> An independent PEP **DECIDES**.
> The kill switch **TERMINATES** without asking nicely.

Model classifier is an advisor, not a boundary.

```
Agent → Broker (PEP) → PDP → (Allow/Deny/Approval) → Execute
              ↓
          Telemetry
```

<!--
Speaker notes:
- Separation of concerns: agent proposes, PEP enforces
- PDP evaluates against policy
- Kill switch operates outside agent control
- Classifier can inform, cannot enforce
-->

---

# Nine Invariants

1. **Identity Separation** — Agent ≠ User
2. **Attenuated Delegation** — No raw user PAT
3. **Complete Mediation** — Every action through broker
4. **Least Agency** — Autonomy off by default
5. **Capability Integrity** — Hash tool definitions
6. **Context Isolation** — Tasks can't cross-access
7. **Fail-Closed Ambiguity** — Unknown = DENY
8. **Independent Containment** — Kill switch is external
9. **Evidence Preservation** — Audit everything

<!--
Speaker notes:
- These are non-negotiable principles
- Violation of any invariant is a security bug
- Defense in depth: multiple layers
-->

---

# How an Action Is Mediated

```
1. Agent calls broker.read_file("/workspace/data.txt")
2. Broker canonicalizes path, rejects traversal
3. Broker sends ActionRequest to PDP
4. PDP queries Registry: known? active? approved?
5. PDP checks permissions: can this agent read here?
6. PDP checks input trust: was input trusted?
7. PDP returns: ALLOW / DENY / REQUIRE_APPROVAL
8. Broker executes or returns error
9. Telemetry records decision
```

<!--
Speaker notes:
- Every step is a potential DENY point
- Fail closed at each stage
- Audit trail for every decision
-->

---

# Data Safety

- **No raw user PAT** — 5-minute scoped tokens
- **Default-deny egress** — Explicit allowlist
- **No raw shell** — Typed commands only
- **Writes in approved roots** — Path validation
- **Redacted telemetry** — No secrets in logs

```yaml
permissions:
  files_write: ["/approved/output"]
  network_allowlist: ["reports.internal.example"]
  shell: false  # Always
```

<!--
Speaker notes:
- Tokens expire in 5 minutes
- Network egress is whitelist, not blacklist
- Shell is never a raw string endpoint
-->

---

# Kill Switch

Not a polite stop. A hard kill.

1. **Suspend** component in registry (new actions fail)
2. **Revoke** all tokens for agent
3. **Terminate** task tree in broker
4. **Hook** EDR isolate
5. **Hook** egress deny

Order matters. Does not ask the agent nicely.

<!--
Speaker notes:
- Kill switch doesn't send "please stop" to agent
- Revokes credentials, suspends identity
- Hooks into EDR and firewall
- Order is critical for security
-->

---

# MVP Components

| Service | Port | Role |
|---------|------|------|
| Registry | 8081 | Component inventory |
| PDP | 8082 | Policy decisions |
| Identity | 8083 | Scoped tokens |
| Broker | 8080 | Typed PEP |
| Approval | 8084 | Out-of-band human |
| Kill Switch | 8086 | Emergency stop |
| Telemetry | 8085 | Audit events |

**Out of MVP**: Computer-use / GUI automation on user desktop

<!--
Speaker notes:
- Each service has a single responsibility
- Broker is the typed PEP - all actions flow through
- Computer-use requires different controls
-->

---

# Deploy Honestly

**Compose is demo.** Production is integration.

| Demo | Production |
|------|------------|
| In-memory JWT | RFC 8693 token exchange with IdP |
| Logged EDR hooks | Real EDR API integration |
| Logged egress hooks | Real firewall rules |
| No TLS | TLS everywhere |
| Single instance | HA cluster |

This runs **next to** EDR/IdP/DLP. Not a replacement.

<!--
Speaker notes:
- Be honest about what you're shipping
- Compose demonstrates the architecture
- Production requires real integrations
- This adds a layer, doesn't replace existing
-->

---

# 90-Day Ask

**Days 1-30**: Inventory and Contain
- Deploy reference implementation
- Catalog existing agents and skills
- Define approved roots and egress allowlist

**Days 31-60**: Integrate
- Connect to IdP (RFC 8693)
- Wire EDR isolate hooks
- Build approval workflows

**Days 61-90**: One Coding Agent
- Put one approved coding agent behind the control plane
- Monitor, tune, document
- Expand to next agent

<!--
Speaker notes:
- Start with visibility: what agents exist?
- Then add controls around one agent
- Learn before expanding
- 90 days to first controlled agent
-->

---

# Questions?

```bash
make test    # Run tests (72 passing)
make up      # Start services (Docker Compose)
make demo    # Run demo scenarios
```

**Docs**: `docs/01-problem.md` through `docs/06-operator-runbook.md`
**Deck**: `presentation/index.html` (self-contained)

<!--
Speaker notes:
- All code is in this repo
- Full documentation included
- Demo shows five key scenarios
- Questions welcome
-->
