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

AI agents act under your identity.
When compromised, they have your credentials.

**Compromise is a sentence, not a binary.**

<!--
Speaker notes:
- AI agents are proliferating: coding agents, browser extensions, IDE plugins
- They inherit user credentials and permissions
- Attack surface is a prompt, not a binary
- EDR can't distinguish agent actions from user actions
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
| **Tool Poisoning** | Malicious tool definition | Arbitrary code execution |
| **Credential Theft** | Over-delegated PAT | Full account compromise |
| **Data Exfiltration** | Confused deputy | Secrets sent to attacker |

**CVE-2025-32711 (EchoLeak)**: Zero-click prompt injection in Copilot

<!--
Speaker notes:
- Goal hijacking: agent reads malicious doc, follows attacker instructions
- Tool poisoning: agent loads modified tool, executes backdoor
- EchoLeak demonstrated real-world zero-click attack
-->

---

# Why EDR Is Not Enough

EDR sees the user's process.
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
- No policy engine for agent capabilities
-->

---

# Architecture Thesis

> The agent **PROPOSES** actions.
> An independent broker **DECIDES**.
> The kill switch **TERMINATES** without asking nicely.

```
Agent → Broker → PDP → (Allow/Deny/Approval) → Execute
           ↓
       Telemetry
```

<!--
Speaker notes:
- Separation of concerns: agent proposes, broker enforces
- PDP evaluates against policy
- Kill switch operates outside agent control
- Every decision is logged
-->

---

# Nine Invariants

1. **Identity Separation** — Agent ≠ User
2. **Attenuated Delegation** — Minimal credentials
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
2. Broker canonicalizes path, checks for traversal
3. Broker sends ActionRequest to PDP
4. PDP queries Registry: is this agent known? active? approved?
5. PDP checks permissions: can this agent read this path?
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

# Decision Outcomes

| Decision | Meaning |
|----------|---------|
| **ALLOW** | Execute the action |
| **DENY** | Reject immediately |
| **REQUIRE_APPROVAL** | Wait for human |
| **ALLOW_IN_SANDBOX** | Execute in isolation |
| **ISSUE_EPHEMERAL_CREDENTIAL** | Provide scoped token |
| **TERMINATE_AND_REVOKE** | Kill switch |

<!--
Speaker notes:
- Six possible outcomes, not just allow/deny
- REQUIRE_APPROVAL for sensitive operations
- Human stays in the loop for high-risk actions
-->

---

# Data Safety

- **No raw long-lived secrets** — 5-minute tokens
- **Default-deny egress** — Explicit allowlist
- **Input provenance** — Trusted vs. untrusted
- **Classification labels** — Control by sensitivity
- **Redacted telemetry** — No secrets in logs

```yaml
permissions:
  network_allowlist: ["reports.internal.example"]
  # All other egress denied
```

<!--
Speaker notes:
- Tokens expire in 5 minutes
- Network egress is whitelist, not blacklist
- Secrets are never written to logs
-->

---

# Kill Switch

Not a polite stop. A hard kill.

1. **Suspend** component in registry
2. **Revoke** all tokens for agent
3. **Terminate** task tree in broker
4. **Hook** EDR isolate
5. **Hook** egress deny

Order matters. Registry first, so new actions fail.

<!--
Speaker notes:
- Kill switch doesn't send "please stop" to agent
- Revokes credentials, suspends identity
- Hooks into EDR and firewall
- Order is critical for security
-->

---

# Components

| Service | Port | Role |
|---------|------|------|
| Registry | 8081 | Component inventory |
| PDP | 8082 | Policy decisions |
| Identity | 8083 | Token management |
| Broker | 8080 | Policy enforcement |
| Approval | 8084 | Human-in-loop |
| Telemetry | 8085 | Audit events |
| Kill Switch | 8086 | Emergency stop |

<!--
Speaker notes:
- Each service has a single responsibility
- Broker is the PEP - all actions flow through
- PDP is the brain - makes decisions
- Registry is the source of truth for components
-->

---

# Deploy Path

| Phase | Focus |
|-------|-------|
| **Demo** | This reference implementation |
| **Pilot** | Single team, non-production |
| **Staging** | Add TLS, IdP, monitoring |
| **Production** | Full HA, real EDR/egress hooks |

**MVP scope**: Teaching system, not drop-in EDR.

<!--
Speaker notes:
- Start with reference implementation for learning
- Pilot with low-risk use cases
- Add production requirements incrementally
- This is a teaching system, not a product
-->

---

# 90-Day Plan

**Days 1-30**: Foundation
- Deploy reference implementation
- Integrate with IdP (RFC 8693)
- Set up monitoring

**Days 31-60**: Pilot
- Onboard pilot team
- Tune policies from telemetry
- Build approval workflows

**Days 61-90**: Expand
- Production hardening
- EDR/egress integration
- Scale to more teams

<!--
Speaker notes:
- 30 days to get foundation right
- 30 days to learn from real usage
- 30 days to harden for production
- This is a journey, not a deployment
-->

---

# What This Is

✅ Working reference implementation
✅ Demonstration of architecture thesis
✅ Testbed for policy patterns
✅ Starting point for production

# What This Is Not

❌ Drop-in EDR replacement
❌ Complete production system
❌ Vendor product

<!--
Speaker notes:
- Be clear about what you're getting
- This is a teaching tool and starting point
- Production requires additional work
- No vendor lock-in - build your own
-->

---

# Questions?

**Repository**: This repo
**Documentation**: `docs/` folder
**Demo**: `make demo`

```bash
make test    # Run tests
make up      # Start services
make demo    # Run demo scenarios
```

<!--
Speaker notes:
- All code is in this repo
- Full documentation included
- Demo shows five key scenarios
- Questions welcome
-->
