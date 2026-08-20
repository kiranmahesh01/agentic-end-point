# Agentic Endpoint Security

Independent execution broker and control plane for AI agents on enterprise endpoints.

## The Problem

AI agents on enterprise endpoints—coding agents, IDE extensions, browser extensions, local MCP servers, skills, and local models—act under the user's identity. They inherit the user's credentials, file access, and network permissions. When an agent is compromised, it's often not through a binary exploit but through a hijacked goal, a poisoned tool definition, or an over-delegated credential—often just a sentence in a prompt.

Traditional EDR still matters. But EDR cannot see:
- **Which agent** performed an action
- **For which user** and toward what declared goal
- **Using which loaded tool definition** (and whether that definition has been modified)
- **Whether the input was trusted** or came from an untrusted external source

## Architecture Thesis

**The agent PROPOSES actions. An independent policy enforcement point OUTSIDE the agent process approves, constrains, or denies them.**

The kill switch does not send a polite stop to the agent. It:
1. Revokes tokens
2. Suspends the component in the registry
3. Terminates the task tree
4. Hooks EDR isolate
5. Hooks egress deny

### Nine Invariants

1. **Identity Separation** — Agent identity is distinct from user identity
2. **Attenuated Delegation** — Agents receive minimal, scoped credentials
3. **Complete Mediation** — Every action flows through the broker
4. **Least Agency** — Autonomy is off by default
5. **Capability Integrity** — Tool definitions are hashed and verified
6. **Context Isolation** — Tasks cannot access other tasks' data
7. **Fail-Closed Ambiguity** — Unknown or missing data = DENY
8. **Independent Containment** — Kill switch operates outside agent control
9. **Evidence Preservation** — All decisions are logged for audit

## Architecture at a Glance

```
┌─────────────┐     PROPOSE      ┌─────────────┐
│   Agent     │ ───────────────► │   Broker    │ ◄─── Policy Enforcement Point
│  (proposes) │                  │   :8080     │
└─────────────┘                  └──────┬──────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
                    ▼                   ▼                   ▼
            ┌───────────┐       ┌───────────┐       ┌───────────┐
            │  Registry │       │    PDP    │       │ Telemetry │
            │   :8081   │       │   :8082   │       │   :8085   │
            └───────────┘       └───────────┘       └───────────┘
                                        │
                                        ▼
                                ┌───────────┐
                                │ Approval  │ ◄─── Out-of-band human approval
                                │   :8084   │
                                └───────────┘

            ┌───────────┐       ┌───────────┐
            │ Identity  │       │Kill Switch│ ◄─── Emergency termination
            │   :8083   │       │   :8086   │
            └───────────┘       └───────────┘
```

## Repository Map

```
├── services/
│   ├── registry/        # Component inventory (:8081)
│   ├── pdp/             # Policy Decision Point (:8082)
│   ├── identity/        # Agent token service (:8083)
│   ├── broker/          # Policy Enforcement Point (:8080)
│   ├── approval/        # Out-of-band approval (:8084)
│   ├── telemetry/       # Audit events (:8085)
│   ├── killswitch/      # Emergency termination (:8086)
│   └── demo_agent/      # Demo cooperating agent (:8090)
├── packages/
│   └── common/          # Shared models, JWT utils, path safety
├── policies/
│   ├── default.yaml     # Policy configuration
│   └── examples.rego    # OPA Rego examples (documentation)
├── tests/               # Pytest test suite
├── docs/                # Documentation
├── presentation/        # Executive deck
├── scripts/             # Demo and utility scripts
├── docker-compose.yml   # Container orchestration
└── Makefile             # Development commands
```

## Quick Start

### Prerequisites

- Python 3.12+
- Docker and Docker Compose (for containerized deployment)

### Run Tests

```bash
# Install dependencies
make install

# Run the test suite
make test
```

### Run with Docker Compose

```bash
# Start all services
make up

# View logs
make logs

# Run demo scenarios
make demo

# Stop services
make down
```

### Run Demo Scenarios

The demo agent demonstrates five key scenarios:

1. **Allowed Read** — Reading from an approved path succeeds
2. **Denied Shell** — Shell execution is denied (agent has shell=false)
3. **Denied Path Traversal** — Write with `..` is rejected
4. **Approval Required** — Untrusted input + write requires human approval
5. **Kill Switch** — After kill switch, subsequent actions are denied

```bash
./scripts/demo.sh
```

## Documentation

- [01 - Problem Statement](docs/01-problem.md) — Why EDR is not enough
- [02 - How It Works](docs/02-how-it-works.md) — Request flow and decision paths
- [03 - Data Safety](docs/03-data-safety.md) — Secrets, DLP, egress controls
- [04 - Architecture](docs/04-architecture.md) — Components and failure modes
- [05 - Deployment](docs/05-deployment.md) — Local, staging, production
- [06 - Operator Runbook](docs/06-operator-runbook.md) — Day-to-day operations

## Status

**Reference Implementation** — Compose is demo. Production is integration next to EDR/IdP/DLP, not a replacement.

### What This Is

- A working demonstration of the architecture thesis
- A testbed for policy enforcement patterns
- A starting point for production implementations
- Documentation of security invariants

### What This Is Not

- A replacement for EDR (EDR stays mandatory)
- A complete production system (missing HA, TLS, real IdP integration)
- A vendor product (vendor-neutral reference implementation)

### Demo vs. Production

| Demo (This Repo) | Production |
|-----------------|------------|
| In-memory JWT | RFC 8693 token exchange with IdP |
| Logged EDR hooks | Real EDR API integration |
| Logged egress hooks | Real firewall rules |
| No TLS | TLS everywhere |
| Single instance | HA cluster |

### Out of Scope for MVP

- Computer-use / GUI automation on the user desktop
- Real EDR integration (hooks are logged)
- Production IdP integration
- High availability / clustering
- TLS termination

## 90-Day Ask

**Days 1-30: Inventory and Contain**
- Deploy reference implementation
- Catalog existing agents and skills
- Define approved roots and egress allowlist

**Days 31-60: Integrate**
- Connect to IdP (RFC 8693)
- Wire EDR isolate hooks
- Build approval workflows

**Days 61-90: One Coding Agent**
- Put one approved coding agent behind the control plane
- Monitor, tune, document
- Expand to next agent

## References

### Standards and Specifications

- [MCP Specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28) (Current, supersedes 2025-11-25)
- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange
- [RFC 9700 / BCP 240](https://datatracker.ietf.org/doc/html/rfc9700) — Best Current Practice for OAuth 2.0 Security
- [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) — OAuth 2.0 Protected Resource Metadata

### Security Frameworks

- [OWASP Top 10 for Agentic Applications 2026](https://owasp.org/www-project-top-10-for-agentic-applications/) (ASI01–ASI10, released Dec 9, 2025)
- [OWASP LLM Top 10 2026](https://owasp.org/www-project-top-10-for-large-language-model-applications/) (Aug 3–4, 2026)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (v0.1 beta)
- [NIST AI RMF 1.0](https://www.nist.gov/itl/ai-risk-management-framework) (Jan 2023)
- [NIST AI 600-1](https://csrc.nist.gov/pubs/ai/600/1/final) (Jul 26, 2024)
- [NIST SP 800-207](https://csrc.nist.gov/publications/detail/sp/800-207/final) — Zero Trust Architecture (Aug 2020)
- [NIST CSF 2.0](https://www.nist.gov/cyberframework) (Feb 2024)
- [CSA MAESTRO](https://cloudsecurityalliance.org/) (Feb 2025)

### OpenTelemetry

- [OpenTelemetry GenAI Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/) (Development status, not stable)

### Known Vulnerabilities

- CVE-2025-32711 (EchoLeak) — Patched zero-click indirect prompt-injection information-disclosure vulnerability in Microsoft 365 Copilot

## License

MIT License — See [LICENSE](LICENSE)

## Author

Kiran Mahesh (kiranmahesh01) — 2026-08-20
