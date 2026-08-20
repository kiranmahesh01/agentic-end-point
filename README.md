# Agentic Endpoint Security

Independent execution broker and control plane for AI agents on enterprise endpoints.

## The Problem

AI agents on enterprise endpoints—coding agents, IDE extensions, browser extensions, local MCP servers, skills, and local models—act under the user's identity. They inherit the user's credentials, file access, and network permissions. When an agent is compromised, it's often not through a binary exploit but through a hijacked goal, a poisoned tool definition, or an inherited token—often just a sentence in a prompt.

Traditional EDR still matters. But EDR cannot see:
- **Which agent** performed an action
- **For which user** and toward what declared goal
- **Using which loaded tool definition** (and whether that definition has been modified)
- **Whether the input was trusted** or came from an untrusted external source

## Architecture Thesis

**The agent PROPOSES actions. An independent policy enforcement point OUTSIDE the agent process approves, constrains, or denies them. The model classifier is an advisor, not a boundary.**

The kill switch does not send a polite stop to the agent. It:
1. Revokes tokens
2. Suspends the component in the registry
3. Terminates the task tree
4. **ACTUALLY** isolates via EDR sensor (container pause + network disconnect)
5. **ACTUALLY** blocks egress via proxy

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
┌─────────────────────────────────────────────────────────────────┐
│                        AGENTIC-NET (Docker)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐    ┌─────────┐    ┌─────────┐                      │
│  │  IdP    │    │ Redis   │    │ PDP x2  │◄─── Nginx LB (HA)    │
│  │ (JWKS)  │    │(shared) │    │         │                      │
│  └────┬────┘    └────┬────┘    └────┬────┘                      │
│       │              │              │                            │
│  ┌────┴──────────────┴──────────────┴────┐                      │
│  │              BROKER (PEP)             │                      │
│  │  - Typed adapters only                │                      │
│  │  - Offline fail-closed (Class D)      │                      │
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
│       ▲              ▲                                           │
│       │              │                                           │
│  ┌────┴──────────────┴────┐                                     │
│  │      KILL SWITCH       │                                     │
│  │  (real isolate + deny) │                                     │
│  └────────────────────────┘                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Repository Map

```
├── services/
│   ├── registry/           # Component inventory (:8081)
│   ├── pdp/                # Policy Decision Point (:8082, HA)
│   ├── identity/           # Token management (:8083)
│   ├── broker/             # Policy Enforcement Point (:8080)
│   ├── approval/           # Out-of-band approval (:8084)
│   ├── telemetry/          # Audit events (:8085)
│   ├── killswitch/         # Emergency termination (:8086)
│   ├── idp/                # Local IdP with JWKS (:8443) ← NEW
│   ├── egress_proxy/       # Real egress deny (:8087) ← NEW
│   ├── edr_sensor/         # Real container isolation (:8088) ← NEW
│   ├── isolated_desktop/   # Xvfb sandbox (:8089) ← NEW
│   └── demo_agent/         # Demo cooperating agent (:8090)
├── packages/
│   └── common/             # Shared models, JWT utils, path safety, Redis state
├── policies/
│   ├── default.yaml        # Policy configuration
│   └── examples.rego       # OPA Rego examples (documentation)
├── certs/                  # TLS certificates (generated by make certs)
├── tests/                  # Pytest test suite
├── docs/                   # Documentation
├── presentation/           # Executive deck
├── scripts/                # Demo and utility scripts
├── docker-compose.yml      # Container orchestration with HA
├── nginx-pdp.conf          # Load balancer for PDP HA
└── Makefile                # Development commands
```

## Quick Start

### Prerequisites

- Python 3.12+
- Docker and Docker Compose
- OpenSSL (for certificate generation)

### Run Tests

```bash
# Install dependencies
make install

# Run the test suite (128 tests)
make test
```

### Run with Docker Compose

```bash
# Generate TLS certificates
make certs

# Start all services (with TLS, HA, Redis)
make up

# Check service health
make health

# View logs
make logs

# Run demo scenarios
make demo

# Test kill switch (real isolation!)
make kill

# Stop services
make down
```

### Run Demo Scenarios

The demo agent demonstrates five key scenarios plus real isolation:

1. **Allowed Read** — Reading from an approved path succeeds
2. **Denied Shell** — Shell execution is denied (agent has shell=false)
3. **Denied Path Traversal** — Write with `..` is rejected
4. **Approval Required** — Untrusted input + write requires human approval
5. **Kill Switch** — After kill switch, subsequent actions are denied
6. **Real Isolation** — Container is paused, network disconnected
7. **Real Egress Block** — Agent cannot reach any destination

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
- [07 - What we built](docs/07-what-we-built.md) — What shipped on 20 Aug 2026, owner decisions, honest limits
- [08 - Mac runbook](docs/08-mac-runbook.md) — Colima + Docker on this laptop
- [Presentation](presentation/index.html) — 14-slide exec deck

## Status: Deploy Honestly

This reference implementation now includes **real working integrations**, not just logged hooks.

### Demo vs. Production

| Feature | This Repo | Production Swap-In |
|---------|-----------|-------------------|
| TLS | ✅ Dev CA + mTLS | Org CA |
| IdP | ✅ Local IdP (RS256/JWKS) | Org IdP via RFC 8693 |
| Token Revocation | ✅ Redis-backed | Same Redis or org IdP |
| Egress Control | ✅ Real proxy with default-deny | Org firewall API |
| EDR Isolation | ✅ Real container isolation (Docker) | Vendor EDR API |
| HA | ✅ PDP replicas + Redis shared state | K8s/ECS + managed Redis |
| Offline Mode | ✅ Class D fail-closed | Same |
| Computer-Use | ✅ Isolated Xvfb sandbox | Same (never operator desktop) |

### What's Real Now

- ✅ RS256-signed JWTs from local IdP with JWKS endpoint
- ✅ Egress denied at proxy level (403, not just logged)
- ✅ Container isolation via Docker API (pause + network disconnect)
- ✅ Fail-closed when PDP unreachable (Class D)
- ✅ Shared state via Redis (revocation, approval, kill)
- ✅ PDP HA with nginx load balancer
- ✅ Computer-use in isolated Xvfb sandbox (never operator desktop)

### Still Simulated

- File operations (no real file I/O)
- Network egress forwarding (real deny, simulated forward)

### Production Swap-In Points

| This Repo | Production Replacement |
|-----------|----------------------|
| Local IdP | Okta/Azure AD/Google via RFC 8693 |
| Redis | AWS ElastiCache / Azure Cache |
| Egress Proxy | Palo Alto / Zscaler API |
| EDR Sensor | CrowdStrike / Defender API |
| Docker Compose | Kubernetes / ECS |

## 90-Day Ask

**Days 1-30: Inventory and Contain**
- Deploy reference implementation
- Catalog existing agents and skills
- Define approved roots and egress allowlist

**Days 31-60: Integrate**
- Connect to IdP (RFC 8693)
- Wire EDR API (replace Docker sensor)
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

- CVE-2025-32711 (EchoLeak) — Patched zero-click indirect prompt-injection information-disclosure vulnerability in Microsoft 365 Copilot (NOT a confirmed in-the-wild breach)

## License

MIT License — See [LICENSE](LICENSE)

## Author

Kiran Mahesh (kiranmahesh01) — 2026-08-20
