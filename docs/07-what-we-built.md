# What we built (20 August 2026)

This is the record of the Agentic Endpoint Security project as delivered to Kiran Mahesh. It is the source of truth for *what shipped*, not a vendor brochure.

Repo: https://github.com/kiranmahesh01/agentic-end-point  
Owner: Kiran Mahesh (`kiranmahesh01`)

## One sentence

An independent broker sits outside the AI agent. The agent proposes actions. The broker allows, denies, or queues them for a human. A kill switch stops the agent without asking it nicely.

## What exists in GitHub (`main`)

| Piece | Where |
|---|---|
| Component registry | `services/registry` :8081 |
| Policy decision point (2 replicas + nginx) | `services/pdp` :8082 |
| Local IdP (RS256 + JWKS) | `services/idp` :8443 |
| Identity / token broker | `services/identity` :8083 |
| Execution broker (PEP) | `services/broker` :8080 |
| Out-of-band approvals | `services/approval` :8084 |
| Telemetry | `services/telemetry` :8085 |
| Kill switch | `services/killswitch` :8086 |
| Real egress proxy (default deny) | `services/egress_proxy` :8087 |
| EDR sensor (pause + disconnect container) | `services/edr_sensor` :8088 |
| Isolated desktop (Xvfb, not the Mac GUI) | `services/isolated_desktop` :8089 |
| Demo cooperating agent | `services/demo_agent` :8090 |
| Redis shared state | :6379 |
| Policy as YAML + Rego docs | `policies/` |
| Tests | `tests/` |
| HTML exec deck | `presentation/index.html` |

## What we did, in order

1. **Source-checked** the v2.0 paper. MCP `2026-07-28` is Current, not Final. EchoLeak is CVE-2025-32711 (patched vuln, not a confirmed breach). OWASP MCP Top 10 is v0.1 beta.
2. **Wrote** problem, architecture, data-safety, deploy, operator, and a 14-slide deck.
3. **Implemented** the FastAPI control plane and merged PR https://github.com/kiranmahesh01/agentic-end-point/pull/1
4. **Stood up a live control-plane team** (Broker, Identity, Policy, Risk, EDR, Kill Switch, Response). First exercise verdict: overall CONSTRAIN.
5. **Kiran’s owner card (binding):**
   1. Read `/approved/workspace` — ALLOW
   2. Raw shell — DENY
   3. Write `/etc/passwd` / path traversal — DENY
   4. Untrusted page then write — CONSTRAIN; human may allow only `/approved/output`
   5. After kill — DENY. Kill Switch stays dark unless someone says TERMINATE.
6. **Ran it on this Mac** with Homebrew Docker + Colima (Docker Desktop was not installed). `make demo` matched the owner card.
7. **Fixed what blocked `make up`:**
   - `docker compose` CLI plugin missing → wired Homebrew plugin
   - Colima image download SHA mismatch → cleared cache, started VM
   - Images failed `pip install -e .` because README/LICENSE were not copied
   - Healthchecks used `curl` on `python:3.12-slim` (no curl) → Python urllib
   - nginx PDP LB healthcheck used `localhost` (IPv6 refuse) → `127.0.0.1`
   - Browser “localhost not working” was FastAPI 404 on `/` → added a homepage

## What `make demo` proved on this laptop

- (a) Approved read ALLOW
- (b) Shell DENY
- (c) Path traversal DENY
- (d) Untrusted write REQUIRE_APPROVAL (not executed)
- (e) After kill, action DENY (`Task has been terminated`)

Kill-switch status logged `completed_with_errors` on one internal hook; the subsequent action was still DENY. That is fail-closed enough for the demo, not proof of a vendor EDR cut.

## What this is not

- Not CrowdStrike / SentinelOne / Microsoft Defender. The EDR sensor isolates **this compose demo-agent**, not the Mac host.
- Not Okta / Entra. The IdP is local.
- Not a corporate firewall. Egress deny is the compose proxy.
- Computer-use never drives the operator desktop. Isolated Xvfb only.
- Not a drop-in replacement for existing endpoint, identity, DLP, or network controls.

## Where to read next

- How to run on this Mac: [08-mac-runbook.md](08-mac-runbook.md)
- Why it exists: [01-problem.md](01-problem.md)
- Request path: [02-how-it-works.md](02-how-it-works.md)
- Data safety: [03-data-safety.md](03-data-safety.md)
- Deck: `presentation/index.html`
