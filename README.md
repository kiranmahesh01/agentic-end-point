# Agentic Endpoint Security

Independent execution broker and control plane for AI agents on enterprise endpoints.

The agent proposes actions. A policy enforcement point outside the agent process authorizes, constrains, or denies them. A kill switch revokes tokens and stops the task without asking the agent nicely.

This repository holds a production-shaped reference implementation: registry, PDP, broker, identity, approvals, telemetry, kill switch, docs, and presentation.

## Status

Initial commit. Full MVP lands in the first pull request.

## Quick start (after MVP lands)

```bash
make test
make up
make demo
```
