# Agentic Endpoint Security - Presentation

This folder contains executive presentation materials for the Agentic Endpoint Security reference implementation.

## Files

| File | Format | Description |
|------|--------|-------------|
| `slides.md` | Marp Markdown | 14-slide executive deck with presenter notes |
| `index.html` | Self-contained HTML | Dark-themed interactive deck (no dependencies) |

## Viewing the Slides

### Marp (slides.md)

The Marp deck can be viewed with:

1. **VS Code**: Install the [Marp for VS Code](https://marketplace.visualstudio.com/items?itemName=marp-team.marp-vscode) extension
2. **CLI**: Install Marp CLI and run `marp slides.md --preview`
3. **Export**: `marp slides.md --pdf` or `marp slides.md --pptx`

### HTML (index.html)

Open `index.html` directly in any modern browser. No server required.

**Navigation**:
- Arrow keys or Space to advance
- Page Up/Down for navigation
- Click the navigation buttons at bottom right

## Deck Outline (14 slides)

1. **Title** — The agent proposes. The broker decides.
2. **The Problem** — Compromise is a sentence, not a binary
3. **Why Now** — Agents everywhere, inheriting credentials
4. **Threat Examples** — Goal hijacking, tool poisoning, EchoLeak
5. **Why EDR Is Not Enough** — EDR sees user, not agent
6. **Architecture Thesis** — Agent proposes, PEP decides, kill switch terminates
7. **Nine Invariants** — Non-negotiable security principles
8. **How an Action Is Mediated** — Request flow step by step
9. **Data Safety** — No raw secrets, default-deny egress
10. **Kill Switch** — Not polite, hard kill
11. **Components** — MVP services
12. **Deploy Honestly** — Compose is demo, production is integration
13. **90-Day Ask** — Inventory, contain, one coding agent
14. **Questions** — Quick start commands

## Key Narrative Points

- Agents on endpoints misuse legitimate tools and valid credentials
- The exploit is often a sentence (goal hijack, poisoned skill, inherited token), not malware
- EDR stays mandatory and is not enough
- **EchoLeak = CVE-2025-32711**: patched zero-click vulnerability, NOT a confirmed in-the-wild breach
- **MCP 2026-07-28** is Current (not Final); **OWASP MCP Top 10** is v0.1 beta
- **Control rule**: agent proposes; independent PEP decides; model classifier is an advisor, not a boundary
- Kill switch does not ask the agent nicely
- **MVP**: registry + identity + PDP + typed PEP + OOB approval + kill switch
- **Default deny**: no raw shell, no user PAT, writes only in approved roots, egress allowlist
- Computer-use on the user desktop is out of MVP
- **Deploy honestly**: compose is demo; production is integration next to EDR/IdP/DLP, not a replacement
- **90-day ask**: inventory and contain, then put one approved coding agent behind that control plane
