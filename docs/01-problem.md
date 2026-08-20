# 01 - The Problem: Why EDR Is Not Enough

## The Rise of Agentic AI on Enterprise Endpoints

AI agents are proliferating across enterprise endpoints:

- **Coding agents** in IDEs that read, write, and execute code
- **Browser extensions** that interact with web applications
- **IDE extensions** that access the file system and network
- **Local MCP servers** that expose tools and resources
- **Skills and plugins** that extend agent capabilities
- **Local models** running inference on sensitive data

These agents act **under the user's identity**. They inherit the user's:
- File system permissions
- Network access
- API credentials
- Secrets and tokens

## Compromise Is a Sentence, Not a Binary

Traditional endpoint compromise involves executable malware:
- A malicious binary is downloaded and executed
- EDR detects anomalous behavior patterns
- The process is terminated and quarantined

Agentic compromise is fundamentally different:
- A **hijacked goal** in a prompt injection
- A **poisoned tool definition** loaded from an untrusted source
- An **over-delegated credential** granted for convenience
- A **confused deputy** executing on behalf of an attacker

The attack surface is often **just a sentence**—a carefully crafted instruction embedded in data the agent processes.

## What EDR Cannot See

Traditional EDR monitors process behavior:
- File operations
- Network connections
- Registry changes
- Process creation

But EDR cannot answer:

| Question | Why EDR Cannot Answer |
|----------|----------------------|
| Which agent performed this action? | EDR sees the user's process, not the agent's identity |
| For which user was this action taken? | The user started the process, but the agent may act for others |
| What was the declared goal? | EDR has no visibility into agent intent |
| Was the input trusted or untrusted? | EDR cannot distinguish prompt sources |
| Has the tool definition been modified? | EDR doesn't hash or verify tool definitions |
| Is this action within the agent's approved scope? | EDR has no policy engine for agent capabilities |

## OWASP Top 10 for Agentic Applications (ASI01–ASI10)

The OWASP Top 10 for Agentic Applications (released December 9, 2025) identifies key risks:

| ID | Risk | How This System Addresses It |
|----|------|------------------------------|
| ASI01 | Prompt Injection | Input trust levels, untrusted input + exec = DENY |
| ASI02 | Insecure Output Handling | Classification-based egress controls |
| ASI03 | Over-Permissive Agency | Autonomy disabled by default, least privilege |
| ASI04 | Excessive Functionality | Registry controls which tools are available |
| ASI05 | Inadequate Sandboxing | Broker mediates all operations |
| ASI06 | Improper Multi-Agent Trust | Agent identity is distinct from user identity |
| ASI07 | Insecure Data Handling | DLP integration, classification labels |
| ASI08 | Uncontrolled Egress | Default-deny egress, explicit allowlist |
| ASI09 | Insufficient Logging | Telemetry on every decision |
| ASI10 | Lack of Human Oversight | Out-of-band approval for sensitive operations |

## Real-World Examples

### EchoLeak (CVE-2025-32711)

A **patched** zero-click indirect prompt-injection vulnerability in Microsoft 365 Copilot demonstrated how:
- An attacker could embed instructions in a document
- When a user asked Copilot to summarize the document
- Copilot would execute the embedded instructions
- Sensitive information could be exfiltrated

This vulnerability was **UI:N** (no user interaction required beyond normal document processing).

**Note**: This is a patched vulnerability that demonstrates the attack class. It is NOT a confirmed in-the-wild breach.

### Tool Definition Poisoning

Consider a coding agent that loads tool definitions from a repository:
1. An attacker contributes a malicious tool definition
2. The tool definition looks legitimate but contains a backdoor
3. When the agent uses the tool, it executes attacker-controlled code
4. EDR sees the user's IDE process making network requests—nothing anomalous

Without **capability integrity** (hashing and verifying tool definitions), this attack is invisible.

### Credential Over-Delegation

A user grants an agent access to their cloud provider credentials "for convenience":
1. The agent now has full access to production infrastructure
2. A prompt injection causes the agent to exfiltrate credentials
3. The attacker uses the credentials to access production systems
4. EDR sees normal API calls from the user's machine

Without **attenuated delegation** (scoped, short-lived credentials), the blast radius is unlimited.

## The Architecture Gap

```
┌─────────────────────────────────────────────────────────────────┐
│                    Current State                                 │
│                                                                  │
│  User ──► Agent ──► OS/API ──► EDR (sees user, not agent)       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Target State                                  │
│                                                                  │
│  User ──► Agent ──► Broker ──► PDP ──► OS/API                   │
│              │          │        │                               │
│              │          │        └──► Registry (who is this?)   │
│              │          │                                        │
│              │          └──► Approval (human-in-loop)           │
│              │                                                   │
│              └──► Identity (attenuated credential)              │
│                                                                  │
│  Kill Switch ──► Revoke ──► Suspend ──► Terminate               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Summary

EDR is necessary but not sufficient for securing agentic AI on endpoints.

We need:
1. **Agent identity** distinct from user identity
2. **Policy enforcement** outside the agent process
3. **Capability integrity** verification
4. **Input trust** classification
5. **Independent containment** via kill switch

This reference implementation demonstrates these principles in a working system.
