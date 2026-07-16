---
name: Feature request
about: Propose new substrate capability
title: ''
labels: enhancement
assignees: ''
---

**What problem does this solve, and for whom?**
Substrate changes should serve every consumer, not one host's specific need
— explain the general use case.

**Proposed shape**
New trait? New crate? Extension to an existing port (`Provider`, `Memory`,
`TurnContextProvider`, ...)? Sketch the API if you have one in mind.

**Does this fit "mechanism, not orchestrator"?**
See the architecture laws in `AGENTS.md` — new behavior should enter as a
trait impl or an MCP server, not a change to the core loop's control flow.

**Alternatives considered**
