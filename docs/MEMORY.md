# Memory architecture and lineage

The Bastion memory architecture deliberately combines two families of ideas instead
of treating a vector store as the complete memory system.

## Inspiration and prior art

- [Mem0](https://github.com/mem0ai/mem0) (Apache-2.0) demonstrated a practical,
  persistent memory layer for personalized agents, with user/session/agent scoping,
  semantic retrieval, entity relationships, and an explicit memory lifecycle.
- [MemPalace](https://github.com/MemPalace/mempalace) (MIT) demonstrated a local-first,
  verbatim store organized into wings, halls, rooms, and drawers, with scoped semantic
  retrieval and a temporal knowledge graph.

Bastion's product-level `memupalace` service merges those inspirations: semantic and
entity-aware retrieval live alongside spatial organization and local storage. The Rust
substrate in `bastion-memory` adds the governance record that the runtime relies on.

## Bastion's governed layer

A retrieved memory is context, never authority. The core represents durable claims as
owner-scoped beliefs and records enough information to challenge them later:

- provenance and source identity;
- observation and validity time;
- confidence/weight and privacy tier;
- correction and revocation state;
- outcomes linked back to remembered beliefs;
- strict canonical-owner isolation.

This split is intentional. Semantic retrieval answers *what may be relevant*; the
governed belief store answers *whose claim it is, where it came from, when it was valid,
and whether it may still be used*. Capability and egress policy remain outside both.

## Attribution boundary

Bastion is independently maintained and is not affiliated with or endorsed by Mem0 or
MemPalace. Project names belong to their respective maintainers. Where source code is
adapted rather than merely inspired, the consuming repository carries file-level or
NOTICE attribution and the applicable upstream license.
