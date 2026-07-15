# M0-03 — Inventário de legado (`keep | move | shim | delete-later`)

> Alimenta a limpeza do M6 (decisão #17: limpeza geral acontece no split físico).
> `move` = destino na topologia de crates do BACKLOG (tabela M1) ou no repo `bastion-agent`.
> **Nada aqui autoriza deleção agora** — cada remoção passa por aprovação no M6.
> `?` = incerteza real, resolver antes do M6.

## Módulos `src/` (tracked)

| Módulo | Classe | Destino / nota |
|---|---|---|
| `agent/` | move | loop/handle → `bastion-runtime`; dream/procedural → `bastion-cognition`; context → runtime |
| `types.rs` | move | `bastion-types` |
| `capability/` | move | `bastion-runtime` (registry, approval, quarantine) |
| `session/` | move | `bastion-runtime` (sessions) |
| `hooks/` | move | genéricos → runtime; policies concretas → app |
| `provider/` | move | trait → runtime; concretos → `bastion-providers` |
| `provider/terminal_agent.rs` | **shim** | vive sob feature `legacy-terminal-agent` até A-09; substituído pelos adapters de `bastion-agent-runtime` |
| `mcp/` | move | `bastion-mcp` |
| `memory/` | move | `bastion-memory` |
| `persona/`, `cabinet/` | move | `bastion-personas` / `bastion-cognition` (Cabinet = contrato estável, decisão #6) |
| `learn/`, `eval/`, `goal/`, `proactive/`, `scheduler/` | move | `bastion-cognition` |
| `mesh/`, `identity/`, `interop/` | move | `bastion-mesh` |
| `channel/` | move | trait → runtime; transports concretos → app `bastion-agent` |
| `api/`, `bin/`, `main.rs`, `config.rs` | move | app `bastion-agent` (composição/daemon) |
| `lib.rs` | move | re-exports temporários durante M2, depois some |

## Top-level tracked

| Entrada | Classe | Nota |
|---|---|---|
| `Cargo.toml/lock`, `rustfmt.toml`, `src/`, `tests/` | keep | viram workspace no M2 |
| `README.md`, `LICENSE`, `AGENTS.md`, `CLAUDE.md`, `.github/` | keep | AGENTS/CLAUDE perdem refs GSD/.planning no M6 |
| `BACKLOG.md`, `docs/revamp/` | keep | vivem até o fim do revamp, depois arquivados |
| `docs/` (en/, pt-br/, specs) | keep | revisar no M6; `docs/archive/` (v2/OpenClaw) = **delete-later** |
| `skills/` (Python MCP: memupalace, skill-writer, self-improving, guardrails, etc.) | move | repo `bastion-agent` (distribuição pessoal); auditar skills órfãs no M6 |
| `mobile/` | move | `bastion-agent` |
| `installer.sh`, `Dockerfile`, `docker-compose*.yml`, `Makefile`, `scripts/` | move | `bastion-agent` (distribuição) |
| `config/`, `bastion.toml`, `.env.example`, `.mcp.json` | move | `bastion-agent`; revisar defaults |
| `bastion-a.toml`, `bastion-b.toml` | delete-later | fixtures do mesh E2E — mover pra `tests/` ou apagar `?` |
| `bastion.local.toml`, `.bastion/` | delete-later `?` | estado/config local commitado por engano? conferir conteúdo antes |
| `bastion/mobile-connect/` (Node/TS OTC) | **move** | NÃO é legado — é o app de conexão do celular do owner (JWT + pareamento OTC). Preservar; refatorar depois. Vai pro `bastion-agent` (produto) no M6. |
| `SOUL.md`, `personas/` (untracked) | move | conteúdo pessoal do owner — sair do repo público, virar dado local/exemplo |
| `benchmark.py`, `conftest.py`, `pyproject.toml` | delete-later | resíduo Python do v2/experimentos; MCP servers Python reais moram em `skills/` |
| `STRATEGY.md` | keep `?` | doc vivo público — decidir se sobrevive ao split ou vai pro privado |
| `testsprite_tests/` | delete-later | resíduo de tooling de teste externo |

## Local-only (untracked/gitignored — lixo de máquina, sem cerimônia)

`__pycache__/`, `.pytest_cache/`, `.hypothesis/`, `.venv/`, `bastion.egg-info/`, `v1_cache/`, `.cargo-test.log`, `.local-data/`, `models/`, `USER.md`, `GEMINI.md`, `opencode.json`, `.clawhub/`, `.kiro/`, `.playwright-mcp/`, `.gemini/`, `.cursor/`, `.vscode/`, `.bastion-local/` — **delete-later** (higiene local; podem ser removidos a qualquer momento fora do M6, nada depende deles no build).

Tooling de planejamento/índice: `.planning` (symlink), `.gitnexus/`, `.aag/`, `.aag.lock`, `.claude/` — **delete-later no M6** (decisão #17; histórico de planejamento preservado no repo privado).
