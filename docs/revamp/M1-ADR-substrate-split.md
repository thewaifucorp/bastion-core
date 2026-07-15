# M1 — ADR: Split substrato / cognição / produto

> Status: **aceito** (decisões #1–#7 do BACKLOG, Q&A 2026-07-13) · Cobre M1-01..06 · M1-07 (caracterização) é entregável separado.
> Baseline de referência: tag `v1.1.0-pre-revamp` (`docs/revamp/BASELINE.md`).

## Decisão

Reorganizar o monolito `src/` num workspace de **10 crates + app** (tabela no BACKLOG §M1), com três classes de estabilidade:

| Classe | Crates | Contrato |
|---|---|---|
| Kernel | `bastion-types`, `bastion-runtime` | semver estrito; API pública mínima; `#![forbid(unsafe_code)]` |
| Quase-kernel | `bastion-memory` | semver estrito após M3; beliefs/proveniência são contrato |
| Extensões oficiais | `bastion-cognition` (Cabinet estável — decisão #6), `bastion-personas` (0.x), `bastion-mesh`, `bastion-mcp`, `bastion-agent-runtime`, `bastion-extension-protocol`, `bastion-providers` | `0.x`, evolução compatível quando possível |
| Produto | app `bastion-agent` | versão de produto; sem promessa de lib |

Regras de dependência (CI, M2-08): extensões → kernel; app → tudo; **kernel → nada acima dele**; ninguém → app.

## Estado real (M1-03): grafo medido no baseline

Método: arestas `use crate::X` agregadas por grupo-alvo, 82 arquivos. Resultado: **27 arestas proibidas**, concentradas em 4 padrões. Nenhuma é surpresa estrutural; todas têm quebra conhecida:

### V1 — Loop faz composição de produto (o maior)

`agent/loop_.rs` importa cabinet, eval, goal, mcp, mesh, persona, provider, channel; `agent/command.rs` importa channel, mcp, persona, provider.

**Quebra:** o que o loop consome vira **port** injetado na construção (o padrão já existe: `TurnContextProvider`, `CapabilityRegistry`). Novos ports mínimos: roteamento de persona (`AgentRouter`), deliberação (`DeliberationStrategy` — já é contrato pela decisão #6), avaliação de saída (`OutputEvaluator`), engine de goals (port de cognição), notificação de canal (`ChannelSink`). O loop conhece traits; o app compõe implementações. `command.rs` (cockpit) é UX → move pro app inteiro.

### V2 — `crate::config` vaza pra extensões

`mcp/client.rs`, `interop/{mod,export}.rs`, `learn/mod.rs` leem a config global do produto.

**Quebra:** cada crate define seu struct de config próprio; o app faz o parse do `bastion.toml` e injeta. Kernel/extensões nunca conhecem formato de arquivo.

### V3 — Cognição/personas chamam provider

`cabinet/{synth,orchestrator}.rs`, `learn/mod.rs`, `persona/{router,runner}.rs` importam `crate::provider`.

**Quebra:** já usam o trait — e o **trait `Provider` fica no kernel** (`bastion-runtime`); só os concretos vão pra `bastion-providers`. Essas arestas viram `→ runtime` (permitidas) automaticamente na extração. Ação real: garantir que nenhum desses arquivos nomeia provider concreto (auditar no M2-04).

### V4 — Arestas pontuais anômalas (investigar antes de mover)

| Aresta | Arquivo | Hipótese / ação |
|---|---|---|
| providers → cognition | `provider/ollama.rs` usa `crate::cabinet` | GBNF/constrained-decoding acoplado ao Cabinet? Inverter: tipo de gramática vai pro kernel ou pro próprio ollama.rs |
| runtime → cognition | `hooks/output_validator.rs` usa `crate::eval` | validador (kernel) chama harness de eval — virar `OutputEvaluator` port |
| memory → mesh | `memory/sqlite.rs` usa `crate::mesh` | tipos de compartilhamento seletivo? Extrair tipo neutro pra `bastion-types` |
| memory → runtime | `memory/sqlite.rs` usa `crate::session` | conexão SQLite compartilhada — aceitável se virar dep de kernel (memory → runtime é permitido), mas preferível injetar pool |
| runtime → mcp | `capability/adapters.rs`, loop | adapters MCP→capability movem pra `bastion-mcp` (registram-se no registry via API pública) |

Ciclos de grupo hoje: `app↔runtime`, `app↔mcp`, `app↔mesh`, `app↔memory`, `app↔providers` — todos causados por V1/V2 (lado "→ app" é sempre config/channel). Quebrando V1+V2, o grafo fica acíclico.

## Ordem de extração (M2, refinada pelo grafo)

1. `bastion-types` (folha; zero deps).
2. `bastion-runtime` **com os ports novos definidos antes de mover** (V1/V2 quebram aqui, com o compilador cobrando).
3. `bastion-memory` (resolver V4-memory junto).
4. `bastion-providers` + `bastion-mcp` (V3 vira legal; V4-ollama e V4-adapters resolvem aqui).
5. `bastion-cognition`, `bastion-personas`, `bastion-mesh`.
6. App = o que sobrar (`api/`, `bin/`, `channel/`, `config.rs`, `main.rs`, `command.rs`).

Re-exports temporários em `lib.rs` com data de remoção; um commit por boundary; caracterização (M1-07) verde antes e depois de cada passo.

## APIs públicas mínimas (M1-04 — lista de estabilização)

Kernel: `Runtime::run_turn(TurnRequest) -> TurnResult` · `Capability`/`CapabilityRegistry`/`InvokeCtx` · `ContextProvider`/`ContextBlock` · `SessionStore` · `Provider` (trait) · `Observer`/contrato de eventos OTel · ports de approval/budget/policy · ports novos do V1 (`AgentRouter`, `DeliberationStrategy`, `OutputEvaluator`, `ChannelSink`).
Quase-kernel: `Memory`/`Belief`/proveniência/temporalidade.
Extensões: `AgentDefinition`+bindings (0.x) · learning delta + interop `.af` · `AgentRuntime`/`SessionHandle`/`RuntimeEvent` (A-01) · `AuthProfileRef` · `ExtensionManifest`/`PackManifest`/`Loadout`+lockfile · `VersionedContextArtifact`/`ContextRevision` · delegação de subagente/ownership coletivo.

## Mecanismo vs. política (M1-05)

Regra única: **crates carregam mecanismo configurável; toda opinião vira política injetada.** O app injeta política pessoal (`PersonalAgentPolicy`, M4-02); um host embedded externo injeta a dele via os mesmos ports. Nenhuma crate contém default que pressuponha "usuário pessoa" ou conceito de consumidor fechado. Teste do M5: se o slice precisar de fork ou `cfg` novo pra servir o segundo consumidor, o boundary falhou e volta pro M3.

## Riscos aceitos

- Cabinet estável antes do A/B do M7 (decisão do owner): se o experimento invalidar a tese, ficamos com contrato estável de baixo uso — custo assumido.
- `bastion-memory` quase-kernel acopla cadência de beliefs à do runtime — aceito porque contexto/loop dependem de trust/proveniência.
- 10 crates > coarse recomendado: mitigado por CI de deps proibidas + ownership único (owner = Mario para tudo, hoje).
