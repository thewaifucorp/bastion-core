# M2 — Design dos ports do kernel (quebra V1/V2 do ADR)

> Status: aceito pelo orquestrador do revamp · Refina a lista de ports do `M1-ADR-substrate-split.md` após leitura dos call sites reais de `agent/loop_.rs`, `agent/command.rs` e `hooks/output_validator.rs`.
> Regra: **um port por motivo de acoplamento, no nível mais grosso que preserve o comportamento** — não um trait por módulo.

## Delta vs. ADR

O ADR propôs `AgentRouter`, `DeliberationStrategy`, `OutputEvaluator`, `ChannelSink`, port de goals. A leitura dos call sites mostra que router/runner/cabinet formam **um** fluxo indivisível dentro do loop (route → `ResponseMode` → run → match `RunnerOutput` → deliberate/synthesize no caso Cabinet). Cortar em 3 traits obrigaria o kernel a conhecer `RouterDecision`/`RunnerOutput`/`CabinetVerdict` — tipos de cognição/persona. Corte correto: **um port coarse** na frente do fluxo inteiro.

`DeliberationStrategy` continua contrato público estável (decisão #6) — mas em `bastion-cognition`, consumido pela implementação do port, não pelo kernel.

## Ports (5 cortes)

### P1 `Responder` — quem responde e como

```rust
// bastion-runtime
#[async_trait]
pub trait Responder: Send + Sync {
    /// Given the built turn context, produce the final assistant response.
    /// Hides persona routing, single/parallel dispatch and any deliberation.
    async fn respond(&self, turn: &TurnContext<'_>) -> anyhow::Result<RespondOutcome>;
}
pub struct RespondOutcome {
    pub text: String,
    /// Which agent definition(s) produced it — for session/OTel labeling.
    pub attribution: Vec<String>,
}
```

Absorve: `persona::router::{route, RouterDecision, ResponseMode}`, `persona::runner::{run, RunnerOutput}`, `cabinet::{build_table, orchestrator::deliberate, synth::{synthesize, CabinetVerdict}}`, `render_verdict`. Implementação: `bastion-personas` + `bastion-cognition` compostas pelo app. `PersonaRegistry` sai do struct do loop e vive dentro do `Responder` concreto.

### P2 `FailureSink` — telemetria de falha

```rust
// bastion-types
pub enum FailureKind { EgressReject, Contestation, /* já existentes em eval::capture */ }
// bastion-runtime
pub trait FailureSink: Send + Sync {
    fn record_failure(&self, kind: FailureKind, detail: &str);
}
```

Absorve: `eval::capture::record_failure` chamado por `loop_.rs:790` e `hooks/output_validator.rs:138`. Implementação em `bastion-cognition` (alimenta o regression set do eval harness — EVAL-01). `FailureKind` move pra `bastion-types` (é vocabulário, não lógica). Resolve também a anomalia V4 `hooks→eval`.

### P3 `ToolSource` — catálogo de tools externo

```rust
// bastion-runtime
#[async_trait]
pub trait ToolSource: Send + Sync {
    /// Anthropic-format tool definitions to offer the model this turn.
    async fn tool_defs(&self) -> anyhow::Result<Vec<serde_json::Value>>;
}
```

Absorve: `McpClient` como campo do loop (defs de tools MCP). A **invocação** já passa por `CapabilityRegistry::invoke` (BIG-1) — não muda. `capability/adapters.rs` (adapters MCP→capability) move pra `bastion-mcp`, que registra capabilities via API pública do registry e implementa `ToolSource`.

### P4 `GoalPort` — engine de goals opcional

`GoalEngine` vira trait object opcional injetado (`Option<Arc<dyn GoalPort>>`) com a superfície mínima que o loop realmente usa (scoring/drift-nudge no fluxo de resposta). Implementação em `bastion-cognition`. Superfície exata a confirmar no passo M2-05 lendo os usos além do import.

### P5 Despejo de produto — sem trait

Não-port: coisas que simplesmente **saem** do kernel.

- `command.rs` inteiro → app (`bastion-agent`). É cockpit/UX. Junto vão os campos `otc_store` (`channel::webhook::OtcStore`) e `composio_oauth` (`mcp::oauth::ComposioOAuth`) do struct do loop, e os setters `set_otc_store`/`set_composio_oauth` (loop_.rs:1652/1659). O app compõe seu próprio command handler com esses recursos; o kernel nunca soube o que é OTC/OAuth de produto.
- Constructor `MeshSliceProvider::from_store` (loop_.rs:263-271) → composição no app. O loop só recebe mais um `TurnContextProvider` boxed — seam que já existe.

## V2 (config leakage) — regra única

`mcp/client.rs`, `interop/{mod,export}.rs`, `learn/mod.rs` deixam de ler `crate::config`: cada crate declara seu próprio struct de config (`McpConfig`, `InteropConfig`, `LearnConfig`) e o app converte `bastion.toml` → structs na composição. Nenhum default escondido: campos obrigatórios explícitos, `Default` só onde o comportamento atual já era default.

## Critérios de aceite (por port)

1. Kernel compila sem `crate::{persona,cabinet,eval,goal,mesh,mcp,channel}`.
2. Comportamento idêntico: caracterização M1-07 verde antes/depois; nenhum teste existente reescrito (só imports).
3. Zero clone de lógica: implementações dos ports são o código movido, não reimplementado.
4. `TurnContext` não expõe tipo de nenhuma extensão (blocos opacos preservados).
