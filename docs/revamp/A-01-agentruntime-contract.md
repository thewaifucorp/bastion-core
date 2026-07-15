# A-01 — Contrato `AgentRuntime` + Threat Model

> Status: **draft para review** · Backlog: Trilha A · Depende de: nada (paralelo a M1) · Alimenta: A-02 (conformance), M1-04 (APIs públicas), M4-06 (`BackendProfile`)
>
> Substitui o `TerminalAgentProvider` (`src/provider/terminal_agent.rs`) — hoje um `Provider` falso: achata a conversa em prompt de stdout, retorna `tool_calls: None` por design, e o tool-loop interno do CLI escapa de egress/approval/budget do Bastion (limitação documentada no próprio módulo).

## v2 — Ciclo 2.2 (revisão pós-validação live)

`docs/revamp/A-05-conformance-matrix.md` §5 rodou a suite A-02 contra harnesses
reais (`acpx`/`claude`, `codex app-server`) e achou 6 furos no contrato/A-02.
Esta revisão fecha os 6:

1. **Watchdog parametrizável** — `ConformanceScenarios` (A-02,
   `crates/bastion-agent-runtime/src/conformance.rs`) ganhou o campo
   `watchdog: Duration`; deixou de ser o `const WATCHDOG = 5s` fixo do crate.
   Runs live passam um valor maior (30s neste ciclo) para absorver os 14
   `start()` frios que um `run_all` faz contra um harness cloud de verdade.
2. **`SandboxCoverage` detectado, não declarado** — ver §3. `CodexAppServerRuntime`
   agora probe bubblewrap (`bwrap --unshare-user ...`) em `health()`/`start()`;
   sem bubblewrap funcional = `SandboxCoverage::None` (pior caso honesto),
   nunca `Partial` otimista sem prova.
3. **`ResumeSpec`** — `AgentRuntime::resume` ganhou um segundo parâmetro com o
   subconjunto de `SessionSpec` re-aplicável num reattach (`timeout`,
   `permissions`, `env`; `workspace`/`sandbox` continuam fixos da sessão
   original). Ver §2/§5.
4. **`PermissionDecision::Deny { scope: DenyScope }`** — alinhado ao
   `DenyScope` do kernel (`bastion_types`, Ciclo 2.1,
   `docs/revamp/C2-approval-port-design.md` §3). `bastion-agent-runtime`
   ainda é standalone (sem dependência de `bastion-types`), então este é um
   espelho local documentado, não um tipo inventado à parte — mesma
   vocabulário de 2 variantes (`Instance`/`Turn`). `Turn` (default do
   produto) faz o adapter cancelar a task graciosamente depois de negar.
5. **Steer race / cancel-vs-timeout ambíguo — já mitigados, agora exigidos
   pelo contrato** — ver §5, itens 3 e 5.

## Contrato base (v1)

## 1. Duas abstrações, não uma

| Abstração | Responsabilidade | Contrato |
|---|---|---|
| `ModelProvider` (o `Provider` atual, `src/provider/mod.rs`) | uma chamada de inferência: mensagens → resposta/tool-calls/usage | `complete(&[Message], &CallConfig) -> LlmResponse` |
| `AgentRuntime` (novo) | uma **sessão** cujo harness externo possui o loop interno: terminal, arquivos, tools próprias, artefatos | sessões, eventos tipados, steer/cancel, artefatos, usage |

Regra: **harness não finge ser modelo**. Nenhum adapter de `AgentRuntime` implementa `Provider`. O dispatcher escolhe pela configuração (`BackendProfile`), nunca por downcast ou heurística.

### 1.1 Três modos operacionais (sem terceiro tipo de provider)

```text
1. inferência nativa      conversation_backend = ModelProvider   → Bastion possui o tool loop
2. conversa runtime-backed conversation_backend = AgentRuntime   → harness possui o loop do turn;
                                                                   Bastion possui o envelope
                                                                   (identidade, memória, canais, supervisão)
3. tarefa delegada         task_runtime = AgentRuntime            → conversa segue viva; sessão longa
                                                                   devolve eventos/artefatos/resultado
```

`AuthProfileRef` é ortogonal: referência opaca de credencial/entitlement consumida por qualquer backend. Não é um terceiro executor.

## 2. Contrato (esqueleto Rust)

Nomes finais podem mudar na implementação; a **semântica** desta seção é o contrato que a conformance (A-02) verifica.

```rust
/// Implementado por adapters (Codex app-server, cliente ACP supervisionado, ...).
/// Kernel não conhece nenhum adapter concreto.
#[async_trait]
pub trait AgentRuntime: Send + Sync {
    /// Identidade + capacidades declaradas. Estático por versão do adapter.
    fn descriptor(&self) -> RuntimeDescriptor;

    /// Probe barato (binário existe? versão compatível? auth resolvível?).
    /// Falha aqui = runtime indisponível ANTES de criar sessão. Fail-closed.
    async fn health(&self) -> Result<RuntimeHealth, RuntimeError>;

    async fn start(&self, spec: SessionSpec) -> Result<Box<dyn RuntimeSession>, RuntimeError>;

    /// Reatar sessão persistida (pós-restart). `NotResumable` é resposta
    /// válida e tipada — nunca silenciosamente uma sessão nova. `spec` (v2,
    /// Ciclo 2.2) carrega o subconjunto re-aplicável do `SessionSpec`
    /// original — ver `ResumeSpec` abaixo; o adapter aplica o que o
    /// protocolo de reattach permitir e reporta o resto via `Warning`.
    async fn resume(
        &self,
        handle: &SessionHandle,
        spec: ResumeSpec,
    ) -> Result<Box<dyn RuntimeSession>, RuntimeError>;
}

#[async_trait]
pub trait RuntimeSession: Send + Sync {
    /// Referência persistível no session store do Bastion (restart recovery).
    fn handle(&self) -> SessionHandle;

    /// Submete um turn/tarefa. Retorna imediatamente; progresso vem por `events()`.
    async fn submit(&mut self, input: TaskInput) -> Result<TaskId, RuntimeError>;

    /// Stream tipado, ordenado por sessão, bounded (backpressure explícito).
    fn events(&mut self) -> BoxStream<'_, RuntimeEvent>;

    /// Mensagem de direcionamento no meio da tarefa (se suportado — ver descriptor).
    async fn steer(&mut self, text: &str) -> Result<(), RuntimeError>;

    /// Cooperativo → grace period → kill. Idempotente. Nunca corrompe o
    /// session store do Bastion (falha do harness ≠ falha da sessão Bastion).
    async fn cancel(&mut self, mode: CancelMode) -> Result<(), RuntimeError>;

    /// Resposta a um `RuntimeEvent::PermissionRequest` (ponte pro ApprovalQueue).
    async fn respond_permission(
        &mut self,
        id: PermissionRequestId,
        decision: PermissionDecision,
    ) -> Result<(), RuntimeError>;

    async fn status(&self) -> Result<SessionStatus, RuntimeError>;
}
```

### 2.1 Tipos centrais

```rust
pub struct RuntimeDescriptor {
    pub id: &'static str,            // "codex_app_server" | "acp" | ...
    pub adapter_version: String,
    pub target_version: VersionReq,  // versão pinada do harness/client suportada
    pub transport: Transport,        // AppServer | AcpJsonRpc | Embedded
    pub supports: RuntimeSupports,   // resume, steer, usage_reporting, diff_events,
                                     // permission_bridge, concurrent_sessions
    pub policy_coverage: PolicyCoverage, // ver §3 — declaração honesta
}

/// v2 (Ciclo 2.2) — subconjunto de SessionSpec re-aplicável num resume().
/// `workspace`/`sandbox` ficam de fora: fixos pela sessão original, não
/// renegociáveis num reattach.
pub struct ResumeSpec {
    pub timeout: TimeoutPolicy,
    pub permissions: PermissionProfile,
    pub env: EnvPolicy,
}

pub struct SessionSpec {
    pub workspace: WorkspacePolicy,      // dir raiz + rw/ro + deny-paths
    pub sandbox: SandboxProfile,         // herdado do host; adapter declara o que honra
    pub permission_profile: PermissionProfile, // o que o harness pode sem perguntar
    pub auth: AuthProfileRef,            // opaco; resolução fora do adapter
    pub runtime_id: String,              // modelo/agente alvo dentro do harness
    pub timeout: TimeoutPolicy,          // por task + por sessão + idle
    pub env: EnvPolicy,                  // allowlist explícita; default vazio
    pub mcp_bridge: Option<McpBridgeSpec>, // servers MCP do Bastion expostos ao harness
    pub otel: OtelContext,               // trace/span pai pra correlação
}

pub struct TaskInput {
    pub prompt: TaskPrompt,          // texto + blocos de contexto JÁ filtrados por egress
    pub attachments: Vec<Artifact>,  // entrada opcional (arquivos, diffs)
    pub expected: TaskExpectation,   // Conversation | CodeChange | Structured(schema)
}

#[non_exhaustive]
pub enum RuntimeEvent {
    Started { handle: SessionHandle },
    MessageDelta { text: String },                    // streaming do assistant
    Thinking { summary: String },                     // se o harness expõe
    ToolCall { name: String, input_digest: String },  // OBSERVADO, não mediado
    ToolResult { name: String, output_digest: String, is_error: bool },
    PermissionRequest { id: PermissionRequestId, action: PermissionAction, detail: String },
    Diff { path: PathBuf, added: u32, removed: u32 },
    Artifact(Artifact),                               // diff completo, arquivo, log
    Usage(UsageDelta),                                // tokens/custo incremental
    Warning { code: WarnCode, detail: String },
    Ended { task: TaskId, outcome: TaskOutcome },     // Success | Failed | Cancelled | TimedOut
}

/// v2 (Ciclo 2.2) — espelho do `DenyScope` do kernel (`bastion_types`,
/// Ciclo 2.1 §3). Duplicado localmente e documentado, não um tipo à parte:
/// `bastion-agent-runtime` ainda não depende de `bastion-types`.
pub enum DenyScope {
    Instance, // nega só esta invocação; task continua normalmente
    Turn,     // nega E encerra a task (adapter cancela graciosamente) — default do produto
}

pub enum PermissionDecision {
    Allow,
    Deny { scope: DenyScope },   // v2: carrega escopo (era variante unitária)
}

#[non_exhaustive]
#[derive(thiserror::Error, Debug)]
pub enum RuntimeError {
    #[error("harness unavailable: {0}")]      Unavailable(String),   // spawn/health
    #[error("protocol violation: {0}")]        Protocol(String),      // JSON inválido, evento fora de ordem
    #[error("version mismatch: {0}")]          Version(String),       // pin ≠ binário
    #[error("auth failed: {0}")]               Auth(String),          // tipado; nunca vaza token
    #[error("task timed out after {0:?}")]     Timeout(Duration),
    #[error("cancelled")]                      Cancelled,
    #[error("harness crashed: {0}")]           Crashed(String),
    #[error("session not resumable: {0}")]     NotResumable(String),
}
```

### 2.2 Semânticas obrigatórias

- **Eventos**: ordem total por sessão; `Ended` é terminal e único por task; nenhum evento após `Ended` da última task. Stream fecha = sessão morta (distinguível de `Ended`).
- **Cancel**: `CancelMode::Graceful { grace }` → sinal cooperativo, depois kill; `CancelMode::Kill` imediato. Pós-cancel, `status()` reporta `Cancelled`, nunca `Running` fantasma.
- **Resume**: `SessionHandle` é serializável e persiste no session store (SQLite) junto da sessão Bastion. Após restart do daemon: `resume(handle)` reata OU retorna `NotResumable` — o chamador então marca a task como interrompida e informa o usuário. **Proibido**: perder a referência e vazar sessão órfã no harness.
- **Timeout**: estouro emite `Ended { outcome: TimedOut }` + cancel automático; nunca sessão zumbi.
- **Transporte**: somente protocolo estruturado (app-server / JSON-RPC/NDJSON). **Proibido interpretar stdout humano, ANSI ou heurística de prompt** — teste negativo na conformance.
- **Encapsulamento**: tipos/paths/lifecycle do client externo (ex.: processo ACP supervisionado, version-pinned) não aparecem na API pública. Trocar o client por implementação nativa não muda consumidor nenhum.

## 3. `PolicyCoverage` — declaração honesta de autoridade

No modo runtime-backed, o harness possui o loop interno. O contrato **não finge** que o Bastion media o que não media; ele **obriga o adapter a declarar** o que cobre, e a UI mostra:

```rust
pub struct PolicyCoverage {
    pub tool_visibility: ToolVisibility,   // Full | DeclaredOnly | Opaque
    pub approvals: ApprovalCoverage,       // Bridged (PermissionRequest → ApprovalQueue)
                                           // | HarnessOwned (perfil pré-aprovado, sem ponte)
    pub egress: EgressCoverage,            // InputFiltered (Bastion filtra o que ENTRA)
                                           // | HarnessOwned (rede própria do harness)
    pub budget: BudgetCoverage,            // Reported | Estimated | Unknown
    pub sandbox: SandboxCoverage,          // Honored | Partial | None
}
```

`sandbox` (v2, Ciclo 2.2 — A-05 §5.2): deixou de ser uma constante estática do
adapter. Um adapter capaz de sandbox real (ex.: Codex/bubblewrap) DEVE
detectar em `health()`/`start()` se o mecanismo funciona neste host (probe
barato, real — não uma heurística de versão) e cachear o resultado para
`descriptor()` reportar. Sem mecanismo detectável, ou detecção impossível a
partir das superfícies do binário: `SandboxCoverage::None`, o pior caso
honesto — nunca `Partial` otimista sem prova de que o mecanismo funciona
neste host específico. `Honored` continua reservado para quando o adapter
consegue provar confinamento de um turno específico, não apenas que o
mecanismo existe.

Integração com os seams existentes (nenhum novo bypass):

| Seam atual | Regra no AgentRuntime |
|---|---|
| `check_egress(tier, dest)` (`src/hooks/egress.rs`) | aplica na **montagem do `TaskInput`**: bloco `local-only` nunca entra em sessão de harness cloud-backed. O destino é o harness, não o modelo — classificado pelo descriptor. |
| `ApprovalQueue` (`src/capability/approval.rs`) | `PermissionRequest` vira approval tipado na mesma fila; decisão volta por `respond_permission`. Adapter **nunca** auto-aprova. Se o harness não expõe ponte de permissão, `approvals: HarnessOwned` + perfil restritivo por default. |
| `TaggedValue` trust (`src/capability/registry.rs`) | TODO output do harness (mensagens, artefatos, tool results observados) entra como **untrusted**. Artefato carrega proveniência (`session`, `task`, `harness id/version`). Diff nunca é aplicado automaticamente fora do workspace da sessão. |
| Budget | `Usage` events alimentam o mesmo budget tracking; `budget: Unknown` exige cap por tempo/tarefa como fallback. |
| OTel GenAI | 1 span por sessão + 1 por task; eventos mapeados; `OtelContext` do spec correlaciona com o turn Bastion que delegou. |

## 4. Threat model

Ativos: credenciais de assinatura/API; memória e contexto do owner (tiers); workspace/filesystem; session store; integridade do que o usuário aprova.

| # | Ameaça | Vetor | Mitigação no contrato |
|---|---|---|---|
| T1 | Harness comprometido/malicioso executa ações destrutivas | binário externo com filesystem/rede próprios | `WorkspacePolicy` (raiz confinada + deny-paths), `SandboxProfile`, `PermissionProfile` restritivo por default; ações fora do workspace = achado de conformance |
| T2 | Prompt injection dentro do loop do harness (conteúdo do workspace/web instrui o agente externo) | Bastion não media tools internas | outputs untrusted por default; diffs revisáveis via approval antes de sair do workspace da sessão; `expected: CodeChange` restringe interpretação do resultado |
| T3 | Exfiltração de contexto tier-alto pro harness cloud | `TaskInput` mal montado | egress check **na montagem do input** (mesmo chokepoint de provider dispatch); conformance inclui caso `local-only → cloud harness = recusa` |
| T4 | Bypass de approval (harness age sem perguntar) | perfil headless pré-aprovado amplo (hoje: `--allowedTools` do legado) | `PolicyCoverage.approvals` explícito; default = menor perfil; UI declara "harness tool loop"; allowlist de permissão vem do `PermissionProfile`, não de env var solta |
| T5 | Vazamento de credencial (token em env/log/prompt/definição) | subprocess herda env; logs verbosos | `EnvPolicy` allowlist (default vazio); `AuthProfileRef` opaco resolvido fora do adapter; `RuntimeError::Auth` nunca inclui token; conformance greps artefatos/logs por padrão de secret |
| T6 | Parsing ambíguo (ANSI/stdout humano) vira execução errada | scraping do legado | transporte estruturado obrigatório; teste negativo rejeita stdout humano; `Protocol` error fail-closed |
| T7 | Sessão órfã/hijack via `SessionHandle` stale | handle persistido sobrevive a restart | handle é capability opaca owner-scoped no session store; `resume` valida dono + versão; `NotResumable` tipado |
| T8 | Usage falso/omisso fura budget | harness reporta errado ou nada | `BudgetCoverage` declarado; fallback de cap por tempo/nº de tasks; discrepância>tolerância = `Warning` |
| T9 | Version drift do client externo (alpha) muda semântica silenciosamente | update do binário | version pin no descriptor + `health()` compara; mismatch = `Version` error, não degradação silenciosa |
| T10 | Crash do harness corrompe estado Bastion | processo morre no meio do turn | sessão Bastion e sessão harness são registros separados; escrita no store só em eventos validados; crash = `Crashed` + task `Failed`, histórico intacto |

## 5. Requisitos de conformance (entrada do A-02)

Todo adapter passa a MESMA suite:

1. start → submit → stream → `Ended{Success}` (happy path).
2. resume pós-restart do processo hospedeiro, com `ResumeSpec` (v2) —
   funciona (aplicando o que o protocolo do adapter permitir e reportando
   divergência via `Warning`) OU `NotResumable` tipado.
3. steer no meio de task longa (ou declarado não-suportado no descriptor — e
   então a chamada falha tipada). **Requisito v2 (A-05 §5.3)**: se o
   protocolo do harness tiver uma janela de readiness transiente entre
   aceitar a task e aceitar um steer nela, o adapter DEVE tolerar isso (ex.:
   retry curto e limitado) em vez de reportar erro tipado na primeira
   rejeição espúria do próprio harness.
4. cancel graceful e kill; sem zumbi; sem evento pós-terminal.
5. timeout → `TimedOut` + cleanup. **Requisito v2 (A-05 §5.4)**: se o
   protocolo do harness reporta o mesmo status para "cancelado
   cooperativamente" e "interrompido pelo watchdog de timeout", o adapter
   DEVE desambiguar client-side (nunca reportar `Cancelled` para um timeout
   nem vice-versa só porque o wire status bate).
6. fila: segundo `submit` durante task ativa (rejeita ou enfileira — conforme descriptor, nunca intercala eventos).
7. streaming: deltas chegam incrementais; ordem total; backpressure não perde evento terminal.
8. diff/artefatos com proveniência; digest bate com conteúdo.
9. `PermissionRequest` → ponte de approval → allow e deny ambos exercitados.
   **v2**: deny carrega `DenyScope`; com `Turn` (default do produto) o
   adapter cancela a task graciosamente após negar — ver
   `docs/revamp/C2-approval-port-design.md` §3 (deny gate-a uma tool-call,
   não a intenção do modelo; `Turn` fecha esse gap no lado do adapter).
10. crash do harness no meio da task → `Crashed`, sessão Bastion legível depois.
11. `AuthProfileRef` inválido → `Auth` tipado sem vazamento de secret.
12. declaração registry-vs-sandbox: relatório final da task lista o que passou pelo `CapabilityRegistry` (MCP bridge) vs. ocorreu dentro do harness.
13. **Negativos**: adapter alimentado com stdout humano/ANSI → `Protocol`; binário de versão errada → `Version`; env não permitida ausente do subprocess; bloco `local-only` recusado na montagem do input.
14. Dupla implementação: Codex nativo E Codex-via-ACP passam idênticos (anti-viés de abstração).

## 6. Não-objetivos

- Não é orquestrador/DAG: uma sessão por vez por delegação; coordenação continua no daemon.
- Kernel não conhece Codex/ACP/CLI nenhum — adapters vivem em `bastion-agent-runtime` (crate evolutiva, tabela M1).
- Não replica o `Provider` streaming de tokens: harness entrega deltas/eventos no nível que expõe.
- Não promete paridade de policy entre modos: modo 2 tem cobertura declaradamente menor — o produto mostra, não esconde.

## 7. Pontos em aberto (resolver na implementação, não bloqueiam A-02)

1. `events()` como `BoxStream` vs. canal mpsc concreto (decisão de ergonomia; semântica idêntica).
2. `McpBridgeSpec`: expor MCP servers do Bastion ao harness via config-file (como o legado faz por env) vs. proxy próprio — proxy dá visibilidade `ToolCall` real; config-file é mais simples. Tendência: começar config-file, declarar `tool_visibility: DeclaredOnly`.
3. Persistência do `SessionHandle`: tabela nova vs. coluna na sessão existente (decidir junto do M1-02 em `bastion-sessions`).
4. Granularidade de `UsageDelta` (por evento vs. agregado por task) — depende do que cada harness reporta de verdade.
