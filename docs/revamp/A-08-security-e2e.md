# A-08 — Security / live E2E + versioned policy-coverage matrix

> Trilha A, `docs/revamp/BACKLOG.md` A-08 (absorve o antigo UAT-02: o legado
> não é validado, é substituído — ver A-09). Este documento consolida (1) o
> resultado da suíte de invariantes de segurança do kernel rodada offline,
> (2) o que dos live E2E foi executado barato/offline vs. o que NÃO foi
> executado e por quê (honesto, sem fingir), e (3) a matriz de policy coverage
> versionada (targets × auth × capabilities × coverage), unindo a A-05
> (conformance por adapter) e a `docs/SUPPORT-MATRIX.md`.
>
> **Data da corrida: 2026-07-14** · Loop 3-F · branch `revamp`. Host do owner
> (sem GPU dedicada pra este passo, disco apertado ~6-12 GB livres durante a
> corrida). Toolchain: `stable-x86_64-unknown-linux-gnu`, `CARGO_BUILD_JOBS=2`.

## 0. Veredito

**Nenhuma regressão de invariante de segurança** (egress / approval / trust /
owner-isolation) foi encontrada. Toda a suíte de invariantes roda verde
offline. O split físico (M6) não é bloqueado por segurança por esta corrida.

## 1. Suíte de invariantes de segurança (offline, executada)

As dez (na verdade onze) invariantes de `docs/SECURITY-INVARIANTS.md` são
cobertas por testes determinísticos que rodam sem rede, sem CLI externo e sem
gastar token. Executados explicitamente nesta corrida (além de virem no
`cargo test --workspace` verde, 729 passed / 10 ignored):

| Suíte (offline) | Testes | Invariante(s) coberta(s) (SECURITY-INVARIANTS.md) |
|---|---|---|
| `tests/characterization_boundary.rs` | 8 ok | 1 (superfície única), 3 (egress fail-closed + gate no `ToolSource`), 5 (trust tag em toda saída de approval), 6 (envelope untrusted), 8 (contexto opaco verbatim) |
| `tests/capability_registry.rs` | 6 ok | 2 (tool nomeada, `cmd:` forjado rejeitado, sem overwrite de chave) |
| `tests/fallback_egress_gate.rs` | 4 ok | 3 (egress no caminho de fallback do provider) |
| `crates/bastion-runtime` lib `egress`/`approval`/`registry` unit | 9 ok (`egress`) + (approval/registry no sweep do workspace) | 3 (matriz tier×destino, none→deny), 4 (approval tipado, fail-closed, IDOR guard), 5 (TaggedValue) |
| `tests/evals` owner-isolation | 2 ok (`owner_isolation_distinct_sessions`, `owner_isolation_spoofed_sender_rejected`) + `channel_inbound_*` no sweep | 7 (isolamento por owner/sessão; sender spoofado/unmapped rejeitado) |
| `crates/bastion-memory` sqlite owner-scope | 5 ok (`test_owner_isolation_revoke_and_provenance`, `test_record_belief_outcome_cross_owner_errors`, `test_supersede_belief_cross_owner_errors`, `record_pending_correction_rejects_cross_owner_belief`, `test_pending_correction_owner_scoped`) | 7 (memória/beliefs/proveniência owner-scoped, cross-owner erra) |
| `tests/extension_adversarial.rs` | 7 ok | 2/4 (extensão maliciosa não registra capability não-declarada, zero órfão em rollback) |
| `tests/extension_ui_adversarial.rs` | 4 ok | 6-adjacente (UI isolada: sem `allow-same-origin`, invoke fora do `PermissionSet` bloqueado) |
| `tests/extension_subprocess.rs` | 11 ok | 2/3 (subprocess: `env_clear`, toda pergunta cross-boundary re-checada pelo `PermissionSet`) |
| `tests/agent_runtime_conformance.rs` | 5 ok | 4-adjacente (`PermissionDecision::Deny{scope}`, deny-turn cancela a task — anti route-around-deny no adapter) |
| `tests/agent_runtime_cross_turn_permission.rs` | 3 ok | 4-adjacente (fila de permissão cross-turn owner-scoped, fail-closed no timeout) |
| `tests/tool_fidelity.rs` | 5 ok | fidelidade de diff/artefato do harness |

Invariantes 9 (observabilidade vendor-neutral), 10 (host, não orquestrador) e
11 (estado de negócio fora do Bastion) são propriedades estruturais/de
contrato — verificadas por review + gates de CI (`check-crate-deps.sh`,
grafo acíclico, ausência de tabela de "business object" no schema) e pela
prova do segundo consumidor (M5, `examples/embedded-host-slice`), não por uma
assertion de runtime única. Ver a nota de cada uma em
`docs/SECURITY-INVARIANTS.md`.

## 2. Live E2E — executado vs. NÃO executado (honesto)

### 2.1 Executado offline / token-free nesta corrida

| Item | Resultado | Nota |
|---|---|---|
| `m4_07_unconfigured_auth_profile_fails_closed_before_session_starts` (`tests/agent_runtime_backend_live.rs`, `--ignored`) | **1 passed** | Live de verdade (spawna o health-probe do `acpx`/`claude` reais, presentes no PATH deste host) mas **zero token de LLM** — a resolução de auth falha fail-closed ANTES de qualquer turn abrir. Prova live da invariante 4/auth fail-closed sem custo. |
| `examples/embedded-host-slice` (`cargo run`) | **exit 0** | Segundo consumidor completo (M5): dois owners, zero cross-owner, contexto opaco, quarantine, e a correlação OTel do turn agora carimba o `gen_ai.conversation.id` real por-owner (fix do Loop 3-F, commit do span). Prova as invariantes 6/7/8/11 num host embedded genérico, offline (provider mockado, SQLite temp). |

### 2.2 NÃO executado — requer infra/custo que esta corrida evitou

Marcado explicitamente com o motivo. Nada aqui é "verde fingido".

| Item | Por que NÃO foi executado | Onde já foi provado (evidência existente) |
|---|---|---|
| Turns runtime-backed reais (`a06_*`, `a07_*` em `tests/agent_runtime_backend_live.rs` / `tests/agent_runtime_delegated_task_live.rs`, `--ignored`) | **Gastam token de assinatura/API** (spawnam `acpx+claude` / `codex app-server` e completam turns reais). O brief pede não gastar em cloud caro. | A-06/A-07 já validados AO VIVO em ciclos anteriores — `docs/revamp/A-06-A-07-live.md` (Claude Code + Codex reais, caminho real do daemon). |
| `crates/bastion-agent-runtime/tests/{acpx_live_claude,codex_live,acpx_live_opencode}.rs` (`--ignored`) | Idem — spawnam subprocess de CLI real e gastam token. | A-05 conformance ao vivo — `docs/revamp/A-05-conformance-matrix.md` (§2/§2A/§3, scorecards reais). |
| `tests/mesh_e2e.sh` | Sobe **docker compose multi-container** (`docker-compose.mesh-e2e.yml`) — pesado e disco-intensivo; disco deste host estava em 91-99% durante a corrida. `docker` está no PATH mas o bring-up completo não cabia com folga. | Mecânica de mesh coberta por unit/integration tests no workspace (`bastion-mesh` suites, verdes no sweep). |
| `docker build` da imagem de release | **Não executado** (disco apertado; `buildx`/`hadolint` indisponíveis) — mesmo trade-off registrado no Loop 3-D. | `tests/boot_local_and_hosted.rs` prova o MESMO binário bootando local + hosted-like sem recompilar; Dockerfile revisado estaticamente (sem path/secret hard-coded). Recomendado rodar em CI com disco fresco. |
| `tests/external_agent_e2e.sh`, `tests/stigmergy_live.sh` | São **scripts de procedimento manual** (só ecoam passos + apontam os companheiros automatizados). Os companheiros automatizados (`tests/mcp_client_e2e.rs`, `tests/stigmergy_mechanism.rs`) rodam no sweep do workspace e estão verdes. | Companheiros automatizados verdes no `cargo test --workspace`. |
| Codex **via** `acpx` (célula 3-way da matriz) | **Indisponível** — mismatch de login-mode externo aos adapters (o bridge ACP só anuncia família `gpt-5.3-codex*`, rejeitada sob auth de assinatura ChatGPT). Não é algo que o Bastion roteia. | A-05 §4 documenta a indisponibilidade. |
| Sandbox `Honored` (confinamento real de 1 turn) | Este host **não tem `bwrap` funcional** — o probe `bwrap --unshare-user` retorna `None` (fail-closed), então o mecanismo de sandbox não pôde ser exercitado como `Honored`, só declarado `None`. | A-05 §7 confirmou `None` neste host; a detecção (não declaração otimista) é a garantia — `Partial` só com probe vivo bem-sucedido. |
| GPU / cloud pago | **N/A** — nenhum caminho de segurança do Bastion Core exige GPU ou serviço cloud pago. Não aplicável. | — |

## 3. Matriz de policy coverage versionada (targets × auth × capabilities × coverage)

> **Versão: 0.1.0** (casa a versão de `bastion-agent-runtime`) · derivada dos
> `RuntimeDescriptor` reais + scorecards vivos da A-05, consolidada com
> `docs/SUPPORT-MATRIX.md`. Fonte da verdade do *como* cada célula foi medida:
> `docs/revamp/A-05-conformance-matrix.md` e `docs/revamp/A-06-A-07-live.md`.
> Se divergir do código atual (`crates/bastion-agent-runtime/src/{acpx,codex}.rs`),
> **o código vence** — é bug de doc.

### 3.1 Auth por target

| Target | Runtime id | Auth suportado | Verificado por | Precisa de API key? |
|---|---|---|---|---|
| Model (inferência nativa) | *(n/a — `ConversationBackend::Model`, sempre disponível)* | API key por-provider | a própria chamada ao provider | **Sim, sempre** — o único caminho que exige |
| Codex / ChatGPT | `codex_app_server` | login de assinatura ChatGPT **ou** API key | `AuthProfileRegistry` → `codex login status` (read-only, só exit code) | **Não**, login de assinatura basta |
| Claude Code (via `acpx`) | `acpx_claude` | login de assinatura/OAuth Claude **ou** `ANTHROPIC_API_KEY` | `AuthProfileRegistry` → `claude auth status` (read-only) | **Não** |
| OpenCode (via `acpx`) | `acpx_opencode` | login multi-provider do próprio opencode | `AuthProfileRegistry` → `opencode auth list` (read-only) | **Não** |
| Cursor (ACP) | *(não implementado ainda)* | — | — | — |

Critério M4-07 provado live (`m4_07_subscription_backend_works_without_api_key_live`,
ciclo anterior): instalação pessoal completa um turn runtime-backed com **zero
env var `*_API_KEY`**, só com login de assinatura verificado por referência. A
resolução fail-closed (auth não configurado derruba o turn antes de abrir
sessão) foi **re-verificada AO VIVO nesta corrida** (§2.1).

### 3.2 Capabilities (`RuntimeSupports`)

| Target | Resume | Steer | Usage | Diff | Permission bridge | Sessões concorrentes |
|---|---|---|---|---|---|---|
| `codex_app_server` | ✅ reattach real (`thread/resume`) | ✅ (retry bounded p/ race) | ✅ | ✅ | ✅ bridge real | ❌ 1 turn ativo/thread |
| `acpx_claude` | ❌ `NotResumable` tipado | ❌ `Protocol` tipado | ✅ | ✅ | ❌ `HarnessOwned` | ✅ |
| `acpx_opencode` | ❌ (mesmo, raiz no transporte acpx) | ❌ | ✅ | ✅ (caveat de frame-shape, A-05 §2A) | ❌ `HarnessOwned` | ✅ |

### 3.3 Policy coverage (`PolicyCoverage`)

| Target | Tool visibility | Approvals | Egress | Budget | Sandbox |
|---|---|---|---|---|---|
| `codex_app_server` | `DeclaredOnly` | **`Bridged`** — round-trip `item/*/requestApproval` ↔ `ApprovalGate` | `HarnessOwned` (Bastion filtra o que entra via `TaskInput`) | `Reported` | **Detectado, não declarado** — `Partial` só com probe `bwrap` vivo; `None` fail-closed senão. Nunca `Honored`. |
| `acpx_claude` | `DeclaredOnly` | `HarnessOwned` — acpx resolve prompts sozinho de flags estáticas | `HarnessOwned` | `Reported` | `None` — `--cwd` é hint, não jail |
| `acpx_opencode` | `DeclaredOnly` | `HarnessOwned` (idêntico ao acpx_claude — transporte, não agente) | `HarnessOwned` | `Reported` | `None` |

**`Bridged` vs `HarnessOwned` como propriedade de segurança:** mesmo `Bridged`
(Codex) gateia só *a tool-call que perguntou* — um modelo capaz pode tentar o
mesmo objetivo por outra tool não-gateada após um deny (achado A-05 §5.5). O
default de produto (`DenyScope::Turn`) fecha isso cancelando a task após um deny
em vez de deixar o harness continuar — **enforced no boundary do adapter para
todo target, independente de `ApprovalCoverage`** (testado em
`tests/agent_runtime_conformance.rs::deny_turn_scope_cancels_the_task`).

### 3.4 Status de conformance (live, reproduzível — herdado da A-05)

| Target | Status | Scorecard | Fonte |
|---|---|---|---|
| `acpx_claude` | Done | 9 passed, 5 skipped, 0 failed | A-05 §2 |
| `codex_app_server` | Done | 9 passed, 3 skipped, 2 failed-by-construction (resolvidos em run dedicado de approval-bridge: allow ✅, deny ✅ com o caveat T4) | A-05 §3 |
| `acpx_opencode` | Mostly done | 8 passed, 5 skipped, 1 failed (`artifact_digest`, frame-shape — não-relacionado a auth) | A-05 §2A |
| `codex` via `acpx` | Unavailable | mismatch de login-mode externo | A-05 §4 |

## 4. Follow-ups de segurança (não bloqueantes pro split, registrados)

- **`artifact_digest` do opencode** — `FrameInterpreter` não reconhece o frame
  shape de tool-call/artefato do opencode ainda (A-05 §2A). Não é auth, não é
  invariante de segurança; fidelidade de artefato.
- **Sandbox `Honored`** — nenhum adapter garante confinamento de 1 turn hoje;
  Codex só prova o *mecanismo* (probe `bwrap`), acpx é `None`. Endurecer isso é
  trabalho de adapter + host, não do kernel.
- **`docker build` real + mesh_e2e** — recomendado rodar em CI com disco fresco
  como primeira validação de imagem/mesh multi-container de verdade.
- **Cursor (ACP)** — adapter inexistente; célula de auth/capabilities vazia.
- **Trust cripto de extensão** (`trust_tier_of` sempre `Local`) — verificação de
  assinatura de publisher fica pro M4-13/discovery híbrido.
