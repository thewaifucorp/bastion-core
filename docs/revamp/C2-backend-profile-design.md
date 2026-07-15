# Ciclo 2.4 — BackendProfile + A-06/A-07 (M4 início)

> Status: aceito (design do orquestrador). Primeira integração do `AgentRuntime` (Trilha A) no fluxo real do daemon. Escopo: wiring + prova E2E live; UX/config-de-usuário fina fica pro M4 pleno.

## 1. O problema

Hoje o turn sempre nasce de um `Provider` (inferência nativa, Bastion possui o tool-loop). A Trilha A entregou `AgentRuntime` (harness externo possui o loop), validado em conformance mas **sem nenhum consumidor no daemon**. O `BackendProfile` é o seletor que decide, por owner/sessão, qual dos dois caminhos atende o turn — sem transformar harness em `Provider` (a lei do A-01).

## 2. Contrato

```rust
// bastion-runtime (kernel — é política de roteamento de turn, não de produto)
pub enum ConversationBackend {
    /// Inferência nativa: Bastion possui o tool-loop (caminho atual).
    Model,                    // usa o SharedProvider já existente
    /// Runtime-backed: harness externo possui o loop do turn.
    Runtime(String),          // id do AgentRuntime registrado (ex.: "codex_app_server")
}

pub struct BackendProfile {
    pub conversation: ConversationBackend,
    /// Runtime opcional pra tarefas delegadas (A-07) — independente do backend
    /// de conversa. None = delegação desligada.
    pub task_runtime: Option<String>,
    /// Referência de credencial por backend (ortogonal — A-01 §1.1).
    pub auth: Option<AuthProfileRef>,
    /// Declaração de cobertura de policy do modo escolhido, propagada do
    /// descriptor do runtime pro produto exibir (não é decisão nova).
    pub coverage_note: Option<PolicyCoverage>,
}
```

Default = `ConversationBackend::Model` + `task_runtime: None` → **comportamento idêntico ao de hoje** (nenhum usuário existente muda de caminho sem opt-in).

Registro: o daemon mantém um `RuntimeRegistry: HashMap<String, Arc<dyn AgentRuntime>>` populado na composição (`main.rs`) com os adapters disponíveis (Codex/acpx conforme auth+health). O kernel resolve `Runtime(id)` contra esse registry; id ausente/unhealthy = erro tipado no início do turn, fail-closed (cai pro Model? NÃO — erro explícito; fallback silencioso esconderia perda de policy coverage).

## 3. Fluxo por modo

**Modo 1 (Model)** — inalterado.

**Modo 2 (Runtime primary, A-06):** no início do turn, se `conversation == Runtime(id)`:
- Bastion monta o `SessionSpec` (workspace = dir de trabalho do owner; egress já filtrou o contexto que entra no `TaskInput`; auth do profile; permission profile do owner).
- Abre/reata sessão (`SessionHandle` persistido na sessão Bastion — restart recovery), `submit(TaskInput)`, consome eventos → traduz `MessageDelta` pro stream de resposta do canal, `PermissionRequest` → ponte pro `ApprovalGate` (do Ciclo 2.1!), `Artifact`/`Diff` → anexos da resposta, `Usage` → budget.
- Bastion continua dono de: identidade, memória (grava a resposta), canais, supervisão, OTel. O harness é dono do tool-loop interno — a UI marca "harness tool loop" (coverage_note).

**Modo 3 (delegated task, A-07):** conversa segue no backend de conversa (Model ou Runtime); uma tool/comando `delegate_task` dispara `task_runtime.submit()` numa sessão SEPARADA, assíncrona; a conversa permanece responsiva; quando a task termina, o resultado/artefatos voltam como evento pro owner. Cancelamento e resume da task independentes do turn de conversa.

## 4. A-06 / A-07 — provas E2E live

- **A-06:** turn real de conversa inteiramente servido por `AcpxAgentRuntime`→Claude Code local (auth da máquina). Prompt simples, resposta volta pelo caminho normal do daemon, memória grava, OTel correlaciona. Prova que o modo 2 funciona ponta-a-ponta, não só em conformance.
- **A-07:** com conversa ativa (Model), delegar uma tarefa de código curta ao `task_runtime` (Codex ou acpx), conversar em paralelo enquanto roda, receber o diff/artefato ao fim, cancelar uma segunda task no meio, e provar resume após restart simulado.

## 5. Critérios de aceite

1. Default preserva comportamento: suite inteira verde sem tocar em config existente.
2. `BackendProfile` selecionável por owner (config + toml); troca de backend NÃO perde memória/sessão Bastion (mesmo store).
3. A-06 live: 1 turn de conversa via runtime-backed, resposta correta, `PolicyCoverage` exibido, memória gravada.
4. A-07 live: task delegada com conversa concorrente + cancel + resume pós-restart.
5. `PermissionRequest` do harness cai no `ApprovalGate` do Ciclo 2.1 (allow e deny, deny com `DenyScope::Turn` cancelando a task).
6. Runtime id inválido/unhealthy = erro tipado no início do turn, nunca fallback silencioso.
7. Nenhum adapter implementa `Provider`; dispatcher escolhe por config, nunca downcast.

## 6. Fora de escopo (M4 pleno)

Login guiado/OAuth interativo, seleção de backend por UX rica, matriz de assinatura versionada, `task_runtime` como tool exposta ao modelo com policy fina. Aqui: config declarativa (toml) + provas live.
