# Ciclo 2.1 — Approval como port, rejeição tipada, trust parity

> Status: aceito (design do orquestrador; owner revisa a decisão de escopo do deny aqui). Fecha LOOP-REPORT findings #3 e #4. Pré-requisito do M5.
> **Este passo contém a primeira mudança de comportamento deliberada do revamp** (rejeição tipada). Testes de caracterização afetados são ATUALIZADOS junto, com nota no mapa — exceção consciente à regra "asserts nunca mudam", não um acidente.

## 1. `ApprovalGate` — port no kernel

Trait em `bastion-runtime` (junto dos demais ports) com a superfície EXATA que `CapabilityRegistry::invoke` consome hoje de `ApprovalQueue` (derivar assinaturas do uso real — comportamento preservado, tipos `ApprovalStatus`/`ApprovalOutcome`/`ApprovalRow` continuam o vocabulário, movendo pra `bastion-types` se forem dados puros). `ApprovalQueue` (SQLite) vira `SqliteApprovalGate: impl ApprovalGate` — mesmo arquivo, mesma lógica, atrás do trait.

Injeção: `CapabilityRegistry` (ou o loop, conforme onde a queue vive hoje) recebe `Arc<dyn ApprovalGate>` na construção. `main.rs` injeta o SQLite; `examples/embedded-host` injeta a policy custom dele (o exemplo já demonstra o gap — atualizar pra demonstrar o fix). **Sem `Option`**: approval é obrigatório; quem não quer fila persistente injeta um gate allow-nothing/deny-all explícito.

## 2. Rejeição tipada (a mudança de comportamento)

Hoje: `outcome_for_existing_row` mapeia `Rejected` → `AlreadyPending`; re-invocar ação negada devolve `Ok({awaiting_approval:true})` pra sempre. O chamador não distingue "aguardando" de "negado".

Novo comportamento:

- `BastionError::ApprovalDenied { capability: String }` em `bastion-types` (padrão `PrivacyEgressBlocked` — simetria deliberada).
- `invoke()` sobre row `Rejected` retorna `Err(ApprovalDenied)` — uma vez sinalizado, o registro rejeitado é consumido/marcado (não vira loop eterno de Err; semântica de consumo = derivar do ciclo de vida atual das rows, preservando auditoria).
- Tool-loop do kernel trata `ApprovalDenied` como resultado de erro estruturado pro modelo (paridade com o caught-error de egress), NÃO como crash do turn.

## 3. Escopo do deny (decisão de design — T4-adjacente, LOOP-REPORT #5.5)

Achado live: negar UMA tool-call não impede o modelo de contornar por outra tool. Decisão:

```rust
pub enum DenyScope {
    /// Nega só esta invocação (comportamento atual).
    Instance,
    /// Nega e ENCERRA o tool-loop do turno — fail-closed contra roteamento
    /// alternativo. O turno termina com o texto já produzido + aviso.
    Turn,
}
```

- `ApprovalGate` resolve com escopo; **default do produto = `Turn`** (fail-closed: usuário que nega uma ação quase nunca quer a mesma intenção por outro caminho). `Instance` fica disponível pra UX futura ("negar só isso").
- `PermissionDecision::Deny` do contrato `AgentRuntime` ganha o mesmo escopo (tarefa 2.2 alinha); adapters mapeiam `Turn` → cancel graceful da task.

## 4. Trust parity nos bypass paths (finding #4)

Os dois call sites de bypass (`dispatch_tool_loop` fallback vazio + `run_provider_fallback`) recebem hoje o JSON cru do `ToolSource`. Fix: aplicar ao resultado o MESMO envelope untrusted (`TaggedValue`/spotlighting) que `registry.invoke` aplica a capability não-local — derivar do wrapping existente em `capability/registry.rs` e reutilizar a função (extrair helper se preciso), nunca duplicar. Teste de invariante novo em `characterization_boundary`: resultado vindo do bypass carrega marca untrusted idêntica à do caminho registry.

## 5. Critérios de aceite

1. `embedded-host` injeta `ApprovalGate` próprio e observa `Err(ApprovalDenied)` — asserts do exemplo atualizados (eles foram escritos pra quebrar neste momento).
2. Deny com `DenyScope::Turn` encerra o tool-loop: teste kernel com double que nega e segunda tool disponível — a segunda NUNCA executa.
3. Caracterização: testes de approval atualizados com nota "behavior change ciclo 2.1" no mapa; todos os demais intactos.
4. Zero referência a `ApprovalQueue` concreto fora da impl SQLite + composição do app.
5. Gates padrão + `check-crate-deps.sh` verdes; contagem de testes só cresce.
