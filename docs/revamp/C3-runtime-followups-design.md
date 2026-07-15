# Loop 3-A — M4 runtime follow-ups (findings 6a/6c/6d)

> Status: aceito (design do orquestrador). Fecha os 3 furos do Ciclo 2.4 que o BackendProfile deixou honestamente abertos. 6a/6d são boundary de segurança; 6c é higiene de CI.

## 6a — Aprovação cross-turn genuína

**Problema:** um `PermissionRequest` levantado dentro de `run_runtime_backed_turn`/consumer de task delegada não pode esperar resposta NL de um turno posterior — o daemon serializa por um `&mut agent` (lei do AGENTS.md). Ciclo 2.4 resolveu fail-closed (`Deny{Turn}` sempre). Agora: aprovação real sem bloquear o daemon.

**Design — fila assíncrona correlacionada, nunca bloqueio síncrono:**

```rust
// bastion-runtime — canal dedicado, NÃO o pending_tx reaproveitado
pub struct PendingPermission {
    pub id: PermissionRequestId,
    pub owner: String,
    pub session: SessionHandle,      // task/sessão que espera
    pub action: PermissionAction,
    pub detail: String,
    pub raised_at: Nanos,
    pub expires_at: Nanos,           // timeout → Deny{Turn} automático (fail-closed)
}
```

Fluxo:
1. Harness emite `PermissionRequest` → adapter NÃO responde na hora; enfileira `PendingPermission` no `ApprovalGate` (persistido, owner-scoped) e a task **pausa** (o adapter segura o turno do harness; se o protocolo não permite pausar indefinidamente, aplica o timeout → Deny, já é o comportamento fail-closed de hoje).
2. Bastion notifica o owner pelo canal dele (a resposta vem como turno normal, NÃO mid-turn — respeita "sem intervenção mid-conversation" do PROJECT).
3. Owner responde ("aprovo o X") → um turno posterior resolve o `PendingPermission` por `id` → `respond_permission(id, decision)` no adapter, task retoma.
4. Timeout/owner nega → `Deny{scope}` (Turn encerra a task, do Ciclo 2.1).

Invariante: **nenhuma espera síncrona segura o `&mut agent`**. O request vive na fila; o daemon segue servindo outros turnos. A correlação é por `PermissionRequestId` + `SessionHandle` persistidos. Se o daemon reinicia com um request pendente, ele sobrevive na fila (owner-scoped) e o adapter reata via resume — ou expira fail-closed.

Escopo honesto: se um harness não suporta pausar a task aguardando resposta externa (a maioria dos CLIs não), o comportamento efetivo continua `Deny{Turn}` no timeout — mas a INFRA de fila + notificação + resolução-por-turno-posterior fica pronta e testada com o FakeRuntime, e funciona plenamente com qualquer harness que exponha pausa. Documentar a matriz de suporte por adapter.

## 6d — Owner-routing do pending_tx

**Problema:** `pending_tx`/`pending_rx` (seam PROACT-05) sempre entrega pro `DEFAULT_OWNER` — construído single-owner. Resultado de task delegada de um owner poderia chegar como turno proativo do owner errado.

**Design:** o item enfileirado carrega `owner: String` explícito; o consumer roteia pela identidade do owner (mesmo mapa que os canais já usam pra resolver destino). `DEFAULT_OWNER` vira fallback só quando o item não tem owner (nudges de goal-drift legados). Teste: dois owners, task de cada, entrega cruzada = falha.

Critério: resultado de task/nudge de owner A nunca é entregue no canal/sessão de owner B.

## 6c — regex `pub async fn` no baseline

`scripts/dump-public-api.sh` casa `pub fn` mas não `pub async fn` — toda a superfície async pública do kernel (`run_turn`, `delegate_task`, etc.) é invisível ao baseline. Fix: regex `pub(\s+async)?\s+fn` (e `pub(\s+(async|unsafe))*` defensivo). Regenerar todos os `docs/api-baseline/*` — o diff vai REVELAR a superfície async que estava escondida (esperado, não é regressão; commitar o baseline expandido). CI `--check` passa a cobrir de verdade.

## Ordem e gates

Commits separados por finding (6c primeiro — barato e revela superfície pros outros dois; depois 6d; depois 6a que é o maior). Gates padrão + `check-crate-deps` + `dump-public-api --check`. Default preservado: quem não usa runtime-backed/delegated não vê diferença. Testes live não obrigatórios aqui (a infra é testável no FakeRuntime); um smoke live opcional se barato.
