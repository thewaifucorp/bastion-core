# Loop 3-E — M5: segundo consumidor (host embedded genérico)

> Status: aceito (design do orquestrador). O teste que prova que o boundary do M2 não foi desenhado só pro Bastion Agent. Decisão do owner (#M5): **host embedded genérico neutro** — sem nome de produto/consumidor fechado, scrub público mantido. Vira template público.

## Por que M5 existe

O `embedded-host` exemplo (M3) já compila contra as crates. Mas "compila" ≠ "prova o boundary". M5 exige um consumidor que exercite o que só um SEGUNDO owner-de-verdade revela: assumptions de single-owner escondidas, contexto autoritativo injetado de fora, policy fechada por adapter, propagação de regra versionada. Se qualquer um exigir fork do substrato ou import do Agent, o boundary falhou e volta pro M3.

Critério-mãe (gate de saída): **zero import de `bastion` (o app), zero fork/patch de qualquer crate do substrato.** O host embedded usa só a API pública das crates. Se precisar de um `pub` novo, é um furo de API — documentar, e é resultado válido (como os exemplos do M3 acharam os furos de approval).

## O que o slice é

Um binário/crate de exemplo `examples/embedded-host-slice` (ou expansão do `embedded-host` existente) que simula um operador fechado hipotético SEM nomeá-lo — "um host que injeta contexto autoritativo e governa policy". Neutro: pode ser lido como um runtime de equipe, um serviço, qualquer coisa. Nada corporativo.

### Componentes (todos via API pública)

1. **`AgentDefinition` owner-local criada FORA do Agent** — o host constrói a definição programaticamente (não via config pessoal do Bastion Agent), provando que persona/AgentDefinition é primitiva compartilhada, não feature do produto pessoal.
2. **Contexto autoritativo via `TurnContextProvider`** — o host injeta um bloco de contexto opaco (simulando "estado de negócio autoritativo") pelo port público; o kernel concatena sem interpretar (SEAM #2). Sem patch no runtime.
3. **Capability dinâmica object-scoped** — o host registra uma capability nomeada via API pública do `CapabilityRegistry` (ex.: "aprovar_X", escopada a um objeto), provando extensibilidade sem raw SQL, sem fork do registry.
4. **Policy fechada via adapter** — uma `ApprovalGate`/policy custom (do Ciclo 2.1) implementada pelo host que NEGA uma ação por regra própria; mostra o `Err(ApprovalDenied)` tipado. Sem tocar no kernel.
5. **Dois owners** — o teste roda a definição pra owner A e owner B; prova isolamento de sessão/memória (nada de A vaza pra B) e revela assumptions single-owner se houver.
6. **OTel neutro correlacionável** — o turn emite spans que o host correlaciona com "seu objeto", sem o Core conhecer a timeline externa.
7. **Trust/spotlighting preservados** — conteúdo injetado como untrusted não ganha autoridade.

## M5.1 — propagação de regra versionada (`RuleBundle`)

O contrato `VersionedContextArtifact`/`ContextRevision` (M1-04) provado end-to-end:

1. Host publica `RuleBundle v1` (bloco de contexto versionado) pra owner A.
2. Dois "workers" (duas sessões/definições) de owner A aplicam v1; um terceiro de owner B **não recebe** (scope por owner).
3. Host publica `v2` com `effective_from`; **nenhum turn em andamento troca de regra no meio** — a revisão só entra no boundary entre turns.
4. Próximo turn usa v2; trace registra a versão aplicada.
5. Rollback pra v1 propagado e auditável.
6. "Worker" offline recupera a revisão correta ao voltar.
7. Regra crítica stale segue policy explícita (última válida OU fail-closed — o host escolhe).

Critério: regra nova atinge os agentes certos **sem rebuild/redeploy, sem cross-owner, sem depender de o LLM lembrar de buscar**. O OSS só precisa do artefato opaco versionado + provenance + `effective_from` + estratégia de stale; o resto (publicação, fan-out) é do host.

## Escopo público / scrub

O slice é lido como genérico. Zero: nome de consumidor fechado, "Company Brain", "Agent Dojo", "worker corporativo", tenancy. Vocabulário neutro: "host embedded", "operador", "contexto autoritativo", "regra versionada", "owner". O detalhamento de como o consumidor fechado real usa isso vive no repo privado, não aqui.

## Critérios de aceite (gate de saída M5)

1. **Zero import de `bastion` (app); zero fork/patch de crate do substrato.** Verificável: o Cargo.toml do slice depende só de `bastion-*` crates.
2. Os 7 componentes rodam; 2 owners provam isolamento.
3. M5.1: os 8 passos de propagação de regra passam.
4. Furos de API achados (se houver) documentados — cada `pub` que faltou é um finding, volta pro backlog do M3/kernel.
5. `AgentDefinition` a mesma usada pelo Agent pessoal serve o host sem fork de schema (a tese persona→worker, provada por construção).
6. Gates padrão + check-crate-deps (o slice é um consumidor, entra como o `embedded-host`) + baseline.
7. Nenhuma entidade do host persiste no session store do Bastion (o estado autoritativo é do host, o Bastion só tem sessão/memória do agente).

## Não-objetivos

Não é o consumidor fechado real (esse é privado, decisão #9 = spike promovível — o slice PODE virar a fundação dele depois, mas aqui é genérico). Não implementa Ontology/OCC/timeline de negócio (fora do OSS). Não é multi-tenant.
