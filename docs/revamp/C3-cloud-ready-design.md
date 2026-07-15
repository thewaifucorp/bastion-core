# Loop 3-D — Cloud-ready contract (M4-13..15)

> Status: aceito (design do orquestrador). Escopo: o contrato que deixa a MESMA instância rodar local e hosted, SEM control plane (isso é fora do OSS). A maior parte é encanamento; este doc fixa só os 2 pontos de segurança inegociáveis + a lista de superfície.

## Regra-mãe

O Core **não conhece** billing, marketplace, tenancy ou control plane. Ele expõe um contrato operacional neutro; qualquer plataforma hosted é "só mais um operador" desse contrato — igual a observabilidade ser "só mais um sink". Nada neste ciclo pode introduzir um conceito de nuvem no kernel.

## Ponto de segurança 1 — Secrets por referência (nunca valor)

Já é o padrão do auth (Loop3-B: `AuthProfileRef`, credencial resolvida por comando read-only, nunca token em disco/log/export). Estender pra TODA config de secret do daemon:

- Config/manifests carregam `SecretRef(nome)`, nunca o valor.
- Resolução no boot via provider de secret injetável (env var, arquivo montado, secret manager do operador hosted) — o Core define o trait `SecretResolver`, o operador implementa.
- **Export/import (M4-13) nunca serializa valor de secret** — só as referências. Um `.af`/dump que vaze secret é bug de segurança bloqueante.
- Log/OTel/erro tipado nunca incluem valor resolvido. Teste: dump completo + grep de padrão de secret = vazio (como o grep que fiz no 3-B).

## Ponto de segurança 2 — UI de extensão isolada (CLD-08)

Extensão pode fornecer UI (§1 do extension protocol: `provides: Ui`). Constraint:

- UI de extensão roda isolada por capability/sandbox — **proibida execução arbitrária same-origin** com a UI embutida do Bastion. Sem acesso ao DOM/estado da UI host, sem chamadas privilegiadas não-mediadas.
- A UI de extensão fala com o backend só pelo mesmo `CapabilityRegistry` (mediado, com as permissões declaradas no manifest), nunca por um canal privilegiado direto.
- Teste adversarial (estende a suíte do 3-C): UI de extensão tentando (a) executar script no contexto da UI host, (b) chamar capability fora do PermissionSet → bloqueado.

## Superfície (encanamento — delegável)

M4-13 (contrato cloud-ready):
- **Daemon API + eventos**: superfície HTTP/eventos estável (reusa o axum/webhook existente) — health, readiness, lifecycle (start/stop/reload), stream de eventos.
- **Health/readiness**: endpoints distintos (liveness ≠ readiness — readiness só true quando providers/canais/stores prontos).
- **Volume persistente**: paths de estado (sessão/memória/loadout) injetados pelo host, nunca hardcoded (o substrato já não assume paths globais — M4-03/regra do ADR).
- **Import/export**: `.af` versionado (INTEROP-01 já existe) + `schema_version` + id do produtor; secrets por referência (ponto 1).
- **Hook de auth**: ponto onde o operador hosted injeta autenticação de acesso ao daemon (não confundir com auth de provider — é quem-fala-com-o-daemon).
- **Container reproduzível**: Dockerfile do produto builda determinístico; a MESMA imagem roda local e hosted.
- **UI embutida idêntica local/hosted**: a UI que já existe (cockpit) cobre conversa/tarefas/memória/canais/loadout; a "Cloud Console" (billing/lifecycle) é do operador, FORA daqui.

## Critérios de aceite

1. Mesma imagem/binário roda local (paths locais) e "hosted-like" (paths/secrets injetados) sem recompilar — teste de boot nos dois modos.
2. Export completo + grep de secret = vazio; secret só por referência.
3. Readiness só true com dependências prontas; liveness independente.
4. UI de extensão isolada: suíte adversarial (2 vetores) verde.
5. Nenhum símbolo de billing/marketplace/tenancy/control-plane no código (grep no CI, junto do scrub).
6. Gates padrão + check-crate-deps + baseline. Kernel não ganha dep de nuvem.

## Fora de escopo (control plane / M6+)

Cloud Console, billing, marketplace, multi-tenancy, provisioning, resource kinds. Este ciclo entrega só o contrato que TORNA a instância hosteável — não hospeda.
