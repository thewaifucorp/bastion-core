# Loop 3-C — Extension Protocol + Host (M4-08..12)

> Status: aceito (design do orquestrador). Maior superfície de segurança nova do revamp: código de terceiros entra no runtime. Regra-mãe: **instalar uma extensão NUNCA concede autoridade — capabilities, memória, rede, devices e egress continuam mediados pelos contratos existentes.** Uma policy extension só PODE restringir grants; nunca ampliar.

## 1. Crate `bastion-extension-protocol` (kernel-adjacente, estável cedo)

Contratos, zero I/O de produto. Depende só de `bastion-types`.

### 1.1 Manifesto

```rust
pub struct ExtensionManifest {
    pub id: String,                    // "publisher/name", namespacing global
    pub version: semver::Version,
    pub kind: ExtensionKind,           // Declarative | Wasm | Subprocess | NativeCrate
    pub compat: semver::VersionReq,    // range de bastion-extension-protocol suportado
    pub provides: Vec<Provided>,       // Provider|Channel|Capability|Memory|Cognition|Trigger|Ui|Service|Policy
    pub requires: Vec<Requirement>,    // outras extensões/versões
    pub permissions: PermissionSet,    // §2 — declarado, revisável, nunca implícito
    pub secrets: Vec<SecretRef>,       // por referência (nome), nunca valor
    pub entrypoint: Entrypoint,        // por kind
    pub migrations: Vec<MigrationRef>,
    pub signature: Option<Signature>,  // publisher signing; ausência → trust `local`
}

pub struct PackManifest {   // composição, não ganha authority própria
    pub id: String,
    pub version: semver::Version,
    pub extensions: Vec<(String, semver::VersionReq)>,
    pub skills: Vec<String>,
    pub personas: Vec<String>,
    pub defaults: LoadoutDefaults,
}
```

### 1.2 Permissões (declaração explícita, deny-by-default)

```rust
pub struct PermissionSet {
    pub capabilities: Vec<String>,     // nomes de capability que pode registrar/invocar
    pub egress: EgressScope,           // None | LocalOnly | Hosts(Vec<String>)
    pub filesystem: FsScope,           // None | WorkspaceRo | WorkspaceRw | Paths(...)
    pub devices: Vec<DeviceKind>,      // audio/video/serial... default vazio
    pub network_bind: bool,            // pode abrir socket de escuta?
    pub memory_scope: MemoryScope,     // None | ReadOwn | ReadWriteOwn — NUNCA cross-owner
}
```

O host materializa isso: uma extensão declara `egress: Hosts(["api.x.com"])` e o egress chokepoint existente (`check_egress`) passa a conhecer só esses hosts pra ela. Nada declarado = negado. **A extensão não consegue registrar uma capability fora de `permissions.capabilities`** — enforcement no host, não confiança.

### 1.3 Trust tiers

`official | verified | community | local`. `signature` verificada define o teto; `local` (sem assinatura) = dev, permitido mas marcado. O host EXIBE o tier + o `PermissionSet` em linguagem humana no install (M4-09). Trust tier **não amplia** permissão — só informa risco; um `community` com `egress: Hosts([...])` ainda passa pelo mesmo enforcement que um `official`.

## 2. Os três mecanismos (M4-08, primeiro release)

| Kind | Isolamento | Uso | Enforcement de permissão |
|---|---|---|---|
| `Declarative` | N/A (dados) | skills, personas, triggers, config | host lê o artefato; nenhum código roda |
| `Wasm` | sandbox WASM/WASI, sem syscalls fora do que o host concede | componentes portáveis puros | imports WASI restritos ao `PermissionSet`; sem ambient authority |
| `Subprocess` | processo separado, `env_clear`+allowlist (padrão dos adapters A-04), protocolo versionado stdio JSON | integrações com rede/devices/SDKs próprios | host media o canal; egress/capability declarados; processo não herda env/secrets do daemon |
| `NativeCrate` | nenhum (linkado) | extensões oficiais de alta confiança / host embedded | só `official`; review humano |

WASM e Subprocess reusam o mesmo modelo de capability do kernel — a extensão pede ao host, o host aplica policy, nunca acesso direto a filesystem/secrets/registry.

## 3. Extension host + package manager (M4-08, no app `bastion-agent`)

**Fora do kernel** (é produto). Responsabilidades:
- resolução de dependências + **lockfile reproduzível** (`loadout.lock` — id+version+hash+signature por componente);
- instalação **atômica** (all-or-nothing; falha não deixa estado parcial);
- upgrade/rollback/revoke — **remoção não deixa capability/secret/processo órfão** (critério de aceite);
- upgrade incompatível (compat range) **bloqueado antes** de alterar o loadout ativo;
- verificação de assinatura + resolução de trust tier;
- resumo humano de permissões no install (M4-09).

## 4. Loadout (M4-10)

`Loadout` = conjunto resolvido de extensões+versões ativas numa instância de agente. `Experience`/`Pack` = setup guiado que produz um Loadout com defaults seguros. **O loadout efetivo é limitado pelos grants da `AgentDefinition`/instância** — um pack não pode ativar um componente que peça mais autoridade do que a instância tem. Policy extension só restringe.

## 5. Subagente e agente coletivo (M4-11)

- **Subagente** = delegação limitada: objetivo, contexto derivado, subconjunto de capabilities, budget e prazo — herda ≤ do pai, nunca >.
- **Agente coletivo** = owner/grupo explícito, participantes, memória privada vs. compartilhada, identidade do solicitante preservada, credenciais coletivas, conflict policy. Nunca "agente pessoal sem dono".

Extensões podem fornecer templates/routers pra esses, mas **não alteram essas invariantes** (são do kernel/host).

## 6. Pack de referência (M4-12)

Pack do uso real do owner (Life OS/Developer — dogfooding), compondo ≥3 extensões de kinds diferentes (ex.: uma declarative skill + um subprocess adapter + um trigger), provando o ciclo completo: **install → permission review → Loadout resolvido → execução → upgrade → rollback**, sem deixar órfãos.

## 7. Escopo deste ciclo vs. depois

ESTE ciclo (Loop3-C): a crate de protocolo + host + os 3 mecanismos com uma extensão de referência por kind passando conformance + o pack de referência. NÃO neste ciclo: registry/catálogo público (é o item de discovery híbrido, decisão #12 — vem depois, agentskills.io pra skills já existe); marketplace; monetização.

## 8. Critérios de aceite

1. Extensão de referência de cada kind (declarative/wasm/subprocess) passa conformance SEM receber acesso implícito a processo/secrets/filesystem/registry.
2. Instalar → resolver loadout → executar → upgrade → rollback → revoke: reproduzível, zero órfão (capability/secret/processo).
3. Extensão maliciosa de teste tentando (a) registrar capability não-declarada, (b) egress a host não-concedido, (c) ler memória cross-owner, (d) abrir socket sem `network_bind` → TODAS bloqueadas com erro tipado, cobertas por teste adversarial.
4. Pack não amplia autoridade: teste com pack pedindo mais que a instância → bloqueado antes de ativar.
5. Upgrade incompatível bloqueado antes de tocar o loadout ativo.
6. Gates padrão + `check-crate-deps` (nova crate entra na allowlist) + baseline de API.
7. `#![forbid(unsafe_code)]` — WASM host provavelmente traz dep com unsafe; isolar num crate de adapter que declare o unsafe explicitamente, kernel/protocol permanecem forbid.
