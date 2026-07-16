# Terminal-agent providers (Claude Code / opencode)

> **DEPRECADO:** substituído por `AgentRuntime`
> (`bastion-agent-runtime`'s `CodexAppServerRuntime`/`AcpxAgentRuntime`) —
> sessão estruturada, eventos reais, sem bypass de egress/approval/budget. Este provider
> agora só compila com a Cargo feature `legacy-terminal-agent` (**OFF por default** —
> `cargo build --features legacy-terminal-agent`, ou no crate isolado
> `cargo build -p bastion-providers --features legacy-terminal-agent`). Mantido por uma
> janela de depreciação (código não removido), não é mais linkado num build padrão.

Rode o Bastion **em cima de um agente de terminal** (`claude` ou `opencode` em modo headless) como
executor do turn, em vez de chamar uma API de LLM. Útil quando você tem acesso ilimitado ao Claude Code:
o Bastion vira o cérebro (roteamento, personas, memória, hooks) e o CC faz a execução — incluindo
Telegram e mobile, já que o CC roda no host do daemon e o canal é só front-end.

> **Opt-in, por-deployment.** NÃO é o default do Bastion OSS. Troca por egress gate, budget e o
> tool-loop nativo (ver [Limitações](#limitações)). Indicado p/ uso pessoal cloud.

## Ligar

```bash
cargo build --features legacy-terminal-agent
BASTION__AGENT__DEFAULT_MODEL=claude_code  bastion daemon   # ou =opencode
```

`registry.rs` resolve `claude_code` → bin `claude`, `opencode` → bin `opencode`. O host do daemon precisa
ter o CLI **instalado e autenticado** (`claude` logado) — o provider usa essa auth, sem API key.

> ⚠️ **Incompatível com o deploy Docker padrão (installer.sh).** O container `core` é `FROM scratch` —
> só o binário do Bastion, sem `claude`, sem node, sem shell: o spawn falha por construção. Este provider
> exige o daemon rodando **no host**. O binário é musl estático — dá pra extrair da imagem já buildada,
> sem toolchain: `docker create --name x bastion-core:latest && docker cp x:/bastion ./bastion-host && docker rm x`.

Rodando local (sem docker), passe paths graváveis senão dá os-error-13 nos paths `/bastion-data`:

```bash
BASTION__AGENT__DEFAULT_MODEL=claude_code \
BASTION__SESSION__DB_PATH=$PWD/.bastion/sessions.db \
BASTION__LOGGING__LOG_PATH=$PWD/.bastion/bastion.log \
cargo run -q -- daemon
```

## Qual modelo o Claude Code usa

Pro `claude` (CC), o provider passa `--model` — **default `claude-haiku-4-5-20251001`** (Haiku 4.5:
barato + rápido). Trocar via env, sem código:

```bash
BASTION_TERMINAL_AGENT_MODEL=claude-sonnet-4-6  BASTION__AGENT__DEFAULT_MODEL=claude_code  bastion daemon
```

Pro `opencode` o `--model` não é passado (sintaxe diferente) — ele usa o próprio default; configure no
opencode se quiser trocar.

## Tools (memória, skill-writer) — config obrigatória

Com o CC como executor, ele roda o **próprio** tool-loop → o Bastion nunca vê `tool_calls`, então
memupalace/skill-writer/MCP **não disparam pelo lado do Bastion**. Fix: aponte o CC pros **mesmos** MCP
servers do daemon. Ele chama no loop dele, gravando na **mesma** memupalace → um cérebro só.

> As URLs do `bastion.toml` (`http://memupalace:8001/...`) são hostnames do docker network. O CC roda no
> HOST → use `localhost:800X` se publicar as portas no compose, ou rode o CC na mesma rede docker.

**Por daemon (recomendado p/ multi-instância)** — o provider repassa um MCP config e a allowlist de
tools direto pro `claude -p`, sem tocar config global do usuário. Ideal quando cada daemon aponta pra
servers diferentes (ex.: um companion com memupalace, um executor com o MCP de um board externo):

```bash
BASTION_TERMINAL_AGENT_MCP_CONFIG=$PWD/cc-mcp.json \
BASTION_TERMINAL_AGENT_ALLOWED_TOOLS="mcp__memupalace mcp__skill-writer" \
BASTION__AGENT__DEFAULT_MODEL=claude_code  bastion daemon
```

`BASTION_TERMINAL_AGENT_MCP_CONFIG` = path de um MCP config do Claude Code (formato abaixo).
`BASTION_TERMINAL_AGENT_ALLOWED_TOOLS` é **necessário** no headless: `-p` não tem como responder prompt
de permissão — tool MCP não pré-aprovada é recusada silenciosamente.

**Claude Code global** (`.mcp.json` no projeto, ou `claude mcp add ... -s user`):

```json
{
  "mcpServers": {
    "memupalace":     { "type": "http", "url": "http://localhost:8001/mcp" },
    "skill-writer":   { "type": "http", "url": "http://localhost:8002/mcp" },
    "self-improving": { "type": "http", "url": "http://localhost:8003/mcp" }
  }
}
```

```bash
claude mcp add memupalace     --transport http http://localhost:8001/mcp -s user
claude mcp add skill-writer   --transport http http://localhost:8002/mcp -s user
claude mcp add self-improving --transport http http://localhost:8003/mcp -s user
```

**opencode** (`~/.config/opencode/opencode.json` — confira a sintaxe da sua versão):

```json
{
  "mcp": {
    "memupalace":     { "type": "remote", "url": "http://localhost:8001/mcp", "enabled": true },
    "skill-writer":   { "type": "remote", "url": "http://localhost:8002/mcp", "enabled": true },
    "self-improving": { "type": "remote", "url": "http://localhost:8003/mcp", "enabled": true }
  }
}
```

## O que funciona / o que muda

**Funciona sem mexer** (rodam na loop, em volta da chamada — o CC é só o executor): router, personas,
cabinet, injeção de identidade/memória (recall), input-guardrail, output-validator, proactive/heartbeat,
weight-system, life-log, e os canais (stdin, **Telegram**, webhook, app mobile).

**Limitações:**
- **Egress gate** em volta das tools do CC é bypassado (o CC chama os MCP direto). Aceitável p/ deploy
  cloud pessoal; **não** use em deploy com persona `local-only`.
- **Budget** (`daily_budget_usd`) não se aplica ao caminho CC.
- **Store de memória** depende do CC decidir chamar `memory_add` (o system prompt instrui; o CC obedece
  bem). Se notar que não persiste, o plano B é store determinístico pós-turn (não implementado, YAGNI).

**Recall sem tool-calling (`BASTION_MEMORY_RAG=1`):** o `MemoryRagProvider` (SEAM #2) injeta os beliefs
locais relevantes direto no system prompt — recall funciona mesmo com o CC nunca emitindo `tool_calls`,
e respeita privacy tiers (blocos separados por tier; o egress derruba só o LocalOnly em provider cloud).
Opt-in; complementa (não substitui) o memupalace semântico via MCP acima.

## Telemetria no REPL

Os spans OTel não vão mais pro stdout por padrão (poluíam o REPL). Pra ver: `BASTION_OTEL_STDOUT=true`.
