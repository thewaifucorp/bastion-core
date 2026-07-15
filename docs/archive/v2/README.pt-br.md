# 🏰 Bastion

> **ARQUIVADO:** esta página descreve a v2 OpenClaw removida. A fonte ativa é [o README raiz](../../README.md), reconciliado com o runtime Rust v1.1. Não use as features/roadmap abaixo para planejar trabalho novo.

Seu assistente pessoal de IA, rodando 100% no seu computador ou servidor. O Bastion aprende como você trabalha, se adapta às diferentes áreas da sua vida e te ajuda a manter o foco no que importa — sem compartilhar seus dados com ninguém.

## O que é?

Agente de IA self-hosted construído sobre o [OpenClaw](https://openclaw.ai). Funciona com **personas** — perfis de comportamento para cada área da sua vida (trabalho, estudos, projetos pessoais). O Bastion detecta automaticamente qual persona usar com base no contexto da mensagem.

Seus dados ficam 100% com você. Nada vai para servidores externos além das chamadas ao LLM que você escolher.

---

## Instalação

### TL;DR

```bash
bash <(curl -fsSL https://bastion.run/install)
```

Siga o wizard e pronto. Leva 5 minutos. Você vai precisar do Docker e de duas API keys:
- **LLM** — OpenRouter, Anthropic, OpenAI, Gemini ou Groq (OpenRouter tem modelos gratuitos)
- **[Composio](https://composio.dev)** — para integrações externas (Google Calendar, Notion, GitHub, etc.)

### Pré-requisitos

- **Docker** ([instalar](https://docs.docker.com/get-docker/))
- **API key de LLM** (pelo menos uma):
  - [OpenRouter](https://openrouter.ai/keys) — recomendado, tem modelos gratuitos
  - [Groq](https://console.groq.com) — gratuito, rápido
  - [Google Gemini](https://aistudio.google.com/app/apikey) — gratuito
  - [Anthropic](https://console.anthropic.com) — pago, melhor qualidade
  - [OpenAI](https://platform.openai.com/api-keys) — pago, popular
- **Canal de mensagens** (pelo menos um):
  - Bot do Telegram (via [@BotFather](https://t.me/BotFather)) — recomendado
  - Evolution API para WhatsApp
  - Bot do Discord
  - App do Slack

### Instalação Interativa

```bash
bash <(curl -fsSL https://bastion.run/install)
```

O instalador vai perguntar:
1. Qual LLM usar (recomendamos OpenRouter com modelos gratuitos)
2. Qual canal configurar (Telegram é o mais fácil)
3. Suas credenciais (API keys, tokens)

Depois disso, ele:
- Verifica/instala Docker se necessário
- Gera todas as configurações automaticamente
- Inicia o Bastion

### Instalação Automatizada (CI/CD)

```bash
export BASTION_WIZARD=false
export OPENROUTER_API_KEY="sk-or-v1-..."
export OPENROUTER_MODEL="openai/gpt-oss-20b:free"
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_USER_ID="987654321"

bash <(curl -fsSL https://bastion.run/install)
```

Veja todas as variáveis suportadas em [como-instalar.md](como-instalar.md).

### Instalação Manual

Se preferir configurar na mão:

```bash
git clone https://github.com/samurai-py/bastion.git
cd bastion
cp .env.example .env
nano .env  # preencha suas chaves
docker compose up -d
```

---

## Primeiros Passos

1. Envie `/start` para seu bot no canal configurado
2. Complete o onboarding (nome, personas, TOTP)
3. Comece a usar!

O Bastion vai criar suas personas automaticamente com base no que você faz. Depois disso, é só conversar normalmente — ele detecta o contexto e responde com a persona certa.

---

## Arquitetura

```
Telegram / WhatsApp / Discord / Slack
              │
              ▼
        Caddy (HTTPS)
              │
              ▼
    OpenClaw Gateway (Node.js)
              │
              ▼
    Bastion Orchestrator (SOUL.md)
              │
    ┌─────────┴──────────┐
    │     Skills Layer   │
    │  onboarding        │
    │  life-log (RAG)    │
    │  persona-engine    │
    │  crisis-mode       │
    │  mobile-connect    │
    │  skill-writer      │
    │  ...               │
    └────────────────────┘
              │
    ┌─────────┴──────────┐
    │  Persistência      │
    │  SQLite · USER.md  │
    │  personas/*/       │
    └────────────────────┘
              │
              ▼
    LLM Provider (OpenRouter / Anthropic / etc.)
```

---

## Skills Incluídas

| Skill | Descrição |
|-------|-----------|
| `bastion/onboarding` | Setup inicial guiado: nome, personas, TOTP |
| `bastion/life-log` | Memória semântica com busca vetorial (RAG) |
| `bastion/persona-engine` | Roteamento e ativação de personas |
| `bastion/weight-system` | Ajuste dinâmico de pesos por uso |
| `bastion/crisis-mode` | Replanejamento emergencial via algoritmo de sacrifício |
| `bastion/weekly-review` | Análise semanal de uso e sugestões de peso |
| `bastion/proactive-engine` | Engine proativo: inatividade (life-log), staleness de memória (memupalace), CVEs, sugestões via LLM |
| `bastion/memupalace` | Memória semântica de longo prazo (ChromaDB + embeddings ONNX) |
| `bastion/self-improving` | Extração de padrões e atualização de memória |
| `bastion/mobile-connect` | Integração com app mobile (JWT + pareamento) |
| `bastion/skill-writer` | Criação de skills customizadas + descoberta no ClawHub |
| `bastion/guardrails` | Enforcement de segurança em runtime |

---

## App Mobile

O Bastion tem um app mobile self-hosted para acesso rápido pelo celular. Veja [app-mobile.md](app-mobile.md) e [conectando-o-app.md](conectando-o-app.md) para instruções de instalação e pareamento.

---

## Troubleshooting

### Docker não encontrado

O instalador oferece instalação automática. Se recusar:
- **Linux:** `curl -fsSL https://get.docker.com | sh`
- **macOS/Windows:** [Docker Desktop](https://docs.docker.com/get-docker/)

### Bot não responde

```bash
cd ~/bastion
docker compose logs -f
```

Verifique se:
- O container está rodando: `docker ps`
- Seu user_id está correto: `grep authorized_user_ids USER.md`
- Para Telegram, obtenha seu ID com [@userinfobot](https://t.me/userinfobot)

### Reconfigurar do zero

```bash
cd ~/bastion
docker compose down -v
rm -rf config/
bash installer.sh
```

---

## Documentação

- [Como Instalar](como-instalar.md) — referência técnica completa do instalador
- [Configurando a VPS](configurando-a-vps.md) — subir numa VPS do zero
- [Segurança](segurança.md) — guardrails e autenticação
- [Personas](personas.md) — como funcionam
- [Modo Crise](modo-crise.md) — replanejamento automático
- [App Mobile](app-mobile.md) — instalação do app
- [Conectando o App](conectando-o-app.md) — pareamento com o Bastion
- [Iniciando](iniciando.md) — primeiros passos detalhados
- [FAQ](faq.md) — perguntas frequentes

---

## Roadmap

### ✅ Bastion v1
Primeira versão funcional. Orquestrador baseado em LangGraph, life-logs no supabase, personas, skills em Python, canal único via API REST, integração com Telegram.

### ✅ Bastion v2 — OpenClaw Based
Migração para o gateway OpenClaw. Skills com property-based testing (Hypothesis), plugin Sage para segurança em runtime, app mobile com JWT, skill-writer com descoberta no ClawHub, life-log com RAG vetorial.

### 📱 Aplicativo Mobile Self-Hosted
App nativo (iOS/Android) para acesso ao Bastion pelo celular, com notificações push, interface de chat e suporte offline parcial. Distribuído como APK/IPA para instalação direta, sem passar por lojas.

### 💰 Otimização de Custo de Tokens
Compactação inteligente de contexto por persona, cache semântico de respostas frequentes, roteamento automático para modelos mais baratos em tarefas simples, e métricas de custo por persona no weekly-review.

### 🔒 Isolamento de Container (NanoClaw-inspired)
Isolamento nativo de agentes em containers Docker/Linux, inspirado na arquitetura do [NanoClaw](https://github.com/qwibitai/nanoclaw). Cada skill roda em seu próprio sandbox com apenas os diretórios explicitamente montados visíveis — sem acesso ao host. Credenciais nunca entram no container: requisições externas passam por um vault de agente que injeta autenticação no nível do proxy. Suporte a micro VM isolation via Docker Sandboxes para skills de terceiros de alto risco.

### 🛠️ Melhorias no Instalador e Automação para LLM Self-Hosted
Suporte a LLMs locais via Ollama e LM Studio no wizard de instalação, detecção automática de GPU, configuração de modelos de embedding locais para o life-log, e modo offline completo sem dependência de APIs externas.

### 🦀 Bastion v3 — ZeroClaw + memU Memory System
Migração do core para Rust, usando o [ZeroClaw](https://github.com/openagen/zeroclaw) como base e inspiração — runtime single-binary com cold starts quase instantâneos, footprint de poucos megabytes e arquitetura portável entre ARM, x86 e RISC-V. Integração do [memU](https://github.com/NevaMind-AI/memUBot) como sistema de memória de longo prazo: busca semântica, auto-flush de contexto e pools de memória compartilhados entre personas. Foco em performance, custo mínimo de infraestrutura e suporte a edge devices.

### ☁️ Bastion Cloud
Versão gerenciada em nuvem para usuários que não querem manter infraestrutura própria. Isolamento por tenant, backups automáticos, domínio personalizado, e painel de controle web. Mantém a filosofia de privacidade com criptografia end-to-end dos dados do usuário.

---

## Licença

MIT
