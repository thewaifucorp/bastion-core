# 🏰 Bastion

> **ARQUIVADO:** esta página descreve a v2 OpenClaw removida. A fonte ativa é [o README raiz](../../README.md), reconciliado com o runtime Rust v1.1. Não use as features/roadmap abaixo para planejar trabalho novo.

Your personal AI assistant, running 100% on your own machine or server. Bastion learns how you work, adapts to different areas of your life, and helps you stay focused on what matters — without sharing your data with anyone.

## What is it?

A self-hosted AI agent built on [OpenClaw](https://openclaw.ai). It works with **personas** — behavioral profiles for each area of your life (work, studies, personal projects). Bastion automatically detects which persona to use based on the message context.

Your data stays 100% with you. Nothing goes to external servers except the LLM API calls you choose to make.

---

## Installation

### TL;DR

```bash
bash <(curl -fsSL https://bastion.run/install)
```

Follow the wizard and you're done. Takes 5 minutes. You'll need Docker and two API keys:
- **LLM** — OpenRouter, Anthropic, OpenAI, Gemini, or Groq (OpenRouter has free models)
- **[Composio](https://composio.dev)** — for external integrations (Google Calendar, Notion, GitHub, etc.)

### Prerequisites

- **Docker** ([install](https://docs.docker.com/get-docker/))
- **LLM API key** (at least one):
  - [OpenRouter](https://openrouter.ai/keys) — recommended, has free models
  - [Groq](https://console.groq.com) — free, fast
  - [Google Gemini](https://aistudio.google.com/app/apikey) — free
  - [Anthropic](https://console.anthropic.com) — paid, best quality
  - [OpenAI](https://platform.openai.com/api-keys) — paid, popular
- **Messaging channel** (at least one):
  - Telegram bot (via [@BotFather](https://t.me/BotFather)) — recommended
  - Evolution API for WhatsApp
  - Discord bot
  - Slack app

### Interactive Installation

```bash
bash <(curl -fsSL https://bastion.run/install)
```

The installer will ask:
1. Which LLM to use (we recommend OpenRouter with free models)
2. Which channel to configure (Telegram is the easiest)
3. Your credentials (API keys, tokens)

After that, it will:
- Check/install Docker if needed
- Generate all configurations automatically
- Start Bastion

### Automated Installation (CI/CD)

```bash
export BASTION_WIZARD=false
export OPENROUTER_API_KEY="sk-or-v1-..."
export OPENROUTER_MODEL="openai/gpt-oss-20b:free"
export TELEGRAM_BOT_TOKEN="123456:ABC..."
export TELEGRAM_USER_ID="987654321"

bash <(curl -fsSL https://bastion.run/install)
```

### Manual Installation

If you prefer to configure manually:

```bash
git clone https://github.com/samurai-py/bastion.git
cd bastion
cp .env.example .env
nano .env  # fill in your keys
docker compose up -d
```

---

## Getting Started

1. Send `/start` to your bot on the configured channel
2. Complete onboarding (name, personas, TOTP)
3. Start using it!

Bastion will create your personas automatically based on what you do. After that, just chat normally — it detects the context and responds with the right persona.

---

## Architecture

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
    │  Persistence       │
    │  SQLite · USER.md  │
    │  personas/*/       │
    └────────────────────┘
              │
              ▼
    LLM Provider (OpenRouter / Anthropic / etc.)
```

---

## Bundled Skills

| Skill | Description |
|-------|-------------|
| `bastion/onboarding` | Guided initial setup: name, personas, TOTP |
| `bastion/life-log` | Semantic memory with vector search (RAG) |
| `bastion/persona-engine` | Persona routing and activation |
| `bastion/weight-system` | Dynamic weight adjustment based on usage |
| `bastion/crisis-mode` | Emergency replanning via sacrifice algorithm |
| `bastion/weekly-review` | Weekly usage analysis and weight suggestions |
| `bastion/proactive-engine` | Proactive engine: inactivity (life-log), memory staleness (memupalace), CVEs, LLM suggestions |
| `bastion/memupalace` | Semantic long-term memory (ChromaDB + ONNX embeddings) |
| `bastion/self-improving` | Pattern extraction and memory updates |
| `bastion/mobile-connect` | Mobile app integration (JWT + device pairing) |
| `bastion/skill-writer` | Custom skill creation + ClawHub discovery |
| `bastion/guardrails` | Runtime security enforcement |

---

## Mobile App

Bastion has a self-hosted mobile app for quick access from your phone, with push notifications and a chat interface. See the [mobile app docs](app-mobile.md) for installation and pairing instructions.

---

## Troubleshooting

### Docker not found

The installer offers automatic installation. If you decline:
- **Linux:** `curl -fsSL https://get.docker.com | sh`
- **macOS/Windows:** [Docker Desktop](https://docs.docker.com/get-docker/)

### Bot not responding

```bash
cd ~/bastion
docker compose logs -f
```

Check that:
- The container is running: `docker ps`
- Your user_id is correct: `grep authorized_user_ids USER.md`
- For Telegram, get your ID with [@userinfobot](https://t.me/userinfobot)

### Reset from scratch

```bash
cd ~/bastion
docker compose down -v
rm -rf config/
bash installer.sh
```

---

## Documentation

- [How to Install](how-to-install.md) — full installer reference
- [VPS Setup](vps-setup.md) — setting up on a VPS from scratch
- [Security](security.md) — guardrails and authentication
- [Personas](personas.md) — how they work
- [Crisis Mode](crisis-mode.md) — automatic replanning
- [Mobile App](mobile-app.md) — app installation
- [Connecting the App](connecting-the-app.md) — pairing with Bastion
- [Getting Started](getting-started.md) — detailed first steps
- [FAQ](faq.md) — frequently asked questions

---

## Roadmap

### ✅ Bastion v1
First functional version. Markdown-based orchestrator, personas, Python skills, TOTP authentication, Telegram integration.

### ✅ Bastion v2 — OpenClaw Based
Migration to the OpenClaw gateway. Skills with property-based testing (Hypothesis), Sage plugin for runtime security, mobile app with JWT, skill-writer with ClawHub discovery, life-log with vector RAG.

### 📱 Self-Hosted Mobile App
Native app (iOS/Android) for mobile access to Bastion, with push notifications, chat interface, and partial offline support. Distributed as APK/IPA for direct installation, bypassing app stores.

### 💰 Token Cost Optimization
Intelligent context compaction per persona, semantic caching of frequent responses, automatic routing to cheaper models for simple tasks, and per-persona cost metrics in the weekly review.

### 🔒 Container Isolation (NanoClaw-inspired)
Native agent isolation in Docker/Linux containers, inspired by [NanoClaw](https://github.com/qwibitai/nanoclaw)'s architecture. Each skill runs in its own sandbox with only explicitly mounted directories visible — no host access. Credentials never enter the container: outbound requests route through an agent vault that injects authentication at the proxy level. Micro VM isolation via Docker Sandboxes for high-risk third-party skills.

### 🛠️ Installer Improvements and Self-Hosted LLM Automation
Support for local LLMs via Ollama and LM Studio in the installation wizard, automatic GPU detection, local embedding model configuration for the life-log, and full offline mode without external API dependencies.

### 🦀 Bastion v3 — ZeroClaw + memU Memory System
Core migration to Rust, using [ZeroClaw](https://github.com/openagen/zeroclaw) as the base and inspiration — single-binary runtime with near-instant cold starts, a few-megabyte footprint, and portable architecture across ARM, x86, and RISC-V. Integration of [memU](https://github.com/NevaMind-AI/memUBot) as the long-term memory system: semantic search, context auto-flush, and shared memory pools across personas. Focus on performance, minimal infrastructure cost, and edge device support.

### ☁️ Bastion Cloud
Managed cloud version for users who don't want to maintain their own infrastructure. Per-tenant isolation, automatic backups, custom domain, and a web control panel. Maintains the privacy philosophy with end-to-end encryption of user data.

---

## License

MIT
