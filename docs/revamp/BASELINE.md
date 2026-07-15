# M0 — Baseline pré-revamp

> Data: 2026-07-13 · Tag: `v1.1.0-pre-revamp` → commit `1528759` (tip da v1.1 shipped, = `main`)
> Máquina de referência: desktop Linux 6.17 do owner (mesma dos números abaixo — comparar sempre no mesmo hardware).

## Gates (todos verdes)

| Gate | Resultado |
|---|---|
| `cargo fmt --check` | ✅ limpo |
| `cargo clippy --all-targets --all-features -- -D warnings` | ✅ exit 0 — único aviso é future-incompat de dep transitiva `proc-macro-error2 v2.0.1` (não é lint do nosso código; tratar na auditoria de deps do M3) |
| `cargo test` | ✅ **525 passed, 0 failed** (453 unit em `src/` + 72 nas suites de integração `tests/`) |

## Métricas

| Métrica | Valor | Nota |
|---|---|---|
| Binário release (`target/release/bastion`) | **24.183.704 bytes (~24 MB)** | ⚠️ acima da constraint ≤20 MB do PROJECT (v1.0 era ~11 MB); crescimento vem da v1.1 (5 canais, voz whisper/Kokoro, MCP server, mesh). Meta do revamp: build mínimo sem features de produto volta pra baixo da linha |
| Código Rust | 32.987 LOC em 82 arquivos `.rs` | só `src/` |
| Superfície pública (grep `pub fn|struct|enum|trait`) | 283 itens | número a REDUZIR no M3-01 |
| Startup (`--help`) | ~0,00 s · RSS ~11,7 MB | proxy fraco de cold start; daemon real precisa de config/canais |
| Memória idle do daemon | N/A | exige daemon vivo com provider — medição vai pro M7 |
| Tempo de turn | N/A | idem (validação viva desceu do M0 pro M7 por decisão #14) |

## O que este baseline garante

Qualquer marco do revamp (M2 extração em diante) compara contra estes números e contra `git diff v1.1.0-pre-revamp`. Regressão de comportamento = teste de caracterização vermelho; regressão de tamanho/startup além da tolerância = anotar e justificar no PR do marco.
