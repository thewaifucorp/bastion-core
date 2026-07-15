#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# migrate.sh — move a Bastion install's personas + memory between machines (e.g. → VPS)
#
# What it moves:
#   • personas/                  — persona SOUL.md (+ per-persona memory.md) files
#   • sessions.db                — the core memory: beliefs, sessions, goals
#   • db/life-log.db  (optional) — the life-log skill's separate SQLite, if present
#
# What it does NOT move (recreate on the target):
#   • .env secrets. Copy them by hand. Keep APP_JWT_SECRET / MESH_IDENTITY_KEY the
#     SAME on the target if you want the mobile app / mesh identity to keep working
#     (regenerating them forces a re-pair).
#   • bastion.toml — it travels with the git repo.
#
# Usage:
#   scripts/migrate.sh export [out.tar.gz]   # on the OLD machine → makes a tarball
#   scripts/migrate.sh import <in.tar.gz>    # on the NEW machine → restores in place
#   scripts/migrate.sh help
#
# IMPORTANT: stop the daemon before export AND before import so SQLite is quiescent.
#   local:  Ctrl-C the `cargo run -- daemon` process
#   docker: docker compose stop core
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Docker named volume holding sessions.db (override if your compose project name differs).
DOCKER_VOLUME="${BASTION_DATA_VOLUME:-bastion_bastion-data}"

log()  { printf '\033[36m▸ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m⚠ %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

# Resolve where sessions.db lives. Precedence: env override → bastion.toml → local default.
resolve_db_path() {
  if [ -n "${BASTION__SESSION__DB_PATH:-}" ]; then
    echo "$BASTION__SESSION__DB_PATH"; return
  fi
  local p=""
  if [ -f bastion.toml ]; then
    p="$(grep -E '^\s*db_path\s*=' bastion.toml | head -1 | sed -E 's/.*=\s*"(.*)"\s*/\1/')"
  fi
  # A /bastion-data/... path means Docker; not readable from the host filesystem.
  if [ -n "$p" ] && [ -f "$p" ]; then echo "$p"; return; fi
  if [ -f ./.bastion/sessions.db ]; then echo ./.bastion/sessions.db; return; fi
  echo "${p:-/bastion-data/sessions.db}"
}

# Make a consistent copy of a live SQLite db (folds in the WAL). Falls back to a
# raw 3-file copy if the sqlite3 CLI is unavailable.
snapshot_sqlite() {
  local src="$1" dst="$2"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$src" ".backup '$dst'"
  else
    warn "sqlite3 CLI not found — doing a raw file copy (make sure the daemon is STOPPED)."
    cp "$src" "$dst"
    [ -f "${src}-wal" ] && cp "${src}-wal" "${dst}-wal" || true
    [ -f "${src}-shm" ] && cp "${src}-shm" "${dst}-shm" || true
  fi
}

cmd_export() {
  local out="${1:-bastion-migrate-$(date +%Y%m%d-%H%M%S).tar.gz}"
  local stage; stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' EXIT

  log "Staging migration bundle in $stage"

  # 1) personas
  if [ -d personas ]; then
    cp -a personas "$stage/personas"
    log "personas/ ($(find personas -name SOUL.md | wc -l | tr -d ' ') personas)"
  else
    warn "no personas/ directory found — skipping"
  fi

  # 2) core memory (sessions.db)
  local db; db="$(resolve_db_path)"
  if [ -f "$db" ]; then
    snapshot_sqlite "$db" "$stage/sessions.db"
    log "sessions.db snapshot from $db"
  elif [[ "$db" == /bastion-data/* ]] && command -v docker >/dev/null 2>&1; then
    log "sessions.db not on host; pulling from Docker volume '$DOCKER_VOLUME'"
    docker run --rm -v "${DOCKER_VOLUME}:/d:ro" -v "$stage:/out" alpine \
      sh -c 'cp /d/sessions.db /out/sessions.db' \
      || die "could not read sessions.db from volume '$DOCKER_VOLUME' (set BASTION_DATA_VOLUME=)"
    log "sessions.db copied from volume (stop 'core' first for a clean copy)"
  else
    warn "sessions.db not found at '$db' — exporting personas only"
  fi

  # 3) life-log skill db (optional)
  if [ -f db/life-log.db ]; then
    mkdir -p "$stage/db"; snapshot_sqlite db/life-log.db "$stage/db/life-log.db"
    log "db/life-log.db snapshot"
  fi

  tar -czf "$out" -C "$stage" .
  trap - EXIT; rm -rf "$stage"
  log "Wrote $out"
  cat <<EOF

Next, on the VPS (after a fresh install + filled .env):
  1) docker compose stop core   # or stop the local daemon
  2) scp this file over, then:  scripts/migrate.sh import $(basename "$out")
  3) docker compose up -d core
EOF
}

cmd_import() {
  local in="${1:?usage: migrate.sh import <in.tar.gz>}"
  [ -f "$in" ] || die "tarball not found: $in"
  local stage; stage="$(mktemp -d)"
  trap 'rm -rf "$stage"' EXIT
  tar -xzf "$in" -C "$stage"

  # personas → repo
  if [ -d "$stage/personas" ]; then
    cp -a "$stage/personas/." personas/
    log "restored personas/"
  fi

  # sessions.db → resolved path or Docker volume
  if [ -f "$stage/sessions.db" ]; then
    local db; db="$(resolve_db_path)"
    if [[ "$db" == /bastion-data/* ]] && command -v docker >/dev/null 2>&1 && ! [ -f "$db" ]; then
      log "restoring sessions.db into Docker volume '$DOCKER_VOLUME'"
      docker run --rm -v "${DOCKER_VOLUME}:/d" -v "$stage:/in:ro" alpine \
        sh -c 'cp /in/sessions.db /d/sessions.db' \
        || die "could not write sessions.db to volume '$DOCKER_VOLUME'"
    else
      mkdir -p "$(dirname "$db")"
      cp "$stage/sessions.db" "$db"
      log "restored sessions.db → $db"
    fi
  fi

  # life-log db
  if [ -f "$stage/db/life-log.db" ]; then
    mkdir -p db; cp "$stage/db/life-log.db" db/life-log.db
    log "restored db/life-log.db"
  fi

  trap - EXIT; rm -rf "$stage"
  log "Import done. Start the daemon: docker compose up -d core"
}

case "${1:-help}" in
  export) shift; cmd_export "${1:-}";;
  import) shift; cmd_import "${1:-}";;
  *) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//';;
esac
