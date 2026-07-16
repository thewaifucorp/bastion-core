#!/usr/bin/env bash
#
# check-crate-deps.sh — enforce the M2-08 crate dependency allowlist.
#
# Parses crates/*/Cargo.toml and validates that every bastion-* dependency
# (and dev-dependency) edge is on the exact allowlist derived from the ADR
# documented in docs/ARCHITECTURE.md. Also
# rejects:
#   - any crate depending on the root `bastion` package (product -> substrate
#     is a one-way street; the substrate must never depend "up" into the app);
#   - any crate not present in the allowlist (new crates must be added here
#     deliberately, not silently allowed);
#   - any dependency cycle among crates/*.
#
# Exit 0 on success (prints a summary), exit 1 on any violation (prints every
# violation found, not just the first).

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd; })"
cd "$REPO_ROOT"

CRATES_DIR="crates"
FAIL=0

# --- Allowlist: production [dependencies] -----------------------------------
declare -A ALLOWED_DEPS
ALLOWED_DEPS[bastion-types]=""
# The kernel's
# BackendProfile/RuntimeRegistry hold Arc<dyn AgentRuntime> directly — a
# deliberate new edge, not a core rewrite (the trait object is routing
# policy; bastion-agent-runtime still never depends back on the kernel, so
# no cycle is introduced — verified by the cycle detector below).
ALLOWED_DEPS[bastion-runtime]="bastion-types bastion-agent-runtime"
ALLOWED_DEPS[bastion-memory]="bastion-types bastion-runtime"
ALLOWED_DEPS[bastion-providers]="bastion-types bastion-runtime"
ALLOWED_DEPS[bastion-mcp]="bastion-types bastion-runtime"
ALLOWED_DEPS[bastion-agent-runtime]="bastion-types"
ALLOWED_DEPS[bastion-cognition]="bastion-types bastion-runtime bastion-memory"
ALLOWED_DEPS[bastion-personas]="bastion-types bastion-runtime bastion-memory bastion-cognition"
ALLOWED_DEPS[bastion-mesh]="bastion-types bastion-runtime bastion-memory bastion-cognition bastion-personas"
# Contracts-only
# crate for the extension protocol (ExtensionManifest/PackManifest/
# PermissionSet/trust tiers). Depends only on bastion-types — zero product
# I/O, no other substrate/extension crate needed.
ALLOWED_DEPS[bastion-extension-protocol]="bastion-types"
# The `Wasm`
# mechanism's sandbox. Zero bastion-* dependencies — it knows nothing about
# ExtensionManifest/PermissionSet/Capability, only how to run a wasm32
# module with a fuel budget and no imports. `src/extension/wasm.rs` (app)
# wraps this into an ExtensionInstance/Capability.
ALLOWED_DEPS[bastion-extension-wasm]=""

# --- Allowlist: [dev-dependencies] only (test-only edges, never production) -
declare -A ALLOWED_DEV_DEPS
ALLOWED_DEV_DEPS[bastion-types]=""
ALLOWED_DEV_DEPS[bastion-runtime]=""
ALLOWED_DEV_DEPS[bastion-memory]=""
ALLOWED_DEV_DEPS[bastion-providers]=""
ALLOWED_DEV_DEPS[bastion-mcp]=""
ALLOWED_DEV_DEPS[bastion-agent-runtime]=""
ALLOWED_DEV_DEPS[bastion-cognition]="bastion-mcp"
ALLOWED_DEV_DEPS[bastion-personas]=""
ALLOWED_DEV_DEPS[bastion-mesh]=""
ALLOWED_DEV_DEPS[bastion-extension-protocol]=""
ALLOWED_DEV_DEPS[bastion-extension-wasm]=""

contains_word() {
  local needle="$1"
  shift
  local hay=" $* "
  [[ "$hay" == *" $needle "* ]]
}

declare -A GRAPH # crate -> space-separated production bastion-* deps

if [[ ! -d "$CRATES_DIR" ]]; then
  echo "check-crate-deps: ERROR — no '$CRATES_DIR' directory found from $REPO_ROOT" >&2
  exit 1
fi

for dir in "$CRATES_DIR"/*/; do
  crate_toml="${dir}Cargo.toml"
  [[ -f "$crate_toml" ]] || continue

  crate_name="$(awk -F'"' '/^name[[:space:]]*=/{print $2; exit}' "$crate_toml")"
  if [[ -z "$crate_name" ]]; then
    echo "check-crate-deps: ERROR — cannot read [package].name from $crate_toml" >&2
    FAIL=1
    continue
  fi

  section=""
  deps=""
  dev_deps=""

  while IFS= read -r raw_line; do
    trimmed="$(printf '%s' "$raw_line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

    case "$trimmed" in
    "[dependencies]")
      section="deps"
      continue
      ;;
    "[dev-dependencies]")
      section="dev-deps"
      continue
      ;;
    "["*"]")
      section=""
      continue
      ;;
    esac

    [[ -z "$section" ]] && continue
    if [[ "$trimmed" =~ ^# ]]; then
      continue
    fi
    if [[ -z "$trimmed" ]]; then
      continue
    fi

    if [[ "$trimmed" =~ ^([A-Za-z0-9_-]+)[[:space:]]*= ]]; then
      dep_name="${BASH_REMATCH[1]}"

      if [[ "$dep_name" == "bastion" ]]; then
        echo "check-crate-deps: FORBIDDEN — '$crate_name' ($section) depends on the root package 'bastion'. Substrate crates must never depend on the product app." >&2
        FAIL=1
      elif [[ "$dep_name" == bastion-* ]]; then
        if [[ "$section" == "deps" ]]; then
          deps="$deps $dep_name"
        else
          dev_deps="$dev_deps $dep_name"
        fi
      fi
    fi
  done <"$crate_toml"

  GRAPH[$crate_name]="$deps"

  printf 'check-crate-deps: %-24s deps=[%s] dev-deps=[%s]\n' \
    "$crate_name" "${deps# }" "${dev_deps# }"

  if [[ -z "${ALLOWED_DEPS[$crate_name]+set}" ]]; then
    echo "check-crate-deps: ERROR — crate '$crate_name' is not in the allowlist (scripts/check-crate-deps.sh). Add it deliberately after checking the ADR." >&2
    FAIL=1
  else
    allowed="${ALLOWED_DEPS[$crate_name]}"
    for d in $deps; do
      if ! contains_word "$d" $allowed; then
        echo "check-crate-deps: FORBIDDEN — '$crate_name' depends on '$d', which is not in its allowlist [${allowed:-<none>}]." >&2
        FAIL=1
      fi
    done
  fi

  if [[ -z "${ALLOWED_DEV_DEPS[$crate_name]+set}" ]]; then
    echo "check-crate-deps: ERROR — crate '$crate_name' is not in the dev-dependency allowlist (scripts/check-crate-deps.sh). Add it deliberately after checking the ADR." >&2
    FAIL=1
  else
    allowed_dev="${ALLOWED_DEV_DEPS[$crate_name]}"
    for d in $dev_deps; do
      if ! contains_word "$d" $allowed_dev; then
        echo "check-crate-deps: FORBIDDEN — '$crate_name' dev-depends on '$d', which is not in its dev-dependency allowlist [${allowed_dev:-<none>}]." >&2
        FAIL=1
      fi
    done
  fi
done

# --- Cycle detection over production bastion-* edges ------------------------
declare -A COLOR # unset=unvisited, 1=in-stack, 2=done
has_cycle=0

visit() {
  local node="$1"
  COLOR[$node]=1
  local nb
  for nb in ${GRAPH[$node]-}; do
    if [[ "${COLOR[$nb]-}" == "1" ]]; then
      echo "check-crate-deps: FORBIDDEN — dependency cycle involving '$node' -> '$nb'." >&2
      has_cycle=1
    elif [[ -z "${COLOR[$nb]-}" ]]; then
      visit "$nb"
    fi
  done
  COLOR[$node]=2
}

for c in "${!GRAPH[@]}"; do
  if [[ -z "${COLOR[$c]-}" ]]; then
    visit "$c"
  fi
done

if [[ "$has_cycle" == "1" ]]; then
  FAIL=1
fi

echo "---"
if [[ "$FAIL" == "0" ]]; then
  echo "check-crate-deps: PASS — all crate-to-crate edges within the allowlist, no cycles, no crate depends on the root 'bastion' package."
  exit 0
else
  echo "check-crate-deps: FAIL — see violations above." >&2
  exit 1
fi
