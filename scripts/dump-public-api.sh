#!/usr/bin/env bash
#
# dump-public-api.sh — deterministic public-API surface dump per crate.
#
# Ciclo 2.3 / M3-01 (docs/revamp/M3-CLOSE.md §7): a cheap, dependency-free
# baseline of every `pub` item exposed by each workspace crate (the root
# `bastion` app package plus the 9 `crates/bastion-*` substrate/extension
# crates), written to docs/api-baseline/<crate>.txt.
#
# Method: structured grep/parse (not `cargo public-api`/`cargo semver-checks`
# — neither is vendored or network-fetchable in this environment, and a
# nightly-rustdoc-JSON dependency is out of scope for a mechanical baseline
# check). For each crate we walk every `*.rs` file under its own `src/` and
# emit one line per `pub` item:
#
#   <kind> <path/to/file.rs>:<name>
#
# kind is one of: fn, struct, enum, trait, const, static, type, mod, use.
# `pub(crate)`/private items are excluded by construction (the patterns
# require a literal space after `pub`, which `pub(crate)` never has).
# `pub use` statements (including the two multi-line `pub use x::{...};`
# forms in this codebase) are expanded to one `use` entry per re-exported
# name (respecting `as alias`; a glob `pub use x::*;` emits a single `*`
# entry, since globs can't be enumerated without full type resolution).
#
# Output is sorted lexically so the file is stable across runs regardless
# of filesystem walk order — a real diff in the baseline means a real
# change to the public surface (an item added, removed, renamed, or its
# visibility changed), not incidental churn.
#
# Usage:
#   scripts/dump-public-api.sh            # regenerate docs/api-baseline/*.txt
#   scripts/dump-public-api.sh --check     # regenerate into a temp dir and
#                                          # diff against the committed
#                                          # baseline; exit 1 with a clear
#                                          # message if they differ (CI gate)

set -uo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd; })"
cd "$REPO_ROOT"

BASELINE_DIR="docs/api-baseline"
MODE="write"
if [[ "${1-}" == "--check" ]]; then
  MODE="check"
fi

# crate-name -> path to its src/ root
declare -A CRATE_SRC
CRATE_SRC[bastion]="src"
for dir in crates/*/; do
  name="$(basename "$dir")"
  [[ -d "${dir}src" ]] || continue
  CRATE_SRC["$name"]="${dir}src"
done

extract_one() {
  # $1 = crate src root, relative to repo root
  python3 - "$1" <<'PYEOF'
import re
import sys
import os

root = sys.argv[1]
entries = []

#
# 6c (docs/revamp/C3-runtime-followups-design.md): `pub fn` alone missed
# every `pub async fn` in the kernel (`run_turn`, `delegate_task`, etc.) —
# the whole async public surface was invisible to this baseline. The
# modifier group below accepts zero or more of `async`/`unsafe`/`const`
# between `pub` and the kind keyword (defensive: `unsafe` never appears
# under this crate's `#![forbid(unsafe_code)]`, but a workspace crate
# could still add one without violating that lint if it were ever
# scoped narrower). `pub const fn foo()` still classifies as `fn` (the
# kind alternation prefers `fn` when both `const` and `fn` are present)
# while a real `pub const NAME: T = ...;` still classifies as `const`
# (Python `re` backtracks: the modifier group re-tries consuming zero
# repetitions when `fn|struct|...` fails to follow a consumed `const`).
decl_pat = re.compile(
    r'^\s*pub\s+(?:(?:async|unsafe|const)\s+)*(fn|struct|enum|trait|const|static|type|mod)\s+([A-Za-z_][A-Za-z0-9_]*)'
)
use_start_pat = re.compile(r'^\s*pub use\b')


def relpath(path):
    return os.path.relpath(path, root)


def split_top_level(s):
    """Split a `{...}` use-tree body on top-level commas (ignores commas
    nested inside a further `{...}` group, e.g. `foo::{a, b}`)."""
    parts = []
    depth = 0
    cur = ""
    for ch in s:
        if ch == "{":
            depth += 1
            cur += ch
        elif ch == "}":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def names_from_use_tree(tree, relf):
    tree = tree.strip().rstrip(",").strip()
    if not tree:
        return
    if tree == "*":
        entries.append(("use", relf, "*"))
        return
    if tree.startswith("{") and tree.endswith("}"):
        inner = tree[1:-1]
        for part in split_top_level(inner):
            names_from_use_tree(part, relf)
        return
    # "path::to::{...}" — recurse into the trailing group, dropping the
    # leading path (only the final segment(s) matter for the public name).
    if "::{" in tree:
        head, _, rest = tree.partition("::{")
        names_from_use_tree("{" + rest, relf)
        return
    # "path::Name as Alias" or "path::Name" or bare "Name"
    if " as " in tree:
        _, _, alias = tree.partition(" as ")
        entries.append(("use", relf, alias.strip()))
        return
    name = tree.rsplit("::", 1)[-1]
    entries.append(("use", relf, name))


for dirpath, _, files in os.walk(root):
    for fname in sorted(files):
        if not fname.endswith(".rs"):
            continue
        path = os.path.join(dirpath, fname)
        relf = relpath(path)
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()

        i = 0
        while i < len(lines):
            line = lines[i]
            m = decl_pat.match(line)
            if m:
                entries.append((m.group(1), relf, m.group(2)))
                i += 1
                continue
            if use_start_pat.match(line):
                # Join lines until we hit a `;` (handles the multi-line
                # `pub use x::{\n  a,\n  b,\n};` form).
                buf = line
                j = i
                while ";" not in buf and j + 1 < len(lines):
                    j += 1
                    buf += lines[j]
                stmt = buf.strip()
                stmt = stmt[len("pub use"):].strip()
                stmt = stmt.rstrip(";").strip()
                # collapse whitespace/newlines inside the tree
                stmt = re.sub(r'\s+', ' ', stmt)
                names_from_use_tree(stmt, relf)
                i = j + 1
                continue
            i += 1

for kind, relf, name in sorted(set(entries), key=lambda t: (t[1], t[2], t[0])):
    print(f"{kind} {relf}:{name}")
PYEOF
}

mkdir -p "$BASELINE_DIR"

if [[ "$MODE" == "check" ]]; then
  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT
  FAIL=0
  for crate in "${!CRATE_SRC[@]}"; do
    extract_one "${CRATE_SRC[$crate]}" >"$TMP_DIR/$crate.txt"
    baseline="$BASELINE_DIR/$crate.txt"
    if [[ ! -f "$baseline" ]]; then
      echo "dump-public-api: ERROR — no baseline file for crate '$crate' ($baseline). Run 'scripts/dump-public-api.sh' and commit it." >&2
      FAIL=1
      continue
    fi
    if ! diff -u "$baseline" "$TMP_DIR/$crate.txt" >"$TMP_DIR/$crate.diff"; then
      echo "dump-public-api: FAIL — public API of crate '$crate' changed but $baseline was not updated." >&2
      echo "  Run 'scripts/dump-public-api.sh' locally, review the diff, and commit the regenerated baseline." >&2
      echo "  (If this is an intentional breaking change, it must also be called out per docs/VERSIONING.md.)" >&2
      cat "$TMP_DIR/$crate.diff" >&2
      FAIL=1
    fi
  done
  if [[ "$FAIL" == "1" ]]; then
    exit 1
  fi
  echo "dump-public-api: PASS — public API baselines match the working tree for all ${#CRATE_SRC[@]} crates."
  exit 0
fi

for crate in "${!CRATE_SRC[@]}"; do
  extract_one "${CRATE_SRC[$crate]}" >"$BASELINE_DIR/$crate.txt"
  echo "dump-public-api: wrote $BASELINE_DIR/$crate.txt ($(wc -l <"$BASELINE_DIR/$crate.txt" | tr -d ' ') items)"
done
