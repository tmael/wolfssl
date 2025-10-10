#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# === Config (override via env or flags) ===
ROOT_DIR="${ROOT_DIR:-$HOME/wolfssl}"    # Source/original tree
DEST_DIR="${DEST_DIR:-}"                        # If empty, we'll decide (see AUTO_SUFFIX)
AUTO_SUFFIX="${AUTO_SUFFIX:-0}"                 # 1 = choose next free suffix (.A .B .C ...)
DRY_RUN="${DRY_RUN:-0}"                         # 1 = preview only
BACKUP_ON_PUSH="${BACKUP_ON_PUSH:-1}"           # 1 = keep timestamped backups when pushing
RSYNC_EXTRA="${RSYNC_EXTRA:-}"                  # Extra rsync flags, e.g. "--progress" or "--checksum"

# Subcommand: init | push | diff (default: init)
CMD="${1:-init}"

# --- Whitelist: paths RELATIVE to ROOT_DIR ---
keep_files=(
  "user_settings.h"
  "wolfcrypt/src/misc.c"
  "wolfcrypt/src/port/arm/armv8-aes.c"
  "wolfcrypt/src/port/arm/armv8-32-aes-asm_c.c"
  "wolfssl/wolfcrypt/aes.h"
  "wolfssl/wolfcrypt/error-crypt.h"
  "wolfssl/wolfcrypt/libwolfssl_sources.h"
  "wolfssl/wolfcrypt/libwolfssl_sources_asm.h"
  "wolfssl/wolfcrypt/memory.h"
  "wolfssl/wolfcrypt/misc.h"
  "wolfssl/wolfcrypt/oid_sum.h"
  "wolfssl/wolfcrypt/settings.h"
  "wolfssl/wolfcrypt/types.h"
  "wolfssl/wolfcrypt/visibility.h"
  "wolfssl/wolfcrypt/wc_port.h"
  "wolf_string.h"
)

# Plus these root-level makefiles
root_makefiles=(
  "aesgcm-test.c"
  "Makefile.gcc-lib"
  "Makefile.ghs-lib"
  "Makefile.gcc-app"
  "Makefile.ghs-app"
  "libwolfcrypt.ghs.gpj"
)

# === Helpers ===
die() { echo "ERROR: $*" >&2; exit 1; }
files_list() { printf "%s\n" "${keep_files[@]}" "${root_makefiles[@]}"; }

# Decide DEST_DIR, honoring AUTO_SUFFIX (A,B,C…)
decide_dest_dir() {
  if [[ -n "$DEST_DIR" ]]; then
    return
  fi
  local base="$ROOT_DIR"
  if (( AUTO_SUFFIX )); then
    local letter
    for letter in {A..Z}; do
      local cand="${base}.${letter}"
      if [[ ! -e "$cand" ]]; then DEST_DIR="$cand"; break; fi
    done
    [[ -n "$DEST_DIR" ]] || die "No free suffix from .A to .Z under $base"
  else
    DEST_DIR="${base}.A"
  fi
}

require_dirs() {
  [[ -d "$ROOT_DIR" ]] || die "ROOT_DIR does not exist: $ROOT_DIR"
  decide_dest_dir
  mkdir -p "$DEST_DIR"
}

# Parent dirs for each rel path under base
precreate_dirs() {
  local base="$1"
  files_list | while IFS= read -r rel; do
    [[ -z "$rel" ]] && continue
    mkdir -p "$base/$(dirname "$rel")"
  done
}

# Build rsync flags as an ARRAY (IFS-safe)
build_rsync_flags() {
  RSYNC_FLAGS=(-a -t)
  (( DRY_RUN )) && RSYNC_FLAGS+=(--dry-run -v)
  if [[ -n "$RSYNC_EXTRA" ]]; then
    # shellcheck disable=SC2206
    local extra=($RSYNC_EXTRA)
    RSYNC_FLAGS+=("${extra[@]}")
  fi
}

# Only those that exist in ROOT_DIR
existing_in_root() {
  files_list | while IFS= read -r rel; do
    [[ -n "$rel" && -e "$ROOT_DIR/$rel" ]] && printf '%s\n' "$rel"
  done
}

# Only those that exist in DEST_DIR
existing_in_dest() {
  files_list | while IFS= read -r rel; do
    [[ -n "$rel" && -e "$DEST_DIR/$rel" ]] && printf '%s\n' "$rel"
  done
}

count_lines() {
  local n=0
  while IFS= read -r _; do ((n++)); done
  echo "$n"
}

do_init() {
  echo "== INIT: Copy ROOT → DEST =="
  require_dirs
  local list; list="$(existing_in_root)"
  local n; n=$(count_lines <<<"$list")
  [[ "$n" -gt 0 ]] || die "None of the whitelisted files exist under $ROOT_DIR"
  echo "Destination: $DEST_DIR  (copying $n files)"
  precreate_dirs "$DEST_DIR"
  build_rsync_flags
  printf "%s\n" "$list" | rsync "${RSYNC_FLAGS[@]}" --files-from=- "$ROOT_DIR"/ "$DEST_DIR"/
  echo "Done. Copied $n files to: $DEST_DIR"
}

do_diff() {
  echo "== DIFF: What would PUSH (DEST → ROOT) change? =="
  require_dirs
  local list; list="$(existing_in_dest)"
  local n; n=$(count_lines <<<"$list")
  [[ "$n" -gt 0 ]] || die "No whitelisted files exist in $DEST_DIR; nothing to diff."
  printf "%s\n" "$list" | rsync -ai --dry-run --files-from=- "$DEST_DIR"/ "$ROOT_DIR"/
  echo "↑ Preview of changes that would be pushed."
}

do_push() {
  echo "== PUSH: Copy DEST → ROOT (only whitelisted) =="
  require_dirs
  local list; list="$(existing_in_dest)"
  local n; n=$(count_lines <<<"$list")
  [[ "$n" -gt 0 ]] || die "No whitelisted files exist in $DEST_DIR; nothing to push."

  local backup_args=()
  if (( BACKUP_ON_PUSH )); then
    local ts backup_dir
    ts="$(date +'%Y%m%d-%H%M%S')"
    backup_dir="${ROOT_DIR}/.push_backups/${ts}"
    mkdir -p "$backup_dir"
    backup_args+=(--backup --backup-dir="$backup_dir")
    echo "Backups of overwritten files → $backup_dir"
  fi

  precreate_dirs "$ROOT_DIR"
  build_rsync_flags
  printf "%s\n" "$list" | rsync "${RSYNC_FLAGS[@]}" --update "${backup_args[@]}" --files-from=- "$DEST_DIR"/ "$ROOT_DIR"/
  echo "Done. Pushed changes from $DEST_DIR back into $ROOT_DIR"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [init|push|diff]

Commands:
  init   Copy whitelisted files ROOT -> DEST (create/refresh trimmed tree)
  push   Copy whitelisted files DEST -> ROOT (only newer; backups optional)
  diff   Show what would change on push (no writes)

Config (env vars or prefix args):
  ROOT_DIR=/path/to/wolfssl               (default: /home/tesfa/wolfssl)
  DEST_DIR=/path/to/wolfssl.A             (default: auto-picked if empty)
  AUTO_SUFFIX=1                           (pick next free .A .B .C ... when DEST_DIR is empty)
  DRY_RUN=1                               (preview only)
  BACKUP_ON_PUSH=0|1                      (default 1)
  RSYNC_EXTRA="--progress"                (extra rsync flags; e.g. "--checksum" for content-based)

Examples:
  # Copy into /home/tesfa/wolfssl.A (default when AUTO_SUFFIX=0)
  ./trimmed_aes_sources.sh init

  # Auto-pick next suffix (wolfssl.A, then .B, .C...)
  AUTO_SUFFIX=1 ./trimmed_aes_sources.sh init

  # Explicitly target wolfssl.B
  DEST_DIR=/home/tesfa/wolfssl.B ./trimmed_aes_sources.sh init

  # Preview and push back to ROOT
  ./trimmed_aes_sources.sh diff
  ./trimmed_aes_sources.sh push
EOF
}

main() {
  case "${1:-init}" in
    init) do_init ;;
    push) do_push ;;
    diff) do_diff ;;
    -h|--help) usage ;;
    *) echo "Unknown command: $1"; usage; exit 2 ;;
  esac
}

main "$@"
