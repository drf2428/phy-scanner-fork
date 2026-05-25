#!/usr/bin/env bash
#
# sync-upstream.sh — fetch pinned upstream Greenbone CE sources into ./build/upstream/
#
# Reads pinned versions from UPSTREAM.md. Idempotent: re-running re-fetches
# only if the local tag differs from the pinned tag.
#
# Usage:
#   ./scripts/sync-upstream.sh            # fetch all components
#   ./scripts/sync-upstream.sh gvmd       # fetch only one component
#   DRY_RUN=1 ./scripts/sync-upstream.sh  # show what would be fetched
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build/upstream"
DRY_RUN="${DRY_RUN:-0}"

# Components hardcoded for now — F2 will parse from UPSTREAM.md table.
declare -a COMPONENTS=(
  "gvm-libs|https://github.com/greenbone/gvm-libs|v22.10.0"
  "openvas-scanner|https://github.com/greenbone/openvas-scanner|v22.10.0"
  "gvmd|https://github.com/greenbone/gvmd|v22.10.0"
  "gsa|https://github.com/greenbone/gsa|v22.10.0"
  "gsad|https://github.com/greenbone/gsad|v22.10.0"
)

want_component="${1:-}"

mkdir -p "${BUILD_DIR}"

for entry in "${COMPONENTS[@]}"; do
  IFS='|' read -r name url tag <<< "${entry}"
  if [[ -n "${want_component}" && "${name}" != "${want_component}" ]]; then
    continue
  fi
  target="${BUILD_DIR}/${name}"
  if [[ "${DRY_RUN}" == "1" ]]; then
    echo "[DRY_RUN] would fetch ${name} (${tag}) → ${target}"
    continue
  fi
  if [[ -d "${target}/.git" ]]; then
    current_tag="$(git -C "${target}" describe --tags --exact-match 2>/dev/null || echo unknown)"
    if [[ "${current_tag}" == "${tag}" ]]; then
      echo "[skip] ${name}: already at ${tag}"
      continue
    fi
    echo "[bump] ${name}: ${current_tag} → ${tag}"
    rm -rf "${target}"
  fi
  echo "[fetch] ${name} ${tag} from ${url}"
  git clone --depth 1 --branch "${tag}" "${url}" "${target}"
done

echo "sync-upstream.sh: OK"
