#!/usr/bin/env bash
# =============================================================================
# run.sh  –  Full pipeline: CNA → P4 → BMV2 → Mininet
#
# Prerequisites (install once):
#   sudo apt install p4lang-p4c p4lang-bmv2 mininet python3-scapy
#   pip3 install scapy
#
# Usage:
#   sudo ./run.sh [--no-compile] [--topo-only]
#
#   --no-compile   Skip CNA→P4 and p4c steps; reuse existing .json artefacts
#   --topo-only    Launch Mininet CLI without running automated tests
#   --skip-verifier Skip running the P4 verifier
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CNA_JSON="${SCRIPT_DIR}/example.json"
P4_SRC="${SCRIPT_DIR}/build/ethernet_ipv4_subduction.p4"
BMV2_JSON="${SCRIPT_DIR}/build/ethernet_ipv4_subduction.json"
P4_INCLUDES="${SCRIPT_DIR}/build"

NO_COMPILE=false
TOPO_ONLY=false
SKIP_VERIFIER=false

for arg in "$@"; do
  case $arg in
    --no-compile) NO_COMPILE=true ;;
    --topo-only)  TOPO_ONLY=true  ;;
    --skip-verifier) SKIP_VERIFIER=true ;;
  esac
done

# ── 0. Sanity checks ──────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] This script must be run as root (sudo)." >&2
  exit 1
fi

for cmd in python3 mn simple_switch p4c; do
  command -v "$cmd" &>/dev/null || {
    echo "[ERROR] Required tool not found: $cmd" >&2
    exit 1
  }
done

mkdir -p "${SCRIPT_DIR}/build" "${SCRIPT_DIR}/logs"

# ── 1. CNA → P4 ───────────────────────────────────────────────────────────────
if [[ "$NO_COMPILE" == false ]]; then
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " Step 1/4 : CNA → P4 (cna2p4.py)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  python3 "${SCRIPT_DIR}/cna2p4.py" \
    "${CNA_JSON}" \
    -o "${P4_SRC}"
  echo "[OK] Generated ${P4_SRC}"

  # ── 2. P4 → BMV2 JSON ───────────────────────────────────────────────────────
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " Step 2/4 : P4 → BMV2 JSON (p4c)"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  p4c --target bmv2 \
      --arch v1model \
      --std p4-16 \
      -o "${P4_INCLUDES}" \
      "${P4_SRC}" 2>&1 | tee "${SCRIPT_DIR}/logs/p4c.log"

  # p4c names the output after the source file
  if [[ ! -f "${BMV2_JSON}" ]]; then
    echo "[ERROR] p4c did not produce ${BMV2_JSON}" >&2
    echo "        Check logs/p4c.log for compiler errors." >&2
    exit 1
  fi
  echo "[OK] Generated ${BMV2_JSON}"
else
  echo "[SKIP] Compilation skipped (--no-compile)"
  [[ -f "${BMV2_JSON}" ]] || { echo "[ERROR] ${BMV2_JSON} not found." >&2; exit 1; }
fi

# ── 3. Run verifier ─────────────────────────────────────────────────────────
if [[ "$SKIP_VERIFIER" == false ]]; then
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo " Step 3/4   : P4 Verifier"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if python3 "${SCRIPT_DIR}/verifier.py" "${CNA_JSON}" "${P4_SRC}"; then
    echo "[OK] Verifier passed: P4 program matches CNA spec."
  else
    echo "[ERROR] Verifier failed: P4 program does not match CNA spec." >&2
    exit 1
  fi
else
  echo "[SKIP] Verifier skipped (--skip-verifier)"
fi

# ── 4. Launch Mininet ─────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Step 4/4   : Mininet + BMV2"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

TOPO_FLAG=""
[[ "$TOPO_ONLY" == true ]] && TOPO_FLAG="--topo-only"

python3 "${SCRIPT_DIR}/topo.py" \
  --bmv2-json "${BMV2_JSON}" \
  ${TOPO_FLAG}
