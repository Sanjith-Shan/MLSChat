#!/usr/bin/env bash
# Run the official mls-implementations interop harness with MLSChat and OpenMLS
# as clients. Every config, every actor assignment, every common suite, both
# handshake modes. Raw runner output goes to $MLS_WORK/interop-out; a summary
# line per config goes to results/interop.jsonl.
set -uo pipefail
source "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${INTEROP_OUT:-$MLS_WORK/interop-out}"
mkdir -p "$OUT"
CFG="$MLS_WORK/mls-implementations/interop/configs"
"$CARGO_TARGET_DIR/release/mlschat-interop" --port 50052 > "$OUT/mlschat.log" 2>&1 &
P1=$!
"$MLS_WORK/target-openmls/release/interop_client" --host "[::1]" --port 50051 > "$OUT/openmls.log" 2>&1 &
P2=$!
trap 'kill $P1 $P2 2>/dev/null' EXIT
sleep 2
for c in ${CONFIGS:-welcome_join commit application external_join external_proposals deep_random reinit branch}; do
  "$MLS_WORK/bin/test-runner" -client "[::1]:50052" -client "[::1]:50051" -config "$CFG/$c.json" > "$OUT/$c.json" 2> "$OUT/$c.err"
  echo "$c exit=$?"
done
python3 "$ROOT/scripts/interop_summary.py" "$OUT" "${INTEROP_RESULTS:-$ROOT/results/interop.jsonl}"
