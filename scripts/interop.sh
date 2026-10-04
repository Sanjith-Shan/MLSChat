#!/usr/bin/env bash
# Run the official mls-implementations interop harness with MLSChat and OpenMLS
# as clients: every config, every actor assignment, every suite each client
# supports, both handshake modes. Raw runner output goes to $INTEROP_OUT; a
# summary line per config goes to results/interop.jsonl.
#
# The box is shared, so every process runs under a hard address-space cap and
# one config runs at a time; a runaway process is killed instead of stalling
# the VM.
set -uo pipefail
source "$(dirname "$0")/env.sh"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${INTEROP_OUT:-$MLS_WORK/interop-out}"
mkdir -p "$OUT"
CFG="$MLS_WORK/mls-implementations/interop/configs"
(ulimit -v 2000000; exec "$CARGO_TARGET_DIR/release/mlschat-interop" --host 127.0.0.1 --port 50052) > "$OUT/mlschat.log" 2>&1 &
P1=$!
(ulimit -v 2000000; exec "$MLS_WORK/target-openmls/release/interop_client" --host 127.0.0.1 --port 50051) > "$OUT/openmls.log" 2>&1 &
P2=$!
trap 'kill $P1 $P2 2>/dev/null' EXIT
sleep 2
for c in ${CONFIGS:-welcome_join commit application external_join external_proposals reinit branch deep_random}; do
  # deep_random over every actor assignment held 4 GB of transcripts in the Go
  # runner and was OOM-killed in the 6 GB VM, so it runs one random assignment
  # per script instead.
  FLAGS=""
  if [ "$c" = deep_random ]; then FLAGS="-random"; fi
  (ulimit -v 3000000; exec "$MLS_WORK/bin/test-runner" $FLAGS -client 127.0.0.1:50052 -client 127.0.0.1:50051 -config "$CFG/$c.json") > "$OUT/$c.json" 2> "$OUT/$c.err"
  echo "$c exit=$? mem_used_mb=$(free -m | awk '/Mem:/ {print $3}') load=$(cut -d' ' -f1 /proc/loadavg)"
done
python3 "$ROOT/scripts/interop_summary.py" "$OUT" "${INTEROP_RESULTS:-$ROOT/results/interop.jsonl}"
