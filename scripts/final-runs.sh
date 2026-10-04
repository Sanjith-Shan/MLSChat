#!/usr/bin/env bash
# Final verification runs on the finished code, meant to run detached inside the
# VM (setsid nohup) so a WSL front-end outage cannot kill them:
#   1. the interop harness, one config at a time
#   2. the ratchet_tree fuzz target again, 10 minutes, after the bug 12 fix
#   3. conformance and the OpenMLS differential re-recorded on the final code
# Progress goes to $MLS_WORK/logs/final.log; $MLS_WORK/logs/final.done marks the end.
set -uo pipefail
source "$(dirname "$0")/env.sh"
cd "$(dirname "$0")/.."
LOG="$MLS_WORK/logs/final.log"
rm -f "$MLS_WORK/logs/final.done"
echo "start $(date -Is) load $(cut -d' ' -f1-3 /proc/loadavg)" > "$LOG"
cargo build -q --release --workspace --exclude web >> "$LOG" 2>&1
rm -f results/interop.jsonl
for c in welcome_join commit application external_join external_proposals reinit branch deep_random; do
  rm -rf "$MLS_WORK/interop-out"
  CONFIGS="$c" timeout 1800 bash scripts/interop.sh >> "$LOG" 2>&1
  echo "after $c: $(date -Is) mem $(free -m | awk '/Mem:/ {print $3}') MB load $(cut -d' ' -f1 /proc/loadavg)" >> "$LOG"
  sleep 5
done
mkdir -p "$MLS_WORK/artifacts/ratchet_tree"
(cd fuzz && cargo +nightly fuzz run ratchet_tree "$MLS_WORK/corpus/ratchet_tree" -- -max_total_time=600 \
   -artifact_prefix="$MLS_WORK/artifacts/ratchet_tree/" -print_final_stats=1) > "$MLS_WORK/logs/fuzz_tree_final.log" 2>&1
echo "ratchet_tree fuzz: $(grep -E 'stat::number_of_executed_units|stat::new_units_added' "$MLS_WORK/logs/fuzz_tree_final.log" | tr '\n' ' ') artifacts: $(ls "$MLS_WORK/artifacts/ratchet_tree" | wc -l)" >> "$LOG"
cargo run -q --release -p conformance --bin mls-conformance -- --record 2>&1 | tail -1 >> "$LOG"
"$CARGO_TARGET_DIR/release/differential" 100 40 --record 2>&1 | tail -4 >> "$LOG"
echo "disk: $(du -sh "$MLS_WORK" | cut -f1) in $MLS_WORK" >> "$LOG"
echo "end $(date -Is)" >> "$LOG"
touch "$MLS_WORK/logs/final.done"
