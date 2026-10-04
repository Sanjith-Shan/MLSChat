#!/usr/bin/env bash
# Run each cargo-fuzz target for N seconds (default 600). Corpora and crash
# artifacts live under $MLS_WORK, not in the repo. Seeds come from the vectors.
set -uo pipefail
source "$(dirname "$0")/env.sh"
cd "$(dirname "$0")/../fuzz"
SECS="${1:-600}"
V="$MLS_WORK/mls-implementations/test-vectors"
mkdir -p "$MLS_WORK/corpus" "$MLS_WORK/artifacts"
python3 - "$V" "$MLS_WORK/corpus" <<'PY'
import json, os, sys, hashlib
v, out = sys.argv[1], sys.argv[2]
def put(target, hexs):
    d = os.path.join(out, target); os.makedirs(d, exist_ok=True)
    for h in hexs:
        if not h: continue
        b = bytes.fromhex(h)
        open(os.path.join(d, hashlib.sha1(b).hexdigest()), "wb").write(b)
m = json.load(open(os.path.join(v, "messages.json")))
put("mls_message", [x[k] for x in m[:40] for k in x])
put("group_process", [x[k] for x in m[:40] for k in ("public_message_proposal", "public_message_commit", "private_message")])
t = json.load(open(os.path.join(v, "tree-validation.json")))
put("ratchet_tree", [x["tree"] for x in t if x["cipher_suite"] == 1])
put("wire_frames", ["01" + "05616c696365"])
PY
for t in mls_message ratchet_tree wire_frames group_process; do
  mkdir -p "$MLS_WORK/corpus/$t" "$MLS_WORK/artifacts/$t"
  echo "== $t"
  cargo +nightly fuzz run "$t" "$MLS_WORK/corpus/$t" -- -max_total_time="$SECS" -artifact_prefix="$MLS_WORK/artifacts/$t/" -print_final_stats=1 2>&1 \
    | grep -E "stat::number_of_executed_units|stat::new_units_added|cov:|ERROR|panicked|SUMMARY|Test unit written" | tail -6
  echo "artifacts: $(ls "$MLS_WORK/artifacts/$t" | wc -l)"
done
