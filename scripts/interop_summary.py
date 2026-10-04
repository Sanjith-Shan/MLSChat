#!/usr/bin/env python3
"""Summarize test-runner JSON outputs: per config, runs passed and failed,
split by which implementations played the actors."""
import json, os, sys, time, collections
out_dir, results = sys.argv[1], sys.argv[2]
load = open("/proc/loadavg").read().split()
lines = []
for f in sorted(os.listdir(out_dir)):
    if not f.endswith(".json"):
        continue
    cfg = f[:-5]
    try:
        data = json.load(open(os.path.join(out_dir, f)))
    except Exception:
        err = open(os.path.join(out_dir, cfg + ".err")).read()[-300:]
        print(f"{cfg}: no JSON ({err.strip()})")
        continue
    total = passed = 0
    by_mix = collections.Counter()
    errors = collections.Counter()
    for script, runs in data["scripts"].items():
        for r in runs:
            total += 1
            names = set(r.get("actors", {}).values())
            mix = "mixed" if len(names) > 1 else ("mlschat-only" if names == {"MLSChat"} else "openmls-only")
            ok = r.get("failed_step") is None
            passed += ok
            by_mix[(mix, ok)] += 1
            if not ok:
                errors[(script, (r.get("error") or "")[:120])] += 1
    line = {
        "experiment": "interop_harness", "config": cfg, "runs": total, "passed": passed, "failed": total - passed,
        "mixed_runs": by_mix[("mixed", True)] + by_mix[("mixed", False)], "mixed_passed": by_mix[("mixed", True)],
        "mlschat_only_passed": by_mix[("mlschat-only", True)], "mlschat_only_runs": by_mix[("mlschat-only", True)] + by_mix[("mlschat-only", False)],
        "openmls_only_passed": by_mix[("openmls-only", True)], "openmls_only_runs": by_mix[("openmls-only", True)] + by_mix[("openmls-only", False)],
        "failures": [{"script": s, "error": e, "count": n} for (s, e), n in errors.most_common(8)],
        "clients": ["MLSChat", "OpenMLS (main @ 4f407c4)"], "harness_commit": "cfd450286d1bfd9cd2519b95c80f9771f94a5b1a",
        "host": "shared mini PC (Acemagic K1, Windows 11) running a 2-vCPU WSL2 Ubuntu 24.04 VM; other projects' sessions may share the box",
        "loadavg_1m": float(load[0]), "unix_time": time.time(),
    }
    lines.append(line)
    print(f"{cfg:20} {passed:5}/{total:<5} passed | mixed {line['mixed_passed']}/{line['mixed_runs']} | MLSChat-only {line['mlschat_only_passed']}/{line['mlschat_only_runs']} | OpenMLS-only {line['openmls_only_passed']}/{line['openmls_only_runs']}")
    for (s, e), n in errors.most_common(4):
        print(f"    {n}x {s}: {e}")
with open(results, "a") as fh:
    for l in lines:
        fh.write(json.dumps(l) + "\n")
