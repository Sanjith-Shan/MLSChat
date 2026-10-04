#!/usr/bin/env python3
"""Turn TLC output files into results/model_check.jsonl lines (with machine and load)."""
import json, os, re, sys, time, platform
work = os.environ.get("MLS_WORK", os.path.expanduser("~/mlschat-work"))
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cfgs = ["fenced", "fenced_2x2", "fenced_logorder", "unfenced_logorder", "unfenced_mergeonack", "relay",
        "unfenced_logorder_nofork", "unfenced_mergeonack_nofork", "relay_nofork"]
load = open("/proc/loadavg").read().split()[:3]
out = open(os.path.join(root, "results", "model_check.jsonl"), "a")
for c in cfgs:
    text = open(os.path.join(work, "tla", c + ".out")).read()
    cfg = open(os.path.join(root, "docs", "tla", c + ".cfg")).read()
    viol = re.search(r"Invariant (\w+) is violated", text)
    m = re.search(r"([\d,]+) states generated, ([\d,]+) distinct states found", text)
    out.write(json.dumps({
        "experiment": "tla_model_check", "config": c,
        "constants": {k: v for k, v in re.findall(r"^\s+(\w+) = (.+)$", cfg, re.M)},
        "invariants_checked": re.search(r"INVARIANTS (.+)", cfg).group(1).split(),
        "result": "violated" if viol else ("holds" if "No error has been found" in text else "unknown"),
        "violated_invariant": viol.group(1) if viol else None,
        "states_generated": int(m.group(1).replace(",", "")) if m else None,
        "distinct_states": int(m.group(2).replace(",", "")) if m else None,
        "counterexample_states": len(re.findall(r"^State \d+:", text, re.M)) or None,
        "host": "shared mini PC (Acemagic K1, Windows 11) running a 2-vCPU WSL2 Ubuntu 24.04 VM; other projects' sessions may share the box",
        "loadavg_1m": float(load[0]), "loadavg_5m": float(load[1]), "kernel": platform.release(),
        "tool": "TLC 1.8.0 (tla2tools.jar), Temurin JRE 21", "unix_time": time.time(),
    }) + "\n")
