#!/bin/sh
# AegisMesh CI smoke gate (public Actions repo, disposable fixture).
# Runs the committed, seeded simulators as a machine-checkable regression
# gate: every MAC-timing / SLO claim in research.md must reproduce from a
# smoke profile of these scripts (see task.md Firmware Validation rules).
set -e
python3 --version

echo "== iter4 fast sections (C,D,E,F) =="
python3 sim/hasp_iter4.py --sections C,D,E,F --json /tmp/iter4.json
python3 - <<'PY'
import json
r = json.load(open("/tmp/iter4.json"))
bq = r["backstop_queue"]
assert bq["lam_max_per_s"] < 0.03, "backstop duty bound moved"
assert bq["rows"][0]["wq_s"] is not None and bq["rows"][0]["wq_s"] < 5
aq = r["ack_quorum"]
assert aq["false_delivered"][1]["p_false_delivered"] == 0.0, "q=1 must be 0"
assert aq["false_delivered"][2]["p_false_delivered"] < 1e-5
vc = r["window_capacity"]
assert 4 <= vc["peers_per_window_p50"] <= 13, "window capacity moved"
vd = r["venue_discovery"]
assert vd["detected_frac"] == 1.0 and vd["detection_latency_p50_min"] <= 60
print("SMOKE GATE PASS: iter4 fast sections within recorded bounds")
PY

echo "== iter3 SLO smoke (DES + MC, reduced reps) =="
python3 sim/hasp_iter3.py --sections rest --des-reps 500 --conc-reps 2000 \
    --ack-reps 1000 --seed 42 --json /tmp/iter3.json
python3 - <<'PY'
import json
r = json.load(open("/tmp/iter3.json"))
sos = r["sos_des"]["N300_sanity"]
assert sos["p95"] < 5.0, "SLO regression: N300 p95 >= 5 s"
assert sos["p_gt_5s"] == 0.0
c = r["concurrent_k16"]
print("SLO check: N300 p95 = %.3f s (P(>5 s) = %.1f%%)"
      % (sos["p95"], 100 * sos["p_gt_5s"]))
print("SMOKE GATE PASS: iter3 DES + SLO check")
PY

echo "== LR2021 Renode skeleton compile check =="
python3 -m py_compile sim/lr2021_peripheral.py
echo "LR2021 skeleton compiles; register-accurate Renode timing pending"

echo "AegisMesh smoke gate: ALL PASS"
