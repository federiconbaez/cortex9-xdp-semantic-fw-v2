#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Evaluate measure-verdicts CSV against corpus/labels.csv.

Prints TPR/FPR and writes results/summary.json. Never retunes anything.
"""
from __future__ import annotations
import argparse, csv, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("verdicts")  # index,action,reason
    ap.add_argument("--labels", default=str(ROOT / "corpus" / "labels.csv"))
    ap.add_argument("--out", default=str(ROOT / "results" / "summary.json"))
    ap.add_argument("--baseline", default=None, help="optional baseline CSV (index,action)")
    args = ap.parse_args()

    labels = {int(r["index"]): r for r in csv.DictReader(open(args.labels))}
    v = {}
    with open(args.verdicts) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            i, action, reason = line.split(",")
            v[int(i)] = (int(action), int(reason))

    if set(v) != set(labels):
        print(f"FATAL: verdict/label index mismatch "
              f"(verdicts={len(v)} labels={len(labels)})", file=sys.stderr)
        return 2

    tp = fp = tn = fn = 0
    by_kind = {}
    for i, lab in labels.items():
        action, reason = v[i]
        dropped = action == 1  # XDP_DROP
        attack = lab["label"] == "attack"
        k = lab["kind"]
        by_kind.setdefault(k, {"n": 0, "drop": 0})
        by_kind[k]["n"] += 1
        if dropped:
            by_kind[k]["drop"] += 1
        if attack and dropped:
            tp += 1
        elif attack and not dropped:
            fn += 1
        elif (not attack) and dropped:
            fp += 1
        else:
            tn += 1

    n_atk = tp + fn
    n_leg = fp + tn
    tpr = tp / n_atk if n_atk else 0.0
    fpr = fp / n_leg if n_leg else 0.0
    summary = {
        "n_attack": n_atk,
        "n_legit": n_leg,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "tpr": round(tpr, 6),
        "fpr": round(fpr, 6),
        "threshold_tpr": 0.90,
        "threshold_fpr": 0.01,
        "pass_tpr": tpr >= 0.90,
        "pass_fpr": fpr <= 0.01,
        "pass": (tpr >= 0.90) and (fpr <= 0.01),
        "by_kind": by_kind,
    }

    if args.baseline:
        btp = bfp = btn = bfn = 0
        with open(args.baseline) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("index"):
                    continue
                i_s, a_s = line.split(",")[:2]
                i, dropped = int(i_s), int(a_s) == 1
                attack = labels[i]["label"] == "attack"
                if attack and dropped: btp += 1
                elif attack and not dropped: bfn += 1
                elif (not attack) and dropped: bfp += 1
                else: btn += 1
        summary["baseline"] = {
            "tp": btp, "fn": bfn, "fp": bfp, "tn": btn,
            "tpr": round(btp / (btp + bfn), 6) if (btp + bfn) else 0.0,
            "fpr": round(bfp / (bfp + btn), 6) if (bfp + btn) else 0.0,
            "note": "nftables string --icase (emulated offline when xt_string unavailable)",
        }

    pathlib.Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(args.out).write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if summary["pass"] else 1

if __name__ == "__main__":
    sys.exit(main())
