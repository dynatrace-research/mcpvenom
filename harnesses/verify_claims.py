# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

"""Independent verification of paper numeric claims against raw results JSON.

Recomputes every table/claim from results/*/*_results.json without reusing
parse_matrix.py, so the numbers are cross-checked by a second implementation.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from collections import Counter, defaultdict


def load_rows(results_dir: str | None = None) -> list[dict]:
    rows: list[dict] = []
    if results_dir:
        base = os.path.abspath(results_dir)
        pattern = os.path.join(base, "*/*_results.json")
    else:
        base = os.path.join(os.path.dirname(__file__), "..")
        pattern = os.path.join(base, "results/*/*_results.json")
    for f in sorted(glob.glob(pattern)):
        rows.extend(json.load(open(f)))
    return rows


def asr(v: int, r: int) -> str:
    denom = v + r
    return f"{100 * v / denom:.1f}%" if denom else "—"


def main(results_dir: str | None = None) -> None:
    rows = load_rows(results_dir)
    print(f"TOTAL CELLS: {len(rows)}")
    print(f"VERDICTS: {dict(Counter(r['verdict'] for r in rows))}\n")

    # key for attack class differs across rows
    sample = rows[0]
    ac_key = "attack_class" if "attack_class" in sample else None
    if ac_key is None:
        for k in sample:
            if "class" in k:
                ac_key = k
    print(f"attack-class key: {ac_key}\n")

    # --- Per-framework table ---
    print("=== Per-Framework ===")
    fw = defaultdict(Counter)
    for r in rows:
        fw[r["framework"]][r["verdict"]] += 1
    print(f"{'framework':18}{'V':>5}{'R':>6}{'E':>6}{'S':>6}{'ASR':>8}")
    for f in sorted(fw):
        c = fw[f]
        print(f"{f:18}{c['VULNERABLE']:>5}{c['RESISTANT']:>6}{c['ERROR']:>6}"
              f"{c['SKIPPED']:>6}{asr(c['VULNERABLE'], c['RESISTANT']):>8}")

    # --- Per-model table ---
    print("\n=== Per-Model ===")
    md = defaultdict(Counter)
    for r in rows:
        md[r["model"]][r["verdict"]] += 1
    print(f"{'model':18}{'V':>5}{'R':>6}{'ASR':>8}")
    for m in sorted(md):
        c = md[m]
        print(f"{m:18}{c['VULNERABLE']:>5}{c['RESISTANT']:>6}{asr(c['VULNERABLE'], c['RESISTANT']):>8}")

    # --- Overall ASR ---
    tot = Counter(r["verdict"] for r in rows)
    print(f"\nOverall ASR = V/(V+R) = {tot['VULNERABLE']}/"
          f"{tot['VULNERABLE'] + tot['RESISTANT']} = "
          f"{asr(tot['VULNERABLE'], tot['RESISTANT'])}")

    # --- Attack class ASR (excluding AG2) ---
    if ac_key:
        print("\n=== Attack-class ASR (excluding AG2) ===")
        cl = defaultdict(Counter)
        for r in rows:
            if r["framework"] == "ag2":
                continue
            ac = r.get(ac_key)
            if ac is None:  # SKIPPED cells carry no attack_class
                continue
            cl[ac][r["verdict"]] += 1
        for c in sorted(cl):
            cc = cl[c]
            print(f"{c:26}{asr(cc['VULNERABLE'], cc['RESISTANT']):>8}  "
                  f"(V={cc['VULNERABLE']} R={cc['RESISTANT']})")

    # --- Chi-squared across non-AG2 frameworks ---
    fws = [f for f in sorted(fw) if f != "ag2"]
    print(f"\n=== Chi-squared ({len(fws)} frameworks excl AG2, V vs R) ===")
    obs = [[fw[f]["VULNERABLE"], fw[f]["RESISTANT"]] for f in fws]
    try:
        from scipy.stats import chi2_contingency  # type: ignore
        chi2, p, dof, _ = chi2_contingency(obs, correction=False)
        print(f"chi2={chi2:.2f}  p={p:.2f}  dof={dof}  (frameworks={fws})")
    except Exception as e:  # noqa: BLE001
        print(f"scipy unavailable ({e}); manual chi2 below")
        # manual chi2
        rowt = [sum(o) for o in obs]
        colt = [sum(o[j] for o in obs) for j in range(2)]
        grand = sum(rowt)
        chi2 = 0.0
        for i, o in enumerate(obs):
            for j in range(2):
                exp = rowt[i] * colt[j] / grand
                chi2 += (o[j] - exp) ** 2 / exp
        print(f"chi2={chi2:.2f}  dof={(len(obs) - 1) * 1}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify paper numeric claims")
    parser.add_argument("--results-dir", type=str, default="",
                        help="Results directory to analyze, e.g. ../results-run2 (REQUIRED; no default)")
    args = parser.parse_args()
    if not args.results_dir:
        parser.error(
            "--results-dir is required (e.g. --results-dir ../results-run2). "
            "No default is used so a superseded run is never read by accident."
        )
    main(args.results_dir)
