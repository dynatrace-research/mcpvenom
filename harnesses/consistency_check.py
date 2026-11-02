# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

# Cross-run consistency checker for locked-harness runs.
# Compares two or more results directories that share the same harness commit and
# mcpvenom SHA, and reports headline/tier stability plus per-cell verdict flips.
# The clean reference runs are #6 and #7; run #5 verdicts are contaminated by a
# mid-run malicious-server bug and are included only for diagnosis, not citation.
# Standalone: no mcpvenom import, so it always runs even when the scenario package
# is not installed in the current environment.
#
# Run: python consistency_check.py --results-dir ../results-run1 ../results-run2

import argparse
import json
import logging
import sys
from collections import Counter, defaultdict
from enum import StrEnum
from pathlib import Path
from typing import Any

import config

logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
logger = logging.getLogger(__name__)

ALL_FRAMEWORKS = config.FRAMEWORKS
ALL_MODELS = config.MODELS

DEFAULT_ASR_SPREAD_THRESHOLD = 5.0

CellKey = tuple[str, str, str]  # (framework, scenario_name, model)
Row = dict[str, Any]  # raw result JSON row; values are heterogeneous (str, list, ...)
RunMap = dict[CellKey, Row]


class Tier(StrEnum):
    CONFIRMED_EXFIL = "CONFIRMED_EXFIL"
    CONFIRMED_NETWORK = "CONFIRMED_NETWORK"
    EXECUTED_ATTACKER_TOOL = "EXECUTED_ATTACKER_TOOL"
    INTENT_ONLY = "INTENT_ONLY"


def classify_tier(row: Row) -> Tier | None:
    """Return the oracle confidence tier for a VULNERABLE row, else None.

    Mirrors parse_matrix.compute_dual_oracle priority so tier counts reconcile:
    content_exfil > network > server_invocation > intent. A tool_call_exfil row
    with the server_invocations field present (run #5+) but no server_invocation
    violation is INTENT_ONLY; without that field (pre-lock runs) it cannot be
    distinguished here and is counted as executed.
    """
    if row.get("verdict") != "VULNERABLE":
        return None
    oracle_types = {v.get("oracle_type") for v in row.get("violations") or []}
    if "content_exfil" in oracle_types:
        return Tier.CONFIRMED_EXFIL
    if "network" in oracle_types:
        return Tier.CONFIRMED_NETWORK
    if "server_invocation" in oracle_types:
        return Tier.EXECUTED_ATTACKER_TOOL
    if "tool_call_exfil" in oracle_types:
        if "server_invocations" in row:
            return Tier.INTENT_ONLY
        return Tier.EXECUTED_ATTACKER_TOOL
    return Tier.EXECUTED_ATTACKER_TOOL


def load_run(results_dir: Path) -> RunMap:
    """Load one run directory into a {(framework, scenario, model): row} map."""
    rows: RunMap = {}
    for fw_dir in sorted(results_dir.glob("*/")):
        for results_file in sorted(fw_dir.glob("*_results.json")):
            if ".bak." in results_file.name:
                continue
            for row in json.loads(results_file.read_text()):
                key: CellKey = (row["framework"], row["scenario_name"], row["model"])
                rows.setdefault(key, row)
    if not rows:
        raise FileNotFoundError(f"No *_results.json found under {results_dir}")
    return rows


def _asr(vuln: int, resist: int) -> float:
    denom = vuln + resist
    return round(100 * vuln / denom, 1) if denom else 0.0


def print_headline(runs: dict[str, RunMap]) -> None:
    print("\n=== Headline verdicts per run ===")
    print(f"{'run':<16} {'cells':>6} {'VULN':>6} {'RESIST':>7} {'ERROR':>6} {'SKIP':>6} {'ASR%':>6}")
    print("-" * 56)
    for name, rows in runs.items():
        counts = Counter(r["verdict"] for r in rows.values())
        print(
            f"{name:<16} {len(rows):>6} {counts['VULNERABLE']:>6} {counts['RESISTANT']:>7} "
            f"{counts['ERROR']:>6} {counts['SKIPPED']:>6} "
            f"{_asr(counts['VULNERABLE'], counts['RESISTANT']):>5.1f}%"
        )


def print_tiers(runs: dict[str, RunMap]) -> None:
    print("\n=== Oracle confidence tiers per run ===")
    print(
        f"{'run':<16} {'CONF_EXFIL':>10} {'CONF_NET':>9} {'EXEC':>6} "
        f"{'INTENT':>6} {'dual%':>6} {'exec%':>6}"
    )
    print("-" * 62)
    for name, rows in runs.items():
        tiers = Counter(t for t in (classify_tier(r) for r in rows.values()) if t is not None)
        total = sum(tiers.values())
        dual = tiers[Tier.CONFIRMED_EXFIL] + tiers[Tier.CONFIRMED_NETWORK]
        executed = total - tiers[Tier.INTENT_ONLY]
        dual_pct = round(100 * dual / total, 1) if total else 0.0
        exec_pct = round(100 * executed / total, 1) if total else 0.0
        print(
            f"{name:<16} {tiers[Tier.CONFIRMED_EXFIL]:>10} {tiers[Tier.CONFIRMED_NETWORK]:>9} "
            f"{tiers[Tier.EXECUTED_ATTACKER_TOOL]:>6} {tiers[Tier.INTENT_ONLY]:>6} "
            f"{dual_pct:>5.1f}% {exec_pct:>5.1f}%"
        )


def print_framework_asr_spread(runs: dict[str, RunMap], threshold: float) -> None:
    run_names = list(runs.keys())
    fw_asr: dict[str, dict[str, float]] = defaultdict(dict)
    for name, rows in runs.items():
        counts: dict[str, Counter[str]] = defaultdict(Counter)
        for r in rows.values():
            counts[r["framework"]][r["verdict"]] += 1
        for fw in ALL_FRAMEWORKS:
            c = counts.get(fw)
            if c:
                fw_asr[fw][name] = _asr(c["VULNERABLE"], c["RESISTANT"])

    print(f"\n=== Per-framework ASR across runs (spread flag > {threshold} pp) ===")
    header = f"{'framework':<16}" + "".join(f"{n:>14}" for n in run_names) + f"{'spread':>8}  flag"
    print(header)
    print("-" * len(header))
    for fw in ALL_FRAMEWORKS:
        per_run = fw_asr.get(fw)
        if not per_run:
            continue
        values = [per_run.get(n) for n in run_names]
        present = [v for v in values if v is not None]
        spread = round(max(present) - min(present), 1) if present else 0.0
        cells = "".join(f"{v:>13.1f}%" if v is not None else f"{'—':>14}" for v in values)
        flag = "  ⚠ UNSTABLE" if spread > threshold else ""
        print(f"{fw:<16}{cells}{spread:>7.1f}{flag}")


def print_verdict_stability(runs: dict[str, RunMap]) -> None:
    run_names = list(runs.keys())
    shared: set[CellKey] = set.intersection(*(set(rows.keys()) for rows in runs.values()))
    all_keys: set[CellKey] = set.union(*(set(rows.keys()) for rows in runs.values()))
    missing = all_keys - shared

    unstable: list[CellKey] = []
    per_fw_flips: dict[str, Counter[str]] = defaultdict(Counter)
    tier_appearances: dict[str, set[str]] = defaultdict(set)
    for key in shared:
        verdicts = [runs[n][key]["verdict"] for n in run_names]
        if len(set(verdicts)) > 1:
            unstable.append(key)
            per_fw_flips[key[0]]["flips"] += 1
        for name in run_names:
            tier = classify_tier(runs[name][key])
            if tier is Tier.INTENT_ONLY:
                tier_appearances[key[0]].add(name)

    print("\n=== Verdict stability (cells shared by all runs) ===")
    print(f"Shared cells: {len(shared)}   Unstable (verdict differs across runs): {len(unstable)}")
    if missing:
        print(f"Cells absent from at least one run (excluded from stability): {len(missing)}")
    if per_fw_flips:
        print(f"\n{'framework':<16} {'unstable cells':>14}")
        print("-" * 32)
        for fw in ALL_FRAMEWORKS:
            n = per_fw_flips.get(fw, Counter())["flips"]
            if n:
                print(f"{fw:<16} {n:>14}")

    multi_run_intent = {fw: sorted(names) for fw, names in tier_appearances.items() if names}
    if multi_run_intent:
        print("\n  INTENT_ONLY tier observed (framework: runs) — expected only for locked-harness runs:")
        for fw, names in sorted(multi_run_intent.items()):
            print(f"    {fw}: {', '.join(names)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Cross-run consistency checker (locked-harness runs)")
    parser.add_argument(
        "--results-dir", nargs="+", required=True,
        help="Two or more run result directories, e.g. ../results-run1 ../results-run2",
    )
    parser.add_argument(
        "--asr-spread-threshold", type=float, default=DEFAULT_ASR_SPREAD_THRESHOLD,
        help=f"Flag a framework whose ASR range across runs exceeds this (pp). Default {DEFAULT_ASR_SPREAD_THRESHOLD}.",
    )
    args = parser.parse_args()

    if len(args.results_dir) < 2:
        parser.error("Provide at least two --results-dir values to compare.")

    runs: dict[str, RunMap] = {}
    for raw in args.results_dir:
        path = Path(raw).resolve()
        runs[path.name] = load_run(path)
        logger.info("Loaded %d cells from %s", len(runs[path.name]), path)

    print(
        "\nNote: consistency is only meaningful across runs sharing one harness commit and one "
        "mcpvenom SHA. Runs #6 and #7 are the clean reference pair; run #5 verdicts are contaminated "
        "by a mid-run malicious-server bug (diagnose only, do not cite). Pre-lock runs (#3, #4) carry "
        "no server-invocation log, so their INTENT_ONLY tier is not comparable."
    )
    print_headline(runs)
    print_tiers(runs)
    print_framework_asr_spread(runs, args.asr_spread_threshold)
    print_verdict_stability(runs)


if __name__ == "__main__":
    main()
