# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

"""Analyze ASR stability across multiple sample replicates.

Computes mean ± std dev of ASR per framework, per model, and overall
from N results directories produced with an identical --scenarios filter.

Usage:
    python analyze_replicates.py --dirs results-sample-r1 results-sample-r2 \
                                          results-sample-r3 results-sample-r4

Output: Markdown tables + Wilson 95% CI for the pooled estimate.
"""

import argparse
import json
import math
import sys
from pathlib import Path

FRAMEWORKS = [
    "openai_baseline", "ag2", "langchain", "agno", "pydantic_ai",
    "smolagents", "crewai", "haystack", "llamaindex", "semantic_kernel",
    "google_adk", "dspy",
]


def wilson_ci(vuln: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval (95% by default)."""
    if n == 0:
        return 0.0, 0.0
    p = vuln / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def load_dir(results_dir: Path) -> dict:
    """Load all *_results.json from a results directory.

    Returns {framework: {model: {"vuln": int, "total": int}}}.
    """
    data: dict = {}
    for fw_dir in results_dir.iterdir():
        if not fw_dir.is_dir():
            continue
        fw = fw_dir.name
        data[fw] = {}
        for result_file in fw_dir.glob("*_results.json"):
            try:
                payload = json.loads(result_file.read_text())
            except Exception:
                continue
            model = result_file.stem.removeprefix(f"{fw}_").removesuffix("_results")
            results = payload if isinstance(payload, list) else payload.get("results", [])
            evaluated = [r for r in results if r.get("verdict") in ("VULNERABLE", "RESISTANT")]
            vuln = sum(1 for r in evaluated if r["verdict"] == "VULNERABLE")
            data[fw][model] = {"vuln": vuln, "total": len(evaluated)}
    return data


def asr(vuln: int, total: int) -> float:
    return vuln / total if total else 0.0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dirs", nargs="+", required=True, help="Results directories (one per replicate)")
    parser.add_argument("--full-run-dir", type=str, default="",
                        help="Optional full-run results dir to compare pooled estimate against")
    args = parser.parse_args()

    dirs = [Path(d) for d in args.dirs]
    for d in dirs:
        if not d.exists():
            sys.exit(f"Directory not found: {d}")

    replicate_data = [load_dir(d) for d in dirs]
    n_rep = len(replicate_data)

    all_frameworks = sorted({fw for rd in replicate_data for fw in rd})
    all_models = sorted({m for rd in replicate_data for fw in rd.values() for m in fw})

    print(f"# Stability Analysis — {n_rep} replicates\n")
    print(f"Replicates: {[str(d) for d in dirs]}\n")

    # Per-replicate overall ASR
    rep_overall: list[float] = []
    for i, rd in enumerate(replicate_data):
        v = sum(fw[m]["vuln"] for fw in rd.values() for m in fw)
        t = sum(fw[m]["total"] for fw in rd.values() for m in fw)
        rep_overall.append(asr(v, t))
        print(f"Replicate {i+1} overall ASR: {rep_overall[-1]*100:.2f}%  (VULN {v}/{t})")

    mean_overall = sum(rep_overall) / n_rep
    std_overall = math.sqrt(sum((x - mean_overall) ** 2 for x in rep_overall) / max(1, n_rep - 1))
    print(f"\n**Overall: {mean_overall*100:.2f}% ± {std_overall*100:.2f}pp (σ across {n_rep} replicates)**\n")

    # Wilson CI on pooled
    pooled_v = sum(
        rd.get(fw, {}).get(m, {}).get("vuln", 0)
        for rd in replicate_data for fw in all_frameworks for m in all_models
    )
    pooled_t = sum(
        rd.get(fw, {}).get(m, {}).get("total", 0)
        for rd in replicate_data for fw in all_frameworks for m in all_models
    )
    lo, hi = wilson_ci(pooled_v, pooled_t)
    print(f"Pooled Wilson 95% CI: [{lo*100:.2f}%, {hi*100:.2f}%]  (VULN {pooled_v}/{pooled_t})\n")

    # Framework table
    print("## ASR by Framework\n")
    print(f"{'Framework':<22} {'Mean':>7} {'±σ':>7} {'Min':>7} {'Max':>7}  {'Replicates'}")
    print("-" * 80)
    for fw in all_frameworks:
        rep_asrs = []
        for rd in replicate_data:
            v = sum(rd.get(fw, {}).get(m, {}).get("vuln", 0) for m in all_models)
            t = sum(rd.get(fw, {}).get(m, {}).get("total", 0) for m in all_models)
            if t:
                rep_asrs.append(asr(v, t))
        if not rep_asrs:
            continue
        m_ = sum(rep_asrs) / len(rep_asrs)
        s_ = math.sqrt(sum((x - m_) ** 2 for x in rep_asrs) / max(1, len(rep_asrs) - 1))
        vals = "  ".join(f"{x*100:.1f}%" for x in rep_asrs)
        print(f"{fw:<22} {m_*100:>6.2f}% {s_*100:>6.2f}pp "
              f"{min(rep_asrs)*100:>6.1f}% {max(rep_asrs)*100:>6.1f}%  [{vals}]")

    # Model table
    print("\n## ASR by Model\n")
    print(f"{'Model':<22} {'Mean':>7} {'±σ':>7} {'Min':>7} {'Max':>7}  {'Replicates'}")
    print("-" * 80)
    for model in all_models:
        rep_asrs = []
        for rd in replicate_data:
            v = sum(rd.get(fw, {}).get(model, {}).get("vuln", 0) for fw in all_frameworks)
            t = sum(rd.get(fw, {}).get(model, {}).get("total", 0) for fw in all_frameworks)
            if t:
                rep_asrs.append(asr(v, t))
        if not rep_asrs:
            continue
        m_ = sum(rep_asrs) / len(rep_asrs)
        s_ = math.sqrt(sum((x - m_) ** 2 for x in rep_asrs) / max(1, len(rep_asrs) - 1))
        vals = "  ".join(f"{x*100:.1f}%" for x in rep_asrs)
        print(f"{model:<22} {m_*100:>6.2f}% {s_*100:>6.2f}pp "
              f"{min(rep_asrs)*100:>6.1f}% {max(rep_asrs)*100:>6.1f}%  [{vals}]")

    # Compare against full run if provided
    if args.full_run_dir:
        full = load_dir(Path(args.full_run_dir))
        print("\n## Pooled replicate mean vs full run\n")
        print(f"{'Framework':<22} {'Full run':>9} {'Replicate mean':>15} {'Delta':>7}")
        print("-" * 60)
        for fw in all_frameworks:
            fv = sum(full.get(fw, {}).get(m, {}).get("vuln", 0) for m in all_models)
            ft = sum(full.get(fw, {}).get(m, {}).get("total", 0) for m in all_models)
            if not ft:
                continue
            full_asr = asr(fv, ft)
            rep_asrs = []
            for rd in replicate_data:
                v = sum(rd.get(fw, {}).get(m, {}).get("vuln", 0) for m in all_models)
                t = sum(rd.get(fw, {}).get(m, {}).get("total", 0) for m in all_models)
                if t:
                    rep_asrs.append(asr(v, t))
            if not rep_asrs:
                continue
            rm = sum(rep_asrs) / len(rep_asrs)
            delta = (rm - full_asr) * 100
            sign = "+" if delta >= 0 else ""
            print(f"{fw:<22} {full_asr*100:>8.2f}% {rm*100:>14.2f}% {sign}{delta:>6.2f}pp")


if __name__ == "__main__":
    main()
