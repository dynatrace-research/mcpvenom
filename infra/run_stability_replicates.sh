#!/usr/bin/env bash
# Run 4 stability replicates on a stratified 5-scenario sample.
# Each replicate produces 12 fw × 18 models × 5 scenarios = 1080 cells.
# Run AFTER a full matrix run finishes (litellm + canary must be up).
#
# Usage (from repo root on EC2):
#   bash infra/run_stability_replicates.sh
#
# Results land in results-sample-r1 … results-sample-r4.
# Analyse with:
#   python harnesses/analyze_replicates.py \
#       --dirs results-sample-r{1,2,3,4} \
#       --full-run-dir results-run1

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
source harnesses/.venv/bin/activate

# 5 scenarios — one from each of the top-5 attack classes by ASR (run #5):
#   annotation-injection (23.3%), confused-deputy (21.4%), tool-poisoning (20.6%),
#   streaming-injection (17.5%), memory-poisoning (11.6%)
SCENARIOS="annotation-hint-injection,confused-deputy-chain,tool-poisoning-exfiltration,streaming-response-injection,memory-poisoning-delayed"

PARALLELISM=8

echo "=== Stability replicates: 4 × 1080 cells ==="
echo "Scenarios: $SCENARIOS"
echo ""

for R in 1 2 3 4; do
    DIR="results-sample-r${R}"
    echo "--- Replicate $R → $DIR ---"

    # Reset canary between replicates to avoid cross-contamination
    curl -s -X POST http://localhost:18080/reset | python3 -c "import sys,json; d=json.load(sys.stdin); print('canary reset:', d)"

    python harnesses/run_matrix.py \
        --results-dir "$DIR" \
        --scenarios "$SCENARIOS" \
        --parallelism "$PARALLELISM" \
        2>&1 | tee "/tmp/sample-r${R}.log"

    echo "Replicate $R done."
    echo ""
done

echo "=== All replicates complete. Analysing... ==="
python harnesses/analyze_replicates.py \
    --dirs results-sample-r1 results-sample-r2 results-sample-r3 results-sample-r4 \
    --full-run-dir results-run1 \
    | tee results-stability-analysis.txt

echo ""
echo "Full report: results-stability-analysis.txt"
