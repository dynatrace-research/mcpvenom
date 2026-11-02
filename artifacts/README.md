# artifacts — frozen measurement data

Frozen result record for the paper *MCP Tool Poisoning in Agentic AI Frameworks:
A Cross-Framework Measurement Study* (AISec '26, co-located with ACM CCS 2026).
It holds the raw per-cell verdict JSON for the two independent runs of the full
matrix that back every number in the paper. The tool that produced it is the rest
of this repository — see the [root README](../README.md).

## Layout

| Path | Contents |
|------|----------|
| `run1/`, `run2/` | Per-cell verdict JSON (`<framework>/<framework>_<model>_results.json`), one file per framework×model, plus `run_metadata.json` and `matrix-summary.md`. Per-attempt transcripts are omitted for size; the verdict rows carry the oracle outcomes. |

The matrix is 12 frameworks × 18 models × 45 scenarios. `run1` and `run2` are two
independent runs of the full matrix, with an aggregate attack-success rate of
22.9% on run2. The `mcpfuzz_*` fields in `run*/run_metadata.json` are the
unmodified run records — the scenario library was called `mcpfuzz` during review
and released as `mcpvenom`; they refer to the same code.

## Reproduce the aggregate numbers

No model access and no agent framework needed — only the scenario library and
`scipy`:

```bash
uv venv --python 3.12
uv pip install "scipy==1.18.0" "pydantic==2.12.5" "pyyaml==6.0.3"
uv pip install --no-deps vendor/mcpvenom
```

Then, from the repository root:

```bash
# Aggregate attack-success-rate tables (overall, per-framework, per-model, per-class)
uv run harnesses/parse_matrix.py --results-dir artifacts/run2 --deep

# Cross-run stability (per-framework spread between run1 and run2)
uv run harnesses/consistency_check.py --results-dir artifacts/run1 artifacts/run2

# Re-derive the specific claims checked in the paper
uv run harnesses/verify_claims.py --results-dir artifacts/run2
```
