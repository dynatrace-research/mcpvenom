# mcpvenom

| ⚠️ WARNING: This product is not officially supported by Dynatrace. |
| --------------------------------------------------------- |

mcpvenom is a behavioral security testing tool for MCP-based AI agents: it runs
declarative tool-poisoning attacks against an agent and uses canary-based oracles
to detect when the agent leaks a planted secret, reads a tripwire file, or takes
an unauthorized action. Use it to test your own agents and frameworks — the
harness, the 45 declarative attack scenarios, the malicious and legitimate MCP
servers, and the registration-time description scanner are all here.

It also backs the paper *MCP Tool Poisoning in Agentic AI Frameworks: A
Cross-Framework Measurement Study* (AISec '26, co-located with ACM CCS 2026); the
frozen result data and reproduction steps live in [`artifacts/`](artifacts/).

## Quickstart

Run one attack scenario end to end against the local canary (needs a LiteLLM
proxy and model access, set up under [Install](#install)):

```bash
# 1. Start the local canary tripwire (listens on localhost:18080)
podman compose -f infra/podman-compose.yml up -d canary-server

# 2. Populate a workspace with the planted (synthetic) secret files
bash infra/init-workspace.sh /tmp/mcpvenom-workspace

# 3. Run one scenario against a model through your LiteLLM proxy
python harnesses/harness_langchain.py \
  vendor/mcpvenom/src/mcpvenom/scenarios/annotation-hint-injection.yaml \
  /tmp/mcpvenom-workspace http://localhost:18080 <model>
```

List the 45 bundled scenarios with `uv run mcpvenom list` once installed. To
reproduce the paper's aggregate numbers from the frozen result data (no model
access needed), see [`artifacts/`](artifacts/).

## Layout

| Path | Contents |
|------|----------|
| `harnesses/` | Per-framework attack drivers (`harness_*.py`), the matrix runner (`run_matrix.py`), the oracle (`oracle.py`), shared config (`config.py`), and the analysis scripts (`parse_matrix.py`, `verify_claims.py`, `consistency_check.py`, `analyze_replicates.py`). |
| `vendor/mcpvenom/` | Vendored scenario library. Ships `models`, `scenarios`, `oracles`, `canaries`, `runner`, `scanner` (the registration-time description scanner evaluated in the paper), and the 45 scenario YAMLs under `src/mcpvenom/scenarios/*.yaml`. Installed as a local path dependency. |
| `experiments/description-scanner/` | Hypothesis, methodology, and results of the description-scanner evaluation (`results/scan-*.md`), produced by `harnesses/scan_descriptions.py`. |
| `scenarios/` | Scenario registry (`README.md`): scenario → attack class → taxonomy class → oracle mapping. |
| `malicious-mcp/` | Malicious MCP server exposing the poisoned tool descriptions. |
| `infra/` | Legitimate MCP server, canary tripwire server, LiteLLM proxy config (AWS Bedrock model routing), and workspace/replicate setup scripts. |
| `requirements-frozen.txt` | Complete freeze (344 packages) of the venv the published matrix was run in. The install source of truth. |

The matrix is 12 frameworks × 18 models × 45 scenarios. `run1` and `run2` are
two independent runs of the full matrix.

## Install

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

`requirements-frozen.txt` is a complete freeze of the single virtual environment
the matrix was run in. Install it verbatim:

```bash
uv venv --python 3.12
uv pip sync requirements-frozen.txt
uv pip install --no-deps vendor/mcpvenom
```

`uv pip sync` installs exactly that set without re-resolving, so the environment
matches the one the results came from. `mcpvenom` is vendored and installed with
`--no-deps` because its two dependencies (`pydantic`, `pyyaml`) are already in
the freeze.

There is deliberately no `pyproject.toml` and no lockfile: the combined stack is
not resolvable. `crewai 1.15.5` requires `json-repair<0.26` while `dspy 3.2.1`
requires `>=0.54.2`, and `semantic-kernel 1.36.0` requires `pydantic<2.12` while
`google-adk 2.5.0` requires `>=2.12`. Both conflicts are metadata-only and do
not surface at runtime, but they mean no resolver can produce this environment,
whereas the freeze reproduces it exactly.

Framework versions under test:

| Harness | Package | Version |
|---------|---------|---------|
| `openai_baseline` | `openai` | 2.46.0 |
| `ag2` | `ag2[mcp]` | 0.14.0 |
| `langchain` | `langchain-core` / `langgraph` | 1.5.0 / 0.3.0 |
| `agno` | `agno` | 2.8.0 |
| `pydantic_ai` | `pydantic-ai` | 2.14.1 |
| `smolagents` | `smolagents[mcp]` | 1.26.0 |
| `crewai` | `crewai` | 1.15.5 |
| `haystack` | `haystack-ai` / `mcp-haystack` | 3.0.0 / 1.4.0 |
| `llamaindex` | `llama-index-core` | 0.14.23 |
| `semantic_kernel` | `semantic-kernel` | 1.36.0 |
| `google_adk` | `google-adk[extensions]` | 2.5.0 |
| `dspy` | `dspy` | 3.2.1 |

## Reproduce the paper's numbers

The frozen result data for both matrix runs and the reproduction steps (no model
access needed) live in [`artifacts/`](artifacts/).

## Run the live matrix (requires model access)

The harness sends attacks to models through a LiteLLM proxy exposing an
OpenAI-compatible endpoint. Configure access via environment variables
(`LITELLM_BASE`, `LITELLM_KEY`; canary via `CANARY_URL`, `CANARY_SECRET`), start
the proxy and the canary server from `infra/`, then:

```bash
uv run harnesses/run_matrix.py --results-dir results-new
```

By default the matrix runs every harness in the frozen venv, which is how the
published runs were produced. Pass `--uv-run` to instead launch each harness
through `uv run`, giving every framework its own isolated venv resolved from that
harness's inline PEP 723 `# /// script` header (no cross-framework conflicts).
These per-harness environments pin the same framework version but resolve their
transitive dependencies fresh, so they are a convenience path, not a
reproduction of the frozen venv:

```bash
uv run harnesses/run_matrix.py --results-dir results-new --uv-run
```

A single framework driver is also runnable on its own:

```bash
# in the frozen venv
python harnesses/harness_langchain.py <scenario.yaml> <workspace_dir> <canary_url> <model>

# in an isolated venv from the script's own PEP 723 header
uv run harnesses/harness_langchain.py <scenario.yaml> <workspace_dir> <canary_url> <model>
```

`uv run` on a harness always uses that header, never the frozen venv, because
the drivers carry inline script metadata.

## Description scanner

`harnesses/scan_descriptions.py` applies the three checks from the paper
(instruction pattern, encoded content, length) to every scenario description
and to the live `tools/list` output of ten public MCP servers at the versions
pinned in the script. It needs the `mcp` client from the freeze plus `npx`,
`uvx`, and `docker` on the path, and writes a new timestamped report under
`experiments/description-scanner/results/`:

```bash
PYTHONPATH=vendor/mcpvenom/src:harnesses python harnesses/scan_descriptions.py
```

## Disclaimer

mcpvenom executes real MCP tool-poisoning attacks — malicious tool descriptions
and a malicious MCP server that exfiltrate a planted secret to a canary
endpoint — strictly for authorized security testing, defensive validation, and
academic research.

- **Authorized Targets Only:** Run mcpvenom only against the bundled canary
  server in an isolated environment, or against agent configurations you own or
  have explicit, written permission to test. Never register the malicious server
  in a real agent configuration, and never point a run at production, public, or
  third-party systems.
- **No Liability:** This software is provided "as is", without warranty of any
  kind. Users assume all responsibility and liability for the execution,
  deployment, or utilization of this toolkit. Dynatrace LLC accepts no liability
  for any damage or loss arising from its use.
- **Reporting:** Report a security issue in mcpvenom itself privately via GitHub
  Security Advisories, not a public issue.

## License

Copyright (c) Dynatrace LLC 2026 - present. All rights reserved. Licensed under
the mcpvenom Distribution License, Version 1.0 — use is restricted to authorized
security testing, defensive validation, and academic research; redistribution
and modification are not permitted. See [LICENSE](LICENSE) for the full terms and
[NOTICE](NOTICE) for third-party attributions.

## Citation

```bibtex
@inproceedings{shaikh2026mcpvenom,
  author    = {Farooq Shaikh and Biagio Montaruli},
  title     = {{MCP} Tool Poisoning in Agentic {AI} Frameworks: A Cross-Framework Measurement Study},
  booktitle = {Proceedings of the 19th ACM Workshop on Artificial Intelligence and Security (AISec '26)},
  year      = {2026},
  publisher = {ACM},
  doi       = {10.1145/3847352.3848107}
}
```
