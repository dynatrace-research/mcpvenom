# Methodology Spec: description-scanner

## Research questions
- RQ-S1: What fraction of poisoned tool descriptions does each check, and their union, flag?
- RQ-S2: What fraction of benign tool descriptions does each check, and their union, flag (false positives)?
- RQ-S3: Which taxonomy classes evade the union scanner?

## Hypotheses
- H1: union detection on poisoned descriptions ≥ 70%. Direction: higher than any single check.
- H2: union false-positive rate on benign descriptions ≤ 10%.
- H3: classes whose payload is not in a `tools/list` description (P6, P9, P10, P14, P18, P21) evade the scanner.

## Independent variable
Check applied: instruction | encoded | length | union.

## Dependent variables
flag(d, check) ∈ {0, 1} per description d.

## Corpora
- Poisoned: every `tools[].description` (top-level and per-phase) in the 45 scenario YAMLs, after `{canary_url}` substitution with `http://localhost:18080`; labelled with the scenario's taxonomy class from `scenarios/README.md`.
- Benign: every tool description extracted from the official reference servers (`github.com/modelcontextprotocol/servers`, pinned commit recorded in `design.md`) plus the five legitimate-server tools in `infra/mcp-legitimate`.

## Metrics
- detection(check) = flagged poisoned / total poisoned
- fpr(check) = flagged benign / total benign
- evasion(class) = unflagged poisoned descriptions of that class / poisoned descriptions of that class (union check)

## Requirements
- R1: The scanner SHALL flag a description as `instruction` when it contains an imperative verb from a fixed list followed within the same sentence by a tool name present in the served tool list or by a URL.
- R2: The scanner SHALL flag a description as `encoded` when it contains a run of at least 24 base64 characters ending in valid padding or a run of at least 32 hexadecimal characters.
- R3: The scanner SHALL flag a description as `length` when its length exceeds 500 characters.
- R4: The scanner SHALL flag a description as `union` when any of R1–R3 flags it.
- R5: The report SHALL give detection(check) and fpr(check) for each of the four checks and evasion(class) for every class present in the poisoned corpus.
- R6: The scanner SHALL be deterministic: identical input yields identical output.

## Sample size
Poisoned: all descriptions in the 45 scenarios (census, N ≥ 45). Benign: all descriptions in the reference servers (N recorded at run time; target ≥ 100).

## Caveats
- The benign corpus is a convenience sample of reference servers, not a random sample of the ecosystem.
- The imperative-verb list is author-chosen; the reported rates depend on it.
- Registration-time scanning cannot see payloads delivered in tool results, resources, notifications, or later turns.
