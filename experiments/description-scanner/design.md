# Design

- Scanner: `vendor/mcpvenom/src/mcpvenom/scanner.py`, one function `scan(description, tool_names) -> set[str]` returning the fired check names. Stdlib `re` only.
- Corpus and report: `harnesses/scan_descriptions.py` loads scenarios through `mcpvenom.scenarios`, extracts benign descriptions from the pinned reference-server checkout by regex over `description:` string literals in `.ts`/`.py`, writes a Markdown table to `experiments/description-scanner/results/scan-<timestamp>.md`.
- Test: `vendor/mcpvenom/tests/test_scanner.py`, one case per check and one benign case.
- Reference servers pinned commit: recorded in `results/` at run time.
- Compute: none beyond local CPU.
