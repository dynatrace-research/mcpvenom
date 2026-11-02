# Experiment Log: description-scanner
Created: 2026-09-11 | Status: Complete
---
2026-09-11 — scanner.py + 8-case test green; scan_descriptions.py run against 10 live servers (pinned versions in the script; reference-server checkout d73f99e, github-mcp-server image ghcr.io/github/github-mcp-server as pulled 2026-09-11). Results: results/scan-20260911T184812Z.md. Union rejects 20/45 scenarios, flags 9/125 benign descriptions. Encoded check fires on no scenario (ROT13 payloads). Status: DONE, pending paper paragraph.
