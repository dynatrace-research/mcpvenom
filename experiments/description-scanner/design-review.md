# Design Review — description-scanner — 2026-09-11

## RQs: 3 defined, all answerable from the scan output
## Hypotheses: falsifiable (H1 ≥70% union detection: REJECTED at 44.4% per scenario; H2 ≤10% FPR: held at 7.2%; H3 result-channel classes evade: held, plus P2/P4/P12/P17/P20)
## Baselines: none needed (measurement of a proposed control, not a comparison); corpus independence: benign descriptions come from third-party servers, poisoned from the authors' scenarios
## Sample size: 95 poisoned descriptions in 45 scenarios (census); 125 benign descriptions from 10 servers
## Benchmark honesty: verb list and thresholds are author-chosen and fixed before the run; no per-corpus tuning after the first run except generalizing verb suffixes (recorded in log)
