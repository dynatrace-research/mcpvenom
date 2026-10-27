# Changelog

## [Unreleased]

### Added
- Registration-time description scanner (`mcpvenom.scanner`) and its evaluation against the 45 scenarios and 125 benign descriptions from ten public MCP servers
- Citation, NOTICE, CODE_OF_CONDUCT, and SECURITY.md for the public release
- CI workflow running ruff and pytest; tests for `determine_verdict` and the shared secret-pattern module

### Changed
- Released under the mcpvenom Distribution License, Version 1.0 (source-available; authorized security testing, defensive validation, and academic research only); added the security notice and disclaimer for the malicious tool definitions
- Scrubbed internal infrastructure detail from `infra/` (preview endpoint, instance name, retention hook now opt-in only)
- Single-sourced the secret-detection patterns; replaced `exec()`-based handler generation with an explicit signature; extracted the shared harness run loop into `harness_base`
- Renamed the scenario library from mcpfuzz to mcpvenom; result records keep their original `mcpfuzz_*` fields
- Replaced anonymized author and repository metadata with the published ones
- Bundled the frozen per-run result JSON under `artifacts/` (run1, run2) alongside the tool, harnesses, scenarios, and scanner
- Changed the `vendor/mcpvenom/pyproject.toml` repository URL to `dynatrace-research/mcpvenom` and added a second author

### Fixed
- Fixed `infra/start-litellm.sh` failing outside the original author's checkout; it now resolves the `litellm` binary and hook directory from the script location
