# Security Policy

## Scope

mcpvenom is offensive security research tooling. It **intentionally** ships malicious MCP tool
definitions and a malicious MCP server that exfiltrate a planted secret to a canary endpoint. Those
payloads are the subject of study, not vulnerabilities — please do not report them as security
issues.

A reportable issue is a flaw in mcpvenom **itself**: for example, a way the harness, scanner, or
canary server can be made to leak real data, execute unintended code from untrusted input, or affect
a system beyond the local canary it is pointed at.

## Reporting

Report a suspected vulnerability privately through GitHub Security Advisories:
**Security → Report a vulnerability** on this repository. Do not open a public issue for a security
report.

Please include the affected file or component, the version or commit, and the minimal steps to
reproduce. We aim to acknowledge a report within a few business days.

## Safe use

Run mcpvenom only against the bundled canary server in an isolated environment. Never register the
malicious MCP server in a real agent configuration, and never point a run at production, public, or
third-party systems. See the Disclaimer in [README.md](README.md).
