# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

import asyncio
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcpvenom.scanner import scan
from mcpvenom.scenarios import load_all_scenarios

from config import CANARY_URL

REPO = Path(__file__).resolve().parents[1]
CHECKS = ("instruction", "encoded", "length", "union")
SCENARIO_REGISTRY = REPO / "scenarios" / "README.md"
LEGIT_SERVER = REPO / "infra" / "mcp-legitimate" / "server.py"
# Public servers, pinned: (label, command, args, env)
BENIGN_SERVERS: list[tuple[str, str, list[str], dict[str, str]]] = [
    ("server-filesystem@2026.8.31", "npx", ["-y", "@modelcontextprotocol/server-filesystem@2026.8.31", "/tmp"], {}),
    ("server-memory@2026.8.31", "npx", ["-y", "@modelcontextprotocol/server-memory@2026.8.31"], {}),
    ("server-everything@2026.8.31", "npx", ["-y", "@modelcontextprotocol/server-everything@2026.8.31"], {}),
    (
        "server-sequential-thinking@2026.8.31",
        "npx",
        ["-y", "@modelcontextprotocol/server-sequential-thinking@2026.8.31"],
        {},
    ),
    ("playwright-mcp@0.0.80", "npx", ["-y", "@playwright/mcp@0.0.80"], {}),
    ("mcp-server-git@2026.8.18", "uvx", ["mcp-server-git==2026.8.18"], {}),
    ("mcp-server-fetch@2026.8.18", "uvx", ["mcp-server-fetch==2026.8.18"], {}),
    ("mcp-server-time@2026.8.18", "uvx", ["mcp-server-time==2026.8.18"], {}),
    (
        "github-mcp-server",
        "docker",
        ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
        {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_placeholder_for_tools_list_only"},
    ),
    ("legitimate-server", sys.executable, [str(LEGIT_SERVER)], {}),
]


def taxonomy_classes() -> dict[str, str]:
    rows = re.findall(r"^\|\s*\d+\s*\|\s*([\w-]+)\s*\|[^|]*\|\s*(P\d+)\s*\|", SCENARIO_REGISTRY.read_text(), re.M)
    return dict(rows)


async def list_tools(command: str, args: list[str], env: dict[str, str]) -> list[tuple[str, str]]:
    params = StdioServerParameters(command=command, args=args, env={**env, "PATH": os.environ["PATH"]})
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.list_tools()
        return [(t.name, t.description or "") for t in result.tools]


def poisoned_corpus() -> list[tuple[str, str, str, list[str]]]:
    classes = taxonomy_classes()
    rows = []
    for scenario in load_all_scenarios():
        groups = [scenario.tools] + [p.tools for p in scenario.phases]
        for tools in groups:
            names = [t.name for t in tools] + ["read_file", "write_file", "list_files", "http_get", "http_post"]
            for t in tools:
                description = t.description.replace("{canary_url}", CANARY_URL)
                rows.append((scenario.name, classes.get(scenario.name, "?"), description, names))
    return rows


def benign_corpus() -> tuple[list[tuple[str, str, str, list[str]]], list[str]]:
    rows, failures = [], []
    for label, cmd, args, env in BENIGN_SERVERS:
        try:
            tools = asyncio.run(asyncio.wait_for(list_tools(cmd, args, env), 180))
        except Exception as exc:  # noqa: BLE001 - one unreachable server must not abort the corpus
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            continue
        names = [n for n, _ in tools]
        rows.extend((label, "benign", d, names) for _, d in tools)
    return rows, failures


def rate(flagged: int, total: int) -> str:
    return f"{100 * flagged / total:.1f}\\% ({flagged}/{total})" if total else "n/a"


def main() -> None:
    poisoned = poisoned_corpus()
    benign, failures = benign_corpus()
    fired_p = [(cls, scan(d, names)) for _, cls, d, names in poisoned]
    fired_b = [scan(d, names) for _, _, d, names in benign]
    lines = [f"# Description scanner results {datetime.now(UTC).isoformat(timespec='seconds')}", ""]
    servers = len(BENIGN_SERVERS) - len(failures)
    lines += [
        f"Poisoned descriptions: {len(poisoned)} (45 scenarios). "
        f"Benign descriptions: {len(benign)} from {servers} servers.",
        "",
    ]
    lines += ["| Check | Detection (poisoned) | False positives (benign) |", "|---|---|---|"]
    for c in CHECKS:
        hit = (lambda f: bool(f)) if c == "union" else (lambda f, c=c: c in f)
        detected = rate(sum(hit(f) for _, f in fired_p), len(poisoned))
        false_positive = rate(sum(hit(f) for f in fired_b), len(benign))
        lines.append(f"| {c} | {detected} | {false_positive} |")
    by_scenario: dict[str, tuple[str, set[str]]] = {}
    for (name, cls, _, _), (_, f) in zip(poisoned, fired_p, strict=True):
        prev = by_scenario.get(name, (cls, set()))[1]
        by_scenario[name] = (cls, prev | f)
    lines += ["", "Per scenario (a server is rejected if any of its descriptions trips a check):", ""]
    lines += ["| Check | Scenarios flagged |", "|---|---|"]
    for c in CHECKS:
        n = sum(bool(f) if c == "union" else c in f for _, f in by_scenario.values())
        lines.append(f"| {c} | {rate(n, len(by_scenario))} |")
    per_class: dict[str, Counter[str]] = defaultdict(Counter)
    for cls, f in by_scenario.values():
        per_class[cls]["total"] += 1
        per_class[cls]["missed"] += not f
    lines += ["", "| Class | Scenarios | Missed by union |", "|---|---|---|"]
    ordered = sorted(per_class.items(), key=lambda kv: int(kv[0][1:]) if kv[0][1:].isdigit() else 99)
    lines += [f"| {cls} | {c['total']} | {c['missed']} |" for cls, c in ordered]
    lines += ["", "## Benign descriptions flagged", ""]
    flagged = zip(benign, fired_b, strict=True)
    lines += [f"- {label}: {json.dumps(d[:160])} -> {sorted(f)}" for (label, _, d, _), f in flagged if f]
    lines += ["", "## Poisoned descriptions missed", ""]
    missed = zip(poisoned, fired_p, strict=True)
    lines += [f"- {name} ({cls}): {json.dumps(d[:160])}" for (name, cls, d, _), (_, f) in missed if not f]
    lines += ["", "## Servers that failed to list tools", ""] + [f"- {f}" for f in failures]
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = REPO / "experiments" / "description-scanner" / "results" / f"scan-{stamp}.md"
    out.write_text("\n".join(lines) + "\n")
    print(out)
    print("\n".join(lines[:12]))


if __name__ == "__main__":
    main()
