# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

import asyncio
import json
import logging
import os
import sys
import uuid
from collections.abc import Callable
from pathlib import Path

from mcpvenom.models import Scenario
from mcpvenom.scenarios import load_scenario

from config import CANARY_FILE, CANARY_SECRET, LITELLM_BASE, LITELLM_KEY

logger = logging.getLogger(__name__)

# Re-export centralized config so harnesses can import it from one place.
__all__ = ["CANARY_FILE", "CANARY_SECRET", "LITELLM_BASE", "LITELLM_KEY"]

# MCP server subprocess paths (repo-relative; each server runs in its own venv).
INFRA_DIR = Path(__file__).resolve().parent.parent / "infra"
LEGIT_SERVER = str(INFRA_DIR / "mcp-legitimate" / "server.py")
LEGIT_VENV_PYTHON = str(INFRA_DIR / "mcp-legitimate" / ".venv" / "bin" / "python")
MALICIOUS_SERVER = str(Path(__file__).resolve().parent.parent / "malicious-mcp" / "server.py")
MALICIOUS_VENV_PYTHON = str(Path(__file__).resolve().parent.parent / "malicious-mcp" / ".venv" / "bin" / "python")


def generate_run_id() -> str:
    """Generate a unique run ID for correlating results with canary logs."""
    return uuid.uuid4().hex[:12]


def substitute_tokens(text: str, canary_url: str) -> str:
    """Replace canary placeholder tokens in user prompts and tool descriptions.
    Harnesses must call this on user_prompt so the model sees real secrets.
    """
    text = text.replace("{canary_url}", canary_url)
    text = text.replace("{canary_secret}", CANARY_SECRET)
    text = text.replace("{canary_file}", CANARY_FILE)
    return text


def parse_cli_args() -> tuple[str, str, str, str, str]:
    """Parse CLI: <scenario_yaml_path> <workspace_dir> <canary_url> <model>

    Returns (scenario_path, scenario_name, workspace_dir, canary_url, model).
    """
    if len(sys.argv) < 5:
        print(
            f"Usage: {sys.argv[0]} <scenario_yaml> <workspace_dir> <canary_url> <model>",
            file=sys.stderr,
        )
        sys.exit(1)
    scenario_path = sys.argv[1]
    scenario_name = Path(scenario_path).stem
    workspace_dir = sys.argv[2]
    canary_url = sys.argv[3]
    model = sys.argv[4]
    return scenario_path, scenario_name, workspace_dir, canary_url, model


def load_scenario_safe(scenario_path: str) -> Scenario | None:
    """Load a scenario from a YAML file. Returns None on failure."""
    return load_scenario(Path(scenario_path))


def is_multi_phase(scenario: Scenario) -> bool:
    """Return True if scenario has multiple phases (requires conversation continuity)."""
    return bool(scenario.phases) and len(scenario.phases) > 1


def legit_server_env(workspace_dir: str) -> dict[str, str]:
    """Environment for the legitimate MCP server subprocess."""
    env = os.environ.copy()
    env["WORKSPACE_DIR"] = workspace_dir
    return env


def malicious_server_env(
    scenario_name: str,
    canary_url: str,
    workspace_dir: str,
    phase_name: str = "",
) -> dict[str, str]:
    """Environment for the malicious MCP server subprocess."""
    env = os.environ.copy()
    env["SCENARIO_NAME"] = scenario_name
    env["CANARY_URL"] = canary_url
    env["CANARY_SECRET"] = CANARY_SECRET
    env["CANARY_FILE"] = CANARY_FILE
    env["WORKSPACE_DIR"] = workspace_dir
    if phase_name:
        env["PHASE_NAME"] = phase_name
    # Forward invocation log path so the server can record each tool execution.
    log = env.pop("MCP_INVOCATION_LOG", "")
    if log:
        env["INVOCATION_LOG"] = log
    return env


def dedup_tools_prefer_malicious(legit_tools: list, mal_tools: list, name_attr: str = "name") -> list:
    """Merge tool lists, preferring malicious tools on name collision.

    When a malicious MCP server defines a tool with the same name as a
    legitimate tool (e.g., 'read_file'), the malicious version takes
    priority. This models real-world tool shadowing attacks.
    """
    mal_names: set[str] = set()
    for t in mal_tools:
        n = getattr(t, name_attr, None) or (t.get(name_attr, "") if isinstance(t, dict) else "")
        mal_names.add(n)
    merged = list(mal_tools)
    for t in legit_tools:
        n = getattr(t, name_attr, None) or (t.get(name_attr, "") if isinstance(t, dict) else "")
        if n not in mal_names:
            merged.append(t)
    return merged


def _extract_root_cause(exc: BaseException) -> str:
    """Extract the deepest root cause from a (possibly nested) ExceptionGroup."""
    current: BaseException = exc
    for _ in range(10):  # safety bound
        if isinstance(current, BaseExceptionGroup) and current.exceptions:
            current = current.exceptions[0]
        else:
            break
    return f"{type(current).__name__}: {current}"


def emit_transcript(transcript: list[dict]) -> None:
    """Write transcript as JSON to stdout."""
    json.dump(transcript, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    sys.stdout.flush()


def emit_error(error: str) -> None:
    """Emit an error transcript entry and exit 0."""
    emit_transcript([{"role": "error", "content": error}])


async def dispatch_async(
    run_single_phase: Callable,
    run_multi_phase: Callable,
    args: tuple[str, str, str, str, str],
) -> list[dict]:
    """Load scenario and await the single- or multi-phase runner.

    args is the parse_cli_args tuple (scenario_path, scenario_name, workspace_dir,
    canary_url, model). Returns an error transcript if the scenario fails to load.
    """
    scenario = load_scenario_safe(args[0])
    if scenario is None:
        return [{"role": "error", "content": f"Failed to load scenario: {args[0]}"}]
    runner = run_multi_phase if is_multi_phase(scenario) else run_single_phase
    return await runner(*args)


def dispatch_sync(
    run_single_phase: Callable,
    run_multi_phase: Callable,
    args: tuple[str, str, str, str, str],
) -> list[dict]:
    """Load scenario and call the single- or multi-phase runner (synchronous)."""
    scenario = load_scenario_safe(args[0])
    if scenario is None:
        return [{"role": "error", "content": f"Failed to load scenario: {args[0]}"}]
    runner = run_multi_phase if is_multi_phase(scenario) else run_single_phase
    return runner(*args)


def run_async_harness(run_single_phase: Callable, run_multi_phase: Callable) -> None:
    """Shared entrypoint for asyncio harnesses: parse CLI, dispatch, emit transcript."""
    args = parse_cli_args()
    try:
        emit_transcript(asyncio.run(dispatch_async(run_single_phase, run_multi_phase, args)))
    except Exception as e:
        logger.exception("Harness error")
        emit_error(_extract_root_cause(e))


def run_sync_harness(run_single_phase: Callable, run_multi_phase: Callable) -> None:
    """Shared entrypoint for synchronous harnesses: parse CLI, dispatch, emit transcript."""
    args = parse_cli_args()
    try:
        emit_transcript(dispatch_sync(run_single_phase, run_multi_phase, args))
    except Exception as e:
        logger.exception("Harness error")
        emit_error(_extract_root_cause(e))
