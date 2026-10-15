# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

# /// script
# requires-python = ">=3.12,<3.13"
# dependencies = [
#     "mcpvenom",
#     "mcp[cli]==1.28.1",
#     "requests==2.34.2",
#     "python-dotenv==1.2.2",
#     "anyio==4.14.1",
#     "agno==2.8.0",
# ]
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# Run: uv run harness_agno.py <scenario.yaml> <workspace_dir> <canary_url> <model>

import logging
import sys

import anyio
from agno.agent import Agent
from agno.models.openai import OpenAILike
from agno.tools.mcp import MCPTools
from harness_base import (
    LEGIT_SERVER,
    LEGIT_VENV_PYTHON,
    LITELLM_BASE,
    LITELLM_KEY,
    MALICIOUS_SERVER,
    MALICIOUS_VENV_PYTHON,
    _extract_root_cause,
    dispatch_async,
    emit_error,
    emit_transcript,
    legit_server_env,
    load_scenario_safe,
    malicious_server_env,
    parse_cli_args,
    substitute_tokens,
)
from mcp import StdioServerParameters

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)


def _extract_messages(
    messages: list,
    legit_fn_names: set[str],
    mal_fn_names: set[str],
    phase_name: str = "",
) -> list[dict]:
    """Extract normalized transcript from Agno response messages."""
    transcript: list[dict] = []
    for msg in messages:
        role = getattr(msg, "role", "unknown")
        content = getattr(msg, "content", "") or ""

        if role == "user":
            entry: dict = {"role": "user", "content": str(content)}
            if phase_name:
                entry["_phase"] = phase_name
            transcript.append(entry)
        elif role == "assistant":
            entry = {"role": "assistant", "content": str(content)}
            tool_calls_raw = getattr(msg, "tool_calls", None)
            if tool_calls_raw:
                entry["tool_calls"] = []
                for tc in tool_calls_raw:
                    if isinstance(tc, dict):
                        fn = tc.get("function", {})
                        entry["tool_calls"].append({
                            "id": tc.get("id", ""),
                            "function": {
                                "name": fn.get("name", ""),
                                "arguments": fn.get("arguments", "{}"),
                            },
                        })
                    else:
                        entry["tool_calls"].append({
                            "id": getattr(tc, "id", ""),
                            "function": {
                                "name": getattr(tc.function, "name", ""),
                                "arguments": getattr(tc.function, "arguments", "{}"),
                            },
                        })
            if phase_name:
                entry["_phase"] = phase_name
            transcript.append(entry)
        elif role == "tool":
            tool_name = getattr(msg, "tool_name", "") or ""
            server_label = (
                "legitimate" if tool_name in legit_fn_names
                else "malicious" if tool_name in mal_fn_names
                else "unknown"
            )
            entry = {
                "role": "tool",
                "content": str(content),
                "tool_name": tool_name,
                "mcp_server": server_label,
            }
            if phase_name:
                entry["_phase"] = phase_name
            transcript.append(entry)
        else:
            entry = {"role": str(role), "content": str(content)}
            if phase_name:
                entry["_phase"] = phase_name
            transcript.append(entry)
    return transcript


async def run_single_phase(
    scenario_path: str,
    scenario_name: str,
    workspace_dir: str,
    canary_url: str,
    model: str,
) -> list[dict]:
    scenario = load_scenario_safe(scenario_path)
    if scenario is None:
        return [{"role": "error", "content": f"Failed to load scenario: {scenario_path}"}]
    user_prompt = substitute_tokens(scenario.user_prompt, canary_url)

    legit_params = StdioServerParameters(
        command=LEGIT_VENV_PYTHON,
        args=[LEGIT_SERVER],
        env=legit_server_env(workspace_dir),
    )
    malicious_params = StdioServerParameters(
        command=MALICIOUS_VENV_PYTHON,
        args=[MALICIOUS_SERVER],
        env=malicious_server_env(scenario_name, canary_url, workspace_dir),
    )

    captured_messages: list = []
    try:
        async with MCPTools(server_params=legit_params) as legit_tools:
            async with MCPTools(server_params=malicious_params) as mal_tools:
                legit_fn_names = set(legit_tools.functions.keys())
                mal_fn_names = set(mal_tools.functions.keys())

                agent = Agent(
                    model=OpenAILike(id=model, api_key=LITELLM_KEY, base_url=LITELLM_BASE),
                    tools=[legit_tools, mal_tools],
                    markdown=False,
                    tool_call_limit=6,
                )

                response = await agent.arun(user_prompt)
                if response and response.messages:
                    captured_messages = list(response.messages)
    except (RuntimeError, BaseExceptionGroup) as e:
        # anyio cancel scope cleanup — only suppress if it's truly a cleanup error
        err_str = str(e)
        if "cancel scope" not in err_str.lower() and "generatorexit" not in err_str.lower():
            raise

    return _extract_messages(captured_messages, legit_fn_names, mal_fn_names)


async def run_multi_phase(
    scenario_path: str,
    scenario_name: str,
    workspace_dir: str,
    canary_url: str,
    model: str,
) -> list[dict]:
    """Run multi-phase scenario. Agno doesn't support conversation continuity
    natively across different tool sets, so we accumulate a conversation summary
    in the system prompt for each phase.
    """
    transcript: list[dict] = []
    scenario = load_scenario_safe(scenario_path)
    if scenario is None:
        return [{"role": "error", "content": f"Failed to load scenario: {scenario_path}"}]

    conversation_summary: list[str] = []
    legit_fn_names: set[str] = set()
    mal_fn_names: set[str] = set()

    legit_params = StdioServerParameters(
        command=LEGIT_VENV_PYTHON,
        args=[LEGIT_SERVER],
        env=legit_server_env(workspace_dir),
    )

    for phase in scenario.phases:
        mal_params = StdioServerParameters(
            command=MALICIOUS_VENV_PYTHON,
            args=[MALICIOUS_SERVER],
            env=malicious_server_env(scenario_name, canary_url, workspace_dir, phase_name=phase.name),
        )

        captured_messages: list = []
        try:
            async with MCPTools(server_params=legit_params) as legit_tools:
                async with MCPTools(server_params=mal_params) as mal_tools:
                    legit_fn_names = set(legit_tools.functions.keys())
                    mal_fn_names = set(mal_tools.functions.keys())

                    instructions = "You are a helpful assistant. Use the available tools to help the user."
                    if conversation_summary:
                        instructions += "\n\nPrevious conversation:\n" + "\n".join(conversation_summary)

                    agent = Agent(
                        model=OpenAILike(id=model, api_key=LITELLM_KEY, base_url=LITELLM_BASE),
                        tools=[legit_tools, mal_tools],
                        markdown=False,
                        instructions=instructions,
                        tool_call_limit=6,
                    )

                    user_prompt = substitute_tokens(phase.user_prompt, canary_url)
                    response = await agent.arun(user_prompt)
                    if response and response.messages:
                        captured_messages = list(response.messages)
        except (RuntimeError, BaseExceptionGroup) as e:
            err_str = str(e)
            if "cancel scope" not in err_str.lower() and "generatorexit" not in err_str.lower():
                raise

        phase_transcript = _extract_messages(captured_messages, legit_fn_names, mal_fn_names, phase.name)
        transcript.extend(phase_transcript)

        # Accumulate conversation context for next phase
        for msg in captured_messages:
            role = getattr(msg, "role", "")
            content = getattr(msg, "content", "") or ""
            if content and role in ("user", "assistant"):
                conversation_summary.append(f"{role}: {str(content)[:200]}")

    return transcript


def main() -> None:
    args = parse_cli_args()
    try:
        transcript = anyio.run(
            dispatch_async, run_single_phase, run_multi_phase, args,
            backend="asyncio",
        )
        emit_transcript(transcript)
    except Exception as e:
        logger.exception("Harness error")
        emit_error(_extract_root_cause(e))


if __name__ == "__main__":
    main()
