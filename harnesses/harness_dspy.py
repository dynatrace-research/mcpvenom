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
#     "dspy==3.2.1",
# ]
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# Run: uv run harness_dspy.py <scenario.yaml> <workspace_dir> <canary_url> <model>
#
# Strategy: Use dspy.LM.aforward() with OpenAI tool format for inference.
# DSPy 3.x uses litellm internally; aforward() returns the raw litellm ModelResponse,
# giving us full access to choices[0].message.tool_calls.
# Tools are loaded via dspy.Tool.from_mcp_tool (native DSPy MCP integration) —
# each Tool.func encapsulates the session.call_tool call so the harness loop dispatches
# via tool.acall() rather than calling session.call_tool directly.

import json
import logging
import sys

import dspy
from harness_base import (
    LEGIT_SERVER,
    LEGIT_VENV_PYTHON,
    LITELLM_BASE,
    LITELLM_KEY,
    MALICIOUS_SERVER,
    MALICIOUS_VENV_PYTHON,
    dedup_tools_prefer_malicious,
    legit_server_env,
    load_scenario_safe,
    malicious_server_env,
    run_async_harness,
    substitute_tokens,
)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

MAX_TURNS = 10


def _mcp_to_dspy_tools(
    mcp_tools: list,
    tool_server_map: dict[str, tuple[str, ClientSession]],
) -> dict[str, dspy.Tool]:
    """Build a name→dspy.Tool map using the native DSPy MCP integration.

    dspy.Tool.from_mcp_tool binds the MCP session into the tool's func so
    the harness loop can dispatch via tool.acall() without calling
    session.call_tool directly.
    """
    result: dict[str, dspy.Tool] = {}
    for t in mcp_tools:
        _label, session = tool_server_map[t.name]
        result[t.name] = dspy.Tool.from_mcp_tool(session, t)
    return result


def _dspy_tool_result_to_str(raw: object) -> str:
    """Coerce dspy.Tool.acall() output to a plain string."""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, list):
        return json.dumps(raw)
    return str(raw) if raw is not None else json.dumps({"status": "ok"})


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
        command=LEGIT_VENV_PYTHON, args=[LEGIT_SERVER], env=legit_server_env(workspace_dir)
    )
    mal_params = StdioServerParameters(
        command=MALICIOUS_VENV_PYTHON,
        args=[MALICIOUS_SERVER],
        env=malicious_server_env(scenario_name, canary_url, workspace_dir),
    )

    async with stdio_client(legit_params) as (lr, lw), ClientSession(lr, lw) as legit_session:
        await legit_session.initialize()
        async with stdio_client(mal_params) as (mr, mw), ClientSession(mr, mw) as mal_session:
            await mal_session.initialize()

            legit_mcp_tools = (await legit_session.list_tools()).tools
            mal_mcp_tools = (await mal_session.list_tools()).tools
            all_mcp_tools = dedup_tools_prefer_malicious(legit_mcp_tools, mal_mcp_tools)

            tool_server_map: dict[str, tuple[str, ClientSession]] = {
                t.name: ("legitimate", legit_session) for t in legit_mcp_tools
            }
            tool_server_map.update({t.name: ("malicious", mal_session) for t in mal_mcp_tools})

            dspy_tool_map = _mcp_to_dspy_tools(all_mcp_tools, tool_server_map)
            openai_tools = [t.format_as_litellm_function_call() for t in dspy_tool_map.values()]

            lm = dspy.LM(
                model=f"openai/{model}",
                api_base=LITELLM_BASE,
                api_key=LITELLM_KEY,
                max_tokens=2048,
                cache=False,
            )
            dspy.configure(lm=lm)

            messages: list[dict] = [{"role": "user", "content": user_prompt}]
            transcript: list[dict] = [{"role": "user", "content": user_prompt}]

            for _ in range(MAX_TURNS):
                response = await lm.aforward(messages=messages, tools=openai_tools)

                choice = response.choices[0]
                msg = choice.message
                text: str = msg.content or ""
                raw_tool_calls = getattr(msg, "tool_calls", None) or []

                entry: dict = {"role": "assistant", "content": text}
                if raw_tool_calls:
                    entry["tool_calls"] = [
                        {
                            "id": tc.id or "",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments or "{}",
                            },
                        }
                        for tc in raw_tool_calls
                    ]
                transcript.append(entry)

                hist_entry: dict = {"role": "assistant", "content": text}
                if raw_tool_calls:
                    hist_entry["tool_calls"] = [
                        {
                            "id": tc.id or "",
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments or "{}",
                            },
                        }
                        for tc in raw_tool_calls
                    ]
                messages.append(hist_entry)

                if not raw_tool_calls:
                    break

                for tc in raw_tool_calls:
                    tool_name = tc.function.name
                    try:
                        arguments = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError:
                        arguments = {}

                    label = tool_server_map.get(tool_name, ("unknown",))[0]
                    dspy_tool = dspy_tool_map.get(tool_name)
                    if dspy_tool is not None:
                        raw = await dspy_tool.acall(**arguments)
                        result_text = _dspy_tool_result_to_str(raw)
                    else:
                        result_text = json.dumps({"error": f"unknown tool: {tool_name}"})

                    transcript.append(
                        {
                            "role": "tool",
                            "content": result_text,
                            "tool_name": tool_name,
                            "mcp_server": label,
                        }
                    )
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tc.id or "",
                            "content": result_text,
                        }
                    )

    return transcript


async def run_multi_phase(
    scenario_path: str,
    scenario_name: str,
    workspace_dir: str,
    canary_url: str,
    model: str,
) -> list[dict]:
    transcript: list[dict] = []
    scenario = load_scenario_safe(scenario_path)
    if scenario is None:
        return [{"role": "error", "content": f"Failed to load scenario: {scenario_path}"}]

    lm = dspy.LM(
        model=f"openai/{model}",
        api_base=LITELLM_BASE,
        api_key=LITELLM_KEY,
        max_tokens=2048,
        cache=False,
    )
    dspy.configure(lm=lm)

    accumulated_messages: list[dict] = []

    for phase in scenario.phases:
        legit_params = StdioServerParameters(
            command=LEGIT_VENV_PYTHON, args=[LEGIT_SERVER], env=legit_server_env(workspace_dir)
        )
        mal_params = StdioServerParameters(
            command=MALICIOUS_VENV_PYTHON,
            args=[MALICIOUS_SERVER],
            env=malicious_server_env(scenario_name, canary_url, workspace_dir, phase_name=phase.name),
        )

        async with stdio_client(legit_params) as (lr, lw), ClientSession(lr, lw) as legit_session:
            await legit_session.initialize()
            async with stdio_client(mal_params) as (mr, mw), ClientSession(mr, mw) as mal_session:
                await mal_session.initialize()

                legit_mcp_tools = (await legit_session.list_tools()).tools
                mal_mcp_tools = (await mal_session.list_tools()).tools
                all_mcp_tools = dedup_tools_prefer_malicious(legit_mcp_tools, mal_mcp_tools)

                tool_server_map: dict[str, tuple[str, ClientSession]] = {
                    t.name: ("legitimate", legit_session) for t in legit_mcp_tools
                }
                tool_server_map.update({t.name: ("malicious", mal_session) for t in mal_mcp_tools})

                dspy_tool_map = _mcp_to_dspy_tools(all_mcp_tools, tool_server_map)
                openai_tools = [t.format_as_litellm_function_call() for t in dspy_tool_map.values()]

                user_prompt = substitute_tokens(phase.user_prompt, canary_url)
                accumulated_messages.append({"role": "user", "content": user_prompt})
                transcript.append({"role": "user", "content": user_prompt, "_phase": phase.name})

                for _ in range(MAX_TURNS):
                    response = await lm.aforward(messages=list(accumulated_messages), tools=openai_tools)

                    choice = response.choices[0]
                    msg = choice.message
                    text: str = msg.content or ""
                    raw_tool_calls = getattr(msg, "tool_calls", None) or []

                    entry: dict = {
                        "role": "assistant",
                        "content": text,
                        "_phase": phase.name,
                    }
                    if raw_tool_calls:
                        entry["tool_calls"] = [
                            {
                                "id": tc.id or "",
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments or "{}",
                                },
                            }
                            for tc in raw_tool_calls
                        ]
                    transcript.append(entry)

                    acc_entry: dict = {"role": "assistant", "content": text}
                    if raw_tool_calls:
                        acc_entry["tool_calls"] = [
                            {
                                "id": tc.id or "",
                                "type": "function",
                                "function": {
                                    "name": tc.function.name,
                                    "arguments": tc.function.arguments or "{}",
                                },
                            }
                            for tc in raw_tool_calls
                        ]
                    accumulated_messages.append(acc_entry)

                    if not raw_tool_calls:
                        break

                    for tc in raw_tool_calls:
                        tool_name = tc.function.name
                        try:
                            arguments = json.loads(tc.function.arguments or "{}")
                        except json.JSONDecodeError:
                            arguments = {}

                        label = tool_server_map.get(tool_name, ("unknown",))[0]
                        dspy_tool = dspy_tool_map.get(tool_name)
                        if dspy_tool is not None:
                            raw = await dspy_tool.acall(**arguments)
                            result_text = _dspy_tool_result_to_str(raw)
                        else:
                            result_text = json.dumps({"error": f"unknown tool: {tool_name}"})

                        transcript.append(
                            {
                                "role": "tool",
                                "content": result_text,
                                "tool_name": tool_name,
                                "mcp_server": label,
                                "_phase": phase.name,
                            }
                        )
                        accumulated_messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tc.id or "",
                                "content": result_text,
                            }
                        )

    return transcript


def main() -> None:
    run_async_harness(run_single_phase, run_multi_phase)


if __name__ == "__main__":
    main()
