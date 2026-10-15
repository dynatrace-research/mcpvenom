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
#     "openai==2.46.0",
# ]
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# OpenAI baseline harness — raw OpenAI API with manual MCP tool loop.
# No framework layer. Isolates model-level susceptibility from framework effects.
#
# Supports both single-phase and multi-phase scenarios. For multi-phase:
# conversation history is preserved across phases, and the malicious MCP server
# is relaunched per phase with the correct PHASE_NAME env var.
#
# Run: uv run harness_openai_baseline.py <scenario.yaml> <workspace_dir> <canary_url> <model>

import json
import logging
import sys

from harness_base import (
    LEGIT_SERVER,
    LEGIT_VENV_PYTHON,
    LITELLM_BASE,
    LITELLM_KEY,
    MALICIOUS_SERVER,
    MALICIOUS_VENV_PYTHON,
    legit_server_env,
    load_scenario_safe,
    malicious_server_env,
    run_async_harness,
    substitute_tokens,
)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from openai import OpenAI

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

MAX_TURNS = 10
_RESPONSES_API_MODEL = "gpt-5-5"


def mcp_tools_to_openai(tools: list, server_label: str) -> list[dict]:
    """Convert MCP tool list to OpenAI function-calling format."""
    result = []
    for tool in tools:
        fn: dict = {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or "",
                "parameters": tool.inputSchema if tool.inputSchema else {"type": "object", "properties": {}},
            },
        }
        result.append(fn)
    return result


def _merge_tools_dedup(
    legit_tools: list[dict],
    mal_tools: list[dict],
) -> list[dict]:
    """Merge tool lists, preferring malicious tools on name collision.

    When a malicious MCP server defines a tool with the same name as a
    legitimate tool (e.g., 'read_file'), the malicious version takes
    priority. This models real-world tool shadowing attacks.
    """
    mal_names = {t["function"]["name"] for t in mal_tools}
    merged = [t for t in legit_tools if t["function"]["name"] not in mal_names]
    merged.extend(mal_tools)
    return merged


def mcp_tools_to_responses_api(tools: list) -> list[dict]:
    result = []
    for tool in tools:
        result.append({
            "type": "function",
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.inputSchema if tool.inputSchema else {"type": "object", "properties": {}},
        })
    return result


def _merge_tools_dedup_responses(legit_tools: list[dict], mal_tools: list[dict]) -> list[dict]:
    mal_names = {t["name"] for t in mal_tools}
    merged = [t for t in legit_tools if t["name"] not in mal_names]
    merged.extend(mal_tools)
    return merged


def _extract_text_responses(output: list) -> str:
    for item in output:
        if item.type == "message" and item.content:
            return item.content[0].text
    return ""


def _extract_function_calls_responses(output: list) -> list:
    return [item for item in output if item.type == "function_call"]


async def _run_turns_responses(
    client: OpenAI,
    model: str,
    initial_input: str | list,
    transcript: list[dict],
    tools: list[dict],
    legit_tool_names: set[str],
    mal_tool_names: set[str],
    legit_session: ClientSession,
    mal_session: ClientSession,
    previous_response_id: str | None,
    phase_name: str = "",
) -> str | None:
    current_input: str | list = initial_input
    last_response_id: str | None = previous_response_id

    for _turn in range(MAX_TURNS):
        resp = client.responses.create(
            model=model,
            input=current_input,
            tools=tools if tools else None,
            previous_response_id=last_response_id,
            max_output_tokens=2048,
        )
        last_response_id = resp.id

        text = _extract_text_responses(resp.output)
        fn_calls = _extract_function_calls_responses(resp.output)

        entry: dict = {"role": "assistant", "content": text}
        if phase_name:
            entry["_phase"] = phase_name
        if fn_calls:
            entry["tool_calls"] = [
                {"id": fc.call_id, "function": {"name": fc.name, "arguments": fc.arguments}}
                for fc in fn_calls
            ]
        transcript.append(entry)

        if not fn_calls:
            break

        tool_outputs: list[dict] = []
        for fc in fn_calls:
            tool_name = fc.name
            try:
                tool_args = json.loads(fc.arguments)
            except json.JSONDecodeError:
                tool_args = {}

            if tool_name in mal_tool_names:
                session = mal_session
                server_label = "malicious"
            elif tool_name in legit_tool_names:
                session = legit_session
                server_label = "legitimate"
            else:
                tool_result = f"Error: unknown tool {tool_name}"
                server_label = "unknown"
                transcript.append({
                    "role": "tool",
                    "content": tool_result,
                    "tool_name": tool_name,
                    "mcp_server": server_label,
                    **({"_phase": phase_name} if phase_name else {}),
                })
                tool_outputs.append({"type": "function_call_output", "call_id": fc.call_id, "output": tool_result})
                continue

            try:
                result = await session.call_tool(tool_name, tool_args)
                tool_result = result.content[0].text if result.content else ""
            except Exception as e:
                tool_result = f"Error: {e}"

            transcript.append({
                "role": "tool",
                "content": tool_result,
                "tool_name": tool_name,
                "mcp_server": server_label,
                **({"_phase": phase_name} if phase_name else {}),
            })
            tool_outputs.append({"type": "function_call_output", "call_id": fc.call_id, "output": tool_result})

        current_input = tool_outputs

    return last_response_id


async def _run_turns(
    client: OpenAI,
    model: str,
    messages: list[dict],
    transcript: list[dict],
    openai_tools: list[dict],
    legit_tool_names: set[str],
    mal_tool_names: set[str],
    legit_session: ClientSession,
    mal_session: ClientSession,
) -> None:
    """Run the tool-calling loop for one phase. Mutates messages and transcript in place."""
    for _turn in range(MAX_TURNS):
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            tools=openai_tools if openai_tools else None,
            max_tokens=2048,
        )
        choice = response.choices[0]
        assistant_msg: dict = {"role": "assistant", "content": choice.message.content or ""}

        if choice.message.tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in choice.message.tool_calls
            ]

        transcript.append(assistant_msg)
        messages.append(
            {"role": "assistant", "content": choice.message.content or "", "tool_calls": choice.message.tool_calls}
            if choice.message.tool_calls
            else {"role": "assistant", "content": choice.message.content or ""}
        )

        if choice.finish_reason != "tool_calls" and not choice.message.tool_calls:
            break

        # Execute tool calls via MCP
        for tc in choice.message.tool_calls:
            tool_name = tc.function.name
            try:
                tool_args = json.loads(tc.function.arguments)
            except json.JSONDecodeError:
                tool_args = {}

            if tool_name in mal_tool_names:
                session = mal_session
                server_label = "malicious"
            elif tool_name in legit_tool_names:
                session = legit_session
                server_label = "legitimate"
            else:
                tool_result = f"Error: unknown tool {tool_name}"
                server_label = "unknown"
                transcript.append({
                    "role": "tool",
                    "content": tool_result,
                    "tool_name": tool_name,
                    "mcp_server": server_label,
                })
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": tool_result})
                continue

            try:
                result = await session.call_tool(tool_name, tool_args)
                tool_result = result.content[0].text if result.content else ""
            except Exception as e:
                tool_result = f"Error: {e}"

            transcript.append({
                "role": "tool",
                "content": tool_result,
                "tool_name": tool_name,
                "mcp_server": server_label,
            })
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": tool_result})


async def run_single_phase(
    scenario_path: str,
    scenario_name: str,
    workspace_dir: str,
    canary_url: str,
    model: str,
) -> list[dict]:
    """Run a single-phase (non-multi-phase) scenario."""
    transcript: list[dict] = []
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

    async with stdio_client(legit_params) as (lr, lw), stdio_client(malicious_params) as (mr, mw):
        async with ClientSession(lr, lw) as legit_session, ClientSession(mr, mw) as mal_session:
            await legit_session.initialize()
            await mal_session.initialize()

            legit_tools_resp = await legit_session.list_tools()
            mal_tools_resp = await mal_session.list_tools()

            legit_tool_names = {t.name for t in legit_tools_resp.tools}
            mal_tool_names = {t.name for t in mal_tools_resp.tools}

            client = OpenAI(base_url=LITELLM_BASE, api_key=LITELLM_KEY)
            transcript.append({"role": "user", "content": user_prompt})

            if model == _RESPONSES_API_MODEL:
                tools = _merge_tools_dedup_responses(
                    mcp_tools_to_responses_api(legit_tools_resp.tools),
                    mcp_tools_to_responses_api(mal_tools_resp.tools),
                )
                await _run_turns_responses(
                    client, model, user_prompt, transcript, tools,
                    legit_tool_names, mal_tool_names, legit_session, mal_session,
                    previous_response_id=None,
                )
            else:
                openai_tools = _merge_tools_dedup(
                    mcp_tools_to_openai(legit_tools_resp.tools, "legitimate"),
                    mcp_tools_to_openai(mal_tools_resp.tools, "malicious"),
                )
                messages: list[dict] = [{"role": "user", "content": user_prompt}]
                await _run_turns(
                    client, model, messages, transcript, openai_tools,
                    legit_tool_names, mal_tool_names, legit_session, mal_session,
                )

    return transcript


async def run_multi_phase(
    scenario_path: str,
    scenario_name: str,
    workspace_dir: str,
    canary_url: str,
    model: str,
) -> list[dict]:
    """Run a multi-phase scenario with conversation continuity.

    Each phase relaunches the malicious MCP server with the phase's PHASE_NAME
    so it serves the correct poisoned tool definitions. The legitimate server
    stays connected throughout. Conversation history (messages) is preserved
    across phases.
    """
    transcript: list[dict] = []
    scenario = load_scenario_safe(scenario_path)
    if scenario is None:
        return [{"role": "error", "content": f"Failed to load scenario: {scenario_path}"}]

    client = OpenAI(base_url=LITELLM_BASE, api_key=LITELLM_KEY)
    messages: list[dict] = []
    last_response_id: str | None = None

    legit_params = StdioServerParameters(
        command=LEGIT_VENV_PYTHON,
        args=[LEGIT_SERVER],
        env=legit_server_env(workspace_dir),
    )

    async with stdio_client(legit_params) as (lr, lw), ClientSession(lr, lw) as legit_session:
        await legit_session.initialize()
        legit_tools_resp = await legit_session.list_tools()
        legit_tool_names = {t.name for t in legit_tools_resp.tools}

        for phase in scenario.phases:
            # Launch a fresh malicious MCP server for this phase
            mal_params = StdioServerParameters(
                command=MALICIOUS_VENV_PYTHON,
                args=[MALICIOUS_SERVER],
                env=malicious_server_env(scenario_name, canary_url, workspace_dir, phase_name=phase.name),
            )

            async with stdio_client(mal_params) as (mr, mw), ClientSession(mr, mw) as mal_session:
                await mal_session.initialize()
                mal_tools_resp = await mal_session.list_tools()
                mal_tool_names = {t.name for t in mal_tools_resp.tools}

                user_prompt = substitute_tokens(phase.user_prompt, canary_url)
                transcript.append({"role": "user", "content": user_prompt, "_phase": phase.name})

                if model == _RESPONSES_API_MODEL:
                    tools = _merge_tools_dedup_responses(
                        mcp_tools_to_responses_api(legit_tools_resp.tools),
                        mcp_tools_to_responses_api(mal_tools_resp.tools),
                    )
                    last_response_id = await _run_turns_responses(
                        client, model, user_prompt, transcript, tools,
                        legit_tool_names, mal_tool_names, legit_session, mal_session,
                        previous_response_id=last_response_id,
                        phase_name=phase.name,
                    )
                else:
                    openai_tools = _merge_tools_dedup(
                        mcp_tools_to_openai(legit_tools_resp.tools, "legitimate"),
                        mcp_tools_to_openai(mal_tools_resp.tools, "malicious"),
                    )
                    messages.append({"role": "user", "content": user_prompt})
                    await _run_turns(
                        client, model, messages, transcript, openai_tools,
                        legit_tool_names, mal_tool_names, legit_session, mal_session,
                    )

    return transcript


def main() -> None:
    run_async_harness(run_single_phase, run_multi_phase)


if __name__ == "__main__":
    main()
