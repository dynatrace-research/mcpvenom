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
#     "pydantic-ai==2.14.1",
# ]
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# PydanticAI harness — Agent with MCPServerStdio.
# Supports single-phase and multi-phase scenarios.
# Run: uv run harness_pydantic_ai.py <scenario.yaml> <workspace_dir> <canary_url> <model>

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
from pydantic_ai import Agent
from pydantic_ai.mcp import MCPToolset, StdioTransport
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIResponsesModel
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.usage import UsageLimits

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

_RESPONSES_API_MODEL = "gpt-5-5"


def _make_model(model: str) -> OpenAIChatModel | OpenAIResponsesModel:
    provider = OpenAIProvider(base_url=LITELLM_BASE, api_key=LITELLM_KEY)
    if model == _RESPONSES_API_MODEL:
        return OpenAIResponsesModel(model, provider=provider)
    return OpenAIChatModel(model, provider=provider)


async def _discover_tool_names(toolset: MCPToolset) -> set[str]:
    """Discover tool names from an MCP server via its MCPToolset."""
    tools = await toolset.list_tools()
    return {t.name for t in tools}


def _extract_transcript(
    all_messages: list,
    legit_tool_names: set[str],
    phase_name: str = "",
) -> list[dict]:
    """Extract normalized transcript from PydanticAI result messages."""
    transcript: list[dict] = []
    for msg in all_messages:
        msg_type = msg.__class__.__name__

        if msg_type == "ModelRequest":
            for part in msg.parts:
                part_type = part.__class__.__name__
                if part_type == "UserPromptPart":
                    entry: dict = {"role": "user", "content": str(part.content)}
                    if phase_name:
                        entry["_phase"] = phase_name
                    transcript.append(entry)
                elif part_type == "ToolReturnPart":
                    tool_name = part.tool_name or ""
                    server_label = "legitimate" if tool_name in legit_tool_names else "malicious"
                    entry = {
                        "role": "tool",
                        "content": str(part.content),
                        "tool_name": tool_name,
                        "mcp_server": server_label,
                    }
                    if phase_name:
                        entry["_phase"] = phase_name
                    transcript.append(entry)

        elif msg_type == "ModelResponse":
            for part in msg.parts:
                part_type = part.__class__.__name__
                if part_type == "TextPart":
                    entry = {"role": "assistant", "content": part.content}
                    if phase_name:
                        entry["_phase"] = phase_name
                    transcript.append(entry)
                elif part_type == "ToolCallPart":
                    args_str = (
                        json.dumps(part.args)
                        if isinstance(part.args, dict)
                        else str(part.args)
                    )
                    entry = {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [{
                            "id": part.tool_call_id or "",
                            "function": {
                                "name": part.tool_name,
                                "arguments": args_str,
                            },
                        }],
                    }
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

    legit_toolset = MCPToolset(
        StdioTransport(LEGIT_VENV_PYTHON, [LEGIT_SERVER], env=legit_server_env(workspace_dir))
    )
    mal_toolset = MCPToolset(
        StdioTransport(
            MALICIOUS_VENV_PYTHON,
            [MALICIOUS_SERVER],
            env=malicious_server_env(scenario_name, canary_url, workspace_dir),
        )
    )

    legit_tool_names = await _discover_tool_names(legit_toolset)

    openai_model = _make_model(model)

    agent = Agent(openai_model, toolsets=[legit_toolset, mal_toolset])

    async with agent:
        result = await agent.run(user_prompt, usage_limits=UsageLimits(request_limit=150))
        return _extract_transcript(result.all_messages(), legit_tool_names)


async def run_multi_phase(
    scenario_path: str,
    scenario_name: str,
    workspace_dir: str,
    canary_url: str,
    model: str,
) -> list[dict]:
    """Run multi-phase scenario. PydanticAI doesn't support swapping MCP servers
    mid-conversation, so we create a new agent per phase and pass conversation
    history via message_history.
    """
    transcript: list[dict] = []
    scenario = load_scenario_safe(scenario_path)
    if scenario is None:
        return [{"role": "error", "content": f"Failed to load scenario: {scenario_path}"}]

    openai_model = _make_model(model)

    # Discover legitimate tool names once (list_tools connects temporarily, then closes)
    _probe = MCPToolset(
        StdioTransport(LEGIT_VENV_PYTHON, [LEGIT_SERVER], env=legit_server_env(workspace_dir))
    )
    legit_tool_names = await _discover_tool_names(_probe)

    accumulated_messages: list = []

    for phase in scenario.phases:
        legit_toolset = MCPToolset(
            StdioTransport(LEGIT_VENV_PYTHON, [LEGIT_SERVER], env=legit_server_env(workspace_dir))
        )
        mal_toolset = MCPToolset(
            StdioTransport(
                MALICIOUS_VENV_PYTHON,
                [MALICIOUS_SERVER],
                env=malicious_server_env(scenario_name, canary_url, workspace_dir, phase_name=phase.name),
            )
        )

        agent = Agent(openai_model, toolsets=[legit_toolset, mal_toolset])
        user_prompt = substitute_tokens(phase.user_prompt, canary_url)

        async with agent:
            result = await agent.run(
                user_prompt,
                message_history=accumulated_messages if accumulated_messages else None,
                usage_limits=UsageLimits(request_limit=150),
            )
            all_msgs = result.all_messages()

            # Extract only messages from this phase (skip those in accumulated_messages)
            new_msgs = all_msgs[len(accumulated_messages):]
            phase_transcript = _extract_transcript(new_msgs, legit_tool_names, phase.name)
            transcript.extend(phase_transcript)

            # Carry forward all messages
            accumulated_messages = list(all_msgs)

    return transcript


def main() -> None:
    run_async_harness(run_single_phase, run_multi_phase)


if __name__ == "__main__":
    main()
