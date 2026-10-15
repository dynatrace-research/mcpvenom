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
#     "haystack-ai==3.0.0",
#     "mcp-haystack==1.4.0",
# ]
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# Run: uv run harness_haystack.py <scenario.yaml> <workspace_dir> <canary_url> <model>

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
from haystack.components.agents import Agent
from haystack.components.generators.chat import OpenAIChatGenerator, OpenAIResponsesChatGenerator
from haystack.dataclasses import ChatMessage, ChatRole
from haystack.tools import Tool
from haystack.utils import Secret
from haystack_integrations.tools.mcp import MCPToolset, StdioServerInfo

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

MAX_TURNS = 10
_RESPONSES_API_MODEL = "gpt-5-5"


def _build_tool_map(
    legit_toolset: MCPToolset,
    mal_toolset: MCPToolset,
) -> tuple[list[Tool], dict[str, str]]:
    """Merge tools from two warmed-up MCPToolsets (malicious overrides legit for same names).

    Returns (merged_tools, tool_label_map) where tool_label_map maps each
    tool name to "legitimate" or "malicious" for transcript labeling.
    """
    tool_label_map: dict[str, str] = {t.name: "legitimate" for t in legit_toolset.tools}
    tool_label_map.update({t.name: "malicious" for t in mal_toolset.tools})
    merged: dict[str, Tool] = {t.name: t for t in legit_toolset.tools}
    merged.update({t.name: t for t in mal_toolset.tools})
    return list(merged.values()), tool_label_map


def _make_generator(model: str) -> OpenAIChatGenerator | OpenAIResponsesChatGenerator:
    if model == _RESPONSES_API_MODEL:
        return OpenAIResponsesChatGenerator(
            api_key=Secret.from_token(LITELLM_KEY),
            api_base_url=LITELLM_BASE,
            model=model,
        )
    return OpenAIChatGenerator(
        api_key=Secret.from_token(LITELLM_KEY),
        api_base_url=LITELLM_BASE,
        model=model,
        generation_kwargs={"max_tokens": 2048},
    )


def _extract_transcript_entries(
    messages: list[ChatMessage],
    tool_label_map: dict[str, str],
    skip_first: bool = True,
    phase_name: str = "",
) -> list[dict]:
    """Convert Haystack Agent messages into our transcript format.

    The Agent returns all messages including the initial user message; skip_first
    drops it to avoid a duplicate when the caller already added the user entry.
    """
    entries: list[dict] = []
    for msg in (messages[1:] if skip_first else messages):
        if msg.role == ChatRole.ASSISTANT:
            entry: dict = {"role": "assistant", "content": msg.text or ""}
            if msg.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": tc.id or "",
                        "function": {
                            "name": tc.tool_name,
                            "arguments": json.dumps(tc.arguments or {}),
                        },
                    }
                    for tc in msg.tool_calls
                ]
            if phase_name:
                entry["_phase"] = phase_name
            entries.append(entry)
        elif msg.role == ChatRole.TOOL:
            for tcr in msg.tool_call_results:
                label = tool_label_map.get(tcr.origin.tool_name, "unknown")
                tool_entry: dict = {
                    "role": "tool",
                    "content": str(tcr.result),
                    "tool_name": tcr.origin.tool_name,
                    "mcp_server": label,
                }
                if phase_name:
                    tool_entry["_phase"] = phase_name
                entries.append(tool_entry)
    return entries


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
        server_info=StdioServerInfo(
            command=LEGIT_VENV_PYTHON,
            args=[LEGIT_SERVER],
            env=legit_server_env(workspace_dir),
        )
    )
    mal_toolset = MCPToolset(
        server_info=StdioServerInfo(
            command=MALICIOUS_VENV_PYTHON,
            args=[MALICIOUS_SERVER],
            env=malicious_server_env(scenario_name, canary_url, workspace_dir),
        )
    )

    legit_toolset.warm_up()
    mal_toolset.warm_up()
    try:
        haystack_tools, tool_label_map = _build_tool_map(legit_toolset, mal_toolset)

        agent = Agent(
            chat_generator=_make_generator(model),
            tools=haystack_tools,
            max_agent_steps=MAX_TURNS,
        )

        transcript: list[dict] = [{"role": "user", "content": user_prompt}]
        result = await agent.run_async(messages=[ChatMessage.from_user(user_prompt)])
        transcript.extend(
            _extract_transcript_entries(result["messages"], tool_label_map, skip_first=True)
        )
    finally:
        legit_toolset.close()
        mal_toolset.close()

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

    generator = _make_generator(model)
    # Accumulate the full conversation history across phases; Agent.run_async
    # takes all prior messages so the model has cross-phase context.
    accumulated_messages: list[ChatMessage] = []

    for phase in scenario.phases:
        legit_toolset = MCPToolset(
            server_info=StdioServerInfo(
                command=LEGIT_VENV_PYTHON,
                args=[LEGIT_SERVER],
                env=legit_server_env(workspace_dir),
            )
        )
        mal_toolset = MCPToolset(
            server_info=StdioServerInfo(
                command=MALICIOUS_VENV_PYTHON,
                args=[MALICIOUS_SERVER],
                env=malicious_server_env(scenario_name, canary_url, workspace_dir, phase_name=phase.name),
            )
        )

        legit_toolset.warm_up()
        mal_toolset.warm_up()
        try:
            haystack_tools, tool_label_map = _build_tool_map(legit_toolset, mal_toolset)

            agent = Agent(
                chat_generator=generator,
                tools=haystack_tools,
                max_agent_steps=MAX_TURNS,
            )

            user_prompt = substitute_tokens(phase.user_prompt, canary_url)
            user_msg = ChatMessage.from_user(user_prompt)
            transcript.append({"role": "user", "content": user_prompt, "_phase": phase.name})

            phase_input = accumulated_messages + [user_msg]
            result = await agent.run_async(messages=phase_input)

            # result["messages"] starts with all input messages; new messages are
            # everything after the phase_input prefix.
            new_messages = result["messages"][len(phase_input):]
            transcript.extend(
                _extract_transcript_entries(
                    new_messages, tool_label_map, skip_first=False, phase_name=phase.name
                )
            )
            accumulated_messages = result["messages"]
        finally:
            legit_toolset.close()
            mal_toolset.close()

    return transcript


def main() -> None:
    run_async_harness(run_single_phase, run_multi_phase)


if __name__ == "__main__":
    main()
