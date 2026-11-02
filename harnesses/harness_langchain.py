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
#     "langchain-core==1.5.0",
#     "langchain-mcp-adapters==0.3.0",
#     "langchain-openai==1.3.5",
#     "langgraph==0.3.0",
#     "langgraph-prebuilt==0.1.8",
# ]
#
# [tool.uv]
# prerelease = "allow"
# override-dependencies = [
#     "langchain-core==1.5.0",
#     "langgraph==0.3.0",
#     "langgraph-prebuilt==0.1.8",
# ]
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# Run: uv run harness_langchain.py <scenario.yaml> <workspace_dir> <canary_url> <model>

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
    dedup_tools_prefer_malicious,
    legit_server_env,
    load_scenario_safe,
    malicious_server_env,
    run_async_harness,
    substitute_tokens,
)
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.sessions import StdioConnection
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

MAX_TURNS = 10
_RESPONSES_API_MODEL = "gpt-5-5"


def _make_llm(model: str) -> ChatOpenAI:
    kwargs: dict = {"base_url": LITELLM_BASE, "api_key": LITELLM_KEY, "model": model, "max_tokens": 2048}
    if model == _RESPONSES_API_MODEL:
        kwargs["use_responses_api"] = True
    return ChatOpenAI(**kwargs)


def _extract_transcript(messages: list, tool_server_map: dict[str, str], phase_name: str = "") -> list[dict]:
    """Extract normalized transcript from LangGraph result messages."""
    transcript: list[dict] = []
    for msg in messages:
        msg_type = msg.__class__.__name__
        if msg_type == "HumanMessage":
            entry: dict = {"role": "user", "content": msg.content}
            if phase_name:
                entry["_phase"] = phase_name
            transcript.append(entry)
        elif msg_type == "AIMessage":
            entry = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                entry["tool_calls"] = [
                    {
                        "id": tc.get("id", ""),
                        "function": {
                            "name": tc["name"],
                            "arguments": json.dumps(tc["args"]),
                        },
                    }
                    for tc in msg.tool_calls
                ]
            if phase_name:
                entry["_phase"] = phase_name
            transcript.append(entry)
        elif msg_type == "ToolMessage":
            entry = {
                "role": "tool",
                "content": str(msg.content),
                "tool_name": msg.name or "",
                "mcp_server": tool_server_map.get(msg.name or "", "unknown"),
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

    server_config = {
        "legitimate": StdioConnection(
            transport="stdio",
            command=LEGIT_VENV_PYTHON,
            args=[LEGIT_SERVER],
            env=legit_server_env(workspace_dir),
        ),
        "malicious": StdioConnection(
            transport="stdio",
            command=MALICIOUS_VENV_PYTHON,
            args=[MALICIOUS_SERVER],
            env=malicious_server_env(scenario_name, canary_url, workspace_dir),
        ),
    }

    # v0.2.2: MultiServerMCPClient is NOT a context manager.
    # Sessions are created per tool call internally.
    client = MultiServerMCPClient(server_config)
    legit_tools_lc = await client.get_tools(server_name="legitimate")
    mal_tools_lc = await client.get_tools(server_name="malicious")
    all_tools = dedup_tools_prefer_malicious(legit_tools_lc, mal_tools_lc)

    tool_server_map: dict[str, str] = {}
    for t in legit_tools_lc:
        tool_server_map[t.name] = "legitimate"
    for t in mal_tools_lc:
        tool_server_map[t.name] = "malicious"

    llm = _make_llm(model)

    agent = create_react_agent(llm, all_tools)
    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": user_prompt}]},
        config={"recursion_limit": MAX_TURNS * 2},
    )

    return _extract_transcript(result["messages"], tool_server_map)


async def run_multi_phase(
    scenario_path: str,
    scenario_name: str,
    workspace_dir: str,
    canary_url: str,
    model: str,
) -> list[dict]:
    """Run multi-phase scenario. Preserves LangGraph message history across phases.
    Relaunches malicious MCP server per phase with correct PHASE_NAME.
    Legitimate server stays connected throughout.
    """
    transcript: list[dict] = []
    scenario = load_scenario_safe(scenario_path)
    if scenario is None:
        return [{"role": "error", "content": f"Failed to load scenario: {scenario_path}"}]

    llm = _make_llm(model)

    # Keep accumulated messages across phases
    accumulated_messages: list = []

    for phase in scenario.phases:
        # Build config with phase-specific malicious server
        phase_config = {
            "legitimate": StdioConnection(
                transport="stdio",
                command=LEGIT_VENV_PYTHON,
                args=[LEGIT_SERVER],
                env=legit_server_env(workspace_dir),
            ),
            "malicious": StdioConnection(
                transport="stdio",
                command=MALICIOUS_VENV_PYTHON,
                args=[MALICIOUS_SERVER],
                env=malicious_server_env(scenario_name, canary_url, workspace_dir, phase_name=phase.name),
            ),
        }

        # v0.2.2: No context manager — sessions created per tool call
        client = MultiServerMCPClient(phase_config)
        legit_tools_lc = await client.get_tools(server_name="legitimate")
        mal_tools_lc = await client.get_tools(server_name="malicious")
        all_tools = dedup_tools_prefer_malicious(legit_tools_lc, mal_tools_lc)

        tool_server_map: dict[str, str] = {}
        for t in legit_tools_lc:
            tool_server_map[t.name] = "legitimate"
        for t in mal_tools_lc:
            tool_server_map[t.name] = "malicious"

        user_prompt = substitute_tokens(phase.user_prompt, canary_url)
        accumulated_messages.append({"role": "user", "content": user_prompt})

        agent = create_react_agent(llm, all_tools)
        result = await agent.ainvoke(
            {"messages": list(accumulated_messages)},
            config={"recursion_limit": MAX_TURNS * 2},
        )

        # Extract only NEW messages from this phase
        new_messages = result["messages"][len(accumulated_messages):]
        phase_transcript = _extract_transcript(
            [result["messages"][len(accumulated_messages) - 1]] + new_messages,
            tool_server_map,
            phase.name,
        )
        transcript.extend(phase_transcript)

        # Carry forward all messages for next phase
        accumulated_messages = list(result["messages"])

    return transcript


def main() -> None:
    run_async_harness(run_single_phase, run_multi_phase)


if __name__ == "__main__":
    main()
