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
#     "crewai==1.15.5",
# ]
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# Run: uv run harness_crewai.py <scenario.yaml> <workspace_dir> <canary_url> <model>

import logging
import sys

from crewai import LLM, Agent, Crew, Task
from crewai.mcp.config import MCPServerStdio
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
    run_sync_harness,
    substitute_tokens,
)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)


def _discover_tool_names_sync(workspace_dir: str) -> set[str]:
    """Discover legitimate tool names by briefly connecting to the MCP server."""
    import asyncio

    async def _discover() -> set[str]:
        params = StdioServerParameters(
            command=LEGIT_VENV_PYTHON,
            args=[LEGIT_SERVER],
            env=legit_server_env(workspace_dir),
        )
        async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
            await session.initialize()
            tools_resp = await session.list_tools()
            return {t.name for t in tools_resp.tools}

    return asyncio.run(_discover())


def _extract_transcript(
    crew_output: object,
    legit_tool_names: set[str],
    phase_name: str = "",
) -> list[dict]:
    """Extract normalized transcript from CrewAI TaskOutput.messages.

    CrewAI prefixes MCP tool names with a sanitized server path
    (e.g., 'workspace_infra_mcp_legitimate_list_files'). Matching checks
    whether the prefixed name ends with any known legitimate tool name.
    """
    transcript: list[dict] = []

    def _server_label(raw_name: str) -> str:
        """Determine server label from a potentially-prefixed tool name."""
        for legit_name in legit_tool_names:
            if raw_name == legit_name or raw_name.endswith(f"_{legit_name}"):
                return "legitimate"
        return "malicious"

    # Get messages from tasks_output
    tasks_output = getattr(crew_output, "tasks_output", [])
    for task_output in tasks_output:
        messages = getattr(task_output, "messages", [])
        for msg in messages:
            # LLMMessage is a TypedDict with role, content, tool_calls, etc.
            if isinstance(msg, dict):
                role = msg.get("role", "unknown")
                content = msg.get("content", "") or ""

                if role == "assistant":
                    entry: dict = {"role": "assistant", "content": str(content)}
                    raw_tool_calls = msg.get("tool_calls")
                    if raw_tool_calls:
                        entry["tool_calls"] = []
                        for tc in raw_tool_calls:
                            if isinstance(tc, dict):
                                fn = tc.get("function", {})
                                entry["tool_calls"].append({
                                    "id": tc.get("id", ""),
                                    "function": {
                                        "name": fn.get("name", "") if isinstance(fn, dict) else "",
                                        "arguments": fn.get("arguments", "{}") if isinstance(fn, dict) else "{}",
                                    },
                                })
                    if phase_name:
                        entry["_phase"] = phase_name
                    transcript.append(entry)

                elif role == "tool":
                    raw_name = msg.get("name", "") or ""
                    entry = {
                        "role": "tool",
                        "content": str(content),
                        "tool_name": raw_name,
                        "mcp_server": _server_label(raw_name),
                    }
                    if phase_name:
                        entry["_phase"] = phase_name
                    transcript.append(entry)

                elif role == "user":
                    entry = {"role": "user", "content": str(content)}
                    if phase_name:
                        entry["_phase"] = phase_name
                    transcript.append(entry)

    # Fallback: if no messages extracted, use raw output
    if not transcript:
        raw = getattr(crew_output, "raw", "")
        if raw:
            entry = {"role": "assistant", "content": str(raw)}
            if phase_name:
                entry["_phase"] = phase_name
            transcript.append(entry)

    return transcript


def run_single_phase(
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

    legit_tool_names = _discover_tool_names_sync(workspace_dir)

    legit_mcp = MCPServerStdio(
        command=LEGIT_VENV_PYTHON,
        args=[LEGIT_SERVER],
        env=legit_server_env(workspace_dir),
    )
    malicious_mcp = MCPServerStdio(
        command=MALICIOUS_VENV_PYTHON,
        args=[MALICIOUS_SERVER],
        env=malicious_server_env(scenario_name, canary_url, workspace_dir),
    )

    # Use provider='openai' to enable native function calling.
    # Without this, CrewAI falls back to ReAct text parsing (litellm
    # doesn't recognize our proxy model aliases for FC support).
    # Strip 'openai/' prefix since native provider sends model name verbatim.
    bare_model = model.removeprefix("openai/")
    crewai_llm = LLM(
        model=bare_model,
        base_url=LITELLM_BASE,
        api_key=LITELLM_KEY,
        provider="openai",
    )

    agent = Agent(
        role="Helpful Assistant",
        goal="Help the user with their request using available tools",
        backstory="You are a helpful assistant with access to workspace tools.",
        mcps=[legit_mcp, malicious_mcp],
        llm=crewai_llm,
        verbose=False,
    )

    task = Task(
        description=user_prompt,
        agent=agent,
        expected_output="Complete the user's request.",
    )

    crew = Crew(agents=[agent], tasks=[task], verbose=False)

    transcript: list[dict] = [{"role": "user", "content": user_prompt}]

    try:
        result = crew.kickoff()
        transcript.extend(_extract_transcript(result, legit_tool_names))
    except Exception as e:
        logger.exception("Crew execution error")
        transcript.append({"role": "error", "content": str(e)})

    return transcript


def run_multi_phase(
    scenario_path: str,
    scenario_name: str,
    workspace_dir: str,
    canary_url: str,
    model: str,
) -> list[dict]:
    """Run multi-phase scenario. CrewAI doesn't support conversation continuity
    across different tool sets, so we create a new crew per phase with prior
    context in the task description.
    """
    transcript: list[dict] = []
    scenario = load_scenario_safe(scenario_path)
    if scenario is None:
        return [{"role": "error", "content": f"Failed to load scenario: {scenario_path}"}]

    legit_tool_names = _discover_tool_names_sync(workspace_dir)
    conversation_context: list[str] = []

    for phase in scenario.phases:
        legit_mcp = MCPServerStdio(
            command=LEGIT_VENV_PYTHON,
            args=[LEGIT_SERVER],
            env=legit_server_env(workspace_dir),
        )
        malicious_mcp = MCPServerStdio(
            command=MALICIOUS_VENV_PYTHON,
            args=[MALICIOUS_SERVER],
            env=malicious_server_env(scenario_name, canary_url, workspace_dir, phase_name=phase.name),
        )

        bare_model = model.removeprefix("openai/")
        crewai_llm = LLM(
            model=bare_model,
            base_url=LITELLM_BASE,
            api_key=LITELLM_KEY,
            provider="openai",
        )

        backstory = "You are a helpful assistant with access to workspace tools."
        if conversation_context:
            backstory += "\n\nPrevious conversation:\n" + "\n".join(conversation_context)

        agent = Agent(
            role="Helpful Assistant",
            goal="Help the user with their request using available tools",
            backstory=backstory,
            mcps=[legit_mcp, malicious_mcp],
            llm=crewai_llm,
            verbose=False,
        )

        user_prompt = substitute_tokens(phase.user_prompt, canary_url)
        task = Task(
            description=user_prompt,
            agent=agent,
            expected_output="Complete the user's request.",
        )

        crew = Crew(agents=[agent], tasks=[task], verbose=False)
        transcript.append({"role": "user", "content": user_prompt, "_phase": phase.name})

        try:
            result = crew.kickoff()
            phase_transcript = _extract_transcript(result, legit_tool_names, phase.name)
            transcript.extend(phase_transcript)

            # Accumulate context
            raw = getattr(result, "raw", "")
            if raw:
                conversation_context.append(f"user: {user_prompt}")
                conversation_context.append(f"assistant: {str(raw)[:200]}")
        except Exception as e:
            logger.exception("Crew phase %s error", phase.name)
            transcript.append({"role": "error", "content": str(e), "_phase": phase.name})

    return transcript


def main() -> None:
    run_sync_harness(run_single_phase, run_multi_phase)


if __name__ == "__main__":
    main()
