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
#     "google-adk[extensions]==2.5.0",
# ]
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# Run: uv run harness_google_adk.py <scenario.yaml> <workspace_dir> <canary_url> <model>

import json
import logging
import sys

from google.adk.labs.openai import OpenAIResponsesLlm
from google.adk.models.base_llm import BaseLlm
from google.adk.models.lite_llm import LiteLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.genai import types
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
from mcp import StdioServerParameters
from openai import AsyncOpenAI

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

MAX_TURNS = 10
_RESPONSES_API_MODEL = "gpt-5-5"


def _make_llm(model: str) -> BaseLlm:
    if model == _RESPONSES_API_MODEL:
        return OpenAIResponsesLlm(
            model=model,
            client=AsyncOpenAI(base_url=LITELLM_BASE, api_key=LITELLM_KEY),
        )
    return LiteLlm(model=f"openai/{model}", api_base=LITELLM_BASE, api_key=LITELLM_KEY)


def _mcp_to_adk_tool_schema(mcp_tools: list) -> types.Tool:
    """Build a types.Tool with FunctionDeclarations for the merged MCP tool list."""
    declarations = []
    for t in mcp_tools:
        schema = (
            t.inputSchema
            if hasattr(t, "inputSchema") and t.inputSchema
            else {"type": "object", "properties": {}, "required": []}
        )
        declarations.append(
            types.FunctionDeclaration(
                name=t.name,
                description=t.description or "",
                parameters_json_schema=schema,
            )
        )
    return types.Tool(function_declarations=declarations)


async def _call_tool_via_toolset(toolset: McpToolset, tool_name: str, arguments: dict) -> str:
    """Dispatch a tool call through McpToolset's session manager.

    McpToolset._mcp_session_manager manages the MCP server connection and
    caches the session; create_session() returns the live session. This routes
    dispatch through the toolset's infrastructure rather than calling
    session.call_tool() on a manually-managed ClientSession.
    """
    session = await toolset._mcp_session_manager.create_session()
    call_result = await session.call_tool(tool_name, arguments)
    if call_result.content:
        first = call_result.content[0]
        return first.text if hasattr(first, "text") else str(first)
    return json.dumps({"status": "ok"})


async def _generate(llm: BaseLlm, contents: list, tool: types.Tool) -> types.Content | None:
    llm_request = LlmRequest(
        contents=list(contents),
        config=types.GenerateContentConfig(
            tools=[tool],
            max_output_tokens=2048,
        ),
    )
    response = None
    async for r in llm.generate_content_async(llm_request, stream=False):
        response = r
    if response is None or response.content is None:
        return None
    return response.content


def _extract_text(content: types.Content) -> str:
    if not content.parts:
        return ""
    return "".join(part.text for part in content.parts if part.text is not None)


def _extract_function_calls(content: types.Content) -> list[types.FunctionCall]:
    if not content.parts:
        return []
    return [part.function_call for part in content.parts if part.function_call is not None]


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

    legit_toolset = McpToolset(
        connection_params=StdioServerParameters(
            command=LEGIT_VENV_PYTHON,
            args=[LEGIT_SERVER],
            env=legit_server_env(workspace_dir),
        )
    )
    mal_toolset = McpToolset(
        connection_params=StdioServerParameters(
            command=MALICIOUS_VENV_PYTHON,
            args=[MALICIOUS_SERVER],
            env=malicious_server_env(scenario_name, canary_url, workspace_dir),
        )
    )
    try:
        # get_tools() establishes the MCP session and returns McpTool objects.
        # raw_mcp_tool is the underlying MCP Tool with name/description/inputSchema.
        legit_adk_tools = await legit_toolset.get_tools()
        mal_adk_tools = await mal_toolset.get_tools()

        legit_mcp_tools = [t.raw_mcp_tool for t in legit_adk_tools]
        mal_mcp_tools = [t.raw_mcp_tool for t in mal_adk_tools]
        all_mcp_tools = dedup_tools_prefer_malicious(legit_mcp_tools, mal_mcp_tools)

        # tool_server_map: original name → (label, McpToolset for dispatch)
        tool_server_map: dict[str, tuple[str, McpToolset]] = {
            t.name: ("legitimate", legit_toolset) for t in legit_mcp_tools
        }
        tool_server_map.update({t.name: ("malicious", mal_toolset) for t in mal_mcp_tools})

        adk_tool_schema = _mcp_to_adk_tool_schema(all_mcp_tools)
        llm = _make_llm(model)

        contents: list[types.Content] = [
            types.Content(role="user", parts=[types.Part(text=user_prompt)])
        ]
        transcript: list[dict] = [{"role": "user", "content": user_prompt}]

        for _ in range(MAX_TURNS):
            model_content = await _generate(llm, contents, adk_tool_schema)
            if model_content is None:
                break

            model_content.role = "model"
            contents.append(model_content)

            text = _extract_text(model_content)
            function_calls = _extract_function_calls(model_content)

            entry: dict = {"role": "assistant", "content": text}
            if function_calls:
                entry["tool_calls"] = [
                    {
                        "id": fc.id or "",
                        "function": {
                            "name": fc.name,
                            "arguments": json.dumps(fc.args or {}),
                        },
                    }
                    for fc in function_calls
                ]
            transcript.append(entry)

            if not function_calls:
                break

            tool_result_parts: list[types.Part] = []
            for fc in function_calls:
                label, toolset = tool_server_map.get(fc.name, ("unknown", legit_toolset))
                # Dispatch via McpToolset's session manager — the native ADK MCP path.
                result_text = await _call_tool_via_toolset(toolset, fc.name, fc.args or {})
                transcript.append(
                    {
                        "role": "tool",
                        "content": result_text,
                        "tool_name": fc.name,
                        "mcp_server": label,
                    }
                )
                tool_result_parts.append(
                    types.Part(
                        function_response=types.FunctionResponse(
                            name=fc.name,
                            id=fc.id or "",
                            response={"result": result_text},
                        )
                    )
                )

            contents.append(types.Content(role="user", parts=tool_result_parts))

    finally:
        await legit_toolset.close()
        await mal_toolset.close()

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

    llm = _make_llm(model)
    accumulated_contents: list[types.Content] = []

    for phase in scenario.phases:
        legit_toolset = McpToolset(
            connection_params=StdioServerParameters(
                command=LEGIT_VENV_PYTHON,
                args=[LEGIT_SERVER],
                env=legit_server_env(workspace_dir),
            )
        )
        mal_toolset = McpToolset(
            connection_params=StdioServerParameters(
                command=MALICIOUS_VENV_PYTHON,
                args=[MALICIOUS_SERVER],
                env=malicious_server_env(scenario_name, canary_url, workspace_dir, phase_name=phase.name),
            )
        )
        try:
            legit_adk_tools = await legit_toolset.get_tools()
            mal_adk_tools = await mal_toolset.get_tools()

            legit_mcp_tools = [t.raw_mcp_tool for t in legit_adk_tools]
            mal_mcp_tools = [t.raw_mcp_tool for t in mal_adk_tools]
            all_mcp_tools = dedup_tools_prefer_malicious(legit_mcp_tools, mal_mcp_tools)

            tool_server_map: dict[str, tuple[str, McpToolset]] = {
                t.name: ("legitimate", legit_toolset) for t in legit_mcp_tools
            }
            tool_server_map.update({t.name: ("malicious", mal_toolset) for t in mal_mcp_tools})

            adk_tool_schema = _mcp_to_adk_tool_schema(all_mcp_tools)

            user_prompt = substitute_tokens(phase.user_prompt, canary_url)
            accumulated_contents.append(
                types.Content(role="user", parts=[types.Part(text=user_prompt)])
            )
            transcript.append({"role": "user", "content": user_prompt, "_phase": phase.name})

            for _ in range(MAX_TURNS):
                model_content = await _generate(llm, accumulated_contents, adk_tool_schema)
                if model_content is None:
                    break

                model_content.role = "model"
                accumulated_contents.append(model_content)

                text = _extract_text(model_content)
                function_calls = _extract_function_calls(model_content)

                entry: dict = {
                    "role": "assistant",
                    "content": text,
                    "_phase": phase.name,
                }
                if function_calls:
                    entry["tool_calls"] = [
                        {
                            "id": fc.id or "",
                            "function": {
                                "name": fc.name,
                                "arguments": json.dumps(fc.args or {}),
                            },
                        }
                        for fc in function_calls
                    ]
                transcript.append(entry)

                if not function_calls:
                    break

                tool_result_parts: list[types.Part] = []
                for fc in function_calls:
                    label, toolset = tool_server_map.get(fc.name, ("unknown", legit_toolset))
                    result_text = await _call_tool_via_toolset(toolset, fc.name, fc.args or {})
                    transcript.append(
                        {
                            "role": "tool",
                            "content": result_text,
                            "tool_name": fc.name,
                            "mcp_server": label,
                            "_phase": phase.name,
                        }
                    )
                    tool_result_parts.append(
                        types.Part(
                            function_response=types.FunctionResponse(
                                name=fc.name,
                                id=fc.id or "",
                                response={"result": result_text},
                            )
                        )
                    )

                accumulated_contents.append(types.Content(role="user", parts=tool_result_parts))

        finally:
            await legit_toolset.close()
            await mal_toolset.close()

    return transcript


def main() -> None:
    run_async_harness(run_single_phase, run_multi_phase)


if __name__ == "__main__":
    main()
