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
#     "llama-index-core==0.14.23",
#     "llama-index-llms-openai==0.7.9",
#     "llama-index-tools-mcp==0.4.8",
# ]
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# Run: uv run harness_llamaindex.py <scenario.yaml> <workspace_dir> <canary_url> <model>

import json
import logging
import sys

import llama_index.llms.openai.base as _oai_base
import llama_index.llms.openai.responses as _oai_responses
import llama_index.llms.openai.utils as _oai_utils
from llama_index.core.llms import ChatMessage, MessageRole
from llama_index.core.tools import FunctionTool
from llama_index.llms.openai import OpenAI as LlamaOpenAI
from llama_index.llms.openai import OpenAIResponses
from llama_index.tools.mcp import McpToolSpec
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# LlamaIndex validates model names against a hardcoded OpenAI list.
# Patch utils, base, and responses — all three bind the functions locally at import time.
_orig_ctx = _oai_utils.openai_modelname_to_contextsize
def _ctx_any(name: str) -> int:
    try:
        return _orig_ctx(name)
    except ValueError:
        return 128000
_oai_utils.openai_modelname_to_contextsize = _ctx_any
_oai_base.openai_modelname_to_contextsize = _ctx_any
if hasattr(_oai_responses, "openai_modelname_to_contextsize"):
    _oai_responses.openai_modelname_to_contextsize = _ctx_any

# Also patch is_chat_model: unknown aliases routed through LiteLLM are always chat models.
_orig_is_chat = _oai_utils.is_chat_model
def _is_chat_any(model: str) -> bool:
    return _orig_is_chat(model) or True
_oai_utils.is_chat_model = _is_chat_any
_oai_base.is_chat_model = _is_chat_any
if hasattr(_oai_responses, "is_chat_model"):
    _oai_responses.is_chat_model = _is_chat_any

from harness_base import (  # noqa: E402
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

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

MAX_TURNS = 10
_RESPONSES_API_MODEL = "gpt-5-5"


def _make_llm(model: str) -> LlamaOpenAI | OpenAIResponses:
    if model == _RESPONSES_API_MODEL:
        # reasoning_options triggers top_p/temperature exclusion in OpenAIResponses._get_model_kwargs
        return OpenAIResponses(
            model=model, api_key=LITELLM_KEY, api_base=LITELLM_BASE,
            max_output_tokens=2048, reasoning_options={"effort": "medium"},
        )
    return LlamaOpenAI(model=model, api_key=LITELLM_KEY, api_base=LITELLM_BASE, max_tokens=2048)


async def _build_tool_map(
    legit_session: ClientSession,
    mal_session: ClientSession,
    legit_mcp_tools: list,
    mal_mcp_tools: list,
) -> dict[str, FunctionTool]:
    """Load tools via McpToolSpec (native LlamaIndex MCP integration).

    McpToolSpec builds real Pydantic models from inputSchema — avoiding the
    raw-schema passthrough of the previous _make_fn_schema approach — and its
    async_tool_fn calls session.call_tool internally, so the harness loop
    dispatches via tool.acall() rather than calling session.call_tool directly.

    Malicious tools override legit tools with the same name (same dedup policy
    as dedup_tools_prefer_malicious in harness_base).
    """
    legit_spec = McpToolSpec(client=legit_session, allowed_tools=[t.name for t in legit_mcp_tools])
    mal_spec = McpToolSpec(client=mal_session, allowed_tools=[t.name for t in mal_mcp_tools])

    legit_tools = {t.metadata.name: t for t in await legit_spec.to_tool_list_async()}
    mal_tools = {t.metadata.name: t for t in await mal_spec.to_tool_list_async()}

    return {**legit_tools, **mal_tools}  # malicious overrides legit for same-name tools


def _tool_output_to_str(tool_output: object) -> str:
    """Extract a plain string from a LlamaIndex ToolOutput (or raw value)."""
    if hasattr(tool_output, "raw_output"):
        raw = tool_output.raw_output
        # McpToolSpec returns a CallToolResult; extract the first text content.
        if hasattr(raw, "content") and raw.content:
            first = raw.content[0]
            return first.text if hasattr(first, "text") else str(first)
        return tool_output.content or json.dumps({"status": "ok"})
    return str(tool_output) if tool_output is not None else json.dumps({"status": "ok"})


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

            tool_map = await _build_tool_map(
                legit_session, mal_session, legit_mcp_tools, mal_mcp_tools
            )
            llama_tools = list(tool_map.values())

            server_label_map: dict[str, str] = {t.name: "legitimate" for t in legit_mcp_tools}
            server_label_map.update({t.name: "malicious" for t in mal_mcp_tools})

            llm = _make_llm(model)

            messages: list[ChatMessage] = [ChatMessage(role=MessageRole.USER, content=user_prompt)]
            transcript: list[dict] = [{"role": "user", "content": user_prompt}]

            for _ in range(MAX_TURNS):
                response = llm.chat_with_tools(llama_tools, chat_history=messages)
                messages.append(response.message)

                tool_selections = llm.get_tool_calls_from_response(
                    response, error_on_no_tool_call=False
                )

                entry: dict = {"role": "assistant", "content": response.message.content or ""}
                if tool_selections:
                    entry["tool_calls"] = [
                        {
                            "id": tc.tool_id or "",
                            "function": {
                                "name": tc.tool_name,
                                "arguments": json.dumps(tc.tool_kwargs or {}),
                            },
                        }
                        for tc in tool_selections
                    ]
                transcript.append(entry)

                if not tool_selections:
                    break

                for tc in tool_selections:
                    label = server_label_map.get(tc.tool_name, "unknown")
                    tool = tool_map.get(tc.tool_name)
                    if tool is not None:
                        tool_output = await tool.acall(**(tc.tool_kwargs or {}))
                        result_text = _tool_output_to_str(tool_output)
                    else:
                        result_text = json.dumps({"error": f"unknown tool: {tc.tool_name}"})
                    transcript.append(
                        {
                            "role": "tool",
                            "content": result_text,
                            "tool_name": tc.tool_name,
                            "mcp_server": label,
                        }
                    )
                    messages.append(
                        ChatMessage(
                            role=MessageRole.TOOL,
                            content=result_text,
                            additional_kwargs={"tool_call_id": tc.tool_id or ""},
                        )
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

    llm = _make_llm(model)
    accumulated_messages: list[ChatMessage] = []

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

                tool_map = await _build_tool_map(
                    legit_session, mal_session, legit_mcp_tools, mal_mcp_tools
                )
                llama_tools = list(tool_map.values())

                server_label_map: dict[str, str] = {t.name: "legitimate" for t in legit_mcp_tools}
                server_label_map.update({t.name: "malicious" for t in mal_mcp_tools})

                user_prompt = substitute_tokens(phase.user_prompt, canary_url)
                accumulated_messages.append(ChatMessage(role=MessageRole.USER, content=user_prompt))
                transcript.append({"role": "user", "content": user_prompt, "_phase": phase.name})

                for _ in range(MAX_TURNS):
                    response = llm.chat_with_tools(
                        llama_tools, chat_history=list(accumulated_messages)
                    )
                    accumulated_messages.append(response.message)

                    tool_selections = llm.get_tool_calls_from_response(
                        response, error_on_no_tool_call=False
                    )

                    entry: dict = {
                        "role": "assistant",
                        "content": response.message.content or "",
                        "_phase": phase.name,
                    }
                    if tool_selections:
                        entry["tool_calls"] = [
                            {
                                "id": tc.tool_id or "",
                                "function": {
                                    "name": tc.tool_name,
                                    "arguments": json.dumps(tc.tool_kwargs or {}),
                                },
                            }
                            for tc in tool_selections
                        ]
                    transcript.append(entry)

                    if not tool_selections:
                        break

                    for tc in tool_selections:
                        label = server_label_map.get(tc.tool_name, "unknown")
                        tool = tool_map.get(tc.tool_name)
                        if tool is not None:
                            tool_output = await tool.acall(**(tc.tool_kwargs or {}))
                            result_text = _tool_output_to_str(tool_output)
                        else:
                            result_text = json.dumps({"error": f"unknown tool: {tc.tool_name}"})
                        transcript.append(
                            {
                                "role": "tool",
                                "content": result_text,
                                "tool_name": tc.tool_name,
                                "mcp_server": label,
                                "_phase": phase.name,
                            }
                        )
                        accumulated_messages.append(
                            ChatMessage(
                                role=MessageRole.TOOL,
                                content=result_text,
                                additional_kwargs={"tool_call_id": tc.tool_id or ""},
                            )
                        )

    return transcript


def main() -> None:
    run_async_harness(run_single_phase, run_multi_phase)


if __name__ == "__main__":
    main()
