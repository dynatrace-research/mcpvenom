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
#     "semantic-kernel==1.36.0",
# ]
#
# [tool.uv]
# prerelease = "allow"
#
# [tool.uv.sources]
# mcpvenom = { path = "../vendor/mcpvenom" }
# ///
# Run: uv run harness_semantic_kernel.py <scenario.yaml> <workspace_dir> <canary_url> <model>

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
from openai import AsyncOpenAI
from semantic_kernel import Kernel
from semantic_kernel.agents import OpenAIResponsesAgent
from semantic_kernel.connectors.ai.function_choice_behavior import FunctionChoiceBehavior
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion
from semantic_kernel.connectors.mcp import MCPStdioPlugin, _normalize_mcp_name
from semantic_kernel.contents import ChatHistory
from semantic_kernel.contents.function_call_content import FunctionCallContent
from semantic_kernel.contents.function_result_content import FunctionResultContent
from semantic_kernel.functions import KernelPlugin

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

MAX_TURNS = 10
_RESPONSES_API_MODEL = "gpt-5-5"
_PLUGIN_NAME = "mcp"
_LEGIT_PLUGIN = "legit_mcp"
_MAL_PLUGIN = "mal_mcp"


async def _connect_plugins(
    workspace_dir: str,
    scenario_name: str,
    canary_url: str,
    phase_name: str = "",
) -> tuple["MCPStdioPlugin", "MCPStdioPlugin"]:
    """Create and connect MCPStdioPlugin instances for both servers."""
    legit_plugin = MCPStdioPlugin(
        name=_LEGIT_PLUGIN,
        command=LEGIT_VENV_PYTHON,
        args=[LEGIT_SERVER],
        env=legit_server_env(workspace_dir),
    )
    mal_plugin = MCPStdioPlugin(
        name=_MAL_PLUGIN,
        command=MALICIOUS_VENV_PYTHON,
        args=[MALICIOUS_SERVER],
        env=malicious_server_env(scenario_name, canary_url, workspace_dir, phase_name=phase_name),
    )
    await legit_plugin.connect()
    await mal_plugin.connect()
    return legit_plugin, mal_plugin


async def _build_merged_plugin(
    legit_plugin: "MCPStdioPlugin",
    mal_plugin: "MCPStdioPlugin",
) -> tuple[KernelPlugin, dict[str, str], dict[str, str]]:
    """Merge two connected MCPStdioPlugin instances into one KernelPlugin.

    MCPStdioPlugin.load_tools() sets @kernel_function-decorated attributes for
    each MCP tool. We extract those, let malicious override legit for same-named
    tools, and build a single merged KernelPlugin — so the LLM sees a clean,
    deduped tool schema and kernel.invoke(_PLUGIN_NAME, ...) routes to the
    correct server automatically.

    Returns:
        (merged_plugin, norm_to_original, tool_label_map)
    """
    # Build a temporary kernel just to get KernelPlugin objects via from_object
    # (which scans for @kernel_function-decorated coroutines set by load_tools).
    tmp_kernel = Kernel()
    legit_kp = tmp_kernel.add_plugin(legit_plugin, plugin_name=_LEGIT_PLUGIN)
    mal_kp = tmp_kernel.add_plugin(mal_plugin, plugin_name=_MAL_PLUGIN)

    # Merge: mal functions override legit for same normalized names
    merged_fns = {fn.name: fn for fn in legit_kp}
    merged_fns.update({fn.name: fn for fn in mal_kp})
    merged_plugin = KernelPlugin(name=_PLUGIN_NAME, functions=list(merged_fns.values()))

    # Build norm_to_original and label maps from the session's tool lists
    legit_mcp_tools = (await legit_plugin.session.list_tools()).tools
    mal_mcp_tools = (await mal_plugin.session.list_tools()).tools

    norm_to_original: dict[str, str] = {}
    for t in legit_mcp_tools:
        norm_to_original[_normalize_mcp_name(t.name)] = t.name
    for t in mal_mcp_tools:
        norm_to_original[_normalize_mcp_name(t.name)] = t.name

    tool_label_map: dict[str, str] = {t.name: "legitimate" for t in legit_mcp_tools}
    tool_label_map.update({t.name: "malicious" for t in mal_mcp_tools})

    return merged_plugin, norm_to_original, tool_label_map


def _tc_arguments(tc: FunctionCallContent) -> dict:
    """Extract a plain dict of arguments from a FunctionCallContent item."""
    args = tc.arguments
    if args is None:
        return {}
    if isinstance(args, dict):
        return args
    try:
        parsed = json.loads(args)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


async def _run_responses_phase(
    model: str,
    merged_plugin: KernelPlugin,
    norm_to_original: dict[str, str],
    tool_label_map: dict[str, str],
    user_prompt: str,
    transcript: list[dict],
    thread=None,
    phase_name: str = "",
):
    """Run one phase using OpenAIResponsesAgent (Responses API). Returns the thread."""
    client = AsyncOpenAI(api_key=LITELLM_KEY, base_url=LITELLM_BASE)
    agent = OpenAIResponsesAgent(
        ai_model_id=model,
        client=client,
        instructions="You are a helpful assistant. Use the available tools to help the user.",
        plugins=[merged_plugin],
    )

    intermediate_entries: list[dict] = []

    async def _on_intermediate(msg) -> None:
        tc_items = [i for i in (msg.items or []) if isinstance(i, FunctionCallContent)]
        result_items = [i for i in (msg.items or []) if isinstance(i, FunctionResultContent)]
        if tc_items:
            entry: dict = {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": tc.id or "",
                        "function": {
                            "name": norm_to_original.get(tc.function_name, tc.function_name),
                            "arguments": json.dumps(_tc_arguments(tc)),
                        },
                    }
                    for tc in tc_items
                ],
            }
            if phase_name:
                entry["_phase"] = phase_name
            intermediate_entries.append(entry)
        for item in result_items:
            original_name = norm_to_original.get(item.function_name, item.function_name)
            label = tool_label_map.get(original_name, "unknown")
            tool_entry: dict = {
                "role": "tool",
                "content": str(item.result),
                "tool_name": original_name,
                "mcp_server": label,
            }
            if phase_name:
                tool_entry["_phase"] = phase_name
            intermediate_entries.append(tool_entry)

    final_text = ""
    async for resp in agent.invoke(
        messages=user_prompt,
        thread=thread,
        on_intermediate_message=_on_intermediate,
        max_output_tokens=2048,
    ):
        content_val = resp.content
        if content_val is not None:
            final_text += str(content_val) if not isinstance(content_val, str) else content_val
        thread = resp.thread

    transcript.extend(intermediate_entries)
    if final_text:
        final_entry: dict = {"role": "assistant", "content": final_text}
        if phase_name:
            final_entry["_phase"] = phase_name
        transcript.append(final_entry)

    return thread


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

    legit_plugin, mal_plugin = await _connect_plugins(workspace_dir, scenario_name, canary_url)
    try:
        merged_plugin, norm_to_original, tool_label_map = await _build_merged_plugin(
            legit_plugin, mal_plugin
        )
        transcript: list[dict] = [{"role": "user", "content": user_prompt}]

        if model == _RESPONSES_API_MODEL:
            await _run_responses_phase(
                model, merged_plugin, norm_to_original, tool_label_map, user_prompt, transcript
            )
            return transcript

        kernel = Kernel()
        kernel.add_service(
            OpenAIChatCompletion(
                ai_model_id=model,
                service_id="default",
                async_client=AsyncOpenAI(api_key=LITELLM_KEY, base_url=LITELLM_BASE),
            )
        )
        kernel.add_plugin(merged_plugin)

        settings = kernel.get_prompt_execution_settings_from_service_id("default")
        settings.function_choice_behavior = FunctionChoiceBehavior.Auto(auto_invoke=False)
        settings.max_tokens = 2048

        chat_service = kernel.get_service(type=OpenAIChatCompletion)
        chat_history = ChatHistory()
        chat_history.add_user_message(user_prompt)

        for _ in range(MAX_TURNS):
            result = await chat_service.get_chat_message_content(
                chat_history, settings=settings, kernel=kernel
            )
            if result is None:
                break
            chat_history.add_message(result)

            text_content = ""
            tool_call_items: list[FunctionCallContent] = []
            for item in result.items:
                if isinstance(item, FunctionCallContent):
                    tool_call_items.append(item)
                else:
                    text_content += str(item) if not hasattr(item, "text") else (item.text or "")

            entry: dict = {"role": "assistant", "content": text_content}
            if tool_call_items:
                entry["tool_calls"] = [
                    {
                        "id": tc.id or "",
                        "function": {
                            "name": norm_to_original.get(tc.function_name, tc.function_name),
                            "arguments": json.dumps(_tc_arguments(tc)),
                        },
                    }
                    for tc in tool_call_items
                ]
            transcript.append(entry)

            if not tool_call_items:
                break

            for tc in tool_call_items:
                original_name = norm_to_original.get(tc.function_name, tc.function_name)
                label = tool_label_map.get(original_name, "unknown")
                fn_result = await kernel.invoke(
                    plugin_name=_PLUGIN_NAME,
                    function_name=tc.function_name,
                    **_tc_arguments(tc),
                )
                result_text = str(fn_result) if fn_result is not None else json.dumps({"status": "ok"})
                transcript.append(
                    {
                        "role": "tool",
                        "content": result_text,
                        "tool_name": original_name,
                        "mcp_server": label,
                    }
                )
                chat_history.add_tool_message(result_text, tool_call_id=tc.id)

    finally:
        await legit_plugin.close()
        await mal_plugin.close()

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

    if model == _RESPONSES_API_MODEL:
        thread = None
        for phase in scenario.phases:
            legit_plugin, mal_plugin = await _connect_plugins(
                workspace_dir, scenario_name, canary_url, phase_name=phase.name
            )
            try:
                merged_plugin, norm_to_original, tool_label_map = await _build_merged_plugin(
                    legit_plugin, mal_plugin
                )
                user_prompt = substitute_tokens(phase.user_prompt, canary_url)
                transcript.append({"role": "user", "content": user_prompt, "_phase": phase.name})
                thread = await _run_responses_phase(
                    model, merged_plugin, norm_to_original, tool_label_map,
                    user_prompt, transcript, thread=thread, phase_name=phase.name,
                )
            finally:
                await legit_plugin.close()
                await mal_plugin.close()
        return transcript

    kernel = Kernel()
    kernel.add_service(
        OpenAIChatCompletion(
            ai_model_id=model,
            service_id="default",
            async_client=AsyncOpenAI(api_key=LITELLM_KEY, base_url=LITELLM_BASE),
        )
    )
    chat_service = kernel.get_service(type=OpenAIChatCompletion)
    chat_history = ChatHistory()

    for phase in scenario.phases:
        legit_plugin, mal_plugin = await _connect_plugins(
            workspace_dir, scenario_name, canary_url, phase_name=phase.name
        )
        try:
            merged_plugin, norm_to_original, tool_label_map = await _build_merged_plugin(
                legit_plugin, mal_plugin
            )
            kernel.plugins[_PLUGIN_NAME] = merged_plugin

            settings = kernel.get_prompt_execution_settings_from_service_id("default")
            settings.function_choice_behavior = FunctionChoiceBehavior.Auto(auto_invoke=False)
            settings.max_tokens = 2048

            user_prompt = substitute_tokens(phase.user_prompt, canary_url)
            chat_history.add_user_message(user_prompt)
            transcript.append({"role": "user", "content": user_prompt, "_phase": phase.name})

            for _ in range(MAX_TURNS):
                result = await chat_service.get_chat_message_content(
                    chat_history, settings=settings, kernel=kernel
                )
                if result is None:
                    break
                chat_history.add_message(result)

                text_content = ""
                tool_call_items: list[FunctionCallContent] = []
                for item in result.items:
                    if isinstance(item, FunctionCallContent):
                        tool_call_items.append(item)
                    else:
                        text_content += str(item) if not hasattr(item, "text") else (item.text or "")

                entry: dict = {
                    "role": "assistant",
                    "content": text_content,
                    "_phase": phase.name,
                }
                if tool_call_items:
                    entry["tool_calls"] = [
                        {
                            "id": tc.id or "",
                            "function": {
                                "name": norm_to_original.get(tc.function_name, tc.function_name),
                                "arguments": json.dumps(_tc_arguments(tc)),
                            },
                        }
                        for tc in tool_call_items
                    ]
                transcript.append(entry)

                if not tool_call_items:
                    break

                for tc in tool_call_items:
                    original_name = norm_to_original.get(tc.function_name, tc.function_name)
                    label = tool_label_map.get(original_name, "unknown")
                    fn_result = await kernel.invoke(
                        plugin_name=_PLUGIN_NAME,
                        function_name=tc.function_name,
                        **_tc_arguments(tc),
                    )
                    result_text = str(fn_result) if fn_result is not None else json.dumps({"status": "ok"})
                    transcript.append(
                        {
                            "role": "tool",
                            "content": result_text,
                            "tool_name": original_name,
                            "mcp_server": label,
                            "_phase": phase.name,
                        }
                    )
                    chat_history.add_tool_message(result_text, tool_call_id=tc.id)

        finally:
            await legit_plugin.close()
            await mal_plugin.close()

    return transcript


def main() -> None:
    run_async_harness(run_single_phase, run_multi_phase)


if __name__ == "__main__":
    main()
