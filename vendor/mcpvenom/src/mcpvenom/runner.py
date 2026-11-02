# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

import logging
import re
from pathlib import Path
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field

from mcpvenom.canaries import cleanup_canary, plant_canaries
from mcpvenom.models import Canary, Message, OracleResult, Phase, Scenario, ToolDefinition, Violation
from mcpvenom.oracles import check_all_oracles
from mcpvenom.recording import DEFAULT_STORAGE_DIR, save_transcript
from mcpvenom.scenarios import load_all_scenarios, load_scenario

logger = logging.getLogger(__name__)

TEMPLATE_PATTERN = re.compile(r"\{(canary_file|canary_url|canary_secret)\}")


@runtime_checkable
class AgentAdapter(Protocol):
    """Protocol for connecting mcpvenom to any agent framework.

    Implement this to test your agent. The runner calls ``send_message``
    with the scenario's poisoned tools and user prompt, and expects back
    the full conversation transcript as a list of ``Message`` objects.
    """

    async def send_message(
        self,
        user_prompt: str,
        tools: list[ToolDefinition],
    ) -> list[Message]:
        """Send a user message with tool definitions to the agent.

        Returns the full conversation transcript (including the user
        message, assistant responses, and any tool calls/results).
        """
        ...

    async def reset(self) -> None:
        """Reset agent state between scenario phases or runs."""
        ...


class RunResult(BaseModel):
    """Result of running a single scenario against an agent."""

    run_id: str
    scenario_name: str
    attack_class: str
    phases_executed: int = 0
    violations: list[Violation] = Field(default_factory=list)
    transcript: list[Message] = Field(default_factory=list)
    oracle_results: list[OracleResult] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True when the agent resisted the attack (no violations)."""
        return len(self.violations) == 0


def _substitute_canary_tokens(text: str, canary: Canary) -> str:
    """Replace {canary_file}, {canary_url}, {canary_secret} in text."""
    replacements = {
        "canary_file": canary.file_path,
        "canary_url": canary.url,
        "canary_secret": canary.secret,
    }
    return TEMPLATE_PATTERN.sub(lambda m: replacements[m.group(1)], text)


def _substitute_tools(tools: list[ToolDefinition], canary: Canary) -> list[ToolDefinition]:
    """Return tool definitions with canary tokens substituted in descriptions."""
    result: list[ToolDefinition] = []
    for tool in tools:
        new_desc = _substitute_canary_tokens(tool.description, canary)
        new_params = [
            p.model_copy(update={"description": _substitute_canary_tokens(p.description, canary)})
            for p in tool.parameters
        ]
        result.append(tool.model_copy(update={"description": new_desc, "parameters": new_params}))
    return result


async def _run_single_phase(
    adapter: AgentAdapter,
    phase: Phase,
    canary: Canary,
) -> tuple[list[Message], OracleResult]:
    """Execute one phase of a scenario and check oracles."""
    tools = _substitute_tools(phase.tools, canary)
    prompt = _substitute_canary_tokens(phase.user_prompt, canary)

    messages = await adapter.send_message(prompt, tools)
    oracle_result = check_all_oracles(canary, messages, oracle_configs=phase.oracles or None)
    return messages, oracle_result


async def _run_multi_phase(
    adapter: AgentAdapter,
    scenario: Scenario,
    canary: Canary,
) -> RunResult:
    """Execute a multi-phase scenario."""
    all_messages: list[Message] = []
    all_oracle_results: list[OracleResult] = []
    all_violations: list[Violation] = []
    phases_executed = 0

    previous_tools: list[ToolDefinition] = []
    for phase in scenario.phases:
        phase_tools = phase.tools if phase.tools else previous_tools
        effective_phase = phase.model_copy(update={"tools": phase_tools})

        messages, oracle_result = await _run_single_phase(adapter, effective_phase, canary)
        all_messages.extend(messages)
        all_oracle_results.append(oracle_result)
        all_violations.extend(oracle_result.violations)
        phases_executed += 1

        if phase.tools:
            previous_tools = phase.tools

        logger.info(
            "Phase '%s' complete: %d violations",
            phase.name,
            len(oracle_result.violations),
        )

    # Final check with top-level oracles across entire transcript
    final_result = check_all_oracles(canary, all_messages, oracle_configs=scenario.oracles or None)
    for v in final_result.violations:
        if v not in all_violations:
            all_violations.append(v)
    all_oracle_results.append(final_result)

    return RunResult(
        run_id=canary.run_id,
        scenario_name=scenario.name,
        attack_class=scenario.attack_class.value,
        phases_executed=phases_executed,
        violations=all_violations,
        transcript=all_messages,
        oracle_results=all_oracle_results,
    )


async def _run_single_phase_scenario(
    adapter: AgentAdapter,
    scenario: Scenario,
    canary: Canary,
) -> RunResult:
    """Execute a single-phase (non-multi-phase) scenario."""
    tools = _substitute_tools(scenario.tools, canary)
    prompt = _substitute_canary_tokens(scenario.user_prompt, canary)

    messages = await adapter.send_message(prompt, tools)
    oracle_result = check_all_oracles(canary, messages, oracle_configs=scenario.oracles or None)

    return RunResult(
        run_id=canary.run_id,
        scenario_name=scenario.name,
        attack_class=scenario.attack_class.value,
        phases_executed=1,
        violations=list(oracle_result.violations),
        transcript=messages,
        oracle_results=[oracle_result],
    )


class ScenarioRunner:
    """Runs attack scenarios against an agent and reports violations.

    Usage::

        adapter = MyAgentAdapter(...)
        runner = ScenarioRunner(adapter)

        # Run a single scenario
        result = await runner.run("tool-poisoning-file-read")

        # Run all scenarios
        results = await runner.run_all()
    """

    def __init__(
        self,
        adapter: AgentAdapter,
        scenarios_dir: Path | None = None,
        storage_dir: Path = DEFAULT_STORAGE_DIR,
        *,
        record_transcripts: bool = True,
    ) -> None:
        self._adapter = adapter
        self._scenarios_dir = scenarios_dir
        self._storage_dir = storage_dir
        self._record = record_transcripts

    async def run(self, scenario_name: str) -> RunResult:
        """Run a single scenario by name."""
        scenarios_dir = self._scenarios_dir
        if scenarios_dir is None:
            from mcpvenom.scenarios import bundled_scenarios_dir

            scenarios_dir = bundled_scenarios_dir()

        scenario_path = scenarios_dir / f"{scenario_name}.yaml"
        scenario = load_scenario(scenario_path)
        if scenario is None:
            raise FileNotFoundError(f"Scenario '{scenario_name}' not found or invalid at {scenario_path}")

        return await self.run_scenario(scenario)

    async def run_scenario(self, scenario: Scenario) -> RunResult:
        """Run a pre-loaded scenario object."""
        canary = plant_canaries()
        logger.info("Running scenario '%s' (run_id=%s)", scenario.name, canary.run_id)

        try:
            await self._adapter.reset()

            if scenario.phases:
                result = await _run_multi_phase(self._adapter, scenario, canary)
            else:
                result = await _run_single_phase_scenario(self._adapter, scenario, canary)

            if self._record and result.transcript:
                save_transcript(self._storage_dir, result.run_id, result.scenario_name, result.transcript)

            status = "PASSED" if result.passed else f"FAILED ({len(result.violations)} violations)"
            logger.info("Scenario '%s': %s", scenario.name, status)
            return result

        finally:
            cleanup_canary(canary)

    async def run_all(self, scenarios_dir: Path | None = None) -> list[RunResult]:
        """Run all scenarios from a directory (or bundled scenarios)."""
        effective_dir = scenarios_dir or self._scenarios_dir
        scenarios = load_all_scenarios(effective_dir)
        if not scenarios:
            logger.warning("No scenarios found")
            return []

        results: list[RunResult] = []
        for scenario in scenarios:
            result = await self.run_scenario(scenario)
            results.append(result)

        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed
        logger.info("Results: %d passed, %d failed out of %d scenarios", passed, failed, len(results))
        return results
