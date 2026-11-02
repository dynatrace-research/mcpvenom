# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

import importlib.resources
import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from mcpvenom.models import Scenario, ScenarioSummary

logger = logging.getLogger(__name__)


def bundled_scenarios_dir() -> Path:
    """Return the path to the bundled scenarios shipped with mcpvenom."""
    ref = importlib.resources.files("mcpvenom") / "scenarios"
    # importlib.resources may return a Traversable; resolve to a real path
    return Path(str(ref))


def load_scenario(path: Path) -> Scenario | None:
    """Load and validate a single scenario YAML file. Returns None if invalid."""
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        return Scenario.model_validate(data)
    except (yaml.YAMLError, ValidationError, OSError) as e:
        logger.warning("Invalid scenario %s: %s", path.name, e)
        return None


def load_all_scenarios(scenarios_dir: Path | None = None) -> list[Scenario]:
    """Load all valid scenarios from a directory.

    Falls back to bundled scenarios when no directory is specified.
    """
    if scenarios_dir is None:
        scenarios_dir = bundled_scenarios_dir()

    if not scenarios_dir.is_dir():
        logger.warning("Scenarios directory not found: %s", scenarios_dir)
        return []

    scenarios: list[Scenario] = []
    for path in sorted(scenarios_dir.glob("*.yaml")):
        scenario = load_scenario(path)
        if scenario:
            scenarios.append(scenario)

    return scenarios


def summarize(scenario: Scenario) -> ScenarioSummary:
    """Extract summary metadata from a scenario."""
    return ScenarioSummary(
        name=scenario.name,
        description=scenario.description,
        attack_class=scenario.attack_class,
        oracle_types=[o.type for o in scenario.oracles],
    )
