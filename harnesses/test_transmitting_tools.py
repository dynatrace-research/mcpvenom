# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

"""Cross-check TRANSMITTING_TOOLS against scenario oracle declarations.

Catches cases where a scenario's exfiltration oracle names a specific tool
("Agent should NOT send the canary secret via <tool>") but that tool is absent
from TRANSMITTING_TOOLS, producing a guaranteed false negative.

Run: pytest harnesses/test_transmitting_tools.py -v
"""

import re
import sys
from pathlib import Path

import pytest
import yaml
from mcpvenom.scenarios import bundled_scenarios_dir

# Allow importing oracle without a full harness environment.
sys.path.insert(0, str(Path(__file__).parent))
from oracle import TRANSMITTING_TOOLS  # noqa: E402

_SCENARIOS_DIR = bundled_scenarios_dir()

_VIA_TOOL_RE = re.compile(r"\bvia\s+(\w+)")


def _exfil_tool_mentions() -> list[tuple[str, str]]:
    """Return (scenario_name, tool_name) for every tool named in an
    exfiltration oracle description via the pattern 'via <tool_name>'."""
    mentions = []
    for path in sorted(_SCENARIOS_DIR.glob("*.yaml")):
        sc = yaml.safe_load(path.read_text())
        for oracle in sc.get("oracles", []):
            if oracle.get("type") != "exfiltration":
                continue
            for m in _VIA_TOOL_RE.finditer(oracle.get("description", "")):
                mentions.append((path.stem, m.group(1)))
    return mentions


@pytest.mark.parametrize("scenario,tool", _exfil_tool_mentions())
def test_oracle_tool_in_transmitting_set(scenario: str, tool: str) -> None:
    """Every tool explicitly named as an exfil vector in a scenario oracle
    must be in TRANSMITTING_TOOLS, otherwise tool_call_exfil never fires
    for that tool and the verdict is silently RESISTANT."""
    assert tool in TRANSMITTING_TOOLS, (
        f"Scenario '{scenario}' declares '{tool}' as an exfiltration vector "
        f"in its oracle description, but '{tool}' is absent from "
        f"TRANSMITTING_TOOLS in oracle.py. "
        f"Either add '{tool}' to the frozenset or update the oracle description."
    )
