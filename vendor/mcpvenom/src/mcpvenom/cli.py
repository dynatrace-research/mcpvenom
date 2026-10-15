# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

# Run: python -m mcpvenom.cli

import argparse
import json
import sys
from pathlib import Path

from mcpvenom.recording import DEFAULT_STORAGE_DIR, list_runs, load_transcript
from mcpvenom.scenarios import bundled_scenarios_dir, load_all_scenarios, load_scenario, summarize


def _cmd_list(args: argparse.Namespace) -> None:
    scenarios_dir = Path(args.scenarios_dir) if args.scenarios_dir else bundled_scenarios_dir()
    scenarios = load_all_scenarios(scenarios_dir)
    if not scenarios:
        print("No scenarios found.")
        return

    attack_classes: dict[str, list[str]] = {}
    for s in scenarios:
        attack_classes.setdefault(s.attack_class.value, []).append(s.name)

    print(f"Available scenarios ({len(scenarios)} total):\n")
    for cls, names in sorted(attack_classes.items()):
        print(f"  {cls} ({len(names)}):")
        for name in names:
            summary = next(summarize(s) for s in scenarios if s.name == name)
            oracles = ", ".join(o.value for o in summary.oracle_types)
            print(f"    {name:<40} [{oracles}]")
        print()


def _cmd_info(args: argparse.Namespace) -> None:
    scenarios_dir = Path(args.scenarios_dir) if args.scenarios_dir else bundled_scenarios_dir()
    scenario_path = scenarios_dir / f"{args.name}.yaml"
    scenario = load_scenario(scenario_path)

    if scenario is None:
        available = [p.stem for p in scenarios_dir.glob("*.yaml")]
        print(f"Scenario '{args.name}' not found.", file=sys.stderr)
        print(f"Available: {', '.join(sorted(available))}", file=sys.stderr)
        sys.exit(1)

    print(f"Name:         {scenario.name}")
    print(f"Attack class: {scenario.attack_class.value}")
    print(f"Description:  {scenario.description.strip()}")
    print(f"Oracles:      {', '.join(o.type.value for o in scenario.oracles)}")

    if scenario.phases:
        print(f"\nPhases ({len(scenario.phases)}):")
        for i, phase in enumerate(scenario.phases, 1):
            tools_str = ", ".join(t.name for t in phase.tools) if phase.tools else "(inherits previous)"
            print(f"  {i}. {phase.name}: tools=[{tools_str}]")
            print(f"     prompt: {phase.user_prompt[:80]}...")
            if phase.expected_behavior:
                print(f"     expected: {phase.expected_behavior[:80]}...")
    else:
        print(f"\nTools:        {', '.join(t.name for t in scenario.tools)}")
        print(f"User prompt:  {scenario.user_prompt[:120]}...")

    if scenario.setup_instructions:
        print(f"\nSetup:\n{scenario.setup_instructions.strip()}")


def _cmd_results(args: argparse.Namespace) -> None:
    storage_dir = Path(args.storage_dir) if args.storage_dir else DEFAULT_STORAGE_DIR

    if args.run_id:
        record = load_transcript(storage_dir, args.run_id)
        if record is None:
            print(f"No transcript found for run_id '{args.run_id}'.", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(record.model_dump(mode="json"), indent=2, default=str))
    else:
        runs = list_runs(storage_dir)
        if not runs:
            print("No recorded runs found.")
            return
        print(f"Recorded runs ({len(runs)}):\n")
        for run_id in runs:
            record = load_transcript(storage_dir, run_id)
            if record:
                print(f"  {run_id}  scenario={record.scenario_name}  messages={len(record.messages)}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcpvenom",
        description="Behavioral security testing for MCP-based AI agents",
    )
    parser.add_argument("--scenarios-dir", help="Custom scenarios directory")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List available attack scenarios")

    info_parser = sub.add_parser("info", help="Show scenario details")
    info_parser.add_argument("name", help="Scenario name")

    results_parser = sub.add_parser("results", help="Show recorded test results")
    results_parser.add_argument("run_id", nargs="?", help="Specific run ID (omit for all)")
    results_parser.add_argument("--storage-dir", help="Custom storage directory")

    args = parser.parse_args()
    if args.command == "list":
        _cmd_list(args)
    elif args.command == "info":
        _cmd_info(args)
    elif args.command == "results":
        _cmd_results(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
