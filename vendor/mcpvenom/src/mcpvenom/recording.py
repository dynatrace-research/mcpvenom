# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

import json
from datetime import UTC, datetime
from pathlib import Path

from mcpvenom.models import Message, RunRecord

MAX_TRANSCRIPT_BYTES = 500 * 1024  # 500KB cap
DEFAULT_STORAGE_DIR = Path("~/.mcpvenom/runs").expanduser()


def save_transcript(
    storage_dir: Path,
    run_id: str,
    scenario_name: str,
    messages: list[Message],
) -> RunRecord:
    """Save a conversation transcript to disk.

    Raises ValueError if transcript exceeds 500KB.
    """
    record = RunRecord(
        run_id=run_id,
        scenario_name=scenario_name,
        messages=messages,
        recorded_at=datetime.now(tz=UTC),
    )

    data = record.model_dump(mode="json")
    payload = json.dumps(data, indent=2)
    size = len(payload.encode())

    if size > MAX_TRANSCRIPT_BYTES:
        raise ValueError(
            f"Transcript exceeds {MAX_TRANSCRIPT_BYTES // 1024}KB cap: {size // 1024}KB. "
            "Truncate messages before recording."
        )

    record.size_bytes = size

    run_dir = storage_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    transcript_path = run_dir / "transcript.json"
    transcript_path.write_text(payload)

    return record


def load_transcript(storage_dir: Path, run_id: str) -> RunRecord | None:
    """Load a transcript from disk by run ID."""
    transcript_path = storage_dir / run_id / "transcript.json"
    if not transcript_path.exists():
        return None

    data = json.loads(transcript_path.read_text())
    return RunRecord.model_validate(data)


def list_runs(storage_dir: Path) -> list[str]:
    """List all stored run IDs."""
    if not storage_dir.is_dir():
        return []
    return sorted(d.name for d in storage_dir.iterdir() if d.is_dir() and (d / "transcript.json").exists())
