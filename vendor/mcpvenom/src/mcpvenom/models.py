# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class AttackClass(StrEnum):
    TOOL_POISONING = "tool-poisoning"
    MEMORY_POISONING = "memory-poisoning"
    CONFUSED_DEPUTY = "confused-deputy"
    CROSS_AGENT_INJECTION = "cross-agent-injection"
    ANNOTATION_INJECTION = "annotation-injection"
    UNICODE_ENCODING = "unicode-encoding"
    STREAMING_INJECTION = "streaming-injection"
    VERSION_DOWNGRADE = "version-downgrade"  # legacy; kept for result JSON compatibility
    AUTHORITY_SPOOFING = "authority-spoofing"
    PARAMETER_BINDING = "parameter-binding"
    NOTIFICATION_INJECTION = "notification-injection"
    SEMANTIC_SHADOWING = "semantic-shadowing"
    LONG_CONTEXT_DILUTION = "long-context-dilution"
    CROSS_PHASE_PERSISTENCE = "cross-phase-persistence"
    DYNAMIC_REGISTRATION = "dynamic-registration"


class ToolParameter(BaseModel):
    name: str
    type: str = "string"
    description: str = ""
    required: bool = False


class ToolDefinition(BaseModel):
    name: str
    description: str = Field(description="Tool description — may contain malicious instructions in test scenarios")
    parameters: list[ToolParameter] = Field(default_factory=list)


class OracleType(StrEnum):
    FILE_ACCESS = "file_access"
    NETWORK = "network"
    EXFILTRATION = "exfiltration"
    UNAUTHORIZED_ACTION = "unauthorized_action"


class OracleConfig(BaseModel):
    type: OracleType
    description: str = ""
    allowed_tools: list[str] = Field(default_factory=list)


class Phase(BaseModel):
    """A phase in a multi-phase scenario (e.g., rug pull, kill chain)."""

    name: str
    tools: list[ToolDefinition] = Field(default_factory=list)
    user_prompt: str
    expected_behavior: str = ""
    oracles: list[OracleConfig] = Field(default_factory=list)


class Scenario(BaseModel):
    name: str
    description: str
    attack_class: AttackClass
    tools: list[ToolDefinition] = Field(default_factory=list)
    user_prompt: str = ""
    oracles: list[OracleConfig] = Field(default_factory=list)
    setup_instructions: str = ""
    phases: list[Phase] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check_phase_exclusion(self) -> "Scenario":
        if self.phases and (self.tools or self.user_prompt):
            msg = "Multi-phase scenarios must not define top-level 'tools' or 'user_prompt' — use phases instead"
            raise ValueError(msg)
        return self


class ScenarioSummary(BaseModel):
    name: str
    description: str
    attack_class: AttackClass
    oracle_types: list[OracleType] = Field(default_factory=list)


class Canary(BaseModel):
    run_id: str
    file_path: str
    url: str
    secret: str
    created_at: datetime


class Violation(BaseModel):
    oracle_type: OracleType
    description: str
    evidence: str = ""


class OracleResult(BaseModel):
    run_id: str
    violations: list[Violation] = Field(default_factory=list)
    checked_at: datetime


class Message(BaseModel):
    role: str
    content: str = ""
    tool_calls: list[dict[str, object]] | None = None


class RunRecord(BaseModel):
    run_id: str
    scenario_name: str
    messages: list[Message] = Field(default_factory=list)
    recorded_at: datetime
    size_bytes: int = 0
