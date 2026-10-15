# Copyright (c) Dynatrace LLC 2026 - present. All rights reserved.
# Licensed under the mcpvenom Distribution License, Version 1.0. See the LICENSE
# file for the full terms.

import re
from collections.abc import Iterable

MAX_DESCRIPTION_LENGTH = 500
IMPERATIVE_VERBS = (
    "call", "use", "invoke", "run", "execute", "send", "post", "read", "fetch", "upload",
    "transmit", "forward", "write", "append", "include", "log", "report", "ignore", "disregard", "override",
)
_URL = re.compile(r"https?://\S+|\{canary_url\}", re.IGNORECASE)
_BASE64_RUN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
_HEX_RUN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32,}(?![0-9a-fA-F])")
_SENTENCE_SPLIT = re.compile(r"[.!?\n]+")
_VERB = re.compile(r"\b(" + "|".join(IMPERATIVE_VERBS) + r")(?:s|ed|ing)?\b", re.IGNORECASE)


def _instruction_pattern(description: str, tool_names: Iterable[str]) -> bool:
    names = [re.compile(r"\b" + re.escape(n) + r"\b") for n in tool_names if n]
    for sentence in _SENTENCE_SPLIT.split(description):
        verb = _VERB.search(sentence)
        if verb is None:
            continue
        tail = sentence[verb.end():]
        if _URL.search(tail) or any(n.search(tail) for n in names):
            return True
    return False


def scan(description: str, tool_names: Iterable[str] = ()) -> set[str]:
    """Return the names of the registration-time checks a tool description trips.

    Checks are the three named in the paper: "instruction" (imperative verb followed in the
    same sentence by a served tool name or a URL), "encoded" (a base64 or hex run), and
    "length" (over MAX_DESCRIPTION_LENGTH characters).
    """
    fired: set[str] = set()
    if _instruction_pattern(description, tool_names):
        fired.add("instruction")
    if _BASE64_RUN.search(description) or _HEX_RUN.search(description):
        fired.add("encoded")
    if len(description) > MAX_DESCRIPTION_LENGTH:
        fired.add("length")
    return fired
