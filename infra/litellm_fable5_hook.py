"""
LiteLLM custom callback for claude-fable-5.

Some Bedrock inference profiles require an account-wide data-retention mode
other than the default before they will serve requests. Setting that mode is an
ACCOUNT-WIDE, unrestored side effect — only ever safe on a dedicated, isolated
account. This hook therefore does nothing unless you explicitly opt in:

    MCPVENOM_ALLOW_BEDROCK_RETENTION_WRITE=1   # authorize the account-wide write
    MCPVENOM_BEDROCK_RETENTION_MODE=<mode>     # the retention mode to set

With neither set, the hook is a no-op and never mutates account state.
"""
import os
import threading

import boto3
from litellm.integrations.custom_logger import CustomLogger

FABLE5_MODEL = "claude-fable-5"
FABLE5_BEDROCK_ID = "us.anthropic.claude-fable-5"

_bedrock = boto3.client("bedrock", region_name="us-east-1")
_mode_set = False
_mode_lock = threading.Lock()


def _is_fable5(kwargs: dict) -> bool:
    model = kwargs.get("model", "")
    return (
        model == FABLE5_MODEL
        or model == FABLE5_BEDROCK_ID
        or model.endswith(f"/{FABLE5_MODEL}")
        or model.endswith(f"/{FABLE5_BEDROCK_ID}")
    )


def _ensure_fable5_mode() -> None:
    """Set the account retention mode once, only when explicitly opted in."""
    global _mode_set
    if _mode_set:
        return
    if os.environ.get("MCPVENOM_ALLOW_BEDROCK_RETENTION_WRITE") != "1":
        _mode_set = True  # opt-out: never write, never re-check
        return
    required_mode = os.environ.get("MCPVENOM_BEDROCK_RETENTION_MODE")
    if not required_mode:
        print("[fable5-hook] retention write enabled but MCPVENOM_BEDROCK_RETENTION_MODE unset; skipping")
        _mode_set = True
        return
    with _mode_lock:
        if _mode_set:
            return
        try:
            current = _bedrock.get_account_data_retention()["mode"]
            if current != required_mode:
                print(f"[fable5-hook] setting data retention: {current} → {required_mode}")
                _bedrock.put_account_data_retention(mode=required_mode)
            else:
                print(f"[fable5-hook] data retention already {required_mode}")
            _mode_set = True
        except Exception as exc:
            print(f"[fable5-hook] ERROR setting data retention: {exc}")


class Fable5DataRetentionHook(CustomLogger):
    def log_pre_api_call(self, model, messages, kwargs):
        if _is_fable5(kwargs):
            _ensure_fable5_mode()

    async def async_log_pre_api_call(self, model, messages, kwargs):
        if _is_fable5(kwargs):
            _ensure_fable5_mode()


fable5_hook = Fable5DataRetentionHook()
