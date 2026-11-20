"""Compatibility import: agent and server use the same masking rules."""
from sli_agent.script_secrets import MASK_FAILED, mask_script_secrets

__all__ = ["MASK_FAILED", "mask_script_secrets"]
