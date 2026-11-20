# SPDX-License-Identifier: Apache-2.0
"""Shared bounded per-agent collection control contract."""
from copy import deepcopy

DEFAULT_CONTROL = {"state": "active", "interval_seconds": 60, "batch_size": 32,
                   "rate_limit_per_minute": 120, "spool_max_bytes": 64 * 1024 * 1024,
                   "manage_windows_audit": False, "audit_process_command_line": False}


def collection_policy(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULT_CONTROL):
        raise ValueError("agent_collection_policy_invalid")
    policy = {**DEFAULT_CONTROL, **deepcopy(value)}
    if any(type(policy[key]) is not bool for key in ("manage_windows_audit", "audit_process_command_line")):
        raise ValueError("agent_collection_policy_invalid")
    if policy["state"] not in ("active", "paused", "drain"):
        raise ValueError("agent_collection_policy_invalid")
    for key, minimum, maximum in (("interval_seconds", 1, 86400), ("batch_size", 1, 128),
                                  ("rate_limit_per_minute", 1, 10000),
                                  ("spool_max_bytes", 65536, 1024 * 1024 * 1024)):
        n = policy[key]
        if type(n) is not int or not minimum <= n <= maximum:
            raise ValueError("agent_collection_policy_invalid")
    return policy
