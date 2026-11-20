"""Stateless, separately configured model roles; no provider SDK or credentials."""
from __future__ import annotations

import copy
import json
import subprocess
from collections import deque
from typing import Protocol

ROLES = {"persona_walker": "SLI_AUDIT_WALKER_COMMAND", "evaluator": "SLI_AUDIT_EVALUATOR_COMMAND"}


class ModelAdapter(Protocol):
    def invoke(self, role: str, request: dict, timeout_seconds: float) -> dict: ...


class OperatorModel:
    """Each invocation starts a fresh external argv command using JSON stdin/stdout.

    The operator manages provider, model, credentials and role/session isolation
    outside the repository. Commands receive only the role-specific request.
    Child output/errors and command arguments are never included in failures.
    """

    def __init__(self, env: dict):
        self.commands = {}
        for role, setting in ROLES.items():
            try:
                command = json.loads(env.get(setting, "null"))
            except (TypeError, ValueError):
                raise ValueError("model_adapter_configuration_required") from None
            if not isinstance(command, list) or not command or any(not isinstance(s, str) or not s for s in command):
                raise ValueError("model_adapter_configuration_required")
            self.commands[role] = command

    def invoke(self, role: str, request: dict, timeout_seconds: float) -> dict:
        if role not in ROLES or timeout_seconds <= 0:
            raise ValueError("model_role_or_budget_rejected")
        try:
            result = subprocess.run(self.commands[role], input=json.dumps({**request, "role": role}, ensure_ascii=False),
                                    text=True, encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=timeout_seconds, check=True)
            if len(result.stdout.encode("utf-8")) > 65536:
                raise ValueError("oversized_model_response")
            response = json.loads(result.stdout)
            if not isinstance(response, dict):
                raise ValueError("invalid_model_response")
            return response
        except (OSError, ValueError, subprocess.SubprocessError):
            raise RuntimeError("model_adapter_failed") from None


class FakeModel:
    def __init__(self, responses: list[dict]):
        self.responses = deque(copy.deepcopy(responses))
        self.requests = []

    def invoke(self, role: str, request: dict, timeout_seconds: float) -> dict:
        self.requests.append({"role": role, "request": copy.deepcopy(request), "timeout_seconds": timeout_seconds})
        if not self.responses:
            raise RuntimeError("fake_model_exhausted")
        return self.responses.popleft()
