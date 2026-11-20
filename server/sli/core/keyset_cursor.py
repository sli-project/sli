"""Small context-bound cursors; every continuation still requires authorization."""
from __future__ import annotations

import base64
import json
from hashlib import sha256
from typing import Any


def encode_cursor(context: Any, position: dict[str, Any]) -> str:
    binding = sha256(json.dumps(context, sort_keys=True, default=str).encode()).hexdigest()
    raw = json.dumps({"binding": binding, "position": position}, separators=(",", ":"), default=str).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(token: str, context: Any) -> dict[str, Any]:
    try:
        if not isinstance(token, str) or not token or len(token) > 2048:
            raise ValueError("invalid_cursor")
        value = json.loads(base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True))
        binding = sha256(json.dumps(context, sort_keys=True, default=str).encode()).hexdigest()
        if not isinstance(value, dict) or value.get("binding") != binding or not isinstance(value.get("position"), dict):
            raise ValueError("invalid_cursor")
        return value["position"]
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("invalid_cursor") from exc
