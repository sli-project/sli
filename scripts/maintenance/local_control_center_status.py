#!/usr/bin/env python3
"""Read-only loopback status for the native SLI Control Center."""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WEB_URL = "http://127.0.0.1:8080/api/health"
MAX_TIMEOUT_SECONDS = 5.0


def _bounded_timeout(value: float) -> float:
    if not math.isfinite(value):
        return MAX_TIMEOUT_SECONDS
    return min(MAX_TIMEOUT_SECONDS, max(0.1, value))


def _redacted_loopback_endpoint(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        return None
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", "", ""))


def _probe_loopback_health(url: str, timeout_seconds: float) -> dict[str, object]:
    endpoint = _redacted_loopback_endpoint(url)
    if endpoint is None:
        return {
            "state": "unknown",
            "endpoint": "[invalid-or-non-loopback-endpoint]",
            "evidence": "Health probe skipped: only loopback HTTP(S) endpoints are allowed.",
        }
    try:
        request = urllib.request.Request(endpoint, method="GET")
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            if 200 <= response.status < 300:
                return {
                    "state": "healthy",
                    "endpoint": endpoint,
                    "evidence": f"Loopback health endpoint returned HTTP {response.status}.",
                }
            return {
                "state": "unknown",
                "endpoint": endpoint,
                "evidence": f"Loopback health endpoint returned HTTP {response.status}.",
            }
    except urllib.error.HTTPError as exc:
        return {
            "state": "unknown",
            "endpoint": endpoint,
            "evidence": f"Loopback health endpoint returned HTTP {exc.code}.",
        }
    except (urllib.error.URLError, TimeoutError, OSError):
        return {
            "state": "unavailable",
            "endpoint": endpoint,
            "evidence": "Loopback health endpoint could not be reached.",
        }
    except Exception:
        return {
            "state": "unknown",
            "endpoint": endpoint,
            "evidence": "Loopback health endpoint check failed without confirming runtime state.",
        }


def status(web_url: str, timeout_seconds: float) -> dict[str, object]:
    """Return the V1 redacted status contract without lifecycle side effects."""
    return {
        "contract_version": "local-control-center-status.v1",
        "action": "status",
        "safety": {
            "read_only": True,
            "process_control": "not_supported",
            "database_writes": False,
            "source_collection": False,
            "secret_values_exposed": False,
            "network_scope": "loopback health endpoint only",
        },
        "components": {
            "local_web_runtime": _probe_loopback_health(
                web_url, _bounded_timeout(timeout_seconds)
            ),
            "lifecycle_control": {
                "state": "unknown",
                "evidence": "V1 does not infer stopped state or start, stop, or restart processes.",
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only local Control Center status.")
    parser.add_argument("--json", action="store_true", help="print the JSON contract")
    parser.add_argument(
        "--web-url",
        default=os.environ.get("SLI_CONTROL_CENTER_WEB_URL", DEFAULT_WEB_URL),
        help="loopback HTTP(S) health URL",
    )
    parser.add_argument("--timeout", type=float, default=2.0, help="bounded probe timeout")
    parser.add_argument("command", choices=("status",))
    args = parser.parse_args()
    result = status(args.web_url, args.timeout)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
