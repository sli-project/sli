from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.sli.ops.tls_client import tls_context_for_url  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="GET a local AD Log Reports API endpoint with a hard timeout.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--path", required=True)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--insecure", action="store_true",
        help="Explicitly allow an untrusted certificate for loopback HTTPS only.",
    )
    args = parser.parse_args()

    path = args.path if args.path.startswith("/") else "/" + args.path
    url = args.base_url.rstrip("/") + path
    try:
        context = tls_context_for_url(url, insecure=args.insecure)
        with urllib.request.urlopen(url, timeout=args.timeout, context=context) as response:
            raw = response.read()
            text = raw.decode("utf-8", errors="replace")
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                print(text)
                return 0 if 200 <= response.status < 300 else 1
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0 if 200 <= response.status < 300 else 1
    except urllib.error.URLError as exc:
        print(json.dumps({
            "status": "failed",
            "url": url,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "timeout_seconds": args.timeout,
        }, ensure_ascii=False, indent=2))
        return 1
    except Exception as exc:
        print(json.dumps({
            "status": "failed",
            "url": url,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "timeout_seconds": args.timeout,
        }, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
