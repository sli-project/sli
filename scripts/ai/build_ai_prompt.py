from __future__ import annotations

import argparse
import json
from pathlib import Path

from server.sli.ai.ai_prompt_builder import build_ai_prompt_from_filters, render_ai_prompt_preview_report
from server.sli.ai.ai_provider import build_ai_api_job
from server.sli.ai.ai_schema import DEFAULT_OPENAI_MODEL
from server.sli.core.paths import REPORTS_DIR


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a safe redacted prompt package for OpenAI API analysis without calling AI.")
    parser.add_argument("--q", default=None, help="Search query: account, IP, host, LogonId, Event ID fragment.")
    parser.add_argument("--account", default=None, help="Account filter.")
    parser.add_argument("--event-id", default=None, help="Single Event ID filter.")
    parser.add_argument("--channel", default=None, help="Windows Event Log channel filter.")
    parser.add_argument("--server", action="append", default=[], help="Server filter. Can be repeated.")
    parser.add_argument("--time-from", default=None, help="UTC lower bound.")
    parser.add_argument("--time-to", default=None, help="UTC upper bound.")
    parser.add_argument("--limit", type=int, default=80, help="Event limit, capped by redaction rules.")
    parser.add_argument("--redaction-level", default="strict", choices=["strict", "balanced", "off"], help="Redaction profile. strict is recommended.")
    parser.add_argument("--allow-unsafe-redaction", action="store_true", help="Allow prompt generation from redaction-level=off for isolated test data only.")
    parser.add_argument("--model", default=DEFAULT_OPENAI_MODEL, help="OpenAI model name.")
    parser.add_argument("--out-dir", type=Path, default=REPORTS_DIR, help="Output directory.")
    parser.add_argument("--prefix", default="ai-openai-prompt", help="Output file prefix.")
    args = parser.parse_args()

    package = build_ai_prompt_from_filters(
        q=args.q,
        account=args.account,
        event_id=args.event_id,
        channel=args.channel,
        servers=args.server,
        time_from=args.time_from,
        time_to=args.time_to,
        limit=args.limit,
        redaction_level=args.redaction_level,
        model=args.model,
        allow_unsafe_redaction=args.allow_unsafe_redaction,
    )
    job = build_ai_api_job(package)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = args.out_dir / f"{args.prefix}.txt"
    package_path = args.out_dir / f"{args.prefix}-package.json"
    request_path = args.out_dir / f"{args.prefix}-request.json"
    html_path = args.out_dir / f"{args.prefix}.html"
    prompt_path.write_text(package["prompt_text"], encoding="utf-8")
    package_path.write_text(json.dumps(package, ensure_ascii=False, indent=2), encoding="utf-8")
    request_path.write_text(json.dumps(job["request_body"], ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(render_ai_prompt_preview_report(package), encoding="utf-8")
    print(json.dumps({"status": "ok", "ai_call_performed": False, "prompt": str(prompt_path), "package": str(package_path), "request": str(request_path), "html": str(html_path)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
