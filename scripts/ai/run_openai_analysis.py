from __future__ import annotations

import argparse
import json
from pathlib import Path

from server.sli.ai.ai_prompt_builder import build_ai_prompt_from_filters
from server.sli.ai.ai_provider import load_ai_provider_config, run_openai_analysis, write_ai_artifacts
from server.sli.ai.ai_reports import record_ai_run, update_report_file_with_run_id
from server.sli.ai.ai_schema import DEFAULT_OPENAI_MODEL
from server.sli.core.paths import REPORTS_DIR


def main() -> int:
    parser = argparse.ArgumentParser(description="Run OpenAI API analysis on a strict redacted security event payload.")
    parser.add_argument("--q", default=None, help="Search query: account, IP, host, LogonId, Event ID fragment.")
    parser.add_argument("--account", default=None, help="Account filter.")
    parser.add_argument("--event-id", default=None, help="Single Event ID filter.")
    parser.add_argument("--channel", default=None, help="Windows Event Log channel filter.")
    parser.add_argument("--server", action="append", default=[], help="Server filter. Can be repeated.")
    parser.add_argument("--time-from", default=None, help="UTC lower bound.")
    parser.add_argument("--time-to", default=None, help="UTC upper bound.")
    parser.add_argument("--limit", type=int, default=80, help="Event limit, capped by redaction rules.")
    parser.add_argument("--redaction-level", default="strict", choices=["strict", "balanced", "off"], help="Redaction profile. strict is recommended.")
    parser.add_argument("--allow-unsafe-redaction", action="store_true", help="Allow redaction-level=off for synthetic test data only.")
    parser.add_argument("--model", default=None, help="Override OpenAI model name.")
    parser.add_argument("--execute", action="store_true", help="Perform the OpenAI API call. Without this, only prompt/request/report are prepared.")
    parser.add_argument("--out-dir", type=Path, default=REPORTS_DIR, help="Output directory.")
    parser.add_argument("--prefix", default="ai-openai-analysis", help="Output file prefix.")
    args = parser.parse_args()

    config = load_ai_provider_config()
    model = args.model or config.model or DEFAULT_OPENAI_MODEL
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
        model=model,
        allow_unsafe_redaction=args.allow_unsafe_redaction,
    )
    result = run_openai_analysis(package, execute=args.execute, config=config)
    artifacts = write_ai_artifacts(package, result, out_dir=args.out_dir, prefix=args.prefix)
    run_id = record_ai_run(package, result, artifacts)
    update_report_file_with_run_id(artifacts.get("html"), run_id)
    print(json.dumps({"status": result["status"], "ai_call_performed": result["ai_call_performed"], "run_id": run_id, "artifacts": artifacts}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
