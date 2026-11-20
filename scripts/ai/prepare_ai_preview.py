from __future__ import annotations

import argparse
import json
from pathlib import Path

from server.sli.access.data_redaction import build_ai_redaction_preview, render_ai_redaction_preview_report
from server.sli.core.paths import REPORTS_DIR


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare a redacted preview payload for a future AI security analysis.")
    parser.add_argument("--q", default=None, help="Search query: account, IP, host, LogonId, Event ID fragment.")
    parser.add_argument("--account", default=None, help="Account filter.")
    parser.add_argument("--event-id", default=None, help="Single Event ID filter.")
    parser.add_argument("--channel", default=None, help="Windows Event Log channel filter.")
    parser.add_argument("--server", action="append", default=[], help="Server filter. Can be repeated.")
    parser.add_argument("--time-from", default=None, help="UTC lower bound.")
    parser.add_argument("--time-to", default=None, help="UTC upper bound.")
    parser.add_argument("--limit", type=int, default=50, help="Preview event limit, capped by application rules.")
    parser.add_argument("--redaction-level", default="strict", choices=["strict", "balanced", "off"], help="Redaction profile.")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional JSON output path.")
    parser.add_argument("--html-out", type=Path, default=None, help="Optional HTML report output path.")
    args = parser.parse_args()

    data = build_ai_redaction_preview(
        q=args.q,
        account=args.account,
        event_id=args.event_id,
        channel=args.channel,
        servers=args.server,
        time_from=args.time_from,
        time_to=args.time_to,
        limit=args.limit,
        redaction_level=args.redaction_level,
    )
    json_out = args.json_out or REPORTS_DIR / "ai-redaction-preview.json"
    html_out = args.html_out or REPORTS_DIR / "ai-redaction-preview.html"
    json_out.parent.mkdir(parents=True, exist_ok=True)
    html_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    html_out.write_text(render_ai_redaction_preview_report(data), encoding="utf-8")
    print(json.dumps({"status": "ok", "json": str(json_out), "html": str(html_out), "events": data["source"]["preview_events"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
