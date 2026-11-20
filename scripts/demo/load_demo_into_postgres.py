"""Load the synthetic demo world into a disposable PostgreSQL (plan 9.4).

Takes the output of ``generate_demo_events.py`` (one ``<DC>-<stamp>`` folder
per synthetic controller) and of ``generate_demo_ad_bundle.py`` and loads it
through the product's own paths:

1. records the first Storage V2 admission for an empty event store
   (``bootstrap_fresh_runtime_authorization``);
2. imports each controller folder with ``scripts/import/import_event_jsonl_to_postgres.py``;
3. imports the AD bundle with ``scripts/import/import_ad_context_bundle.py``.

The target must be a loopback PostgreSQL whose event store is empty and whose
only registered domain is ``example.test`` -- for example a clean install from
``config/postgres_baseline`` with that domain. Credentials come only from the
environment and are never printed:

- ``ADLOG_PG_DSN`` -- runtime DSN of the demo database (role ``adlog_user``);
- ``ADLOG_PG_ADMIN_USER`` / ``ADLOG_PG_ADMIN_PASSWORD`` -- an administrator of
  that cluster (Storage V2 worker and AD Context import roles are entered
  from it, as in the product).

Example::

    python scripts/demo/generate_demo_events.py --out D:/sli-demo/events --end 2026-10-01T00:00:00Z
    python scripts/demo/generate_demo_ad_bundle.py --out D:/sli-demo/ad --end 2026-10-01T00:00:00Z
    python scripts/demo/load_demo_into_postgres.py --events D:/sli-demo/events \
        --bundle D:/sli-demo/ad/ad-context-bundle.json
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEMO_DOMAIN = "example.test"
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class DemoLoadError(RuntimeError):
    pass


def _admin_connection():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    parts = conninfo_to_dict(os.environ.get("ADLOG_PG_DSN", ""))
    user = os.environ.get("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.environ.get("ADLOG_PG_ADMIN_PASSWORD", "")
    if not parts.get("dbname") or not user or not password:
        raise DemoLoadError("ADLOG_PG_DSN, ADLOG_PG_ADMIN_USER and ADLOG_PG_ADMIN_PASSWORD are required")
    if parts.get("host") not in _LOOPBACK:
        raise DemoLoadError("the demo database must be on a loopback address")
    parts.update(user=user, password=password)
    return psycopg.connect(**parts, row_factory=dict_row)


def check_target(cur) -> None:
    """Refuse anything but an empty store whose single domain is the demo domain."""
    cur.execute("select lower(fqdn) as fqdn from domains order by id")
    domains = [row["fqdn"] for row in cur.fetchall()]
    if domains != [DEMO_DOMAIN]:
        raise DemoLoadError(f"the demo database must have exactly one domain, {DEMO_DOMAIN}")
    cur.execute("select exists(select 1 from events_v2_core) as has_events")
    if cur.fetchone()["has_events"]:
        raise DemoLoadError("the event store is not empty; load the demo only into a clean database")


def admit_storage(cur, archive_root: Path) -> None:
    from server.sli.storage.storage_v2_runtime_authorization import (
        bootstrap_fresh_runtime_authorization,
        load_runtime_authorization,
    )

    if load_runtime_authorization(cur) is not None:
        return
    issued = datetime.now(timezone.utc)
    bootstrap_fresh_runtime_authorization(
        cur, archive_root=archive_root, authorized_by="demo-loader",
        issued_at=issued, expires_at=issued + timedelta(days=365),
    )


def _run(command: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(
        [sys.executable, *command], cwd=ROOT, env=environment,
        capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
    )
    output = result.stdout + result.stderr
    for secret in (environment.get("ADLOG_PG_ADMIN_PASSWORD"), environment.get("ADLOG_PG_DSN")):
        if secret:
            output = output.replace(secret, "***")
    if result.returncode != 0:
        raise DemoLoadError(f"{command[0]} failed: {output[-800:]}")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--events", type=Path, required=True, help="output folder of generate_demo_events.py")
    parser.add_argument("--bundle", type=Path, required=True, help="ad-context-bundle.json of generate_demo_ad_bundle.py")
    args = parser.parse_args(argv)
    folders = sorted(path for path in args.events.iterdir() if path.is_dir() and (path / "Security.jsonl").is_file())
    if not folders:
        raise DemoLoadError("no demo controller folders with Security.jsonl found")
    # Existing publication records keep their historical location; it is no
    # longer a separately configured prerequisite for importing demo data.
    from server.sli.core.paths import DATA_DIR

    archive_root = (DATA_DIR / "storage-v2-archive").resolve()

    with _admin_connection() as conn:
        with conn.cursor() as cur:
            check_target(cur)
            admit_storage(cur, archive_root)
        conn.commit()

    environment = dict(
        os.environ,
        ADLOG_DB_BACKEND="postgres",
        ADLOG_STORAGE_READ_MODE="v2",
        ADLOG_STORAGE_WRITE_MODE="v2",
        PYTHONUTF8="1",
    )
    summary: dict[str, object] = {"events": {}}
    for folder in folders:
        server = folder.name.split("-", 1)[0] + "." + DEMO_DOMAIN
        output = _run([
            "scripts/import/import_event_jsonl_to_postgres.py", "--input-dir", str(folder),
            "--forest", DEMO_DOMAIN, "--domain", DEMO_DOMAIN, "--server", server, "--backend", "postgres",
        ], environment)
        total = [line for line in output.splitlines() if line.startswith("total_inserted=")]
        summary["events"][server] = total[-1] if total else "imported"
    output = _run(["scripts/import/import_ad_context_bundle.py", str(args.bundle.resolve())], environment)
    start = output.find("{")
    summary["ad_context"] = json.loads(output[start:]) if start >= 0 else output.strip()
    print(json.dumps({"status": "ok", "domain": DEMO_DOMAIN, **summary}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except DemoLoadError as exc:
        print(f"demo load refused: {exc}", file=sys.stderr)
        raise SystemExit(2)
