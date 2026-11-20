#!/usr/bin/env python3
"""Exercise storage-capacity retention only in a disposable loopback PostgreSQL 18."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import os
import re
import secrets
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.app_config import redact_dsn  # noqa: E402
from server.sli.storage.postgres_profile_retention import (  # noqa: E402
    execute_postgres_profile_retention,
)
from server.sli.storage.storage_policy import StoragePolicy  # noqa: E402


CONFIRMATION = "ACCEPT-DISPOSABLE-STORAGE-CAPACITY-PROFILE"
DISPOSABLE_CONTAINER = "sli-storage-capacity-pg18"
CONTAINER_PATTERN = re.compile(r"^sli-storage-capacity-pg18-[0-9]+-[0-9]+$")
VOLUME_PATTERN = re.compile(r"^sli-storage-capacity-pg18-data-[0-9]+-[0-9]+$")
OWNER_LABEL = "sli.storage-capacity-run"
DATABASE_PATTERN = re.compile(r"^sli_disposable_storage_capacity_[0-9]+_[0-9]+$")


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=30, check=False
    )
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()[-800:]
        raise RuntimeError(f"docker {' '.join(args[:2])} failed: {detail}")
    return result


def _connect(dsn: str):
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(
        dsn,
        autocommit=False,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="sli_storage_capacity_disposable_acceptance",
    )


def _start_cluster(*, container: str, volume: str, database: str, password: str, ownership: dict[str, Any]) -> str:
    from psycopg.conninfo import make_conninfo

    if not (
        CONTAINER_PATTERN.fullmatch(container)
        and VOLUME_PATTERN.fullmatch(volume)
        and DATABASE_PATTERN.fullmatch(database)
    ):
        raise RuntimeError("refusing unguarded disposable cluster identity")
    if _docker("container", "inspect", container, check=False).returncode == 0:
        raise RuntimeError("disposable container already exists")
    if _docker("volume", "inspect", volume, check=False).returncode == 0:
        raise RuntimeError("disposable volume already exists")
    # Creation can fail after Docker has created the resource. Mark attempts first,
    # but require the fresh per-run label before using or removing anything.
    ownership["volume_attempted"] = True
    _docker("volume", "create", "--label", f"{OWNER_LABEL}={ownership['token']}", volume)
    _owned_resource("volume", volume, ownership["token"])
    ownership["container_attempted"] = True
    _docker(
        "run", "--detach", "--name", container,
        "--label", "sli.purpose=storage-capacity-disposable",
        "--label", f"{OWNER_LABEL}={ownership['token']}",
        "--memory", "512m", "--cpus", "1.0", "--pids-limit", "128",
        "--pull", "never",
        "--env", "POSTGRES_USER=postgres",
        "--env", f"POSTGRES_PASSWORD={password}",
        "--env", f"POSTGRES_DB={database}",
        "--publish", "127.0.0.1:0:5432",
        "--volume", f"{volume}:/var/lib/postgresql",
        "postgres:18-alpine",
    )
    _owned_resource("container", container, ownership["token"])
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        mapped = _docker("port", container, "5432/tcp", check=False)
        if mapped.returncode == 0 and mapped.stdout.strip():
            dsn = make_conninfo(
                host="127.0.0.1",
                port=mapped.stdout.strip().rsplit(":", 1)[-1],
                dbname=database,
                user="postgres",
                password=password,
            )
            try:
                with _connect(dsn) as conn:
                    conn.execute("select 1")
                return dsn
            except Exception:  # noqa: BLE001
                pass
        time.sleep(0.3)
    raise RuntimeError("disposable PostgreSQL readiness timeout")


def _owned_resource(kind: str, name: str, token: str) -> dict[str, Any]:
    # A failed inspect is not proof of absence or ownership. Preserve the resource
    # and surface the uncertainty rather than guessing it is safe to remove.
    result = _docker(kind, "inspect", name)
    try:
        records = json.loads(result.stdout)
        resource = records[0] if len(records) == 1 else {}
        labels = resource.get("Config", {}).get("Labels") if kind == "container" else resource.get("Labels")
        if not token or not isinstance(labels, dict) or labels.get(OWNER_LABEL) != token:
            raise ValueError("ownership label mismatch")
        if kind == "container" and not resource.get("Id"):
            raise ValueError("missing immutable container identity")
        return resource
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise RuntimeError(f"cannot verify disposable {kind} ownership; preserving {name}") from exc


def _remove_cluster(*, container: str, volume: str, ownership: dict[str, Any]) -> None:
    if not (CONTAINER_PATTERN.fullmatch(container) and VOLUME_PATTERN.fullmatch(volume)):
        raise RuntimeError("refusing unguarded disposable cluster removal")
    errors = []
    for kind, name in (("container", container), ("volume", volume)):
        if not ownership.get(f"{kind}_attempted"):
            continue
        try:
            resource = _owned_resource(kind, name, ownership["token"])
            if kind == "container":
                # Delete the inspected ID, never a subsequently replaced name.
                _docker("rm", "--force", resource["Id"])
            else:
                # Volumes have no immutable ID; never force removal of an in-use volume.
                _docker("volume", "rm", name)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{kind}: {exc}")
    if errors:
        raise RuntimeError("disposable cleanup incomplete: " + "; ".join(errors))


def _bootstrap(dsn: str) -> None:
    with _connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            create table storage_v2_cutover_state(singleton boolean primary key,read_mode text not null);
            insert into storage_v2_cutover_state values(true,'v2');
            create table events_v2_core(id integer primary key,time_created_utc timestamptz not null);
            create table event_facts_v2(event_id integer primary key references events_v2_core(id) on delete cascade);
            create table entities_v2(id integer primary key);
            create table event_entity_link_blocks_v2(
              entity_id integer not null references entities_v2(id),block_no integer not null,
              first_event_id integer not null,last_event_id integer not null,event_ids integer[] not null,
              primary key(entity_id,block_no)
            );
            create table storage_v2_archive_blocks(
              archive_set_id uuid not null,archive_kind text not null,state text not null,
              first_event_id bigint not null,last_event_id bigint not null,
              primary key(archive_set_id,archive_kind)
            );
            insert into events_v2_core values(1,'2026-07-01T00:00:00Z');
            insert into event_facts_v2 values(1);
            insert into events_v2_core values(2,'2026-07-21T00:00:00Z');
            insert into event_facts_v2 values(2);
            insert into events_v2_core values(3,'2026-07-01T00:00:00Z');
            insert into event_facts_v2 values(3);
            insert into events_v2_core values(4,'2026-07-01T00:00:00Z');
            insert into event_facts_v2 values(4);
            insert into entities_v2 values(10);
            insert into event_entity_link_blocks_v2 values(10,0,2,2,array[2]);
            insert into event_entity_link_blocks_v2 values(10,1,3,3,array[3]);
            insert into storage_v2_archive_blocks values(
              '00000000-0000-0000-0000-000000000001','event','published',1,1
            );
            insert into storage_v2_archive_blocks values(
              '00000000-0000-0000-0000-000000000002','event','published',2,2
            );
            """
        )
        conn.commit()


def _count(conn: Any, statement: str) -> int:
    with conn.cursor() as cur:
        cur.execute(statement)
        return int((cur.fetchone() or {}).get("count") or 0)


def _accept(dsn: str) -> dict[str, Any]:
    policy = StoragePolicy(db_retention_days=7)
    now = datetime(2026, 8, 10, tzinfo=timezone.utc)
    with _connect(dsn) as conn:
        before = _count(conn, "select count(*)::bigint as count from events_v2_core")
        dry_run = execute_postgres_profile_retention(conn, policy=policy, now=now)
        after_dry = _count(conn, "select count(*)::bigint as count from events_v2_core")
        conn.rollback()
    with _connect(dsn) as conn:
        applied = execute_postgres_profile_retention(
            conn, policy=policy, now=now, apply=True, retention_apply_by_default=True
        )
        after_apply = _count(conn, "select count(*)::bigint as count from events_v2_core")
        facts_after_apply = _count(conn, "select count(*)::bigint as count from event_facts_v2")
        control_state_preserved = _count(
            conn, "select count(*)::bigint as count from storage_v2_cutover_state where read_mode='v2'"
        ) == 1
        conn.commit()
    with _connect(dsn) as conn:
        classified = execute_postgres_profile_retention(conn, policy=policy, now=now)
        linked_event_preserved = _count(conn, "select count(*)::bigint as count from events_v2_core where id=2") == 1
        post_horizon_link_event_preserved = _count(conn, "select count(*)::bigint as count from events_v2_core where id=3") == 1
        unarchived_event_preserved = _count(conn, "select count(*)::bigint as count from events_v2_core where id=4") == 1
        conn.rollback()
    result = {
        "dry_run_mutates_nothing": before == after_dry == 4 and dry_run.get("rows_deleted") == {"events_v2_core": 0},
        "mixed_candidates_delete_only_eligible": applied.get("rows_deleted") == {"events_v2_core": 1} and after_apply == 3 and facts_after_apply == 3,
        "control_state_preserved": control_state_preserved,
        "relationship_horizon_days": classified.get("relationship_horizon_days"),
        "in_horizon_link_hold": classified.get("held_by_reason", {}).get("held_by_relationship_horizon"),
        "in_horizon_link_event_preserved": linked_event_preserved,
        "post_horizon_link_hold": classified.get("held_by_reason", {}).get("held_by_other_dependency"),
        "post_horizon_link_event_preserved": post_horizon_link_event_preserved,
        "archive_hold": classified.get("held_by_reason", {}).get("held_by_archive_gap"),
        "unarchived_event_preserved": unarchived_event_preserved,
    }
    expected = {
        "dry_run_mutates_nothing": True,
        "mixed_candidates_delete_only_eligible": True,
        "control_state_preserved": True,
        "relationship_horizon_days": 30,
        "in_horizon_link_hold": 1,
        "in_horizon_link_event_preserved": True,
        "post_horizon_link_hold": 1,
        "post_horizon_link_event_preserved": True,
        "archive_hold": 1,
        "unarchived_event_preserved": True,
    }
    if result != expected:
        raise RuntimeError(f"disposable retention acceptance mismatch: {result}")
    return result


def run() -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    suffix = f"{os.getpid()}_{int(started_at.timestamp())}"
    container = f"{DISPOSABLE_CONTAINER}-{suffix.replace('_', '-')}"
    volume = f"sli-storage-capacity-pg18-data-{suffix.replace('_', '-')}"
    database = f"sli_disposable_storage_capacity_{suffix}"
    ownership: dict[str, Any] = {"token": secrets.token_hex(32)}
    try:
        dsn = _start_cluster(container=container, volume=volume, database=database, password=secrets.token_urlsafe(24), ownership=ownership)
        _bootstrap(dsn)
        acceptance = _accept(dsn)
        result = {
            "status": "passed", "generated_at_utc": started_at.isoformat(),
            "database": database, "dsn": redact_dsn(dsn), "acceptance": acceptance,
            "production_database_changed": False, "source_contacted": False,
            "collection_started": False, "runtime_changed": False,
        }
    finally:
        _remove_cluster(container=container, volume=volume, ownership=ownership)
    result["disposable_cluster_removed"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation", default="")
    args = parser.parse_args()
    if not args.execute or args.confirmation != CONFIRMATION:
        raise PermissionError(f"requires --execute --confirmation {CONFIRMATION}")
    print(json.dumps(run(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
