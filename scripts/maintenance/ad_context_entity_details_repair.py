#!/usr/bin/env python3
"""Bounded repair for AD directory details overwritten by supplemental imports."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.core.report_domain import report_domain_fqdn
from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment

APPLY_TOKEN = "APPLY-AD-CONTEXT-DIRECTORY-DETAILS-REPAIR"
ROLLBACK_TOKEN = "ROLLBACK-AD-CONTEXT-DIRECTORY-DETAILS-REPAIR"
SUPPLEMENTAL_SECTIONS = ("privileged_membership", "vpn_membership")


def _load_environment() -> None:
    if not (
        os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
        and os.getenv("ADLOG_PG_DSN", "").strip()
    ):
        load_supervisor_environment()


def _admin_dsn() -> str:
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    source = os.getenv("ADLOG_PG_DSN", "").strip()
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not user or not password:
        raise RuntimeError("protected_postgres_credentials_required")
    parts = conninfo_to_dict(source)
    parts.update(user=user, password=password)
    return make_conninfo(**parts)


def _admin_connect():
    import psycopg
    from psycopg.rows import dict_row

    _load_environment()
    return psycopg.connect(
        _admin_dsn(),
        autocommit=False,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="sli_ad_context_entity_details_repair",
        options="-c statement_timeout=120000 -c lock_timeout=5000",
    )


def _require_storage_owner(cursor: Any) -> dict[str, Any]:
    cursor.execute(
        """
        select session_user,current_user,
               pg_has_role(session_user,'adlog_storage_owner','MEMBER') as storage_owner,
               has_table_privilege(current_user,'entity_details_v2','UPDATE') as can_update
        """
    )
    identity = dict(cursor.fetchone() or {})
    if not identity.get("storage_owner"):
        raise PermissionError(
            "current PostgreSQL identity is not an approved storage owner member"
        )
    if not identity.get("can_update"):
        raise PermissionError(
            "current PostgreSQL identity cannot update entity_details_v2"
        )
    return {
        "session_user": str(identity["session_user"]),
        "current_user": str(identity["current_user"]),
        "storage_owner_member": True,
        "entity_details_update": True,
    }


def merge_directory_details(
    directory: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    return {**directory, **current}


def require_confirmation(actual: str | None, expected: str) -> None:
    if actual != expected:
        raise ValueError(f"confirmation token must equal {expected}")


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _sha(value: dict[str, Any]) -> bytes:
    return sha256(_json(value).encode("utf-8")).digest()


def _summary(cursor: Any, domain_dns: str) -> dict[str, int]:
    cursor.execute(
        """
        select count(*)::int as total_users,
               count(*) filter (
                 where details.attributes_json ? 'exact_last_logon_status'
               )::int as with_exact_status
        from entities_v2 entity
        join entity_details_v2 details on details.entity_id=entity.id
        join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
        join domains domain on domain.id=entity.domain_id
        where domain.fqdn=%s and entity_type.value='ad_user'
        """,
        (domain_dns,),
    )
    return dict(cursor.fetchone())


def _targets(cursor: Any, domain_dns: str) -> list[dict[str, Any]]:
    cursor.execute(
        """
        with latest_directory as (
          select distinct on (version.entity_id)
                 version.entity_id,
                 version.attributes_json->'attributes' as directory_attributes
          from ad_context_entity_versions version
          where version.source_section='directory_accounts'
            and version.attributes_json->'identity'->>'kind'='ad_user'
          order by version.entity_id, version.last_observed_at_utc desc, version.id desc
        )
        select entity.id as entity_id,
               details.attributes_json as current_attributes,
               latest.directory_attributes
        from entities_v2 entity
        join entity_details_v2 details on details.entity_id=entity.id
        join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
        join domains domain on domain.id=entity.domain_id
        join latest_directory latest on latest.entity_id=entity.id
        where domain.fqdn=%s and entity_type.value='ad_user'
          and not (details.attributes_json ? 'exact_last_logon_status')
          and latest.directory_attributes ? 'exact_last_logon_status'
        order by entity.id
        """,
        (domain_dns,),
    )
    return [dict(row) for row in cursor.fetchall()]


def plan(domain_dns: str) -> dict[str, Any]:
    with connect() as connection, connection.cursor() as cursor:
        summary = _summary(cursor, domain_dns)
        targets = _targets(cursor, domain_dns)
    missing = summary["total_users"] - summary["with_exact_status"]
    return {
        "action": "plan",
        "domain_dns": domain_dns,
        **summary,
        "missing_exact_status": missing,
        "repairable_targets": len(targets),
        "unrepairable_missing": missing - len(targets),
        "source_contacted": False,
        "database_modified": False,
    }


def _write_receipt(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temporary.replace(path)


def apply_repair(
    domain_dns: str,
    *,
    expected_targets: int,
    receipt_path: Path,
    connection_factory: Any = connect,
) -> dict[str, Any]:
    receipt: dict[str, Any]
    with connection_factory() as connection, connection.cursor() as cursor:
        database_identity = _require_storage_owner(cursor)
        summary = _summary(cursor, domain_dns)
        targets = _targets(cursor, domain_dns)
        missing = summary["total_users"] - summary["with_exact_status"]
        if len(targets) != expected_targets:
            raise RuntimeError("repair_target_count_mismatch")
        if missing != len(targets):
            raise RuntimeError("repair_has_unrepairable_missing_entities")
        entries: list[dict[str, Any]] = []
        for row in targets:
            current = dict(row["current_attributes"] or {})
            directory = dict(row["directory_attributes"] or {})
            merged = merge_directory_details(directory, current)
            cursor.execute(
                """
                update entity_details_v2
                set attributes_json=%s::jsonb,
                    source_details_sha256=%s,
                    migrated_at=now()
                where entity_id=%s and attributes_json=%s::jsonb
                """,
                (_json(merged), _sha(merged), row["entity_id"], _json(current)),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("repair_concurrent_entity_change")
            entries.append(
                {
                    "entity_id": int(row["entity_id"]),
                    "before_sha256": _sha(current).hex(),
                    "after_sha256": _sha(merged).hex(),
                }
            )
        verified = _summary(cursor, domain_dns)
        if verified["with_exact_status"] != verified["total_users"]:
            raise RuntimeError("repair_exact_status_verification_failed")
        receipt = {
            "version": "ad-context-entity-details-repair/v1",
            "status": "prepared",
            "domain_dns": domain_dns,
            "target_count": len(entries),
            "entries": entries,
        }
        _write_receipt(receipt_path, receipt)
    receipt["status"] = "applied"
    _write_receipt(receipt_path, receipt)
    return {
        "action": "apply",
        "domain_dns": domain_dns,
        "updated": len(receipt["entries"]),
        "total_users": verified["total_users"],
        "with_exact_status": verified["with_exact_status"],
        "receipt": str(receipt_path),
        "database_identity": database_identity,
        "source_contacted": False,
        "database_modified": True,
    }


def rollback_repair(
    receipt_path: Path,
    *,
    connection_factory: Any = connect,
) -> dict[str, Any]:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("version") != "ad-context-entity-details-repair/v1":
        raise ValueError("unsupported repair receipt")
    entries = list(receipt.get("entries") or [])
    domain_dns = str(receipt["domain_dns"])
    restored = 0
    with connection_factory() as connection, connection.cursor() as cursor:
        database_identity = _require_storage_owner(cursor)
        for entry in entries:
            cursor.execute(
                """
                select details.attributes_json as current_attributes,
                       version.attributes_json as supplemental_record
                from entity_details_v2 details
                join lateral (
                  select attributes_json
                  from ad_context_entity_versions
                  where entity_id=details.entity_id
                    and source_section = any(%s)
                  order by last_observed_at_utc desc, id desc
                  limit 1
                ) version on true
                where details.entity_id=%s
                """,
                (list(SUPPLEMENTAL_SECTIONS), entry["entity_id"]),
            )
            row = cursor.fetchone()
            if not row:
                raise RuntimeError("rollback_supplemental_version_missing")
            current = dict(row["current_attributes"] or {})
            if _sha(current).hex() != entry["after_sha256"]:
                raise RuntimeError("rollback_current_hash_mismatch")
            record = dict(row["supplemental_record"] or {})
            identity = dict(record.get("identity") or {})
            previous = {
                **dict(record.get("attributes") or {}),
                "object_guid": identity.get("object_guid"),
                "sid": identity.get("object_sid"),
            }
            if _sha(previous).hex() != entry["before_sha256"]:
                raise RuntimeError("rollback_reconstructed_hash_mismatch")
            cursor.execute(
                """
                update entity_details_v2
                set attributes_json=%s::jsonb,
                    source_details_sha256=%s,
                    migrated_at=now()
                where entity_id=%s and attributes_json=%s::jsonb
                """,
                (_json(previous), _sha(previous), entry["entity_id"], _json(current)),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("rollback_concurrent_entity_change")
            restored += 1
    receipt["status"] = "rolled_back"
    _write_receipt(receipt_path, receipt)
    return {
        "action": "rollback",
        "domain_dns": domain_dns,
        "restored": restored,
        "receipt": str(receipt_path),
        "database_identity": database_identity,
        "source_contacted": False,
        "database_modified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", help="report domain FQDN; defaults to the platform setting reports.domain_fqdn")
    parser.add_argument("--load-supervisor-environment", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--confirm")
    parser.add_argument("--expected-targets", type=int)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--use-admin-connection", action="store_true")
    args = parser.parse_args()
    if args.apply and args.rollback:
        raise ValueError("apply and rollback are mutually exclusive")
    if args.load_supervisor_environment:
        load_supervisor_environment(override_existing=True)
    if not args.rollback and not args.domain:
        args.domain = report_domain_fqdn()  # raises report_domain_not_configured when unset
    if args.apply:
        require_confirmation(args.confirm, APPLY_TOKEN)
        if (
            args.expected_targets is None
            or args.receipt is None
            or not args.use_admin_connection
        ):
            raise ValueError(
                "apply requires --expected-targets, --receipt, and --use-admin-connection"
            )
        result = apply_repair(
            args.domain,
            expected_targets=args.expected_targets,
            receipt_path=args.receipt.resolve(),
            connection_factory=_admin_connect,
        )
    elif args.rollback:
        require_confirmation(args.confirm, ROLLBACK_TOKEN)
        if args.receipt is None or not args.use_admin_connection:
            raise ValueError("rollback requires --receipt and --use-admin-connection")
        result = rollback_repair(
            args.receipt.resolve(), connection_factory=_admin_connect
        )
    else:
        result = plan(args.domain)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
