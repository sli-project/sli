"""Compact snapshot differences; PostgreSQL confirmations fence hot expiry.

Only allowed field fingerprints survive. A confirmation is written after exact
ClickHouse readback, including empty baseline/pair batches. No raw snapshot is
copied into ClickHouse, and incomplete collections never prove deletions.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from server.ad_context.repository import (
    load_exact_projection_source,
    load_projection_manifest,
)
from server.sli.plugins.ad.snapshots.history_policy import (
    DEFAULT_DAYS,
    ENVIRONMENT,
    SETTING_KEY,
    history_days,
)
from server.sli.sources.ad_snapshot_projection import canonical_output_sha256
from server.sli.sources.gpo_v2_source import redact_gpo_snapshot
from server.sli.storage import permanent_fact_history as ch

TABLE = "sli_history.ad_snapshot_changes"
SCHEMA = ch.ROOT / "config/clickhouse/004_ad_snapshot_change_history.sql"
FAMILIES = ("users_v2", "computers_v6", "gpo_v2")
LOCK = "sli_ad_snapshot_change_history_v1"

# These are fields of the existing Users/Computers snapshot contracts, projected
# from the AD Context allowlist. Nested state/error/evidence blobs are excluded.
USER_FIELDS = frozenset({
    "name", "displayName", "givenName", "surname", "samAccountName", "userPrincipalName",
    "distinguishedName", "canonicalName", "ou", "enabled", "lockedOut", "accountExpirationDate",
    "whenCreated", "whenChanged", "department", "title", "company", "office", "description",
    "employeeID", "employeeNumber", "mail", "proxyAddresses", "telephoneNumber", "otherTelephones",
    "mobile", "ipPhone", "fax", "streetAddress", "city", "state", "postalCode", "country",
    "scriptPath", "homeDirectory", "homeDrive", "profilePath", "passwordLastSet", "passwordExpiry",
    "passwordExpired", "passwordNeverExpires", "passwordNotRequired", "cannotChangePassword",
    "lastLogonTimestamp", "exactLastLogon", "lastBadPasswordAttempt", "badPasswordCountAtQueryDc",
    "smartcardLogonRequired", "accountNotDelegated", "allowReversiblePasswordEncryption",
    "trustedForDelegation", "trustedToAuthForDelegation", "doesNotRequirePreAuth", "useDesKeyOnly",
    "adminCount", "servicePrincipalNames", "userAccountControl", "msDSSupportedEncryptionTypes",
})
COMPUTER_FIELDS = frozenset({
    "name", "dnsHostName", "enabled", "deviceType", "ipv4s", "ipv6s", "osName", "osVersion",
    "osBuild", "osFamily", "servicePack", "ou", "distinguishedName", "canonicalName", "adSite",
    "lastLogonTimestamp", "exactLastLogon", "passwordLastSet", "whenCreated", "whenChanged",
    "description", "location", "userAccountControl", "spns", "trustedForDelegation",
    "trustedToAuthForDelegation",
})
GROUP_FIELDS = frozenset({"name", "samAccountName", "distinguishedName", "canonicalName", "category", "scope"})
GPO_FIELDS = {
    "gpos": ("gpo", frozenset({"display_name", "gpo_status", "creation_time", "modification_time",
                                "wmi_filter_id", "computer_enabled", "user_enabled", "versions"})),
    "links": ("gpo_link", frozenset({"gpo_id", "scope_id", "enabled", "enforced", "order"})),
    "settings": ("gpo_setting", frozenset({"gpo_id", "side", "category", "setting_name", "path", "value_display"})),
    "scopes": ("gpo_scope", frozenset({"name", "scope_type", "canonical_path", "gpo_inheritance_blocked"})),
}


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _hash(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _stamp(value: Any) -> datetime:
    stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("snapshot_history_timestamp_requires_timezone")
    return stamp.astimezone(timezone.utc)


def _complete(snapshot: Mapping[str, Any]) -> bool:
    metadata = snapshot.get("metadata") or snapshot
    return (metadata.get("collection_status") in {"complete", "completed"}
            and all(state.get("status") == "observed" for state in (snapshot.get("source_states") or {}).values()))


def comparable_pair(previous: Mapping[str, Any], current: Mapping[str, Any]) -> bool:
    old_meta, new_meta = previous.get("metadata") or previous, current.get("metadata") or current
    return all(old_meta.get(key) == new_meta.get(key) for key in ("search_base", "domain", "domain_dn")) and (
        previous.get("scope") == current.get("scope"))


def _members(row: Mapping[str, Any]) -> set[tuple[str, str]] | None:
    memberships = row.get("memberships")
    if not isinstance(memberships, Mapping):
        return None
    if memberships.get("status", memberships.get("state")) not in {None, "observed", "complete", "completed"}:
        return None
    result = set()
    for kind in ("primary", "direct"):
        values = memberships.get(kind) or []
        if isinstance(values, Mapping):
            values = [values]
        for item in values:
            identity = (item.get("objectGuid") or item.get("id")) if isinstance(item, Mapping) else item
            if identity:
                result.add((kind, str(identity)))
    return result


def _objects(family: str, snapshot: Mapping[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    if family == "gpo_v2":
        snapshot = redact_gpo_snapshot(dict(snapshot))
        collections = GPO_FIELDS
    elif family == "users_v2":
        collections = {"users": ("ad_user", USER_FIELDS), "groups": ("ad_group", GROUP_FIELDS)}
    elif family == "computers_v6":
        collections = {"objects": ("ad_computer", COMPUTER_FIELDS)}
    else:
        raise ValueError("snapshot_history_family_invalid")
    objects = {}
    for collection, (kind, fields) in collections.items():
        for row in snapshot.get(collection) or []:
            identity = row.get("objectGuid") or row.get("guid") or row.get("id")
            if not identity:
                raise ValueError("snapshot_history_object_identity_missing")
            key = (kind, str(identity))
            if key in objects:
                raise ValueError("snapshot_history_object_identity_duplicate")
            # No arbitrary nested objects are retained or fingerprinted.
            attrs = {field: row[field] for field in fields if field in row and _scalar_sequence(row[field])}
            if kind == "ad_user" and isinstance(row.get("manager"), Mapping):
                attrs["manager"] = {key: row["manager"][key] for key in ("id", "objectGuid") if key in row["manager"]}
            if kind == "gpo":
                for side in ("computer", "user"):
                    attrs.update({f"{side}.{field}": value for field, value in (row.get(side) or {}).items()
                                  if field in {"enabled", "directory_version", "sysvol_version"} and _scalar_sequence(value)})
            state = (row.get("sourceStates") or {}).get("directory") or row.get("sourceState") or row.get("source_state")
            directory_observed = not state or state.get("status") == "observed"
            if not directory_observed:
                attrs = {}
            memberships = _members(row) if kind == "ad_user" and directory_observed else None
            if kind == "ad_group" and "parentGroupIds" in row and directory_observed:
                memberships = {("parent", str(item)) for item in row["parentGroupIds"]}
            objects[key] = {"attrs": attrs, "memberships": memberships,
                            "related_id": str(row.get("gpo_id") or "") if family == "gpo_v2" else ""}
    return objects


def _scalar_sequence(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool)) or (
        isinstance(value, list) and all(item is None or isinstance(item, (str, int, float, bool)) for item in value))


def extract_changes(family: str, previous: Mapping[str, Any], current: Mapping[str, Any]) -> list[dict[str, Any]]:
    before, after = _objects(family, previous), _objects(family, current)
    if not comparable_pair(previous, current):
        return []
    complete = _complete(previous) and _complete(current)
    rows = []

    def append(key, kind, field="", old=None, new=None, related_id=""):
        related_id = related_id or (after.get(key) or before[key])["related_id"]
        rows.append({"object_type": key[0], "object_id": key[1], "kind": kind, "field": field,
                     "related_object_id": related_id,
                     "before_sha256": _hash(old) if old is not None else "",
                     "after_sha256": _hash(new) if new is not None else ""})

    if complete:
        for key in sorted(before.keys() - after.keys()):
            append(key, "object_removed")
        for key in sorted(after.keys() - before.keys()):
            append(key, "object_added")
    for key in sorted(before.keys() & after.keys()):
        old, new = before[key], after[key]
        for field in sorted(old["attrs"].keys() & new["attrs"].keys()):
            if old["attrs"][field] != new["attrs"][field]:
                append(key, "attribute_changed", field, old["attrs"][field], new["attrs"][field])
        if old["memberships"] is not None and new["memberships"] is not None:
            if complete:
                for relation in sorted(old["memberships"] - new["memberships"]):
                    append(key, "membership_removed", relation[0], old=relation[1], related_id=relation[1])
            # Observed memberships of the same object confirm additions even
            # when another source makes the snapshot partial. Removals still
            # require a complete pair; unknown object memberships prove neither.
            for relation in sorted(new["memberships"] - old["memberships"]):
                append(key, "membership_added", relation[0], new=relation[1], related_id=relation[1])
    return rows


def ensure_schema(port: int) -> None:
    for statement in SCHEMA.read_text(encoding="utf-8").split(";"):
        if statement.strip():
            ch._http_query(port, statement.strip())


def publish_batch(port: int, batch: Mapping[str, Any]) -> None:
    records = batch["records"]
    # ReplacingMergeTree plus deterministic identities makes retries (including
    # an ambiguous HTTP timeout before the PostgreSQL commit) idempotent.
    if records:
        for offset in range(0, len(records), 1000):
            ch._http_insert_json_rows(port, TABLE, records[offset:offset + 1000])
    parameters = {"batch": batch["batch_id"]}
    scope = ""
    if records:
        parameters.update(domain=str(records[0]["domain_id"]), family=records[0]["family"],
                          observed=records[0]["observed_at"])
        scope = (" AND domain_id={domain:UInt64} AND family={family:String}"
                 " AND observed_at={observed:DateTime64(6)}")
    actual = ch._rows(port, f"SELECT record_id,payload_json,domain_id,family,observed_at FROM {TABLE} FINAL "
                      f"WHERE batch_id={{batch:String}}{scope} ORDER BY record_id",
                      query_params=parameters)
    expected = sorted((row["record_id"], row["payload_json"]) for row in records)
    if [(row["record_id"], row["payload_json"]) for row in actual] != expected:
        raise RuntimeError("snapshot_history_clickhouse_readback_mismatch")
    expected_rows = {row["record_id"]: row for row in records}
    for row in actual:
        expected_row = expected_rows[row["record_id"]]
        if (int(row["domain_id"]) != expected_row["domain_id"] or row["family"] != expected_row["family"]
                or ch._json_ch_time(row["observed_at"]) != expected_row["observed_at"]):
            raise RuntimeError("snapshot_history_clickhouse_identity_readback_mismatch")


def configured_days(connection: Any) -> int:
    # Destructive retention cannot silently fall back after a PostgreSQL error.
    with connection.cursor() as cursor:
        cursor.execute("select value from public.platform_settings where key=%s", (SETTING_KEY,))
        row = cursor.fetchone()
    value = row["value"] if row else os.environ.get(ENVIRONMENT) or DEFAULT_DAYS
    return int(history_days(value))


def _payload(connection: Any, manifest: Mapping[str, Any], family: str) -> tuple[dict, str]:
    member = next((row for row in manifest["members"] if row["family"] == family), None)
    if member is None:
        # GPO is optional in a partial manifest. Its absence cannot prove an
        # empty history batch or authorize source expiry.
        raise RuntimeError("snapshot_history_source_family_missing")
    payload = load_exact_projection_source(connection, family=family, source_id=str(member["source_id"]),
                                           payload_sha256=member["payload_sha256"])
    # Verify the actual bytes, not just the stored hash column.
    if canonical_output_sha256(payload) != member["payload_sha256"].lower():
        raise RuntimeError("snapshot_history_source_hash_mismatch")
    return payload, member["payload_sha256"].lower()


def publish_manifest(connection: Any, port: int, manifest_id: str) -> dict[str, Any]:
    with connection.cursor() as cursor:
        cursor.execute("select pg_advisory_xact_lock(hashtext(%s))", (LOCK,))
        cursor.execute("select domain_id,slot_start_utc from public.ad_snapshot_manifests "
                       "where manifest_id=%s::uuid", (manifest_id,))
        anchor = cursor.fetchone()
        if not anchor:
            raise ValueError("snapshot_history_manifest_missing")
        cursor.execute("select manifest_id from public.ad_snapshot_manifests "
                       "where domain_id=%s and slot_start_utc<%s order by slot_start_utc desc limit 1",
                       (anchor["domain_id"], anchor["slot_start_utc"]))
        previous_row = cursor.fetchone()
    current = load_projection_manifest(connection, manifest_id)
    previous_id = str(previous_row["manifest_id"]) if previous_row else None
    previous = load_projection_manifest(connection, previous_id) if previous_id else None
    records_written = 0
    for family in FAMILIES:
        if not any(member["family"] == family for member in current["members"]):
            # Optional absent families are not empty sources and get no receipt.
            continue
        with connection.cursor() as cursor:
            cursor.execute("select * from public.ad_snapshot_history_confirmations "
                           "where manifest_id=%s::uuid and family=%s", (manifest_id, family))
            confirmed = cursor.fetchone()
        if confirmed:
            # Confirmed pairs remain valid after their predecessor hot rows expire.
            continue
        payload, source_hash = _payload(connection, current, family)
        has_previous = previous is not None and any(member["family"] == family for member in previous["members"])
        old, old_hash = _payload(connection, previous, family) if has_previous else (None, None)
        changes = extract_changes(family, old, payload) if old is not None else []
        family_previous_id = previous_id if has_previous else None
        identity = {"manifest_id": str(manifest_id), "previous_manifest_id": family_previous_id,
                    "domain_id": int(anchor["domain_id"]), "family": family,
                    "source_sha256": source_hash, "previous_sha256": old_hash, "version": 1}
        batch_id = _hash(identity)
        records = []
        for change in changes:
            body = _json(change)
            records.append({"batch_id": batch_id, "record_id": _hash([batch_id, change]),
                            "domain_id": identity["domain_id"], "family": family,
                            "observed_at": ch._ch_time(_stamp(anchor["slot_start_utc"])), "payload_json": body})
        publish_batch(port, {"batch_id": batch_id, "records": records})
        pair_complete = old is not None and _complete(old) and _complete(payload) and comparable_pair(old, payload)
        if current.get("coverage_state") != "complete" or (previous and previous.get("coverage_state") != "complete"):
            pair_complete = False
        digest = _hash(sorted((row["record_id"], row["payload_json"]) for row in records))
        with connection.cursor() as cursor:
            cursor.execute("""insert into public.ad_snapshot_history_confirmations
                (manifest_id,family,domain_id,previous_manifest_id,source_sha256,previous_sha256,
                 batch_id,records_sha256,record_count,observed_at,coverage_state)
                values (%s::uuid,%s,%s,%s::uuid,%s,%s,%s,%s,%s,%s,%s)""",
                (manifest_id, family, identity["domain_id"], family_previous_id, source_hash, old_hash,
                 batch_id, digest, len(records), anchor["slot_start_utc"], "complete" if pair_complete else "partial"))
        records_written += len(records)
    return {"status": "confirmed", "records_published": records_written}


def purge_history(port: int, *, days: int, now: datetime) -> dict[str, Any]:
    days = int(history_days(str(days)))
    cutoff = _stamp(now) - timedelta(days=days)
    params = {"cutoff": ch._ch_time(cutoff)}
    count_sql = f"SELECT count() AS count FROM {TABLE} FINAL WHERE observed_at<{{cutoff:DateTime64(6)}}"
    before = int(ch._rows(port, count_sql, query_params=params)[0]["count"])
    ch._http_query(port, f"ALTER TABLE {TABLE} DELETE WHERE observed_at<{{cutoff:DateTime64(6)}} "
                   "SETTINGS mutations_sync=2", params={"param_cutoff": params["cutoff"]})
    if int(ch._rows(port, count_sql, query_params=params)[0]["count"]):
        raise RuntimeError("snapshot_history_retention_readback_failed")
    return {"deleted_records": before, "cutoff_utc": cutoff.isoformat(), "history_days": days}


def publish_agent_gpo_cycle(connection: Any, port: int, cycle_id: str) -> dict[str, Any]:
    """Preserve an independently published GPO cycle, without rewriting AD manifests."""
    with connection.cursor() as cursor:
        cursor.execute("select pg_advisory_xact_lock(hashtext(%s))", (LOCK,))
        cursor.execute("""select c.cycle_id::text,c.agent_id::text,c.slot_start_utc,c.policy,
            s.domain_id,s.source_run_id::text,encode(s.payload_sha256,'hex') as payload_sha256
            from public.sli_agent_snapshot_cycles c join public.gpo_report_v2_source_snapshots s
              on s.source_run_id=c.gpo_source_run_id
            join public.domains d on d.id=s.domain_id and d.domain_sid=c.domain_sid
              and d.domain_sid=c.policy->>'domain_sid' and lower(d.fqdn)=c.policy->>'domain_dns'
            where c.cycle_id=%s::uuid and c.module_id='sli.gpo-snapshot'
              and c.publication_state='published' and s.import_status='completed'""", (cycle_id,))
        current = cursor.fetchone()
        if not current:
            raise ValueError("snapshot_history_gpo_cycle_missing")
        cursor.execute("select 1 from public.ad_snapshot_history_confirmations "
                       "where manifest_id=%s::uuid and family='gpo_v2'", (cycle_id,))
        if cursor.fetchone():
            return {"status": "confirmed", "records_published": 0}
        # Inspect the immediately preceding capture, including failed/pending
        # cycles. A missing publication starts a baseline instead of skipping a gap.
        cursor.execute("""select c.cycle_id::text,c.policy,c.publication_state,s.domain_id,
            s.source_run_id::text,encode(s.payload_sha256,'hex') as payload_sha256
            from public.sli_agent_snapshot_cycles c left join public.gpo_report_v2_source_snapshots s
              on s.source_run_id=c.gpo_source_run_id and s.import_status='completed' and s.domain_id=%s
            where c.agent_id=%s::uuid and c.module_id='sli.gpo-snapshot' and c.slot_start_utc<%s
            order by c.slot_start_utc desc,c.cycle_id desc limit 1""",
            (current['domain_id'], current['agent_id'], current['slot_start_utc']))
        previous = cursor.fetchone()
    bound = ('source_instance_id', 'domain_sid', 'domain_dns', 'scope')
    if previous and (previous['publication_state'] != 'published'
            or previous['domain_id'] != current['domain_id']
            or any(previous['policy'].get(k) != current['policy'].get(k) for k in bound)):
        previous = None
    def payload(row):
        # source_run_id is unique only within a domain in the legacy store.
        with connection.cursor() as cursor:
            cursor.execute("select payload_json,encode(payload_sha256,'hex') as payload_sha256 "
                "from public.gpo_report_v2_source_snapshots where domain_id=%s "
                "and source_run_id=%s::uuid and import_status='completed'",
                (row['domain_id'], row['source_run_id']))
            stored = cursor.fetchone()
        if (not stored or stored['payload_sha256'] != row['payload_sha256']
                or canonical_output_sha256(stored['payload_json']) != row['payload_sha256']):
            raise RuntimeError('snapshot_history_source_hash_mismatch')
        return stored['payload_json']
    new = payload(current)
    old = payload(previous) if previous else None
    changes = extract_changes('gpo_v2', old, new) if old is not None else []
    identity = {'manifest_id': cycle_id, 'previous_manifest_id': previous['cycle_id'] if previous else None,
        'domain_id': current['domain_id'], 'family': 'gpo_v2', 'source_sha256': current['payload_sha256'],
        'previous_sha256': previous['payload_sha256'] if previous else None, 'version': 1}
    batch_id = _hash(identity)
    records = [{'batch_id': batch_id, 'record_id': _hash([batch_id, change]),
        'domain_id': current['domain_id'], 'family': 'gpo_v2',
        'observed_at': ch._ch_time(_stamp(current['slot_start_utc'])), 'payload_json': _json(change)} for change in changes]
    publish_batch(port, {'batch_id': batch_id, 'records': records})
    complete = old is not None and _complete(old) and _complete(new) and comparable_pair(old, new)
    with connection.cursor() as cursor:
        cursor.execute("""insert into public.ad_snapshot_history_confirmations
            (manifest_id,family,domain_id,previous_manifest_id,source_sha256,previous_sha256,
             batch_id,records_sha256,record_count,observed_at,coverage_state)
            values(%s::uuid,'gpo_v2',%s,%s::uuid,%s,%s,%s,%s,%s,%s,%s)""",
            (cycle_id, current['domain_id'], identity['previous_manifest_id'], identity['source_sha256'],
             identity['previous_sha256'], batch_id, _hash(sorted((r['record_id'], r['payload_json']) for r in records)),
             len(records), current['slot_start_utc'], 'complete' if complete else 'partial'))
    return {'status': 'confirmed', 'records_published': len(records)}


def run_cycle(*, port: int, apply_retention: bool, now: datetime, max_manifests: int = 16) -> dict[str, Any]:
    from server.sli.core.postgres_runtime_pipeline import connect

    published = 0
    with connect() as connection:
        with connection.cursor() as cursor:
            cursor.execute("select exists(select 1 from public.schema_migrations "
                           "where version=195 and name='ad_snapshot_history_composition') as admitted")
            if not cursor.fetchone()["admitted"]:
                raise RuntimeError("snapshot_history_migration_required")
            cursor.execute("select exists(select 1 from public.schema_migrations "
                           "where version=200 and name='agent_gpo_change_history') as admitted")
            agent_gpo_admitted = cursor.fetchone()['admitted']
            if agent_gpo_admitted:
                # Migration 200 compares the agent's text slot to timestamptz.
                # Wait for its repair before publishing or expiring any sources.
                cursor.execute("select exists(select 1 from public.schema_migrations "
                               "where version=204 and name='agent_gpo_history_slot_timestamp') as admitted")
                if not cursor.fetchone()['admitted']:
                    raise RuntimeError("snapshot_history_migration_required")
        ensure_schema(port)
        with connection.cursor() as cursor:
            cursor.execute("select pg_advisory_xact_lock(hashtext(%s))", (LOCK,))
            cursor.execute("""select m.manifest_id from public.ad_snapshot_manifests m
                where exists (select 1 from public.ad_snapshot_manifest_sources s
                  where s.manifest_id=m.manifest_id and s.family=any(%s::text[])
                  and not exists (select 1 from public.ad_snapshot_history_confirmations h
                    where h.manifest_id=m.manifest_id and h.family=s.family))
                order by m.slot_start_utc,m.manifest_id limit %s""", (list(FAMILIES), max_manifests))
            pending = list(cursor.fetchall())
        for row in pending:
            published += publish_manifest(connection, port, str(row["manifest_id"]))["records_published"]
        gpo_pending = []
        with connection.cursor() as cursor:
            if agent_gpo_admitted:
                cursor.execute("""select c.cycle_id from public.sli_agent_snapshot_cycles c
                    where c.module_id='sli.gpo-snapshot' and c.publication_state='published'
                      and not exists(select 1 from public.ad_snapshot_history_confirmations h
                        where h.manifest_id=c.cycle_id and h.family='gpo_v2')
                    order by c.slot_start_utc,c.cycle_id limit %s""", (max_manifests,))
                gpo_pending = list(cursor.fetchall())
        for row in gpo_pending:
            published += publish_agent_gpo_cycle(connection, port, str(row['cycle_id']))['records_published']
        days = configured_days(connection)
        with connection.cursor() as cursor:
            cursor.execute("""select exists(select 1 from public.ad_snapshot_manifests m
                where m.coverage_state='partial' or not exists(
                    select 1 from public.ad_snapshot_manifest_sources s
                    where s.manifest_id=m.manifest_id and s.family='gpo_v2')) as partial""")
            partial_coverage = cursor.fetchone()["partial"]
        # Commit preservation receipts before any expiry can reference them.
        connection.commit()
        retention = {"deleted_records": 0, "history_days": days}
        if apply_retention:
            retention = purge_history(port, days=days, now=now)
            with connection.cursor() as cursor:
                cursor.execute("select public.expire_ad_snapshot_history_confirmations_v165(%s)",
                               (_stamp(now) - timedelta(days=days),))
                retention["deleted_confirmations"] = cursor.fetchone()["expire_ad_snapshot_history_confirmations_v165"]
        connection.commit()
    return {"status": "partial" if len(pending) == max_manifests or len(gpo_pending) == max_manifests else "ok",
            "manifests_published": len(pending), "records_published": published,
            "gpo_cycles_published": len(gpo_pending),
            "coverage_state": "partial" if partial_coverage else "complete", **retention}
