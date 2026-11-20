"""Durable projection of approximate domain-user logons to Computers V6 workstations."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import Any, Callable, Mapping
from zoneinfo import ZoneInfo

from server.sli.sources.computers_v6_source import load_latest_computers_v6_source_snapshot
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.storage.storage_v2_models import event_source_core_sha256
from server.sli.reports.users_reporting import classify_service_account
from server.source_packs.windows_ad_dc import event_ids_for_analysis_family
from server.sli.core.report_domain import NOT_CONFIGURED_CODE, ReportDomainNotConfiguredError, report_domain_fqdn

REPORT_TIMEZONE = ZoneInfo("Asia/Novosibirsk")
WORKER_NAME = "what_where_when_projection"
SYSTEM_SIDS = frozenset({"S-1-5-18", "S-1-5-19", "S-1-5-20"})
SYSTEM_NAMES = frozenset({"system", "local service", "network service", "anonymous logon"})
SUCCESS_LOGON_TYPES = frozenset({"2", "3", "4", "5", "7", "8", "9", "10", "11"})
MAX_BATCH_LIMIT = 10_000
MAX_RETENTION_LIMIT = 50_000
MAX_DOMAIN_CONTROLLER_SERVER_IDS = 1_000
ARCHIVE_BLOCKS_PER_CYCLE = 8
_SUCCESSFUL_LOGON_EVENT_IDS = event_ids_for_analysis_family("successful_logon")
if len(_SUCCESSFUL_LOGON_EVENT_IDS) != 1:
    raise RuntimeError("successful_logon_event_id_must_be_singleton")
SUCCESSFUL_LOGON_EVENT_ID = _SUCCESSFUL_LOGON_EVENT_IDS[0]


def _name(value: Any) -> str:
    return str(value or "").strip().rstrip(".").casefold()


def _hourly_observation_key(observation: Mapping[str, Any]) -> tuple[str, str, datetime]:
    """Return the one-hour report bucket for one resolved user/computer observation."""
    observed = observation.get("observed_at_utc")
    if not isinstance(observed, datetime) or observed.tzinfo is None:
        raise ValueError("observation_timezone_required")
    local_hour = observed.astimezone(REPORT_TIMEZONE).replace(minute=0, second=0, microsecond=0, tzinfo=None)
    return (
        str(observation["computer_object_guid"]).casefold(),
        str(observation["user_name"]).strip().lower(),
        local_hour,
    )


def _ip(value: Any) -> str | None:
    raw = str(value or "").strip()
    if not raw or raw == "-":
        return None
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return address.compressed.casefold()


def _hash_bytes(value: Any, *, fallback: Mapping[str, Any] | None = None) -> bytes:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes) and len(value) == 32:
        return value
    if isinstance(value, str):
        try:
            decoded = bytes.fromhex(value)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass
    if fallback is None:
        raise ValueError("source_event_hash_invalid")
    encoded = json.dumps(dict(fallback), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).digest()


def load_computer_match_index(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Build collision-preserving name/IP indexes from workstation objects."""
    document = snapshot.get("snapshot") if isinstance(snapshot.get("snapshot"), Mapping) else snapshot
    names: dict[str, set[str]] = {}
    ips: dict[str, set[str]] = {}
    computers: dict[str, dict[str, Any]] = {}
    for raw in document.get("objects") or []:
        item = dict(raw)
        device_type = _name(item.get("deviceType") or item.get("device_type"))
        if device_type not in {"workstation", "рабочая станция", "desktop", "laptop"}:
            continue
        guid = str(item.get("objectGuid") or item.get("object_guid") or "").strip().lower()
        if not guid:
            continue
        display = str(item.get("name") or item.get("dnsHostName") or guid).strip().rstrip(".")
        computers[guid] = {"computer_object_guid": guid, "computer_name": display}
        for candidate in (item.get("name"), item.get("dnsHostName"), item.get("dns_host_name")):
            normalized = _name(candidate)
            if normalized:
                names.setdefault(normalized, set()).add(guid)
                if "." in normalized:
                    names.setdefault(normalized.split(".", 1)[0], set()).add(guid)
        for candidate in [*(item.get("ipv4s") or []), *(item.get("ipv6s") or []), *(item.get("ip_addresses") or [])]:
            normalized_ip = _ip(candidate)
            if normalized_ip:
                ips.setdefault(normalized_ip, set()).add(guid)
    return {"names": names, "ips": ips, "computers": computers}


def _filter_reason(event: Mapping[str, Any], service_accounts: Mapping[str, bool]) -> str | None:
    if int(event["event_id"] if event.get("event_id") is not None else SUCCESSFUL_LOGON_EVENT_ID) != SUCCESSFUL_LOGON_EVENT_ID:
        return "not_successful_logon_event"
    sid = str(event.get("target_user_sid") or "").strip().upper()
    user = str(event.get("target_user_name") or "").strip()
    normalized_user = user.casefold()
    if not user:
        return "user_missing"
    if sid in SYSTEM_SIDS or normalized_user in SYSTEM_NAMES:
        return "system_account"
    if user.endswith("$"):
        return "machine_account"
    logon_type = str(event.get("logon_type") or "").strip()
    if logon_type and logon_type not in SUCCESS_LOGON_TYPES:
        return "logon_type_not_user_success"
    lookup = normalized_user.rsplit("\\", 1)[-1]
    if lookup not in service_accounts:
        return "classification_unknown"
    if service_accounts[lookup]:
        return "service_account"
    return None


def project_event(
    event: Mapping[str, Any],
    computer_index: Mapping[str, Any],
    service_accounts: Mapping[str, bool],
) -> dict[str, Any]:
    """Classify one already-successful Security logon event without database I/O."""
    reason = _filter_reason(event, service_accounts)
    if reason:
        return {"status": "filtered", "reason": reason}
    by_name = set(computer_index["names"].get(_name(event.get("workstation_name")), set()))
    normalized_ip = _ip(event.get("ip_address"))
    by_ip = set(computer_index["ips"].get(normalized_ip, set())) if normalized_ip else set()
    if by_name and by_ip and by_name != by_ip:
        return {"status": "ambiguous", "reason": "name_ip_conflict"}
    candidates = by_name | by_ip
    if not candidates:
        return {"status": "unmatched", "reason": "computer_not_resolved"}
    if len(candidates) != 1:
        return {"status": "ambiguous", "reason": "computer_identity_not_unique"}
    guid = next(iter(candidates))
    computer = computer_index["computers"][guid]
    target_domain = str(event.get("target_domain_name") or "").strip()
    target_user = str(event.get("target_user_name") or "").strip()
    user_name = f"{target_domain}\\{target_user}" if target_domain else target_user
    observed = event.get("observed_at_utc") or event.get("time_created_utc")
    if not isinstance(observed, datetime):
        observed = datetime.fromisoformat(str(observed).replace("Z", "+00:00"))
    if observed.tzinfo is None:
        raise ValueError("event_observation_timezone_required")
    return {
        "status": "observation",
        "observation": {
            "source_event_id": int(event["source_event_id"]),
            "source_event_hash": _hash_bytes(event.get("source_event_hash"), fallback=event),
            "computer_object_guid": computer["computer_object_guid"],
            "computer_name": computer["computer_name"],
            "user_name": user_name,
            "observed_at_utc": observed.astimezone(timezone.utc),
        },
    }


def _canonical_hash(payload: Mapping[str, Any]) -> bytes:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).digest()


def _load_service_accounts(connection: Any, domain_id: int) -> tuple[int, dict[str, bool]]:
    with connection.cursor() as cur:
        cur.execute(
            """select snapshot_id,payload_json,payload_sha256
                 from users_report_v2_snapshots
                where domain_id=%s and source_state in ('complete','partial')
                order by captured_at_utc desc,snapshot_id desc limit 1""",
            (domain_id,),
        )
        row = cur.fetchone()
    if not row:
        raise RuntimeError("what_where_when_users_snapshot_unavailable")
    data = dict(row)
    payload = data["payload_json"] if isinstance(data["payload_json"], Mapping) else json.loads(data["payload_json"])
    if _hash_bytes(data["payload_sha256"]) != _canonical_hash(payload):
        raise RuntimeError("what_where_when_users_snapshot_hash_mismatch")
    classified: dict[str, bool] = {}
    for item in payload.get("users") or []:
        sam = str(item.get("samAccountName") or item.get("sam_account_name") or "").strip()
        if not sam:
            continue
        attrs = {
            "sam_account_name": sam,
            "user_principal_name": item.get("userPrincipalName") or item.get("user_principal_name"),
            "display_name": item.get("displayName") or item.get("display_name"),
            "distinguished_name": item.get("distinguishedName") or item.get("distinguished_name"),
        }
        classified[sam.casefold()] = classify_service_account(attrs, natural_key=sam)[0]
    return int(data["snapshot_id"]), classified


def _event_data(row: Mapping[str, Any]) -> dict[str, Any]:
    raw = row.get("event_data_json") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            raw = {}
    return dict(raw) if isinstance(raw, Mapping) else {}


def _normalize_source_event(row: Mapping[str, Any]) -> dict[str, Any]:
    data = _event_data(row)
    source_event_hash = row.get("source_event_hash")
    if source_event_hash is None:
        source_event_hash = row.get("source_core_sha256")
    if source_event_hash is None:
        source_event_hash = event_source_core_sha256(row)
    return {
        "source_event_id": int(row.get("source_event_id") or row.get("id")),
        "source_event_hash": source_event_hash,
        "event_id": int(row["event_id"] if row.get("event_id") is not None else SUCCESSFUL_LOGON_EVENT_ID),
        "observed_at_utc": row.get("observed_at_utc") or row.get("time_created_utc"),
        "target_user_sid": row.get("target_user_sid") or data.get("TargetUserSid"),
        "target_user_name": row.get("target_user_name") or data.get("TargetUserName"),
        "target_domain_name": row.get("target_domain_name") or data.get("TargetDomainName"),
        "workstation_name": row.get("workstation_name") or data.get("WorkstationName"),
        "ip_address": row.get("ip_address") or data.get("IpAddress"),
        "logon_type": row.get("logon_type") or data.get("LogonType"),
    }


@dataclass(frozen=True)
class _SourceBatch:
    events: list[dict[str, Any]]
    scanned_through: int
    exhausted: bool


@dataclass(frozen=True)
class BackfillBatch:
    events: list[dict[str, Any]]
    scanned_through: int
    archive_exhausted: bool
    hot_exhausted: bool

    @property
    def backfill_completed(self) -> bool:
        return self.archive_exhausted and self.hot_exhausted


@dataclass(frozen=True)
class _DomainControllerMembership:
    server_ids: frozenset[int]
    stable_name_owners: Mapping[str, frozenset[int]]


def _load_hot_events(cur: Any, *, domain_id: int, cutoff: datetime, after_id: int, limit: int) -> _SourceBatch:
    cur.execute(
        """select event.id as source_event_id,event.source_core_sha256 as source_event_hash,
                  event.time_created_utc as observed_at_utc,event.event_id,event.target_user_sid,
                  event.target_user_name,target_domain.value as target_domain_name,
                  event.workstation_name,event.ip_address,facts.logon_type
             from events_v2_core event
             join servers server on server.id=event.server_id and server.role='domain_controller'
             join storage_v2_channel channel on channel.id=event.channel_id and lower(channel.value)='security'
             left join storage_v2_domain_name target_domain on target_domain.id=event.target_domain_id
             left join event_facts_v2 facts on facts.event_id=event.id
            where event.domain_id=%s
              and event.time_created_utc >= %s and event.id > %s
            order by event.id limit %s""",
        (domain_id, cutoff, after_id, limit + 1),
    )
    rows = [dict(row) for row in cur.fetchall()]
    events = rows[:limit]
    scanned_through = int(events[-1]["source_event_id"]) if events else after_id
    return _SourceBatch(events=events, scanned_through=scanned_through, exhausted=len(rows) <= limit)


def _load_reconciliation_events(cur: Any, *, domain_id: int, high_water: int, limit: int) -> list[dict[str, Any]]:
    cur.execute(
        """select event.id as source_event_id,event.source_core_sha256 as source_event_hash,
                  event.time_created_utc as observed_at_utc,event.event_id,event.target_user_sid,
                  event.target_user_name,target_domain.value as target_domain_name,
                  event.workstation_name,event.ip_address,facts.logon_type
             from events_v2_core event
             join servers server on server.id=event.server_id and server.role='domain_controller'
             join storage_v2_channel channel on channel.id=event.channel_id and lower(channel.value)='security'
             left join storage_v2_domain_name target_domain on target_domain.id=event.target_domain_id
             left join event_facts_v2 facts on facts.event_id=event.id
            where event.domain_id=%s and event.event_id=%s and event.id<=%s
              and event.time_created_utc>=transaction_timestamp()-interval '24 hours'
              and not exists (
                    select 1 from what_where_when_observations observation
                     where observation.source_event_id=event.id
              )
            order by event.id desc limit %s""",
        (domain_id, SUCCESSFUL_LOGON_EVENT_ID, high_water, limit),
    )
    return [dict(row) for row in cur.fetchall()]


def _load_domain_controller_membership(cur: Any, *, domain_id: int) -> _DomainControllerMembership:
    cur.execute(
        """select id,hostname,fqdn from servers
            where domain_id=%s and role='domain_controller'
            order by id limit %s""",
        (domain_id, MAX_DOMAIN_CONTROLLER_SERVER_IDS + 1),
    )
    rows = [dict(row) for row in cur.fetchall()]
    if len(rows) > MAX_DOMAIN_CONTROLLER_SERVER_IDS:
        raise RuntimeError("what_where_when_domain_controller_membership_limit_exceeded")
    stable_name_owners: dict[str, set[int]] = {}
    for row in rows:
        server_id = int(row["id"])
        for raw_name in (row.get("hostname"), row.get("fqdn")):
            stable_name = _name(raw_name)
            if not stable_name:
                continue
            stable_name_owners.setdefault(stable_name, set()).add(server_id)
            if "." in stable_name:
                stable_name_owners.setdefault(stable_name.split(".", 1)[0], set()).add(server_id)
    return _DomainControllerMembership(
        server_ids=frozenset(int(row["id"]) for row in rows),
        stable_name_owners={name: frozenset(owners) for name, owners in stable_name_owners.items()},
    )


def _archive_source_is_current_domain_controller(
    row: Mapping[str, Any], *, domain_id: int, membership: _DomainControllerMembership
) -> bool:
    if (
        int(row.get("domain_id") or -1) == domain_id
        and int(row.get("server_id") or -1) in membership.server_ids
    ):
        return True
    computer = _name(row.get("computer"))
    if not computer:
        return False
    exact_owners = membership.stable_name_owners.get(computer, frozenset())
    if len(exact_owners) == 1:
        return True
    if len(exact_owners) > 1:
        return False
    short_name, separator, suffix = computer.partition(".")
    if separator and suffix != _name(report_domain_fqdn()):
        return False
    return len(membership.stable_name_owners.get(short_name, ())) == 1


def _load_archive_events(cur: Any, *, domain_id: int, cutoff: datetime, after_id: int, limit: int) -> _SourceBatch:
    """Read a bounded page of published, double-hash-verified event archive blocks."""
    domain_controller_membership = _load_domain_controller_membership(cur, domain_id=domain_id)
    cur.execute(
        """select block.object_location,block.row_count,block.raw_bytes,block.compressed_bytes,
                  block.raw_sha256,block.archive_sha256
             from storage_v2_archive_blocks block
             join storage_v2_archive_sets archive_set using(archive_set_id)
            where block.archive_kind='event' and block.state='published'
              and archive_set.state='published' and block.last_event_id>%s
            order by block.first_event_id,block.block_index limit 9""",
        (after_id,),
    )
    candidate_blocks = [dict(row) for row in cur.fetchall()]
    blocks = candidate_blocks[:ARCHIVE_BLOCKS_PER_CYCLE]
    more_blocks = len(candidate_blocks) > ARCHIVE_BLOCKS_PER_CYCLE
    events: list[dict[str, Any]] = []
    scanned_through = after_id
    unread_in_block = False
    for block in blocks:
        compressed = Path(str(block["object_location"])).read_bytes()
        if len(compressed) != int(block["compressed_bytes"]) or hashlib.sha256(compressed).digest() != _hash_bytes(block["archive_sha256"]):
            raise RuntimeError("what_where_when_archive_compressed_hash_mismatch")
        raw = gzip.decompress(compressed)
        if len(raw) != int(block["raw_bytes"]) or hashlib.sha256(raw).digest() != _hash_bytes(block["raw_sha256"]):
            raise RuntimeError("what_where_when_archive_raw_hash_mismatch")
        lines = raw.splitlines()
        if len(lines) != int(block["row_count"]):
            raise RuntimeError("what_where_when_archive_row_count_mismatch")
        rows: list[Mapping[str, Any]] = []
        for line in lines:
            envelope = json.loads(line)
            row = envelope.get("row")
            if envelope.get("kind") == "event" and isinstance(row, Mapping):
                rows.append(row)
        rows.sort(key=lambda row: int(row.get("id") or 0))
        for row in rows:
            source_event_id = int(row.get("id") or 0)
            if source_event_id <= scanned_through:
                continue
            if len(events) >= limit:
                unread_in_block = True
                break
            scanned_through = source_event_id
            observed_raw = row.get("time_created_utc")
            if not observed_raw:
                continue
            observed = datetime.fromisoformat(str(observed_raw).replace("Z", "+00:00"))
            if observed.astimezone(timezone.utc) < cutoff:
                continue
            if str(row.get("channel") or "").casefold() != "security":
                continue
            if not _archive_source_is_current_domain_controller(
                row, domain_id=domain_id, membership=domain_controller_membership
            ):
                continue
            events.append(_normalize_source_event(row))
        if unread_in_block:
            break
    return _SourceBatch(
        events=events,
        scanned_through=scanned_through,
        exhausted=not more_blocks and not unread_in_block,
    )


def _persist_observation(cur: Any, observation: Mapping[str, Any], *, computer_snapshot_id: int, user_snapshot_id: int) -> str:
    """Keep one resolved observation in a user/computer local-hour bucket."""
    computer_guid, user_key, observed_hour_local = _hourly_observation_key(observation)
    cur.execute(
        """select source_event_id,source_event_hash,computer_object_guid,computer_name,
                  user_name,observed_at_utc,computer_source_snapshot_id,user_snapshot_id
             from what_where_when_observations where source_event_id=%s""",
        (observation["source_event_id"],),
    )
    existing = dict(cur.fetchone() or {})
    if existing:
        same_identity = (
            int(existing.get("source_event_id") or 0) == int(observation["source_event_id"])
            and _hash_bytes(existing.get("source_event_hash")) == observation["source_event_hash"]
            and str(existing.get("computer_object_guid") or "").casefold()
            == str(observation["computer_object_guid"]).casefold()
            and existing.get("computer_name") == observation["computer_name"]
            and existing.get("user_name") == observation["user_name"]
            and existing.get("observed_at_utc") == observation["observed_at_utc"]
            and int(existing.get("computer_source_snapshot_id") or 0) == int(computer_snapshot_id)
            and int(existing.get("user_snapshot_id") or 0) == int(user_snapshot_id)
        )
        if not same_identity:
            raise RuntimeError("what_where_when_source_event_identity_conflict")
        return "duplicate"

    cur.execute(
        """insert into what_where_when_observations(
               source_event_id,source_event_hash,computer_object_guid,computer_name,
               user_name,user_key,observed_at_utc,observed_hour_local,
               computer_source_snapshot_id,user_snapshot_id)
           values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           on conflict (computer_object_guid,user_key,observed_hour_local) do nothing
           returning source_event_id""",
        (
            observation["source_event_id"], observation["source_event_hash"], computer_guid,
            observation["computer_name"], observation["user_name"], user_key,
            observation["observed_at_utc"], observed_hour_local,
            computer_snapshot_id, user_snapshot_id,
        ),
    )
    if cur.fetchone():
        return "inserted"
    return "collapsed"


def run_backfill_batch(connection: Any, *, state: Mapping[str, Any], domain_id: int, limit: int) -> BackfillBatch:
    """Load a bounded archive-first batch and prove source exhaustion explicitly."""
    cutoff = state["initial_cutoff_utc"]
    high_water = int(state.get("high_water_event_id") or 0)
    with connection.cursor() as cur:
        archive = _load_archive_events(cur, domain_id=domain_id, cutoff=cutoff, after_id=high_water, limit=limit)
        if not archive.exhausted:
            return BackfillBatch(archive.events, archive.scanned_through, False, False)
        remaining = limit - len(archive.events)
        if remaining <= 0:
            return BackfillBatch(archive.events, archive.scanned_through, True, False)
        hot = _load_hot_events(
            cur,
            domain_id=domain_id,
            cutoff=cutoff,
            after_id=archive.scanned_through,
            limit=remaining,
        )
        return BackfillBatch(
            events=archive.events + hot.events,
            scanned_through=hot.scanned_through,
            archive_exhausted=True,
            hot_exhausted=hot.exhausted,
        )


def run_projection_cycle(
    *,
    batch_limit: int,
    retention_limit: int,
    connection_factory: Callable[[], Any] = connect,
) -> dict[str, Any]:
    """Atomically project one bounded batch, advance state, and enforce retention."""
    batch_limit = max(1, min(int(batch_limit), MAX_BATCH_LIMIT))
    retention_limit = max(1, min(int(retention_limit), MAX_RETENTION_LIMIT))
    counters = {key: 0 for key in ("inserted", "collapsed", "duplicate", "filtered", "unmatched", "ambiguous", "deleted")}
    try:
        domain_fqdn = report_domain_fqdn()
    except ReportDomainNotConfiguredError:
        # No report domain in settings: skip the cycle, nothing is projected.
        return {**counters, "status": "skipped", "reason": NOT_CONFIGURED_CODE, "high_water": None, "backfill_completed": False}
    with connection_factory() as connection:
        with connection.cursor() as cur:
            cur.execute("select pg_try_advisory_xact_lock(hashtext('ad_log_reports_what_where_when_projection_cycle')) as acquired")
            if not bool(dict(cur.fetchone()).get("acquired")):
                return {**counters, "status": "skipped", "reason": "lock_busy", "high_water": None, "backfill_completed": False}
            cur.execute("select id from domains where lower(fqdn)=%s order by id", (domain_fqdn,))
            domains = [dict(row) for row in cur.fetchall()]
            if len(domains) != 1:
                raise RuntimeError("what_where_when_requires_one_domain")
            domain_id = int(domains[0]["id"])
            cur.execute("select * from what_where_when_projection_state where singleton for update")
            state = dict(cur.fetchone() or {})
            if not state:
                raise RuntimeError("what_where_when_projection_state_missing")
        computer_source = load_latest_computers_v6_source_snapshot(connection, domain_fqdn=domain_fqdn)
        if not computer_source or computer_source["base_inventory_status"] != "observed":
            raise RuntimeError("what_where_when_computers_population_unavailable")
        computer_index = load_computer_match_index(computer_source["snapshot"])
        user_snapshot_id, service_accounts = _load_service_accounts(connection, domain_id)
        batch = run_backfill_batch(connection, state=state, domain_id=domain_id, limit=batch_limit)
        events = batch.events
        high_water = max(int(state.get("high_water_event_id") or 0), batch.scanned_through)
        with connection.cursor() as cur:
            reconciliation = _load_reconciliation_events(
                cur, domain_id=domain_id, high_water=high_water, limit=min(batch_limit, 2000)
            )
        reconciliation_ids = {int(item["source_event_id"]) for item in reconciliation}
        seen = {int(item.get("source_event_id") or item.get("id")) for item in events}
        events_with_reconciliation = [*events, *(item for item in reconciliation if int(item["source_event_id"]) not in seen)]
        with connection.cursor() as cur:
            for event in events_with_reconciliation:
                normalized = _normalize_source_event(event)
                decision = project_event(normalized, computer_index, service_accounts)
                status = decision["status"]
                if status == "observation":
                    status = _persist_observation(
                        cur, decision["observation"],
                        computer_snapshot_id=int(computer_source["source_snapshot_id"]),
                        user_snapshot_id=user_snapshot_id,
                    )
                counters[status] += 1
                if int(normalized["source_event_id"]) not in reconciliation_ids:
                    high_water = max(high_water, int(normalized["source_event_id"]))
            backfill_completed = bool(state["backfill_completed"]) or batch.backfill_completed
            cur.execute(
                """with doomed as (
                       select projection_id from what_where_when_observations
                        where observed_at_utc < transaction_timestamp()-interval '365 days'
                        order by observed_at_utc,projection_id limit %s
                   ) delete from what_where_when_observations observation
                     using doomed where observation.projection_id=doomed.projection_id""",
                (retention_limit,),
            )
            counters["deleted"] = max(0, int(cur.rowcount or 0))
            cur.execute(
                """update what_where_when_projection_state set
                       high_water_event_id=%s,backfill_completed=%s,
                       computer_source_snapshot_id=%s,user_snapshot_id=%s,
                       filtered_count=filtered_count+%s,
                       unmatched_count=unmatched_count+%s,
                       ambiguous_count=ambiguous_count+%s,
                       last_cycle_at_utc=transaction_timestamp(),updated_at=transaction_timestamp()
                     where singleton""",
                (
                    high_water, backfill_completed, int(computer_source["source_snapshot_id"]),
                    user_snapshot_id, counters["filtered"], counters["unmatched"], counters["ambiguous"],
                ),
            )
    return {**counters, "status": "ok", "high_water": high_water, "backfill_completed": backfill_completed}
