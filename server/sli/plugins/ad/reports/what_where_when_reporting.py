from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from server.sli.plugins.ad.reports.computers_reporting import COMPUTERS_INPUT_LIMIT
from server.sli.plugins.ad.reports.computers_v6_reporting import get_computers_v6_report
from server.sli.core.database import QueryTimeoutError, query_rows_bounded
from server.sli.core.report_domain import NOT_CONFIGURED_CODE, ReportDomainNotConfiguredError, report_domain_fqdn

CONTRACT_ID = "sli.ad-computer-logons.v1"
REPORT_KEY = "ad.computer-logons"
MAX_DAYS = 365
MAX_LIMIT = 200
DEFAULT_LIMIT = 50
DEFAULT_DAYS = 30
_CURSOR_VERSION = 1
_LIMITATION = "Наблюдения приблизительны; полнота сбора не доказана."
_EMPTY_LIMITATION = "Отсутствие наблюдений не подтверждает, что ПК не использовался."
_CURRENT_POPULATION_LIMITATION = "Список ПК — текущий инвентарь рабочих станций Computers V6; исторический состав не восстанавливается."
_CURRENT_NAME_LIMITATION = "Отображаемое имя пользователя — текущий AD-контекст из последнего Users V2, а не историческое имя в момент входа."


class InventoryUnavailableError(RuntimeError):
    pass


class ObservationsUnavailableError(InventoryUnavailableError):
    """Observation summaries could not be read in time (e.g. whole-population scan)."""


def _utc_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    elif isinstance(value, datetime):
        parsed = value
    else:
        raise ValueError("invalid_observed_time")
    if parsed.tzinfo is None:
        raise ValueError("invalid_observed_time")
    return parsed.astimezone(timezone.utc).isoformat()


def _parse_utc(value: str | None, *, default: datetime, error: str) -> datetime:
    if value in (None, ""):
        return default.astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(error) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("time_must_be_utc")
    return parsed.astimezone(timezone.utc)


def parse_time_range(
    from_utc: str | None,
    to_utc_exclusive: str | None,
    *,
    now: datetime | None = None,
) -> tuple[datetime, datetime]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    end = _parse_utc(to_utc_exclusive, default=current, error="invalid_to_utc_exclusive")
    start = _parse_utc(from_utc, default=end - timedelta(days=DEFAULT_DAYS), error="invalid_from_utc")
    if start >= end:
        raise ValueError("invalid_time_range")
    if end - start > timedelta(days=MAX_DAYS):
        raise ValueError("time_range_exceeds_365_days")
    return start, end


def resolve_report_domain_id() -> int:
    try:
        domain_fqdn = report_domain_fqdn()
    except ReportDomainNotConfiguredError as exc:
        raise InventoryUnavailableError(NOT_CONFIGURED_CODE) from exc
    rows = query_rows_bounded(
        "select id from domains where lower(fqdn)=? order by id limit 2",
        (domain_fqdn,), statement_timeout_ms=3000,
    )
    if len(rows) != 1:
        raise InventoryUnavailableError("report_domain_unavailable")
    return int(rows[0]["id"])


def _clean_limit(limit: int) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_limit") from exc
    if not 1 <= value <= MAX_LIMIT:
        raise ValueError("invalid_limit")
    return value


def _clean_query(q: str | None) -> str:
    value = str(q or "").strip()
    if len(value) > 256:
        raise ValueError("query_too_long")
    return value.casefold()


def _login_key(value: str) -> str:
    login = str(value or "").strip()
    if "\\" in login:
        login = login.rsplit("\\", 1)[-1]
    if "@" in login:
        login = login.split("@", 1)[0]
    return login.casefold()


def _canonical_payload_hash(payload: Mapping[str, Any]) -> bytes:
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).digest()


def _stored_hash_bytes(value: Any) -> bytes | None:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        return value if len(value) == 32 else None
    if isinstance(value, str):
        try:
            decoded = bytes.fromhex(value)
        except ValueError:
            return None
        return decoded if len(decoded) == 32 else None
    return None


def _load_current_user_directory(domain_ids: list[int]) -> dict[str, str]:
    """Resolve current public AD names from one latest bounded snapshot per domain."""
    rows = query_rows_bounded(
        """select distinct on (domain_id) domain_id,payload_json,payload_sha256
             from users_report_v2_snapshots
            where domain_id=any(?) and source_state in ('complete','partial')
            order by domain_id,captured_at_utc desc,snapshot_id desc""",
        (domain_ids,), statement_timeout_ms=5000,
    )
    directory: dict[str, str] = {}
    for row in rows:
        raw = row.get("payload_json") or {}
        try:
            payload = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if _stored_hash_bytes(row.get("payload_sha256")) != _canonical_payload_hash(payload):
            continue
        for item in payload.get("users") or []:
            if not isinstance(item, Mapping):
                continue
            sam = str(item.get("samAccountName") or item.get("sam_account_name") or "").strip()
            display = str(item.get("displayName") or item.get("display_name") or "").strip()
            if sam and display:
                directory[sam.casefold()] = display
    return directory


def _matching_sams(directory: Mapping[str, str], user_q: str) -> tuple[str, ...]:
    if not user_q:
        return ()
    return tuple(sorted(sam for sam, display in directory.items() if user_q in display.casefold()))


def _user_sql(user_q: str, matching_sams: tuple[str, ...]) -> tuple[str, list[Any]]:
    if not user_q:
        return "", []
    escaped = user_q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return (
        " and (lower(user_name) like ? escape E'\\\\' or "
        "lower(case when strpos(user_name,E'\\\\')>0 then split_part(user_name,E'\\\\',2) "
        "else split_part(user_name,'@',1) end)=any(?))",
        [f"%{escaped}%", list(matching_sams)],
    )


def _filter_hash(kind: str, values: Mapping[str, Any]) -> str:
    raw = json.dumps({"kind": kind, **dict(values)}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _encode_cursor(kind: str, binding: str, position: Mapping[str, Any]) -> str:
    body = {"v": _CURSOR_VERSION, "kind": kind, "binding": binding, "position": dict(position)}
    canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    envelope = {"body": body, "checksum": hashlib.sha256(("sli-computer-logons:" + canonical).encode("utf-8")).hexdigest()}
    return base64.urlsafe_b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str, kind: str, binding: str) -> dict[str, Any]:
    try:
        token = str(cursor)
        envelope = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)).decode("utf-8"))
        body = dict(envelope["body"])
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        checksum = hashlib.sha256(("sli-computer-logons:" + canonical).encode("utf-8")).hexdigest()
        if envelope.get("checksum") != checksum:
            raise ValueError
        if body.get("v") != _CURSOR_VERSION or body.get("kind") != kind or body.get("binding") != binding:
            raise ValueError
        return dict(body["position"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid_cursor") from exc


def _load_workstation_population(domain_ids: list[int], *, raise_on_error: bool = False) -> dict[str, Any]:
    try:
        payload = get_computers_v6_report(
            domain_ids=domain_ids,
            view="all",
            computer_type="workstation",
            sort_by="display_name",
            sort_direction="asc",
            limit=COMPUTERS_INPUT_LIMIT,
            max_page_limit=COMPUTERS_INPUT_LIMIT,
        )
    except Exception:
        if raise_on_error:
            raise
        return {"state": "unavailable", "partial": True, "items": []}
    state = str(payload.get("state") or "unavailable")
    if state in {"unavailable", "not_collected"}:
        return {"state": "unavailable", "partial": True, "items": []}
    items = []
    for raw in payload.get("items") or []:
        guid = str(raw.get("object_guid") or (raw.get("identity") or {}).get("object_guid") or "").strip().lower()
        if not guid or raw.get("computer_type") != "workstation":
            continue
        items.append({
            "entity_id": int(raw["entity_id"]),
            "object_guid": guid,
            "display_name": str(raw.get("display_name") or "").strip(),
            "dns_host_name": str(raw.get("dns_host_name") or "").strip(),
        })
    partial = bool((payload.get("limits") or {}).get("input_truncated")) or state == "partial"
    inventory_state = "partial" if partial else "stale" if state == "stale" else "available"
    return {"state": inventory_state, "partial": partial, "items": items}


def _load_projection_status() -> dict[str, Any]:
    try:
        rows = query_rows_bounded(
            "select backfill_completed,last_cycle_at_utc from what_where_when_projection_state where singleton=true",
            (), statement_timeout_ms=3000,
        )
    except Exception:
        return {"state": "unavailable", "backfill_completed": False}
    if len(rows) != 1:
        return {"state": "not_collected", "backfill_completed": False}
    row = rows[0]
    completed = bool(row.get("backfill_completed"))
    return {"state": "available" if completed else "partial", "backfill_completed": completed}


def _load_observation_summaries(
    guids: list[str], start: datetime, end: datetime, user_q: str = "",
    matching_sams: tuple[str, ...] = (),
) -> dict[str, dict[str, Any]]:
    if not guids:
        return {}
    user_sql, user_params = _user_sql(user_q, matching_sams)
    rows = query_rows_bounded(
        f"""select computer_object_guid::text as computer_object_guid,count(*)::bigint as login_count,
                  max(observed_at_utc) as last_observed_logon_at_utc
           from what_where_when_observations
           where computer_object_guid=any(?) and observed_at_utc>=? and observed_at_utc<?{user_sql}
           group by computer_object_guid""",
        tuple([guids, start, end, *user_params]), statement_timeout_ms=10_000,
    )
    return {str(row["computer_object_guid"]).lower(): dict(row) for row in rows}


def _load_observations(
    guid: str, start: datetime, end: datetime, after: Mapping[str, Any] | None, limit: int,
    user_q: str = "", matching_sams: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    cursor_sql = ""
    params: list[Any] = [guid, start, end]
    user_sql, user_params = _user_sql(user_q, matching_sams)
    params.extend(user_params)
    if after:
        try:
            after_time = _parse_utc(str(after["observed_at_utc"]), default=end, error="invalid_cursor")
            after_id = int(after["projection_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid_cursor") from exc
        cursor_sql = " and (observed_at_utc,projection_id)<(?,?)"
        params.extend([after_time, after_id])
    params.append(limit + 1)
    return query_rows_bounded(
        f"""select projection_id,source_event_id,user_name,observed_at_utc
            from what_where_when_observations
            where computer_object_guid=? and observed_at_utc>=? and observed_at_utc<?{user_sql}{cursor_sql}
            order by observed_at_utc desc,projection_id desc limit ?""",
        tuple(params), statement_timeout_ms=10_000,
    )


def _coverage(inventory: Mapping[str, Any], projection: Mapping[str, Any]) -> dict[str, Any]:
    inventory_state = str(inventory.get("state") or "unavailable")
    observation_state = str(projection.get("state") or "unavailable")
    limitations = [_LIMITATION, _CURRENT_POPULATION_LIMITATION]
    if observation_state != "available":
        limitations.append("Накопительная проекция ещё не подтверждена как полностью обработанная.")
    if inventory_state in {"partial", "stale"}:
        limitations.append("Инвентарь рабочих станций частичный или устаревший.")
    return {
        "inventory_state": inventory_state if inventory_state in {"available", "partial", "stale"} else "unavailable",
        "observation_state": observation_state if observation_state in {"available", "partial", "not_collected"} else "unavailable",
        "completeness": "unverified",
        "limitations": limitations,
    }


def get_computer_logon_computers(
    *, domain_ids: list[int], q: str | None = None, from_utc: str | None = None,
    to_utc_exclusive: str | None = None, limit: int = DEFAULT_LIMIT, cursor: str | None = None,
    user_q: str | None = None, with_logons: bool = False,
) -> dict[str, Any]:
    clean_domains = sorted({int(value) for value in domain_ids if int(value) > 0})
    if not clean_domains:
        raise PermissionError("report_scope_not_executable")
    clean_limit = _clean_limit(limit)
    clean_q = _clean_query(q)
    clean_user_q = _clean_query(user_q)
    start, end = parse_time_range(from_utc, to_utc_exclusive)
    inventory = _load_workstation_population(clean_domains)
    if inventory.get("state") == "unavailable":
        raise InventoryUnavailableError("computer_inventory_unavailable")
    projection = _load_projection_status()
    items = [dict(item) for item in inventory.get("items") or []]
    if clean_q:
        items = [item for item in items if clean_q in str(item.get("display_name") or "").casefold() or clean_q in str(item.get("dns_host_name") or "").casefold()]
    directory = _load_current_user_directory(clean_domains) if clean_user_q else {}
    matching_sams = _matching_sams(directory, clean_user_q)
    summaries: dict[str, dict[str, Any]] = {}
    if clean_user_q or with_logons:
        summary_args = ([str(item["object_guid"]) for item in items], start, end)
        try:
            summaries = (
                _load_observation_summaries(*summary_args, user_q=clean_user_q, matching_sams=matching_sams)
                if clean_user_q else _load_observation_summaries(*summary_args)
            )
        except QueryTimeoutError as exc:
            # A filter by logons scans the whole population; on timeout answer
            # "unavailable" instead of an HTTP 500.
            raise ObservationsUnavailableError("observations_unavailable") from exc
        items = [item for item in items if int((summaries.get(str(item["object_guid"]).lower()) or {}).get("login_count") or 0) > 0]
    items.sort(key=lambda item: (str(item.get("display_name") or "").casefold(), int(item["entity_id"])))
    binding = _filter_hash("computers", {"domains": clean_domains, "q": clean_q, "user_q": clean_user_q, "with_logons": bool(with_logons), "from": start.isoformat(), "to": end.isoformat()})
    if cursor:
        position = _decode_cursor(cursor, "computers", binding)
        marker = (str(position.get("display_name") or ""), int(position.get("entity_id") or 0))
        positions = [(str(item.get("display_name") or "").casefold(), int(item["entity_id"])) for item in items]
        try:
            offset = positions.index(marker) + 1
        except ValueError as exc:
            raise ValueError("invalid_cursor") from exc
        items = items[offset:]
    page = items[:clean_limit]
    has_more = len(items) > clean_limit

    if not clean_user_q and not with_logons:
        summaries = _load_observation_summaries([str(item["object_guid"]) for item in page], start, end)

    public_items = []
    for item in page:
        summary = summaries.get(str(item["object_guid"]).lower())
        count = int((summary or {}).get("login_count") or 0)
        state = "observed" if count else "partial" if projection.get("state") == "partial" or inventory.get("partial") else "not_collected" if projection.get("state") == "not_collected" else "empty_unverified"
        public_items.append({
            "entity_id": int(item["entity_id"]), "display_name": str(item["display_name"]),
            "last_observed_logon_at_utc": _utc_iso((summary or {}).get("last_observed_logon_at_utc")),
            "login_count": count, "observation_state": state,
        })
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = _encode_cursor("computers", binding, {"display_name": str(last.get("display_name") or "").casefold(), "entity_id": int(last["entity_id"])})
    coverage = _coverage(inventory, projection)
    state = (
        "partial" if inventory.get("partial") or projection.get("state") == "partial"
        else "stale" if inventory.get("state") == "stale"
        else "unavailable" if projection.get("state") == "unavailable"
        else "not_collected" if projection.get("state") == "not_collected"
        else "empty" if not public_items
        else "available"
    )
    return {
        "contract_id": CONTRACT_ID, "report_key": REPORT_KEY, "state": state,
        "time_range": {"from_utc": start.isoformat(), "to_utc_exclusive": end.isoformat(), "max_days": MAX_DAYS},
        "coverage": coverage, "items": public_items, "has_more": has_more, "next_cursor": next_cursor,
    }


def get_computer_logon_observations(
    *, domain_ids: list[int], entity_id: int, from_utc: str | None = None,
    to_utc_exclusive: str | None = None, limit: int = DEFAULT_LIMIT, cursor: str | None = None,
    user_q: str | None = None,
) -> dict[str, Any]:
    clean_domains = sorted({int(value) for value in domain_ids if int(value) > 0})
    if not clean_domains:
        raise PermissionError("report_scope_not_executable")
    clean_limit = _clean_limit(limit)
    clean_user_q = _clean_query(user_q)
    start, end = parse_time_range(from_utc, to_utc_exclusive)
    inventory = _load_workstation_population(clean_domains)
    if inventory.get("state") == "unavailable":
        raise InventoryUnavailableError("computer_inventory_unavailable")
    computer = next((dict(item) for item in inventory.get("items") or [] if int(item.get("entity_id") or 0) == int(entity_id)), None)
    if computer is None:
        raise KeyError("computer_not_found")
    projection = _load_projection_status()
    directory = _load_current_user_directory(clean_domains)
    matching_sams = _matching_sams(directory, clean_user_q)
    binding = _filter_hash("observations", {"domains": clean_domains, "entity_id": int(entity_id), "user_q": clean_user_q, "from": start.isoformat(), "to": end.isoformat()})
    after = _decode_cursor(cursor, "observations", binding) if cursor else None
    observation_args = (str(computer["object_guid"]), start, end, after, clean_limit)
    rows = (
        _load_observations(*observation_args, user_q=clean_user_q, matching_sams=matching_sams)
        if clean_user_q else _load_observations(*observation_args)
    )
    page = rows[:clean_limit]
    has_more = len(rows) > clean_limit
    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = _encode_cursor("observations", binding, {"observed_at_utc": _utc_iso(last["observed_at_utc"]), "projection_id": int(last["projection_id"])})
    items = []
    missing_exact_event = False
    for row in page:
        display_name = directory.get(_login_key(str(row["user_name"])))
        try:
            source_event_id = int(row.get("source_event_id") or 0)
        except (TypeError, ValueError):
            source_event_id = 0
        if source_event_id <= 0:
            source_event_id = None
            missing_exact_event = True
        items.append({
            "user_name": str(row["user_name"]),
            "user_display_name": display_name,
            "user_identity_state": "resolved" if display_name else "not_found",
            "observed_at_utc": _utc_iso(row["observed_at_utc"]),
            "source_event_id": source_event_id,
            "source_event_state": "available" if source_event_id else "unavailable",
        })
    state = "partial" if inventory.get("state") in {"partial", "stale"} or projection.get("state") == "partial" else "unavailable" if projection.get("state") == "unavailable" else "not_collected" if projection.get("state") == "not_collected" else "available" if items else "empty_unverified"
    limitations = [_LIMITATION, _CURRENT_NAME_LIMITATION, _CURRENT_POPULATION_LIMITATION]
    if not items:
        limitations.append(_EMPTY_LIMITATION)
    if missing_exact_event:
        limitations.append("Для части наблюдений точный идентификатор исходного события не сохранён; переход к доказательству не показан.")
    return {
        "contract_id": CONTRACT_ID, "report_key": REPORT_KEY, "state": state,
        "computer": {"entity_id": int(computer["entity_id"]), "display_name": str(computer["display_name"])},
        "time_range": {"from_utc": start.isoformat(), "to_utc_exclusive": end.isoformat()},
        "identity_context": {"display_name": "current_ad_context", "historical_display_name": "not_retained"},
        "population_context": {"computers": "current_computers_v6_workstations", "historical_membership": "not_retained"},
        "items": items, "has_more": has_more, "next_cursor": next_cursor, "limitations": limitations,
    }
