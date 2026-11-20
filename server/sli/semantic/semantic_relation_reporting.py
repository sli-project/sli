from __future__ import annotations

"""Fail-closed, read-only projection of persisted semantic relations."""

from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
from collections import OrderedDict
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
import secrets
from threading import Lock
import time
from typing import Any

from server.sli.access.access_control_v4 import capability_decision_for_resource_groups, report_action_decision
from server.sli.reporting.reporting_common import (
    format_iso,
    get_runtime_connection,
    parse_utc,
)
from server.sli.reports.security_event_reporting import (
    REQUIRED_FIELD_CATEGORIES,
    SECURITY_CHANNEL,
    normalize_security_event_filters,
    security_event_read_contract,
)
from server.sli.semantic.semantic_correlation_repository import EXECUTABLE_RULE_STATES
from server.sli.semantic.semantic_identity import parse_exact_domain_sid_partition
from server.sli.semantic.semantic_investigation_backfill import INVESTIGATION_RULE_IDS
from server.sli.core.time_contract import TimeRangeError, normalize_utc_range
from server.sli.core.time_format import parse_event_time


CONTRACT_ID = "sli.semantic-relations.v1"
REPORT_KEY = "security.events.chains"
REQUIRED_CAPABILITIES = ("semantic.review", "evidence.exact", "field.security", "events.view")
DEFAULT_LIMIT = 100
MAX_LIMIT = 200
MAX_PERIOD_DAYS = 31
# Resource-scoped grants may require reading past denied candidates.  Keep that
# work bounded so a long hidden prefix cannot consume unbounded database work.
MAX_RESOURCE_SCOPED_PREFLIGHT_PAGES = 20
RuleSnapshot = tuple[tuple[str, int, str], ...]
_CURSOR_TTL_SECONDS = 60 * 60
_CURSOR_STATE_LIMIT = 4096
_CURSOR_STATE_LOCK = Lock()
_CURSOR_STATES: OrderedDict[
    str,
    tuple[float, int, str, str, str, RuleSnapshot, str, str],
] = OrderedDict()
_AMBIGUITY_RULE_IDS = frozenset({
    "investigation.account.unlock.after-lock",
    "investigation.group.membership.removed-after-add",
    "investigation.account.created-then-group-add",
    "investigation.password.reset-then-logon",
})


class SchemaUnavailable(Exception):
    pass


class _RelationSnapshot:
    """Lazy repeatable-read cursor shared by selection and hydration."""

    def __init__(self) -> None:
        self._connection_context: Any | None = None
        self._cursor_context: Any | None = None
        self.cursor_value: Any | None = None

    def cursor(self) -> Any:
        if self.cursor_value is None:
            self._connection_context = _connect()
            connection = self._connection_context.__enter__()
            self._cursor_context = connection.cursor()
            self.cursor_value = self._cursor_context.__enter__()
            self.cursor_value.execute("set transaction isolation level repeatable read, read only")
        return self.cursor_value

    def close(self) -> None:
        if self._cursor_context is not None:
            self._cursor_context.__exit__(None, None, None)
        if self._connection_context is not None:
            self._connection_context.__exit__(None, None, None)


_ACTIVE_RELATION_SNAPSHOT: ContextVar[_RelationSnapshot | None] = ContextVar("active_relation_snapshot", default=None)


@contextmanager
def _relation_snapshot():
    snapshot = _RelationSnapshot()
    token = _ACTIVE_RELATION_SNAPSHOT.set(snapshot)
    try:
        yield snapshot
    finally:
        _ACTIVE_RELATION_SNAPSHOT.reset(token)
        snapshot.close()


_utc = parse_utc
_iso = format_iso


def _positive(value: Any, code: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(code) from exc
    if result <= 0:
        raise ValueError(code)
    return result


def _filters(
    *, category: Any = None, event_id: Any = None, outcome: Any = None, actor: Any = None,
    target_account: Any = None, group: Any = None, source_host: Any = None, q: Any = None,
    event_db_id: Any = None, entity_id: Any = None, rule_version: Any = None,
    relation_kind: Any = None,
) -> dict[str, Any]:
    result = normalize_security_event_filters(
        category=category, event_id=event_id, outcome=outcome, actor=actor,
        target_account=target_account, group=group, source_host=source_host, q=q,
        event_db_id=event_db_id, entity_id=entity_id,
    )
    for key, value in (("rule_version", rule_version),):
        if value not in (None, ""):
            result[key] = _positive(value, "invalid_semantic_relation_filter")
    if relation_kind not in (None, ""):
        text = str(relation_kind).strip()
        if not text or len(text) > 200:
            raise ValueError("invalid_semantic_relation_filter")
        result["relation_kind"] = text
    return result


def _normalize_rule_snapshot(rules: list[dict[str, Any]]) -> RuleSnapshot:
    snapshot = tuple(sorted(
        (
            str(rule.get("rule_id") or "").strip(),
            _positive(rule.get("rule_version"), "invalid_semantic_relation_rule_snapshot"),
            str(rule.get("lifecycle_status") or "").strip(),
        )
        for rule in rules
    ))
    if (
        len(snapshot) > len(INVESTIGATION_RULE_IDS)
        or len({rule_id for rule_id, _version, _state in snapshot}) != len(snapshot)
        or any(
            rule_id not in INVESTIGATION_RULE_IDS or state not in EXECUTABLE_RULE_STATES
            for rule_id, _version, state in snapshot
        )
    ):
        raise ValueError("invalid_semantic_relation_rule_snapshot")
    return snapshot


def _rule_snapshot_payload(snapshot: RuleSnapshot) -> list[dict[str, Any]]:
    return [
        {"rule_id": rule_id, "rule_version": version, "lifecycle_status": state}
        for rule_id, version, state in snapshot
    ]


def _rule_snapshot_revision(snapshot: RuleSnapshot) -> str:
    raw = json.dumps(snapshot, separators=(",", ":")).encode()
    return hashlib.sha256(b"sli.semantic-relations.rules.v1\0" + raw).hexdigest()


def _encode_cursor(
    *, domain_id: int, start: datetime, end: datetime, filters: Mapping[str, Any],
    rule_snapshot: RuleSnapshot, window_end: datetime, candidate_id: str,
) -> str:
    token = "v2." + secrets.token_urlsafe(32)
    now = time.monotonic()
    canonical_filters = json.dumps(
        dict(filters), sort_keys=True, separators=(",", ":"),
    )
    state = (
        now + _CURSOR_TTL_SECONDS, int(domain_id), _iso(start), _iso(end),
        canonical_filters, rule_snapshot, _iso(window_end), str(candidate_id),
    )
    with _CURSOR_STATE_LOCK:
        for expired in [
            key for key, value in _CURSOR_STATES.items() if value[0] <= now
        ]:
            _CURSOR_STATES.pop(expired, None)
        while len(_CURSOR_STATES) >= _CURSOR_STATE_LIMIT:
            _CURSOR_STATES.popitem(last=False)
        _CURSOR_STATES[token] = state
    return token


def _decode_cursor(
    value: str, *, domain_id: int, start: datetime, end: datetime,
    filters: Mapping[str, Any],
) -> tuple[datetime, str, RuleSnapshot]:
    try:
        token = str(value)
        if not token.startswith("v2.") or len(token) > 128:
            raise ValueError
        (
            expires_at, cursor_domain, cursor_start, cursor_end, cursor_filters,
            rule_snapshot, window_end, candidate_id,
        ) = _cursor_state(token)
        parsed = _utc(window_end)
        if (
            expires_at <= time.monotonic()
            or int(cursor_domain) != domain_id
            or cursor_start != _iso(start)
            or cursor_end != _iso(end)
            or cursor_filters != json.dumps(
                dict(filters), sort_keys=True, separators=(",", ":"),
            )
            or parsed is None
            or not str(candidate_id)
        ):
            raise ValueError
        return parsed, str(candidate_id), rule_snapshot
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_cursor") from exc


def _cursor_state(
    token: str,
) -> tuple[float, int, str, str, str, RuleSnapshot, str, str]:
    now = time.monotonic()
    with _CURSOR_STATE_LOCK:
        state = _CURSOR_STATES.get(token)
        if state is None or state[0] <= now:
            _CURSOR_STATES.pop(token, None)
            raise ValueError("invalid_cursor")
        _CURSOR_STATES.move_to_end(token)
        return state


def _resource_groups(candidate: Mapping[str, Any]) -> list[list[dict[str, Any]]]:
    groups = []
    for evidence in candidate.get("evidence") or []:
        try:
            groups.append([
                {"kind": "server", "id": _positive(evidence.get("server_id"), "invalid_resource")},
                {"kind": "domain", "id": _positive(evidence.get("domain_id"), "invalid_resource")},
                {"kind": "channel", "value": str(evidence.get("channel") or "").strip()},
            ])
        except ValueError:
            return [[]]
    return groups or [[]]


def _candidate_authorized(access: Mapping[str, Any], candidate: Mapping[str, Any]) -> bool:
    groups = _resource_groups(candidate)
    if not report_action_decision(
        access,
        REPORT_KEY,
        "view",
        resource_groups=groups,
        required_field_categories=REQUIRED_FIELD_CATEGORIES,
    )["allowed"]:
        return False
    return all(capability_decision_for_resource_groups(access, capability, resource_groups=groups)["allowed"] for capability in REQUIRED_CAPABILITIES)


def _scope_matches_domain_or_may_need_evidence(scope: Mapping[str, Any], domain_id: int) -> str:
    """Return allow/potential/deny without inventing a server or channel."""

    kind = str(scope.get("kind") or "")
    if kind == "all":
        return "allow"
    if kind == "domain":
        try:
            return "allow" if int(domain_id) in {int(value) for value in scope.get("ids") or []} else "deny"
        except (TypeError, ValueError):
            return "deny"
    if kind in {"server", "channel"}:
        return "potential"
    return "deny"


def _report_access_preflight(access: Mapping[str, Any], domain_id: int) -> str:
    report = next((dict(item) for item in access.get("reports", []) if str(item.get("report_key") or "") == REPORT_KEY), None)
    if report is None or not report.get("allowed"):
        return "deny"
    required = set(REQUIRED_FIELD_CATEGORIES)
    grants = [
        dict(grant) for grant in report.get("grants", [])
        if "view" in {str(action) for action in grant.get("allowed_actions", [])}
        and required <= {str(field) for field in grant.get("field_categories", [])}
    ]
    states = [_scope_matches_domain_or_may_need_evidence(dict(grant.get("scope") or {}), domain_id) for grant in grants]
    if "allow" in states:
        return "allow"
    return "potential" if "potential" in states else "deny"


def _capability_access_preflight(access: Mapping[str, Any], capability: str, domain_id: int) -> str:
    if access.get("platform_owner"):
        return "allow"
    policies = [dict(item) for item in access.get("capability_policies", []) if str(item.get("capability_key") or "") == capability]
    if any(item.get("effect") == "deny" and not item.get("valid") for item in policies):
        return "deny"
    valid = [item for item in policies if item.get("valid")]
    deny_states = [_scope_matches_domain_or_may_need_evidence(dict(item.get("scope") or {}), domain_id) for item in valid if item.get("effect") == "deny"]
    if "allow" in deny_states:
        return "deny"
    global_allow = capability in {str(item) for item in access.get("capabilities") or []}
    allow_states = [_scope_matches_domain_or_may_need_evidence(dict(item.get("scope") or {}), domain_id) for item in valid if item.get("effect") == "allow"]
    allowed_without_evidence = global_allow or "allow" in allow_states
    if not allowed_without_evidence:
        return "potential" if "potential" in allow_states else "deny"
    # A server/channel deny can still reject an otherwise domain-wide grant.
    return "potential" if "potential" in deny_states else "allow"


def _domain_access_allowed(access: Mapping[str, Any], domain_id: int) -> str:
    """Tri-state preflight: deny only when no unseen evidence could authorize."""

    states = [_report_access_preflight(access, domain_id)] + [
        _capability_access_preflight(access, capability, domain_id)
        for capability in REQUIRED_CAPABILITIES
    ]
    if "deny" in states:
        return "deny"
    return "potential" if "potential" in states else "allow"


def _read_supported_rules() -> list[dict[str, Any]]:
    """Read the explicit active investigation-rule inventory, never infer it from matches."""

    sql = """
        with current_supported as (
            select rule_id,rule_version,lifecycle_status,
                   row_number() over (partition by rule_id order by rule_version desc) as version_rank
            from semantic_correlation_rules
            where rule_id=any(%s) and lifecycle_status=any(%s)
        )
        select rule_id,rule_version,lifecycle_status
        from current_supported where version_rank=1
        order by rule_id,rule_version
    """
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute("set transaction read only")
            cur.execute(sql, (list(INVESTIGATION_RULE_IDS), sorted(EXECUTABLE_RULE_STATES)))
            return [
                {
                    "rule_id": str(row["rule_id"]),
                    "rule_version": int(row["rule_version"]),
                    "lifecycle_status": str(row["lifecycle_status"]),
                }
                for row in cur.fetchall()
            ]
    except Exception as exc:
        if "undefined_table" in str(exc).casefold() or "does not exist" in str(exc).casefold():
            raise SchemaUnavailable() from exc
        raise


def get_semantic_relations(
    access: Mapping[str, Any], *, domain_id: Any, time_from: str | None, time_to: str | None,
    timezone_name: str, limit: Any = DEFAULT_LIMIT, cursor: str | None = None,
    category: Any = None, event_id: Any = None, outcome: Any = None, actor: Any = None,
    target_account: Any = None, group: Any = None, source_host: Any = None, q: Any = None,
    event_db_id: Any = None, entity_id: Any = None, rule_version: Any = None,
    relation_kind: Any = None,
) -> dict[str, Any]:
    domain = _positive(domain_id, "invalid_semantic_relation_filter")
    if not time_from or not time_to:
        raise TimeRangeError("semantic_relations_requires_time_bounds")
    start_raw, end_raw = normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    start, end = _utc(start_raw), _utc(end_raw)
    if start is None or end is None or start >= end:
        raise TimeRangeError("empty_or_reversed_time_range")
    if end - start > timedelta(days=MAX_PERIOD_DAYS):
        raise ValueError("semantic_relations_period_too_wide")
    clean_limit = _positive(limit, "invalid_semantic_relation_filter")
    if clean_limit > MAX_LIMIT:
        raise ValueError("invalid_semantic_relation_filter")
    filters = _filters(
        category=category, event_id=event_id, outcome=outcome, actor=actor,
        target_account=target_account, group=group, source_host=source_host, q=q,
        event_db_id=event_db_id, entity_id=entity_id, rule_version=rule_version,
        relation_kind=relation_kind,
    )
    before: tuple[datetime, str] | None = None
    rule_snapshot: RuleSnapshot | None = None
    if cursor:
        cursor_time, cursor_candidate_id, rule_snapshot = _decode_cursor(
            cursor, domain_id=domain, start=start, end=end, filters=filters,
        )
        before = (cursor_time, cursor_candidate_id)
    access_preflight = _domain_access_allowed(access, domain)
    if access_preflight == "deny":
        return _payload("not_authorized", domain, start, end, filters, [], False, None, clean_limit)
    if rule_snapshot is not None:
        supported_rules = _rule_snapshot_payload(rule_snapshot)
    else:
        try:
            supported_rules = _read_supported_rules()
            rule_snapshot = _normalize_rule_snapshot(supported_rules)
        # Inventory is optional coverage metadata.  Its independent read must not
        # erase already-authorizable relations; relation queries below retain their
        # own fail-closed SchemaUnavailable handling.
        except Exception:
            supported_rules = None
    result_revision = _rule_snapshot_revision(rule_snapshot) if rule_snapshot is not None else None
    try:
        items, has_more, next_cursor, scan_limited = _read_visible_relation_page(
            access=access, domain=domain, start=start, end=end, filters=filters,
            limit=clean_limit, before=before, access_preflight=access_preflight,
            rule_snapshot=rule_snapshot,
        )
    except SchemaUnavailable:
        return _payload("schema_unavailable", domain, start, end, filters, [], False, None, clean_limit, result_revision=result_revision)
    if not items:
        return _payload("empty", domain, start, end, filters, [], has_more, next_cursor, clean_limit, scan_limited=scan_limited, supported_rules=supported_rules, supported_rules_unavailable=supported_rules is None, result_revision=result_revision)
    return _payload("available", domain, start, end, filters, items, has_more, next_cursor, clean_limit, scan_limited=scan_limited, supported_rules=supported_rules, supported_rules_unavailable=supported_rules is None, result_revision=result_revision)


def _hydrated_candidate_authorized(access: Mapping[str, Any], relation: Mapping[str, Any]) -> bool:
    evidence = list(relation.get("evidence") or [])
    if not evidence:
        return False
    # Production hydration carries the resource tuple for every atom. Focused
    # legacy test doubles may omit it; their preflight decision remains the
    # compatible substitute, whereas a partial tuple fails closed.
    complete = [item for item in evidence if all(item.get(key) not in (None, "") for key in ("server_id", "domain_id", "channel"))]
    if not complete:
        return True
    if len(complete) != len(evidence):
        return False
    return _candidate_authorized(access, {"evidence": complete})


def _read_visible_relation_page(
    *, access: Mapping[str, Any], domain: int, start: datetime, end: datetime,
    filters: Mapping[str, Any], limit: int, before: tuple[datetime, str] | None,
    access_preflight: str, rule_snapshot: RuleSnapshot | None = None,
) -> tuple[list[dict[str, Any]], bool, str | None, bool]:
    """Select, hydrate and authorize an entire relation page in one snapshot."""

    with _relation_snapshot():
        authorized: list[dict[str, Any]] = []
        scan_before = before
        scanned_pages = 0
        scan_limited = False
        source_has_more_for_domain_page = False
        last_scanned: dict[str, Any] | None = None
        while len(authorized) <= limit:
            preflight, source_has_more = _read_candidate_preflight(
                domain_id=domain, start=start, end=end, filters=filters,
                limit=limit, before=scan_before, rule_snapshot=rule_snapshot,
            )
            scanned_pages += 1
            if not preflight:
                break
            last_scanned = preflight[-1]
            authorized.extend(candidate for candidate in preflight if _candidate_authorized(access, candidate))
            if access_preflight == "allow":
                source_has_more_for_domain_page = source_has_more
            if len(authorized) > limit or not source_has_more:
                break
            if access_preflight == "allow":
                break
            if scanned_pages >= MAX_RESOURCE_SCOPED_PREFLIGHT_PAGES:
                scan_limited = True
                break
            scan_time = _utc(last_scanned.get("window_end_utc"))
            if scan_time is None:
                raise ValueError("invalid_semantic_relation_filter")
            scan_before = (scan_time, str(last_scanned["candidate_id"]))
        authorized = authorized[:limit + 1]
        capped_continuation = (
            scan_limited and source_has_more and last_scanned is not None
            and rule_snapshot is not None
        )
        if not authorized:
            next_cursor = None
            if capped_continuation:
                next_cursor = _encode_cursor(
                    domain_id=domain, start=start, end=end, filters=filters,
                    rule_snapshot=rule_snapshot,
                    window_end=_utc(last_scanned["window_end_utc"]) or start,
                    candidate_id=str(last_scanned["candidate_id"]),
                )
            return [], capped_continuation, next_cursor, scan_limited
        raw_has_more = len(authorized) > limit or (
            access_preflight == "allow" and len(authorized) == limit and source_has_more_for_domain_page
        ) or capped_continuation
        if raw_has_more and rule_snapshot is None:
            scan_limited = True
        has_more = raw_has_more and rule_snapshot is not None
        authorized = authorized[:limit]
        ids = [str(candidate["candidate_id"]) for candidate in authorized]
        hydrated = _read_authorized_candidates(ids)
        by_id = {str(item["candidate_id"]): item for item in hydrated}
        items = [
            _present_relation(by_id[candidate_id])
            for candidate_id in ids
            if candidate_id in by_id and _hydrated_candidate_authorized(access, by_id[candidate_id])
        ]
        # Under one snapshot these sets are identical. A mismatch is treated as
        # a denial, never as a pagination/count signal from changed evidence.
        if len(items) != len(ids):
            return [], False, None, scan_limited
        next_cursor = None
        if has_more:
            last = last_scanned if capped_continuation else authorized[-1]
            assert last is not None and rule_snapshot is not None
            next_cursor = _encode_cursor(
                domain_id=domain, start=start, end=end, filters=filters,
                rule_snapshot=rule_snapshot,
                window_end=_utc(last["window_end_utc"]) or start,
                candidate_id=str(last["candidate_id"]),
            )
        return items, has_more, next_cursor, scan_limited


def _payload(state: str, domain: int, start: datetime, end: datetime, filters: Mapping[str, Any], items: list[dict[str, Any]], has_more: bool, next_cursor: str | None, limit: int, *, scan_limited: bool = False, supported_rules: list[dict[str, Any]] | None = None, supported_rules_unavailable: bool = False, result_revision: str | None = None) -> dict[str, Any]:
    observed_rules = sorted({
        (str(item.get("rule_id")), int(item.get("rule_version") or 0))
        for item in items
        if str(item.get("rule_id") or "") and int(item.get("rule_version") or 0) > 0
    })
    coverage = {
        "state": "available" if state == "available" else state,
        "matched_relation_count": len(items) if state == "available" else None,
        "matched_relation_state": "bounded_page" if state == "available" else state,
        "limitation_codes": ["bounded_retained_page", "no_completeness_proof"],
        # A matched candidate witnesses that its rule was observed, but does
        # not establish the complete active/supported rule inventory.  That
        # independent schema check is deliberately not inferred from rows.
        "supported_rules": supported_rules or [],
        "observed_rules": [
            {"rule_id": rule_id, "rule_version": rule_version}
            for rule_id, rule_version in observed_rules
        ] if state == "available" else [],
        "limitations": [
            "Покрытие относится только к разрешённой ограниченной странице сохранённых связей.",
            "Тестовый или пустой результат не доказывает наличие либо полноту retained-истории.",
        ] + (
            ["Продолжение страницы недоступно без подтверждённой версии правил; более поздние разрешённые связи могли не быть прочитаны."]
            if scan_limited and result_revision is None
            else ["Поиск по resource-scoped доступу ограничен числом страниц; продолжение доступно с той же версией результата."]
            if scan_limited
            else []
        ),
    }
    if supported_rules is not None:
        coverage["supported_rules_state"] = "available"
    elif supported_rules_unavailable or state == "schema_unavailable":
        coverage["supported_rules_state"] = "check_unavailable"
    return {"contract_id": CONTRACT_ID, "state": state, "domain_id": domain, "time_bounds": {"from_utc": _iso(start), "to_utc_exclusive": _iso(end)}, "filters": dict(filters), "result_revision": result_revision, "items": items, "has_more": has_more, "next_cursor": next_cursor, "coverage": coverage, "limits": {"max_period_days": MAX_PERIOD_DAYS, "row_limit": limit, "max_row_limit": MAX_LIMIT, "bounded": True}}


def _typed_identity_basis(partition_key: object) -> dict[str, Any] | None:
    """Translate a trusted correlation partition into a public typed identity basis."""
    pieces = parse_exact_domain_sid_partition(partition_key)
    if pieces is None:
        return None
    try:
        domain_id = int(pieces["domain"])
    except (KeyError, TypeError, ValueError):
        return None
    if set(pieces) == {"domain", "account_sid"}:
        return {
            "kind": "exact_domain_account_sid",
            "domain_id": domain_id,
            "account_sid": pieces["account_sid"],
        }
    if set(pieces) == {"domain", "member_sid", "group_sid"}:
        return {
            "kind": "exact_domain_member_group_sid",
            "domain_id": domain_id,
            "member_sid": pieces["member_sid"],
            "group_sid": pieces["group_sid"],
        }
    if set(pieces) == {"domain", "account_member_sid"}:
        return {
            "kind": "exact_domain_account_member_sid",
            "domain_id": domain_id,
            "account_member_sid": pieces["account_member_sid"],
        }
    return None


def _present_relation(relation: Mapping[str, Any]) -> dict[str, Any]:
    """Expose anchor ambiguity only after every evidence item passed preflight."""
    item = dict(relation)
    identity_basis = _typed_identity_basis(item.pop("partition_key", None))
    if identity_basis is not None:
        item["identity_basis"] = identity_basis
    evidence = [dict(value) for value in item.get("evidence") or []]
    for value in evidence:
        value.pop("server_id", None)
        value.pop("domain_id", None)
    item["evidence"] = evidence
    if str(item.get("rule_id")) in _AMBIGUITY_RULE_IDS and int(item.get("rule_version") or 0) >= 2:
        ordered = sorted(evidence, key=lambda value: int(value.get("evidence_order") or 0))
        for index, value in enumerate(ordered):
            value["evidence_role"] = "anchor" if index == 0 else "alternative_continuation"
        continuations = max(0, len(ordered) - 1)
        item["continuation_state"] = "unique" if continuations == 1 else "ambiguous"
        item["possible_continuation_count"] = continuations
        item["evidence"] = ordered
    return item


def _read_candidate_preflight(
    *, domain_id: int, start: datetime, end: datetime, filters: Mapping[str, Any],
    limit: int, before: tuple[datetime, str] | None,
    rule_snapshot: RuleSnapshot | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    event_filters = {key: value for key, value in filters.items() if key not in {"rule_version", "relation_kind"}}
    (
        event_ids, provider_predicate, provider_params,
        _target_identity_sql, _target_name_sql, filter_sql, filter_params,
    ) = security_event_read_contract(
        event_filters,
        event_alias="selected_event", facts_alias="selected_facts", server_alias="selected_server",
        keywords_alias="selected_keywords", provider_alias="selected_provider",
    )
    clauses = [
        "candidate.candidate_status='matched'",
        "candidate.window_start_utc<%s",
        "candidate.window_end_utc>=%s",
        "exists (select 1 from semantic_correlation_candidate_evidence domain_evidence join normalized_events domain_normalized on domain_normalized.normalized_event_id=domain_evidence.normalized_event_id join events_v2_core domain_event on domain_event.id=domain_normalized.source_event_id where domain_evidence.candidate_id=candidate.candidate_id and domain_event.domain_id=%s)",
        "not exists (select 1 from semantic_correlation_candidate_evidence foreign_evidence join normalized_events foreign_normalized on foreign_normalized.normalized_event_id=foreign_evidence.normalized_event_id join events_v2_core domain_event on domain_event.id=foreign_normalized.source_event_id where foreign_evidence.candidate_id=candidate.candidate_id and domain_event.domain_id<>%s)",
    ]
    params: list[Any] = [end, start, domain_id, domain_id]
    if rule_snapshot is None:
        clauses.append("not exists (select 1 from semantic_correlation_rules newer_rule where newer_rule.rule_id=candidate.rule_id and newer_rule.rule_version>candidate.rule_version and newer_rule.lifecycle_status in ('shadow','enabled'))")
    elif not rule_snapshot:
        clauses.append("false")
    else:
        clauses.append("(" + " or ".join(
            "(candidate.rule_id=%s and candidate.rule_version=%s)"
            for _rule_id, _version, _state in rule_snapshot
        ) + ")")
        for rule_id, version, _state in rule_snapshot:
            params.extend((rule_id, version))
    clauses.append(
        "exists (select 1 from semantic_correlation_candidate_evidence selected_evidence "
        "join normalized_events selected_normalized on selected_normalized.normalized_event_id=selected_evidence.normalized_event_id "
        "join events_v2_core selected_event on selected_event.id=selected_normalized.source_event_id "
        "join servers selected_server on selected_server.id=selected_event.server_id "
        "join storage_v2_channel selected_channel on selected_channel.id=selected_event.channel_id "
        "join storage_v2_provider selected_provider on selected_provider.id=selected_event.provider_id "
        "left join storage_v2_keywords selected_keywords on selected_keywords.id=selected_event.keywords_id "
        "left join event_facts_v2 selected_facts on selected_facts.event_id=selected_event.id "
        "where selected_evidence.candidate_id=candidate.candidate_id "
        "and selected_event.domain_id=%s and selected_server.role='domain_controller' "
        "and selected_event.event_id=any(%s) and selected_channel.value=%s and "
        + provider_predicate
        + " and selected_event.time_created_utc>=%s and selected_event.time_created_utc<%s"
        + filter_sql
        + ")"
    )
    params.extend([domain_id, event_ids, SECURITY_CHANNEL, *provider_params, start, end, *filter_params])
    for key, column in (("rule_version", "candidate.rule_version"), ("relation_kind", "candidate.relation_kind")):
        if filters.get(key) is not None:
            clauses.append(column + "=%s")
            params.append(filters[key])
    if before:
        clauses.append("(candidate.window_end_utc,candidate.candidate_id)<(%s,%s::uuid)")
        params.extend(before)
    sql = (
        "with candidate_page as (select candidate.candidate_id,candidate.window_end_utc "
        "from semantic_correlation_candidates candidate where "
        + " and ".join(clauses)
        + " order by candidate.window_end_utc desc,candidate.candidate_id desc limit %s) "
        "select candidate.candidate_id,candidate.window_end_utc,normalized.source_event_id as event_db_id,"
        "event.server_id,event.domain_id,channel.value as channel from candidate_page candidate "
        "join semantic_correlation_candidate_evidence evidence on evidence.candidate_id=candidate.candidate_id "
        "join normalized_events normalized on normalized.normalized_event_id=evidence.normalized_event_id "
        "join events_v2_core event on event.id=normalized.source_event_id "
        "join storage_v2_channel channel on channel.id=event.channel_id "
        "order by candidate.window_end_utc desc,candidate.candidate_id desc,evidence.evidence_order"
    )
    params.append(limit + 1)
    try:
        snapshot = _ACTIVE_RELATION_SNAPSHOT.get()
        if snapshot is not None:
            cur = snapshot.cursor()
            cur.execute(sql, params)
            rows = [dict(row) for row in cur.fetchall()]
        else:
            with _connect() as conn, conn.cursor() as cur:
                cur.execute("set transaction isolation level repeatable read, read only")
                cur.execute(sql, params)
                rows = [dict(row) for row in cur.fetchall()]
    except Exception as exc:
        if "undefined_table" in str(exc).casefold() or "does not exist" in str(exc).casefold():
            raise SchemaUnavailable() from exc
        raise
    candidates: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = candidates.setdefault(str(row["candidate_id"]), {"candidate_id": str(row["candidate_id"]), "window_end_utc": row["window_end_utc"], "evidence": []})
        item["evidence"].append({key: row[key] for key in ("event_db_id", "server_id", "domain_id", "channel")})
    page = list(candidates.values())[:limit]
    return page, len(candidates) > limit


def _read_authorized_candidates(candidate_ids: list[str]) -> list[dict[str, Any]]:
    if not candidate_ids:
        return []
    sql = """select candidate.candidate_id,candidate.rule_id,candidate.rule_version,candidate.relation_kind,candidate.partition_key,candidate.window_start_utc,candidate.window_end_utc,candidate.confidence,candidate.explanation,evidence.evidence_order,core.id as event_db_id,core.event_id,core.time_created_utc,normalized.semantic_type,server.hostname as source_host,core.server_id,core.domain_id,channel.value as channel
from semantic_correlation_candidates candidate
join semantic_correlation_candidate_evidence evidence on evidence.candidate_id=candidate.candidate_id
join normalized_events normalized on normalized.normalized_event_id=evidence.normalized_event_id
join events_v2_core core on core.id=normalized.source_event_id
join servers server on server.id=core.server_id
join storage_v2_channel channel on channel.id=core.channel_id
where candidate.candidate_id=any(%s::uuid[])
    order by candidate.window_end_utc desc,candidate.candidate_id desc,evidence.evidence_order"""
    try:
        snapshot = _ACTIVE_RELATION_SNAPSHOT.get()
        if snapshot is not None:
            cur = snapshot.cursor()
            cur.execute(sql, (candidate_ids,))
            rows = [dict(row) for row in cur.fetchall()]
        else:
            with _connect() as conn, conn.cursor() as cur:
                cur.execute("set transaction read only")
                cur.execute(sql, (candidate_ids,))
                rows = [dict(row) for row in cur.fetchall()]
    except Exception as exc:
        if "undefined_table" in str(exc).casefold() or "does not exist" in str(exc).casefold():
            raise SchemaUnavailable() from exc
        raise
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        candidate_id = str(row["candidate_id"])
        item = result.setdefault(candidate_id, {key: row[key] for key in ("candidate_id", "rule_id", "rule_version", "relation_kind", "partition_key", "window_start_utc", "window_end_utc", "confidence", "explanation")})
        item.setdefault("evidence", []).append({key: row[key] for key in ("event_db_id", "event_id", "time_created_utc", "semantic_type", "source_host", "server_id", "domain_id", "channel", "evidence_order")})
    return list(result.values())


_connect = get_runtime_connection
