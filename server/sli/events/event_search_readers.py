"""Split out of ``server.sli.events.event_search`` (plan 7.2b).

Module-level names of ``event_search`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.events.event_search as _src


def _query_v2_postgres_event_rows(filters: dict[str, _src.Any], fetch_limit: int, timeout_ms: int, *, account_timeline: bool) -> list[dict[str, _src.Any]]:
    where_sql, params = _src._v2_handler_where_clause(filters, account_timeline=account_timeline)
    cursor_sql, cursor_params = _src._cursor_where_clause(filters)
    where_sql = _src._append_where(where_sql, cursor_sql)
    params.extend(cursor_params)
    order_sql = "asc" if filters["order"] == "asc" else "desc"
    return _src._database.query_rows_bounded(
        f"""
        select e.id,e.normalized_hash,s.hostname as server,channel.value as channel,provider.value as provider_name,e.event_id,e.event_record_id,
               e.time_created_utc,e.time_created_utc as time_created_local,e.subject_user_name,subject_domain.value as subject_domain_name,
               e.target_user_name,target_domain.value as target_domain_name,e.ip_address,e.workstation_name,e.logon_id,
               facts.message_sample as message_text,
               jsonb_build_object(
                 'TaskName',facts.task_name,'Action',facts.task_action,'Author',facts.task_author,
                 'RunAs',facts.run_as,'ProcessName',facts.process_name,'Message',facts.message_sample
               )::text as event_data_json
        from events_v2_core e join servers s on s.id=e.server_id
        join storage_v2_channel channel on channel.id=e.channel_id
        left join storage_v2_provider provider on provider.id=e.provider_id
        left join storage_v2_domain_name subject_domain on subject_domain.id=e.subject_domain_id
        left join storage_v2_domain_name target_domain on target_domain.id=e.target_domain_id
        left join event_facts_v2 facts on facts.event_id=e.id
        {where_sql}
        order by e.time_created_utc {order_sql},coalesce(e.event_record_id,-1) {order_sql},e.id {order_sql} limit ?
        """,
        tuple(params + [fetch_limit]), statement_timeout_ms=timeout_ms, wall_timeout_ms=timeout_ms + 1500,
    )


def _query_clickhouse_history_rows(
    filters: dict[str, _src.Any], fetch_limit: int, *, account_timeline: bool,
) -> list[dict[str, _src.Any]]:
    port = _src.configured_read_port()
    if port is None:
        raise RuntimeError("history ClickHouse port missing")
    params: dict[str, str] = {}

    def bind(value: _src.Any) -> str:
        name = f"v{len(params)}"
        params[name] = str(value)
        return "{" + name + ":String}"

    def field(name: str) -> str:
        # All callers use constant field names from this function.
        return f"JSONExtractString(e.core_json,'{name}')"

    def account_predicate(value: _src.Any, columns: tuple[str, ...]) -> str:
        exact = _src._account_exact_values(value)
        prefix = _src._account_prefix_values(value)
        if not exact:
            return "0"
        clauses = []
        for column in columns:
            normalized = f"lowerUTF8({column})"
            parts = [f"{normalized} IN ({','.join(bind(item) for item in exact)})"]
            parts.extend(f"{normalized} LIKE {bind(item)}" for item in prefix)
            clauses.append("(" + " OR ".join(parts) + ")")
        return "(" + " OR ".join(clauses) + ")"

    parts = [
        "e.batch_sha256 IN (SELECT batch_sha256 FROM sli_history.published_batches)",
    ]
    for key, column in (
        ("channel", field("channel")),
        ("provider", field("provider_name")),
    ):
        if filters.get(key):
            if key == "provider":
                parts.append(f"lowerUTF8({column})=lowerUTF8({bind(filters[key])})")
            else:
                parts.append(f"{column}={bind(filters[key])}")
    for key, column in (
        ("subject", field("subject_user_name")),
        ("target", field("target_user_name")),
    ):
        if filters.get(key):
            parts.append(account_predicate(filters[key], (column,)))
    if filters.get("servers"):
        names = list(filters["servers"])
        server_rows = _src._database.query_rows_bounded(
            f"select id from servers where hostname in ({','.join('?' for _ in names)})",
            tuple(names), statement_timeout_ms=3000,
        )
        server_ids = [int(row["id"]) for row in server_rows]
        if not server_ids:
            return []
        parts.append(f"e.server_id IN ({','.join(str(value) for value in server_ids)})")
    for key, op in (("time_from", ">="), ("time_to", "<")):
        if filters.get(key):
            parts.append(
                f"e.time_created_utc {op} parseDateTime64BestEffort({bind(filters[key])},6,'UTC')"
            )
    if filters.get("event_ids"):
        parts.append(f"e.event_key IN ({','.join(str(int(value)) for value in filters['event_ids'])})")
    category = filters.get("category")
    family = {
        "authentication": _src.AUTHENTICATION_EVENT_IDS,
        "account_management": _src.ACCOUNT_MANAGEMENT_EVENT_IDS,
        "privilege_management": _src.PRIVILEGE_MANAGEMENT_EVENT_IDS,
        "policy_change": _src.POLICY_CHANGE_EVENT_IDS,
    }.get(category)
    if family:
        parts.append(f"e.event_key IN ({','.join(str(value) for value in sorted(family))})")
    elif category == "service_task":
        parts.append(
            "(lowerUTF8(" + field("channel") + ") LIKE '%taskscheduler%' OR "
            f"e.event_key IN ({','.join(str(value) for value in sorted(_src.SERVICE_TASK_EVENT_IDS))}))"
        )
    subject = field("subject_user_name")
    target = field("target_user_name")
    if account_timeline or filters.get("account"):
        parts.append(account_predicate(filters.get("account"), (subject, target)))
    elif filters.get("q"):
        value = filters["q"]
        q_parts = [account_predicate(value, (subject, target))]
        exact = _src._account_exact_values(value)
        for column in (field("ip_address"), field("logon_id")):
            q_parts.append(f"{column} IN ({','.join(bind(item) for item in exact)})")
        try:
            q_parts.append(f"e.event_key={int(value)}")
        except ValueError:
            pass
        parts.append("(" + " OR ".join(q_parts) + ")")
    record = "coalesce(JSONExtract(e.core_json,'event_record_id','Nullable(Int64)'),-1)"
    cursor = filters.get("cursor_values") or {}
    direction = "ASC" if filters["order"] == "asc" else "DESC"
    if cursor:
        op = ">" if direction == "ASC" else "<"
        cursor_time = f"parseDateTime64BestEffort({bind(cursor['time'])},6,'UTC')"
        cursor_record = int(cursor["record"])
        cursor_id = int(cursor["id"])
        parts.append(
            f"(e.time_created_utc {op} {cursor_time} OR "
            f"(e.time_created_utc={cursor_time} AND {record} {op} {cursor_record}) OR "
            f"(e.time_created_utc={cursor_time} AND {record}={cursor_record} "
            f"AND e.event_db_id {op} {cursor_id}))"
        )
    sql = (
        "SELECT e.event_db_id,e.time_created_utc,e.event_key,e.server_id,"
        "e.noise_class,e.core_json,e.facts_json,e.row_sha256 "
        "FROM sli_history.events e WHERE " + " AND ".join(parts) + " "
        f"ORDER BY e.time_created_utc {direction},{record} {direction},"
        f"e.event_db_id {direction} LIMIT {int(fetch_limit)}"
    )
    stored = _src._history_rows(port, sql, query_params=params)
    server_ids: set[int] = set()
    rows: list[dict[str, _src.Any]] = []
    for stored_row in stored:
        core = _src.json.loads(stored_row["core_json"])
        facts = _src.json.loads(stored_row["facts_json"])
        if _src._payload_sha({"core": core, "facts": facts}) != stored_row["row_sha256"]:
            raise _src.ArchiveIntegrityError("historical search fact hash mismatch")
        if int(core["id"]) != int(stored_row["event_db_id"]):
            raise _src.ArchiveIntegrityError("historical search identity mismatch")
        if (
            _src._json_ch_time(core["time_created_utc"]) != stored_row["time_created_utc"]
            or int(core["event_id"]) != int(stored_row["event_key"])
            or int(core["server_id"]) != int(stored_row["server_id"])
            or str(core.get("noise_class") or "") != stored_row["noise_class"]
        ):
            raise _src.ArchiveIntegrityError("historical search indexed fact mismatch")
        server_ids.add(int(core["server_id"]))
        rows.append({
            **core, **facts, "id": int(core["id"]),
            "time_created_local": core["time_created_utc"],
            "message_text": facts.get("message_sample"),
            "event_data_json": _src.json.dumps({
                "TaskName": facts.get("task_name"), "Action": facts.get("task_action"),
                "Author": facts.get("task_author"), "RunAs": facts.get("run_as"),
                "ProcessName": facts.get("process_name"), "Message": facts.get("message_sample"),
            }, ensure_ascii=False),
            "source_payload_state": "expired",
        })
    if server_ids:
        servers = _src._database.query_rows_bounded(
            f"select id,hostname from servers where id in ({','.join('?' for _ in server_ids)})",
            tuple(sorted(server_ids)), statement_timeout_ms=3000,
        )
        names = {int(row["id"]): row["hostname"] for row in servers}
        if set(names) != server_ids:
            raise _src.ArchiveIntegrityError("historical search server identity missing")
        for row in rows:
            row["server"] = names[int(row["server_id"])]
    return rows


def _query_v2_deep_archive_rows(filters: dict[str, _src.Any], fetch_limit: int, timeout_ms: int) -> list[dict[str, _src.Any]]:
    """Search exact metadata candidates in one bounded, verified archive pass."""
    from server.sli.storage.storage_v2_runtime import DEEP_SEARCH_CANDIDATE_LIMIT

    where_sql, params = _src._v2_handler_where_clause({**filters, "q": None, "account": None}, account_timeline=False)
    cursor_sql, cursor_params = _src._cursor_where_clause(filters)
    where_sql = _src._append_where(where_sql, cursor_sql)
    params.extend(cursor_params)
    order_sql = "asc" if filters["order"] == "asc" else "desc"
    candidates = _src._database.query_rows_bounded(
        f"""
        select e.id,e.server_id,e.domain_id,e.log_source_id,e.event_id,
               e.time_created_utc,e.event_record_id,s.hostname as server
        from events_v2_core e join servers s on s.id=e.server_id
        join storage_v2_channel channel on channel.id=e.channel_id
        left join storage_v2_provider provider on provider.id=e.provider_id
        {where_sql}
        order by e.time_created_utc {order_sql},coalesce(e.event_record_id,-1) {order_sql},e.id {order_sql} limit ?
        """,
        tuple(params + [DEEP_SEARCH_CANDIDATE_LIMIT + 1]), statement_timeout_ms=timeout_ms,
        wall_timeout_ms=timeout_ms + 1500,
    )
    if len(candidates) > DEEP_SEARCH_CANDIDATE_LIMIT:
        raise ValueError("archive search exceeds candidate limit; narrow the event range")
    if not candidates:
        return []
    from server.sli.core.postgres_runtime_pipeline import connect

    reader = _src.StorageV2RuntimeReader(
        _src.PostgresStorageV2ReadStore(connect),
        _src.ArchiveReader(_src.PostgresArchiveManifestStore(connect)),
    )
    payload_rows = reader.deep_search_candidates(
        term=str(filters.get("q") or filters.get("account") or "").strip(),
        candidates=candidates,
        max_blocks=8,
        max_results=fetch_limit,
        account_values=(
            _src._account_exact_values(filters["account"])
            if filters.get("account") else None
        ),
    )
    server_names = {int(row["id"]): row["server"] for row in candidates}
    return [{**dict(row), "server": server_names[int(row["id"])]} for row in payload_rows]
