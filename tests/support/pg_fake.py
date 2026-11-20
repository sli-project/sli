"""In-memory stand-in for the PostgreSQL read path, used by business-logic tests.

Why this exists
---------------
About 25 tests used a temporary SQLite file only as a cheap event store while
testing security-monitor / search / timeline / event-detail logic.  SQLite is
being removed from the runtime (docs/SQLITE_RUNTIME_REMOVAL.md, chunk 8),
and CI has no PostgreSQL, so those tests need a store that is neither.

Boundary (two seams, both explicit)
-----------------------------------
1. Function seam, used by event search / account timeline.  The production code
   builds a normalised ``filters`` dict and hands it to ``_query_v2_event_rows``.
   The double replaces that one function and filters the seeded rows in Python
   (account lookup, q, servers, time range, event ids, keyset cursor, order,
   limit).  Everything above it (normalisation, row shaping, timeline chain,
   summary, rendering, investigation pivots) stays real.
2. SQL seam, used by the security monitor and event detail, which put every
   filter only into SQL text.  The double replaces ``query_rows`` /
   ``query_rows_bounded`` in the modules under test and answers exactly the
   query shapes those modules issue.  There is NO SQL parser: the WHERE text is
   split at top-level `` and `` and each clause is recognised by its known
   production prefix (or by equality with the production helper that builds it).
   An unknown query shape or clause raises ``UnsupportedQuery`` so a changed
   query fails loudly instead of silently returning wrong rows.

What is NOT covered (by design)
-------------------------------
The double re-implements predicate semantics in Python, so it cannot prove that
the SQL text itself is correct (LIKE/lower/COALESCE behaviour, the compiled
catalog risk SQL, index-friendliness).  That belongs to ``postgres_integration``
tests against a real database.  Tests using this double verify the business
outcome: which rows the logic asks for, how it shapes, counts, limits, groups
and renders them.

Rows are flat dicts carrying the column names the queries project
(``subject_user_name``, ``event_data_json`` ...), which is the shape both the
V1 and the V2 projections return.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any


class UnsupportedQuery(AssertionError):
    """Raised when production code issues a query the double does not model."""


_COLUMNS = (
    "id", "server", "channel", "provider_name", "event_id", "event_record_id", "level", "task",
    "opcode", "computer", "time_created_utc", "time_created_local", "subject_user_sid",
    "subject_user_name", "subject_domain_name", "target_user_sid", "target_user_name",
    "target_domain_name", "ip_address", "workstation_name", "logon_id", "correlation_id",
    "message_text", "event_data_json",
)


def _norm(sql: str) -> str:
    return " ".join(sql.split())


# Storage V2 core projected under the V1 alias ``e`` (security monitor, plan 6.5).
# The double answers it from the same rows, but with only the payload V2 keeps:
# ``event_data_json`` is rebuilt from ``event_facts_v2`` (the keys below) and
# ``message_text`` is the facts' message sample.
_V2_EVENT_SOURCE = re.compile(
    r"\( select core\.id, core\.event_id, channel\.value as channel, .*? "
    r"from events_v2_core core .*?\) e join servers s on s\.id=e\.server_id",
    re.IGNORECASE,
)
# Storage V2 entity drill-down sources (server.sli.entities.entity_details):
# links and core keep the V1 aliases ``eel`` / ``e``; link details come from
# the archive, which ``install_entity_details`` answers from the seeded links.
_V2_ENTITY_EVENT_SOURCE = re.compile(
    r"\( select link\.event_id,link\.entity_id,role\.value as link_role,.*? "
    r"\) e on e\.id=eel\.event_id join servers s on s\.id=e\.server_id",
    re.IGNORECASE,
)
_V2_ENTITY_SOURCE = "from entities_v2 entity"

_V2_FACT_KEYS = ("TaskName", "Action", "Author", "RunAs", "ProcessName", "Message")


def _as_v2_row(row: dict) -> dict:
    if "event_data_json" not in row:
        return row
    data = json.loads(row.get("event_data_json") or "{}")
    kept = {key: data.get(key) for key in _V2_FACT_KEYS}
    return {**row, "event_data_json": json.dumps(kept)}


def _lower(value: Any) -> str:
    return str(value or "").casefold()


def split_top_level_and(where: str) -> list[str]:
    """Split a WHERE body at `` and `` outside parentheses and string literals."""
    clauses: list[str] = []
    depth = 0
    quote = False
    start = 0
    i = 0
    while i < len(where):
        ch = where[i]
        if ch == "'":
            quote = not quote
        elif not quote:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth == 0 and where[i:i + 5] == " and ":
                clauses.append(where[start:i].strip())
                start = i + 5
                i += 4
        i += 1
    clauses.append(where[start:].strip())
    return [c for c in clauses if c]


class FakePgStore:
    """Seeded event rows plus the small set of PostgreSQL answers tests need."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.entities: list[dict[str, Any]] = []
        # Link rows: event_id, entity_id, link_role, confidence, extracted_from, attributes_json, evidence_json.
        self.links: list[dict[str, Any]] = []
        self.queries: list[tuple[str, tuple]] = []
        self._next_id = 1

    # ------------------------------------------------------------------ seed
    def add_event(
        self,
        *,
        event_id: int,
        time: str,
        record_id: int | None = None,
        server: str = "DC1",
        channel: str = "Security",
        provider: str = "Microsoft-Windows-Security-Auditing",
        computer: str = "DC1",
        subject: str | None = None,
        subject_domain: str | None = "EXAMPLE",
        target: str | None = None,
        target_domain: str | None = "EXAMPLE",
        ip: str | None = None,
        workstation: str | None = None,
        logon_id: str | None = None,
        message: str = "",
        event_data: dict[str, Any] | None = None,
        time_local: str | None = None,
    ) -> int:
        row_id = self._next_id
        self._next_id += 1
        self.events.append({
            "id": row_id, "server": server, "channel": channel, "provider_name": provider,
            "event_id": event_id, "event_record_id": record_id if record_id is not None else row_id,
            "level": None, "task": None, "opcode": None, "computer": computer,
            "time_created_utc": time, "time_created_local": time_local or time,
            "subject_user_sid": None, "subject_user_name": subject,
            "subject_domain_name": subject_domain, "target_user_sid": None,
            "target_user_name": target, "target_domain_name": target_domain,
            "ip_address": ip, "workstation_name": workstation, "logon_id": logon_id,
            "correlation_id": None, "message_text": message,
            "event_data_json": json.dumps(event_data, ensure_ascii=False) if event_data is not None else None,
        })
        return row_id

    def add_entity(
        self,
        *,
        entity_type: str,
        natural_key: str,
        display_name: str | None = None,
        first_seen: str | None = None,
        last_seen: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> int:
        entity_id = len(self.entities) + 1
        self.entities.append({
            "id": entity_id, "entity_type": entity_type, "natural_key": natural_key,
            "display_name": display_name, "domain_id": None, "server_id": None,
            "first_seen_utc": first_seen, "last_seen_utc": last_seen,
            "attributes_json": json.dumps(attributes, ensure_ascii=False) if attributes is not None else None,
        })
        return entity_id

    def add_link(
        self,
        *,
        event_id: int,
        entity_id: int,
        role: str,
        confidence: float | None = 1.0,
        extracted_from: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        self.links.append({
            "event_id": event_id, "entity_id": entity_id, "link_role": role,
            "confidence": confidence, "extracted_from": extracted_from,
            "attributes_json": json.dumps(attributes, ensure_ascii=False) if attributes is not None else None,
            "evidence_json": None,
        })

    # --------------------------------------------------------------- install
    def install(self, monkeypatch: Any, *modules: Any) -> FakePgStore:
        """Replace ``query_rows`` / ``query_rows_bounded`` in the given modules."""
        for module in modules:
            for name, fake in (("query_rows", self.query_rows), ("query_rows_bounded", self.query_rows_bounded)):
                if hasattr(module, name):
                    monkeypatch.setattr(module, name, fake)
        return self

    def install_security_monitor(self, monkeypatch: Any) -> FakePgStore:
        """SQL seam for the security monitor, event details and the dashboard summary."""
        from server.sli.core import database
        from server.sli.events import event_details
        from server.sli.events import security_events_monitor

        return self.install(monkeypatch, security_events_monitor, event_details, database)

    def install_entity_details(self, monkeypatch: Any) -> FakePgStore:
        """SQL seam for the entity drill-down report (Storage V2 projection of entities and links)."""
        from server.sli.entities import entity_details

        monkeypatch.setattr(entity_details, "is_postgres_runtime_db", lambda *_a, **_k: True)
        monkeypatch.setattr(entity_details, "primary_read_enabled", lambda: False)
        monkeypatch.setattr(entity_details, "_read_v2_link_details", self.link_details)
        return self.install(monkeypatch, entity_details)

    def install_event_search(self, monkeypatch: Any) -> FakePgStore:
        """Route event search / account timeline through the store (function seam)."""
        from server.sli.events import event_search

        monkeypatch.setattr(event_search, "_v2_primary_read_enabled_for_request", lambda *_a, **_k: True)
        monkeypatch.setattr("server.sli.storage.permanent_fact_history.primary_read_enabled", lambda: False)
        monkeypatch.setattr(event_search, "_query_v2_event_rows", self.search_rows)
        monkeypatch.setattr("server.sli.core.database.query_rows_bounded", self.query_rows_bounded)
        return self

    # ------------------------------------------------------------ SQL seam
    def query_rows_bounded(self, sql: str, params: tuple = (), **_bounds: Any) -> list[dict]:
        return self.query_rows(sql, params)

    def query_rows(self, sql: str, params: tuple = ()) -> list[dict]:
        text = _norm(sql)
        self.queries.append((text, tuple(params)))
        if _V2_ENTITY_SOURCE in text.lower():
            return self._v2_entities(text, params)
        entity_events = _V2_ENTITY_EVENT_SOURCE.search(text)
        if entity_events is not None:
            v1_text = text.replace(entity_events.group(0), "event_entity_links eel join events e on e.id=eel.event_id join servers s on s.id=e.server_id")
            return self._v2_entity_events(v1_text, params)
        v2_source = _V2_EVENT_SOURCE.search(text)
        if v2_source is None:
            return self._answer(text, params)
        rows = self._answer(text.replace(v2_source.group(0), "events e join servers s on s.id=e.server_id"), params)
        return [_as_v2_row(row) for row in rows]

    def _answer(self, text: str, params: tuple) -> list[dict]:
        low = text.lower()
        if "as event_db_id" in low and "limit ?" in low and "from events e join servers s" in low:
            return self._monitor_rows(text, params)
        if low.startswith("select e.event_id, count(*) as count from events e join servers s"):
            return self._monitor_summary(text, params)
        if '"important_total"' in low:
            return [self._monitor_aggregate(text, params)]
        if low.startswith("select count(*) as count from events e join servers s on s.id = e.server_id"):
            return [{"count": len(self._detail_filtered(text, params, with_paging=False))}]
        if "e.level," in low and "limit ? offset ?" in low:
            return self._detail_rows(text, params)
        if low.startswith("select entity.* from observed_entities entity where entity.id = ?"):
            return [dict(e) for e in self.entities if e["id"] == int(params[0])][:1]
        if low.startswith("select entity.* from observed_entities entity where lower(entity.natural_key) = lower(?)"):
            return self._resolve_entity(str(params[0]))
        if "from event_entity_links eel join events e on e.id=eel.event_id join servers s" in low:
            return self._entity_events(text, params)
        if "from event_entity_links_v2" in low and "group by event_id" in low:
            return self._relation_counts(params)
        if "from event_entity_link_blocks_v2 block" in low and "group by expanded.event_id" in low:
            # (max_id, min_id, *ids): the block range bounds come first.
            return self._relation_counts(tuple(params)[2:])
        if low in {"select count(*) as count from events", "select count(*) as count from events_v2_core"}:
            return [{"count": len(self.events)}]
        # Storage V2 event summary (server.sli.core.database._get_event_summary_v2).
        if low.startswith("select channel.value as channel, count(*) as count from events_v2_core event"):
            return self._group_count(("channel",))
        if low.startswith("select event.event_id, channel.value as channel, count(*) as count from events_v2_core event"):
            return self._group_count(("event_id", "channel"))[:20]
        if low.startswith("select server.hostname, channel.value as channel, count(event.id) as count from events_v2_core event"):
            rows = self._group_count(("server", "channel"))
            return sorted(
                ({"hostname": r["server"], "channel": r["channel"], "count": r["count"]} for r in rows),
                key=lambda r: (r["hostname"], r["channel"]),
            )
        if low.startswith("select channel, count(*) as count from events group by channel"):
            return self._group_count(("channel",))
        if low.startswith("select event_id, channel, count(*) as count from events group by event_id, channel"):
            return self._group_count(("event_id", "channel"))[:20]
        if low.startswith("select s.hostname, e.channel, count(e.id) as count from events e join servers s"):
            rows = self._group_count(("server", "channel"))
            return sorted(
                ({"hostname": r["server"], "channel": r["channel"], "count": r["count"]} for r in rows),
                key=lambda r: (r["hostname"], r["channel"]),
            )
        if low.startswith(("select distinct s.hostname, s.fqdn, s.role, s.is_active",
                           "select distinct server.hostname, server.fqdn, server.role, server.is_active")):
            counts: dict[str, int] = {}
            for row in self.events:
                counts[row["server"]] = counts.get(row["server"], 0) + 1
            return [
                {"hostname": name, "fqdn": None, "role": "domain_controller", "is_active": 1,
                 "domain_fqdn": None, "site_name": None, "count": count}
                for name, count in sorted(counts.items())
            ]
        raise UnsupportedQuery(f"pg_fake does not model this query: {text[:200]}")

    # ------------------------------------------------- where-clause plumbing
    @staticmethod
    def _split_where(text: str) -> tuple[int, str, str]:
        """Return (placeholders before WHERE, where body, tail after body)."""
        match = re.search(r"\swhere\s", text, flags=re.IGNORECASE)
        if not match:
            return text.count("?"), "", ""
        head = text[:match.start()]
        body = text[match.end():]
        tail = ""
        cut = re.search(r"\s(group by|order by|limit)\s", body, flags=re.IGNORECASE)
        if cut:
            body, tail = body[:cut.start()], body[cut.start():]
        return head.count("?"), body, tail

    def _predicates(
        self, text: str, params: tuple, table: dict[str, Callable[[str, tuple], Callable[[dict], bool] | None]],
    ) -> tuple[list[Callable[[dict], bool]], tuple]:
        offset, body, tail = self._split_where(text)
        predicates: list[Callable[[dict], bool]] = []
        cursor = offset
        for clause in split_top_level_and(body) if body else []:
            count = clause.count("?")
            args = tuple(params[cursor:cursor + count])
            cursor += count
            for matcher in table.values():
                predicate = matcher(clause, args)
                if predicate is not None:
                    predicates.append(predicate)
                    break
            else:
                raise UnsupportedQuery(f"pg_fake does not model this clause: {clause[:160]}")
        return predicates, tuple(params[cursor:]) if tail else ()

    # ------------------------------------------------------ security monitor
    def _monitor_table(self) -> dict[str, Callable[[str, tuple], Callable[[dict], bool] | None]]:
        from server.sli.events import security_events_monitor as mon

        def like_value(args: tuple) -> str:
            return _lower(str(args[0]).strip("%"))

        def event_ids(clause: str, args: tuple):
            if clause.startswith("e.event_id in ("):
                wanted = {int(v) for v in args}
                return lambda r: int(r["event_id"]) in wanted

        def account(clause: str, args: tuple):
            if clause.startswith("(lower(coalesce(e.subject_user_name,'')) like lower(?)"):
                needle = like_value(args)
                keys = ("subject_user_name", "target_user_name", "subject_domain_name", "target_domain_name",
                        "event_data_json", "message_text")
                return lambda r: any(needle in _lower(r.get(k)) for k in keys)

        def source(clause: str, args: tuple):
            if clause.startswith("(lower(coalesce(e.ip_address,'')) like lower(?)"):
                needle = like_value(args)
                return lambda r: any(needle in _lower(r.get(k)) for k in ("ip_address", "workstation_name", "computer"))

        def target(clause: str, args: tuple):
            if clause.startswith("(lower(coalesce(e.target_user_name,'')) like lower(?)"):
                needle = like_value(args)
                keys = ("target_user_name", "target_domain_name", "event_data_json", "message_text")
                return lambda r: any(needle in _lower(r.get(k)) for k in keys)

        def server(clause: str, args: tuple):
            if clause == "s.hostname = ?":
                return lambda r: r["server"] == args[0]

        def time_from(clause: str, args: tuple):
            if clause == "e.time_created_utc >= ?":
                return lambda r: str(r["time_created_utc"]) >= str(args[0])

        def time_to(clause: str, args: tuple):
            if clause == "e.time_created_utc <= ?":
                return lambda r: str(r["time_created_utc"]) <= str(args[0])

        def privileged(clause: str, args: tuple):
            if clause == _norm(mon._privileged_sql()):
                hints = re.findall(r"like '%([^%']+)%'", clause)
                ids = {int(v) for v in re.search(r"e\.event_id in \(([\d,]+)\)", clause).group(1).split(",")}
                return lambda r: int(r["event_id"]) in ids or any(
                    h in _lower(
                        f"{r.get('subject_domain_name') or ''}\\{r.get('subject_user_name') or ''} "
                        f"{r.get('target_domain_name') or ''}\\{r.get('target_user_name') or ''}"
                    )
                    for h in hints
                )

        def service(clause: str, args: tuple):
            if clause == _norm(mon._service_sql()):
                def is_service(r: dict) -> bool:
                    for key in ("subject_user_name", "target_user_name"):
                        name = _lower(r.get(key))
                        if (name.endswith("$") or name[:4] in {"svc_", "svc-"} or name[:3] == "sa_"
                                or "service" in name or "служб" in name):
                            return True
                    return False
                return is_service

        def risk(clause: str, args: tuple):
            if clause.startswith("((case when"):
                wanted = str(args[-1])
                # Stand-in for the compiled catalog risk SQL: the production Python
                # projection (_decorate -> build_event_card, fallback by event id).
                return lambda r: mon._decorate({**r, "event_db_id": r["id"]})["severity"] == wanted

        return {k: v for k, v in locals().items() if callable(v) and k not in {"mon", "like_value"}}

    def _monitor_filtered(self, text: str, params: tuple) -> list[dict]:
        predicates, _rest = self._predicates(text, params, self._monitor_table())
        return [r for r in self.events if all(p(r) for p in predicates)]

    def _monitor_rows(self, text: str, params: tuple) -> list[dict]:
        rows = self._monitor_filtered(text, params[:-1])
        rows.sort(key=lambda r: (str(r["time_created_utc"]), int(r["event_record_id"] or 0), int(r["id"])), reverse=True)
        return [{**r, "event_db_id": r["id"]} for r in rows[: int(params[-1])]]

    def _monitor_summary(self, text: str, params: tuple) -> list[dict]:
        counts: dict[int, int] = {}
        for row in self._monitor_filtered(text, params):
            counts[int(row["event_id"])] = counts.get(int(row["event_id"]), 0) + 1
        return [{"event_id": k, "count": v} for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]

    def _monitor_aggregate(self, text: str, params: tuple) -> dict[str, int]:
        from server.sli.events import security_events_monitor as mon

        rows = self._monitor_filtered(text, params)
        table = self._monitor_table()
        result: dict[str, int] = {"important_total": len(rows)}
        for ids, key in re.findall(r'sum\(case when e\.event_id in \(([\d,]+)\) then 1 else 0 end\) as "(\w+)"', text):
            wanted = {int(v) for v in ids.split(",")}
            result[key] = sum(1 for r in rows if int(r["event_id"]) in wanted)
        for level in ("high", "medium"):
            result[level] = sum(1 for r in rows if mon._decorate({**r, "event_db_id": r["id"]})["severity"] == level)
        privileged = table["privileged"](_norm(mon._privileged_sql()), ())
        service = table["service"](_norm(mon._service_sql()), ())
        result["privileged"] = sum(1 for r in rows if privileged(r))
        result["service"] = sum(1 for r in rows if service(r))
        return result

    # ---------------------------------------------------------- event detail
    def _detail_table(self) -> dict[str, Callable[[str, tuple], Callable[[dict], bool] | None]]:
        def by_id(clause: str, args: tuple):
            if clause == "e.id = ?":
                return lambda r: r["id"] == int(args[0])

        def event_ids(clause: str, args: tuple):
            if clause.startswith("e.event_id in ("):
                wanted = {int(v) for v in args}
                return lambda r: int(r["event_id"]) in wanted

        def channel(clause: str, args: tuple):
            if clause == "e.channel = ?":
                return lambda r: r["channel"] == args[0]

        def servers(clause: str, args: tuple):
            if clause.startswith("s.hostname in ("):
                return lambda r: r["server"] in set(args)

        def time_from(clause: str, args: tuple):
            if clause == "e.time_created_utc >= ?":
                return lambda r: str(r["time_created_utc"]) >= str(args[0])

        def time_to(clause: str, args: tuple):
            if clause == "e.time_created_utc <= ?":
                return lambda r: str(r["time_created_utc"]) <= str(args[0])

        def user(clause: str, args: tuple):
            if clause.startswith("(lower(coalesce(e.subject_user_name,'')) like lower(?)"):
                needle = _lower(str(args[0]).strip("%"))
                return lambda r: needle in _lower(r.get("subject_user_name")) or needle in _lower(r.get("target_user_name"))

        def ip(clause: str, args: tuple):
            if clause.startswith("(e.ip_address = ?"):
                needle = _lower(str(args[1]).strip("%"))
                return lambda r: r.get("ip_address") == args[0] or needle in _lower(r.get("workstation_name"))

        def logon(clause: str, args: tuple):
            if clause == "e.logon_id = ?":
                return lambda r: r.get("logon_id") == args[0]

        return {k: v for k, v in locals().items() if callable(v)}

    def _detail_filtered(self, text: str, params: tuple, *, with_paging: bool) -> list[dict]:
        predicates, _ = self._predicates(text, params, self._detail_table())
        return [r for r in self.events if all(p(r) for p in predicates)]

    def _detail_rows(self, text: str, params: tuple) -> list[dict]:
        limit, offset = int(params[-2]), int(params[-1])
        rows = self._detail_filtered(text, params[:-2], with_paging=True)
        reverse = " desc, e.event_record_id desc" in text.lower()
        rows.sort(key=lambda r: (str(r["time_created_utc"]), int(r["event_record_id"] or 0), int(r["id"])), reverse=reverse)
        return [{k: r.get(k) for k in _COLUMNS} for r in rows[offset: offset + limit]]

    # -------------------------------------------------------- entity drill-down
    def _resolve_entity(self, q: str) -> list[dict]:
        """Exact (natural key / display name) match first, else casefold prefix; newest first."""
        wanted = q.casefold()

        def exact(e: dict) -> bool:
            return wanted in (_lower(e["natural_key"]), _lower(e["display_name"]))

        found = [
            e for e in self.entities
            if exact(e) or _lower(e["display_name"]).startswith(wanted) or _lower(e["natural_key"]).startswith(wanted)
        ]
        found.sort(key=lambda e: int(e["id"]), reverse=True)
        found.sort(key=lambda e: str(e["last_seen_utc"] or ""), reverse=True)
        found.sort(key=lambda e: 0 if exact(e) else 1)
        return [dict(e) for e in found[:1]]

    def _entity_table(self) -> dict[str, Callable[[str, tuple], Callable[[dict], bool] | None]]:
        def entity(clause: str, args: tuple):
            if clause == "eel.entity_id = ?":
                return lambda r: r["entity_id"] == int(args[0])

        def role(clause: str, args: tuple):
            if clause == "eel.link_role = ?":
                return lambda r: r["link_role"] == args[0]

        def event_ids(clause: str, args: tuple):
            if clause.startswith("e.event_id in ("):
                return lambda r: int(r["event_id"]) in {int(v) for v in args}

        def channel(clause: str, args: tuple):
            if clause == "e.channel = ?":
                return lambda r: r["channel"] == args[0]

        def servers(clause: str, args: tuple):
            if clause.startswith("s.hostname in ("):
                return lambda r: r["server"] in set(args)

        def time_from(clause: str, args: tuple):
            if clause == "e.time_created_utc >= ?":
                return lambda r: str(r["time_created_utc"]) >= str(args[0])

        def time_to(clause: str, args: tuple):
            if clause == "e.time_created_utc < ?":
                return lambda r: str(r["time_created_utc"]) < str(args[0])

        return {
            "entity": entity, "role": role, "event_ids": event_ids, "channel": channel,
            "servers": servers, "time_from": time_from, "time_to": time_to,
        }

    def _entity_events(self, text: str, params: tuple) -> list[dict]:
        by_id = {e["id"]: e for e in self.events}
        joined = [
            {**by_id[link["event_id"]], **link, "event_db_id": link["event_id"], "event_id": by_id[link["event_id"]]["event_id"]}
            for link in self.links if link["event_id"] in by_id
        ]
        is_rows = "limit ? offset ?" in text.lower()
        where_params = params[:-2] if is_rows else params
        predicates, _ = self._predicates(text, where_params, self._entity_table())
        rows = [r for r in joined if all(p(r) for p in predicates)]
        if not is_rows:
            return [{"count": len(rows)}]
        limit, offset = int(params[-2]), int(params[-1])
        reverse = " desc, e.event_record_id desc" in text.lower()
        rows.sort(key=lambda r: (str(r["time_created_utc"]), int(r["event_record_id"] or 0), int(r["event_db_id"])), reverse=reverse)
        keys = ("link_role", "confidence", "extracted_from", "evidence_json", "event_db_id", "server", "channel",
                "provider_name", "event_id", "event_record_id", "time_created_utc", "time_created_local",
                "subject_user_name", "subject_domain_name", "target_user_name", "target_domain_name",
                "ip_address", "workstation_name", "logon_id", "message_text", "event_data_json")
        out = []
        for r in rows[offset: offset + limit]:
            row = {k: r.get(k) for k in keys}
            row["link_attributes_json"] = r.get("attributes_json")
            out.append(row)
        return out

    def _v2_entities(self, text: str, params: tuple) -> list[dict]:
        """Resolve an entity from the V2 projection (exact id, else key/name lookup)."""
        if text.lower().rstrip().endswith("where entity.id = ?"):
            found = [dict(e) for e in self.entities if e["id"] == int(params[0])][:1]
        else:
            found = self._resolve_entity(str(params[0]))
        return [{**e, "domain_name": None} for e in found]

    def _v2_entity_events(self, text: str, params: tuple) -> list[dict]:
        """V2 link rows: no payload, no link details (those come from the archive)."""
        rows = self._entity_events(text, params)
        if rows and "count" in rows[0] and len(rows[0]) == 1:
            return rows
        by_event = {(link["event_id"], link["link_role"]): link["entity_id"] for link in self.links}
        out = []
        for row in rows:
            entity_id = by_event.get((row["event_db_id"], row["link_role"]))
            out.append({
                **row, "entity_id": entity_id, "confidence": None, "extracted_from": None,
                "link_attributes_json": None, "evidence_json": None,
                "message_text": None, "event_data_json": None, "time_created_local": None,
            })
        return out

    def link_details(self, event_ids: list[int], _archive_root: Any = None) -> dict[int, list[dict]]:
        """Archive link details for V2 entity drill-down, from the seeded links."""
        wanted = {int(value) for value in event_ids}
        details: dict[int, list[dict]] = {}
        for link in self.links:
            if link["event_id"] in wanted:
                details.setdefault(link["event_id"], []).append(dict(link))
        return details

    # -------------------------------------------------------------- misc SQL
    def _group_count(self, keys: tuple[str, ...]) -> list[dict]:
        counts: dict[tuple, int] = {}
        for row in self.events:
            key = tuple(row[k] for k in keys)
            counts[key] = counts.get(key, 0) + 1
        return [
            {**dict(zip(keys, key)), "count": count}
            for key, count in sorted(counts.items(), key=lambda kv: -kv[1])
        ]

    def _relation_counts(self, ids: tuple) -> list[dict]:
        wanted = {int(v) for v in ids}
        counts: dict[int, int] = {}
        for link in self.links:
            if link["event_id"] in wanted:
                counts[link["event_id"]] = counts.get(link["event_id"], 0) + 1
        return [{"event_db_id": k, "relation_count": v} for k, v in counts.items()]

    # ----------------------------------------------------- event search seam
    def search_rows(
        self, filters: dict[str, Any], fetch_limit: int, timeout_ms: int, *, account_timeline: bool,
    ) -> list[dict]:
        """Python model of ``_v2_handler_where_clause`` + order + keyset + limit."""
        from server.sli.events import event_search as es

        unsupported = [k for k in ("category", "risk", "tier", "provider", "subject", "target") if filters.get(k)]
        if unsupported:
            raise UnsupportedQuery(f"pg_fake search does not model filters: {unsupported}")

        def lookup(value: Any, columns: tuple[str, ...]) -> Callable[[dict], bool]:
            exact = set(es._account_exact_values(value))
            prefixes = [p[:-1] for p in es._account_prefix_values(value)]
            if not exact:
                return lambda _r: False
            return lambda r: any(
                _lower(r.get(c)) in exact or any(_lower(r.get(c)).startswith(p) for p in prefixes)
                for c in columns
            )

        checks: list[Callable[[dict], bool]] = []
        if filters.get("channel"):
            checks.append(lambda r: r["channel"] == filters["channel"])
        if filters.get("servers"):
            checks.append(lambda r: r["server"] in set(filters["servers"]))
        if filters.get("time_from"):
            checks.append(lambda r: str(r["time_created_utc"]) >= str(filters["time_from"]))
        if filters.get("time_to"):
            checks.append(lambda r: str(r["time_created_utc"]) < str(filters["time_to"]))
        if filters.get("event_ids"):
            checks.append(lambda r: int(r["event_id"]) in set(filters["event_ids"]))
        subject_target = ("subject_user_name", "target_user_name")
        if account_timeline or filters.get("account"):
            checks.append(lookup(filters.get("account"), subject_target))
        elif filters.get("q"):
            account_match = lookup(filters["q"], subject_target)
            values = set(es._account_exact_values(filters["q"]))
            try:
                numeric = int(filters["q"])
            except ValueError:
                numeric = None
            checks.append(lambda r: (
                account_match(r)
                or _lower(r.get("ip_address")) in values and r.get("ip_address") is not None
                or _lower(r.get("logon_id")) in values and r.get("logon_id") is not None
                or (numeric is not None and int(r["event_id"]) == numeric)
            ))

        ascending = filters["order"] == "asc"

        def key(r: dict) -> tuple:
            return (str(r["time_created_utc"]), int(r["event_record_id"] if r["event_record_id"] is not None else -1), int(r["id"]))

        rows = [r for r in self.events if all(c(r) for c in checks)]
        cursor = filters.get("cursor_values") or {}
        if cursor:
            after = (str(cursor["time"]), int(cursor["record"]), int(cursor["id"]))
            rows = [r for r in rows if (key(r) > after if ascending else key(r) < after)]
        rows.sort(key=key, reverse=not ascending)
        return [{k: r.get(k) for k in _COLUMNS} for r in rows[:fetch_limit]]
