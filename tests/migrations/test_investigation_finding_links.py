"""Migration 149 and the finding <-> investigation link (fakes, no database)."""

from __future__ import annotations

import re
from http import HTTPStatus
from pathlib import Path
from typing import Any

import pytest

from server.api.routes import investigations as routes
from server.sli.semantic import investigation_cases as cases
from server.sli.semantic import investigation_finding_links as links

ROOT = Path(__file__).resolve().parents[2]
FORWARD = ROOT / "config/postgres_migrations/149_investigation_finding_links.sql"
ROLLBACK = ROOT / "config/postgres_migrations/149_investigation_finding_links.rollback.sql"


def _statements(path: Path) -> str:
    return " ".join(line for line in path.read_text(encoding="utf-8").splitlines() if not line.lstrip().startswith("--"))


def test_migration_text_contract() -> None:
    sql = _statements(FORWARD)
    assert "requires exact migration 148 vpn_session_reader_domains_grant" in sql
    assert "pg_advisory_xact_lock" in sql
    assert "investigation_id bigint not null references public.investigations(id) on delete restrict" in sql
    assert "finding_id bigint not null references public.findings(id) on delete restrict" in sql
    assert "primary key (investigation_id, finding_id)" in sql
    assert "unique (finding_id)" in sql
    assert re.findall(r"grant\s+[^;]+;", sql) == [
        "grant select, insert on public.investigation_finding_links to adlog_user;"
    ]
    assert "values (149, 'investigation_finding_links')" in sql


def test_rollback_only_when_latest() -> None:
    sql = _statements(ROLLBACK)
    assert "version > 149" in sql
    assert "drop table if exists public.investigation_finding_links;" in sql
    assert "delete from schema_migrations where version = 149;" in sql


class FakeDb:
    def __init__(self) -> None:
        self.findings = {7: {"id": 7, "rule_code": "R1", "title": "Подозрительный вход", "status": "new"}}
        self.finding_events = {7: [101, 102, 103]}
        self.cases: dict[int, dict[str, Any]] = {
            1: {"id": 1, "public_id": "p1", "title": "Открытое", "status": "active", "owner": "a"},
            2: {"id": 2, "public_id": "p2", "title": "Закрытое", "status": "closed", "owner": "a"},
        }
        self.case_events: set[tuple[int, int]] = {(1, 102)}
        self.links: dict[int, int] = {}
        self.audit: list[tuple[int, str, dict[str, Any]]] = []
        self.next_case = 10
        self.last_case_id = 0

    def connect(self) -> "FakeDb":
        return self

    def __enter__(self) -> "FakeDb":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def cursor(self) -> "Cursor":
        return Cursor(self)


class Cursor:
    def __init__(self, db: FakeDb) -> None:
        self.db = db
        self.rows: list[dict[str, Any]] = []

    def __enter__(self) -> "Cursor":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def fetchone(self) -> dict[str, Any] | None:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[dict[str, Any]]:
        rows, self.rows = self.rows, []
        return rows

    def execute(self, query: str, params: tuple[Any, ...] = ()) -> None:
        q = " ".join(query.split())
        db = self.db
        self.rows = []
        if q == "show transaction_isolation":
            self.rows = [{"transaction_isolation": "read committed"}]
            return
        if q == "lock table investigation_events in row exclusive mode":
            return
        if q.startswith("select pg_advisory_xact_lock"):
            return
        if q.startswith("select id, rule_code, title, status from findings"):
            row = db.findings.get(int(params[0]))
            self.rows = [dict(row)] if row else []
        elif "from finding_evidence" in q:
            self.rows = [{"event_id": e} for e in db.finding_events.get(int(params[0]), [])]
        elif q.startswith("select investigation_id from investigation_finding_links"):
            case = db.links.get(int(params[0]))
            self.rows = [{"investigation_id": case}] if case else []
        elif q.startswith("insert into investigations("):
            case_id = db.next_case
            db.next_case += 1
            db.cases[case_id] = {"id": case_id, "public_id": params[0], "title": params[1], "status": "new", "owner": params[2]}
            self.rows = [{"id": case_id}]
        elif q.startswith("insert into investigation_audit") and "'created'" in q:
            db.audit.append((int(params[0]), "created", {}))
        elif q.startswith("insert into investigation_finding_links"):
            assert int(params[1]) not in db.links
            db.links[int(params[1])] = int(params[0])
        elif q.startswith("insert into investigation_events"):
            key = (int(params[0]), int(params[1]))
            if key not in db.case_events:
                db.case_events.add(key)
                self.rows = [{"event_db_id": key[1]}]
        elif q.startswith("update investigations set updated_at"):
            return
        elif q.startswith("insert into investigation_audit") and "'finding_linked'" in q:
            db.audit.append((int(params[0]), "finding_linked", {"finding_id": int(params[2]), "events_copied": int(params[3])}))
        else:  # pragma: no cover - a new statement must be modelled explicitly
            raise AssertionError(f"unexpected SQL: {q}")


@pytest.fixture()
def db(monkeypatch: pytest.MonkeyPatch) -> FakeDb:
    fake = FakeDb()
    monkeypatch.setattr(links, "connect", fake.connect)

    def case_row(cur: Cursor, identity: Any) -> dict[str, Any]:
        row = fake.cases.get(int(identity))
        if not row:
            raise cases.InvestigationCaseError("not_found", "missing")
        return dict(row)

    monkeypatch.setattr(links, "_case_row", case_row)
    return fake


def test_create_from_finding_links_copies_events_and_audits(db: FakeDb) -> None:
    case = links.create_case_from_finding(finding_id=7, actor="analyst")

    assert case["title"] == "Проблема #7: Подозрительный вход"
    assert case["owner"] == "analyst"
    assert db.links == {7: case["id"]}
    assert {e for c, e in db.case_events if c == case["id"]} == {101, 102, 103}
    assert [(a, p) for _c, a, p in db.audit if a == "finding_linked"] == [
        ("finding_linked", {"finding_id": 7, "events_copied": 3})
    ]


def test_link_to_open_case_copies_events_without_duplicates(db: FakeDb) -> None:
    links.link_finding_to_case(investigation_id=1, finding_id=7, actor="analyst")

    assert db.links == {7: 1}
    assert sorted(e for c, e in db.case_events if c == 1) == [101, 102, 103]
    assert db.audit == [(1, "finding_linked", {"finding_id": 7, "events_copied": 2})]


def test_closed_case_is_refused(db: FakeDb) -> None:
    with pytest.raises(cases.InvestigationCaseError) as error:
        links.link_finding_to_case(investigation_id=2, finding_id=7, actor="analyst")
    assert error.value.code == "investigation_case_closed"
    assert db.links == {}


def test_already_linked_finding_reports_the_existing_case(db: FakeDb) -> None:
    db.links[7] = 1
    for action in (
        lambda: links.create_case_from_finding(finding_id=7, actor="a"),
        lambda: links.link_finding_to_case(investigation_id=1, finding_id=7, actor="a"),
    ):
        with pytest.raises(cases.InvestigationCaseError) as error:
            action()
        assert error.value.code == "finding_already_linked"
        assert error.value.details == {"investigation_id": 1}
    assert len(db.cases) == 2  # nothing was created by the refused attempt


def test_unknown_finding_is_refused(db: FakeDb) -> None:
    with pytest.raises(cases.InvestigationCaseError) as error:
        links.create_case_from_finding(finding_id=99, actor="a")
    assert error.value.code == "finding_not_found"


# --- HTTP handlers --------------------------------------------------------


class Handler:
    def __init__(self, body: dict[str, Any], *, capabilities: tuple[str, ...] = ("investigations.manage",)) -> None:
        self.body = body
        self.sent: list[tuple[dict[str, Any], HTTPStatus]] = []
        self._principal = {"username": "analyst"}
        self.storage_route_authorization = None
        self._capabilities = list(capabilities)

    def _access_decision(self) -> dict[str, Any]:
        return {
            "capabilities": self._capabilities,
            "reports": [{"report_key": "investigations.workspace", "allowed": True, "allowed_actions": ["start_case", "view"]}],
        }

    def _read_json_body(self) -> dict[str, Any]:
        return self.body

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        self.sent.append((payload, status))


@pytest.fixture()
def wired(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "finding_event_ids", lambda _id: [101])
    monkeypatch.setattr(routes, "_event_resources", lambda _h, _e: [{"kind": "domain", "id": 1}])
    monkeypatch.setattr(routes, "_case_resources", lambda _h, _c: [[{"kind": "domain", "id": 1}]])
    monkeypatch.setattr(routes, "_require_investigation_access", lambda *_a: True)
    monkeypatch.setattr(routes, "_visible_case_result", lambda _h, result: result)


def _case(case_id: int = 10) -> dict[str, Any]:
    return {
        "id": case_id, "public_id": None, "title": "Проблема #7", "status": "new", "owner": "analyst",
        "created_by": "analyst", "created_at": "2026-10-02T10:00:00Z", "updated_at": "2026-10-02T10:00:00Z",
        "events": [], "evidence_refs": [], "evidence_refs_state": "available", "notes": [], "audit": [],
    }


def test_from_finding_route_creates_case(monkeypatch: pytest.MonkeyPatch, wired: None) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(routes, "create_case_from_finding", lambda **kw: calls.append(kw) or _case())
    handler = Handler({"finding_id": 7})

    routes._handle_v1_investigation_from_finding(handler)

    assert calls == [{"finding_id": 7, "actor": "analyst"}]
    assert handler.sent[0][1] == HTTPStatus.CREATED
    assert handler.sent[0][0]["id"] == 10


def test_link_route_uses_case_from_path(monkeypatch: pytest.MonkeyPatch, wired: None) -> None:
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(routes, "link_finding_to_case", lambda **kw: calls.append(kw) or _case(5))
    handler = Handler({"finding_id": 7})

    routes._handle_v1_investigation_finding(handler, "/api/v1/investigations/5/findings")

    assert calls == [{"investigation_id": "5", "finding_id": 7, "actor": "analyst"}]
    assert handler.sent[0][1] == HTTPStatus.CREATED


def test_routes_are_dispatched_by_path(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    monkeypatch.setattr(routes, "_handle_v1_investigation_from_finding", lambda _h: seen.append("from"))
    monkeypatch.setattr(routes, "_handle_v1_investigation_finding", lambda _h, path: seen.append(path))

    class Dispatch:
        def _authorize_mutation(self, **_kw: Any) -> bool:
            return True

    assert routes.try_handle_post(Dispatch(), "/api/v1/investigations/from-finding")
    assert routes.try_handle_post(Dispatch(), "/api/v1/investigations/5/findings")
    assert seen == ["from", "/api/v1/investigations/5/findings"]


def test_forbidden_without_manage_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(routes, "create_case_from_finding", lambda **_kw: pytest.fail("must not create"))
    monkeypatch.setattr(routes, "link_finding_to_case", lambda **_kw: pytest.fail("must not link"))
    for call in (
        lambda h: routes._handle_v1_investigation_from_finding(h),
        lambda h: routes._handle_v1_investigation_finding(h, "/api/v1/investigations/5/findings"),
    ):
        handler = Handler({"finding_id": 7}, capabilities=("investigations.view",))
        call(handler)
        assert handler.sent == [({"error": "insufficient_capability", "required_capability": "investigations.manage"}, HTTPStatus.FORBIDDEN)]


def test_already_linked_is_409_with_existing_case(monkeypatch: pytest.MonkeyPatch, wired: None) -> None:
    def refuse(**_kw: Any) -> None:
        raise cases.InvestigationCaseError("finding_already_linked", "linked", {"investigation_id": 4})

    monkeypatch.setattr(routes, "create_case_from_finding", refuse)
    handler = Handler({"finding_id": 7})

    routes._handle_v1_investigation_from_finding(handler)

    payload, status = handler.sent[0]
    assert status == HTTPStatus.CONFLICT
    assert payload["error"] == "finding_already_linked"
    assert payload["investigation_id"] == 4


def test_closed_case_is_409(monkeypatch: pytest.MonkeyPatch, wired: None) -> None:
    def refuse(**_kw: Any) -> None:
        raise cases.InvestigationCaseError("investigation_case_closed", "closed")

    monkeypatch.setattr(routes, "link_finding_to_case", refuse)
    handler = Handler({"finding_id": 7})

    routes._handle_v1_investigation_finding(handler, "/api/v1/investigations/2/findings")

    assert handler.sent[0][1] == HTTPStatus.CONFLICT
    assert handler.sent[0][0]["error"] == "investigation_case_closed"


def test_bad_finding_id_is_400(wired: None) -> None:
    for body in ({}, {"finding_id": "x"}, {"finding_id": True}):
        handler = Handler(body)
        routes._handle_v1_investigation_from_finding(handler)
        assert handler.sent == [({"error": "invalid_finding_id"}, HTTPStatus.BAD_REQUEST)]
