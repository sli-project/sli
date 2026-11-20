"""Synthetic retained evidence, never a live directory or database."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from server.sli.semantic import findings
from server.sli.entities.identity_resolution import разрешить_субъект
from server.sli.reporting.v2.reports import security_problems as report
from server.sli.reporting.v2.access import ReportAccess
from server.sli.core.messages import response_messages, catalog


SID = "S-1-5-21-100-200-300-1101"
GROUP = "S-1-5-21-100-200-300-512"
AT = "2026-09-03T10:00:00+00:00"
SNAPSHOT = "2026-08-01T10:00:00+00:00"


def event(**changes):
    return {"finding_id": 7, "event_db_id": 91, "event_id": 4728,
            "hostname": "synthetic-dc", "channel": "Security", "identity_provider": "Microsoft-Windows-Security-Auditing", "time_created_utc": AT,
            "domain_id": 3, "subject_user_sid": SID, "subject_user_name": "synthetic-admin",
            "subject_domain_name": "EXAMPLE", "target_user_sid": GROUP,
            "membership_member_sid": SID, "identity_domain_min": 3, "identity_domain_max": 3,
            "identity_event_count": 1, **changes}


def row(**changes):
    return {"id": 7, "title": "Member was added to a privileged group", "actor": None,
            "target": SID, "evidence_count": 1, **changes}


def attach(monkeypatch, raw, events=None, snapshots=None):
    calls = []
    evidence = [event()] if events is None else events
    def read(sql, params=(), **kwargs):
        calls.append((sql, params, kwargs))
        if "problem_identity_snapshot_labels" in sql:
            if isinstance(snapshots, Exception):
                raise snapshots
            return deepcopy(snapshots or [])
        if "from finding_evidence fe" in sql:
            return deepcopy(evidence)
        if "from finding_entities" in sql:
            return [{"finding_id": 7, "entity_role": "container_entity", "entity_type": "group", "display_name": GROUP}]
        return []
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
    monkeypatch.setattr(findings, "query_rows", read)
    monkeypatch.setattr(findings, "query_rows_bounded", read, raising=False)
    findings._attach_postgres_finding_details([raw], authorization="sealed", identity_labels=True)
    return calls


@pytest.mark.parametrize("event_id", [4728, 4732, 4756])
def test_observed_initiator_is_named_without_rewriting_source_or_evidence(monkeypatch, event_id):
    raw = row()
    attach(monkeypatch, raw, [event(event_id=event_id)])
    view = report._row(raw, {})
    assert view["actor_text"] == "EXAMPLE\\synthetic-admin"
    assert view["actor"] is None and view["target"] == SID
    assert view["identity_context"]["actor"]["source"] == "event"
    assert view["identity_context"]["actor"]["event_db_id"] == 91
    assert view["evidence"][0]["event_db_id"] == 91
    assert "subject_user_name" not in view["evidence"][0]
    assert "subject_user_name" not in raw["evidence"][0]



@pytest.mark.parametrize("contract", [
    (),
    (("Application", "Microsoft-Windows-Security-Auditing", "4728"),),
    (("Security", "Synthetic-Other-Provider", "4728"),),
])
def test_observed_actor_consumes_the_source_owned_exact_identity_contract(monkeypatch, contract):
    calls = []
    def identities(semantic_types):
        calls.append(semantic_types)
        return tuple(SimpleNamespace(stream=stream, provider_name=provider, event_key=key)
                     for stream, provider, key in contract)
    monkeypatch.setattr(findings, "_FINDINGS_NORMALIZER", SimpleNamespace(semantic_event_identities=identities))
    raw = row()
    attach(monkeypatch, raw)
    assert report._row(raw, {})["actor_text"] == "—"
    assert calls == [("group.member.added",)]


def test_snapshot_name_uses_exact_witness_scope_without_treating_old_snapshot_as_live(monkeypatch):
    raw = row(actor=f"sid:synthetic-dc:{SID}")
    snapshots = [{"request_index": 0, "label": "Synthetic admin", "observed_at_utc": SNAPSHOT,
                  "source_run_id": "synthetic-run", "entity_id": 14},
                 {"request_index": 1, "label": "Synthetic admin", "observed_at_utc": SNAPSHOT,
                  "source_run_id": "synthetic-run", "entity_id": 14},
                 {"request_index": 2, "label": "Synthetic administrators", "observed_at_utc": SNAPSHOT,
                  "source_run_id": "synthetic-run", "entity_id": 15}]
    calls = attach(monkeypatch, raw, snapshots=snapshots)
    view = report._row(raw, {})
    assert view["entity_text"] == "Synthetic administrators"
    assert view["entities"][0]["display_name"] == GROUP
    context = view["identity_context"]["principals"]
    assert context[GROUP]["source"] == "ad_snapshot"
    assert context[GROUP]["observed_at_utc"] == SNAPSHOT
    assert context[GROUP]["domain_id"] == 3
    assert context[GROUP]["sid"] == GROUP
    assert context[GROUP]["event_db_id"] == 91
    assert view["entity_identifiers"] == GROUP
    query = next(call for call in calls if "problem_identity_snapshot_labels" in call[0])
    assert "run.status='completed'" in query[0]
    assert "section.status='complete'" in query[0]
    assert "version.valid_from_utc<=request.at_utc" in query[0]
    assert "alias.domain_id=request.domain_id" in query[0]
    assert "limit 2" in query[0]


@pytest.mark.parametrize("changes", [
    {"event_id": 4624}, {"subject_user_name": "-"},
    {"channel": "Application"}, {"identity_provider": "Synthetic-Other-Provider"}, {"identity_provider": None},
    {"identity_event_count": 21}, {"identity_domain_max": 4},
])
def test_missing_or_ambiguous_actor_evidence_stays_unknown(monkeypatch, changes):
    raw = row()
    attach(monkeypatch, raw, [event(**changes)])
    assert report._row(raw, {})["actor_text"] == "—"


def test_conflicting_event_actors_are_not_collapsed_to_one_person(monkeypatch):
    raw = row(evidence_count=2)
    attach(monkeypatch, raw, [event(identity_event_count=2),
           event(event_db_id=92, subject_user_sid=SID[:-1] + "2", subject_user_name="another-admin", identity_event_count=2)])
    assert report._row(raw, {})["actor_text"] == "—"


def test_event_name_cannot_replace_a_different_existing_actor(monkeypatch):
    raw = row(actor="sid:synthetic-dc:S-1-5-21-100-200-300-1999")
    attach(monkeypatch, raw)
    view = report._row(raw, {})
    assert view["actor_text"] == "Неизвестная учётная запись"
    assert view["actor"] == raw["actor"]
    assert view["identity_context"] == raw["identity_context"]
    assert view["identity_context"]["actor"] is None


def test_qualified_actor_cannot_borrow_a_name_from_another_source_host(monkeypatch):
    raw = row(actor=f"sid:other-dc:{SID}")
    attach(monkeypatch, raw)
    view = report._row(raw, {})
    assert view["actor_text"] == "Неизвестная учётная запись"
    assert view["actor"] == raw["actor"]
    assert view["identity_context"] == raw["identity_context"]
    assert view["identity_context"]["actor"] is None


def test_native_or_missing_evidence_does_not_make_a_partial_actor_sample_complete(monkeypatch):
    raw = row(evidence_count=2)
    attach(monkeypatch, raw)
    assert report._row(raw, {})["actor_text"] == "—"


def test_ambiguous_or_unavailable_snapshot_keeps_raw_identifier(monkeypatch):
    for snapshots in ([{"request_index": 1, "label": "One"}, {"request_index": 1, "label": "Two"}], RuntimeError("synthetic")):
        raw = row()
        attach(monkeypatch, raw, snapshots=snapshots)
        assert report._row(raw, {})["entity_text"] == GROUP
        assert raw["entities"][0]["display_name"] == GROUP


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_provenance_and_unassigned_copy_are_localized_without_losing_raw_identifiers(monkeypatch, locale):
    raw = row(assigned_to=None)
    attach(monkeypatch, raw)
    view = response_messages({"report_key": report.REPORT_KEY, "items": [report._row(raw, {})]}, locale)["items"][0]
    assert view["assigned_to_text"] == catalog(locale)["security.problems.assignee.unassigned"]
    assert view["assigned_to"] is None
    assert "91" in view["identity_sources_text"]
    assert "synthetic-admin" in view["identity_sources_text"]


def test_derived_names_and_provenance_do_not_escape_field_projection(monkeypatch):
    raw = row()
    attach(monkeypatch, raw)
    access = {"reports": [{"report_key": "security.queue", "allowed": True, "allowed_actions": ["view"],
              "grants": [{"scope": {"kind": "all"}, "allowed_actions": ["view"], "field_categories": ["security"]}]}]}
    projected = ReportAccess(report.REPORT, access).result({"state": "ok", "items": [report._row(raw, {})]})["items"][0]
    assert "synthetic-admin" not in str(projected)
    assert "identity_context" not in projected and "entity_identifiers" not in projected


@pytest.mark.postgres_integration
@pytest.mark.postgres_historical(371, "password_domain_auto")
def test_legacy_finding_evidence_identity_query_compiles_with_runtime_reader(monkeypatch):
    import os

    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row
    from server.sli.core.database import _pg_sql
    from tests.postgres_integration_guard import assert_disposable_database

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL is not configured")
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.transaction(force_rollback=True):
        assert_disposable_database(conn)
        executed = []

        def query(statement, params=(), **_):
            executed.append(statement)
            return conn.execute(_pg_sql(statement), params).fetchall()

        monkeypatch.setattr(findings, "query_rows", query)
        monkeypatch.setattr(findings, "query_rows_bounded", query)
        monkeypatch.setattr(findings, "resolve_storage_route", lambda **_: {"route": "v2"})
        conn.execute("set local role adlog_user")
        findings._attach_postgres_finding_details([{"id": 9223372036854775806}], identity_labels=True)
        assert any("identity_event_count" in sql for sql in executed)


@pytest.mark.postgres_integration
def test_identity_queries_execute_on_migrated_schema_with_retained_snapshot_guards(monkeypatch):
    """CI only: actual tables/SQL and web role, in the existing disposable clone."""
    import json
    import os
    from uuid import uuid4

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable migrated PostgreSQL is not configured")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row
    from server.sli.core.database import _pg_sql
    from tests.postgres_integration_guard import assert_disposable_database

    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.transaction(force_rollback=True):
        assert_disposable_database(conn)
        marker = str(uuid4())
        forest = conn.execute("insert into forests(name) values(%s) returning id", ("synthetic-" + marker,)).fetchone()["id"]
        domain = conn.execute("insert into domains(forest_id,fqdn) values(%s,%s) returning id",
                              (forest, marker + ".example.invalid")).fetchone()["id"]
        other_domain = conn.execute("insert into domains(forest_id,fqdn) values(%s,%s) returning id",
                                    (forest, "other-" + marker + ".example.invalid")).fetchone()["id"]
        conn.execute("insert into storage_v2_entity_type(value) values('ad_user') on conflict(value) do nothing")
        kind = conn.execute("select id from storage_v2_entity_type where value='ad_user'").fetchone()["id"]
        entity = conn.execute("""insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            values(%s,%s,'Current name must not win',%s,%s) returning id""", (kind, marker, domain, b"a" * 32)).fetchone()["id"]
        run = str(uuid4())
        conn.execute("""insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,
            observed_at_utc,bundle_sha256,status) values(%s,'synthetic','1',%s,'full',%s,%s,'completed')""",
                     (run, domain, SNAPSHOT, b"b" * 32))
        conn.execute("""insert into ad_context_sections(run_id,section_name,status,record_count)
            values(%s,'directory_accounts','complete',1),(%s,'directory_group_graph','complete',1)""", (run, run))
        alias = conn.execute("""insert into ad_context_entity_aliases(entity_id,domain_id,alias_type,alias_value,
            normalized_value,first_seen_utc,last_seen_utc,source_run_id)
            values(%s,%s,'object_sid',%s,%s,%s,%s,%s) returning id""",
            (entity, domain, SID, SID.lower(), SNAPSHOT, SNAPSHOT, run)).fetchone()["id"]
        attrs = {"identity": {"kind": "ad_user", "object_sid": SID},
                 "attributes": {"display_name": "Retained synthetic name"}}
        version = conn.execute("""insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,
            last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            values(%s,'directory_accounts',%s,%s,%s,%s::jsonb,%s) returning id""",
            (entity, SNAPSHOT, SNAPSHOT, b"c" * 32, json.dumps(attrs), run)).fetchone()["id"]

        def query(statement, params=(), **_):
            return conn.execute(_pg_sql(statement), params).fetchall()

        monkeypatch.setattr(findings, "query_rows_bounded", query)
        conn.execute("set local role adlog_user")

        def label(expected_state="named"):
            raw = row(actor=SID, entities=[], evidence=[event(domain_id=domain, identity_domain_min=domain,
                identity_domain_max=domain, subject_user_name="-")])
            findings._attach_problem_identities([raw])
            # The optional fallback may not conceal a query syntax/permission failure.
            assert raw["identity_context"]["snapshot_state"] != "unavailable"
            assert raw["actor"] == SID
            assert raw["identity_context"]["principal_states"][SID] == expected_state
            if expected_state != "named":
                assert SID not in raw["identity_context"]["principals"]
            return report.presentation(raw)["actor_text"]
        assert label() == "Retained synthetic name"
        for status in ("partial", "failed", "skipped"):
            conn.execute("update ad_context_sections set status=%s where run_id=%s", (status, run))
            assert label("no_match") == "Неизвестная учётная запись"
        conn.execute("update ad_context_sections set status='complete' where run_id=%s", (run,))
        for status in ("failed", "importing"):
            conn.execute("update ad_context_runs set status=%s where run_id=%s", (status, run))
            assert label("no_match") == "Неизвестная учётная запись"
        conn.execute("update ad_context_runs set status='completed' where run_id=%s", (run,))
        for field, value in (("valid_from_utc", "2026-10-01T00:00:00Z"), ("valid_to_utc", AT)):
            conn.execute(f"update ad_context_entity_versions set {field}=%s where id=%s", (value, version))
            assert label("no_match") == "Неизвестная учётная запись"
            conn.execute("update ad_context_entity_versions set valid_from_utc=%s,valid_to_utc=null where id=%s", (SNAPSHOT, version))
        conn.execute("update ad_context_runs set observed_at_utc='2026-10-01' where run_id=%s", (run,))
        assert label("no_match") == "Неизвестная учётная запись"
        conn.execute("update ad_context_runs set observed_at_utc=%s where run_id=%s", (SNAPSHOT, run))
        conn.execute("update ad_context_entity_aliases set domain_id=%s where id=%s", (other_domain, alias))
        assert label("no_match") == "Неизвестная учётная запись"
        conn.execute("update ad_context_entity_aliases set domain_id=%s where id=%s", (domain, alias))
        conflict = {**attrs, "attributes": {"display_name": "Conflicting retained name"}}
        conn.execute("""insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,
            last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            values(%s,'directory_group_graph',%s,%s,%s,%s::jsonb,%s)""",
            (entity, SNAPSHOT, SNAPSHOT, b"d" * 32, json.dumps(conflict), run))
        assert label("ambiguous") == "Неизвестная учётная запись"


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_available_event_name_does_not_hide_unavailable_snapshot_lookup(monkeypatch, locale):
    raw = row()
    attach(monkeypatch, raw, snapshots=RuntimeError("synthetic"))
    view = report._row(raw, {})
    localized = response_messages({"report_key": "security.problems", "items": [view]}, locale)["items"][0]
    assert localized["actor_text"] == "EXAMPLE\\synthetic-admin"
    assert view["presentation_messages"]["identity_sources_text"]["code"] == "security.problems.identity.sources_partial"
    assert "AD" in localized["identity_sources_text"]



@pytest.mark.parametrize('snapshots, expected', [
    ([], 'no_match'),
    ([{'request_index': 0, 'label': 'One'}, {'request_index': 0, 'label': 'Two'}], 'ambiguous'),
    (RuntimeError('synthetic lookup failure'), 'unavailable'),
])
def test_home_principal_outcomes_distinguish_lookup_from_unwitnessed_sid(monkeypatch, snapshots, expected):
    absent = 'S-1-5-21-100-200-300-1999'
    raw = row(_identity_objects=[SID, absent])
    attach(monkeypatch, raw, snapshots=snapshots)
    states = raw['identity_context']['principal_states']
    assert states[SID] == expected
    assert states[absent] == 'unverified'
    assert raw['target'] == SID


def test_declared_retained_name_is_not_reclassified_by_its_spelling(monkeypatch):
    raw = row()
    attach(monkeypatch, raw, snapshots=[{'request_index': 0, 'label': SID,
        'observed_at_utc': SNAPSHOT, 'source_run_id': 'synthetic-run', 'entity_id': 14}])
    assert raw['identity_context']['principal_states'][SID] == 'named'
    assert raw['identity_context']['principals'][SID]['label'] == SID



def test_canonical_short_domain_sid_is_recognized_without_rewriting_identity():
    # The canonical identity ladder emits sid:<SID> for domain principals.
    canonical = разрешить_субъект(sid=SID).ключ
    assert canonical == f"sid:{SID}"
    assert findings._principal_sid(canonical) == SID
    for value in (SID, f"sid:{SID}", f"SID:{SID.lower()}", f"sid:synthetic-dc:{SID}"):
        assert findings._principal_sid(value) == SID
        view = findings._home_identity_object(value, {}, None)
        assert view["identifier"] == value
        assert view["name"] == "" and view["name_state"] == "unverified"


def test_unscoped_or_malformed_short_sid_cannot_become_a_named_principal():
    for value in ("sid:S-1-5-18", "sid:S-1-5-21-100-200-1101", "sid:S-1-5-21-100-200-300-1101-extra",
                  f"sid:extra:synthetic-dc:{SID}"):
        assert findings._principal_sid(value) is None
        view = findings._home_identity_object(value, {}, None)
        assert view["identifier"] == value
        assert view["name"] == "" and view["name_state"] == "unverified"


def _short_identity_context(monkeypatch, value, evidence, snapshots=()):
    requests = []
    def read(sql, params=(), **kwargs):
        import json
        requests.extend(json.loads(params[0]))
        if isinstance(snapshots, Exception):
            raise snapshots
        return list(snapshots)
    monkeypatch.setattr(findings, "query_rows_bounded", read)
    raw = row(actor=value, target=None, evidence=evidence)
    findings._attach_problem_identities([raw])
    return raw["identity_context"], requests


def test_short_domain_sid_uses_only_exact_retained_domain_and_witness_time(monkeypatch):
    value = f"sid:{SID}"
    snapshot = {"request_index": 0, "label": "Retained synthetic name", "observed_at_utc": SNAPSHOT,
                "source_run_id": "synthetic-run", "entity_id": 14}
    context, requests = _short_identity_context(monkeypatch, value, [event()], [snapshot])
    assert requests == [{"request_index": 0, "domain_id": 3, "sid": SID.lower(), "at_utc": AT}]
    assert context["actor"]["label"] == "EXAMPLE\\synthetic-admin"
    view = findings._home_identity_object(value, context, "EXAMPLE")
    assert view["name"] == "Retained synthetic name" and view["name_state"] == "named"
    assert view["identifier"] == value
    assert view["source"]["domain_id"] == 3 and view["source"]["witness_at_utc"] == AT


def test_short_sid_cannot_bypass_witness_domain_completeness_or_host_scope(monkeypatch):
    cases = [
        (f"sid:{SID}", event(identity_domain_max=4)),
        (f"sid:{SID}", event(identity_domain_min=None, identity_domain_max=None)),
        (f"sid:{SID}", event(identity_event_count=2)),
        (f"sid:{SID}", event(subject_user_sid=GROUP, membership_member_sid=GROUP)),
        (f"sid:other-dc:{SID}", event()),
        ("sid:S-1-5-18", event(subject_user_sid="S-1-5-18", membership_member_sid="S-1-5-18")),
    ]
    for value, witness in cases:
        context, requests = _short_identity_context(monkeypatch, value, [witness])
        assert requests == []
        assert context["actor"] is None
        assert findings._home_identity_object(value, context, None)["name_state"] == "unverified"


def test_short_sid_preserves_no_match_ambiguous_and_unavailable_states(monkeypatch):
    for snapshots, state in (([], "no_match"),
                             ([{"request_index": 0, "label": "One"}, {"request_index": 0, "label": "Two"}], "ambiguous"),
                             (RuntimeError("synthetic unavailable"), "unavailable")):
        value = f"sid:{SID}"
        context, requests = _short_identity_context(monkeypatch, value, [event()], snapshots)
        assert len(requests) == 1
        view = findings._home_identity_object(value, context, None)
        assert view["identifier"] == value and view["name"] == ""
        assert view["name_state"] == state


def test_non_sid_literal_names_keep_their_existing_presentation():
    for value in ("ordinary-name", "sid:not-a-principal", "sid:"):
        view = findings._home_identity_object(value, {"snapshot_state": "unavailable"}, None)
        assert view["name"] == value and view["identifier"] == value
        assert view["name_state"] == "literal"


@pytest.mark.parametrize("locale, expected", [("ru", "Неизвестная учётная запись"), ("en", "Unknown account")])
@pytest.mark.parametrize("state", ["no_match", "ambiguous", "unverified", "unavailable"])
@pytest.mark.parametrize("actor", [SID, f"sid:{SID}", f"sid:synthetic-dc:{SID}",
                                   "sid:S-1-5-18", "sid:S-1-5-21-malformed"])
def test_queue_unresolved_actor_hides_sid_without_collapsing_evidence_state(locale, expected, state, actor):
    context = {"actor": None, "principals": {}, "principal_states": {actor: state},
               "snapshot_state": "unavailable" if state == "unavailable" else "lookup_complete"}
    raw = row(actor=actor, identity_context=context)
    before = deepcopy(raw)
    view = response_messages({"report_key": report.REPORT_KEY, "items": [report._row(raw, {})]}, locale)["items"][0]
    assert view["actor_text"] == expected
    assert view["actor"] == actor
    assert view["identity_context"] == context
    assert view["identity_context"]["principal_states"][actor] == state
    assert raw == before
    if state == "unavailable":
        assert view["identity_sources_text"] == catalog(locale)["security.problems.identity.unavailable"]


@pytest.mark.parametrize("actor", ["ordinary-name", "sid:not-a-principal", "sid:",
                                   "0b525814-8c42-4e9a-8899-1d3bea4ade84"])
def test_queue_literal_actor_is_not_reclassified_or_prettified(actor):
    raw = row(actor=actor)
    view = report._row(raw, {})
    assert view["actor_text"] == actor and view["actor"] == actor


@pytest.mark.parametrize("source", ["event", "ad_snapshot"])
def test_queue_confirmed_actor_name_wins_even_when_sid_shaped(source):
    actor = f"sid:{SID}"
    label = SID
    retained = {"label": label, "source": source, "event_id": 4728, "event_db_id": 91,
                "sid": SID, "domain_id": 3, "observed_at_utc": SNAPSHOT,
                "source_run_id": "synthetic-run"}
    context = {"actor": retained if source == "event" else None,
               "principals": {actor: retained} if source == "ad_snapshot" else {},
               "principal_states": {actor: "named"}}
    raw = row(actor=actor, identity_context=context)
    view = report._row(raw, {})
    assert view["actor_text"] == label and view["actor"] == actor
    assert view["identity_context"] == context
    assert label in view["identity_sources_text"]


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_queue_system_actor_keeps_existing_system_label(locale):
    actor = "sid:synthetic-dc:S-1-5-18"
    view = response_messages({"report_key": report.REPORT_KEY, "items": [report._row(row(actor=actor), {})]}, locale)["items"][0]
    assert view["actor_text"] == catalog(locale)["security.problems.entity.system"].format(name="SYNTHETIC-DC")
    assert view["actor"] == actor
