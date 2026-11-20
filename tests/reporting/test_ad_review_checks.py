"""AD checks contract: synthetic snapshot/event fakes, no database or collector."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.core.messages import catalog, localize_presentation
from server.sli.plugins.ad.reports import review_catalog, review_checks as checks
from server.sli.plugins.ad.reports.definitions import computers, users
from server.sli.reporting.v2.definition import QueryContext
from tests.reporting.test_reporting_v2_field_access import access, call, grant

NOW = datetime(2026, 10, 17, 3, tzinfo=timezone.utc)
PRIOR = NOW - timedelta(days=1)
SINCE = (NOW - timedelta(hours=12)).isoformat()


def user(number=1, **fields):
    return {"entityId": number, "objectGuid": f"synthetic-user-{number}", "sid": f"synthetic-user-sid-{number}",
            "samAccountName": f"synthetic-account-{number}", "enabled": True,
            "userAccountControl": 512, "lockedOut": False,
            "passwordLastSet": (NOW - timedelta(days=10)).isoformat(),
            "lastLogonTimestamp": (NOW - timedelta(days=2)).isoformat(),
            "servicePrincipalNames": [], "memberships": {"status": "observed", "effective": []}, **fields}


def computer(number=1, **fields):
    return {"entity_id": number, "object_guid": f"synthetic-computer-{number}", "object_sid": f"synthetic-computer-sid-{number}",
            "display_name": f"synthetic-host-{number}", "enabled": True, "computer_type": "workstation",
            "last_logon_utc": (NOW - timedelta(days=2)).isoformat(),
            "password_last_set_utc": (NOW - timedelta(days=10)).isoformat(),
            "created_utc": (NOW - timedelta(days=10)).isoformat(),
            "operating_system": "Windows 11 Enterprise", "operating_system_version": "10.0 (26100)",
            "delegation": {"unconstrained": False, "resource_based": False},
            "laps": {"state": "metadata_present"}, **fields}


def snapshot(objects, at=NOW, state="complete"):
    return {"objects": objects, "observed_at": at.isoformat(), "state": state}


def bundle(current, previous=None, baseline=None, domain_id=1):
    return {"domain_id": domain_id, "domain_name": f"synthetic-{domain_id}.example.test",
            "current": snapshot(current),
            "previous": snapshot(previous, PRIOR) if previous is not None else None,
            "baseline": snapshot(baseline, PRIOR) if baseline is not None else None}


def rows(kind, bundles, **kwargs):
    return checks.summarize(kind, bundles, now=NOW, **kwargs)


def by_key(data, key):
    return next(row for row in data["items"] if row["key"] == key)


def event(code, **fields):
    return {"id": code, "domain_id": 1, "event_id": code,
            "time_created_utc": (NOW - timedelta(hours=1)).isoformat(),
            "target_user_sid": "synthetic-user-sid-1", "subject_user_name": "synthetic-operator",
            "subject_domain_name": "synthetic-domain", **fields}


@pytest.mark.parametrize("kind,count,hygiene", [("users", 12, 3), ("computers", 8, 2)])
def test_catalog_count_severity_hygiene_and_bilingual_explanations(kind, count, hygiene):
    data = rows(kind, [bundle([])])
    assert len(data["items"]) == count
    assert sum(row["section"] == "hygiene" for row in data["items"]) == hygiene
    assert all(row["severity"] == "low" for row in data["items"][-hygiene:])
    for row in data["items"]:
        assert row["total"] == 0
        for locale in ("ru", "en"):
            localized = localize_presentation(row, locale)
            for field in ("title", "why", "action", "remediation"):
                code = f"{review_catalog.PREFIX}{kind}.{row['key']}.{field}"
                assert localized[field] == catalog(locale)[code]


def test_unique_counts_samples_domain_and_overlap_are_not_added():
    objects = [user(i, userAccountControl=512 | 128 | 65536) for i in range(1, 6)]
    data = rows("users", [bundle([*objects, objects[0]]), bundle([objects[0]], domain_id=2)])
    row = by_key(data, "reversible_password")
    assert row["total"] == 6
    assert len(row["objects"]) == 3 and row["remaining_objects"] == 3
    assert all(obj["domain_id"] and obj["domain_name"] for obj in row["objects"])
    assert data["coverage"]["affected_objects"] == 6
    assert data["coverage"]["population"] == 6


def test_new_since_login_uses_baseline_instead_of_creation_or_latest_pair():
    old = [user(1, userAccountControl=640), user(2), user(3)]
    previous = [*old, user(4, userAccountControl=640)]
    current = [user(i, userAccountControl=640) for i in range(1, 5)]
    data = rows("users", [bundle(current, previous, old)], since=SINCE)
    row = by_key(data, "reversible_password")
    assert row["total"] == 4 and row["previous_total"] == 2
    assert row["new_count"] == 3 and row["delta"] == 2 and row["status"] == "new"


def test_decreased_is_count_delta_not_object_replacement():
    data = rows("users", [bundle([user(3, userAccountControl=640)],
                                 [user(1, userAccountControl=640), user(2, userAccountControl=640)], [])], since=SINCE)
    row = by_key(data, "reversible_password")
    assert row["status"] == "decreased" and row["delta"] == -1
    assert row["new_count"] == 1
    assert localize_presentation(row, "en")["status_text"] == "Decreased by 1"


@pytest.mark.parametrize("previous_state,current_state", [("partial", "complete"), ("complete", "partial")])
def test_partial_pair_cannot_claim_reduction(previous_state, current_state):
    source = bundle([user()], [user(1, userAccountControl=640)], [])
    source["previous"]["state"] = previous_state
    source["current"]["state"] = current_state
    row = by_key(rows("users", [source], since=SINCE), "reversible_password")
    assert row["previous_total"] is None and row["status"] == "no_comparison"
    if current_state == "partial":
        assert row["new_count"] is None


def test_unknown_inputs_are_not_zero_and_count_unique_unassessed_objects():
    data = rows("computers", [bundle([{"object_guid": "synthetic-unknown"}])])
    assert all(row["total"] is None for row in data["items"])
    assert data["coverage"]["not_evaluated_count"] == 1
    assert data["coverage"]["footer_rows"][0]["total"] == 1
    assert all(row["not_evaluated_count"] == 1 for row in data["items"])
    assert data["state"] == "partial"


def test_first_login_missing_domain_and_missing_baseline_are_unknown():
    data = rows("computers", [bundle([computer()])])
    assert all(row["new_count"] is None for row in data["items"])
    assert all(row["status"] == ("no_comparison" if row["total"] is not None else "not_evaluated")
               for row in data["items"])
    missing = rows("computers", [bundle([computer()]), {"domain_id": 2, "domain_name": "synthetic-2.example.test"}])
    assert missing["coverage"]["population"] is None
    assert missing["coverage"]["not_evaluated_count"] is None
    assert missing["state"] == "partial"


def test_thresholds_are_strict_365_90_and_60_days():
    obj = user(passwordLastSet=(NOW - timedelta(days=365)).isoformat(), lastLogonTimestamp=(NOW - timedelta(days=90)).isoformat())
    values = checks.evaluate("users", obj, NOW, None, False, [])
    assert values["old_password"] is False and values["inactive_enabled"] is False
    obj["passwordLastSet"] = (NOW - timedelta(days=366)).isoformat()
    obj["lastLogonTimestamp"] = (NOW - timedelta(days=91)).isoformat()
    values = checks.evaluate("users", obj, NOW, None, False, [])
    assert values["old_password"] is True and values["inactive_enabled"] is True
    values = checks.evaluate("computers", computer(password_last_set_utc=(NOW - timedelta(days=60)).isoformat()), NOW, None, False, [])
    assert values["old_machine_password"] is False


def test_nested_privileges_and_admin_count_are_distinct():
    privileged = user(memberships={"status": "observed", "effective": [{"watchGroup": True, "relation": "nested"}]},
                      userAccountControl=512 | 65536, servicePrincipalNames=["HTTP/synthetic.example.test"], enabled=False)
    values = checks.evaluate("users", privileged, NOW, user(), True, [])
    assert all(values[key] is True for key in ("new_privileged", "inactive_privileged", "spn_privileged", "privileged_password_never_expires"))
    values = checks.evaluate("users", user(adminCount=1), NOW, None, True, [])
    assert values["new_privileged"] is False and values["inactive_privileged"] is False


def test_disabled_logon_needs_disable_event_and_reenable_cancels_it():
    obj = user(enabled=False)
    disable = event(4725, time_created_utc=(NOW - timedelta(hours=2)).isoformat())
    logon = event(4624)
    assert checks.evaluate("users", obj, NOW, None, False, [logon])["disabled_logon"] is None
    assert checks.evaluate("users", obj, NOW, None, False, [disable, logon])["disabled_logon"] is True
    assert checks.evaluate("users", obj, NOW, None, False, [disable, logon, event(4722)])["disabled_logon"] is None
    assert checks.evaluate("users", obj, NOW, None, False, [disable, event(4624, target_user_sid="different-sid")])["disabled_logon"] is None


def test_service_logon_requires_snapshot_classification_and_exact_interactive_type():
    obj = user(objectClasses=["msDS-GroupManagedServiceAccount"])
    assert checks.evaluate("users", obj, NOW, None, False, [event(4624, logon_type=10)])["service_interactive_logon"] is True
    assert checks.evaluate("users", obj, NOW, None, False, [event(4624, logon_type=3)])["service_interactive_logon"] is None
    assert checks.evaluate("users", user(), NOW, None, False, [event(4624, logon_type=2)])["service_interactive_logon"] is None


def test_events_are_scoped_and_actor_requires_relevant_evidence():
    obj = user(userAccountControl=640)
    unrelated = event(4724)
    data = rows("users", [bundle([obj])], events=[unrelated])
    assert by_key(data, "reversible_password")["change"] is None
    change = event(5136, facts_json={"attribute": "userAccountControl"})
    data = rows("users", [bundle([obj])], events=[change, event(5136, domain_id=2, facts_json={"attribute": "userAccountControl"})])
    actor = by_key(data, "reversible_password")["change"]
    assert actor["event_db_id"] == 5136 and actor["actor"] == "synthetic-domain\\synthetic-operator"
    assert by_key(data, "reversible_password")["objects"][0]["change"] == actor


def test_computer_posture_all_checks_and_creation_is_not_first_seen():
    obj = computer(operating_system="Windows 8.1", operating_system_version="6.3 (9600)",
                   delegation={"unconstrained": True, "resource_based": True}, laps={"state": "expired"}, sli_agent={"state": "absent"},
                   created_utc=(NOW - timedelta(hours=12)).isoformat(),
                   last_logon_utc=(NOW - timedelta(days=91)).isoformat(), password_last_set_utc=(NOW - timedelta(days=61)).isoformat())
    data = rows("computers", [bundle([obj])])
    assert all(row["total"] == 1 for row in data["items"])
    obj["created_utc"] = (NOW - timedelta(days=10)).isoformat()
    assert by_key(rows("computers", [bundle([obj])]), "new_computer")["total"] == 0
    obj["laps"] = {"state": "unknown"}
    assert by_key(rows("computers", [bundle([obj])]), "laps")["total"] is None


def test_service_hygiene_exception_does_not_suppress_security_findings():
    obj = user(objectClasses=["msDS-GroupManagedServiceAccount"], userAccountControl=640,
               passwordLastSet=(NOW - timedelta(days=400)).isoformat(), lastLogonTimestamp=(NOW - timedelta(days=100)).isoformat())
    data = rows("users", [bundle([obj])], exceptions={obj["sid"].upper(): {"sid": obj["sid"]}})
    assert by_key(data, "old_password")["total"] == by_key(data, "inactive_enabled")["total"] == 0
    assert by_key(data, "reversible_password")["total"] == 1


def test_sources_are_not_mutated_and_old_snapshots_remain_visible():
    source = bundle([computer()])
    source["current"]["observed_at"] = (NOW - timedelta(days=2)).isoformat()
    original = deepcopy(source)
    data = rows("computers", [source])
    assert source == original
    assert data["state"] in {"stale", "partial"}


@pytest.mark.parametrize("kind,report", [("users", users), ("computers", computers)])
def test_http_contract_nonempty_scoped_localized_and_no_real_db(monkeypatch, kind, report):
    read = []
    monkeypatch.setattr(checks, "previous_login", lambda principal: SINCE)
    monkeypatch.setattr(checks.ad_service_exceptions, "configured", lambda: {})
    def load(selected_kind, ids, since):
        read.append((selected_kind, ids, since))
        factory = user if kind == "users" else computer
        return [bundle([factory()], [], [], domain_id=domain_id) for domain_id in ids]
    monkeypatch.setattr(checks, "load_snapshots", load)
    monkeypatch.setattr(checks, "load_events", lambda *args: ([], False))
    fields = review_catalog.FIELDS if kind == "users" else review_catalog.COMPUTER_FIELDS
    decision = access(grant(fields, ids=(1, 2)), key=report.REPORT_KEY)
    handler = call(monkeypatch, report.REPORT, decision, "/data", {"tab": ["checks"], "domain_id": ["2"]})
    payload, status = handler.sent[-1]
    assert status == 200 and len(payload["items"]) == len(review_catalog.CATALOG[kind])
    assert read == [(kind, [2], SINCE)]
    assert payload["coverage"]["contract_id"] == "sli.ad-review-checks.v1"
    assert payload["coverage"]["domains"][0]["domain_id"] == 2
    assert payload["metrics"][0]["key"] == "not_evaluated"
    collection = payload["collections"]["checks"]
    assert len(collection) == len(review_catalog.CATALOG[kind]) + 1
    assert collection[-1]["section"] == "not_evaluated"
    # No HR grant is needed to see a check's title or explanations.
    assert all(row.get("title") and row.get("why") for row in collection[:-1])
    assert next(view for view in report.REPORT.views if view.key == "checks").source == "checks"
    denied = call(monkeypatch, report.REPORT, decision, "/data", {"tab": ["checks"], "domain_id": ["3"]})
    assert denied.sent[-1][1] == 403
    assert len(read) == 1


@pytest.mark.parametrize("kind,report", [("users", users), ("computers", computers)])
def test_field_denial_happens_before_any_snapshot_or_event_read(monkeypatch, kind, report):
    monkeypatch.setattr(checks, "load_snapshots", lambda *args: pytest.fail("unauthorized read"))
    context = QueryContext(access={}, params={}, domain_ids=[1], tab="checks", field_access=lambda fields: False)
    assert report._query(context)["state"] == "denied"


def test_snapshot_loader_uses_published_sources_checksums_exact_scope_and_no_report_computer_cache(monkeypatch):
    reads = []
    def read(sql, params=(), **kwargs):
        reads.append((sql, params))
        if "select id,fqdn" in sql:
            return [{"id": 2, "fqdn": "synthetic-2.example.test"}]
        return [{"role": role, "scope": scope, "contract_id": "synthetic-contract", "source_state": "complete",
                 "source_observed_at_utc": NOW if role == "current" else PRIOR,
                 "payload_json": {"objects": [{"objectGuid": "synthetic-guid", "name": "synthetic-host", "sid": "synthetic-sid"}]}}
                for role, scope in (("current", {}), ("previous", {"different": True}), ("baseline", {}))]
    monkeypatch.setattr(checks, "query_rows_bounded", read)
    loaded = checks.load_snapshots("computers", [2], SINCE)
    assert loaded[0]["current"]["objects"][0]["object_guid"] == "synthetic-guid"
    assert "previous" not in loaded[0] and "baseline" in loaded[0]
    sql = reads[1][0]
    assert "ad_snapshot_manifest_sources" in sql and "snap.payload_sha256=source.payload_sha256" in sql
    assert "computers_v6_source_snapshots" in sql and "computers_report_v6_snapshots" not in sql
    assert reads[1][1][0] == 2


def test_missing_source_family_does_not_fall_back_to_older_slot(monkeypatch):
    monkeypatch.setattr(checks, "query_rows_bounded", lambda sql, *args, **kwargs:
                        [{"id": 1, "fqdn": "synthetic.example.test"}] if "select id,fqdn" in sql else
                        [{"role": "current", "payload_json": None},
                         {"role": "previous", "payload_json": {"users": [user()]}, "scope": {}}])
    loaded = checks.load_snapshots("users", [1], None)
    data = rows("users", loaded)
    assert data["state"] == "not_collected"
    assert all(row["total"] is None for row in data["items"])


def test_query_errors_do_not_expose_database_details(monkeypatch):
    monkeypatch.setattr(checks, "previous_login", lambda principal: None)
    def fail(*args):
        raise RuntimeError("synthetic-private-database-detail")
    monkeypatch.setattr(checks, "load_snapshots", fail)
    data = users._query(QueryContext(access={}, params={}, domain_ids=[1], tab="checks"))
    assert data["state"] == "error" and data["items"] == []
    assert "synthetic-private-database-detail" not in str(data)


def test_privilege_check_compares_complete_membership_history_at_each_baseline():
    privileged = user(memberships={"status": "observed", "effective": [{"watchGroup": True}]})
    source = bundle([privileged], [user()], [user()])
    source["previous_predecessor"] = snapshot([user()], PRIOR - timedelta(days=1))
    source["baseline_predecessor"] = source["previous_predecessor"]
    row = by_key(rows("users", [source], since=SINCE), "new_privileged")
    assert row["total"] == row["new_count"] == 1
    assert row["previous_total"] == 0 and row["status"] == "new"


def test_previous_login_is_optional_until_homeimpl2_is_available(monkeypatch):
    monkeypatch.delattr(checks.auth, "previous_login", raising=False)
    assert checks.previous_login({"type": "session", "id": 1}) is None


def test_unreadable_events_preserve_snapshot_checks(monkeypatch):
    monkeypatch.setattr(checks, "previous_login", lambda principal: None)
    monkeypatch.setattr(checks, "load_snapshots", lambda *args: [bundle([computer(delegation={"unconstrained": True})])])
    def fail(*args):
        raise PermissionError("synthetic-private-detail")
    monkeypatch.setattr(checks, "load_events", fail)
    data = computers._query(QueryContext(access={}, params={}, domain_ids=[1], tab="checks"))
    assert by_key(data, "unconstrained_delegation")["total"] == 1
    assert data["coverage"]["event_coverage"] == "unavailable"
    assert "synthetic-private-detail" not in str(data)


def test_busy_authentication_scan_does_not_displace_changes(monkeypatch):
    seen = []
    def read(sql, params, **kwargs):
        seen.append((sql, params))
        return [event(4624)] * (checks.SCAN_LIMIT + 1) if params[1] == [4624] else [event(4725)]
    monkeypatch.setattr(checks, "query_rows_bounded", read)
    events, truncated = checks.load_events([2], PRIOR, NOW)
    assert truncated and len(events) == checks.SCAN_LIMIT + 1
    assert any(entry["event_id"] == 4725 for entry in events)
    assert all(params[0] == [2] for _, params in seen)
    assert all("with source_page" in sql and "actor_domain.id=e.subject_domain_id" in sql for sql, _ in seen)


def test_privilege_actor_is_not_inferred_from_an_unrelated_group_add():
    obj = user(memberships={"status": "observed", "effective": [{"watchGroup": True}]})
    unrelated = event(4728, membership_member_sid=obj["sid"], target_user_sid="synthetic-unrelated-group")
    data = rows("users", [bundle([obj], [user()])], events=[unrelated])
    assert by_key(data, "new_privileged")["change"] is None


def test_attribute_actor_can_be_correlated_by_exact_object_guid():
    obj = user(userAccountControl=640)
    change = event(5136, target_user_sid=None, facts_json={"object": obj["objectGuid"], "attribute": "userAccountControl"})
    data = rows("users", [bundle([obj])], events=[change])
    assert by_key(data, "reversible_password")["change"]["event_db_id"] == change["id"]


@pytest.mark.parametrize("kind,collection,source,count_key,factory,size", [
    ("users", "users", "directory", "user_count", user, 158),
    ("computers", "objects", "ad", "object_count", computer, 44),
])
def test_optional_partial_sources_do_not_hide_evaluated_zeroes(
    monkeypatch, kind, collection, source, count_key, factory, size,
):
    objects = [factory(i, **({"objectClasses": ["user"]} if kind == "users" else {"sli_agent": {"state": "absent"}}))
               for i in range(size)]
    payload = {collection: objects, "metadata": {count_key: size, "collection_status": "partial",
        "sources": [{"name": source, "status": "observed"}, {"name": "exact_last_logon", "status": "not_collected"}]}}
    def read(sql, *args, **kwargs):
        if "select id,fqdn" in sql:
            return [{"id": 1, "fqdn": "synthetic.invalid"}]
        return [{"role": role, "scope": {}, "contract_id": "synthetic", "payload_json": payload,
                 "source_state": "partial", "source_observed_at_utc": at}
                for role, at in (("current", NOW), ("previous", PRIOR))]
    monkeypatch.setattr(checks, "query_rows_bounded", read)
    loaded = checks.load_snapshots(kind, [1], None)
    assert loaded[0]["current"]["population_complete"] is True
    # The computer adapter projects source keys, so exercise aggregation with
    # the same normalized objects used by its other rule tests.
    if kind == "computers":
        for role in ("current", "previous"):
            loaded[0][role]["objects"] = objects
    data = rows(kind, loaded)
    key = "kerberos_no_preauth" if kind == "users" else "new_computer"
    row = by_key(data, key)
    assert row["total"] == row["previous_total"] == 0
    assert row["status"] == "unchanged" and not row["is_lower_bound"]
    assert data["coverage"]["domains"][0]["state"] == "complete"
    assert data["coverage"]["domains"][0]["snapshot_state"] == "partial"


@pytest.mark.parametrize("kind,source,count_key,collection", [
    ("users", "directory", "user_count", "users"), ("computers", "ad", "object_count", "objects"),
])
def test_partial_population_is_not_promoted_without_explicit_inventory_attestation(kind, source, count_key, collection):
    payload = {collection: [{}], "metadata": {count_key: 1, "sources": [{"name": source, "status": "partial"}]}}
    assert not checks._payload_population_complete(kind, payload, "partial")
    payload["metadata"]["sources"][0]["status"] = "observed"
    payload["metadata"][count_key] = 2
    assert not checks._payload_population_complete(kind, payload, "partial")
    payload["metadata"][count_key] = 1
    payload["metadata"]["coverage"] = {"truncated": True}
    assert not checks._payload_population_complete(kind, payload, "complete")
    assert not checks._payload_population_complete(kind, payload, "partial")


def test_known_zero_is_a_lower_bound_when_only_some_objects_have_inputs():
    source = bundle([user(), user(2, passwordLastSet=None)])
    row = by_key(rows("users", [source]), "old_password")
    assert row["total"] == 0 and row["is_lower_bound"]
    assert row["assessed_count"] == row["not_evaluated_count"] == 1
    assert row["status"] == "no_comparison"
    assert localize_presentation(row, "en")["status_text"] == "First check"
    source["current"]["objects"][0]["passwordLastSet"] = None
    assert by_key(rows("users", [source]), "old_password")["total"] is None


def test_known_nonservice_accounts_do_not_need_event_coverage():
    data = rows("users", [bundle([user(i, objectClasses=["top", "user"]) for i in range(158)])], events_truncated=True)
    row = by_key(data, "service_interactive_logon")
    assert row["total"] == row["not_evaluated_count"] == 0
    assert not row["is_lower_bound"]
    service = user(objectClasses=["msDS-GroupManagedServiceAccount"])
    assert checks.evaluate("users", service, NOW, None, False, [])["service_interactive_logon"] is None
    assert checks.evaluate("users", user(objectClasses=None), NOW, None, False, [])["service_interactive_logon"] is None


def test_computers_skip_authentication_without_discarding_change_evidence(monkeypatch):
    reads = []
    def read(sql, params, **kwargs):
        reads.append((sql, params))
        return []
    monkeypatch.setattr(checks, "query_rows_bounded", read)
    checks.load_events([1], PRIOR, NOW)
    assert len(reads) == 2
    assert reads[1][1] == ([1], [4624], PRIOR, NOW, checks.SCAN_LIMIT + 1)
    reads.clear()
    checks.load_events([1], PRIOR, NOW, False)
    assert len(reads) == 1 and 4624 not in reads[0][1][1]


@pytest.mark.parametrize("kind,report", [("users", users), ("computers", computers)])
def test_query_requests_logons_only_for_user_checks(monkeypatch, kind, report):
    source = bundle([user(1), user(2, enabled=False)], [user(3, objectClasses=["msDS-GroupManagedServiceAccount"])])
    monkeypatch.setattr(checks, "previous_login", lambda _: None)
    monkeypatch.setattr(checks, "load_snapshots", lambda *args: [source])
    monkeypatch.setattr(checks.ad_service_exceptions, "configured", lambda: {})
    monkeypatch.setattr(checks.report_additions, "load_agents", lambda *args: [])
    seen = []
    monkeypatch.setattr(checks, "load_events", lambda *args: (seen.append(args) or ([], False)))
    data = report._query(QueryContext({}, {}, domain_ids=[1], tab="checks"))
    assert data["state"] != "error"
    assert seen[0][-1] is (kind == "users")
