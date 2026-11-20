"""ATT&CK HTTP/reporting contracts using in-memory cursors, never a database."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json

import pytest

from server.api.errors import RequestInputError
from server.api.routes import semantic as routes
from server.sli.sigma import attack_coverage as coverage
from server.sli.sigma.history_job import HistoryCheckpoint, HistoryCounts, HistoryPartition, HistoryRequest, HistoryResult
from server.sli.sigma.windows_mapping import EventScope
from server.sli.storage.evidence_ref import EvidenceScope
from tests.unit.test_sigma_history_job import rule

START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = START + timedelta(days=1)
SCOPE = EvidenceScope("00000000-0000-0000-0000-000000000001", "sli.windows.ad-dc", "fixture-source", "generation-1")
RESOURCES = [{"server_id": 12, "domain_id": 7, "channel": "Security", "plugin_id": SCOPE.plugin_id,
              "source_instance_id": SCOPE.source_instance_id, "collection_scope_id": ""}]
CATALOG_SHA = "e" * 64
TECHNIQUE = {"stix_id": "attack-pattern--00000000-0000-0000-0000-000000000001", "modified": "2026-01-01T00:00:00Z",
             "object_version": "1.0", "tactics": ["credential-access"], "revoked": False, "deprecated": False}
CATALOG = {"release": "fixture-v1", "source_uri": "urn:fixture:offline", "techniques": {
    "T1003": TECHNIQUE, "T1003.001": TECHNIQUE | {"deprecated": True}, "T9999": TECHNIQUE | {"revoked": True}}}


def revision(number=1, tags=None, raw_sha256="a" * 64):
    return {**asdict(SCOPE), "rule_id": rule(number).rule_id, "raw_sha256": raw_sha256,
            "canonical_sha256": "b" * 64, "upstream_commit": "b" * 40, "status": "test",
            "tags": ["attack.t1003.001", "attack.credential_access"] if tags is None else tags,
            "requirements": {}, "requirements_sha256": "d" * 64}


def observation(*, counts=None, complete=True, status="completed", start=START, end=END,
                manifest="c" * 64, mapping="mapping-v1", created=END, digest="f" * 64, revision_row=None):
    rev = revision_row or revision()
    metrics = asdict(HistoryCounts("partition", rev["rule_id"], **(counts or {})))
    return {**asdict(SCOPE), "rule_id": rev["rule_id"], "raw_sha256": rev["raw_sha256"],
            "time_from": start, "time_to": end, "created_at": created, "coverage_sha256": digest,
            "document_json": {"version": coverage.CONTRACT, "request_sha256": "1" * 64,
                              "snapshot_sha256": "2" * 64, "high_watermark": 20,
                              "partition_complete": complete, "status": status,
                              "manifest_sha256": manifest, "plan_sha256": "d" * 64,
                              "compiler_version": "compiler-v1", "mapping_version": mapping,
                              "overlay_sha256": None, "counts": metrics}}


class Cursor:
    def __init__(self):
        self.calls = []
        self.sources = {tuple(asdict(SCOPE).values()): {"resources": RESOURCES}}
        self.catalogs = {CATALOG_SHA: deepcopy(CATALOG)}
        self.revisions = [revision()]
        self.observations = []
        self.matches = []
        self.result = []
        self.inserts = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        self.calls.append((normalized, params))
        if normalized.startswith("insert"):
            self.inserts.append((normalized, params))
            if "into sli_sigma.attack_catalogs" in normalized:
                self.catalogs.setdefault(params[0], json.loads(params[1]))
            elif "into sli_sigma.attack_source_scopes" in normalized:
                self.sources.setdefault(params[:5], {"resources": json.loads(params[5])})
            self.result = []
        elif normalized.startswith("set transaction"):
            self.result = []
        elif "from sli_sigma.attack_source_scopes" in normalized:
            row = self.sources.get(params)
            self.result = [row] if row else []
        elif "from sli_sigma.attack_catalogs" in normalized:
            self.result = [{"document_json": self.catalogs[params[0]]}] if params[0] in self.catalogs else []
        elif "from sli_sigma.sigma_rule_revisions" in normalized:
            self.result = [row for row in self.revisions if tuple(str(row[key]) for key in (
                "installation_id", "plugin_id", "source_instance_id")) == params[:3]]
            if "r.*" in normalized:
                self.result = [row for row in self.result if (row["rule_id"], row["raw_sha256"]) == params[3:5]]
        elif "from sli_sigma.attack_history_coverage" in normalized:
            self.result = [row for row in self.observations if tuple(row[key] for key in asdict(SCOPE)) == params[:5]
                           and row["time_from"] < params[5] and row["time_to"] > params[6]]
        elif "from sli_sigma.read_attack_live_matches" in normalized:
            self.result = deepcopy(self.matches)
        else:
            raise AssertionError(normalized)

    def fetchone(self):
        return self.result[0] if self.result else None

    def fetchall(self):
        return self.result


class Connection:
    def __init__(self, cursor):
        self.value = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def cursor(self):
        return self.value


@pytest.fixture
def cur(monkeypatch):
    value = Cursor()
    monkeypatch.setattr(coverage, "get_runtime_connection", lambda: Connection(value))
    return value


def read(**kwargs):
    args = {"scope": SCOPE, "since": START.isoformat(), "until": END.isoformat(), "catalog_sha256": CATALOG_SHA}
    return coverage.get_attack_coverage(kwargs.pop("access", {"platform_owner": True}), **(args | kwargs))


@pytest.mark.parametrize(("counts", "state"), [
    ({}, "no_data"), ({"scanned": 10, "evaluable": 10}, "no_matches"),
    ({"scanned": 10, "evaluable": 10, "matched": 2}, "matched"),
    ({"scanned": 10, "evaluable": 8, "unknown": 2}, "degraded"),
    ({"scanned": 10, "unknown": 10}, "not_evaluable"),
    ({"scanned": 10, "skipped": 10}, "not_evaluable"),
])
def test_data_states_are_independent_of_match_count(cur, counts, state):
    cur.observations = [observation(counts=counts)]
    payload = read()
    assert payload["state"] == "available"
    result, = payload["rules"]
    execution, = result["executions"]
    assert execution["state"] == state
    assert execution["counts"]["matched"] == counts.get("matched", 0)
    assert execution["matches_per_1000_evaluable"] == (
        1000 * counts.get("matched", 0) / counts["evaluable"] if counts.get("evaluable") else None)
    assert result["fixture_validation"] == "not_checked"
    assert result["telemetry_continuity"] == "unknown"
    assert result["current_admission"] == "not_measured"
    assert payload["items"][0]["history_states"][state] == 1
    assert payload["items"][0]["counts"]["fixture_verified"] == 0
    assert [item["technique_id"] for item in payload["items"]] == ["T1003.001"]
    assert payload["items"][0]["deprecated"] is True
    assert payload["unmapped"] == []
    assert execution["observed_intervals"] == []  # No event bounds are invented from the requested day.
    json.dumps(payload)  # HTTP-compatible, including all timestamps.


@pytest.mark.parametrize("status", ["partial", "cancelled", "failed"])
def test_unfinished_runs_never_become_clean_zeroes(cur, status):
    cur.observations = [observation(status=status)]
    execution, = read()["rules"][0]["executions"]
    assert (execution["state"], execution["complete"]) == ("incomplete", False)


def test_no_check_is_not_a_zero_data_check_and_unmapped_is_independent(cur):
    cur.revisions = [revision(tags=["attack.t0000", "attack.invalid_tag"]), revision(2, tags=[]),
                     revision(3, tags=["attack.credential_access"]), revision(4, tags=["attack.t9999"])]
    payload = read()
    assert all(row["executions"] == [] and row["compile_state"] == "not_checked" for row in payload["rules"])
    assert {row["reason"] for row in payload["unmapped"]} == {
        "not_a_catalog_technique", "missing_attack_tag", "missing_technique_tag"}
    assert len(payload["unmapped"]) == 4
    assert payload["items"][0]["revoked"] is True
    assert payload["items"][0]["counts"]["library"] == 1


def test_periods_are_half_open_and_partial_intervals_cannot_be_apportioned(cur):
    cur.observations = [observation(counts={"scanned": 10, "evaluable": 10, "matched": 1}),
                        observation(start=END, end=END + timedelta(days=1), counts={"scanned": 900})]
    assert read()["rules"][0]["executions"][0]["counts"]["scanned"] == 10
    short = read(since=(START + timedelta(hours=1)).isoformat())
    execution = short["rules"][0]["executions"][0]
    assert (execution["state"], execution["counts"]["scanned"]) == ("incomplete", 0)
    long = read(until=(END + timedelta(days=2)).isoformat())
    assert long["rules"][0]["executions"][0]["state"] == "incomplete"
    sql, params = next(call for call in cur.calls if "from sli_sigma.read_attack_live_matches" in call[0])
    assert params == (*tuple(asdict(SCOPE).values()), START, END)


def test_replay_checkpoint_and_overlapping_snapshots_do_not_double_count(cur):
    old = observation(counts={"scanned": 100, "evaluable": 100, "matched": 100})
    new = observation(counts={"scanned": 10, "evaluable": 10, "matched": 1}, created=END + timedelta(seconds=1))
    cur.observations = [old, new]
    execution = read()["rules"][0]["executions"][0]
    assert execution["counts"]["matched"] == 1
    cur.observations.append(observation(start=START + timedelta(hours=1), created=END + timedelta(seconds=2)))
    assert read()["rules"][0]["executions"][0]["state"] == "incomplete"


def test_execution_versions_quality_and_registered_revisions_remain_separate(cur):
    second = revision(raw_sha256="f" * 64)
    cur.revisions.append(second)
    old = observation(counts={"scanned": 2, "evaluable": 1, "unknown": 1})
    old["document_json"]["counts"]["unknown_fields"] = [["CommandLine", "field_missing", 1]]
    old["document_json"]["counts"]["reasons"] = [["payload_expired", 1]]
    cur.observations = [old, observation(manifest="b" * 64, mapping="mapping-v2"),
                        observation(revision_row=second)]
    payload = read()
    assert len(payload["rules"]) == 2
    assert len(payload["rules"][0]["executions"]) == 2
    assert payload["items"][0]["counts"]["library"] == 2
    quality = next(row for row in payload["rules"][0]["executions"] if row["mapping_version"] == "mapping-v1")["quality"][0]
    assert quality["unknown_fields"] == [["CommandLine", "field_missing", 1]]
    assert quality["reasons"] == [["payload_expired", 1]]


def access(*, scope=None, deny=None):
    policies = [] if scope is None else [{"capability_key": key, "effect": "allow", "valid": True, "scope": scope}
                                       for key in coverage.CAPABILITIES]
    if deny:
        policies.append({"capability_key": "semantic.review", "effect": "deny", "valid": True, "scope": deny})
    return {"capabilities": list(coverage.CAPABILITIES) if scope is None else [], "capability_policies": policies}


@pytest.mark.parametrize("grant", [{"kind": "domain", "ids": [7]}, {"kind": "server", "ids": [12]},
                                    {"mode": "restricted", "clauses": [{"plugin_ids": [SCOPE.plugin_id],
                                                                          "source_instance_ids": [SCOPE.source_instance_id]}]}])
def test_actual_source_resources_authorize_scoped_readers(cur, grant):
    assert read(access=access(scope=grant))["state"] == "available"


@pytest.mark.parametrize("decision", [access(scope={"kind": "domain", "ids": [8]}),
                                         access(deny={"kind": "channel", "values": ["Security"]}),
                                         access(deny={"kind": "server", "ids": [12]})])
def test_denied_readers_cannot_observe_catalog_versions_rules_counts_or_unmapped(cur, decision):
    payload = read(access=decision)
    assert payload["reason"] == "source_unavailable_or_denied"
    assert payload["items"] == payload["rules"] == payload["unmapped"] == []
    assert not any("from sli_sigma.sigma_rule_revisions" in sql for sql, _ in cur.calls)
    assert not any("attack_history_coverage" in sql for sql, _ in cur.calls)


def test_every_protected_source_resource_must_be_allowed(cur):
    cur.sources[tuple(asdict(SCOPE).values())] = {"resources": RESOURCES + [RESOURCES[0] | {"domain_id": 8}]}
    assert read(access=access(scope={"kind": "domain", "ids": [7]}))["state"] == "unavailable"


def test_missing_native_dimension_cannot_bypass_a_scoped_deny(cur):
    cur.sources[tuple(asdict(SCOPE).values())] = {"resources": [{"plugin_id": SCOPE.plugin_id,
                                                               "source_instance_id": SCOPE.source_instance_id}]}
    assert read(access=access(deny={"kind": "channel", "values": ["Security"]}))["state"] == "unavailable"


def test_invalid_deny_and_missing_one_required_capability_fail_closed(cur):
    decision = access()
    decision["capability_policies"].append({"capability_key": "semantic.review", "effect": "deny", "valid": False})
    assert read(access=decision)["state"] == "unavailable"
    assert read(access={"capabilities": ["semantic.review", "events.view"]})["state"] == "unavailable"


def test_no_module_rights_means_no_database_access(cur):
    assert read(access={})["state"] == "unavailable"
    assert cur.calls == []


@pytest.mark.parametrize("change", [{"source_instance_id": "other-source"}, {"source_generation": "generation-2"},
                                   {"plugin_id": "sli.workstations"}, {"collection_scope_id": "other-root"}])
def test_unavailable_and_denied_sources_share_the_same_response(cur, change):
    assert read(scope=replace(SCOPE, **change))["reason"] == "source_unavailable_or_denied"


def test_other_sources_generations_and_collection_roots_do_not_enter_counts(cur):
    cur.observations = [observation(counts={"scanned": 1, "evaluable": 1})]
    for key, value in (("source_instance_id", "other-source"), ("source_generation", "generation-2"),
                       ("plugin_id", "sli.workstations"), ("collection_scope_id", "other-root")):
        cur.observations.append(observation(counts={"scanned": 900}) | {key: value})
    assert read()["rules"][0]["executions"][0]["counts"]["scanned"] == 1


def test_atomic_input_matches_are_separate_from_history_and_admission(cur):
    cur.observations = [observation()]
    cur.matches = [{"rule_id": revision()["rule_id"], "rule_sha256": "a" * 64,
                    "manifest_sha256": "b" * 64, "compiler_version": "compiler-v2", "mapping_version": "mapping-v2",
                    "overlay_sha256": "c" * 64, "evaluation_mode": "shadow", "matches": 3,
                    "first_occurred_at": START, "last_occurred_at": START + timedelta(hours=1)}]
    payload = read()
    assert payload["rules"][0]["executions"][0]["state"] == "no_data"
    assert payload["rules"][0]["eligible_detection_matches"] == 3
    assert payload["rules"][0]["detection_inputs"][0]["evaluation_mode"] == "shadow"
    assert payload["items"][0]["counts"]["enabled"] is None
    json.dumps(payload)


def test_missing_catalog_schema_and_limits_are_not_zero_data(cur, monkeypatch):
    assert read(catalog_sha256="0" * 64)["reason"] == "catalog_unavailable"
    monkeypatch.setattr(coverage, "MAX_ROWS", 1)
    cur.revisions.append(revision(2))
    assert read()["reason"] == "projection_limit"
    monkeypatch.setattr(coverage, "get_runtime_connection", lambda: (_ for _ in ()).throw(RuntimeError("private-diagnostic")))
    payload = read()
    assert payload["reason"] == "projection_unavailable"
    assert "private-diagnostic" not in repr(payload)


@pytest.mark.parametrize("kwargs", [{"since": "2026-01-01"}, {"until": START.isoformat()},
                                    {"until": (START + timedelta(days=32)).isoformat()},
                                    {"catalog_sha256": "invalid"}])
def test_invalid_filters_fail_before_any_database_read(cur, kwargs):
    with pytest.raises(ValueError, match="^sigma_attack_filter_invalid$"):
        read(**kwargs)
    assert cur.calls == []


def history_result(*, status="completed"):
    part = HistoryPartition(EventScope(SCOPE.installation_id, SCOPE.source_instance_id, SCOPE.source_generation),
                            "core_event", START, END, "fixture-snapshot", 5)
    req = HistoryRequest("fixture-job", (rule(),), (part,), "c" * 64)
    count = HistoryCounts(part.key, rule().rule_id, scanned=5, evaluable=5, matched=1)
    checkpoint = HistoryCheckpoint(req.key, partition_index=1, counts=(count,))
    return HistoryResult(status, "snapshot_exhausted", checkpoint, req)


def test_history_publisher_retains_versions_counters_not_evidence_or_payload(cur):
    result = history_result()
    coverage.record_history_coverage(cur, result, scope=SCOPE, resources=[{"domain_id": 7, "server_id": 12, "channel": "Security"}])
    sql, params = cur.inserts[-1]
    document = json.loads(params[-1])
    assert "attack_history_coverage" in sql
    assert params[:5] == tuple(asdict(SCOPE).values())
    assert document["counts"]["matched"] == 1
    assert document["manifest_sha256"] == result.request.manifest_sha256
    assert document["compiler_version"] == result.request.rules[0].compiler_version
    assert document["mode"] == "test" and document["telemetry_continuity"] == "unknown"
    assert "fixture-snapshot" not in params[-1]
    assert "samples" not in document and "fields" not in document and "native_id" not in params[-1]


def test_history_publisher_rejects_rebinding_and_missing_retained_revision(cur):
    with pytest.raises(coverage.CoverageUnavailable, match="sigma_attack_source_conflict"):
        coverage.record_history_coverage(cur, history_result(), scope=SCOPE, resources=[{"domain_id": 8}])
    cur.revisions.clear()
    with pytest.raises(coverage.CoverageUnavailable, match="sigma_attack_revision_unavailable"):
        coverage.record_history_coverage(cur, history_result(), scope=SCOPE, resources=RESOURCES)


@pytest.mark.parametrize("resources", [[{"plugin_id": "other-plugin"}], [{"domain_id": -1}], [{"channel": ""}],
                                     [{"raw": "not-allowed"}]])
def test_publisher_rejects_invalid_resource_metadata(cur, resources):
    with pytest.raises(ValueError, match="sigma_attack_history_invalid"):
        coverage.record_history_coverage(cur, history_result(), scope=SCOPE, resources=resources)
    assert not cur.calls


def test_missing_completed_counters_are_not_published_as_zero_data(cur):
    result = history_result()
    result = replace(result, checkpoint=replace(result.checkpoint, counts=()))
    with pytest.raises(ValueError, match="sigma_attack_history_invalid"):
        coverage.record_history_coverage(cur, result, scope=SCOPE, resources=RESOURCES)
    assert not cur.calls


def test_history_publisher_requires_the_retained_upstream_version(cur):
    cur.revisions[0]["upstream_commit"] = "0" * 40
    with pytest.raises(coverage.CoverageUnavailable, match="sigma_attack_revision_unavailable"):
        coverage.record_history_coverage(cur, history_result(), scope=SCOPE, resources=RESOURCES)


def test_observed_time_bounds_come_from_events_not_the_selected_day(cur):
    row = observation(counts={"scanned": 2, "evaluable": 2})
    first = (START + timedelta(hours=1)).isoformat()
    last = (START + timedelta(hours=2)).isoformat()
    row["document_json"]["counts"].update(first_occurred_at=first, last_occurred_at=last)
    cur.observations = [row]
    execution = read()["rules"][0]["executions"][0]
    assert execution["observed_intervals"] == [{"first_occurred_at": first, "last_occurred_at": last}]
    assert execution["evaluation_intervals"] == [{"since": START.isoformat(), "until": END.isoformat()}]


def stix_bytes():
    return json.dumps({"type": "bundle", "objects": [{
        "type": "attack-pattern", "id": TECHNIQUE["stix_id"], "modified": TECHNIQUE["modified"],
        "x_mitre_domains": ["enterprise-attack"], "x_mitre_version": "1.0", "revoked": True,
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1003.001"}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
        "description": "Synthetic discarded text"}]}).encode()


def import_catalog(cur, **kwargs):
    raw = stix_bytes()
    args = {"release": "fixture-v1", "expected_sha256": sha256(raw).hexdigest(), "source_uri":
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/" + "a" * 40 + "/enterprise-attack/enterprise-attack.json"}
    return coverage.import_attack_catalog(cur, raw, **(args | kwargs))


def test_offline_stix_retains_retired_ids_tactics_versions_and_provenance(cur):
    digest = import_catalog(cur)
    catalog = cur.catalogs[digest]
    assert catalog["techniques"]["T1003.001"]["revoked"] is True
    assert catalog["techniques"]["T1003.001"]["tactics"] == ["credential-access"]
    assert "Synthetic discarded text" not in repr(catalog)
    assert import_catalog(cur) == digest
    with pytest.raises(coverage.CoverageUnavailable, match="sigma_attack_catalog_conflict"):
        import_catalog(cur, release="other-release")


@pytest.mark.parametrize("kwargs", [{"expected_sha256": "0" * 64}, {"source_uri": "https://example.invalid/unpinned"},
                                    {"release": "invalid release"}])
def test_unpinned_or_invalid_stix_is_rejected_without_writes(cur, kwargs):
    with pytest.raises(ValueError, match="^sigma_attack_catalog_invalid$"):
        import_catalog(cur, **kwargs)
    assert not cur.calls


class Handler:
    def __init__(self):
        self.payload = None

    def _access_decision(self):
        return {"platform_owner": True}

    def _send_json(self, payload):
        self.payload = payload


def query():
    return {key: [value] for key, value in asdict(SCOPE).items()} | {
        "since": [START.isoformat()], "until": [END.isoformat()], "catalog_sha256": [CATALOG_SHA]}


def test_http_route_is_registered_resource_aware_and_uses_the_projection(cur):
    handler = Handler()
    path = "/api/v1/semantic/attack-coverage"
    assert ("GET", path) in routes.ROUTES
    assert routes.is_resource_aware(path)
    assert routes.try_handle_get(handler, path, query()) is True
    assert handler.payload["contract"] == coverage.CONTRACT
    assert handler.payload["scope"] == asdict(SCOPE)


@pytest.mark.parametrize("change", [{"raw_sql": ["invalid"]}, {"since": ["2026-01-01"]},
                                  {"source_instance_id": ["one", "two"]}, {"installation_id": ["invalid"]},
                                  {"until": []}])
def test_http_rejects_unknown_duplicate_empty_and_invalid_filters(cur, change):
    with pytest.raises(RequestInputError, match="^sigma_attack_filter_invalid$"):
        routes.try_handle_get(Handler(), "/api/v1/semantic/attack-coverage", query() | change)
    assert not cur.calls
