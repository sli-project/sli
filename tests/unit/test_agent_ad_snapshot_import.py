"""AD publication and shared projection equivalence, with fakes and no DB."""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from test_agent_ad_snapshot import DN, NOW, SID, config, directory, obj
from test_agent_snapshot_stream import AGENT, Ledger, packets

from server.ad_context import repository
from server.ad_context.contracts import AdContextContractError, validate_bundle
from server.ad_context.snapshot_manifest import ALLOWED_FAMILY_CONTRACTS
from server.sli.agents import ad_snapshot_import as importer
from server.sli.agents import snapshot_consumer
from server.sli.agents.import_authorization import PacketPending
from server.sli.entities import users_v2_directory_projection as projection
from server.sli.reports.active_directory_reporting import build_active_directory_controls, evaluate_active_directory_risks
from server.sli.reports.computers_v6_reporting import project_computers_v6_exact
from server.sli.reports.users_v2_reporting import snapshot_from_directory_projection
from sli_agent.ad_snapshot import ATTRIBUTE_MAP, DATE_MAP, INTERVAL_MAP, UAC_FLAGS, normalize_capture
from sli_agent.snapshot_stream import SnapshotStream, due_slot


def complete_families(**changes):
    cfg = config(expensive_flags={}, **changes)
    raw = directory(8)
    raw["objects"].append(obj(50001, "domain", name="directory.invalid", minpwdlength=14, lockoutthreshold=5))
    return cfg, {name: data for name, (data, _) in normalize_capture(raw, cfg, observed_at=NOW).items()}


def cycle(cfg):
    return {"cycle_id": str(UUID(int=90001)), "agent_id": AGENT, "module_id": "sli.ad-snapshot",
            "domain_sid": SID, "slot_start_utc": due_slot(cfg, NOW), "policy": cfg}


@pytest.mark.parametrize("identity_conflict", [None, "kind", "sid"])
def test_first_import_reuses_guid_across_directory_and_exact_logon(monkeypatch, identity_conflict):
    cfg = config(expensive_flags={"exact_last_logon": True})
    raw = directory(2)
    raw["objects"][0]["properties"].update({"pwdlastset": 0,
        "msds-allowedtoactonbehalfofotheridentity": {"present": True, "status": "observed",
            "sids": [SID + "-2001"], "descriptor_sha256": "a" * 64}})
    bundle = normalize_capture(raw, cfg, observed_at=NOW)["ad_context_base"][0]
    if identity_conflict:
        repeated = next(r for r in bundle["records"] if r["record_type"] == "entity" and r["section"] == "directory_exact_logon")
        repeated["identity"]["kind" if identity_conflict == "kind" else "object_sid"] = (
            "ad_computer" if identity_conflict == "kind" else SID + "-999999")
        bundle.pop("bundle_sha256", None)
    aliases, details, observations = {}, {}, []

    class IdentityCursor:
        rowcount = 0

        def execute(self, sql, params=()):
            self.rows = []
            self.rowcount = 0
            if "select attributes_json from entity_details_v2" in sql:
                self.rows = [{"attributes_json": details[params[0]]}] if params[0] in details else []
            elif "insert into ad_context_entity_aliases" in sql:
                entity_id, _, alias_type, _, normalized, *_ = params
                previous = aliases.setdefault((alias_type, normalized), entity_id)
                self.rowcount = int(previous == entity_id)

        def fetchone(self):
            return self.rows[0] if self.rows else None

    def persist(cur, domain_id, record, *, entity_id, attributes):
        if entity_id is None:
            entity_id = len(details) + 1
        details[entity_id] = attributes
        observations.append((record["identity"]["object_guid"], record["section"], entity_id))
        return entity_id

    monkeypatch.setattr(repository, "_resolve_domain", lambda *a: 7)
    monkeypatch.setattr(repository, "_start_run", lambda *a: False)
    monkeypatch.setattr(repository, "_preload_existing_entity_ids", lambda *a: {})
    monkeypatch.setattr(repository, "persist_entity_identity", persist)
    monkeypatch.setattr(repository, "_observe_entity", lambda *a: 0)
    monkeypatch.setattr(repository, "_observe_relation", lambda *a: 0)
    monkeypatch.setattr(repository, "_write_evidence", lambda *a: None)
    conn = type("IdentityConnection", (), {"cursor": lambda self: nullcontext(IdentityCursor())})()
    if identity_conflict:
        with pytest.raises(ValueError, match="^stable GUID alias conflicts with entity identity$"):
            repository.import_bundle(conn, bundle)
        return
    repository.import_bundle(conn, bundle)

    repeated = {guid for guid, section, _ in observations if section == "directory_exact_logon"}
    assert repeated
    for guid in repeated:
        matches = [(section, entity_id) for observed_guid, section, entity_id in observations if observed_guid == guid]
        assert {section for section, _ in matches} == {"directory_accounts", "directory_exact_logon"}
        assert len({entity_id for _, entity_id in matches}) == 1
    entity_id = next(entity_id for guid, section, entity_id in observations
                     if guid == str(UUID(int=1)) and section == "directory_accounts")
    assert details[entity_id]["resource_based_delegation_sids"] == [SID + "-2001"]
    assert details[entity_id]["resource_based_delegation_status"] == "observed"
    assert details[entity_id]["password_last_set_status"] == "not_set"


@pytest.mark.parametrize("schedule,slot", [
    (None, "2026-10-09T20:00:00+00:00"),
    (None, "2026-10-09T23:01:00+00:00"),
    (None, "2026-10-09T23:00:00"),
    ({"timezone": "UTC", "hours": [0]}, "2026-10-09T11:00:00+00:00"),
    ({"timezone": "Asia/Kathmandu", "hours": [0, 8, 23]}, "2026-10-09T11:00:00+00:00"),
])
def test_unscheduled_slot_is_reported_before_any_database_work(schedule, slot):
    cfg, families = complete_families(**({"schedule": schedule} if schedule else {}))
    current = {**cycle(cfg), "slot_start_utc": slot}
    with pytest.raises(PacketPending, match="^agent_ad_schedule_unsupported$"):
        importer.import_ad_cycle(None, current, families)


@pytest.mark.parametrize("schedule,version", [
    (None, "2.0"),
    ({"timezone": "Asia/Novosibirsk", "hours": list(range(24))}, "3.0"),
    ({"timezone": "Asia/Kathmandu", "hours": list(range(24))}, "3.0"),
    ({"timezone": "Asia/Kathmandu", "hours": [0, 8, 23]}, "3.0"),
    ({"timezone": "UTC", "hours": [0]}, "3.0"),
    ({"timezone": "UTC", "hours": [1, 11, 17]}, "3.0"),
])
def test_configured_agent_cycle_publishes_its_exact_slot(monkeypatch, schedule, version):
    cfg, families = complete_families(**({"schedule": schedule} if schedule else {}))
    conn = Connection()
    fake_publication(monkeypatch, conn, families)
    current = cycle(cfg)
    with conn.transaction():
        result = importer.import_ad_cycle(conn, current, families)
    assert result["status"] == "published"
    assert conn.manifest["contract_version"] == "sli.ad-snapshot-manifest/" + version
    assert conn.manifest["slot_start_utc"] == current["slot_start_utc"].replace("+00:00", "Z")
    if version == "2.0":
        assert conn.manifest["schedule_timezone"] == "Asia/Novosibirsk"
        assert conn.manifest["scheduled_local_at"] == "2026-10-08T18:00:00"
    else:
        assert conn.manifest["schedule_timezone"] == "UTC"
        assert conn.manifest["scheduled_local_at"] == current["slot_start_utc"].removesuffix("+00:00")
    assert [kind for kind, _ in conn.effects][-1] == "projections"


def test_newer_ad_observation_is_a_safe_pending_reason(monkeypatch):
    cfg, families = complete_families()
    def stale(*args):
        raise repository.AdContextOutOfOrderError("synthetic-private-diagnostic")
    monkeypatch.setattr(importer, "import_bundle", stale)
    with pytest.raises(PacketPending, match="^agent_ad_snapshot_superseded$"):
        importer.import_ad_cycle(Connection(), cycle(cfg), families)


class Connection:
    def __init__(self, cycle=None, rows=None):
        self.cycle, self.rows = cycle, rows or []
        self.effects, self.sql, self.tx = [], [], 0
        self.manifest = None

    def cursor(self):
        return nullcontext(Cursor(self))

    @contextmanager
    def transaction(self):
        old = deepcopy((self.effects, self.manifest))
        self.tx += 1
        try:
            yield
        except Exception:
            self.effects, self.manifest = old
            raise
        finally:
            self.tx -= 1


class Cursor:
    def __init__(self, conn):
        self.conn, self.rows = conn, []

    def execute(self, sql, params=()):
        self.conn.sql.append((sql, params))
        if "from domains" in sql:
            self.rows = [{"id": 7, "sid": SID, "dns": "directory.invalid"}]
        elif "select transport_state" in sql:
            self.rows = [{"transport_state": "pending", "publication_state": "pending"}]
        elif "from sli_agent_snapshot_chunks" in sql:
            self.rows = self.conn.rows
        elif "from sli_agent_snapshot_cycles" in sql:
            self.rows = [self.conn.cycle] if self.conn.cycle else []
        elif sql.lstrip().startswith("update sli_agent_snapshot_cycles"):
            if "publication_state='published'" in sql:
                self.conn.effects.append(("cycle_published", params))
            elif "publication_state='superseded'" in sql:
                self.conn.effects.append(("cycle_superseded", params))
            else:
                assert "transport_state='complete'" in sql
                self.conn.effects.append(("transport_complete", params))
            self.rows = []
        elif "from ad_context_entity_aliases" in sql:
            self.rows = [{"alias_value": guid, "entity_id": index + 1} for index, guid in enumerate(params[1])]
        elif "pg_advisory_xact_lock" in sql:
            self.rows = []
        else:
            raise AssertionError(sql)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


def fake_publication(monkeypatch, conn, families, *, fail=None):
    def imported(connection, bundle):
        assert connection is conn and conn.tx >= 1
        conn.effects.append(("import", bundle["run_id"]))
    monkeypatch.setattr(importer, "import_bundle", imported)
    def descriptor(connection, family, source):
        assert connection is conn
        return {"family": family, "source_id": str(source), "contract_id": ALLOWED_FAMILY_CONTRACTS[family],
                "observed_at_utc": NOW.isoformat().replace("+00:00", "Z"), "source_state": "complete",
                "payload_sha256": "a" * 64, "reason_code": None}
    monkeypatch.setattr(importer, "_source_descriptor", descriptor)
    def users(connection, **kwargs):
        assert len([e for e in conn.effects if e[0] == "import"]) == 5
        conn.effects.append(("users", kwargs["snapshot"]))
        return {"snapshot_id": 1}
    monkeypatch.setattr(importer, "persist_users_v2_snapshot", users)
    def computers(connection, **kwargs):
        assert connection is conn and kwargs["snapshot"] == families["computers_v6"]
        assert kwargs["collector_sha256"] == hashlib.sha256(b"sli-agent/ad-snapshot/1").digest()
        conn.effects.append(("computers", deepcopy(kwargs["snapshot"])))
        if fail == "computers":
            raise ValueError("private-marker")
        return {"snapshot_uuid": families["computers_v6"]["metadata"]["snapshot_id"]}
    monkeypatch.setattr(importer, "persist_computers_v6_source_snapshot", computers)
    def publish(connection, manifest):
        assert connection is conn
        conn.manifest = manifest
        conn.effects.append(("manifest", manifest["manifest_id"]))
        return {"manifest_id": manifest["manifest_id"], "replayed": 0}
    monkeypatch.setattr(importer, "publish_snapshot_manifest", publish)
    monkeypatch.setattr(repository, "load_projection_manifest", lambda connection, manifest: conn.manifest)
    def project(connection, **kwargs):
        assert connection is conn
        assert kwargs["projection_keys"] == ("ad.state", "ad.users.v2", "ad.computers.v6")
        assert kwargs["manifest_id"] == conn.manifest["manifest_id"]
        conn.effects.append(("projections", kwargs["manifest_id"]))
        return {"status": "pending" if fail == "projection" else "completed"}
    monkeypatch.setattr(importer, "run_exact_manifest_projection_cycle", project)


def signed_cycle(tmp_path, cfg, families):
    stream = SnapshotStream(tmp_path, "sli.ad-snapshot")
    state = stream.begin(cfg, now=NOW)
    stream.freeze(state, {name: (data, len(data.get("records", data.get("objects", [])))) for name, data in families.items()})
    key = ec.generate_private_key(ec.SECP256R1())
    ledger = Ledger(cfg)
    for packet in packets(stream, key):
        assert ledger.receive(packet, key)["status"] == "committed"
    current = next(iter(ledger.cycles.values()))
    current["domain_sid"] = SID
    return current, ledger.rows, ledger.identity


def test_complete_cycle_imports_all_families_users_computers_manifest_and_projections(monkeypatch):
    cfg, families = complete_families()
    conn = Connection()
    fake_publication(monkeypatch, conn, families)
    with conn.transaction():
        result = importer.import_ad_cycle(conn, cycle(cfg), families)
    assert result["status"] == "published"
    assert [kind for kind, _ in conn.effects] == ["import"] * 5 + ["users", "computers", "manifest", "projections"]
    users = next(value for kind, value in conn.effects if kind == "users")
    assert len(users["users"]) == 8
    assert users["users"][0]["memberships"]["primary"] is not None
    assert any("Цикл" in entry for user in users["users"] for entry in user["memberships"]["unresolved"])
    assert "pg_advisory_xact_lock" in conn.sql[0][0]
    assert not any("latest" in sql.lower() for sql, _ in conn.sql)
    assert {m["family"] for m in conn.manifest["members"]} == set(cfg["families"]) | {"users_v2"}


@pytest.mark.parametrize("fail", ["computers", "projection"])
def test_failure_rolls_back_whole_publication_and_keeps_previous(monkeypatch, fail):
    cfg, families = complete_families()
    conn = Connection()
    conn.effects = [("previous", "retained")]
    fake_publication(monkeypatch, conn, families, fail=fail)
    with pytest.raises(ValueError):
        with conn.transaction():
            importer.import_ad_cycle(conn, cycle(cfg), families)
    assert conn.effects == [("previous", "retained")]
    assert conn.manifest is None


@pytest.mark.parametrize("change,reason", [
    ("missing_family", "agent_ad_required_families_missing"),
    ("partial_accounts", "agent_ad_base_incomplete"),
    ("partial_graph", "agent_ad_base_incomplete"),
    ("partial_exact", "agent_ad_exact_logon_incomplete"),
])
def test_incomplete_cycle_is_pending_before_any_import(change, reason):
    cfg, families = complete_families()
    if change == "missing_family":
        families.pop("ad_domain_health")
    else:
        index = {"partial_accounts": 0, "partial_graph": 1, "partial_exact": 2}[change]
        families["ad_context_base"]["sections"][index]["status"] = "partial"
        if change == "partial_graph":
            families["ad_context_base"]["scope"]["computer_membership_collected"] = False
    conn = Connection()
    with pytest.raises(PacketPending, match=reason):
        importer.import_ad_cycle(conn, cycle(cfg), families)
    assert conn.effects == [] and conn.sql == []


@pytest.mark.parametrize("postgres_slot", [None, timezone.utc, timezone(timedelta(hours=7))])
def test_consumer_transport_and_atomic_publication_complete(tmp_path, monkeypatch, postgres_slot):
    cfg, families = complete_families()
    current, rows, identity = signed_cycle(tmp_path, cfg, families)
    if postgres_slot is not None:
        current["slot_start_utc"] = datetime.fromisoformat(current["slot_start_utc"]).astimezone(postgres_slot)
    conn = Connection(current, rows)
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a, **kw: None)
    fake_publication(monkeypatch, conn, families)
    assert snapshot_consumer.consume_snapshot_cycles(conn) == {
        "completed": 1, "scanned": 1, "pending_reasons": {}}
    assert conn.effects[-1][0] == "cycle_published"
    update = conn.sql[-1][0]
    assert "publication_state='published'" in update
    assert any("transport_state='complete'" in sql for sql, _ in conn.sql)


def test_consumer_missing_chunk_and_disabled_plugin_do_not_touch_previous(tmp_path, monkeypatch):
    cfg, families = complete_families()
    current, rows, identity = signed_cycle(tmp_path, cfg, families)
    conn = Connection(current, rows[:-1])
    conn.effects = [("previous", "retained")]
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a, **kw: None)
    assert snapshot_consumer.consume_snapshot_cycles(conn)["completed"] == 0
    assert conn.effects == [("previous", "retained")]
    conn.rows = rows
    def disabled(*a):
        raise PacketPending("agent_plugin_disabled")
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", disabled)
    assert snapshot_consumer.consume_snapshot_cycles(conn)["pending_reasons"] == {"agent_plugin_disabled": 1}
    assert conn.effects == [("previous", "retained")]


def test_unavailable_publication_connection_is_not_an_invalid_cycle(tmp_path, monkeypatch):
    cfg, families = complete_families()
    current, rows, _ = signed_cycle(tmp_path, cfg, families)
    conn = Connection(current, rows)
    conn.effects = [("previous", "retained")]
    def unavailable():
        raise RuntimeError("synthetic-private-connection-diagnostic")
    result = snapshot_consumer.consume_snapshot_cycles(conn, publication_connection_factory=unavailable)
    assert result == {"completed": 0, "scanned": 1,
                      "pending_reasons": {"agent_snapshot_import_unavailable": 1}}
    assert conn.effects == [("previous", "retained")]


def test_superseded_ad_cycle_rolls_back_import_and_finishes_publication(tmp_path, monkeypatch):
    cfg, families = complete_families()
    current, rows, identity = signed_cycle(tmp_path, cfg, families)
    conn = Connection(current, rows)
    conn.effects = [("previous", "retained")]
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a: None)
    def stale(*args):
        conn.effects.append(("partial_import", "rolled_back"))
        raise repository.AdContextOutOfOrderError("synthetic-private-diagnostic")
    monkeypatch.setattr(importer, "import_bundle", stale)
    result = snapshot_consumer.consume_snapshot_cycles(conn)
    assert result == {"completed": 1, "scanned": 1, "pending_reasons": {}}
    assert [kind for kind, _ in conn.effects] == ["previous", "transport_complete", "cycle_superseded"]
    assert conn.effects[-1][1] == ("agent_ad_snapshot_superseded", current["cycle_id"])


def equivalence_rows(legacy_users, agent_users, legacy_computers, agent_computers, legacy_infrastructure, agent_infrastructure):
    """PR 4 can extend this row comparison with DB schemas/filters/exports."""
    def users(snapshot):
        return {r["objectGuid"]: {key: value for key, value in r.items() if key not in {"id", "entityId"}}
                for r in snapshot["users"]}
    assert users(legacy_users) == users(agent_users)
    assert {r["objectGuid"]: r for r in legacy_computers["objects"]} == {r["objectGuid"]: r for r in agent_computers["objects"]}
    assert legacy_infrastructure == agent_infrastructure


def test_legacy_and_agent_use_same_directory_membership_and_row_projectors(monkeypatch):
    cfg, families = complete_families()
    bundles, computers = importer.prepare_ad_cycle(cycle(cfg), families)
    guids = sorted({r["identity"]["object_guid"] for b in bundles.values() for r in b["records"] if r["record_type"] == "entity"})
    entity_ids = {guid: index + 1 for index, guid in enumerate(guids)}
    items, inputs = importer.exact_directory_inputs(bundles, domain_id=7, entity_ids=entity_ids)
    coverage = {"domains": [{"domain_id": 7, "domain_name": "directory.invalid"}], "latest_observed_at_utc": NOW.isoformat().replace("+00:00", "Z")}
    monkeypatch.setattr(projection, "_entity_versions", lambda _: (inputs["versions"], inputs["domains"]))
    monkeypatch.setattr(projection, "_aliases", lambda _: inputs["aliases"])
    monkeypatch.setattr(projection, "_latest_sections", lambda _: inputs["sections"])
    monkeypatch.setattr(projection, "_load_graph", lambda **kw: inputs["graph"])
    legacy = projection.build_directory_projection(items=items, coverage=coverage, requested_domain_ids=[7])
    # Prove the exact path cannot call a latest DB reader.
    monkeypatch.setattr(projection, "_latest_sections", lambda _: pytest.fail("unbound latest read"))
    agent = projection.build_directory_projection(items=items, coverage=coverage, requested_domain_ids=[7], exact_inputs=inputs)
    legacy_users = snapshot_from_directory_projection(legacy, coverage=coverage, active={})
    agent_users = snapshot_from_directory_projection(agent, coverage=coverage, active={})
    rows = [{"entity_type": r["identity"]["kind"], "attributes": r["attributes"],
             "entity_id": entity_ids[r["identity"]["object_guid"]], "domain_id": 7,
             "display_name": r["attributes"].get("display_name") or r["record_key"],
             "source_section": r["section"], "observed_at_utc": r["observed_at_utc"]}
            for r in bundles["ad_domain_posture"]["records"] if r["record_type"] == "entity"]
    controls = build_active_directory_controls(rows)
    risks = [evaluate_active_directory_risks(r["entity_type"], r["attributes"], NOW) for r in rows]
    equivalence_rows(legacy_users, agent_users, project_computers_v6_exact(computers),
                     project_computers_v6_exact(deepcopy(computers)), (controls, risks), (deepcopy(controls), deepcopy(risks)))
    assert legacy == agent


@pytest.mark.parametrize("area", ["users", "computers", "infrastructure"])
def test_equivalence_helper_detects_a_changed_row_in_each_area(area):
    users = {"users": [{"objectGuid": str(UUID(int=1)), "displayName": "synthetic"}]}
    computers = {"objects": [{"objectGuid": str(UUID(int=2)), "enabled": True}]}
    infrastructure = [{"entity_type": "domain", "password_min_length": 14}]
    changed_users, changed_computers, changed_infrastructure = deepcopy((users, computers, infrastructure))
    if area == "users":
        changed_users["users"][0]["displayName"] = "changed"
    elif area == "computers":
        changed_computers["objects"][0]["enabled"] = False
    else:
        changed_infrastructure[0]["password_min_length"] = 0
    with pytest.raises(AssertionError):
        equivalence_rows(users, changed_users, computers, changed_computers, infrastructure, changed_infrastructure)


def test_destination_allowlist_matches_existing_contract():
    from server.ad_context.contracts import ENTITY_ATTRIBUTE_KEYS
    assert set(ATTRIBUTE_MAP.values()) | set(DATE_MAP.values()) | set(INTERVAL_MAP.values()) | set(UAC_FLAGS) <= ENTITY_ATTRIBUTE_KEYS


def test_unconfigured_membership_scope_can_only_be_skipped():
    _, families = complete_families()
    for name in ("ad_privileged_membership", "ad_vpn_membership"):
        bundle = deepcopy(families[name])
        assert validate_bundle(bundle)["sections"][0]["status"] == "skipped"
        bundle["sections"][0]["status"] = "complete"
        with pytest.raises(AdContextContractError, match="requires scope"):
            validate_bundle(bundle)


@pytest.mark.parametrize("code", ["directory_accounts_truncated", "directory_group_memberships_truncated",
                                "directory_group_links_unresolved", "unknown_source_failure"])
def test_legacy_quality_blockers_cannot_publish_even_with_complete_section_headers(code):
    cfg, families = complete_families()
    base = families["ad_context_base"]
    base["records"].append({"record_type": "data_quality", "record_key": "quality:test",
        "section": "directory_accounts", "observed_at_utc": base["observed_at_utc"],
        "classification": "DataQuality", "code": code, "message": "Incomplete synthetic source."})
    base["sections"][0]["record_count"] += 1
    conn = Connection()
    with pytest.raises(PacketPending, match="agent_ad_base_incomplete"):
        importer.import_ad_cycle(conn, cycle(cfg), families)
    assert not conn.effects and not conn.sql


@pytest.mark.parametrize("family", ["ad_domain_posture", "ad_domain_health", "ad_vpn_membership", "computers_v6"])
def test_frozen_internal_family_scope_cannot_be_substituted(family):
    cfg, families = complete_families()
    if family == "computers_v6":
        families[family]["metadata"]["search_base"] = "OU=other," + DN
    else:
        families[family]["scope"]["search_base"] = "OU=other," + DN
    conn = Connection()
    with pytest.raises(ValueError):
        importer.import_ad_cycle(conn, cycle(cfg), families)
    assert not conn.effects and not conn.sql


def test_configured_group_roots_are_pinned_and_cycles_terminate():
    cfg, families = complete_families(groups=[f"privileged:{SID}-130001"])
    importer.prepare_ad_cycle(cycle(cfg), families)
    group = families["ad_privileged_membership"]
    group["scope"]["privileged_group_sids"] = [f"{SID}-130002"]
    with pytest.raises(ValueError, match="agent_ad_group_scope_mismatch"):
        importer.prepare_ad_cycle(cycle(cfg), families)


@pytest.mark.parametrize("fail", ["computers", "projection", "partial"])
def test_publication_pending_releases_transport_quota_and_keeps_previous(tmp_path, monkeypatch, fail):
    cfg, families = complete_families()
    if fail == "partial":
        families["ad_context_base"]["sections"][0]["status"] = "partial"
    current, rows, identity = signed_cycle(tmp_path, cfg, families)
    conn = Connection(current, rows)
    conn.effects = [("previous", "retained")]
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a, **kw: None)
    fake_publication(monkeypatch, conn, families, fail=fail)
    result = snapshot_consumer.consume_snapshot_cycles(conn)
    assert result["completed"] == 1
    assert result["pending_reasons"]
    assert conn.effects == [("previous", "retained"), ("transport_complete", (current["cycle_id"],))]
    assert conn.manifest is None
    assert not any("publication_state='published'" in sql for sql, _ in conn.sql)


def test_empty_users_readback_preserves_zero_count():
    from scripts.runtime.users_report_v2_snapshot_worker import CONTRACT_ID, persist_users_v2_snapshot
    class FakeCursor:
        def __init__(self):
            self.params = None
            self.insert = True
        def execute(self, sql, params):
            self.insert = sql.lstrip().startswith("insert")
            if self.insert:
                self.params = params
        def fetchone(self):
            return {"snapshot_id": 1} if self.insert else {"user_count": 0, "payload_sha256": self.params[-1]}
    cur = FakeCursor()
    conn = type("FakeConnection", (), {"cursor": lambda self: nullcontext(cur)})()
    result = persist_users_v2_snapshot(conn, snapshot={"metadata": {"contract_id": CONTRACT_ID,
        "collection_status": "complete", "observed_at": NOW.isoformat()}, "users": []}, domain_id=7, captured_at=NOW)
    assert result["status"] == "captured" and result["user_count"] == 0


def test_computer_persistence_admits_agent_hash_and_preserves_legacy_default(monkeypatch):
    from server.sli.plugins.ad.snapshots import computers_persistence as worker
    _, families = complete_families()
    class FakeCursor:
        def execute(self, sql, params):
            self.insert = sql.lstrip().startswith("insert")
            if self.insert:
                self.params = params
        def fetchone(self):
            return {"source_snapshot_id": 1} if self.insert else {"object_count": self.params[12],
                "payload_sha256": self.params[15], "snapshot_uuid": self.params[1]}
    cur = FakeCursor()
    conn = type("FakeConnection", (), {"cursor": lambda self: nullcontext(cur)})()
    monkeypatch.setattr(worker, "_domain_id", lambda connection, domain: 7)
    kwargs = {"snapshot": families["computers_v6"], "captured_at": NOW, "capture_options": {}, "collector_exit_code": 0}
    assert worker.persist_computers_v6_source_snapshot(conn, **kwargs)["status"] == "captured"
    assert cur.params[9] == worker.APPROVED_REFERENCE_SHA256_BYTES
    agent_hash = hashlib.sha256(b"sli-agent/ad-snapshot/1").digest()
    worker.persist_computers_v6_source_snapshot(conn, **kwargs, collector_sha256=agent_hash)
    assert cur.params[9] == agent_hash
    with pytest.raises(ValueError, match="computers_v6_collector_sha256_invalid"):
        worker.persist_computers_v6_source_snapshot(conn, **kwargs, collector_sha256=b"short")
