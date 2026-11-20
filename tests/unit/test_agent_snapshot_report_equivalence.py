"""PR 4: legacy import-contract readers versus signed agent publication.

Synthetic capture contracts replace PowerShell/LDAP and SQL rows replace DB
access. This proves report assembly and transport parity, not installed capture.
"""
from __future__ import annotations

import base64
import json
from copy import deepcopy
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
from server.ad_context.contracts import validate_bundle
from server.ad_context.repository import _store_gpo_v2_snapshot
from server.ad_context.snapshot_manifest import ALLOWED_FAMILY_CONTRACTS, V2_CONTRACT_VERSION
from server.sli.agents import ad_snapshot_import, snapshot_consumer
from server.sli.entities import users_v2_directory_projection as directory_projection
from server.sli.reports import active_directory_reporting as infrastructure
from server.sli.reports import computers_v6_reporting as computers
from server.sli.reports import gpo_v2_reporting as gpo
from server.sli.reports import users_v2_reporting as users
from server.sli.reports.users_reporting import normalize_ou_path
from sli_agent.ad_snapshot import normalize_capture
from sli_agent.envelope import canonical, digest, make_packet
from sli_agent.gpo_snapshot import normalize_capture as normalize_gpo
from sli_agent.snapshot_stream import SnapshotStream
from sli_agent.spool import Spool
from test_agent_ad_snapshot import NOW, SID, config, directory, obj
from test_agent_ad_snapshot_import import Connection, fake_publication
from test_agent_gpo_snapshot import capture, config as gpo_config
from test_agent_gpo_snapshot_import import Connection as GpoConnection
from test_agent_gpo_snapshot_import import fake_import
from test_agent_snapshot_stream import AGENT, Ledger


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz else NOW.replace(tzinfo=None)


@pytest.fixture
def catalog():
    raw = directory(2100)
    raw["objects"] += [
        obj(11000 + index, "ad_computer", dnshostname=f"host-{index}.invalid",
            operatingsystem="Windows Server", useraccountcontrol=514 if index % 2 else 512)
        for index in range(12)
    ]
    raw["objects"].append(obj(50001, "domain", name="directory.invalid", minpwdlength=14, lockoutthreshold=5))
    raw["objects"][0]["properties"].update({
        "unicodepwd": "synthetic-secret-marker", "ms-mcs-admpwd": "synthetic-secret-marker",
        "msds-managedpassword": "synthetic-secret-marker",
        "accountexpires": 134041392000000000, "department": "Synthetic department",
    })
    raw["health"] = [{"properties": obj(10001, "ad_computer", dnshostname="dc-a.invalid")["properties"],
                      "metadata": {"site_name": "synthetic-site"},
                      "checks": {"connectivity_state": "failed", "sysvol_state": "unavailable"}}]
    raw["gpo_capture"] = capture()
    cfg = config(expensive_flags={})
    families = {name: value for name, (value, _) in normalize_capture(raw, cfg, observed_at=NOW).items()}
    return raw, cfg, families


class ContractRows:
    """Independent SQL-result adapter; never uses agent exact-input builders."""
    def __init__(self, bundles):
        self.bundles = bundles
        self.records = [r for b in bundles.values() for r in b["records"]]
        guids = sorted({r["identity"]["object_guid"] for r in self.records if r["record_type"] == "entity"})
        self.ids = {guid: index + 1 for index, guid in enumerate(guids)}
        self.by_key = {r["record_key"]: r for r in self.records if r["record_type"] == "entity"}

    def entity(self, r):
        return {"entity_id": self.ids[r["identity"]["object_guid"]], "domain_id": 7,
                "entity_type": r["identity"]["kind"], "natural_key": r["record_key"],
                "display_name": r["attributes"].get("display_name"), "source_section": r["section"],
                "identity": r["identity"],
                "observed_at_utc": r["observed_at_utc"], "last_observed_at_utc": r["observed_at_utc"],
                "attributes": {"identity": r["identity"], "attributes": r["attributes"]},
                "attributes_json": {"identity": r["identity"], "attributes": r["attributes"]}}

    def query(self, sql, params=(), **kwargs):
        entities = [r for r in self.records if r["record_type"] == "entity"]
        if "computers_v6_source_domains" in sql:
            assert params == ([7], [7])
            return [{"id": 7, "fqdn": "directory.invalid"}]
        if "users_v2_latest_source_sections" in sql or "active_directory_report_coverage" in sql:
            result = [{"domain_id": 7, "domain_name": "directory.invalid", "run_status": "completed",
                     "section_name": s["name"], "status": s["status"], "section_status": s["status"],
                     "record_count": s["record_count"], "error_code": s["error_code"],
                     "observed_at_utc": b["observed_at_utc"], "source_pack_version": b["source_pack_version"],
                     "run_id": b["run_id"]}
                    for b in self.bundles.values() for s in b["sections"]
                    if s["name"] in (infrastructure.ALLOWED_SECTIONS if "active_directory" in sql
                                     else directory_projection.SOURCE_SECTIONS)]
            if "active_directory" in sql:
                selected = {"domain_id", "domain_name", "run_status", "section_name", "section_status",
                            "record_count", "observed_at_utc"}
                return [{key: value for key, value in row.items() if key in selected} for row in result]
            return result
        if "users_v2_current_source_versions" in sql:
            return [{**self.entity(r), "source_run_id": b["run_id"]}
                    for b in self.bundles.values() for r in b["records"]
                    if r["record_type"] == "entity" and r["section"] in params[0]
                    and self.ids[r["identity"]["object_guid"]] in params[1]]
        if "users_v2_stable_aliases" in sql:
            aliases = {}
            for r in entities:
                eid = self.ids[r["identity"]["object_guid"]]
                for name, value in {"object_guid": r["identity"]["object_guid"],
                                    "object_sid": r["identity"].get("object_sid"),
                                    "distinguished_name": r["attributes"].get("distinguished_name"),
                                    "sam_account_name": r["attributes"].get("sam_account_name")}.items():
                    if value is not None:
                        aliases[(eid, name)] = value
            return [{"entity_id": eid, "alias_type": name, "alias_value": value}
                    for (eid, name), value in sorted(aliases.items()) if eid in params[0]]
        if "users_v2_group_graph_relations" in sql:
            result = []
            for r in self.records:
                if r["record_type"] != "relation" or r["section"] != "directory_group_graph":
                    continue
                source, target = (self.by_key[r[key]] for key in ("source_record_key", "target_record_key"))
                result.append({"domain_id": 7, "source_entity_id": self.ids[source["identity"]["object_guid"]],
                               "target_entity_id": self.ids[target["identity"]["object_guid"]],
                               "source_kind": source["identity"]["kind"], "target_kind": target["identity"]["kind"],
                               "attributes_json": r["attributes"], "last_observed_at_utc": r["observed_at_utc"]})
            return result
        if "users_v2_group_graph_entities" in sql:
            return [self.entity(r) for r in entities if r["section"] == "directory_group_graph"
                    and r["identity"]["kind"] == "ad_group"]
        if "users_v2_complete_get_aduser_population" in sql:
            return [self.entity(r) for r in entities if r["section"] == "directory_accounts"
                    and r["identity"]["kind"] == "ad_user"]
        if "computers_v6_accounts" in sql:
            return [self.entity(r) for r in entities if r["section"] == "directory_accounts"
                    and r["identity"]["kind"] == "ad_computer"]
        if "active_directory_report_entities" in sql:
            return [self.entity(r) for r in entities if r["section"] in infrastructure.ALLOWED_SECTIONS]
        if "active_directory_report_semantic" in sql:
            return []
        raise AssertionError("unexpected synthetic reader query")


def legacy_bundles(families):
    result = {}
    for index, (name, data) in enumerate(families.items(), start=1):
        if name == "computers_v6":
            continue
        bundle = deepcopy(data)
        bundle["run_id"] = str(UUID(int=900000 + index))
        bundle.pop("bundle_sha256", None)
        result[name] = validate_bundle(bundle)
    return result


def bind_readers(monkeypatch, rows):
    for module in (directory_projection, users, computers, infrastructure):
        monkeypatch.setattr(module, "query_rows_bounded", rows.query)
    monkeypatch.setattr(infrastructure, "datetime", FrozenDatetime)
    monkeypatch.setattr(computers, "datetime", FrozenDatetime)
    def accounts(**kwargs):
        items = []
        for r in rows.records:
            if r["record_type"] != "entity" or r["section"] != "directory_accounts" or r["identity"]["kind"] != "ad_user":
                continue
            a = r["attributes"]
            if (kwargs["view"] == "active") != (a.get("enabled") is True):
                continue
            items.append({"entity_id": rows.ids[r["identity"]["object_guid"]], "domain_id": 7,
                          "natural_key": r["record_key"], "display_name": a.get("display_name"),
                          "ou_path": normalize_ou_path(a.get("distinguished_name")),
                          "created_utc": a.get("created_utc"), "email": a.get("email"),
                          "direct_privileges": [], **{key: a.get(key) for key in (
                              "enabled", "locked_out", "account_expiration_utc", "department", "title",
                              "password_last_set_utc", "password_never_expires", "last_logon_utc")}})
        return {"items": items, "state": "ready", "limitations": [],
                "coverage": {"domains": [{"domain_id": 7, "domain_name": "directory.invalid"}],
                             "latest_observed_at_utc": NOW.isoformat().replace("+00:00", "Z")}}
    monkeypatch.setattr(users, "get_users_report", accounts)


def signed_transport(tmp_path, module, cfg, families):
    """Lose the first ACK, restart both disk readers and replay real contracts."""
    stream = SnapshotStream(tmp_path / "capture", module)
    stream.freeze(stream.begin(cfg, now=NOW), families)
    frozen = json.loads((stream.root / "cycle.json").read_bytes())
    for family in frozen["families"].values():
        assert b"synthetic-secret-marker" not in base64.b64decode(family["data_b64"])
    key = ec.generate_private_key(ec.SECP256R1())
    spool_options = {"max_bytes": 32 * 1024**2, "max_age_seconds": 86400}
    spool = Spool(tmp_path / "spool", **spool_options)
    ledger = Ledger(cfg, module=module)
    first = spool.capture(key, agent_id=AGENT, sample=stream.next_sample(None), now=NOW)
    receipt = ledger.receive(first, key)
    assert receipt["status"] == "committed"
    spool = Spool(tmp_path / "spool", **spool_options)
    stream = SnapshotStream(tmp_path / "capture", module)
    assert spool.pending() == [first]
    assert stream.begin({**cfg, "policy_revision": "2"}, now=NOW)["policy"] == cfg
    replay = ledger.receive(spool.pending()[0], key)
    assert replay == {**receipt, "status": "duplicate"}
    assert spool.acknowledge(first, replay)
    assert len(ledger.rows) == 1
    # A correctly signed conflicting replay must not replace durable bytes.
    sample = stream.next_sample(None)
    sample = replace(sample, payload={**sample.payload, "family_sha256": "0" * 64})
    conflict = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    assert ledger.receive(conflict, key)["status"] == "rejected"
    assert len(ledger.rows) == 1 and ledger.rows[0]["payload"] == first["payload"]
    while (sample := stream.next_sample(spool.captured(module))) is not None:
        packet = spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)
        receipt = ledger.receive(packet, key)
        assert receipt["status"] == "committed"
        assert spool.acknowledge(packet, receipt)
    assert not spool.pending()
    cycle = next(iter(ledger.cycles.values()))
    cycle["domain_sid"] = SID
    assert snapshot_consumer.validate_cycle(cycle, ledger.rows)
    return cycle, ledger.rows, ledger.identity


def computer_report(monkeypatch, rows, snapshot, **filters):
    bind_readers(monkeypatch, rows)
    stored = {"source_snapshot_id": 1, "domain_id": 7, "base_inventory_status": "observed",
              "collection_status": snapshot["metadata"]["collection_status"],
              "object_count": len(snapshot["objects"]), "snapshot": snapshot}
    monkeypatch.setattr(computers, "connect", lambda: SimpleNamespace(close=lambda: None))
    def load_source(_connection, *, domain_fqdn):
        assert domain_fqdn == "directory.invalid"
        return stored
    monkeypatch.setattr(computers, "load_latest_computers_v6_source_snapshot", load_source)
    monkeypatch.setattr(computers, "_coverage", lambda _: {"state": "complete"})
    monkeypatch.setattr(computers, "_semantic_rows", lambda _: [])
    monkeypatch.setattr(computers, "_load_snapshot_comparison", lambda _: {"state": "not_collected", "items": []})
    return computers.get_computers_v6_report(domain_ids=[7], limit=200, **filters)


def legacy_publication(monkeypatch, bundles, snapshot, cfg):
    """Run the retained coordinator with bounded synthetic acquisition adapters."""
    rows = ContractRows(bundles)
    bind_readers(monkeypatch, rows)
    saved = {}
    slot = coordinator.latest_due_scheduled_slot(NOW)
    def descriptor(family, source_id, data):
        return {"family": family, "contract_id": ALLOWED_FAMILY_CONTRACTS[family],
                "source_id": source_id, "source_state": "complete", "reason_code": None,
                "observed_at_utc": NOW.isoformat().replace("+00:00", "Z"), "payload_sha256": digest(data)}
    def acquire(family):
        result = {"bundle": deepcopy(bundles[family])}
        if family == "ad_context_base":
            result.update(base_complete=True, acquisition={"profile": coordinator.BASE_PROFILE,
                          "user_full_queries": 1, "computer_full_queries": 1},
                          computer_rows=coordinator._computer_rows(bundles[family]))
        return result
    def imported(bundle, family):
        saved[family] = validate_bundle(bundle)
        return descriptor(family, bundle["run_id"], bundle)
    def persist_users(bundle):
        assert bundle["run_id"] == saved["ad_context_base"]["run_id"]
        saved["users_v2"] = users.build_users_v2_snapshot(domain_ids=[7])
        return descriptor("users_v2", "910001", saved["users_v2"])
    def persist_computers(base_rows):
        assert len(base_rows) == len(snapshot["objects"])
        saved["computers_v6"] = deepcopy(snapshot)
        return descriptor("computers_v6", snapshot["metadata"]["snapshot_id"], snapshot)
    def publish(manifest):
        saved["manifest"] = manifest
        return {"manifest_id": manifest["manifest_id"], "readback_verified": True}
    result = coordinator.run_one_shot(
        slot_start_utc=slot.slot_start_utc, domain={"id": 7, "sid": SID, "dns": cfg["domain_dns"]},
        execute=True, acquire_ad_family=acquire, import_ad_family=imported,
        persist_users=persist_users, persist_computers=persist_computers, publish=publish,
        import_gpo=lambda _: pytest.fail("GPO is a separate frozen agent cycle"), gpo_enabled=False,
        assembled_at_utc=NOW.isoformat().replace("+00:00", "Z"), contract_version=V2_CONTRACT_VERSION,
        schedule_timezone=slot.schedule_timezone, scheduled_local_at=slot.scheduled_local_at,
    )
    assert result["status"] == "published"
    assert set(saved) == set(bundles) | {"users_v2", "computers_v6", "manifest"}
    return saved


def test_large_catalog_reports_match_legacy_readers_after_signed_publication(tmp_path, monkeypatch, catalog):
    _, cfg, families = catalog
    legacy = legacy_bundles(families)
    rows = ContractRows(legacy)
    old_publication = legacy_publication(monkeypatch, legacy, families["computers_v6"], cfg)
    old_users = old_publication["users_v2"]
    frozen = {name: (data, len(data.get("records", data.get("objects", [])))) for name, data in families.items()}
    current, chunks, identity = signed_transport(tmp_path, "sli.ad-snapshot", cfg, frozen)
    assert len(chunks) > len(families)  # Real multi-part family, not one packet per fixture.
    conn = Connection(current, chunks)
    fake_publication(monkeypatch, conn, families)
    imported = {}
    def store(connection, bundle):
        assert connection is conn and conn.tx >= 1
        imported[next(name for name, data in families.items() if data.get("run_id") == bundle["run_id"])] = deepcopy(bundle)
        conn.effects.append(("import", bundle["run_id"]))
    monkeypatch.setattr(ad_snapshot_import, "import_bundle", store)
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a, **kw: None)
    assert snapshot_consumer.consume_snapshot_cycles(conn)["pending_reasons"] == {}
    assert conn.effects[-1][0] == "cycle_published"
    new_users = next(value for kind, value in conn.effects if kind == "users")
    assert old_users == new_users
    assert old_publication["manifest"]["manifest_id"] != conn.manifest["manifest_id"]
    old_sources = {m["family"]: m for m in old_publication["manifest"]["members"]}
    new_sources = {m["family"]: m for m in conn.manifest["members"]}
    assert set(old_sources) == set(new_sources) == set(cfg["families"]) | {"users_v2"}
    for name in legacy:
        assert old_sources[name]["source_id"] == legacy[name]["run_id"]
        assert new_sources[name]["source_id"] == families[name]["run_id"]
    assert len(new_users["users"]) == 2100
    direct = [r for r in imported["ad_context_base"]["records"] if r["record_type"] == "relation"
              and r["target_record_key"].endswith(str(UUID(int=30001)))
              and r["attributes"]["membership_type"] == "direct"]
    assert len(direct) > 1500
    assert all(u["memberships"]["primary"] is not None for u in new_users["users"])
    assert any(u["memberships"]["unresolved"] for u in new_users["users"])
    assert set(imported) == set(legacy)
    for name, bundle in imported.items():
        assert bundle["run_id"] != legacy[name]["run_id"]
        assert bundle["domain"] == legacy[name]["domain"]
        assert bundle["observed_at_utc"] == legacy[name]["observed_at_utc"]
        assert bundle["records"] == legacy[name]["records"]
    assert all(c["envelope"]["source_instance_id"] == cfg["source_instance_id"] for c in chunks)
    assert all(c["envelope"]["agent_id"] == current["agent_id"] for c in chunks)
    assert b"synthetic-secret-marker" not in canonical(chunks)

    new_rows = ContractRows(imported)
    saved_computers = next(value for kind, value in conn.effects if kind == "computers")
    for filters in ({"view": "all"}, {"view": "all", "enabled": "disabled"}, {"view": "data_quality"},
                    {"view": "all", "q": "host-1"}):
        old = computer_report(monkeypatch, rows, old_publication["computers_v6"], **filters)
        new = computer_report(monkeypatch, new_rows, saved_computers, **filters)
        assert old == new
        assert computers.render_computers_v6_csv(old) == computers.render_computers_v6_csv(new)
    assert len(computer_report(monkeypatch, new_rows, saved_computers, view="all")["items"]) == 13
    assert len(computer_report(monkeypatch, new_rows, saved_computers, view="all", enabled="disabled")["items"]) == 6
    for view in ("overview", "domain_controllers", "policies", "risks", "dns"):
        bind_readers(monkeypatch, rows)
        old = infrastructure.get_active_directory_report(domain_ids=[7], view=view)
        bind_readers(monkeypatch, new_rows)
        new = infrastructure.get_active_directory_report(domain_ids=[7], view=view)
        assert old == new
        assert infrastructure.render_active_directory_report_csv(old) == infrastructure.render_active_directory_report_csv(new)
    assert new["summary"]["domain_controller_count"] == 1
    assert new["summary"]["domain_controllers_with_failures"] == 1


@pytest.mark.parametrize("source_failure", [False, True])
def test_gpo_rows_changes_filters_and_storage_match_after_signed_publication(tmp_path, monkeypatch, catalog, source_failure):
    cfg, raw = gpo_config(), deepcopy(catalog[0]["gpo_capture"])
    raw["snapshot"]["gpos"][0]["computer"]["enabled"] = False
    raw["snapshot"]["settings"][0].update(setting_name="cpassword", value_display="synthetic-secret-marker")
    raw["records"][0]["attributes"]["gpo_settings"][0]["properties"]["cpassword"] = "synthetic-secret-marker"
    if source_failure:
        raw["snapshot"]["collection_status"] = "partial"
        raw["snapshot"]["source_states"]["sysvol_gpt"]["status"] = "access_denied"
        raw["snapshot"]["gpos"][0]["gpt"]["status"] = "access_denied"
    families = normalize_gpo(raw, cfg)
    current, chunks, identity = signed_transport(tmp_path, "sli.gpo-snapshot", cfg, families)
    conn = GpoConnection(current, chunks)
    fake_import(monkeypatch, conn)
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a, **kw: None)
    assert snapshot_consumer.consume_snapshot_cycles(conn)["pending_reasons"] == {}
    agent_bundle = next(value for kind, value in conn.effects if kind == "import")
    # Legacy receives the same sanitized capture contract at the import boundary.
    old_bundle = deepcopy(families["ad_gpo_governance"][0])
    old_bundle["run_id"] = str(UUID(int=900099))
    old_bundle["gpo_v2_snapshot"] = deepcopy(families["gpo_v2"][0])
    old_bundle = validate_bundle(old_bundle)
    assert old_bundle["run_id"] != agent_bundle["run_id"]
    assert agent_bundle["mode"] == ("targeted" if source_failure else "full")
    class Storage:
        def execute(self, sql, params):
            assert "insert into gpo_report_v2_source_snapshots" in sql
            self.payload, self.sha = json.loads(params[-2]), params[-1]
    old_store, new_store = Storage(), Storage()
    _store_gpo_v2_snapshot(old_store, domain_id=7, run_id=old_bundle["run_id"], snapshot=old_bundle["gpo_v2_snapshot"])
    _store_gpo_v2_snapshot(new_store, domain_id=7, run_id=agent_bundle["run_id"], snapshot=agent_bundle["gpo_v2_snapshot"])
    assert old_store.sha == new_store.sha
    assert new_store.payload["gpos"][0]["computer"]["enabled"] is False
    if source_failure:
        assert new_store.payload["source_states"]["sysvol_gpt"]["status"] == "access_denied"
    previous = deepcopy(old_store.payload)
    previous["gpos"][0]["computer"]["enabled"] = True
    previous["gpos"][0]["display_name"] = "Previous synthetic policy"
    old = gpo.build_gpo_v2_payload({"current": old_store.payload, "previous": previous})
    new = gpo.build_gpo_v2_payload({"current": new_store.payload, "previous": previous})
    assert old == new
    assert new["comparison"]["items"]
    for view in ("all", "attention", "unverified", "linked", "settings", "permissions", "quality"):
        for query in ("", "synthetic"):
            assert gpo.filter_snapshot_view(old_store.payload, view, query=query) == gpo.filter_snapshot_view(new_store.payload, view, query=query)
    assert b"synthetic-secret-marker" not in canonical(chunks)
    assert b"synthetic-secret-marker" not in canonical(new)
    assert new_store.payload["privacy"] == {"masked": True, "raw_content_collected": False}


@pytest.mark.parametrize("failure", ["chunk", "conflict", "accounts", "exact_logon"])
def test_incomplete_large_cycle_keeps_previous_report_rows(tmp_path, monkeypatch, catalog, failure):
    raw, cfg, families = catalog
    if failure == "accounts":
        families["ad_context_base"]["sections"][0]["status"] = "partial"
    elif failure == "exact_logon":
        cfg = config()
        families = {name: value for name, (value, _) in normalize_capture(raw, cfg, observed_at=NOW).items()}
    frozen = {name: (data, len(data.get("records", data.get("objects", [])))) for name, data in families.items()}
    current, chunks, identity = signed_transport(tmp_path, "sli.ad-snapshot", cfg, frozen)
    if failure == "chunk":
        chunks = chunks[:-1]
    elif failure == "conflict":
        chunks[0]["payload"]["family_sha256"] = "0" * 64
        chunks[0]["envelope"]["payload_sha256"] = digest(chunks[0]["payload"])
        chunks[0]["envelope_sha256"] = digest(chunks[0]["envelope"])
    conn = Connection(current, chunks)
    previous = deepcopy(families)
    conn.effects = [("previous", previous)]
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **kw: identity)
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda *a, **kw: None)
    def forbidden(*args, **kwargs):
        pytest.fail("incomplete cycle must not import or reconcile")
    monkeypatch.setattr(ad_snapshot_import, "import_bundle", forbidden)
    result = snapshot_consumer.consume_snapshot_cycles(conn)
    assert [value for kind, value in conn.effects if kind == "previous"] == [previous]
    assert not any(kind in {"import", "users", "computers", "manifest", "cycle_published"} for kind, _ in conn.effects)
    assert conn.manifest is None
    transport_complete = failure in {"accounts", "exact_logon"}
    assert [kind for kind, _ in conn.effects] == ["previous"] + (["transport_complete"] if transport_complete else [])
    assert not any("publication_state='published'" in sql for sql, _ in conn.sql)
    assert result == {"completed": int(transport_complete), "scanned": 1, "pending_reasons": {
        "chunk": {},
        "conflict": {"agent_snapshot_cycle_invalid": 1},
        "accounts": {"agent_ad_base_incomplete": 1},
        "exact_logon": {"agent_ad_exact_logon_incomplete": 1},
    }[failure]}
