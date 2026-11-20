"""Local audit and inventory with fakes only: no Windows and no database."""
import json
import ntpath
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from sli_agent.control import collection_policy
from sli_agent.envelope import canonical
from sli_agent.file_audit import FileAuditManager, desired_aces, digest
from sli_agent.file_audit_policy import audit_requirements
from sli_agent.policies import apply_policy
from sli_agent.windows_audit import AuditManager, KNOWN_GUIDS, SUBCATEGORIES

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
ROOT = r"C:\synthetic"


def settings():
    return {"roots": [{"collection_scope_id": "scope:one", "share_name": "synthetic", "path": ROOT,
                       "important": False, "sacl": {"trustee_sids": ["S-1-1-0"],
                       "inherit_files": True, "inherit_directories": True}}]}


def command(action="check", *, key=None, config=None):
    return {"config": config or settings(), "command": {"contract_id": "sli.file-audit.audit-command.v1",
            "command_id": key or "synthetic-" + action, "action": action, "policy_revision": "1",
            "collection_scope_ids": ["scope:one"]}}


class AuditAPI:
    def __init__(self, root):
        self.root, self.actual, self.writes = root, dict.fromkeys(KNOWN_GUIDS, 0), []
        self.owner, self.system = "ok", True

    def query(self, guids):
        return {guid: self.actual[guid] for guid in guids}

    def ownership(self):
        return self.owner

    def is_system(self):
        return self.system

    def command_line(self):
        return None

    def set(self, changes):
        state = json.loads((self.root / "state.json").read_bytes())
        assert set(changes) <= set(state["subcategories"])
        self.actual.update(changes)
        self.writes.append(dict(changes))


class Object:
    def __init__(self, api, path, *, directory=False, protected=False, existing=()):
        self.api, self.path = api, path
        self.row = {"object_id": "synthetic-object:" + str(len(api.objects)),
                    "object_type": "directory" if directory else "file", "owner_sid": "S-1-5-18",
                    "dacl": "D:(A;;FA;;;SY)", "sacl": canonical(list(existing)).decode(), "sacl_protected": protected}

    def describe(self):
        return deepcopy(self.row)

    def plan(self, aces):
        rows = json.loads(self.row["sacl"])
        for ace in aces:
            if ace not in rows:
                rows.append(ace)
        return canonical(rows).decode()

    def set_sacl(self, value):
        saved = json.loads((self.api.root / "state.json").read_bytes())["objects"][self.path]
        assert saved["phase"] in ("pending", "restoring")
        self.api.writes.append((self.path, value))
        if self.api.fail == self.path:
            self.api.fail = None
            raise OSError("synthetic-private-diagnostic")
        if not self.api.ignore_write:
            self.row["sacl"] = value

    def children(self):
        for path in self.api.objects:
            if path != self.path and path.rsplit("\\", 1)[0] == self.path:
                yield path.rsplit("\\", 1)[1]

    def inherited_from(self, previous, applied):
        before = json.loads(previous)
        added = [ace for ace in json.loads(applied) if ace not in before]
        return any(ace["flags"] & 0x10 and any(ace["mask"] == source["mask"] and ace["sid"] == source["sid"]
                   and ace["flags"] & 0xc0 == source["flags"] & 0xc0 for source in added)
                   for ace in json.loads(self.row["sacl"]))


class FileAPI:
    def __init__(self, root):
        self.root, self.objects, self.writes = root, {}, []
        self.owner, self.fail, self.ignore_write = "ok", None, False
        self.objects[ROOT] = Object(self, ROOT, directory=True)
        self.objects[ROOT + r"\item"] = Object(self, ROOT + r"\item")
        self.reparse = set()

    def preflight(self, roots=()):
        return self.owner

    @contextmanager
    def open(self, path, root):
        if path in self.reparse:
            raise ValueError("file_audit_reparse_point")
        key = next(key for key in self.objects if ntpath.normcase(key) == ntpath.normcase(path))
        yield self.objects[key]

    def share(self, name, path):
        return {"name": name, "path": path, "dacl": "D:(A;;FA;;;SY)", "complete": True}

    def local_groups(self, limit):
        return {"complete": True, "groups": [{"group_sid": "S-1-5-32-544", "member_sids": ["S-1-5-18"]}]}


def setup(tmp_path):
    audit_api = AuditAPI(tmp_path / "audit")
    shared = AuditManager(audit_api.root, api=audit_api)
    file_api = FileAPI(tmp_path / "file")
    return FileAuditManager(file_api.root, shared, api=file_api), file_api, audit_api


def execute(manager, value, *, manage=True, assignments=()):
    return manager.reconcile(assignments, collection_policy({"manage_windows_audit": manage}), 1, value, now=NOW)


def test_successful_reads_require_important_root_but_failures_include_reads():
    root = settings()["roots"][0]
    normal = desired_aces(root)
    assert not normal[0]["mask"] & 1 and normal[1]["mask"] & 1
    root["important"] = True
    assert all(row["mask"] & 1 for row in desired_aces(root))
    assert normal[0]["flags"] == 0x43 and normal[1]["flags"] == 0x83


def test_default_check_collects_acl_and_sid_inventory_without_windows_writes(tmp_path):
    manager, api, audit = setup(tmp_path)
    _, result = execute(manager, command(), manage=False)
    assert not api.writes and not audit.writes
    assert result["scopes"][0]["state"] == "partial"
    assert result["scopes"][0]["reason_code"] == "policy_missing" or result["scopes"][0]["reason_code"] == "sacl_missing"
    snapshot = result["snapshots"][0]
    assert snapshot["completeness"] == "complete" and len(snapshot["objects"]) == 2
    assert snapshot["local_groups"]["groups"][0]["member_sids"] == ["S-1-5-18"]
    assert result["ownership_remaining"] is False
    assert snapshot["snapshot_sha256"] == digest({key: value for key, value in snapshot.items() if key not in ("snapshot_sha256", "snapshot_id")})


def test_apply_journals_before_each_write_restart_repeat_and_explicit_restore(tmp_path):
    manager, api, audit = setup(tmp_path)
    before = {path: obj.describe() for path, obj in api.objects.items()}
    _, result = execute(manager, command("apply"))
    assert result["scopes"][0]["state"] == "verified" and len(api.writes) == 2
    assert len(audit.writes) == 1
    assert result["ownership_remaining"] is True
    # Lost HTTP receipt and restart preserve the exact result and snapshot ID.
    manager = FileAuditManager(api.root, manager.audit_manager, api=api)
    assert execute(manager, command("apply"))[1] == result
    assert len(api.writes) == 2 and len(audit.writes) == 1
    manager.acknowledge(result)
    assert execute(manager, command("apply"))[1] is None
    # Opt-out and collection shutdown do not restore file audit.
    manager.reconcile([], collection_policy({}), 2, None, now=NOW)
    assert len(api.writes) == 2 and len(audit.writes) == 1
    _, restored = execute(manager, command("restore"))
    assert restored["scopes"][0]["state"] == "verified" and restored["ownership_remaining"] is False
    assert {path: obj.describe() for path, obj in api.objects.items()} == before
    assert all(mask == 0 for mask in audit.actual.values())


def test_agent_apply_enables_file_and_handle_audit_and_inherited_read_write_sacl(tmp_path):
    manager, api, audit = setup(tmp_path)
    config = settings()
    config["roots"][0]["important"] = True
    config["optional_events"] = True
    _, result = execute(manager, command("apply", config=config))
    required = audit_requirements(config)
    assert required["0cce921d-69ae-11d9-bed3-505054503030"] == 3
    assert required["0cce9223-69ae-11d9-bed3-505054503030"] == 1
    scope = result["scopes"][0]
    assert scope["state"] == "verified"
    assert scope["actual_masks"] == scope["required_masks"] == required
    assert audit.writes and api.writes
    for obj in api.objects.values():
        aces = json.loads(obj.row["sacl"])
        assert all(ace["mask"] & 7 == 7 for ace in aces)
        assert all(ace["flags"] & 3 == 3 for ace in aces)


@pytest.mark.parametrize("owner", ["managed_by_gpo", "unknown", "system_required", "global_sacl_present", "global_sacl_unknown"])
def test_unproven_management_never_changes_sacl_or_policy(tmp_path, owner):
    manager, api, audit = setup(tmp_path)
    api.owner = owner
    _, result = execute(manager, command("apply"))
    assert result["scopes"][0]["state"] == "blocked"
    assert not api.writes and not audit.writes
    assert result["ownership_remaining"] is False


def test_gpo_supplied_masks_allow_sacl_without_any_audit_policy_write(tmp_path):
    from sli_agent.file_audit_policy import audit_requirements
    manager, api, audit = setup(tmp_path)
    audit.owner = "managed_by_gpo"
    audit.actual.update(audit_requirements(settings()))
    _, result = execute(manager, command("apply"))
    assert result["scopes"][0]["state"] == "verified"
    assert api.writes and not audit.writes


def test_missing_gpo_mask_blocks_sacl_without_competing_with_policy(tmp_path):
    manager, api, audit = setup(tmp_path)
    audit.owner = "managed_by_gpo"
    _, result = execute(manager, command("apply"))
    assert result["scopes"][0]["state"] == "blocked"
    assert result["scopes"][0]["reason_code"] == "managed_by_gpo"
    assert not api.writes and not audit.writes


@pytest.mark.parametrize("owner", ["managed_by_gpo", "unknown", "system_required", "global_sacl_present", "global_sacl_unknown"])
def test_check_reports_management_blocker_with_read_only_inventory(tmp_path, owner):
    manager, api, audit = setup(tmp_path)
    api.owner = owner
    _, result = execute(manager, command("check"), manage=False)
    assert result["scopes"][0]["state"] == "blocked"
    assert result["scopes"][0]["reason_code"] == owner
    assert len(result["snapshots"][0]["objects"]) == 2
    assert not api.writes and not audit.writes


def test_apply_requires_explicit_management_consent(tmp_path):
    manager, api, audit = setup(tmp_path)
    _, result = execute(manager, command("apply"), manage=False)
    assert result["scopes"][0]["reason_code"] == "management_disabled"
    assert not api.writes and not audit.writes


def test_preexisting_matching_aces_are_preserved_and_never_owned(tmp_path):
    manager, api, audit = setup(tmp_path)
    aces = desired_aces(settings()["roots"][0])
    for obj in api.objects.values():
        obj.row["sacl"] = canonical(aces).decode()
    original = deepcopy(aces)
    _, result = execute(manager, command("apply"))
    assert result["scopes"][0]["state"] == "verified" and not api.writes
    manager.acknowledge(result)
    _, result = execute(manager, command("restore"))
    assert not api.writes and all(json.loads(obj.row["sacl"]) == original for obj in api.objects.values())


def test_partial_failure_is_private_and_pending_intent_resumes_after_restart(tmp_path):
    manager, api, audit = setup(tmp_path)
    api.fail = ROOT + r"\item"
    _, result = execute(manager, command("apply"))
    assert result["scopes"][0]["state"] == "partial"
    assert "synthetic-private" not in json.dumps(result)
    assert manager._load()["objects"][ROOT + r"\item"]["phase"] == "pending"
    manager.acknowledge(result)
    manager = FileAuditManager(api.root, manager.audit_manager, api=api)
    _, retry = execute(manager, command("apply", key="synthetic-retry"))
    assert retry["scopes"][0]["state"] == "verified"
    assert manager._load()["objects"][ROOT + r"\item"]["phase"] == "confirmed"


def test_interrupted_restore_resumes_without_reapplying_audit_aces(tmp_path):
    manager, api, audit = setup(tmp_path)
    _, applied = execute(manager, command("apply"))
    manager.acknowledge(applied)
    original = api.objects[ROOT].set_sacl
    def interrupted(value):
        original(value)
        raise OSError("synthetic-private-diagnostic")
    api.objects[ROOT].set_sacl = interrupted
    _, result = execute(manager, command("restore"))
    assert result["scopes"][0]["state"] == "partial"
    assert manager._load()["objects"][ROOT]["phase"] == "restoring"
    manager.acknowledge(result)
    api.objects[ROOT].set_sacl = original
    writes = len(api.writes)
    manager = FileAuditManager(api.root, manager.audit_manager, api=api)
    _, result = execute(manager, command("restore"))
    assert result["scopes"][0]["state"] == "verified" and result["ownership_remaining"] is False
    assert len(api.writes) == writes


def test_protected_inheritance_and_reparse_objects_are_coverage_gaps(tmp_path):
    manager, api, audit = setup(tmp_path)
    child = ROOT + r"\item"
    api.objects[child].row["sacl_protected"] = True
    _, result = execute(manager, command("apply"))
    assert result["scopes"][0]["state"] == "partial"
    assert all(path != child for path, _ in api.writes)
    manager.acknowledge(result)
    api.reparse.add(child)
    _, result = execute(manager, command("check", key="synthetic-reparse"))
    assert result["snapshots"][0]["unread_objects"] > 0
    assert all(row["path"] != child for row in result["snapshots"][0]["objects"])


@pytest.mark.parametrize("drift", ["sacl", "object_id"])
@pytest.mark.parametrize("path", [ROOT, ROOT + r"\item"])
def test_foreign_change_or_object_replacement_blocks_restore(tmp_path, drift, path):
    manager, api, audit = setup(tmp_path)
    _, result = execute(manager, command("apply"))
    manager.acknowledge(result)
    api.objects[path].row[drift] = "synthetic-foreign-change"
    writes = len(api.writes), len(audit.writes)
    _, result = execute(manager, command("restore"))
    assert result["ownership_remaining"] is True and result["scopes"][0]["state"] == "blocked"
    assert result["scopes"][0]["reason_code"] == "restore_conflict"
    assert manager._load()["objects"][path]["phase"] == "conflict"
    assert (len(api.writes), len(audit.writes)) == writes


def test_readback_failure_is_a_durable_conflict(tmp_path):
    manager, api, audit = setup(tmp_path)
    api.ignore_write = True
    _, result = execute(manager, command("apply"))
    assert result["scopes"][0]["state"] == "partial"
    assert manager._load()["objects"][ROOT]["phase"] == "conflict"
    manager.acknowledge(result)
    writes = len(api.writes)
    _, result = execute(manager, command("apply", key="synthetic-retry"))
    assert len(api.writes) == writes


def test_shared_policy_owner_preserves_workstation_requirements_on_file_restore(tmp_path):
    manager, api, audit = setup(tmp_path)
    modules = [{"module_id": "sli.workstations", "enabled": True, "config": {"families": {
        "logons": True, "processes": False, "local_admins": False, "protection": False, "usb": False}}}]
    _, result = execute(manager, command("apply"), assignments=modules)
    manager.acknowledge(result)
    _, result = execute(manager, command("restore"), assignments=modules)
    assert audit.actual[SUBCATEGORIES["logon"][0]] == 3
    assert audit.actual[SUBCATEGORIES["logoff"][0]] == 1
    assert audit.actual["0cce921d-69ae-11d9-bed3-505054503030"] == 0


def test_per_root_read_policy_and_bounded_snapshot_continuation(tmp_path):
    manager, api, audit = setup(tmp_path)
    config = settings()
    config["max_bytes"] = 1024
    for index in range(8):
        path = ROOT + "\\synthetic-" + str(index)
        api.objects[path] = Object(api, path)
    value = command("apply", config=config)
    seen, scan_ids, pages = set(), set(), []
    for _ in range(20):
        _, result = execute(manager, value)
        if result is None:
            break
        snapshot = result["snapshots"][0]
        seen.update(row["path"] for row in snapshot["objects"])
        scan_ids.add(snapshot["scan_id"])
        pages.append(snapshot["page_number"])
        manager.acknowledge(result)
    assert seen == set(api.objects)
    assert len(scan_ids) == 1 and pages == list(range(len(pages)))
    assert audit.actual["0cce9244-69ae-11d9-bed3-505054503030"] == 2


def test_inventory_is_refreshed_daily_and_command_id_cannot_be_reused(tmp_path):
    manager, api, audit = setup(tmp_path)
    _, result = execute(manager, command("check"))
    manager.acknowledge(result)
    assert execute(manager, command("check"))[1] is None
    _, next_day = manager.reconcile([], collection_policy({}), 1, command("check"), now=NOW + timedelta(days=1))
    assert next_day["snapshots"][0]["snapshot_id"] != result["snapshots"][0]["snapshot_id"]
    manager.acknowledge(next_day)
    with pytest.raises(ValueError, match="file_audit_command_reused"):
        execute(manager, command("apply", key="synthetic-check"))


def test_file_control_is_separate_from_collection_assignment_and_policy_ack(tmp_path):
    manager, api, audit = setup(tmp_path)
    agent = "00000000-0000-4000-8000-000000000001"
    transport = Mock()
    applied = apply_policy(SimpleNamespace(collection_enabled=False), agent,
        {"agent_id": agent, "policy_revision": 1, "assigned_modules": [], "collection_policy": {},
         "file_audit": command("check")}, transport, SimpleNamespace(agent_id=agent), file_audit_manager=manager)
    assert applied.file_audit["action"] == "check"
    assert [module.module_id for module in applied] == ["sli.heartbeat"]
    assert transport.post.call_args.args[0] == "/api/v1/agent/policy-report"
    assert "file_audit" not in transport.post.call_args.args[1]


def test_corrupted_file_journal_blocks_shared_audit_mutation(tmp_path):
    manager, api, audit = setup(tmp_path)
    api.root.mkdir()
    (api.root / "state.json").write_text('{"masks":{"arbitrary":3}}')
    with pytest.raises(ValueError, match="file_audit_state_invalid"):
        execute(manager, command("apply"))
    assert not api.writes and not audit.writes


def test_new_inherited_child_keeps_rollback_material_instead_of_guessing_ownership(tmp_path):
    manager, api, audit = setup(tmp_path)
    _, applied = execute(manager, command("apply"))
    manager.acknowledge(applied)
    path = ROOT + r"\synthetic-new"
    inherited = [{**ace, "flags": ace["flags"] | 0x10} for ace in desired_aces(settings()["roots"][0])]
    api.objects[path] = Object(api, path, existing=inherited)
    writes = len(api.writes)
    _, result = execute(manager, command("restore"))
    assert result["scopes"][0]["state"] == "blocked"
    assert result["scopes"][0]["reason_code"] == "inheritance_untracked"
    assert result["ownership_remaining"] is True and len(api.writes) == writes


def test_absent_request_freezes_owned_audit_and_keeps_pending_inventory_local(tmp_path):
    manager, api, audit = setup(tmp_path)
    _, result = execute(manager, command("apply"))
    writes = len(api.writes), len(audit.writes)
    assert manager.reconcile([], collection_policy({}), 2, None, now=NOW)[1] is None
    assert (len(api.writes), len(audit.writes)) == writes
    assert manager._load()["pending_report"] == result


def test_overlapping_shares_keep_scope_receipts_and_share_one_rollback_journal(tmp_path):
    manager, api, audit = setup(tmp_path)
    config = settings()
    important = deepcopy(config["roots"][0])
    important.update(collection_scope_id="scope:two", share_name="synthetic-two", important=True, path=ROOT.lower())
    config["roots"].append(important)
    value = command("apply", config=config)
    value["command"]["collection_scope_ids"].append("scope:two")
    reports = []
    for _ in range(2):
        _, result = execute(manager, value)
        reports.extend(result["scopes"])
        manager.acknowledge(result)
    assert {row["collection_scope_id"] for row in reports} == {"scope:one", "scope:two"}
    assert all(row["state"] == "verified" for row in reports)
    assert audit.actual["0cce9244-69ae-11d9-bed3-505054503030"] == 3
    assert len(manager._load()["objects"]) == 2
    restore = command("restore", config=config)
    restore["command"]["collection_scope_ids"].append("scope:two")
    _, result = execute(manager, restore)
    assert result["ownership_remaining"] is False
    assert all(obj.row["sacl"] == "[]" for obj in api.objects.values())


def test_five_roots_apply_and_restore_continue_across_agent_restarts(tmp_path):
    manager, api, audit = setup(tmp_path)
    config = settings()
    for index in range(2, 6):
        root = deepcopy(config["roots"][0])
        root.update(collection_scope_id=f"scope:{index}", share_name=f"synthetic-{index}",
                    path=f"C:\\synthetic-{index}", important=index == 2)
        config["roots"].append(root)
        api.objects[root["path"]] = Object(api, root["path"], directory=True)
        child = root["path"] + r"\item"
        api.objects[child] = Object(api, child)
    before = {path: obj.describe() for path, obj in api.objects.items()}
    scopes = [root["collection_scope_id"] for root in config["roots"]]
    for action in ("apply", "restore"):
        value = command(action, config=config)
        value["command"]["collection_scope_ids"] = scopes
        reported = []
        for _ in scopes:
            manager = FileAuditManager(api.root, manager.audit_manager, api=api)
            _, result = execute(manager, value)
            assert len(result["snapshots"]) == 1
            assert result["scopes"][0]["state"] == "verified"
            reported.append(result["scopes"][0]["collection_scope_id"])
            manager.acknowledge(result)
        assert reported == scopes
        assert execute(manager, value)[1] is None
        if action == "apply":
            assert audit.actual["0cce9244-69ae-11d9-bed3-505054503030"] == 3
            for root in config["roots"]:
                aces = json.loads(api.objects[root["path"]].row["sacl"])
                assert bool(aces[0]["mask"] & 1) == root["important"]
    assert {path: obj.describe() for path, obj in api.objects.items()} == before
    assert all(mask == 0 for mask in audit.actual.values())

@pytest.mark.parametrize('foreign,replaced', [(False,False),(True,False),(False,True)])
def test_exact_native_readback_recovers_legacy_conflict_without_rewriting(tmp_path, foreign, replaced):
    manager,api,audit=setup(tmp_path)
    _,result=execute(manager,command('apply'))
    manager.acknowledge(result)
    state=manager._load();path=ROOT+r'\item';saved=state['objects'][path]
    applied=saved['applied'];effective=json.loads(applied)
    for ace in effective:ace['flags'] &= ~3
    actual=canonical(effective).decode()
    saved['phase']='conflict';manager._save(state)
    obj=api.objects[path]
    obj.expected_sacl=lambda value:actual if value==applied else value
    obj.plan=lambda aces:actual
    obj.row['sacl']=actual+' ' if foreign else actual
    if replaced:obj.row['object_id']='synthetic-replacement'
    writes=len(api.writes)
    _,result=execute(manager,command('apply',key='synthetic-native-retry'))
    assert len(api.writes)==writes
    saved=manager._load()['objects'][path]
    if foreign or replaced:
        assert saved['phase']=='conflict' and result['scopes'][0]['state']=='partial'
    else:
        assert saved['phase']=='confirmed' and saved['applied']==actual
        assert result['scopes'][0]['state']=='verified'


def paged_check(tmp_path):
    manager, api, audit = setup(tmp_path)
    config = {**settings(), "max_bytes": 1024}
    audit.actual.update(audit_requirements(config))
    for obj in api.objects.values():
        obj.row["dacl"] += "x" * 400
    api.objects[ROOT + r"\item"].row["sacl"] = canonical(desired_aces(config["roots"][0])).decode()
    return manager, api, audit, command(config=config)


def test_scan_missing_sacl_survives_clean_final_page_and_restart(tmp_path):
    manager, api, audit, value = paged_check(tmp_path)
    _, first = execute(manager, value)
    assert first["snapshots"][0]["has_more"]
    assert first["snapshots"][0]["objects"][0]["sacl_missing"]
    manager.acknowledge(first)
    manager = FileAuditManager(api.root, manager.audit_manager, api=api)
    _, final = execute(manager, value)
    assert not final["snapshots"][0]["has_more"]
    assert not any(row["sacl_missing"] for row in final["snapshots"][0]["objects"])
    assert final["scopes"][0]["state"] == "partial"
    assert final["scopes"][0]["reason_code"] == "sacl_missing"
    assert manager._load()["walks"]["scope:one"]["sacl_missing"] == 1
    assert not api.writes and not audit.writes


def test_new_clean_scan_resets_missing_evidence(tmp_path):
    manager, api, audit, value = paged_check(tmp_path)
    for _ in range(2):
        _, report = execute(manager, value)
        manager.acknowledge(report)
    api.objects[ROOT].row["sacl"] = canonical(desired_aces(settings()["roots"][0])).decode()
    _, first = manager.reconcile([], collection_policy({}), 1, value, now=NOW + timedelta(days=1))
    manager.acknowledge(first)
    _, final = manager.reconcile([], collection_policy({}), 1, value, now=NOW + timedelta(days=1))
    assert final["scopes"][0]["state"] == "verified"
    assert manager._load()["walks"]["scope:one"]["sacl_missing"] == 0
    assert not api.writes and not audit.writes


def test_changed_policy_command_resets_missing_evidence(tmp_path):
    manager, api, audit, value = paged_check(tmp_path)
    _, first = execute(manager, value)
    manager.acknowledge(first)
    config = deepcopy(value["config"])
    config["policy_revision"] = "2"
    config["roots"][0]["important"] = True
    for obj in api.objects.values():
        obj.row["sacl"] = canonical(desired_aces(config["roots"][0])).decode()
    audit.actual.update(audit_requirements(config))
    value = command(key="synthetic-revision-2", config=config)
    value["command"]["policy_revision"] = "2"
    _, first = execute(manager, value)
    assert first["snapshots"][0]["page_number"] == 0
    manager.acknowledge(first)
    _, final = execute(manager, value)
    assert final["scopes"][0]["state"] == "verified"
    assert manager._load()["walks"]["scope:one"]["sacl_missing"] == 0


def test_missing_evidence_is_isolated_between_scopes(tmp_path):
    manager, api, audit, value = paged_check(tmp_path)
    root = deepcopy(value["config"]["roots"][0])
    root.update(collection_scope_id="scope:two", path=r"C:\synthetic-two", share_name="synthetic-two")
    value["config"]["roots"].append(root)
    value["command"]["collection_scope_ids"].append("scope:two")
    api.objects[root["path"]] = Object(api, root["path"], directory=True, existing=desired_aces(root))
    reports = []
    for _ in range(3):
        _, report = execute(manager, value)
        reports.append(report)
        manager.acknowledge(report)
    assert reports[1]["scopes"][0]["state"] == "partial"
    assert reports[2]["scopes"][0]["collection_scope_id"] == "scope:two"
    assert reports[2]["scopes"][0]["state"] == "verified"


def test_requeued_and_oversized_missing_objects_are_not_double_counted(tmp_path):
    manager, api, audit, value = paged_check(tmp_path)
    api.objects[ROOT + r"\item"].row["sacl"] = "[]"
    _, first = execute(manager, value)
    assert first["snapshots"][0]["has_more"]
    assert manager._load()["walks"]["scope:one"]["sacl_missing"] == 1
    manager.acknowledge(first)
    _, final = execute(manager, value)
    assert manager._load()["walks"]["scope:one"]["sacl_missing"] == 2
    manager.acknowledge(final)
    api.objects[ROOT + r"\item"].row["dacl"] += "x" * 2048
    value["command"]["command_id"] = "synthetic-oversized"
    _, first = execute(manager, value)
    manager.acknowledge(first)
    _, final = execute(manager, value)
    walk = manager._load()["walks"]["scope:one"]
    assert walk["sacl_missing"] == 1 and walk["gaps"] > 0
    assert final["scopes"][0]["state"] == "partial"


def test_legacy_walk_without_scan_evidence_never_claims_verified(tmp_path):
    manager, api, audit, value = paged_check(tmp_path)
    _, first = execute(manager, value)
    manager.acknowledge(first)
    state = manager._load()
    state["walks"]["scope:one"].pop("sacl_missing", None)
    manager._save(state)
    manager = FileAuditManager(api.root, manager.audit_manager, api=api)
    _, final = execute(manager, value)
    assert not final["snapshots"][0]["has_more"]
    assert final["scopes"][0]["state"] == "partial"
    assert final["scopes"][0]["reason_code"] == "coverage_incomplete"
