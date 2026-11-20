"""Regenerate synthetic vectors with the unchanged Python snapshot-history reference."""
from copy import deepcopy
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from server.sli.plugins.ad.snapshots import change_history as reference  # noqa: E402


def snapshot(collection, rows):
    return {"metadata": {"collection_status": "complete", "domain": "example.test"}, collection: rows}


vectors = []


def add(name, family, previous, current, error=None):
    vector = {"name": name, "family": family, "previous": previous, "current": current}
    try:
        rows = reference.extract_changes(family, previous, current)
    except (ValueError, TypeError, AttributeError):
        if error is None:
            raise
        vector["error"] = error
    else:
        assert error is None, name
        vector.update(rows=rows, rows_sha256=reference._hash(rows),
                      payloads=[reference._json(row) for row in rows],
                      record_ids=[reference._hash(["synthetic-batch", row]) for row in rows])
    vectors.append(vector)


families = [("users_v2", "users", reference.USER_FIELDS),
            ("computers_v6", "objects", reference.COMPUTER_FIELDS),
            ("gpo_v2", "gpos", reference.GPO_FIELDS["gpos"][1])]
dirty = [None, 7, [None, 1, "Тест", True, "same", "same"], "", False, 1.5, {"excluded": "synthetic"}]
for family, collection, fields in families:
    before, after = {"id": "synthetic-1"}, {"id": "synthetic-1"}
    for i, field in enumerate(sorted(fields)):
        before[field], after[field] = dirty[i % len(dirty)], dirty[(i + 1) % len(dirty)]
    before["unknown"], after["unknown"] = "excluded-before", "excluded-after"
    add(f"{family}:all-allowed-fields", family, snapshot(collection, [before]), snapshot(collection, [after]))
    for identity in [7, True, [1, None, False], {"z": 1, "a": None}, "\U00010000", "\ue000"]:
        old = {"id": identity, "name": None, "display_name": None}
        new = {"id": identity, "name": [1, None, 1], "display_name": [1, None, 1]}
        add(f"{family}:identity:{identity!r}", family, snapshot(collection, [old]), snapshot(collection, [new]))
    add(f"{family}:truthy-identity-fallback", family,
        snapshot(collection, [{"objectGuid": 0, "guid": [], "id": "synthetic-1", "name": 0, "display_name": 0}]),
        snapshot(collection, [{"objectGuid": False, "guid": "", "id": "synthetic-1", "name": 2, "display_name": 2}]))
    for value in [None, False, 0, "", [], {}]:
        add(f"{family}:empty-collection:{value!r}", family, snapshot(collection, value), snapshot(collection, []))
    for value in [None, 7, [], "synthetic"]:
        add(f"{family}:bad-row:{value!r}", family, snapshot(collection, [value]), snapshot(collection, []),
            f"snapshot_history_field_invalid:{collection}")
    for value in [7, True, "synthetic", {"id": "synthetic"}]:
        add(f"{family}:bad-collection:{value!r}", family, snapshot(collection, value), snapshot(collection, []),
            f"snapshot_history_field_invalid:{collection}")
    for value in [None, 0, False, [], {}]:
        old = snapshot(collection, [{"objectGuid": value}])
        add(f"{family}:missing-identity:{value!r}", family, old, {}, "snapshot_history_object_identity_missing")
    for rows in [[{"id": "synthetic"}, {"objectGuid": "synthetic"}], [{"id": 7}, {"id": "7"}]]:
        add(f"{family}:duplicate:{rows!r}", family, snapshot(collection, rows), {},
            "snapshot_history_object_identity_duplicate")
    old = snapshot(collection, [{"id": "synthetic-1", "enabled": True, "display_name": True, "description": [True, 2]}])
    new = snapshot(collection, [{"id": "synthetic-1", "enabled": 1.0, "display_name": 1.0, "description": [1, 2.0]}])
    add(f"{family}:python-number-equality", family, old, new)
    old = snapshot(collection, [{"id": "\U00010000"}, {"id": "\ue000"}])
    new = snapshot(collection, [{"id": "new"}])
    add(f"{family}:unicode-order", family, old, new)
    for field in ["metadata", "source_states"]:
        for value in [None, False, 0, "", [], {}, [1], 7, "synthetic"]:
            old = snapshot(collection, [])
            old["collection_status"] = "complete"
            old[field] = value
            invalid = value in ([1], 7, "synthetic")
            add(f"{family}:{field}:{value!r}", family, old, deepcopy(old),
                f"snapshot_history_field_invalid:{field}" if invalid else None)
    for value in [[], {}, None, 7, True]:
        old = snapshot(collection, [])
        old["metadata"]["collection_status"] = value
        add(f"{family}:collection-status:{value!r}", family, old, deepcopy(old),
            "snapshot_history_field_invalid:collection_status" if isinstance(value, (list, dict)) else None)
    for value in [None, [], 7, "synthetic", {"status": []}, {"status": "partial"}]:
        old = snapshot(collection, [])
        old["source_states"] = {"untrusted-source-name": value}
        add(f"{family}:source-state:{value!r}", family, old, deepcopy(old),
            "snapshot_history_field_invalid:source_states" if not isinstance(value, dict) else None)
    old, new = snapshot(collection, [{"id": "old"}]), snapshot(collection, [{"id": "new"}])
    new["metadata"]["search_base"] = [None, 7]
    add(f"{family}:different-scope", family, old, new)


def users(row):
    return snapshot("users", [{"id": "synthetic-user", **row}])


for value in [None, 7, [], "synthetic", {}, {"id": [1, None], "objectGuid": {"z": 1, "a": None}, "excluded": 1}]:
    add(f"users:manager:{value!r}", "users_v2", users({"manager": {"id": "old"}}), users({"manager": value}))
for field in ["sourceStates", "sourceState", "source_state"]:
    for value in [None, False, 0, "", [], {}, [1], 7, "observed", {"status": "observed"}, {"status": []}]:
        row = {field: value, "name": "new"}
        invalid = bool(value) and not isinstance(value, dict)
        add(f"users:{field}:{value!r}", "users_v2", users({"name": "old"}), users(row),
            f"snapshot_history_field_invalid:{field}" if invalid else None)
for value in [None, 7, [], "synthetic", {}, {"status": None, "state": "partial", "direct": [7, 7, None, False, True, [1, None], {"objectGuid": 0, "id": "fallback"}]}]:
    add(f"users:memberships:{value!r}", "users_v2", users({"memberships": {"direct": ["old"]}}), users({"memberships": value}))
for field in ["primary", "direct"]:
    for value in [None, False, 0, "", [], {}, "a\U00010000a", {"objectGuid": [], "id": 7}, [7, 7, None, False, True, {"id": "synthetic-group"}], 7, True]:
        add(f"users:membership-{field}:{value!r}", "users_v2", users({"memberships": {field: []}}), users({"memberships": {field: value}}),
            f"snapshot_history_field_invalid:{field}" if value is True or type(value) is int and value != 0 else None)
for status in [None, 7, True, [], {}, "partial", "observed", "completed"]:
    add(f"users:membership-status:{status!r}", "users_v2", users({"memberships": {"direct": []}}),
        users({"memberships": {"status": status, "direct": ["synthetic-group"]}}),
        "snapshot_history_field_invalid:memberships" if isinstance(status, (list, dict)) else None)
for value in [[], [None, 7, True, False, [1, None], {"z": 1}, "same", "same"], "a\U00010000a", {"synthetic-group": 1}, None, 0, False]:
    old = snapshot("groups", [{"id": "synthetic-group", "parentGroupIds": ["old"], "name": None}])
    new = snapshot("groups", [{"id": "synthetic-group", "parentGroupIds": value, "name": [1, None]}])
    add(f"groups:parents:{value!r}", "users_v2", old, new,
        "snapshot_history_field_invalid:parentGroupIds" if value is None or type(value) in (int, bool) else None)
for status in ["complete", "partial"]:
    old = users({"name": "same", "sourceStates": {"directory": {}}, "sourceState": {"status": "partial"}, "memberships": {"direct": ["old"]}})
    new = users({"name": "changed", "memberships": {"direct": ["new", "new"]}})
    old["metadata"]["collection_status"] = status
    add(f"users:directory-fallback:{status}", "users_v2", old, new)
    old = users({"memberships": {"status": "observed", "direct": ["old"]}})
    old["metadata"]["collection_status"] = status
    add(f"users:partial-addition:{status}", "users_v2", old, new)
for collection, (_, fields) in reference.GPO_FIELDS.items():
    old = {"id": "synthetic-gpo-item", "gpo_id": 7, **{key: None for key in fields}}
    new = {"id": "synthetic-gpo-item", "gpo_id": 8, **{key: [None, 1, "same", "same"] for key in fields}}
    add(f"gpo:{collection}:all-fields", "gpo_v2", snapshot(collection, [old]), snapshot(collection, [new]))
for side in ["computer", "user"]:
    for value in [None, False, 0, "", [], {}, [1], 7, "synthetic", {"enabled": [1, None], "directory_version": 3, "sysvol_version": None, "excluded": 9}]:
        add(f"gpo:{side}:{value!r}", "gpo_v2", snapshot("gpos", [{"id": "synthetic-gpo", side: {"enabled": False, "directory_version": 2, "sysvol_version": 1}}]),
            snapshot("gpos", [{"id": "synthetic-gpo", side: value}]),
            f"snapshot_history_field_invalid:{side}" if bool(value) and not isinstance(value, dict) else None)
old = snapshot("settings", [{"id": "synthetic-setting", "setting_name": "cpassword", "value_display": "synthetic-old"}])
new = deepcopy(old)
new["settings"][0]["value_display"] = ["synthetic-new", None]
add("gpo:redaction-before-fingerprint", "gpo_v2", old, new)
add("invalid-family", "untrusted-family", {}, {}, "snapshot_history_family_invalid")

Path(__file__).with_name("snapshot-changes-vectors.json").write_text(
    json.dumps(vectors, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Generated {len(vectors)} Python vectors")
