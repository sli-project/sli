"""Frozen pre-relocation contracts supplement synthetic publication tests."""
from __future__ import annotations

import ast
import hashlib
import importlib
import json
from pathlib import Path
from textwrap import dedent

import pytest

from server.sli.plugins import registry

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "tests/unit/fixtures/ad_snapshot_library_baseline.json"


def _definitions(path):
    return {node.name: node for node in ast.parse(path.read_text(encoding="utf-8")).body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))}


def _restore_entity_context_lookup_sql(sql):
    """Undo the reviewed history read and lookups, keeping frozen hashes intact."""
    # The new read preserves the DTO and parameter contract. Restore only its
    # exact SQL delta; the query regression tests cover the early-stop ordering.
    wrapper = "\n        (\n"
    local_limit = (
        "        order by current desc, last_observed_at_utc desc, observed_at_utc desc, context_evidence_id desc\n"
        "        limit 100\n"
        "        )\n"
    )
    assert sql.count(wrapper) == sql.count(local_limit) == 2, "Reviewed AD fix no longer matches exactly"
    sql = sql.replace(wrapper, "\n").replace(local_limit, "")
    for alias, table, predicate, original_predicate, key, kind in (
        ("version", "ad_context_entity_versions", "entity_id=?", "version.entity_id=?",
         "version.attributes_json->>'record_key'", "entity"),
        ("relation", "ad_context_relation_versions", "source_entity_id=? or target_entity_id=?",
         "relation.source_entity_id=? or relation.target_entity_id=?", "relation.relation_key", "relation"),
    ):
        for current, frozen in (
            (
                f"        from (\n            select *, (valid_to_utc is null) as current\n"
                f"            from {table} where {predicate}\n"
                "            order by (valid_to_utc is null) desc, last_observed_at_utc desc offset 0\n"
                f"        ) {alias}\n",
                f"        from {table} {alias}\n",
            ),
            (f"{alias}.last_observed_at_utc, {alias}.current,", f"{alias}.last_observed_at_utc, ({alias}.valid_to_utc is null) as current,"),
            (
                "        join lateral (\n            select * from ad_context_evidence evidence\n"
                f"            where evidence.source_run_id={alias}.source_run_id\n"
                f"         and evidence.evidence_type='{kind}_observation'\n"
                f"         and evidence.locator_json->>'record_key'={key}\n"
                "            order by evidence.observed_at_utc desc, evidence.id desc limit 100\n"
                "        ) evidence on true\n",
                f"        join ad_context_evidence evidence\n          on evidence.source_run_id={alias}.source_run_id\n"
                f"         and evidence.evidence_type='{kind}_observation'\n"
                f"         and evidence.locator_json->>'record_key'={key}\n"
                f"        where {original_predicate}\n",
            ),
        ):
            assert sql.count(current) == 1, "Reviewed AD fix no longer matches exactly"
            sql = sql.replace(current, frozen)
    for participant, entity_id in (
        ("current_entity", "version.entity_id"),
        ("source_entity", "relation.source_entity_id"),
        ("target_entity", "relation.target_entity_id"),
    ):
        current = (
            "        join lateral (\n"
            "            select display_name from entities_v2_active\n"
            f"            where id={entity_id} limit 1\n"
            f"        ) {participant} on true\n"
        )
        frozen = f"        join entities_v2_active {participant} on {participant}.id={entity_id}\n"
        assert sql.count(current) == 1, "Reviewed AD fix no longer matches exactly"
        sql = sql.replace(current, frozen)
    return sql


def _replace_reviewed_statements(node, current, frozen):
    """Undo an exact reviewed delta without masking changes to surrounding AST."""
    current = ast.parse(dedent(current)).body
    frozen = ast.parse(dedent(frozen)).body
    expected = [ast.dump(value, include_attributes=False) for value in current]
    matches = []
    for parent in ast.walk(node):
        for _, values in ast.iter_fields(parent):
            if not isinstance(values, list):
                continue
            for index in range(len(values) - len(current) + 1):
                window = values[index:index + len(current)]
                if all(isinstance(value, ast.stmt) for value in window) and [
                    ast.dump(value, include_attributes=False) for value in window
                ] == expected:
                    matches.append((values, index))
    assert len(matches) == 1, "Reviewed AD fix no longer matches exactly"
    values, index = matches[0]
    values[index:index + len(current)] = frozen


def _restore_agent_slot_ast(node):
    # Keep the relocation reference checksums intact while allowing only the
    # exact v3 delta covered by publication and manifest contract tests.
    if node.name == "import_ad_cycle":
        _replace_reviewed_statements(node, '''
            try:
                stamp = datetime.fromisoformat(cycle["slot_start_utc"])
                if stamp.tzinfo is None or datetime.fromisoformat(due_slot(cycle["policy"], stamp)) != stamp:
                    raise ValueError("agent_slot_not_scheduled")
                default_schedule = cycle["policy"]["schedule"] == {"timezone": "Asia/Novosibirsk", "hours": [6, 18]}
                contract_version = V2_CONTRACT_VERSION if default_schedule else V3_CONTRACT_VERSION
                slot = (scheduled_slot_from_utc(stamp) if default_schedule else
                        ScheduledSlot(**agent_schedule_header(stamp),
                                      slot_start_utc=stamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")))
            except ValueError:
                raise PacketPending("agent_ad_schedule_unsupported") from None
        ''', '''
            try:
                slot = scheduled_slot_from_utc(datetime.fromisoformat(cycle["slot_start_utc"]))
            except ValueError:
                raise PacketPending("agent_ad_schedule_unsupported") from None
        ''')
        calls = [value for value in ast.walk(node) if isinstance(value, ast.Call)
                 and isinstance(value.func, ast.Name) and value.func.id == "run_one_shot"]
        assert len(calls) == 1
        keyword = next(value for value in calls[0].keywords if value.arg == "contract_version")
        assert ast.dump(keyword.value) == ast.dump(ast.Name(id="contract_version", ctx=ast.Load()))
        keyword.value = ast.Name(id="V2_CONTRACT_VERSION", ctx=ast.Load())
    elif node.name == "_resolve_manifest_slot":
        _replace_reviewed_statements(node, '''
            if contract_version not in {V1_CONTRACT_VERSION, V2_CONTRACT_VERSION, V3_CONTRACT_VERSION}:
                raise ValueError("unsupported_manifest_contract_version")
        ''', '''
            if contract_version not in {V1_CONTRACT_VERSION, V2_CONTRACT_VERSION}:
                raise ValueError("unsupported_manifest_contract_version")
        ''')
        _replace_reviewed_statements(node, '''
            if contract_version == V3_CONTRACT_VERSION:
                header = agent_schedule_header(parsed_slot)
                scheduled_slot = ScheduledSlot(**header, slot_start_utc=canonical_slot)
            else:
                scheduled_slot = scheduled_slot_from_utc(parsed_slot)
        ''', "scheduled_slot = scheduled_slot_from_utc(parsed_slot)")
    elif node.name == "_normalize_shape":
        _replace_reviewed_statements(node, '''
            expected_header = (agent_schedule_header(slot) if contract_version == V3_CONTRACT_VERSION
                               else v2_schedule_header(slot))
        ''', "expected_header = v2_schedule_header(slot)")
        _replace_reviewed_statements(node, '''
            raise SnapshotManifestError(
                f"{'v3' if contract_version == V3_CONTRACT_VERSION else 'v2'} schedule header does not match slot_start_utc"
            )
        ''', '''
            raise SnapshotManifestError("v2 schedule header does not match slot_start_utc")
        ''')
    elif node.name == "_validate_readback":
        _replace_reviewed_statements(node, '''
            if manifest["contract_version"] == V3_CONTRACT_VERSION:
                if observed < slot or observed > _parse_utc(manifest["assembled_at_utc"], "assembled_at_utc"):
                    raise SnapshotManifestError("manifest source observation is outside the agent cycle")
            elif observed < slot or observed >= slot_end:
                raise SnapshotManifestError("manifest source observation is outside the half-day slot")
        ''', '''
            if observed < slot or observed >= slot_end:
                raise SnapshotManifestError("manifest source observation is outside the half-day slot")
        ''')


def _restore_directory_name_ast(node):
    # Name ownership is covered by test_ad_directory_name_ownership.py.
    # Undo this exact fix for relocation checks, keeping reference hashes intact.
    if node.name == "_upsert_entity":
        _replace_reviewed_statements(node, '''
            if identity["kind"] in {"ad_user", "ad_computer"} and section_name in SUPPLEMENTAL_ENTITY_ATTRIBUTE_SECTIONS:
                attributes.pop("display_name", None)
                if "display_name" in existing_attributes:
                    attributes["display_name"] = existing_attributes["display_name"]
        ''', "")
    elif node.name == "persist_entity_identity":
        _replace_reviewed_statements(node, '''
            owns_name = identity["kind"] not in {"ad_user", "ad_computer"} or record["section"] == "directory_accounts"
        ''', "")
        # Keep the old update verbatim, including its SQL whitespace.
        updates = [value for value in ast.walk(node) if isinstance(value, ast.If)
                   and ast.unparse(value.test) == "not owns_name"]
        assert len(updates) == 1, "Reviewed AD fix no longer matches exactly"
        update = updates[0]
        _replace_reviewed_statements(update, '''
            cur.execute(
                "update entities_v2 set last_seen_utc=greatest(last_seen_utc, %s),migrated_at=now() where id=%s",
                (record["observed_at_utc"], entity_id),
            )
        ''', "")
        assert not update.body and len(update.orelse) == 1, "Reviewed AD fix no longer matches exactly"
        for parent in ast.walk(node):
            if isinstance(parent, ast.If) and parent.orelse == [update]:
                parent.orelse = update.orelse
                break
        else:
            pytest.fail("Reviewed name ownership branch is missing")
        for current, frozen in (
            ("display_name=case when %s then excluded.display_name else entities_v2.display_name end,", "display_name=excluded.display_name,"),
            ("source_core_sha256=case when %s then excluded.source_core_sha256 else entities_v2.source_core_sha256 end,", "source_core_sha256=excluded.source_core_sha256,"),
        ):
            matches = [value for value in ast.walk(node) if isinstance(value, ast.Constant)
                       and isinstance(value.value, str) and current in value.value]
            assert len(matches) == 1, "Reviewed AD fix no longer matches exactly"
            matches[0].value = matches[0].value.replace(current, frozen)
        tuples = [value for value in ast.walk(node) if isinstance(value, ast.Tuple) and len(value.elts) == 9
                  and all(isinstance(item, ast.Name) and item.id == "owns_name" for item in value.elts[-2:])]
        assert len(tuples) == 1, "Reviewed AD fix no longer matches exactly"
        tuples[0].elts = tuples[0].elts[:-2]


def _restore_gpo_completeness_ast(node):
    """Undo only PR866's reviewed delta; behavior has independent regressions."""
    loops = [value for value in ast.walk(node) if isinstance(value, ast.For)
             and ast.unparse(value.target) == "declared_section"
             and ast.unparse(value.iter) == "normalized['sections']"]
    assert len(loops) == 1, "Reviewed AD fix no longer matches exactly"
    loop = loops[0]
    bodies = [values for parent in ast.walk(node) for _, values in ast.iter_fields(parent)
              if isinstance(values, list) and loop in values]
    assert len(bodies) == 1, "Reviewed AD fix no longer matches exactly"
    body = bodies[0]
    index = body.index(loop)
    initializer = ast.parse("declared_sections = {}").body[0]
    assert index > 0 and ast.dump(body[index - 1]) == ast.dump(initializer), (
        "Reviewed AD fix no longer matches exactly"
    )
    body.pop(index - 1)
    prefix = ast.parse(dedent( '''
        section = dict(declared_section)
        if (
            section["name"] == "gpo_governance"
            and section["status"] == "complete"
            and normalized.get("gpo_v2_snapshot") is not None
        ):
            snapshot = normalized["gpo_v2_snapshot"]
            states = snapshot.get("source_states", {})
            if (
                snapshot.get("collection_status") != "complete"
                or any(
                    states.get(name, {}).get("status") != "observed"
                    for name in ("gpo_list", "gpc_directory")
                )
            ):
                section["status"] = "partial"
        declared_sections[section["name"]] = section
    ''')).body
    assert [ast.dump(value) for value in loop.body[:len(prefix)]] == [
        ast.dump(value) for value in prefix
    ], "Reviewed AD fix no longer matches exactly"
    del loop.body[:len(prefix)]
    loop.target = ast.Name(id="section", ctx=ast.Store())
    reconciliation = [value for value in ast.walk(node) if isinstance(value, ast.For)
                      and ast.unparse(value.target) == "section_name"]
    assert len(reconciliation) == 1, "Reviewed AD fix no longer matches exactly"
    parents = [value for value in ast.walk(node) if hasattr(value, "body")
               and reconciliation[0] in value.body]
    assert len(parents) == 1, "Reviewed AD fix no longer matches exactly"
    body = parents[0].body
    body[body.index(reconciliation[0]):body.index(reconciliation[0])] = ast.parse(
        'declared_sections = {item["name"]: item for item in normalized["sections"]}'
    ).body


def _restore_pre_fix_ad_ast(node):
    _restore_directory_name_ast(node)
    _restore_agent_slot_ast(node)
    if node.name == "get_entity_context_evidence":
        # The bounded participant lookups fix the entity-card timeout and are
        # covered by test_ad_context_entity_state_bridge1.py. Keep the original
        # relocation hash and require the rest of the function to match exactly.
        queries = [value for value in ast.walk(node) if isinstance(value, ast.Constant)
                   and isinstance(value.value, str) and "from ad_context_entity_versions where" in value.value]
        assert len(queries) == 1, "Reviewed AD fix no longer matches exactly"
        queries[0].value = _restore_entity_context_lookup_sql(queries[0].value)
    # 7a502db0 intentionally fixed GUID reuse and safe publication deferral.
    # Their behavior is covered by test_agent_ad_snapshot_import.py and the
    # repository watermark tests; keep the original relocation hashes intact.
    if node.name == "import_ad_cycle":
        _replace_reviewed_statements(node, '''
            try:
                slot = scheduled_slot_from_utc(datetime.fromisoformat(cycle["slot_start_utc"]))
            except ValueError:
                raise PacketPending("agent_ad_schedule_unsupported") from None
            if slot.slot_start_utc != cycle["slot_start_utc"].replace("+00:00", "Z"):
                raise PacketPending("agent_ad_schedule_unsupported")
        ''', "")
        _replace_reviewed_statements(node, '''
            if not domain:
                raise PacketPending("agent_ad_domain_not_bound")
        ''', '''
            if not domain:
                raise PacketPending("agent_ad_domain_not_bound")
            slot = scheduled_slot_from_utc(datetime.fromisoformat(cycle["slot_start_utc"]))
            if slot.slot_start_utc != cycle["slot_start_utc"].replace("+00:00", "Z"):
                raise PacketPending("agent_ad_schedule_unsupported")
        ''')
        _replace_reviewed_statements(node, '''
            try:
                import_bundle(conn, bundle)
            except AdContextOutOfOrderError:
                raise PacketPending("agent_ad_snapshot_superseded") from None
        ''', "import_bundle(conn, bundle)")
    elif node.name == "import_bundle":
        _restore_gpo_completeness_ast(node)
        _replace_reviewed_statements(node,
            "observed_entities: dict[str, tuple[int, dict[str, Any]]] = {}", "")
        _replace_reviewed_statements(node, '''
            identity = record["identity"]
            guid = identity["object_guid"]
            existing_entity_id = existing_entity_ids.get(record["record_key"])
            if guid in observed_entities:
                observed_id, observed_identity = observed_entities[guid]
                if (
                    observed_identity["kind"] != identity["kind"]
                    or (observed_identity.get("object_sid") and identity.get("object_sid")
                        and observed_identity["object_sid"].casefold() != identity["object_sid"].casefold())
                    or (existing_entity_id is not None and existing_entity_id != observed_id)
                ):
                    raise ValueError("stable GUID alias conflicts with entity identity")
                existing_entity_id = observed_id
                identity = {**identity, "object_sid": observed_identity.get("object_sid") or identity.get("object_sid")}
        ''', "")
        _replace_reviewed_statements(node, '''
            entity_id = _upsert_entity(
                cur, domain_id, normalized["run_id"], record,
                existing_entity_id=existing_entity_id, lookup_complete=True,
            )
        ''', '''
            entity_id = _upsert_entity(
                cur, domain_id, normalized["run_id"], record,
                existing_entity_id=existing_entity_ids.get(record["record_key"]), lookup_complete=True,
            )
        ''')
        _replace_reviewed_statements(node,
            "observed_entities[guid] = (entity_id, identity)", "")
    elif node.name == "_start_run":
        _replace_reviewed_statements(node, '''
            raise AdContextOutOfOrderError(
                "out-of-order AD Context bundle is not allowed for sections: "
                + ",".join(stale_sections)
            )
        ''', '''
            raise ValueError(
                "out-of-order AD Context bundle is not allowed for sections: "
                + ",".join(stale_sections)
            )
        ''')
    elif node.name == "_record":
        # Daily posture validation is covered by test_agent_ad_snapshot_security.py.
        # Remove only this exact addition before checking the frozen relocation AST.
        _replace_reviewed_statements(node, r'''
            for key in ("password_last_set_status", "laps_password_expiration_status", "legacy_laps_password_expiration_status"):
                if key in attributes:
                    _enum(attributes[key], frozenset({"observed", "not_set", "not_returned", "schema_absent", "parse_error"}), key)
            if "resource_based_delegation_status" in attributes:
                _enum(attributes["resource_based_delegation_status"], frozenset({
                    "observed", "partial", "not_returned", "schema_absent", "parse_error", "not_collected",
                }), "resource_based_delegation_status")
            if attributes.get("resource_based_delegation_sids") is not None:
                sids = attributes["resource_based_delegation_sids"]
                if not isinstance(sids, list) or any(not re.fullmatch(r"S-1-(?:\d+-)+\d+", sid) for sid in sids):
                    raise AdContextContractError("resource_based_delegation_sids must contain SIDs")
        ''', "")
    elif node.name == "_preload_existing_entity_ids":
        # 3871e970 scopes legacy JSON SID hints to the requested entity type.
        # Batch-resolution tests cover the fix; preserve the relocation hash.
        _replace_reviewed_statements(node, '''
            matches_by_identity: dict[tuple[str, str], list[dict[str, Any]]] = {}
            for row in cur.fetchall():
                matches_by_identity.setdefault(
                    (str(row["normalized_sid"]).casefold(), str(row["entity_type"])), []
                ).append(dict(row))
        ''', '''
            matches_by_sid: dict[str, list[dict[str, Any]]] = {}
            for row in cur.fetchall():
                matches_by_sid.setdefault(
                    str(row["normalized_sid"]).casefold(), []
                ).append(dict(row))
        ''')
        loops = [value for value in ast.walk(node) if isinstance(value, ast.For)
                 and ast.unparse(value.iter) == "keys_by_sid.items()"]
        assert len(loops) == 1, "Reviewed AD fix no longer matches exactly"
        loop = loops[0]
        assert len(loop.body) == 1 and isinstance(loop.body[0], ast.For), (
            "Reviewed AD fix no longer matches exactly"
        )
        _replace_reviewed_statements(loop, '''
            record = next(
                item
                for item in entities
                if item["record_key"] == record_key
            )
            matches = matches_by_identity.get((sid, record["identity"]["kind"]), [])
            if len(matches) != 1:
                continue
        ''', '''
            record = next(
                item
                for item in entities
                if item["record_key"] == record_key
            )
        ''')
        loop.body[:0] = ast.parse(dedent('''
            matches = matches_by_sid.get(sid, [])
            if len(matches) != 1:
                continue
        ''')).body


@pytest.mark.parametrize("path,name,changed_literal", [
    ("server/sli/plugins/ad/snapshot_import.py", "import_ad_cycle", "agent_ad_snapshot_superseded"),
    ("server/sli/plugins/ad/context/repository.py", "import_bundle", "stable GUID alias conflicts with entity identity"),
    ("server/sli/plugins/ad/context/repository.py", "import_bundle", "partial"),
    ("server/sli/plugins/ad/context/repository.py", "import_bundle", "observed"),
    ("server/sli/plugins/ad/context/repository.py", "import_bundle", "gpc_directory"),
    ("server/sli/plugins/ad/context/repository.py", "_start_run", "out-of-order AD Context bundle is not allowed for sections: "),
    ("server/sli/entities/context_identity.py", "_preload_existing_entity_ids", "normalized_sid"),
    ("server/sli/entities/context_identity.py", "persist_entity_identity", "directory_accounts"),
    ("server/sli/plugins/ad/context/contracts.py", "_record", "not_set"),
    ("server/sli/plugins/ad/context/contracts.py", "_record", r"S-1-(?:\d+-)+\d+"),
    ("server/sli/plugins/ad/context/contracts.py", "_record", "resource_based_delegation_sids must contain SIDs"),
])
def test_reviewed_ad_ast_normalization_rejects_unreviewed_changes(path, name, changed_literal):
    node = _definitions(ROOT / path)[name]
    literal = next(value for value in ast.walk(node)
                   if isinstance(value, ast.Constant) and value.value == changed_literal)
    literal.value += "changed"
    with pytest.raises(AssertionError, match="Reviewed AD fix no longer matches exactly"):
        _restore_pre_fix_ad_ast(node)


@pytest.mark.parametrize("relocation", ["initializer_after_loop", "prefix_after_sql"])
def test_gpo_completeness_normalization_rejects_statement_relocations(relocation):
    node = _definitions(ROOT / "server/sli/plugins/ad/context/repository.py")["import_bundle"]
    loop = next(value for value in ast.walk(node) if isinstance(value, ast.For)
                and ast.unparse(value.target) == "declared_section")
    if relocation == "initializer_after_loop":
        body = next(value.body for value in ast.walk(node) if hasattr(value, "body")
                    and loop in value.body)
        index = body.index(loop)
        initializer = body.pop(index - 1)
        body.insert(body.index(loop) + 1, initializer)
    else:
        loop.body[:] = loop.body[3:] + loop.body[:3]
    with pytest.raises(AssertionError, match="Reviewed AD fix no longer matches exactly"):
        _restore_pre_fix_ad_ast(node)


@pytest.mark.parametrize("entity_id", [
    "version.entity_id", "relation.source_entity_id", "relation.target_entity_id",
])
def test_context_lookup_normalization_rejects_changed_bounds(entity_id):
    node = _definitions(ROOT / "server/sli/plugins/ad/context/integration.py")["get_entity_context_evidence"]
    literal = next(value for value in ast.walk(node) if isinstance(value, ast.Constant)
                   and isinstance(value.value, str) and f"where id={entity_id} limit 1" in value.value)
    literal.value = literal.value.replace(f"where id={entity_id} limit 1", f"where id={entity_id} limit 2")
    with pytest.raises(AssertionError, match="Reviewed AD fix no longer matches exactly"):
        _restore_pre_fix_ad_ast(node)


@pytest.mark.parametrize("name,changed_literal", [
    ("import_bundle", "relations_closed"),
    ("_preload_existing_entity_ids", "object_guid"),
    ("_record", "entity.attributes"),
    ("get_entity_context_evidence", "bounded"),
])
def test_reviewed_ad_ast_normalization_preserves_unreviewed_changes(name, changed_literal):
    contract = next(value for value in json.loads(BASELINE.read_text(encoding="utf-8"))["definitions"]
                    if value["name"] == name)
    node = _definitions(ROOT / contract["candidate"])[contract["name"]]
    literal = next(value for value in ast.walk(node)
                   if isinstance(value, ast.Constant) and value.value == changed_literal)
    literal.value += "changed"
    _restore_pre_fix_ad_ast(node)
    digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
    assert digest != contract["sha256"]


@pytest.mark.parametrize("contract", json.loads(BASELINE.read_text(encoding="utf-8"))["definitions"])
def test_relocated_computation_matches_frozen_pre_plugin_ast(contract):
    node = _definitions(ROOT / contract["candidate"])[contract["name"]]
    _restore_pre_fix_ad_ast(node)
    if contract.get("strip_context_import"):
        assert isinstance(node.body[0], ast.ImportFrom)
        assert node.body[0].module == "server.sli.plugins.ad.context.contracts"
        node.body.pop(0)
    if contract.get("inline_gpo_validation"):
        helper = _definitions(ROOT / "server/sli/plugins/gpo/context_contracts.py")["validate_context_snapshot"]
        for index, statement in enumerate(node.body):
            if (isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Call)
                    and isinstance(statement.value.func, ast.Name)
                    and statement.value.func.id == "validate_context_snapshot"):
                node.body[index:index + 1] = helper.body[1:-1]
                break
        else:
            pytest.fail("GPO validation delegation is missing")
    if contract.get("inline_identity_writes"):
        helper = _definitions(ROOT / "server/sli/entities/context_identity.py")["persist_entity_identity"]
        _restore_directory_name_ast(helper)
        assert ast.unparse(helper.body[1]) == "identity = record['identity']"
        for index, statement in enumerate(node.body):
            if (isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Call)
                    and isinstance(statement.value.func, ast.Name)
                    and statement.value.func.id == "persist_entity_identity"):
                assert ast.unparse(statement) == (
                    "entity_id = persist_entity_identity(cur, domain_id, record, "
                    "entity_id=entity_id, attributes=attributes)"
                )
                node.body[index:index + 1] = helper.body[2:-1]
                break
        else:
            pytest.fail("Shared identity persistence delegation is missing")
    for value in ast.walk(node):
        if isinstance(value, ast.ImportFrom):
            value.module = contract.get("import_aliases", {}).get(value.module, value.module)
    digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
    assert digest == contract["sha256"]


@pytest.mark.parametrize("contract", json.loads(BASELINE.read_text(encoding="utf-8"))["sql"])
def test_split_stores_keep_every_sql_statement(contract):
    statements = []
    for target in contract["candidates"]:
        node = _definitions(ROOT / target["path"])[target["name"]]
        _restore_directory_name_ast(node)
        statements.extend(value.value for value in ast.walk(node)
                          if isinstance(value, ast.Constant) and isinstance(value.value, str)
                          and value.value.strip().lower().startswith(
                              ("select ", "insert ", "update ", "delete ", "with ")))
    digest = hashlib.sha256(json.dumps(sorted(statements), ensure_ascii=False).encode()).hexdigest()
    assert digest == contract["sha256"]


@pytest.mark.parametrize("old,new", [
    ("server.sli.agents.ad_snapshot_import", "server.sli.plugins.ad.snapshot_import"),
    ("server.ad_context.contracts", "server.sli.plugins.ad.context.contracts"),
    ("server.ad_context.repository", "server.sli.plugins.ad.context.repository"),
    ("server.ad_context.projection", "server.sli.plugins.ad.context.projection"),
    ("server.ad_context.enrichment", "server.sli.plugins.ad.context.enrichment"),
    ("server.ad_context.integration", "server.sli.plugins.ad.context.integration"),
    ("server.ad_context.snapshot_manifest", "server.sli.plugins.ad.snapshots.manifest"),
    ("server.sli.sources.ad_snapshot_projection", "server.sli.plugins.ad.snapshots.projection"),
])
def test_compatibility_paths_share_implementation_and_patches(old, new):
    assert importlib.import_module(old) is importlib.import_module(new)


@pytest.mark.parametrize("plugin_id", ["sli.ad", "sli.gpo"])
def test_snapshot_dispatch_uses_current_reviewed_hook(monkeypatch, plugin_id):
    from contextlib import contextmanager
    from server.sli.agents import snapshot_consumer

    @contextmanager
    def admission(owner):
        assert owner == plugin_id
        yield

    contribution = registry.Contributions()
    calls = []
    contribution.hooks["import_snapshot_cycle"] = lambda *args: calls.append(args) or {"generation": 1}
    monkeypatch.setattr(registry, "registered_plugins", lambda: {plugin_id: contribution})
    monkeypatch.setattr(registry.update_runtime, "admission", admission)
    importer = snapshot_consumer.import_ad_cycle if plugin_id == "sli.ad" else snapshot_consumer.import_gpo_cycle
    connection, cycle, families = object(), {}, {}
    assert importer(connection, cycle, families) == {"generation": 1}
    contribution.hooks["import_snapshot_cycle"] = lambda *args: {"generation": 2}
    assert importer(connection, cycle, families) == {"generation": 2}
    assert calls == [(connection, cycle, families)]


def test_gpo_snapshot_hook_does_not_admit_ad(monkeypatch):
    from contextlib import contextmanager
    from server.sli.agents import snapshot_consumer
    from server.sli.plugins.gpo import registration, snapshot_import

    contribution = registry.Contributions()
    registration.register(contribution)
    monkeypatch.setattr(registry, "registered_plugins", lambda: {"sli.gpo": contribution})
    admitted = []

    @contextmanager
    def admission(owner):
        admitted.append(owner)
        yield

    monkeypatch.setattr(registry.update_runtime, "admission", admission)
    monkeypatch.setattr(snapshot_import, "import_gpo_cycle", lambda *args: {"source_run_id": "synthetic"})
    assert snapshot_consumer.import_gpo_cycle(object(), {}, {}) == {"source_run_id": "synthetic"}
    assert admitted == ["sli.gpo"]


def test_gpo_projection_preserves_exact_input_without_admission(monkeypatch):
    from server.sli.plugins.ad.snapshots import projection
    from server.sli.reports import gpo_v2_reporting

    exact_input = {"gpos": [], "coverage": {"state": "partial"}}
    output = {"items": [], "limitations": ["synthetic"]}

    def project(value):
        assert value is exact_input
        return output

    monkeypatch.setattr(gpo_v2_reporting, "project_gpo_v2_exact", project)
    monkeypatch.setattr(registry.update_runtime, "admission", lambda *args: pytest.fail("pure GPO projection cannot admit AD"))
    assert projection._pure_project("ad.gpo.v2", exact_input) is output


def test_agent_importer_has_no_runtime_worker_dependency():
    source = ROOT / "server/sli/plugins/ad/snapshot_import.py"
    imports = [node.module for node in ast.walk(ast.parse(source.read_text(encoding="utf-8")))
               if isinstance(node, ast.ImportFrom)]
    assert not any(module.startswith("scripts.runtime") for module in imports if module)
    consumer = (ROOT / "server/sli/agents/consumer.py").read_text(encoding="utf-8")
    assert "scripts.runtime.ad_context_snapshot_worker" not in consumer


def test_publication_connection_preserves_credentials_options_and_role(monkeypatch):
    import sys
    from contextlib import nullcontext
    from types import ModuleType, SimpleNamespace
    from server.sli.agents import snapshot_publication_connection as publication

    calls, statements = [], []
    cursor = SimpleNamespace(execute=statements.append)
    connection = SimpleNamespace(cursor=lambda: nullcontext(cursor))
    row_factory = object()
    psycopg = ModuleType("psycopg")
    psycopg.connect = lambda **kwargs: calls.append(kwargs) or connection
    conninfo = ModuleType("psycopg.conninfo")
    conninfo.conninfo_to_dict = lambda dsn: {"dbname": "synthetic", "host": "localhost"}
    rows = ModuleType("psycopg.rows")
    rows.dict_row = row_factory
    monkeypatch.setitem(sys.modules, "psycopg", psycopg)
    monkeypatch.setitem(sys.modules, "psycopg.conninfo", conninfo)
    monkeypatch.setitem(sys.modules, "psycopg.rows", rows)
    monkeypatch.setattr(publication, "load_config", lambda: SimpleNamespace(
        postgres_dsn="synthetic", postgres_connect_timeout_seconds=0,
    ))
    monkeypatch.setenv("ADLOG_PG_ADMIN_USER", "synthetic_admin")
    monkeypatch.setenv("ADLOG_PG_ADMIN_PASSWORD", "synthetic_password")

    assert publication._import_connect() is connection
    assert calls == [{
        "dbname": "synthetic", "host": "localhost", "user": "synthetic_admin",
        "password": "synthetic_password", "application_name": "adlog_context_snapshot_import",
        "row_factory": row_factory, "connect_timeout": 1,
        "options": "-c statement_timeout=300000 -c lock_timeout=10000",
    }]
    assert statements == ["set role adlog_context_worker"]


@pytest.mark.parametrize("missing", ["ADLOG_PG_ADMIN_USER", "ADLOG_PG_ADMIN_PASSWORD"])
def test_publication_connection_rejects_missing_credentials_before_connect(monkeypatch, missing):
    from types import SimpleNamespace
    import psycopg
    from server.sli.agents import snapshot_publication_connection as publication

    monkeypatch.setattr(publication, "load_config", lambda: SimpleNamespace(postgres_dsn="synthetic"))
    monkeypatch.setenv("ADLOG_PG_ADMIN_USER", "synthetic_admin")
    monkeypatch.setenv("ADLOG_PG_ADMIN_PASSWORD", "synthetic_password")
    monkeypatch.delenv(missing)
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: pytest.fail("missing credentials must not connect"))
    with pytest.raises(RuntimeError, match="admin credentials are required"):
        publication._import_connect()


def test_source_workers_keep_publication_function_aliases():
    from scripts.runtime import (
        ad_context_snapshot_worker, ad_snapshot_manifest_coordinator_worker,
        users_report_v2_snapshot_worker, computers_v6_source_worker,
    )
    from server.sli.agents import snapshot_publication_connection
    from server.sli.plugins.ad.snapshots import coordinator, users_persistence, computers_persistence

    assert ad_context_snapshot_worker._import_connect is snapshot_publication_connection._import_connect
    assert ad_snapshot_manifest_coordinator_worker.run_one_shot is coordinator.run_one_shot
    assert users_report_v2_snapshot_worker.persist_users_v2_snapshot is users_persistence.persist_users_v2_snapshot
    assert computers_v6_source_worker.persist_computers_v6_source_snapshot is computers_persistence.persist_computers_v6_source_snapshot


@pytest.mark.parametrize("conflict", [False, True])
def test_shared_identity_replay_keeps_entity_id_and_rejects_alias_conflict(conflict):
    from server.sli.plugins.ad.context.repository import _upsert_entity

    class Cursor:
        def __init__(self):
            self.rows = []
            self.aliases = {}
            self.rowcount = 1
            self.inserts = 0

        def execute(self, sql, params):
            sql = " ".join(sql.split()).lower()
            self.rows = []
            if sql.startswith("insert into storage_v2_entity_type"):
                self.rows = [{"id": 3}]
            elif sql.startswith("insert into entities_v2"):
                self.inserts += 1
                self.rows = [{"id": 42}]
            elif sql.startswith("insert into ad_context_entity_aliases"):
                key = (params[1], params[2], params[4])
                self.rowcount = 0 if conflict else 1
                self.aliases.setdefault(key, params[0])

        def fetchone(self):
            return self.rows[0] if self.rows else None

    cursor = Cursor()
    record = {"identity": {"kind": "ad_user", "object_guid": "00000000-0000-4000-8000-000000000001",
                           "object_sid": "S-1-5-21-100-200-300-1001"},
              "attributes": {"display_name": "synthetic", "sam_account_name": "synthetic"},
              "record_key": "synthetic:user", "section": "directory_accounts",
              "observed_at_utc": "2026-10-01T00:00:00Z"}
    if conflict:
        with pytest.raises(ValueError, match="already belongs to a different SLI entity"):
            _upsert_entity(cursor, 7, "synthetic-run", record, lookup_complete=True)
        return
    assert _upsert_entity(cursor, 7, "synthetic-run", record, lookup_complete=True) == 42
    aliases = dict(cursor.aliases)
    assert _upsert_entity(cursor, 7, "synthetic-replay", record,
                          existing_entity_id=42, lookup_complete=True) == 42
    assert cursor.inserts == 1
    assert cursor.aliases == aliases
    assert set(cursor.aliases.values()) == {42}
