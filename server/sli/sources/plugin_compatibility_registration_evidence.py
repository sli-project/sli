"""Split out of ``server.sli.sources.plugin_compatibility_registration`` (plan 7.2b).

Module-level names of ``plugin_compatibility_registration`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.sources.plugin_compatibility_registration as _src


def build_ad_dc_compatibility_evidence() -> dict[str, _src.Any]:
    registration = _src.load_ad_dc_compatibility_registration()
    return {
        "schema_version": 1,
        "evidence_id": "stage9-ad-dc-compatibility-registration-v1",
        "status": "accepted_source_only",
        "scope": "existing_ad_dc_compatibility_registration",
        "read_only": True,
        "source_contact": False,
        "database_changed": False,
        "cursor_changed": False,
        "runtime_changed": False,
        "autostart_changed": False,
        "access_changed": False,
        "registration": registration.public_dict(),
        "next_gate": "source_pack_parity_without_runtime_ownership_transfer",
    }


def build_ad_dc_source_pack_parity_evidence() -> dict[str, _src.Any]:
    """Prove the existing pack/router/entrypoint wiring without executing it."""

    registration = _src.load_ad_dc_compatibility_registration()
    event_pack = _src.get_source_pack("sli.windows.ad-dc")
    context_pack = _src.get_source_pack("sli.windows.ad-context")
    if event_pack is None or event_pack.catalog_path is None or context_pack is None:
        raise _src.CompatibilityRegistrationError(
            "compatibility_parity_source_pack_missing"
        )
    catalog = _src.json.loads(event_pack.catalog_path.read_text(encoding="utf-8"))
    entries = catalog.get("entries") if isinstance(catalog, dict) else None
    if not isinstance(entries, list) or not entries:
        raise _src.CompatibilityRegistrationError(
            "compatibility_parity_catalog_entries_missing"
        )
    routed = 0
    normalized = 0
    channel_counts: dict[str, int] = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, _src.Mapping):
            raise _src.CompatibilityRegistrationError(
                "compatibility_parity_catalog_entry_invalid"
            )
        entry = dict(raw_entry)
        stream = str(entry.get("stream") or entry.get("channel") or "")
        provider = str(entry.get("provider_name") or "")
        event_key = str(entry.get("event_key") or entry.get("event_id") or "")
        pack = _src.resolve_source_pack(stream, provider, event_key)
        if pack is None or pack.pack_id != event_pack.pack_id:
            raise _src.CompatibilityRegistrationError(
                f"compatibility_parity_route_mismatch:{stream}/{provider}/{event_key}"
            )
        routed += 1
        normalizer = _src.resolve_source_normalizer(stream, provider, event_key)
        if normalizer is None or normalizer.normalizer_id != event_pack.normalizer_id:
            raise _src.CompatibilityRegistrationError(
                f"compatibility_parity_normalizer_mismatch:{stream}/{provider}/{event_key}"
            )
        normalized += 1
        channel_counts[stream] = channel_counts.get(stream, 0) + 1
    if set(channel_counts) != set(event_pack.channels):
        raise _src.CompatibilityRegistrationError(
            "compatibility_parity_channel_coverage_mismatch"
        )

    worker_path = _src.ROOT / "scripts" / "runtime" / "ad_context_snapshot_worker.py"
    declared_worker_sections = (
        _src._literal_string_sequence(worker_path, "LIGHT_SECTIONS")
        + _src._literal_string_sequence(worker_path, "DEEP_SECTIONS")
        + _src._literal_string_sequence(worker_path, "EXACT_LOGON_SECTIONS")
    )
    worker_sections = tuple(
        section for section in context_pack.sections if section in declared_worker_sections
    )
    if (
        len(declared_worker_sections) != len(set(declared_worker_sections))
        or set(declared_worker_sections) != set(context_pack.sections)
        or worker_sections != context_pack.sections
    ):
        raise _src.CompatibilityRegistrationError(
            "compatibility_parity_context_sections_mismatch"
        )
    pilot_source = (
        _src.ROOT / "scripts" / "run_dc_log_pilot.py"
    ).read_text(encoding="utf-8")
    collector_source = (
        _src.ROOT / "server" / "jobs" / "collector.py"
    ).read_text(encoding="utf-8")
    worker_source = (
        _src.ROOT / "scripts" / "runtime" / "collection_worker.py"
    ).read_text(encoding="utf-8")
    if (
        "validate_adapter_for_channels(" not in pilot_source
        or "source_pack_metadata_for_channels(" not in pilot_source
    ):
        raise _src.CompatibilityRegistrationError(
            "compatibility_parity_pilot_registry_wiring_missing"
        )
    if (
        'ROOT / "scripts" / "run_dc_log_pilot.py"'
        not in collector_source
    ):
        raise _src.CompatibilityRegistrationError(
            "compatibility_parity_collector_pilot_wiring_missing"
        )
    if (
        "from server.jobs.collector import create_collect_job, get_job"
        not in worker_source
        or "create_collect_job(" not in worker_source
    ):
        raise _src.CompatibilityRegistrationError(
            "compatibility_parity_worker_collector_wiring_missing"
        )
    return {
        "schema_version": 1,
        "evidence_id": "stage9-ad-dc-source-pack-parity-v1",
        "status": "accepted_source_pack_parity",
        "scope": "existing_ad_dc_source_pack_and_execution_wiring",
        "read_only": True,
        "source_contact": False,
        "database_changed": False,
        "cursor_changed": False,
        "runtime_changed": False,
        "registration_sha256": registration.registration_sha256,
        "event_pack": {
            "pack_id": event_pack.pack_id,
            "version": event_pack.version,
            "manifest_sha256": event_pack.manifest_sha256,
            "catalog_entry_count": len(entries),
            "exact_route_count": routed,
            "normalizer_resolution_count": normalized,
            "channel_counts": dict(sorted(channel_counts.items())),
        },
        "context_pack": {
            "pack_id": context_pack.pack_id,
            "version": context_pack.version,
            "manifest_sha256": context_pack.manifest_sha256,
            "sections": list(context_pack.sections),
            "worker_sections": list(worker_sections),
        },
        "execution_wiring": {
            "collection_worker_to_collector": True,
            "collector_to_run_dc_log_pilot": True,
            "pilot_to_source_pack_registry": True,
        },
        "next_gate": "dataset_and_report_parity_without_read_path_cutover",
    }


def build_ad_dc_dataset_report_parity_evidence() -> dict[str, _src.Any]:
    """Prove existing dataset/report source contracts without DB or cutover."""

    registration = _src.load_ad_dc_compatibility_registration()
    parity = _src.load_ad_dc_dataset_report_parity()
    if parity.registration_id != registration.registration_id:
        raise _src.CompatibilityRegistrationError(
            "dataset_report_parity_registration_mismatch"
        )
    context_pack = _src.get_source_pack("sli.windows.ad-context")
    if context_pack is None:
        raise _src.CompatibilityRegistrationError(
            "dataset_report_parity_context_pack_missing"
        )
    declared_sections = {
        section
        for contract in parity.contracts
        for section in (
            contract.primary_source_sections
            + contract.enrichment_source_sections
        )
    }
    if declared_sections != set(context_pack.sections):
        raise _src.CompatibilityRegistrationError(
            "dataset_report_parity_context_coverage_mismatch"
        )

    reporting_path = _src.ROOT / "server" / "sli" / "reporting" / "reporting_v4.py"
    reporting_source = reporting_path.read_text(encoding="utf-8")
    catalog_path = _src.ROOT / "server" / "sli" / "reporting" / "reporting_v4_catalog.py"
    executable = set(
        _src._literal_assignment_value(catalog_path, "EXECUTABLE_DATASETS")
    )
    filter_fields = _src._literal_assignment_value(
        catalog_path, "RUNTIME_FILTER_FIELDS"
    )
    sort_fields = _src._literal_assignment_value(
        catalog_path, "RUNTIME_SORT_FIELDS"
    )
    default_orders = _src._literal_assignment_value(
        catalog_path, "DEFAULT_ORDERS"
    )
    if not all(
        isinstance(item, _src.Mapping)
        for item in (filter_fields, sort_fields, default_orders)
    ):
        raise _src.CompatibilityRegistrationError(
            "dataset_report_parity_runtime_maps_invalid"
        )

    migration_035 = (
        _src.ROOT / "config" / "postgres_migrations" / "035_sli_v4_access_reports_objects.sql"
    ).read_text(encoding="utf-8")
    migration_036 = (
        _src.ROOT / "config" / "postgres_migrations" / "036_ad_audit_vpn_gpo_source.sql"
    ).read_text(encoding="utf-8")
    migration_041 = (
        _src.ROOT / "config" / "postgres_migrations" / "041_stage6_report_workspaces.sql"
    ).read_text(encoding="utf-8")
    migration_042 = (
        _src.ROOT / "config" / "postgres_migrations" / "042_stage6_report_workspace_routes.sql"
    ).read_text(encoding="utf-8")
    access_path = _src.ROOT / "server" / "sli" / "access" / "access_control_v4.py"
    scoped_membership_counts = _src._domain_scope_membership_counts(access_path)
    route_test_source = (
        _src.ROOT / "frontend" / "src" / "app" / "report-target-path.test.ts"
    ).read_text(encoding="utf-8")
    frontend_source = (
        _src.ROOT / "frontend" / "src" / "app" / "report-viewer.tsx"
    ).read_text(encoding="utf-8")

    runtime_markers = {
        "ad.audit.snapshot": ("version.source_section='directory_accounts'",),
        "ad.accounts.privileged": (
            "relation.source_section='privileged_membership'",
            "{VPN_ACCOUNT_ATTRIBUTES_LATERAL}",
        ),
        "ad.accounts.vpn": (
            "relation.source_section='vpn_membership'",
            "privileged.source_section='privileged_membership'",
            "{_src.VPN_ACCOUNT_ATTRIBUTES_LATERAL}",
        ),
        "ad.gpo.governance": ("version.source_section='gpo_governance'",),
    }
    contract_evidence: list[dict[str, _src.Any]] = []
    for contract in parity.contracts:
        dataset_key = contract.dataset_key
        report_key = contract.report_key
        if (
            dataset_key not in executable
            or dataset_key not in filter_fields
            or dataset_key not in sort_fields
            or dataset_key not in default_orders
        ):
            raise _src.CompatibilityRegistrationError(
                f"dataset_report_parity_runtime_dataset_missing:{dataset_key}"
            )
        branch = _src._dataset_query_branch(reporting_source, dataset_key)
        if dataset_key == "ad.accounts.vpn":
            branch = _vpn_dataset_query_source(branch)
        missing_markers = [
            marker for marker in runtime_markers[dataset_key] if marker not in branch
        ]
        if missing_markers:
            raise _src.CompatibilityRegistrationError(
                f"dataset_report_parity_runtime_source_mismatch:{dataset_key}"
            )
        uses_account_enrichment = any(
            "VPN_ACCOUNT_ATTRIBUTES_LATERAL" in marker
            for marker in runtime_markers[dataset_key]
        )
        if uses_account_enrichment and (
            "'directory_accounts'" not in reporting_source
            or "VPN_ACCOUNT_ATTRIBUTES_LATERAL" not in branch
        ):
            raise _src.CompatibilityRegistrationError(
                f"dataset_report_parity_runtime_enrichment_mismatch:{dataset_key}"
            )
        registry_source = migration_036 if dataset_key == "ad.accounts.vpn" else migration_035
        if not _src.re.search(
            _src.re.escape(report_key) + r"[\s\S]{0,1200}" + _src.re.escape(dataset_key),
            registry_source,
        ):
            raise _src.CompatibilityRegistrationError(
                f"dataset_report_parity_registry_mapping_missing:{report_key}"
            )
        if f"where dataset_key='{dataset_key}' and version=1;" not in migration_041:
            raise _src.CompatibilityRegistrationError(
                f"dataset_report_parity_workspace_columns_missing:{dataset_key}"
            )
        route_marker = f"('{report_key}','{contract.target_path}')"
        if route_marker not in migration_042:
            raise _src.CompatibilityRegistrationError(
                f"dataset_report_parity_route_migration_missing:{report_key}"
            )
        # The registered legacy path is kept in migration 042 (checked above); the
        # frontend now redirects each report_key to its report-v2 workspace, so the
        # route test must still cover the report_key (its target is frontend-owned).
        frontend_route_marker = f'["{report_key}", "/'
        if frontend_route_marker not in route_test_source:
            raise _src.CompatibilityRegistrationError(
                f"dataset_report_parity_frontend_route_missing:{report_key}"
            )
        # Reports share one generic viewer (report-v2 framework) that loads any
        # report_key through api.v4ReportData; per-report routes are checked above.
        if "api.v4ReportData(reportKey" not in frontend_source:
            raise _src.CompatibilityRegistrationError(
                f"dataset_report_parity_frontend_consumer_missing:{report_key}"
            )
        membership_count = scoped_membership_counts.get(dataset_key, 0)
        if membership_count < 2:
            raise _src.CompatibilityRegistrationError(
                f"dataset_report_parity_access_scope_missing:{dataset_key}"
            )
        contract_evidence.append(
            {
                "primary_source_sections": list(contract.primary_source_sections),
                "enrichment_source_sections": list(
                    contract.enrichment_source_sections
                ),
                "dataset_key": dataset_key,
                "dataset_version": contract.dataset_version,
                "report_key": report_key,
                "report_version": contract.report_version,
                "target_path": contract.target_path,
                "scope_kinds": list(contract.scope_kinds),
                "runtime_query_branch": True,
                "registry_definition": True,
                "workspace_columns": True,
                "route_migration": True,
                "access_scope_declarations": membership_count,
                "frontend_consumer": True,
            }
        )
    return {
        "schema_version": 1,
        "evidence_id": "stage9-ad-dc-dataset-report-parity-v1",
        "status": "accepted_source_contract_parity",
        "scope": "existing_ad_dc_dataset_report_and_frontend_source_contracts",
        "read_only": True,
        "source_contact": False,
        "database_changed": False,
        "migration_applied": False,
        "cursor_changed": False,
        "runtime_changed": False,
        "access_assignment_changed": False,
        "report_publication_changed": False,
        "frontend_changed": False,
        "read_path_cutover": False,
        "production_state_asserted": False,
        "registration_sha256": registration.registration_sha256,
        "parity_sha256": parity.parity_sha256,
        "context_pack_sections": list(context_pack.sections),
        "contracts": contract_evidence,
        "next_gate": "adapter_and_worker_parity_without_read_path_cutover",
    }


def build_ad_dc_adapter_worker_parity_evidence() -> dict[str, _src.Any]:
    """Prove allowlisted adapters and existing manual workers source-only."""

    registration = _src.load_ad_dc_compatibility_registration()
    expected_adapters = {
        "sli.windows.ad-dc": (
            "windows-eventlog-pywin32",
            "windows-eventlog-powershell",
        ),
        "sli.windows.ad-context": ("ad-context-powershell",),
    }
    adapter_evidence: list[dict[str, _src.Any]] = []
    for pack_id, adapter_ids in expected_adapters.items():
        pack = _src.get_source_pack(pack_id)
        if pack is None or pack.adapters != adapter_ids:
            raise _src.CompatibilityRegistrationError(
                f"adapter_worker_parity_pack_adapter_mismatch:{pack_id}"
            )
        for adapter_id in adapter_ids:
            metadata = _src.validate_adapter_for_pack(adapter_id, pack_id)
            descriptor = _src.get_source_adapter(adapter_id)
            if (
                descriptor is None
                or metadata.get("pack_id") != pack_id
                or adapter_id not in metadata.get("adapters", [])
            ):
                raise _src.CompatibilityRegistrationError(
                    f"adapter_worker_parity_descriptor_mismatch:{adapter_id}"
                )
            adapter_evidence.append(
                {
                    "pack_id": pack_id,
                    **descriptor.public_dict(),
                    "allowlisted_for_pack": True,
                }
            )
    if (
        _src.adapter_id_for_backend("python") != "windows-eventlog-pywin32"
        or _src.adapter_id_for_backend("powershell")
        != "windows-eventlog-powershell"
    ):
        raise _src.CompatibilityRegistrationError(
            "adapter_worker_parity_backend_mapping_mismatch"
        )

    worker_specs = (
        (
            "scripts/runtime/collection_worker.py",
            "event_collection",
            (
                "create_collect_job(",
                "get_job(",
                "session_advisory_lock(",
                "record_worker_heartbeat(",
                'add_argument("--once"',
            ),
        ),
        (
            "scripts/runtime/ad_context_snapshot_worker.py",
            "ad_context_snapshot",
            (
                "build_ad_context_command(",
                "load_bundle(",
                "snapshot_packet(bundle,",
                "import_snapshot_packet(",
                "session_advisory_lock(",
                "record_worker_heartbeat(",
                'add_argument("--once"',
            ),
        ),
        (
            "scripts/runtime/post_collection_worker.py",
            "core_post_collection",
            (
                "run_persisted_post_collection_worker_once(",
                "session_advisory_lock(",
                "record_worker_heartbeat(",
                'add_argument("--once"',
            ),
        ),
        (
            "scripts/runtime/entity_state_worker.py",
            "core_entity_state",
            (
                "run_once(limit=limit)",
                "session_advisory_lock(",
                "record_worker_heartbeat(",
                'add_argument("--once"',
            ),
        ),
    )
    registered_entrypoints = set(registration.entrypoints)
    worker_evidence: list[dict[str, _src.Any]] = []
    for relative, role, markers in worker_specs:
        if relative not in registered_entrypoints:
            raise _src.CompatibilityRegistrationError(
                f"adapter_worker_parity_worker_not_registered:{relative}"
            )
        source = (_src.ROOT / relative).read_text(encoding="utf-8")
        missing = [marker for marker in markers if marker not in source]
        if missing:
            raise _src.CompatibilityRegistrationError(
                f"adapter_worker_parity_worker_wiring_missing:{relative}"
            )
        worker_evidence.append(
            {
                "entrypoint": relative,
                "role": role,
                "manual_once_supported": True,
                "process_lock_present": True,
                "heartbeat_present": True,
                "runtime_started": False,
            }
        )
    if "scripts/run_dc_log_pilot.py" not in registered_entrypoints:
        raise _src.CompatibilityRegistrationError(
            "adapter_worker_parity_pilot_not_registered"
        )
    return {
        "schema_version": 1,
        "evidence_id": "stage9-ad-dc-adapter-worker-parity-v1",
        "status": "accepted_adapter_and_worker_source_parity",
        "scope": "existing_ad_dc_allowlisted_adapters_and_manual_workers",
        "read_only": True,
        "source_contact": False,
        "database_changed": False,
        "cursor_changed": False,
        "runtime_started": False,
        "autostart_changed": False,
        "ownership_transferred": False,
        "read_path_cutover": False,
        "registration_sha256": registration.registration_sha256,
        "adapter_parity": {
            "status": "accepted_source_only",
            "items": adapter_evidence,
            "event_backend_mapping": {
                "python": "windows-eventlog-pywin32",
                "powershell": "windows-eventlog-powershell",
            },
        },
        "worker_parity": {
            "status": "accepted_source_only",
            "component_runtime": registration.state["component_runtime"],
            "items": worker_evidence,
        },
        "next_gate": "separate_read_path_cutover_decision",
    }


def _mapping(value: _src.Mapping[str, _src.Any], key: str) -> dict[str, _src.Any]:
    item = value.get(key)
    if not isinstance(item, _src.Mapping):
        raise _src.CompatibilityRegistrationError(
            f"compatibility_{key}_object_required"
        )
    return dict(item)


def _literal_string_sequence(path: _src.Path, name: str) -> tuple[str, ...]:
    value = _src._literal_assignment_value(path, name)
    if (
        isinstance(value, (tuple, list))
        and value
        and all(isinstance(item, str) for item in value)
    ):
        return tuple(value)
    raise _src.CompatibilityRegistrationError(
        f"compatibility_literal_sequence_missing:{path.name}:{name}"
    )


def _literal_expression_value(expression: _src.ast.expr, symbols: dict[str, _src.Any]) -> _src.Any:
    if isinstance(expression, _src.ast.Name):
        if expression.id not in symbols:
            raise ValueError(f"unknown_literal_symbol:{expression.id}")
        return symbols[expression.id]
    if isinstance(expression, _src.ast.Constant):
        return expression.value
    if isinstance(expression, _src.ast.Tuple):
        return tuple(_src._literal_expression_value(item, symbols) for item in expression.elts)
    if isinstance(expression, _src.ast.List):
        return [_src._literal_expression_value(item, symbols) for item in expression.elts]
    if isinstance(expression, _src.ast.Set):
        return {_src._literal_expression_value(item, symbols) for item in expression.elts}
    if isinstance(expression, _src.ast.Dict):
        if any(key is None for key in expression.keys):
            raise ValueError("literal_dict_unpack_forbidden")
        return {
            _src._literal_expression_value(key, symbols): _src._literal_expression_value(
                value, symbols
            )
            for key, value in zip(expression.keys, expression.values, strict=True)
        }
    if (
        isinstance(expression, _src.ast.Call)
        and isinstance(expression.func, _src.ast.Name)
        and expression.func.id in {"frozenset", "set", "tuple", "list"}
        and len(expression.args) == 1
        and not expression.keywords
    ):
        value = _src._literal_expression_value(expression.args[0], symbols)
        return {
            "frozenset": frozenset,
            "set": set,
            "tuple": tuple,
            "list": list,
        }[expression.func.id](value)
    return _src.ast.literal_eval(expression)


def _literal_assignment_value(path: _src.Path, name: str) -> _src.Any:
    tree = _src.ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    symbols: dict[str, _src.Any] = {}
    for node in tree.body:
        if not isinstance(node, (_src.ast.Assign, _src.ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, _src.ast.Assign) else [node.target]
        target_names = [
            target.id for target in targets if isinstance(target, _src.ast.Name)
        ]
        if not target_names:
            continue
        try:
            value = _src._literal_expression_value(node.value, symbols)
        except (ValueError, TypeError, SyntaxError) as exc:
            if name in target_names:
                raise _src.CompatibilityRegistrationError(
                    f"compatibility_literal_assignment_invalid:{path.name}:{name}"
                ) from exc
            continue
        for target_name in target_names:
            symbols[target_name] = value
        if name in target_names:
            return value
    raise _src.CompatibilityRegistrationError(
        f"compatibility_literal_assignment_missing:{path.name}:{name}"
    )


def _vpn_dataset_query_source(branch: str) -> str:
    """Follow the registered VPN reader without importing or executing it."""
    plugin_path = _src.ROOT / "server" / "sli" / "plugins" / "remote_access"
    registration_source = (plugin_path / "registration.py").read_text(encoding="utf-8")
    if (
        not _src.re.search(
            r'require_plugin\(\s*"sli.remote-access",\s*"accounts_dataset",', branch
        )
        or not _src.re.search(
            r'"accounts_dataset":\s*_deferred\(\s*'
            r'"server\.sli\.plugins\.remote_access\.reports\.accounts_dataset",\s*'
            r'"read_accounts"\s*\)',
            registration_source,
        )
    ):
        raise _src.CompatibilityRegistrationError(
            "dataset_report_parity_runtime_reader_wiring_missing:ad.accounts.vpn"
        )
    reader_path = plugin_path / "reports" / "accounts_dataset.py"
    reader_source = reader_path.read_text(encoding="utf-8")
    tree = _src.ast.parse(reader_source, filename=str(reader_path))
    for node in tree.body:
        if isinstance(node, _src.ast.FunctionDef) and node.name == "read_accounts":
            return _src.ast.get_source_segment(reader_source, node) or ""
    raise _src.CompatibilityRegistrationError(
        "dataset_report_parity_runtime_reader_missing:ad.accounts.vpn"
    )


def _dataset_query_branch(source: str, dataset_key: str) -> str:
    marker = f'elif dataset_key == "{dataset_key}":'
    start = source.rfind(marker)
    if start < 0:
        raise _src.CompatibilityRegistrationError(
            f"dataset_report_parity_runtime_branch_missing:{dataset_key}"
        )
    next_branch = source.find('\n    elif dataset_key == "', start + len(marker))
    if next_branch < 0:
        next_branch = len(source)
    return source[start:next_branch]


def _domain_scope_membership_counts(path: _src.Path) -> dict[str, int]:
    tree = _src.ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    counts: dict[str, int] = {}
    for node in _src.ast.walk(tree):
        if not isinstance(node, _src.ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.left, _src.ast.Name) or node.left.id != "dataset_key":
            continue
        if not isinstance(node.ops[0], _src.ast.In) or len(node.comparators) != 1:
            continue
        try:
            values = _src.ast.literal_eval(node.comparators[0])
        except (ValueError, TypeError, SyntaxError):
            continue
        if not isinstance(values, (set, frozenset, tuple, list)):
            continue
        for value in values:
            if isinstance(value, str):
                counts[value] = counts.get(value, 0) + 1
    return counts
