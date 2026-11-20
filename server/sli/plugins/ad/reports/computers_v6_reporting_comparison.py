"""Split out of ``server.sli.plugins.ad.reports.computers_v6_reporting`` (plan 7.2b).

Module-level names of ``computers_v6_reporting`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.plugins.ad.reports.computers_v6_reporting as _src


def compare_computers_v6_snapshots(
    *, current: _src.Mapping[str, _src.Any], previous: _src.Mapping[str, _src.Any],
) -> dict[str, _src.Any]:
    if current.get("contract_id") != _src.CONTRACT_ID or previous.get("contract_id") != _src.CONTRACT_ID:
        raise ValueError("incompatible_computers_v6_snapshots")
    current_index = _src._snapshot_index(current)
    previous_index = _src._snapshot_index(previous)
    current_partial = (
        str(current.get("state") or "") == "partial"
        or str((current.get("coverage") or {}).get("state") or "") == "partial"
    )
    previous_partial = (
        str(previous.get("state") or "") == "partial"
        or str((previous.get("coverage") or {}).get("state") or "") == "partial"
    )
    rows: list[dict[str, _src.Any]] = []
    for object_guid in sorted(set(current_index) | set(previous_index)):
        current_item = current_index.get(object_guid)
        previous_item = previous_index.get(object_guid)
        if current_item is None:
            rows.append(_src._change_row(
                change_type="missing_current", item=previous_item or {"entity_id": 0},
                before="Присутствовал в предыдущем снимке", after="Отсутствует в текущем снимке",
                current_partial=current_partial,
            ))
            continue
        if previous_item is None:
            rows.append(_src._change_row(
                change_type="new_object", item=current_item, before="Отсутствовал",
                after="Присутствует в текущем снимке", current_partial=current_partial,
            ))
            continue
        previous_states = dict((previous_item.get("evidence") or {}).get("attribute_states") or {})
        current_states = dict((current_item.get("evidence") or {}).get("attribute_states") or {})
        quality_rows = 0
        for field in sorted(set(previous_states) | set(current_states)):
            before_state = _src._state_name(previous_states.get(field))
            after_state = _src._state_name(current_states.get(field))
            if before_state == after_state:
                continue
            row = _src._change_row(
                change_type="quality_changed",
                item=current_item,
                before=before_state,
                after=after_state,
                current_partial=current_partial,
            )
            row["field"] = field
            row["row_id"] = f"quality_changed:{current_item['entity_id']}:{field}"
            rows.append(row)
            quality_rows += 1
        comparisons = (
            ("enabled_changed", str(previous_item.get("enabled")), str(current_item.get("enabled"))),
            ("ou_changed", str(previous_item.get("ou_path") or "нет данных"), str(current_item.get("ou_path") or "нет данных")),
            (
                "os_changed",
                " · ".join(str(value) for value in (previous_item.get("operating_system"), previous_item.get("operating_system_version"), previous_item.get("operating_system_build")) if value) or "нет данных",
                " · ".join(str(value) for value in (current_item.get("operating_system"), current_item.get("operating_system_version"), current_item.get("operating_system_build")) if value) or "нет данных",
            ),
            ("ip_changed", ", ".join(sorted(previous_item.get("ip_addresses") or [])) or "нет данных", ", ".join(sorted(current_item.get("ip_addresses") or [])) or "нет данных"),
            (
                "site_changed",
                str(((previous_item.get("network") or {}).get("ad_site") or {}).get("value") or "нет данных"),
                str(((current_item.get("network") or {}).get("ad_site") or {}).get("value") or "нет данных"),
            ),
            (
                "managed_by_changed",
                str(previous_item.get("managed_by") or "нет данных"),
                str(current_item.get("managed_by") or "нет данных"),
            ),
            ("classification_changed", str(previous_item.get("computer_type") or "unknown"), str(current_item.get("computer_type") or "unknown")),
            ("semantic_changed", _src._semantic_count(previous_item), _src._semantic_count(current_item)),
        )
        for change_type, before, after in comparisons:
            if before == after:
                continue
            rows.append(_src._change_row(
                change_type=change_type, item=current_item, before=before, after=after,
                current_partial=current_partial,
            ))
        if quality_rows == 0 and _src._quality_codes(previous_item) != _src._quality_codes(current_item):
            row = _src._change_row(
                change_type="quality_changed",
                item=current_item,
                before=_src._quality_codes(previous_item),
                after=_src._quality_codes(current_item),
                current_partial=current_partial,
            )
            row["field"] = "summary"
            rows.append(row)
    state = "partial" if current_partial or previous_partial else "available"
    return {
        "state": state,
        "current": {"captured_at_utc": current.get("captured_at_utc"), "state": current.get("state")},
        "previous": {"captured_at_utc": previous.get("captured_at_utc"), "state": previous.get("state")},
        "items": rows,
        "change_count": len(rows),
        "deletion_claim_allowed": False,
    }


def _load_snapshot_comparison(domain_ids: list[int] | None) -> dict[str, _src.Any]:
    if domain_ids is None:
        domain_ids = [int(row["id"]) for row in _src.query_rows_bounded("select id from domains order by id")]
    # Read at most two compatible snapshots per requested domain in one
    # statement. LIMIT must be inside each lateral read, never global.
    rows = [] if domain_ids == [] else _src.query_rows_bounded(
        """/* computers_v6_snapshots */
            select pair.*
            from domains selected_domain
            cross join lateral (
                select snapshot.domain_id,snapshot.scope_sha256,snapshot.contract_id,snapshot.schema_version
                from computers_report_v6_snapshots snapshot
                where snapshot.domain_id=selected_domain.id
                order by snapshot.captured_at_utc desc,snapshot.snapshot_id desc limit 1
            ) latest
            cross join lateral (
                select snapshot.snapshot_id,snapshot.domain_id,snapshot.bucket_start_utc,
                       snapshot.captured_at_utc,snapshot.source_observed_at_utc,
                       snapshot.source_state,snapshot.object_count,snapshot.payload_json,
                       (select count(*) from computers_report_v6_snapshots history
                        where history.domain_id=snapshot.domain_id) as domain_snapshot_count
                from computers_report_v6_snapshots snapshot
                where snapshot.domain_id=latest.domain_id
                  and snapshot.scope_sha256=latest.scope_sha256
                  and snapshot.contract_id=latest.contract_id
                  and snapshot.schema_version=latest.schema_version
                order by snapshot.captured_at_utc desc,snapshot.snapshot_id desc limit 2
            ) pair
            where selected_domain.id=any(?)
            order by selected_domain.id,pair.captured_at_utc desc,pair.snapshot_id desc""",
        (domain_ids,),
        statement_timeout_ms=5000,
    )
    by_domain: dict[int, list[dict[str, _src.Any]]] = {}
    for row in rows:
        by_domain.setdefault(int(row["domain_id"]), []).append(row)
    if len(domain_ids) > 1:
        # Keep caller ordering and duplicate-domain behavior, including domains
        # with no snapshots, rather than deriving scope from returned rows.
        domains = [{"domain_id": domain_id, **_snapshot_comparison_from_rows(
            by_domain.get(domain_id, []), domain_id,
        )} for domain_id in domain_ids]
        items = [{**item, "domain_id": domain["domain_id"]} for domain in domains for item in domain["items"]]
        return {"state": "available" if all(domain["state"] == "available" for domain in domains) else "partial",
                "domains": domains, "items": items, "change_count": len(items), "deletion_claim_allowed": False}
    domain_id = domain_ids[0] if domain_ids else None
    return _snapshot_comparison_from_rows(by_domain.get(domain_id, []), domain_id)


def _snapshot_comparison_from_rows(
    rows: list[dict[str, _src.Any]], domain_id: int | None,
) -> dict[str, _src.Any]:
    if len(rows) < 2:
        return {
            "state": "not_collected",
            "reason": (
                "incompatible_snapshot_pair_not_compared"
                if rows and int(rows[0].get("domain_snapshot_count") or 0) > 1
                else
                "previous_compatible_snapshot_not_collected"
                if rows
                else "snapshot_history_not_collected"
            ),
            "current": _src._snapshot_context(rows[0]) if rows else None,
            "previous": None,
            "items": [],
            "change_count": 0,
            "deletion_claim_allowed": False,

        }
    payloads: list[dict[str, _src.Any]] = []
    for row in rows[:2]:
        raw = row.get("payload_json")
        payload = dict(raw) if isinstance(raw, _src.Mapping) else _src.json.loads(str(raw))
        payloads.append(payload)
    result = _src.compare_computers_v6_snapshots(current=payloads[0], previous=payloads[1])
    result["items"] = [{**item, "domain_id": domain_id} for item in result["items"]]
    result["current"] = {**dict(result.get("current") or {}), **_src._snapshot_context(rows[0])}
    result["previous"] = {**dict(result.get("previous") or {}), **_src._snapshot_context(rows[1])}
    return result


def _change_row(
    *,
    change_type: str,
    item: _src.Mapping[str, _src.Any],
    before: str,
    after: str,
    current_partial: bool,
) -> dict[str, _src.Any]:
    missing = change_type == "missing_current"
    qualification = (
        "Объект отсутствует в текущем неполном снимке; причина не установлена."
        if missing and current_partial
        else "Объект отсутствует в текущем снимке; причина не установлена."
        if missing
        else "Зафиксировано различие двух совместимых снимков; причина изменения не устанавливается автоматически."
    )
    limitation = (
        "Отсутствие в текущем снимке не доказывает удаление: объект мог выпасть из scope или неполного сбора."
        if missing
        else "Снимки показывают два наблюдаемых состояния и не доказывают, кто, почему или вследствие чего внёс изменение."
    )
    return {
        "row_id": f"{change_type}:{int(item['entity_id'])}",
        "entity_id": int(item["entity_id"]),
        "display_name": str(item.get("display_name") or item["entity_id"]),
        "change_type": change_type,
        "before": before,
        "after": after,
        "object": dict(item),
        "qualification": qualification,
        "limitation": limitation,
        "next_action": "Проверить объект и связанные evidence; решение принимает человек.",
    }


def _snapshot_index(snapshot: _src.Mapping[str, _src.Any]) -> dict[str, dict[str, _src.Any]]:
    indexed: dict[str, dict[str, _src.Any]] = {}
    for raw in snapshot.get("items") or []:
        item = dict(raw)
        identity = item.get("identity") if isinstance(item.get("identity"), _src.Mapping) else {}
        object_guid = str(item.get("object_guid") or identity.get("object_guid") or "").strip().lower()
        if not object_guid:
            raise ValueError("snapshot_missing_object_guid")
        if object_guid in indexed:
            raise ValueError("snapshot_duplicate_object_guid")
        indexed[object_guid] = item
    return indexed


def _snapshot_context(row: _src.Mapping[str, _src.Any]) -> dict[str, _src.Any]:
    raw_payload = row.get("payload_json")
    payload = (
        dict(raw_payload)
        if isinstance(raw_payload, _src.Mapping)
        else _src.json.loads(str(raw_payload))
        if raw_payload
        else {}
    )
    source_snapshot = payload.get("source_snapshot") if isinstance(payload.get("source_snapshot"), _src.Mapping) else {}
    return {
        "snapshot_id": int(row["snapshot_id"]),
        "captured_at_utc": _src._iso(row.get("captured_at_utc")),
        "source_observed_at_utc": _src._iso(row.get("source_observed_at_utc")),
        "collection_status": str(source_snapshot.get("state") or row.get("source_state") or "unknown"),
        "source_state": str(row.get("source_state") or "unknown"),
        "object_count": int(row.get("object_count") or 0),
        "query_dc": source_snapshot.get("query_dc"),
    }


def _semantic_rows(items: list[dict[str, _src.Any]]) -> list[dict[str, _src.Any]]:
    if not items:
        return []
    return _src.query_rows_bounded(
        """/* computers_v6_semantic */
           select distinct finding.id as finding_id,linked.entity_id,computer.display_name,
                  finding.title,finding.status,finding.summary,finding.why_it_matters,
                  finding.recommended_action,finding.last_seen_utc
           from findings finding
           join finding_entities linked on linked.finding_id=finding.id
           join entities_v2_active computer on computer.id=linked.entity_id
           join storage_v2_entity_type entity_type on entity_type.id=computer.entity_type_id
           where linked.entity_id=any(?) and entity_type.value='ad_computer'
             and is_semantic_finding_published_v1(finding.id)
           order by finding.last_seen_utc desc,finding.id desc limit 201""",
        ([int(item["entity_id"]) for item in items],),
        statement_timeout_ms=5000,
    )
