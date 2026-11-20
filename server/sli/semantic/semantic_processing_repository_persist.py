"""Split out of ``server.sli.semantic.semantic_processing_repository`` (plan 7.2b).

Module-level names of ``semantic_processing_repository`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.semantic.semantic_processing_repository as _src


def persist_canonical_actions(
    cur: _src.Any,
    *,
    actions: _src.Sequence[_src.CanonicalAction],
    normalizer_version: str = _src.NORMALIZER_VERSION,
) -> tuple[str, ...]:
    """Upsert stable actions and append normalized evidence without re-risking."""
    persisted: list[str] = []
    for action in actions:
        deduplication_key = bytes.fromhex(action.canonical_deduplication_key)
        action_id = str(
            _src.uuid.uuid5(
                _src.uuid.NAMESPACE_URL,
                f"adlog:canonical:{action.canonical_deduplication_key}",
            )
        )
        # Serialize even the first insert for this identity.  A row lock cannot
        # protect an absent action, while the transaction-scoped advisory lock
        # also makes concurrent at-least-once deliveries converge safely.
        cur.execute(
            "select pg_advisory_xact_lock(hashtextextended(%s,0))",
            (action.canonical_deduplication_key,),
        )
        # The action UUID is intentionally stable across assembler revisions.
        # A replay after a version bump must therefore find the existing row by
        # primary key before looking for a row scoped to the current revision;
        # otherwise a valid replay collides with canonical_actions_pkey.
        cur.execute(
            """
            select canonical_action_id,action_kind,action_status,action_sha256,
                   semantic_contract_version,assembler_id,assembler_version,
                   canonical_deduplication_key,attributes_json
            from canonical_actions
            where canonical_action_id=%s
            for update
            """,
            (action_id,),
        )
        existing = cur.fetchone()
        if existing is None:
            cur.execute(
                """
                select canonical_action_id,action_kind,action_status,action_sha256,
                       semantic_contract_version,assembler_id,assembler_version,
                       canonical_deduplication_key,attributes_json
                from canonical_actions
                where semantic_contract_version=%s and assembler_id=%s
                  and assembler_version=%s and canonical_deduplication_key=%s
                for update
                """,
                (
                    _src.SEMANTIC_CONTRACT_VERSION,
                    _src.ASSEMBLER_ID,
                    _src.ASSEMBLER_VERSION,
                    deduplication_key,
                ),
            )
            existing = cur.fetchone()
        existing_evidence_by_source: dict[int, dict[str, _src.Any]] = {}
        prior_evidence: list[dict[str, _src.Any]] = []
        version_changed = False
        if existing:
            row = dict(existing)
            if int(row["semantic_contract_version"]) != _src.SEMANTIC_CONTRACT_VERSION:
                raise RuntimeError("canonical action semantic contract replay conflict")
            if (
                str(row["canonical_action_id"]) != action_id
                or row["action_kind"] != action.action_kind
                or row["assembler_id"] != _src.ASSEMBLER_ID
                or bytes(row["canonical_deduplication_key"]) != deduplication_key
            ):
                raise RuntimeError("canonical action identity replay conflict")
            version_changed = row["assembler_version"] != _src.ASSEMBLER_VERSION
            prior_attributes = _src._json_object(row.get("attributes_json"))
            evidence_sources = (None,) if version_changed else action.source_event_ids
            for source_event_id in evidence_sources:
                source_filter = "" if source_event_id is None else "and normalized.source_event_id=%s"
                evidence_params = ((action_id,) if source_event_id is None
                                   else (action_id, source_event_id))
                cur.execute(
                    f"""
                    select normalized.source_event_id,evidence.normalized_event_id,
                           evidence.evidence_role,evidence.entity_role,
                           evidence.evidence_order,evidence.relation_confidence
                    from canonical_action_evidence evidence
                    join normalized_events normalized
                      on normalized.normalized_event_id=evidence.normalized_event_id
                    where evidence.canonical_action_id=%s
                      {source_filter}
                    order by evidence.evidence_order
                    for update of evidence
                    """,
                    evidence_params,
                )
                links = [dict(link) for link in (cur.fetchall() or [])]
                for link in links:
                    link_source_event_id = int(link["source_event_id"])
                    if link_source_event_id in existing_evidence_by_source:
                        raise RuntimeError("canonical action duplicate source evidence conflict")
                    existing_evidence_by_source[link_source_event_id] = link
                    if version_changed:
                        prior_evidence.append({
                            "source_event_id": link_source_event_id,
                            "normalized_event_id": str(link["normalized_event_id"]),
                            "evidence_role": link["evidence_role"],
                            "entity_role": link["entity_role"],
                            "evidence_order": int(link["evidence_order"]),
                            "relation_confidence": str(link["relation_confidence"]),
                        })
            if (
                version_changed
                and len(action.source_event_ids) == 1
                and "source_evidence" in prior_attributes
                and "source_evidence" in action.attributes
            ):
                if action.source_event_ids[0] not in existing_evidence_by_source:
                    raise RuntimeError("canonical action interpretation evidence missing")
                attributes = _src._reinterpreted_single_source_attributes(
                    prior_attributes, action.attributes,
                    source_event_id=action.source_event_ids[0],
                )
            else:
                attributes = _src._merge_action_attributes(prior_attributes, action.attributes)
            if version_changed:
                history = prior_attributes.get("prior_interpretations", [])
                if not isinstance(history, list):
                    raise RuntimeError("canonical action interpretation provenance conflict")
                attributes["prior_interpretations"] = [
                    *history,
                    {
                        "assembler_id": row["assembler_id"],
                        "assembler_version": row["assembler_version"],
                        "action_sha256": bytes(row["action_sha256"]).hex(),
                        "evidence": prior_evidence,
                        "attributes": {
                            key: value for key, value in prior_attributes.items()
                            if key != "prior_interpretations"
                        },
                    },
                ]
            cur.execute(
                """
                update canonical_actions
                set attributes_json=%s::jsonb,action_sha256=%s,
                    assembler_version=%s,
                    occurred_at_utc=least(occurred_at_utc,%s),updated_at=now()
                where canonical_action_id=%s
                """,
                (
                    _src.json.dumps(attributes, sort_keys=True, separators=(",", ":")),
                    _src._action_sha256(
                        action_kind=action.action_kind,
                        deduplication_key=action.canonical_deduplication_key,
                        attributes=attributes,
                    ),
                    _src.ASSEMBLER_VERSION,
                    action.occurred_at_utc,
                    action_id,
                ),
            )
        else:
            attributes = dict(action.attributes)
            cur.execute(
                """
                insert into canonical_actions(
                    canonical_action_id,action_kind,action_status,
                    semantic_contract_version,assembler_id,assembler_version,
                    occurred_at_utc,contribution_key,canonical_deduplication_key,
                    action_sha256,attributes_json
                ) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
                """,
                (
                    action_id,
                    action.action_kind,
                    action.status,
                    _src.SEMANTIC_CONTRACT_VERSION,
                    _src.ASSEMBLER_ID,
                    _src.ASSEMBLER_VERSION,
                    action.occurred_at_utc,
                    deduplication_key,
                    deduplication_key,
                    _src._action_sha256(
                        action_kind=action.action_kind,
                        deduplication_key=action.canonical_deduplication_key,
                        attributes=attributes,
                    ),
                    _src.json.dumps(attributes, sort_keys=True, separators=(",", ":")),
                ),
            )

        cur.execute(
            """
            select normalized_event_id,source_event_id
            from normalized_events
            where semantic_contract_version=%s
              and normalizer_id=%s and normalizer_version=%s
              and source_event_id=any(%s)
            """,
            (
                _src.SEMANTIC_CONTRACT_VERSION,
                _src.NORMALIZER_ID,
                normalizer_version,
                list(action.source_event_ids),
            ),
        )
        normalized_by_source = {
            int(row["source_event_id"]): str(row["normalized_event_id"])
            for row in (cur.fetchall() or [])
        }
        missing = sorted(set(action.source_event_ids) - normalized_by_source.keys())
        if missing:
            raise RuntimeError(f"canonical action evidence is not normalized: {missing}")
        for source_event_id in action.source_event_ids:
            normalized_id = normalized_by_source[source_event_id]
            previous_link = existing_evidence_by_source.get(source_event_id)
            if previous_link is not None:
                if str(previous_link["normalized_event_id"]) != normalized_id:
                    if not version_changed:
                        raise RuntimeError("canonical action normalized evidence replay conflict")
                    cur.execute(
                        """
                        update canonical_action_evidence set normalized_event_id=%s
                        where canonical_action_id=%s and normalized_event_id=%s
                        """,
                        (normalized_id, action_id, previous_link["normalized_event_id"]),
                    )
                continue
            cur.execute(
                """
                select coalesce(max(evidence_order),-1) as last_order
                from canonical_action_evidence where canonical_action_id=%s
                """,
                (action_id,),
            )
            last_order = int(dict(cur.fetchone() or {"last_order": -1})["last_order"])
            evidence_order = last_order + 1
            cur.execute(
                """
                insert into canonical_action_evidence(
                    canonical_action_id,normalized_event_id,evidence_role,
                    entity_role,evidence_order,relation_confidence
                ) values (%s,%s,%s,null,%s,1.000)
                """,
                (
                    action_id,
                    normalized_id,
                    "primary" if evidence_order == 0 else "supporting",
                    evidence_order,
                ),
            )
        cur.execute(
            """
            update canonical_actions action
            set action_status='multi_source_confirmed',updated_at=now()
            where canonical_action_id=%s
              and action_status in ('observed','partially_confirmed')
              and (
                  select count(distinct normalized.source_event_id)
                  from canonical_action_evidence evidence
                  join normalized_events normalized
                    on normalized.normalized_event_id=evidence.normalized_event_id
                  where evidence.canonical_action_id=%s
                    and evidence.evidence_role in ('primary','supporting')
              ) > 1
            """,
            (action_id, action_id),
        )
        persisted.append(action_id)
    return tuple(persisted)


def persist_process_episode_revision(
    cur: _src.Any,
    *,
    episode: _src.ProcessEpisode,
    evidence_by_id: _src.Mapping[int, _src.NormalizedEvent],
) -> str:
    """Call the constrained DB writer with a fully bound evidence manifest."""

    evidence_event_ids = (episode.boot_event_id, *episode.evidence_event_ids)
    if len(set(evidence_event_ids)) != len(evidence_event_ids):
        raise ValueError("process episode boot evidence must be distinct")
    if not 2 <= len(evidence_event_ids) <= 256:
        raise ValueError("process episode evidence membership must be bounded")
    missing = [value for value in evidence_event_ids if value not in evidence_by_id]
    if missing:
        raise ValueError(f"process episode evidence is missing: {missing}")
    if _src.windows_process_id(episode.process_id) is None or (
        episode.parent_process_id is not None
        and _src.windows_process_id(episode.parent_process_id) is None
    ):
        raise ValueError("process episode PID is outside the Windows range")
    for value, field in (
        (episode.process_name, "process_name"),
        (episode.command_line, "process_command_line"),
        (episode.user_sid, "process_user_sid"),
        (episode.user_name, "process_user_name"),
        (episode.user_domain, "process_user_domain"),
        (episode.logon_id, "process_logon_id"),
    ):
        if value is not None and _src.bounded_process_text(value, field) is None:
            raise ValueError(f"process episode {field} violates the byte contract")

    manifest: list[dict[str, _src.Any]] = []
    for evidence_order, source_event_id in enumerate(evidence_event_ids):
        event = evidence_by_id[source_event_id]
        source_hash = str(event.facts.get("source_event_sha256") or "").casefold()
        facts_hash = str(event.facts.get("source_facts_sha256") or "").casefold()
        semantic_hash = str(event.semantic_sha256 or "").casefold()
        try:
            native_record_id = int(event.facts["event_record_id"])
        except (KeyError, TypeError, ValueError):
            native_record_id = 0
        if native_record_id <= 0:
            raise ValueError("process episode evidence EventRecordID must be positive")
        if (
            len(source_hash) != 64 or len(facts_hash) != 64
            or len(semantic_hash) != 64
            or any(
                char not in "0123456789abcdef"
                for char in source_hash + facts_hash + semantic_hash
            )
        ):
            raise ValueError("process episode provenance is incomplete")
        if (
            str(event.facts.get("domain_id") or "") != episode.domain_id
            or str(event.facts.get("source_host_id") or "") != episode.source_host_id
        ):
            raise ValueError("process episode evidence scope conflicts with episode identity")
        manifest.append({
            "evidence_order": evidence_order,
            "source_event_id": source_event_id,
            "evidence_role": (
                "boot_scope" if source_event_id == episode.boot_event_id else
                "start" if source_event_id == episode.start_event_id else
                "confirmed_end" if source_event_id == episode.end_event_id else "attached"
            ),
            "semantic_type": event.semantic_type,
            "semantic_contract_version": _src.SEMANTIC_CONTRACT_VERSION,
            "normalizer_id": _src.NORMALIZER_ID,
            "normalizer_version": _src.NORMALIZER_VERSION,
            "semantic_sha256": semantic_hash,
            "observed_at_utc": event.occurred_at_utc.isoformat(),
            "source_channel": str(event.facts.get("channel") or ""),
            "event_record_id": native_record_id,
            "source_event_sha256": source_hash,
            "source_facts_sha256": facts_hash,
            "domain_id": int(episode.domain_id),
            "source_host_id": int(episode.source_host_id),
        })
    manifest_payload = _src.json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    state = {
        "episode_id": episode.episode_id,
        "process_id": episode.process_id,
        "domain_id": int(episode.domain_id),
        "source_host_id": int(episode.source_host_id),
        "display_host": episode.display_host,
        "boot_event_id": episode.boot_event_id,
        "start_event_id": episode.start_event_id,
        "started_at_utc": episode.started_at_utc.isoformat(),
        "end_event_id": episode.end_event_id,
        "confirmed_end_at_utc": (
            episode.confirmed_end_at_utc.isoformat()
            if episode.confirmed_end_at_utc else None
        ),
        "process_name": episode.process_name,
        "command_line": episode.command_line,
        "user_sid": episode.user_sid,
        "user_name": episode.user_name,
        "user_domain": episode.user_domain,
        "logon_id": episode.logon_id,
        "parent_process_id": episode.parent_process_id,
        "parent_episode_id": episode.parent_episode_id,
        "completeness_state": episode.completeness_state,
        "confirmation_state": episode.confirmation_state,
        "ordering_state": episode.ordering_state,
        "evidence_count": len(manifest),
        "evidence_manifest_sha256": _src.sha256(manifest_payload.encode("utf-8")).hexdigest(),
        "assembler_id": episode.assembler_id,
        "assembler_version": episode.assembler_version,
    }
    revision_payload = _src.json.dumps(
        state, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    revision_sha = _src.sha256(revision_payload.encode("utf-8")).digest()
    idempotency_key = _src.sha256(
        f"{episode.episode_id}:{episode.assembler_id}:{episode.assembler_version}:".encode("utf-8")
        + revision_sha
    ).digest()
    revision_id = str(_src.uuid.uuid5(
        _src.uuid.NAMESPACE_URL, f"adlog:process-revision:{idempotency_key.hex()}"
    ))
    writer_payload = _src.json.dumps({
        **state,
        "revision_id": revision_id,
        "idempotency_key": idempotency_key.hex(),
        "revision_sha256": revision_sha.hex(),
        "revision_payload": revision_payload,
        "evidence_manifest": manifest,
        "evidence_manifest_payload": manifest_payload,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    cur.execute(
        "select public.write_process_episode_revision_v89(%s::jsonb)::text as revision_id",
        (writer_payload,),
    )
    row = dict(cur.fetchone() or {})
    actual_revision_id = str(row.get("revision_id") or revision_id)
    if actual_revision_id != revision_id:
        raise RuntimeError("process episode writer replay identity conflict")
    return actual_revision_id


def _reinterpreted_single_source_attributes(
    existing: _src.Mapping[str, _src.Any], incoming: _src.Mapping[str, _src.Any], *, source_event_id: int
) -> dict[str, _src.Any]:
    """Replace one versioned authentication interpretation after preserving it."""
    if existing.get("material_identity") != incoming.get("material_identity"):
        raise RuntimeError("canonical action material identity conflict")
    if incoming.get("prior_interpretations") is not None:
        raise RuntimeError("canonical action interpretation provenance conflict")
    for attributes in (existing, incoming):
        material = attributes.get("material_identity")
        evidence = attributes.get("source_evidence")
        if (
            not isinstance(material, _src.Mapping)
            or material.get("source_event_id") != source_event_id
            or not isinstance(evidence, list)
            or len(evidence) != 1
            or not isinstance(evidence[0], _src.Mapping)
            or evidence[0].get("source_event_id") != source_event_id
            or not isinstance(attributes.get("observed_facts"), list)
            or len(attributes["observed_facts"]) != 1
            or not isinstance(attributes.get("observed_roles"), list)
            or len(attributes["observed_roles"]) != 1
        ):
            raise RuntimeError("canonical action interpretation source conflict")
    return dict(incoming)


def _merge_action_attributes(
    existing: _src.Mapping[str, _src.Any], incoming: _src.Mapping[str, _src.Any]
) -> dict[str, _src.Any]:
    merged = dict(existing)
    if existing.get("material_identity") not in (None, incoming.get("material_identity")):
        raise RuntimeError("canonical action material identity conflict")
    for key, value in incoming.items():
        if key in {"added_values", "removed_values"}:
            merged[key] = sorted(
                {str(item) for item in merged.get(key, [])}
                | {str(item) for item in value or []}
            )
        elif key not in merged or merged[key] in (None, ""):
            merged[key] = value
        elif merged[key] != value and key not in {"quality", "identity_quality"}:
            raise RuntimeError(f"canonical action attribute conflict: {key}")
    if "added_values" in merged or "removed_values" in merged:
        merged["quality"] = (
            "complete"
            if merged.get("added_values") and merged.get("removed_values")
            else "partial"
        )
    return merged


def _action_sha256(
    *, action_kind: str, deduplication_key: str, attributes: _src.Mapping[str, _src.Any]
) -> bytes:
    payload = _src.json.dumps(
        {
            "action_kind": action_kind,
            "deduplication_key": deduplication_key,
            "attributes": dict(attributes),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return _src.sha256(payload).digest()
