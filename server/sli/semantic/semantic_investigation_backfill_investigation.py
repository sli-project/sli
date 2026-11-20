"""Split out of ``server.sli.semantic.semantic_investigation_backfill`` (plan 7.2b).

Module-level names of ``semantic_investigation_backfill`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.semantic.semantic_investigation_backfill as _src


def new_investigation_checkpoint(
    *, high_watermark: int, fingerprint: str,
    frozen_normalized_at: str | None = None,
    range_start: int = 1,
) -> dict[str, _src.Any]:
    if high_watermark < 0 or range_start < 1 or range_start > high_watermark + 1:
        raise ValueError("investigation backfill high watermark is invalid")
    return {
        "checkpoint_type": "retained_semantic_investigation_relations_v1",
        "status": "active",
        "created_at_utc": _src.datetime.now(_src.timezone.utc).isoformat(),
        "source": "normalized_events",
        "facts_contract": {
            "semantic_contract_version": _src.SEMANTIC_CONTRACT_VERSION,
            "normalizer_id": _src.NORMALIZER_ID,
            "normalizer_version": _src.NORMALIZER_VERSION,
        },
        "frozen_normalized_at": frozen_normalized_at or _src.datetime.now(_src.timezone.utc).isoformat(),
        "range_start_source_event_id": int(range_start),
        "frozen_high_watermark_source_event_id": int(high_watermark),
        "last_committed_source_event_id": int(range_start) - 1,
        "rules_fingerprint": str(fingerprint),
        "rule_ids": list(_src.INVESTIGATION_RULE_IDS),
        "source_event_ids_by_semantic_type": _src.investigation_source_contract(),
        "batch_limit": _src.BACKFILL_BATCH_MAX,
        "moves_collection_cursors": False,
        "contacts_sources": False,
    }


def validate_investigation_facts_checkpoint(
    checkpoint: _src.Mapping[str, _src.Any], *, fingerprint: str,
) -> None:
    expected = {
        "checkpoint_type": "retained_semantic_investigation_facts_v1",
        "source": "events_v2_core",
        "rules_fingerprint": fingerprint,
        "windows_event_ids": list(_src.INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS),
        "context_windows_event_ids": list(_src.INVESTIGATION_CONTEXT_WINDOWS_EVENT_IDS),
        "source_event_ids_by_semantic_type": _src.investigation_source_contract(),
        "batch_limit": _src.BACKFILL_BATCH_MAX,
        "moves_collection_cursors": False,
        "contacts_sources": False,
    }
    if any(checkpoint.get(key) != value for key, value in expected.items()):
        raise RuntimeError("investigation facts checkpoint contract is invalid")
    if checkpoint.get("phase") not in {_src.FACTS_PHASE_ANCHORS, _src.FACTS_PHASE_CONTEXT}:
        raise RuntimeError("investigation facts checkpoint phase is invalid")
    try:
        range_start = int(checkpoint["range_start_event_id"])
        high = int(checkpoint["frozen_high_watermark_event_id"])
        committed = int(checkpoint["last_committed_event_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("investigation facts checkpoint bounds are invalid") from exc
    if (
        high < 0
        or range_start < 1
        or range_start > high + 1
        or committed < range_start - 1
        or committed > high
    ):
        raise RuntimeError("investigation facts checkpoint bounds are invalid")


def validate_investigation_checkpoint(
    checkpoint: _src.Mapping[str, _src.Any], *, fingerprint: str,
) -> None:
    if checkpoint.get("checkpoint_type") != "retained_semantic_investigation_relations_v1":
        raise RuntimeError("investigation checkpoint type is invalid")
    if checkpoint.get("rules_fingerprint") != fingerprint:
        raise RuntimeError("investigation checkpoint fingerprint mismatch")
    if checkpoint.get("source") != "normalized_events":
        raise RuntimeError("investigation checkpoint source is invalid")
    if checkpoint.get("rule_ids") != list(_src.INVESTIGATION_RULE_IDS):
        raise RuntimeError("investigation checkpoint rules are invalid")
    if checkpoint.get("source_event_ids_by_semantic_type") != _src.investigation_source_contract():
        raise RuntimeError("investigation checkpoint source contract is invalid")
    if checkpoint.get("batch_limit") != _src.BACKFILL_BATCH_MAX:
        raise RuntimeError("investigation checkpoint batch limit is invalid")
    if checkpoint.get("moves_collection_cursors") is not False or checkpoint.get("contacts_sources") is not False:
        raise RuntimeError("investigation checkpoint violates source isolation")
    if checkpoint.get("facts_contract") != {
        "semantic_contract_version": _src.SEMANTIC_CONTRACT_VERSION,
        "normalizer_id": _src.NORMALIZER_ID,
        "normalizer_version": _src.NORMALIZER_VERSION,
    }:
        raise RuntimeError("investigation checkpoint facts contract is invalid")
    try:
        frozen = _src.datetime.fromisoformat(str(checkpoint["frozen_normalized_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("investigation checkpoint frozen time is invalid") from exc
    if frozen.tzinfo is None:
        raise RuntimeError("investigation checkpoint frozen time is invalid")
    try:
        range_start = int(checkpoint["range_start_source_event_id"])
        high = int(checkpoint["frozen_high_watermark_source_event_id"])
        committed = int(checkpoint["last_committed_source_event_id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("investigation checkpoint bounds are invalid") from exc
    if (
        high < 0
        or range_start < 1
        or range_start > high + 1
        or committed < range_start - 1
        or committed > high
    ):
        raise RuntimeError("investigation checkpoint bounds are invalid")


def select_investigation_fact_targets(
    cur: _src.Any, *, after_id: int, high_watermark: int,
    limit: int = _src.BACKFILL_BATCH_MAX,
    phase: str = _src.FACTS_PHASE_ANCHORS,
) -> tuple[int, ...]:
    requested = max(1, min(int(limit), _src.BACKFILL_BATCH_MAX))
    if phase == _src.FACTS_PHASE_ANCHORS:
        cur.execute(
            """
            select id
            from events_v2_core
            where id>%s and id<=%s and event_id=any(%s)
            order by id
            limit %s
            """,
            (
                int(after_id), int(high_watermark),
                list(_src.INVESTIGATION_SOURCE_WINDOWS_EVENT_IDS), requested,
            ),
        )
    elif phase == _src.FACTS_PHASE_CONTEXT:
        cur.execute(
            """
            select distinct login.id
            from events_v2_core login
            join events_v2_core reset_event
              on reset_event.domain_id=login.domain_id
             and lower(nullif(btrim(reset_event.target_user_sid),''))=
                 lower(nullif(btrim(login.target_user_sid),''))
            join normalized_events reset
              on reset.source_event_id=reset_event.id
             and reset.processing_status='normalized'
             and reset.semantic_contract_version=%s
             and reset.normalizer_id=%s and reset.normalizer_version=%s
             and reset.semantic_type='account.password.reset.succeeded'
             and reset.quality_json->'relation_account_identity'->>'state'='exact'
             and reset_event.event_id=%s
            where login.id>%s and login.id<=%s
              and login.event_id=any(%s)
              and nullif(btrim(login.target_user_sid),'') is not null
              and login.time_created_utc>reset.occurred_at_utc
              and login.time_created_utc<=reset.occurred_at_utc+interval '1 hour'
            order by login.id
            limit %s
            """,
            (
                _src.SEMANTIC_CONTRACT_VERSION, _src.NORMALIZER_ID, _src.NORMALIZER_VERSION,
                _src.INVESTIGATION_PASSWORD_RESET_WINDOWS_EVENT_ID,
                int(after_id), int(high_watermark),
                list(_src.INVESTIGATION_CONTEXT_WINDOWS_EVENT_IDS), requested,
            ),
        )
    else:
        raise ValueError("investigation facts phase is invalid")
    return tuple(int(row["id"]) for row in (cur.fetchall() or []))


def select_investigation_targets(
    cur: _src.Any, *, after_id: int, high_watermark: int, limit: int = _src.BACKFILL_BATCH_MAX,
    pack_path: _src.Path = _src.DEFAULT_PACK_PATH,
    frozen_normalized_at: str | None = None,
) -> list[dict[str, _src.Any]]:
    requested = max(1, min(int(limit), _src.BACKFILL_BATCH_MAX))
    source_semantic_types: list[str] = []
    source_event_ids: list[int] = []
    for semantic_type, event_ids in _src.SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE.items():
        for event_id in event_ids:
            source_semantic_types.append(semantic_type)
            source_event_ids.append(int(event_id))
    cur.execute(
        """
        select normalized_events.normalized_event_id,normalized_events.source_event_id
        from normalized_events
        join unnest(%s::text[],%s::integer[]) as source_contract(semantic_type,event_id)
          on source_contract.semantic_type=normalized_events.semantic_type
        join events_v2_core source_event
          on source_event.id=normalized_events.source_event_id
         and source_event.event_id=source_contract.event_id
        where normalized_events.processing_status='normalized'
          and normalized_events.semantic_contract_version=%s
          and normalized_events.normalizer_id=%s and normalized_events.normalizer_version=%s
          and normalized_events.normalized_at<=%s
          and normalized_events.source_event_id>%s and normalized_events.source_event_id<=%s
          and normalized_events.semantic_type=any(%s)
          and (
            normalized_events.semantic_type<>'authentication.session.created'
            or exists (
              select 1
              from normalized_events reset
              join events_v2_core reset_source_event
                on reset_source_event.id=reset.source_event_id
               and reset_source_event.event_id=%s
              where reset.processing_status='normalized'
                and reset.semantic_contract_version=%s
                and reset.normalizer_id=%s and reset.normalizer_version=%s
                and reset.normalized_at<=%s
                and reset.semantic_type='account.password.reset.succeeded'
                and reset.quality_json->'relation_account_identity'->>'state'='exact'
                and reset.facts_json->>'domain_id'=normalized_events.facts_json->>'domain_id'
                and reset.facts_json->>'relation_account_sid'=normalized_events.facts_json->>'relation_account_sid'
                and normalized_events.occurred_at_utc>reset.occurred_at_utc
                and normalized_events.occurred_at_utc<=reset.occurred_at_utc+interval '1 hour'
            )
          )
        order by normalized_events.source_event_id,normalized_events.normalized_event_id
        limit %s
        """,
        (
            source_semantic_types, source_event_ids,
            _src.SEMANTIC_CONTRACT_VERSION, _src.NORMALIZER_ID, _src.NORMALIZER_VERSION,
            frozen_normalized_at or _src.datetime.now(_src.timezone.utc).isoformat(),
            after_id, high_watermark,
            list(_src.investigation_rule_semantic_types(pack_path)),
            _src.INVESTIGATION_PASSWORD_RESET_WINDOWS_EVENT_ID,
            _src.SEMANTIC_CONTRACT_VERSION, _src.NORMALIZER_ID, _src.NORMALIZER_VERSION,
            frozen_normalized_at or _src.datetime.now(_src.timezone.utc).isoformat(),
            requested,
        ),
    )
    return [{
        "normalized_event_id": str(row["normalized_event_id"]),
        "source_event_id": int(row["source_event_id"]),
    } for row in (cur.fetchall() or [])]


def retire_superseded_investigation_rule_versions(cur: _src.Any, definition: _src.CorrelationRuleDefinition) -> None:
    """Retire older executable versions only after their replacement is SHADOW."""
    cur.execute(
        """
        select rule_version,lifecycle_status
        from semantic_correlation_rules
        where rule_id=%s and rule_version<%s
          and lifecycle_status in ('draft','validated','test','shadow','enabled','disabled')
        order by rule_version
        for update
        """,
        (definition.rule_id, definition.rule_version),
    )
    for row in (cur.fetchall() or []):
        version = int(dict(row)["rule_version"])
        status = str(dict(row)["lifecycle_status"])
        while status != "deprecated":
            target = {
                "draft": "disabled", "validated": "disabled", "test": "disabled",
                "shadow": "deprecated", "enabled": "deprecated", "disabled": "deprecated",
            }.get(status)
            if target is None:
                raise RuntimeError("superseded investigation rule has invalid lifecycle")
            status = _src.transition_correlation_rule(
                cur, rule_id=definition.rule_id, rule_version=version, target_status=target,
            )


def activate_investigation_rules(
    cur: _src.Any, path: _src.Path = _src.DEFAULT_PACK_PATH,
) -> dict[str, str]:
    """Register exact versions and stop at SHADOW; never enable risk/findings."""
    result: dict[str, str] = {}
    for definition in _src.selected_investigation_rules(path):
        existing = _src._rule_status(cur, definition.rule_id, definition.rule_version)
        if existing == "enabled":
            raise RuntimeError("investigation rule is unexpectedly enabled")
        if existing == "deprecated":
            raise RuntimeError("deprecated investigation rule version cannot be reactivated")
        if existing == "disabled":
            _src.transition_correlation_rule(
                cur, rule_id=definition.rule_id,
                rule_version=definition.rule_version, target_status="draft",
            )
            existing = "draft"
        _src.register_correlation_rule(cur, rule=definition)
        compiled = _src.compile_correlation_rule(definition)
        current = _src._rule_status(cur, definition.rule_id, definition.rule_version) or "draft"
        if current == "draft":
            _src.replace_rule_subscriptions(cur, rule=compiled)
        _src._verify_rule_subscriptions(cur, compiled)
        for source, target in (("draft", "validated"), ("validated", "test"), ("test", "shadow")):
            if current == source:
                current = _src.transition_correlation_rule(
                    cur, rule_id=definition.rule_id,
                    rule_version=definition.rule_version, target_status=target,
                )
        if current != "shadow":
            raise RuntimeError("investigation rule did not stop at shadow")
        if compiled.continuation_policy == "anchor_all_admissible":
            _src.retire_superseded_investigation_rule_versions(cur, definition)
        result[definition.rule_id] = current
    return result
