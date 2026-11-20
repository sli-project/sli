"""Split out of ``server.sli.reporting.ui_workspace`` (plan 7.2b).

Module-level names of ``ui_workspace`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reporting.ui_workspace as _src
from server.sli.core.keyset_cursor import decode_cursor, encode_cursor


def get_investigations_workspace_data(
    *,
    q: str | None,
    scope: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    timezone_name: str | None = "UTC",
    event_db_id: str | int | None = None,
    cursor: str | None = None,
    entity_id: str | int | None = None,
    related_event_allowed: _src.Callable[[int], bool] | None = None,
    entity_evidence_allowed: _src.Callable[[int], bool] | None = None,
    entity_security_event_candidates: _src.Callable[..., dict[str, _src.Any]] | None = None,
    authorization: _src.CutoverAuthorization | None = None,
    consumer: str = _src.StorageRouteConsumer.INVESTIGATIONS,
) -> dict[str, _src.Any]:
    """Return a query-led investigation view, never a global findings feed."""
    query = str(q or "").strip()
    anchor_event_db_id = _src.parse_investigation_event_id(event_db_id)
    exact_entity_id = _src.parse_investigation_entity_id(entity_id)
    if anchor_event_db_id is not None:
        start, end = _src.normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
        return _src._anchored_investigation_workspace_data(
            event_db_id=anchor_event_db_id,
            cursor=cursor,
            query=query,
            scope=scope,
            time_from_utc=start,
            time_to_utc_exclusive=end,
            timezone_name=timezone_name or "UTC",
            related_event_allowed=related_event_allowed,
            entity_id=exact_entity_id,
            authorization=authorization,
            consumer=consumer,
        )
    if cursor is not None:
        raise ValueError("invalid_cursor")
    if exact_entity_id is not None:
        start, end = _src.normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
        return _src._entity_investigation_workspace_data(
            entity_id=exact_entity_id,
            scope=scope,
            time_from_utc=start,
            time_to_utc_exclusive=end,
            timezone_name=timezone_name or "UTC",
            entity_evidence_allowed=entity_evidence_allowed,
            entity_security_event_candidates=entity_security_event_candidates,
            authorization=authorization,
            consumer=consumer,
        )
    # Storage V2 is the only route (plan 6.5): an investigation starts from an
    # exact event or entity; a free-text query alone has no V2 reader.
    _src.resolve_storage_route(authorization=authorization, consumer=consumer)
    raise _src.StorageRouteAuthorizationError(
        "storage_v2_investigation_requires_exact_event_id"
    )


def _anchored_investigation_workspace_data(
    *,
    event_db_id: int,
    cursor: str | None = None,
    query: str,
    scope: str | None,
    time_from_utc: str | None = None,
    time_to_utc_exclusive: str | None = None,
    timezone_name: str = "UTC",
    related_event_allowed: _src.Callable[[int], bool] | None = None,
    entity_id: int | None = None,
    authorization: _src.CutoverAuthorization | None = None,
    consumer: str = _src.StorageRouteConsumer.INVESTIGATIONS,
) -> dict[str, _src.Any]:
    """Build a bounded evidence chain anchored to one exact persisted event."""
    context = {
        "event_db_id": event_db_id,
        "entity_id": entity_id,
        "time_from_utc": time_from_utc,
        "time_to_utc_exclusive": time_to_utc_exclusive,
        "timezone": timezone_name,
        "anchor_in_window": None,
    }

    cursor_context = ["investigation", event_db_id, entity_id, query, scope, time_from_utc, time_to_utc_exclusive, timezone_name]
    relation_cursor = None
    if cursor is not None:
        position = decode_cursor(cursor, cursor_context)
        relation_cursor = position.get("relations")
        if not isinstance(relation_cursor, str) or not relation_cursor:
            raise ValueError("invalid_cursor")
    detail_kwargs: dict[str, _src.Any] = {"event_db_id": event_db_id, "limit": 1}
    if authorization is not None:
        detail_kwargs["authorization"] = authorization
        detail_kwargs["consumer"] = consumer
    base_items = _src.get_event_detail_report_data(**detail_kwargs).get("items") or []
    if not base_items:
        return {
            "query": query or f"Event DB {event_db_id}",
            "anchor_event_db_id": event_db_id,
            "context": context,
            "scope": scope or "important",
            "state": "empty",
            "summary": {
                "events_returned": 0,
                "has_more": False,
                "attention_level": "unknown",
                "story": "Опорное событие не найдено.",
                "why_it_matters": "Цепочка не построена без точного доказательства.",
            },
            "timeline": [],
            "findings": [],
            "next_checks": [],
            "limits": {"timeline": 0, "relations": 0, "full_history": False},
        }

    base = dict(base_items[0])
    relation_kwargs: dict[str, _src.Any] = {"limit": 40}
    if authorization is not None:
        relation_kwargs["authorization"] = authorization
        relation_kwargs["consumer"] = consumer
    if relation_cursor is not None:
        relation_kwargs["cursor"] = relation_cursor
    relation_page = _src.get_event_relations(event_db_id, **relation_kwargs)
    relation_items = list(relation_page.get("items") or [])
    relations_at_limit = bool(relation_page.get("truncated"))
    next_relation_cursor = relation_page.get("next_cursor")
    next_cursor = encode_cursor(cursor_context, {"relations": next_relation_cursor}) if next_relation_cursor else None
    if related_event_allowed is not None:
        # The HTTP owner supplies the caller's resource/report decision. Check
        # before hydrating related payloads; an anchor grant is not transitive.
        decisions: dict[int, bool] = {}
        permitted_relations = []
        for relation in relation_items:
            related_id = _src._exact_event_db_id({"event_db_id": relation.get("related_event_db_id")})
            if related_id is None:
                continue
            if related_id not in decisions:
                decisions[related_id] = related_event_allowed(related_id) is True
            if decisions[related_id]:
                permitted_relations.append(relation)
        relation_items = permitted_relations
    related_ids = [
        related_id
        for relation in relation_items
        if (related_id := _src._exact_event_db_id({"event_db_id": relation.get("related_event_db_id")})) is not None
    ]
    batch_kwargs: dict[str, _src.Any] = {}
    if authorization is not None:
        batch_kwargs["authorization"] = authorization
        batch_kwargs["consumer"] = consumer
    related_by_id = _src.get_event_details_by_ids(related_ids, **batch_kwargs)
    anchor_source = _src._detail_timeline_source(base, "Опорное событие расследования.")
    timeline_sources = [anchor_source] if cursor is None else []
    for relation in relation_items:
        related_id = _src._exact_event_db_id({"event_db_id": relation.get("related_event_db_id")})
        if related_id is None:
            continue
        related = related_by_id.get(related_id)
        if related is None:
            continue
        reason = str(relation.get("reason") or relation.get("explanation") or "Связанное доказательство.")
        timeline_sources.append(_src._detail_timeline_source(dict(related), reason))
    def event_time(item: dict[str, _src.Any]) -> _src.datetime | None:
        raw = item.get("time")
        if not raw:
            return None
        try:
            parsed = _src.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed.astimezone(_src.timezone.utc) if parsed.tzinfo is not None else None

    start = _src.datetime.fromisoformat(time_from_utc.replace("Z", "+00:00")) if time_from_utc else None
    end = _src.datetime.fromisoformat(time_to_utc_exclusive.replace("Z", "+00:00")) if time_to_utc_exclusive else None

    def in_window(item: dict[str, _src.Any]) -> bool:
        instant = event_time(item)
        return instant is not None and (start is None or instant >= start) and (end is None or instant < end)

    unknown_time_count = sum(event_time(item) is None for item in timeline_sources)
    context["anchor_in_window"] = in_window(anchor_source) if event_time(anchor_source) else None
    if start is not None or end is not None:
        timeline_sources = [item for item in timeline_sources if in_window(item)]
    timeline_sources.sort(
        key=lambda item: (str(item.get("time") or ""), int(item.get("event_db_id") or 0)),
        reverse=True,
    )
    card = _src.build_event_card(base)
    known = bool(card.get("known"))
    anchor_classification = {
        "risk": str(card.get("final_risk") or "unknown") if known else "unknown",
        "classification_origin": str(card.get("classification_origin") or "unavailable"),
        "card_completeness": str(card.get("card_completeness") or "not_applicable"),
    }
    checks = [str(item) for item in (card.get("checks") or [])[:7]] if known else ["Проверить исходные поля опорного события."]
    return {
        "next_cursor": next_cursor,
        "query": query or f"Event DB {event_db_id}",
        "anchor_event_db_id": event_db_id,
        "context": context,
        "scope": scope or "important",
        "state": "ok" if timeline_sources else "empty",
        "summary": {
            "events_returned": len(timeline_sources),
            "has_more": relations_at_limit,
            "attention_level": "unknown",
            "anchor_classification": anchor_classification,
            "story": str(card.get("summary") or "Событие пока не расшифровано каталогом."),
            "story_code": card.get("summary_code"),
            "why_it_matters_code": "investigations.exact_chain",
            "why_it_matters": "Цепочка начинается с выбранного точного evidence и содержит только объяснимые связи.",
        },
        "timeline": [_src._timeline_item(item) for item in timeline_sources[:_src.INVESTIGATION_TIMELINE_LIMIT]],
        "findings": [],
        "next_checks": checks,
        "next_check_codes": (card.get("check_codes") or [])[:len(checks)] if known else [],
        "limits": {
            "timeline": _src.INVESTIGATION_TIMELINE_LIMIT,
            "relations": 40,
            "full_history": False,
            "anchor_contract": "exact_event_db_id",
            "events_with_unknown_time": unknown_time_count,
        },
    }


def _empty_entity_history(
    *,
    entity_id: int,
    time_from_utc: _src.Any,
    time_to_utc_exclusive: _src.Any,
    timezone_name: str,
    scope: str | None,
) -> dict[str, _src.Any]:
    """Пустая история объекта: подтверждённых доступных событий нет."""
    return {
        "query": "",
        "anchor_event_db_id": None,
        "context": {
            "entity_id": entity_id,
            "time_from_utc": time_from_utc,
            "time_to_utc_exclusive": time_to_utc_exclusive,
            "timezone": timezone_name,
            "anchor_in_window": None,
        },
        "scope": scope or "all",
        "state": "ok",
        "summary": {
            "events_returned": 0,
            "has_more": False,
            "attention_level": "unknown",
            "story": "Для объекта нет подтверждённых событий в выбранном периоде.",
            "why_it_matters": "Отсутствие связи в сохранённых данных не доказывает отсутствие активности.",
        },
        "timeline": [],
        "findings": [],
        "next_checks": ["Расширьте период или откройте событие по точному идентификатору."],
        "limits": {
            "timeline": _src.INVESTIGATION_TIMELINE_LIMIT,
            "full_history": False,
            "coverage": "bounded_exact_entity_evidence",
        },
    }


def _entity_investigation_workspace_data(
    *,
    entity_id: int,
    scope: str | None,
    time_from_utc: str | None,
    time_to_utc_exclusive: str | None,
    timezone_name: str,
    entity_evidence_allowed: _src.Callable[[int], bool] | None,
    entity_security_event_candidates: _src.Callable[..., dict[str, _src.Any]] | None,
    authorization: _src.CutoverAuthorization | None,
    consumer: str,
) -> dict[str, _src.Any]:
    """Build history only from exact entity-to-event evidence, never names."""
    if str(_src.resolve_storage_route(
        authorization=authorization, consumer=consumer
    ).get("route") or "v1") != "v2":
        raise _src.StorageRouteAuthorizationError(
            "storage_v2_investigation_requires_exact_entity_id"
        )
    security_candidate_path = (
        entity_security_event_candidates is not None
        and time_from_utc is not None
        and time_to_utc_exclusive is not None
    )
    canonical_candidates: list[dict[str, _src.Any]] = []
    candidate_ids: list[int] = []
    if security_candidate_path:
        candidate_report = entity_security_event_candidates(
            entity_id=entity_id,
            time_from_utc=time_from_utc,
            time_to_utc_exclusive=time_to_utc_exclusive,
            timezone_name=timezone_name,
            limit=_src.INVESTIGATION_TIMELINE_LIMIT + 1,
        )
        if str(candidate_report.get("state") or "") == "available":
            candidate_ids = list(dict.fromkeys(
                event_db_id for row in candidate_report.get("items") or []
                if (event_db_id := _src._exact_event_db_id(row)) is not None
            ))
    else:
        try:
            canonical_candidates = _src._get_entity_evidence_event_rows(
                entity_id=entity_id,
                limit=_src.INVESTIGATION_TIMELINE_LIMIT + 1,
                before_time_utc=None,
                before_event_db_id=None,
                time_from_utc=time_from_utc,
                time_to_utc_exclusive=time_to_utc_exclusive,
                id_only=True,
            )
        except _src.QueryTimeoutError as exc:
            raise _src.EntityEvidenceLookupError("unavailable") from exc
        candidate_ids = list(dict.fromkeys(
            event_db_id for row in canonical_candidates
            if (event_db_id := _src._exact_event_db_id(row)) is not None
        ))
    # Before per-event authorization the boundary carries identifiers only.
    # Real timestamps are hydrated and sorted only after every exact proof is admitted.
    # «Нет доказательств» и «все доказательства недоступны» дают один и тот же
    # пустой честный ответ 200: по коду нельзя отличить отсутствие связей от
    # скрытых прав, а страница расследования не получает ложную ошибку 404.
    permitted_ids = [
        event_db_id for event_db_id in candidate_ids
        if entity_evidence_allowed is not None and entity_evidence_allowed(event_db_id) is True
    ]
    if not permitted_ids:
        return _empty_entity_history(
            entity_id=entity_id,
            time_from_utc=time_from_utc,
            time_to_utc_exclusive=time_to_utc_exclusive,
            timezone_name=timezone_name,
            scope=scope,
        )
    metadata_event_ids = (
        permitted_ids
        if security_candidate_path
        else permitted_ids[:_src.INVESTIGATION_TIMELINE_LIMIT]
    )
    try:
        metadata_rows = _src._get_entity_evidence_event_rows(
            entity_id=entity_id,
            limit=len(metadata_event_ids),
            before_time_utc=None,
            before_event_db_id=None,
            time_from_utc=time_from_utc,
            time_to_utc_exclusive=time_to_utc_exclusive,
            event_db_ids=metadata_event_ids,
            field_projection="security_history",
            preauthorized_exact_event_ids=security_candidate_path,
        )
    except _src.QueryTimeoutError as exc:
        raise _src.EntityEvidenceLookupError("unavailable") from exc
    metadata_by_id = {
        event_db_id: dict(row)
        for row in metadata_rows
        if (event_db_id := _src._exact_event_db_id(row)) is not None
    }
    if any(event_db_id not in metadata_by_id for event_db_id in metadata_event_ids):
        raise _src.EntityEvidenceLookupError("unavailable")
    ordered_metadata_rows = sorted(
        (metadata_by_id[event_db_id] for event_db_id in metadata_event_ids),
        key=_src._entity_candidate_sort_key,
        reverse=True,
    )
    has_more = len(permitted_ids) > _src.INVESTIGATION_TIMELINE_LIMIT
    visible_metadata_rows = ordered_metadata_rows[:_src.INVESTIGATION_TIMELINE_LIMIT]
    timeline_sources = [
        _src._metadata_timeline_source(
            row,
            (
                "Точное совпадение SID события или сохранённой связи с сущностью; "
                "совпадение имени не использовалось."
                if security_candidate_path
                else "Точное evidence сущности; связь не доказывает причинность."
            ),
        )
        for row in visible_metadata_rows
        if _src._exact_event_db_id(row) is not None
    ]
    return {
        "query": "",
        "anchor_event_db_id": None,
        "context": {
            "entity_id": entity_id,
            "time_from_utc": time_from_utc,
            "time_to_utc_exclusive": time_to_utc_exclusive,
            "timezone": timezone_name,
            "anchor_in_window": None,
        },
        "scope": scope or "all",
        "state": "ok",
        "summary": {
            "events_returned": len(timeline_sources),
            "has_more": has_more,
            "attention_level": "unknown",
            "story": "Показаны только события, где объект подтверждён точным идентификатором.",
            "why_it_matters": "Связь сущности с событием не доказывает причинность или вывод расследования.",
        },
        "timeline": [_src._timeline_item(item) for item in timeline_sources],
        "findings": [],
        "next_checks": ["Точная связь объекта с событием не является причинной цепочкой."],
        "limits": {
            "timeline": _src.INVESTIGATION_TIMELINE_LIMIT,
            "full_history": False,
            "coverage": "bounded_exact_entity_evidence",
        },
    }
