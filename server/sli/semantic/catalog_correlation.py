"""Compile storage correlation declarations from the canonical event catalogue."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable

from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.events.event_catalog_quality import STORAGE_EVENT_FIELDS


_SQL_ALIAS = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True)
class CatalogPairRule:
    source: str
    stream: str
    open_event_key: str
    close_event_key: str
    open_event_id: int
    close_event_id: int
    key_fields: tuple[str, ...]
    close_timeout_seconds: int
    rollup: str


def compile_catalog_pair_rules(
    entries: Iterable[dict[str, Any]] | None = None,
) -> tuple[CatalogPairRule, ...]:
    """Return only complete pair rules; inconsistent declarations fail closed."""
    source_entries = [
        dict(entry)
        for entry in (
            entries if entries is not None else all_event_catalog_entries()
        )
    ]
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in source_entries:
        identity = _identity(entry)
        if not all(identity):
            continue
        if identity in index:
            raise ValueError(
                f"catalog_pair_duplicate_identity:{'/'.join(identity)}"
            )
        index[identity] = entry
    rules: list[CatalogPairRule] = []
    for opener in source_entries:
        correlation = opener.get("correlation")
        if not isinstance(correlation, dict):
            continue
        if correlation.get("role") != "open" or correlation.get("cardinality") != "pair":
            continue
        terminators = correlation.get("terminators")
        if not isinstance(terminators, list) or len(terminators) != 1:
            raise ValueError("catalog_pair_opener_requires_exactly_one_terminator")
        source, stream, open_event_key = _identity(opener)
        close_event_key = str(terminators[0]).strip()
        closer = index.get((source, stream, close_event_key.casefold()))
        if closer is None:
            raise ValueError(
                f"catalog_pair_terminator_missing:{source}/{stream}/{close_event_key}"
            )
        close_correlation = closer.get("correlation")
        if not isinstance(close_correlation, dict):
            raise ValueError("catalog_pair_terminator_has_no_correlation")
        if (
            close_correlation.get("role") != "close"
            or close_correlation.get("cardinality") != "pair"
        ):
            raise ValueError("catalog_pair_terminator_role_mismatch")

        key_fields = _key_fields(correlation)
        if key_fields != _key_fields(close_correlation):
            raise ValueError("catalog_pair_key_mismatch")
        timeout = int(correlation.get("close_timeout_seconds") or 0)
        if timeout <= 0 or timeout != int(
            close_correlation.get("close_timeout_seconds") or 0
        ):
            raise ValueError("catalog_pair_timeout_mismatch")
        rollup = str((opener.get("lifecycle") or {}).get("rollup") or "").strip()
        if not rollup or rollup != str(
            (closer.get("lifecycle") or {}).get("rollup") or ""
        ).strip():
            raise ValueError("catalog_pair_rollup_mismatch")
        rules.append(
            CatalogPairRule(
                source=str(opener["source"]),
                stream=str(opener["stream"]),
                open_event_key=str(opener["event_key"]),
                close_event_key=str(closer["event_key"]),
                open_event_id=_numeric_event_id(opener),
                close_event_id=_numeric_event_id(closer),
                key_fields=key_fields,
                close_timeout_seconds=timeout,
                rollup=rollup,
            )
        )
    return tuple(
        sorted(
            rules,
            key=lambda rule: (
                rule.source.casefold(),
                rule.stream.casefold(),
                rule.open_event_key.casefold(),
            ),
        )
    )


def get_catalog_pair_rule(
    source: str,
    stream: str,
    open_event_key: str,
    *,
    entries: Iterable[dict[str, Any]] | None = None,
) -> CatalogPairRule:
    wanted = (
        str(source).strip().casefold(),
        str(stream).strip().casefold(),
        str(open_event_key).strip().casefold(),
    )
    matches = [
        rule
        for rule in compile_catalog_pair_rules(entries)
        if (
            rule.source.casefold(),
            rule.stream.casefold(),
            rule.open_event_key.casefold(),
        )
        == wanted
    ]
    if len(matches) != 1:
        raise ValueError(
            f"catalog_pair_rule_not_unique:{source}/{stream}/{open_event_key}"
        )
    return matches[0]


def postgres_open_event_predicate(
    rule: CatalogPairRule,
    *,
    alias: str,
) -> str:
    _validate_alias(alias)
    return (
        f"{alias}.event_id={rule.open_event_id} and "
        f"{alias}.channel_id=(select id from storage_v2_channel "
        f"where value={_sql_literal(rule.stream)})"
    )


def postgres_close_event_predicate(
    rule: CatalogPairRule,
    *,
    alias: str,
) -> str:
    _validate_alias(alias)
    return (
        f"{alias}.event_id={rule.close_event_id} and "
        f"{alias}.channel_id=(select id from storage_v2_channel "
        f"where value={_sql_literal(rule.stream)})"
    )


def postgres_pair_match_predicate(
    rule: CatalogPairRule,
    *,
    open_alias: str,
    close_alias: str,
) -> str:
    """Build the bounded Storage V2 join from the declaration, not event constants."""
    _validate_alias(open_alias)
    _validate_alias(close_alias)
    conditions = [
        postgres_close_event_predicate(rule, alias=close_alias),
        f"{close_alias}.server_id={open_alias}.server_id",
        f"{close_alias}.channel_id={open_alias}.channel_id",
        *(
            f"{close_alias}.{field}={open_alias}.{field}"
            for field in rule.key_fields
        ),
        f"{close_alias}.time_created_utc>={open_alias}.time_created_utc",
        (
            f"{close_alias}.time_created_utc<="
            f"{open_alias}.time_created_utc + "
            f"interval '{rule.close_timeout_seconds} seconds'"
        ),
    ]
    return " and ".join(conditions)


def _identity(entry: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(entry.get("source") or "").strip().casefold(),
        str(entry.get("stream") or "").strip().casefold(),
        str(entry.get("event_key") or "").strip().casefold(),
    )


def _key_fields(correlation: dict[str, Any]) -> tuple[str, ...]:
    raw = correlation.get("key")
    values = raw if isinstance(raw, list) else [raw]
    fields = tuple(str(value or "").strip() for value in values)
    if not fields or any(field not in STORAGE_EVENT_FIELDS for field in fields):
        raise ValueError("catalog_pair_key_not_in_storage_v2")
    return fields


def _numeric_event_id(entry: dict[str, Any]) -> int:
    raw = entry.get("event_id")
    if isinstance(raw, bool):
        raise ValueError("catalog_pair_event_id_must_be_numeric")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("catalog_pair_event_id_must_be_numeric") from exc
    if value <= 0:
        raise ValueError("catalog_pair_event_id_must_be_numeric")
    return value


def _validate_alias(alias: str) -> None:
    if not _SQL_ALIAS.fullmatch(str(alias)):
        raise ValueError("unsafe_sql_alias")


def _sql_literal(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"
