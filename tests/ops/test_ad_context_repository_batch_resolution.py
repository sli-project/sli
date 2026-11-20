import pytest

from datetime import datetime, timezone

from server.ad_context.repository import AdContextOutOfOrderError, _preload_existing_entity_ids, _start_run


def _entity(key: str, sid: str, guid: str | None = None) -> dict:
    return {
        "record_type": "entity",
        "record_key": key,
        "identity": {
            "kind": "ad_user",
            "object_sid": sid,
            "object_guid": guid or f"guid-{key}",
        },
    }


class _Cursor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self.rows: list[dict] = []

    def execute(self, sql: str, params: tuple) -> None:
        normalized = " ".join(sql.split()).lower()
        self.calls.append((normalized, params))
        if "alias_type='object_sid'" in normalized:
            self.rows = [{
                "normalized_value": "sid-alias",
                "entity_id": 11,
                "domain_id": 7,
                "natural_key": "canonical:user-alias",
                "entity_type": "ad_user",
            }]
        elif "alias_type='object_guid'" in normalized:
            self.rows = [{
                "normalized_value": "guid-user-alias",
                "entity_id": 11,
            }]
        elif "entity.natural_key = any" in normalized:
            self.rows = [
                {
                    "id": 22,
                    "natural_key": "user-natural",
                    "entity_type": "ad_user",
                }
            ]
        elif "lower(details.attributes_json->>'sid') = any" in normalized:
            self.rows = [
                {
                    "normalized_sid": "sid-json",
                    "entity_id": 33,
                    "domain_id": 7,
                    "natural_key": "user-json",
                    "entity_type": "ad_user",
                },
                {
                    "normalized_sid": "sid-duplicate",
                    "entity_id": 44,
                    "domain_id": 7,
                    "natural_key": "user-ambiguous",
                    "entity_type": "ad_user",
                },
                {
                    "normalized_sid": "sid-duplicate",
                    "entity_id": 45,
                    "domain_id": 7,
                    "natural_key": "other-user",
                    "entity_type": "ad_user",
                },
            ]
        else:  # pragma: no cover - protects the query contract
            raise AssertionError(normalized)

    def fetchall(self) -> list[dict]:
        return list(self.rows)


def test_bundle_resolution_batches_alias_natural_key_and_json_sid_lookup() -> None:
    cursor = _Cursor()
    records = [
        _entity("user-alias", "SID-ALIAS"),
        _entity("user-natural", "SID-NATURAL"),
        _entity("user-json", "SID-JSON"),
        _entity("user-ambiguous", "SID-DUPLICATE"),
    ]

    resolved = _preload_existing_entity_ids(cursor, 7, records)

    assert resolved == {
        "user-alias": 11,
        "user-natural": 22,
        "user-json": 33,
    }
    assert len(cursor.calls) == 4
    json_calls = [
        call for call in cursor.calls
        if "lower(details.attributes_json->>'sid') = any" in call[0]
    ]
    assert len(json_calls) == 1
    assert set(json_calls[0][1][1]) == {
        "sid-json",
        "sid-duplicate",
    }


def test_sid_alias_accepts_a_different_canonical_natural_key() -> None:
    cursor = _Cursor()

    assert _preload_existing_entity_ids(
        cursor,
        7,
        [_entity("user-alias", "SID-ALIAS")],
    ) == {"user-alias": 11}


@pytest.mark.parametrize(
    ("domain_id", "entity_type"),
    [
        (8, "ad_user"),
        (7, "ad_computer"),
    ],
)
def test_sid_alias_cannot_cross_domain_or_entity_type(
    domain_id: int,
    entity_type: str,
) -> None:
    cursor = _Cursor()

    def conflicting_execute(sql: str, params: tuple) -> None:
        normalized = " ".join(sql.split()).lower()
        cursor.calls.append((normalized, params))
        if "alias_type='object_sid'" in normalized:
            cursor.rows = [{
                "normalized_value": "sid-alias",
                "entity_id": 11,
                "domain_id": domain_id,
                "natural_key": "canonical:user-alias",
                "entity_type": entity_type,
            }]
        elif "alias_type='object_guid'" in normalized:
            cursor.rows = [{
                "normalized_value": "guid-user-alias",
                "entity_id": 11,
            }]
        else:  # pragma: no cover - the conflict must fail before more lookups
            raise AssertionError(normalized)

    cursor.execute = conflicting_execute  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="SID alias conflicts"):
        _preload_existing_entity_ids(
            cursor,
            7,
            [_entity("user-alias", "SID-ALIAS")],
        )


def test_sid_alias_cannot_conflict_with_object_guid_alias() -> None:
    cursor = _Cursor()

    def conflicting_execute(sql: str, params: tuple) -> None:
        normalized = " ".join(sql.split()).lower()
        cursor.calls.append((normalized, params))
        if "alias_type='object_sid'" in normalized:
            cursor.rows = [{
                "normalized_value": "sid-alias",
                "entity_id": 11,
                "domain_id": 7,
                "natural_key": "canonical:user-alias",
                "entity_type": "ad_user",
            }]
        elif "alias_type='object_guid'" in normalized:
            cursor.rows = [{
                "normalized_value": "guid-user-alias",
                "entity_id": 12,
            }]
        else:  # pragma: no cover - the conflict must fail before more lookups
            raise AssertionError(normalized)

    cursor.execute = conflicting_execute  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="SID alias conflicts"):
        _preload_existing_entity_ids(
            cursor,
            7,
            [_entity("user-alias", "SID-ALIAS")],
        )


@pytest.mark.parametrize("compatible_ids", [[], [33], [33, 34]])
def test_json_sid_fallback_ignores_legacy_entities_of_another_type(compatible_ids) -> None:
    cursor = _Cursor()

    def execute(sql: str, params: tuple) -> None:
        normalized = " ".join(sql.split()).lower()
        cursor.calls.append((normalized, params))
        cursor.rows = []
        if "lower(details.attributes_json->>'sid') = any" in normalized:
            # Historical event identities can store a group's SID as ad_user.
            cursor.rows = [{
                "normalized_sid": "sid-group", "entity_id": 11,
                "domain_id": 7, "natural_key": "legacy:user",
                "entity_type": "ad_user",
            }] + [{
                "normalized_sid": "sid-group", "entity_id": entity_id,
                "domain_id": 7, "natural_key": f"canonical:group-{entity_id}",
                "entity_type": "ad_group",
            } for entity_id in compatible_ids]

    cursor.execute = execute  # type: ignore[method-assign]
    group = _entity("group-key", "SID-GROUP")
    group["identity"]["kind"] = "ad_group"
    expected = {"group-key": compatible_ids[0]} if len(compatible_ids) == 1 else {}
    assert _preload_existing_entity_ids(cursor, 7, [group]) == expected


class _RunCursor:
    def __init__(self, latest_rows: list[dict]) -> None:
        self.latest_rows = latest_rows
        self.current = ""
        self.params: list[tuple] = []

    def execute(self, sql: str, params: tuple) -> None:
        self.current = " ".join(sql.split()).lower()
        self.params.append(params)

    def fetchone(self):
        if "where run_id=%s" in self.current:
            return None
        raise AssertionError(self.current)

    def fetchall(self):
        if "join ad_context_sections" in self.current:
            return list(self.latest_rows)
        raise AssertionError(self.current)


def _run_bundle() -> dict:
    return {
        "run_id": "00000000-0000-4000-8000-000000000001",
        "bundle_sha256": "11" * 32,
        "source_pack_id": "sli.windows.ad-context",
        "source_pack_version": "1",
        "mode": "full",
        "observed_at_utc": "2026-07-27T11:00:00Z",
        "scope": {
            "search_base": "DC=example,DC=test",
            "privileged_group_sids": ["S-1-5-21-512"],
            "vpn_group_sids": [],
        },
        "sections": [{"name": "directory_accounts"}],
    }


def test_run_watermark_is_scoped_to_the_bundle_section() -> None:
    cursor = _RunCursor([])
    assert _start_run(cursor, 7, _run_bundle()) is False
    watermark_params = next(
        params
        for params in cursor.params
        if len(params) == 3 and params[1] == "sli.windows.ad-context"
    )
    assert watermark_params[2] == ["directory_accounts"]
    insert_params = next(params for params in cursor.params if len(params) == 8)
    assert insert_params[-1] == '{"privileged_group_sids": ["S-1-5-21-512"], "search_base": "DC=example,DC=test", "vpn_group_sids": []}'


def test_run_watermark_rejects_a_stale_snapshot_of_the_same_section() -> None:
    cursor = _RunCursor([
        {
            "section_name": "directory_accounts",
            "latest": datetime(2026, 7, 27, 12, tzinfo=timezone.utc),
        }
    ])
    with pytest.raises(AdContextOutOfOrderError, match="directory_accounts"):
        _start_run(cursor, 7, _run_bundle())
    assert not any(len(params) == 8 for params in cursor.params)
