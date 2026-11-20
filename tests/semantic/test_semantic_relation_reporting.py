from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.api.errors import RequestInputError
from server.api.routes import semantic as routes_semantic
from server.sli.semantic import semantic_relation_reporting as reporting


UTC = timezone.utc


@pytest.fixture(autouse=True)
def _supported_investigation_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        reporting,
        "_read_supported_rules",
        lambda: [{"rule_id": "investigation.account.unlock.after-lock", "rule_version": 2, "lifecycle_status": "shadow"}],
    )


def _access(
    *,
    scoped_semantic_review: bool = False,
    grants: list[dict] | None = None,
) -> dict:
    access = {
        "platform_owner": False,
        "capabilities": ["evidence.exact", "field.security", "events.view"],
        "capability_policies": [],
        "reports": [{
            "report_key": "security.events.chains",
            "allowed": True,
            "allowed_actions": ["view"],
            "grants": grants if grants is not None else [{
                "allowed_actions": ["view"],
                "field_categories": ["security", "technical", "raw_evidence"],
                "scope": {"kind": "all"},
            }],
        }],
    }
    if scoped_semantic_review:
        access["capability_policies"] = [{
            "capability_key": "semantic.review", "effect": "allow", "valid": True,
            "scope": {"kind": "domain", "ids": [7]},
        }]
    else:
        access["capabilities"].append("semantic.review")
    return access


def _preflight(candidate_id: str, *domains: int) -> dict:
    return {
        "candidate_id": candidate_id,
        "window_end_utc": datetime(2026, 9, 1, 10, tzinfo=UTC),
        "evidence": [
            {"event_db_id": 100 + index, "server_id": 30 + index, "domain_id": domain, "channel": "Security"}
            for index, domain in enumerate(domains)
        ],
    }


def _hydrated(candidate_id: str) -> dict:
    return {
        "candidate_id": candidate_id,
        "rule_id": "lockout-preceded-by-failures",
        "rule_version": 1,
        "relation_kind": "authentication.lockout_preceded_by_failures",
        "window_start_utc": datetime(2026, 9, 1, 9, 55, tzinfo=UTC),
        "window_end_utc": datetime(2026, 9, 1, 10, tzinfo=UTC),
        "confidence": "medium",
        "explanation": "Observed exact source events; no causal claim.",
        "evidence": [{
            "event_db_id": 100,
            "event_id": 4740,
            "time_created_utc": datetime(2026, 9, 1, 10, tzinfo=UTC),
            "semantic_type": "account.lockout",
            "source_host": "dc01.example.test",
            "channel": "Security",
            "evidence_order": 0,
        }],
    }


def test_relation_reader_omits_candidate_when_any_exact_evidence_is_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = _preflight("00000000-0000-0000-0000-000000000001", 7)
    denied = _preflight("00000000-0000-0000-0000-000000000002", 7, 8)
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([allowed, denied], False))
    hydrated_ids: list[str] = []
    monkeypatch.setattr(
        reporting,
        "_read_authorized_candidates",
        lambda candidate_ids: hydrated_ids.extend(candidate_ids) or [_hydrated(candidate_ids[0])],
    )

    payload = reporting.get_semantic_relations(
        _access(scoped_semantic_review=True),
        domain_id=7,
        time_from="2026-09-01T09:00:00Z",
        time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC",
    )

    assert payload["state"] == "available"
    assert [item["candidate_id"] for item in payload["items"]] == [allowed["candidate_id"]]
    assert hydrated_ids == [allowed["candidate_id"]]
    assert "00000000-0000-0000-0000-000000000002" not in repr(payload)
    assert payload["items"][0]["evidence"][0]["event_db_id"] == 100


def test_relation_reader_omits_late_denied_evidence_before_any_payload_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000023", 7)
    hydrated = _hydrated(candidate["candidate_id"])
    hydrated["evidence"][0].update({"server_id": 30, "domain_id": 7})
    # This atom was appended after preflight in the former two-transaction
    # flow. It is denied by the domain-scoped semantic-review policy.
    hydrated["evidence"].append({
        **hydrated["evidence"][0], "event_db_id": 101, "evidence_order": 1,
        "server_id": 31, "domain_id": 8,
    })
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([candidate], False))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda _ids: [hydrated])

    payload = reporting.get_semantic_relations(
        _access(scoped_semantic_review=True), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )

    assert payload["state"] == "empty"
    assert payload["items"] == []
    assert payload["has_more"] is False and payload["next_cursor"] is None
    assert payload["coverage"]["matched_relation_count"] is None
    assert "101" not in repr(payload)


def test_relation_reader_fails_closed_for_partial_hydration_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _preflight("00000000-0000-0000-0000-000000000024", 7)
    second = _preflight("00000000-0000-0000-0000-000000000025", 7)
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([first, second], False))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(ids[0])])

    payload = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC", limit=2,
    )

    assert payload["state"] == "empty" and payload["items"] == []
    assert payload["has_more"] is False and payload["next_cursor"] is None
    assert payload["coverage"]["matched_relation_count"] is None
    assert payload["coverage"]["observed_rules"] == []
    assert first["candidate_id"] not in repr(payload)


def test_present_relation_strips_internal_resource_tuple_without_ambiguity() -> None:
    relation = _hydrated("00000000-0000-0000-0000-000000000026")
    relation["evidence"][0].update({"server_id": 30, "domain_id": 7})

    item = reporting._present_relation(relation)

    assert "server_id" not in item["evidence"][0]
    assert "domain_id" not in item["evidence"][0]


@pytest.mark.parametrize(
    ("partition_key", "expected"),
    (
        (
            "domain:7|account_sid:S-1-5-21-100-200-300-1001",
            {
                "kind": "exact_domain_account_sid",
                "domain_id": 7,
                "account_sid": "S-1-5-21-100-200-300-1001",
            },
        ),
        (
            "domain:7|member_sid:S-1-5-21-100-200-300-1002|group_sid:S-1-5-21-100-200-300-512",
            {
                "kind": "exact_domain_member_group_sid",
                "domain_id": 7,
                "member_sid": "S-1-5-21-100-200-300-1002",
                "group_sid": "S-1-5-21-100-200-300-512",
            },
        ),
        (
            "domain:7|account_member_sid:S-1-5-21-100-200-300-1003",
            {
                "kind": "exact_domain_account_member_sid",
                "domain_id": 7,
                "account_member_sid": "S-1-5-21-100-200-300-1003",
            },
        ),
    ),
)
def test_present_relation_exposes_typed_exact_identity_basis_after_authorization(
    partition_key: str, expected: dict[str, object],
) -> None:
    relation = _hydrated("00000000-0000-0000-0000-000000000035")
    relation["partition_key"] = partition_key

    item = reporting._present_relation(relation)

    assert item["identity_basis"] == expected
    assert "partition_key" not in item


def test_present_relation_does_not_expose_unknown_internal_partition_key() -> None:
    relation = _hydrated("00000000-0000-0000-0000-000000000036")
    relation["partition_key"] = "untyped:secret-internal-value"

    item = reporting._present_relation(relation)

    assert "identity_basis" not in item
    assert "partition_key" not in item


def test_present_relation_does_not_label_malformed_sid_as_exact_identity() -> None:
    relation = _hydrated("00000000-0000-0000-0000-000000000037")
    relation["partition_key"] = "domain:7|account_sid:not-a-sid"

    item = reporting._present_relation(relation)

    assert "identity_basis" not in item
    assert "partition_key" not in item


def test_present_relation_does_not_label_non_numeric_domain_sid_as_exact_identity() -> None:
    relation = _hydrated("00000000-0000-0000-0000-000000000038")
    relation["partition_key"] = "domain:7|account_sid:S-1-5-21-not-numeric"

    item = reporting._present_relation(relation)

    assert "identity_basis" not in item
    assert "partition_key" not in item


def test_snapshot_context_and_cursor_close_after_read_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[str] = []

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): closed.append("cursor")
        def execute(self, *_args): pass

    class Connection:
        def __enter__(self): return self
        def __exit__(self, *_args): closed.append("connection")
        def cursor(self): return Cursor()

    monkeypatch.setattr(reporting, "_connect", lambda: Connection())

    def fail_after_snapshot(**_kwargs):
        reporting._ACTIVE_RELATION_SNAPSHOT.get().cursor()
        raise RuntimeError("read failed")

    monkeypatch.setattr(reporting, "_read_candidate_preflight", fail_after_snapshot)
    with pytest.raises(RuntimeError, match="read failed"):
        reporting._read_visible_relation_page(
            access=_access(), domain=7,
            start=datetime(2026, 9, 1, 9, tzinfo=UTC), end=datetime(2026, 9, 1, 11, tzinfo=UTC),
            filters={}, limit=1, before=None, access_preflight="allow",
        )

    assert closed == ["cursor", "connection"]
    assert reporting._ACTIVE_RELATION_SNAPSHOT.get() is None


def test_relation_reader_denies_missing_required_report_category_before_hydration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000003", 7)
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([candidate], False))
    monkeypatch.setattr(
        reporting,
        "_read_authorized_candidates",
        lambda *_args, **_kwargs: pytest.fail("report field denial must occur before hydration"),
    )

    payload = reporting.get_semantic_relations(
        _access(grants=[{
            "allowed_actions": ["view"],
            "field_categories": ["security", "technical"],
            "scope": {"kind": "all"},
        }]),
        domain_id=7,
        time_from="2026-09-01T09:00:00Z",
        time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC",
    )

    assert payload["state"] == "not_authorized"
    assert payload["items"] == []
    assert payload["has_more"] is False
    assert payload["next_cursor"] is None
    assert candidate["candidate_id"] not in repr(payload)


def test_relation_reader_does_not_union_report_grants_for_action_fields_and_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000004", 7)
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([candidate], False))
    monkeypatch.setattr(
        reporting,
        "_read_authorized_candidates",
        lambda *_args, **_kwargs: pytest.fail("split report grants must not authorize hydration"),
    )

    payload = reporting.get_semantic_relations(
        _access(grants=[
            {
                "allowed_actions": ["view"],
                "field_categories": ["security", "technical"],
                "scope": {"kind": "domain", "ids": [7]},
            },
            {
                "allowed_actions": ["export"],
                "field_categories": ["raw_evidence"],
                "scope": {"kind": "domain", "ids": [7]},
            },
            {
                "allowed_actions": ["view"],
                "field_categories": ["security", "technical", "raw_evidence"],
                "scope": {"kind": "domain", "ids": [8]},
            },
        ]),
        domain_id=7,
        time_from="2026-09-01T09:00:00Z",
        time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC",
    )

    assert payload["state"] == "not_authorized"
    assert payload["items"] == []
    assert candidate["candidate_id"] not in repr(payload)


def test_relation_reader_allows_one_complete_report_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000005", 7)
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([candidate], False))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(ids[0])])

    payload = reporting.get_semantic_relations(
        _access(),
        domain_id=7,
        time_from="2026-09-01T09:00:00Z",
        time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC",
    )

    assert payload["state"] == "available"
    assert [item["candidate_id"] for item in payload["items"]] == [candidate["candidate_id"]]
    assert payload["coverage"]["supported_rules_state"] == "available"
    assert payload["coverage"]["limitation_codes"] == ["bounded_retained_page", "no_completeness_proof"]
    assert len(payload["coverage"]["limitations"]) >= len(payload["coverage"]["limitation_codes"])

    assert payload["coverage"]["supported_rules"] == [
        {"rule_id": "investigation.account.unlock.after-lock", "rule_version": 2, "lifecycle_status": "shadow"},
    ]
    assert payload["coverage"]["observed_rules"] == [
        {"rule_id": "lockout-preceded-by-failures", "rule_version": 1},
    ]


def test_relation_reader_allows_server_scoped_report_and_capability_grants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000016", 7)
    access = _access(grants=[{
        "allowed_actions": ["view"],
        "field_categories": ["security", "technical", "raw_evidence"],
        "scope": {"kind": "server", "ids": [30]},
    }])
    access["capabilities"].remove("semantic.review")
    access["capability_policies"] = [{
        "capability_key": "semantic.review", "effect": "allow", "valid": True,
        "scope": {"kind": "server", "ids": [30]},
    }]
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([candidate], False))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(ids[0])])

    payload = reporting.get_semantic_relations(
        access, domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )

    assert payload["state"] == "available"
    assert [item["candidate_id"] for item in payload["items"]] == [candidate["candidate_id"]]


def test_server_scoped_preflight_without_candidates_is_empty_not_denied(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    access = _access(grants=[{
        "allowed_actions": ["view"],
        "field_categories": ["security", "technical", "raw_evidence"],
        "scope": {"kind": "server", "ids": [30]},
    }])
    access["capabilities"].remove("semantic.review")
    access["capability_policies"] = [{
        "capability_key": "semantic.review", "effect": "allow", "valid": True,
        "scope": {"kind": "server", "ids": [30]},
    }]
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([], False))

    payload = reporting.get_semantic_relations(
        access, domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )

    assert payload["state"] == "empty"
    assert payload["items"] == [] and payload["next_cursor"] is None


def test_domain_wide_preflight_reads_only_one_raw_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000017", 7)
    calls: list[object] = []
    monkeypatch.setattr(
        reporting,
        "_read_candidate_preflight",
        lambda **kwargs: calls.append(kwargs["before"]) or ([candidate], True),
    )
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(ids[0])])

    payload = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )

    assert payload["state"] == "available"
    assert calls == [None]


def test_domain_wide_full_raw_page_keeps_source_pagination_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _preflight("00000000-0000-0000-0000-000000000020", 7)
    second = _preflight("00000000-0000-0000-0000-000000000021", 7)
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([first, second], True))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(candidate_id) for candidate_id in ids])

    payload = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC", limit=2,
    )

    assert payload["has_more"] is True
    assert payload["next_cursor"]
    assert reporting._decode_cursor(
        payload["next_cursor"], domain_id=7,
        start=datetime(2026, 9, 1, 9, tzinfo=UTC), end=datetime(2026, 9, 1, 11, tzinfo=UTC), filters={},
    )[1] == second["candidate_id"]


def test_resource_scoped_scan_stops_at_bounded_page_limit_without_hidden_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden = _preflight("00000000-0000-0000-0000-000000000018", 8)
    monkeypatch.setattr(reporting, "MAX_RESOURCE_SCOPED_PREFLIGHT_PAGES", 1)
    monkeypatch.setattr(reporting, "_domain_access_allowed", lambda *_args: "potential")
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([hidden], True))

    payload = reporting.get_semantic_relations(
        _access(scoped_semantic_review=True), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )

    assert payload["state"] == "empty"
    assert payload["has_more"] is True and payload["next_cursor"]
    assert hidden["candidate_id"] not in repr(payload)
    assert any("resource-scoped" in item for item in payload["coverage"]["limitations"])


def test_resource_scoped_scan_cursor_resumes_after_short_authorized_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    allowed = _preflight("00000000-0000-0000-0000-000000000027", 7)
    hidden = _preflight("00000000-0000-0000-0000-000000000028", 8)
    monkeypatch.setattr(reporting, "MAX_RESOURCE_SCOPED_PREFLIGHT_PAGES", 1)
    monkeypatch.setattr(reporting, "_domain_access_allowed", lambda *_args: "potential")
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([allowed, hidden], True))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(ids[0])])

    payload = reporting.get_semantic_relations(
        _access(scoped_semantic_review=True), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC", limit=2,
    )

    assert [item["candidate_id"] for item in payload["items"]] == [allowed["candidate_id"]]
    assert payload["has_more"] is True and payload["next_cursor"]
    assert hidden["candidate_id"] not in repr(payload)


def test_relation_cursor_keeps_the_first_page_rule_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _preflight("00000000-0000-0000-0000-000000000029", 7)
    second = _preflight("00000000-0000-0000-0000-000000000030", 7)
    captured_snapshots: list[object] = []

    def preflight(**kwargs):
        captured_snapshots.append(kwargs["rule_snapshot"])
        return ([first, second], True) if kwargs["before"] is None else ([second], False)

    monkeypatch.setattr(reporting, "_read_candidate_preflight", preflight)
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(candidate_id) for candidate_id in ids])
    page_one = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC", limit=1,
    )
    monkeypatch.setattr(
        reporting,
        "_read_supported_rules",
        lambda: [{"rule_id": "investigation.account.unlock.after-lock", "rule_version": 3, "lifecycle_status": "enabled"}],
    )
    page_two = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC", limit=1, cursor=page_one["next_cursor"],
    )

    expected_snapshot = (("investigation.account.unlock.after-lock", 2, "shadow"),)
    assert captured_snapshots == [expected_snapshot, expected_snapshot]
    assert page_one["result_revision"] == page_two["result_revision"]
    assert page_two["coverage"]["supported_rules"] == [
        {"rule_id": "investigation.account.unlock.after-lock", "rule_version": 2, "lifecycle_status": "shadow"}
    ]


def test_relation_cursor_is_server_opaque_and_rejects_forgery() -> None:
    candidate_id = "00000000-0000-0000-0000-000000000033"
    cursor = reporting._encode_cursor(
        domain_id=7,
        start=datetime(2026, 9, 1, 9, tzinfo=UTC),
        end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        filters={"entity_id": 42},
        rule_snapshot=(("investigation.account.unlock.after-lock", 2, "shadow"),),
        window_end=datetime(2026, 9, 1, 10, tzinfo=UTC),
        candidate_id=candidate_id,
    )

    assert cursor.startswith("v2.")
    assert candidate_id not in cursor
    assert "investigation.account.unlock.after-lock" not in cursor
    decoded = reporting._decode_cursor(
        cursor, domain_id=7,
        start=datetime(2026, 9, 1, 9, tzinfo=UTC),
        end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        filters={"entity_id": 42},
    )
    assert decoded[1] == candidate_id
    forged = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting._decode_cursor(
            forged, domain_id=7,
            start=datetime(2026, 9, 1, 9, tzinfo=UTC),
            end=datetime(2026, 9, 1, 11, tzinfo=UTC),
            filters={"entity_id": 42},
        )


def test_relation_cursor_expires_server_side(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [100.0]
    monkeypatch.setattr(reporting.time, "monotonic", lambda: now[0])
    cursor = reporting._encode_cursor(
        domain_id=7,
        start=datetime(2026, 9, 1, 9, tzinfo=UTC),
        end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        filters={},
        rule_snapshot=(("investigation.account.unlock.after-lock", 2, "shadow"),),
        window_end=datetime(2026, 9, 1, 10, tzinfo=UTC),
        candidate_id="00000000-0000-0000-0000-000000000034",
    )

    now[0] += reporting._CURSOR_TTL_SECONDS + 1
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting._decode_cursor(
            cursor, domain_id=7,
            start=datetime(2026, 9, 1, 9, tzinfo=UTC),
            end=datetime(2026, 9, 1, 11, tzinfo=UTC),
            filters={},
        )


def test_supported_rule_inventory_failure_keeps_authorized_relation_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000019", 7)
    monkeypatch.setattr(reporting, "_read_supported_rules", lambda: (_ for _ in ()).throw(reporting.SchemaUnavailable()))
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([candidate], False))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(ids[0])])

    payload = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )

    assert payload["state"] == "available"
    assert [item["candidate_id"] for item in payload["items"]] == [candidate["candidate_id"]]
    assert payload["coverage"]["supported_rules_state"] == "check_unavailable"
    assert payload["coverage"]["supported_rules"] == []


def test_inventory_permission_failure_keeps_authorized_relation_rows_without_error_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000022", 7)
    monkeypatch.setattr(reporting, "_read_supported_rules", lambda: (_ for _ in ()).throw(RuntimeError("permission denied for rule inventory")))
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([candidate], False))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(ids[0])])

    payload = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )

    assert payload["state"] == "available"
    assert payload["coverage"]["supported_rules_state"] == "check_unavailable"
    assert "permission denied for rule inventory" not in repr(payload)


def test_inventory_failure_does_not_emit_an_unbound_relation_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _preflight("00000000-0000-0000-0000-000000000031", 7)
    second = _preflight("00000000-0000-0000-0000-000000000032", 7)
    monkeypatch.setattr(
        reporting,
        "_read_supported_rules",
        lambda: (_ for _ in ()).throw(RuntimeError("inventory unavailable")),
    )
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([first, second], True))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(ids[0])])

    payload = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC", limit=1,
    )

    assert [item["candidate_id"] for item in payload["items"]] == [first["candidate_id"]]
    assert payload["result_revision"] is None
    assert payload["has_more"] is False and payload["next_cursor"] is None
    assert payload["coverage"]["supported_rules_state"] == "check_unavailable"
    assert any("версии правил" in item for item in payload["coverage"]["limitations"])


def test_supported_rule_inventory_returns_only_current_executable_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executed: list[tuple[str, object]] = []
    monkeypatch.undo()

    class Cursor:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def execute(self, sql, params=None): executed.append((sql, params))
        def fetchall(self): return [{"rule_id": "investigation.account.unlock.after-lock", "rule_version": 3, "lifecycle_status": "shadow"}]

    class Connection:
        def cursor(self): return Cursor()
        def __enter__(self): return self
        def __exit__(self, *_args): return False

    monkeypatch.setattr(reporting, "_connect", lambda: Connection())
    rules = reporting._read_supported_rules()

    assert rules == [{"rule_id": "investigation.account.unlock.after-lock", "rule_version": 3, "lifecycle_status": "shadow"}]
    assert "row_number() over (partition by rule_id order by rule_version desc)" in executed[-1][0]


def test_relation_reader_exposes_anchor_and_all_authorized_continuations_without_unique_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000001", 7, 7, 7)
    hydrated = _hydrated(candidate["candidate_id"])
    hydrated["rule_id"] = "investigation.password.reset-then-logon"
    hydrated["rule_version"] = 2
    hydrated["evidence"] = [
        {**hydrated["evidence"][0], "event_db_id": 100, "evidence_order": 0},
        {**hydrated["evidence"][0], "event_db_id": 101, "evidence_order": 1},
        {**hydrated["evidence"][0], "event_db_id": 102, "evidence_order": 2},
    ]
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([candidate], False))
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda _ids: [hydrated])

    payload = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )

    item = payload["items"][0]
    assert item["continuation_state"] == "ambiguous"
    assert item["possible_continuation_count"] == 2
    assert [evidence["evidence_role"] for evidence in item["evidence"]] == [
        "anchor", "alternative_continuation", "alternative_continuation",
    ]


def test_relation_reader_binds_exact_filters_to_reverse_cursor_and_preserves_schema_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _preflight("00000000-0000-0000-0000-000000000001", 7)
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        reporting,
        "_read_candidate_preflight",
        lambda **kwargs: captured.update(kwargs) or ([candidate, _preflight("00000000-0000-0000-0000-000000000006", 7)], True),
    )
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda candidate_ids: [_hydrated(candidate_ids[0])])
    payload = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
        event_db_id=100, entity_id=42, rule_version=1,
        relation_kind="authentication.lockout_preceded_by_failures", limit=1,
    )
    assert captured["filters"] == {
        "event_db_id": 100, "entity_id": 42, "rule_version": 1,
        "relation_kind": "authentication.lockout_preceded_by_failures",
    }
    assert payload["has_more"] is True and payload["next_cursor"]
    with pytest.raises(ValueError, match="invalid_cursor"):
        reporting.get_semantic_relations(
            _access(), domain_id=7,
            time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
            event_db_id=101, cursor=payload["next_cursor"],
        )

    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: (_ for _ in ()).throw(reporting.SchemaUnavailable()))
    assert reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )["state"] == "schema_unavailable"


def test_relations_route_is_resource_aware_and_rejects_unknown_or_duplicate_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert routes_semantic.is_resource_aware("/api/v1/semantic/relations", {}) is True
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        routes_semantic,
        "get_semantic_relations",
        lambda access, **kwargs: captured.update(access=access, **kwargs) or {
            "state": "empty", "items": [], "has_more": False, "next_cursor": None,
            "filters": {}, "limits": {}, "time_bounds": {}, "contract_id": "sli.semantic-relations.v1",
        },
    )

    class Handler:
        def _access_decision(self): return {"server_built": True}
        def _send_json(self, payload, status=None): captured["payload"] = payload

    assert routes_semantic.try_handle_get(Handler(), "/api/v1/semantic/relations", {
        "domain_id": ["7"], "time_from": ["2026-09-01T09:00:00Z"],
        "time_to": ["2026-09-01T11:00:00Z"], "timezone": ["UTC"], "limit": ["10"],
        "category": ["group_membership"], "event_id": ["4728"], "outcome": ["unknown"],
        "actor": ["operator"], "target": ["member"], "group": ["admins"],
        "source": ["dc01"], "q": ["operator"],
    })
    assert captured["domain_id"] == 7 and captured["access"] == {"server_built": True}
    assert {key: captured[key] for key in ("category", "event_id", "outcome", "actor", "target_account", "group", "source_host", "q")} == {
        "category": "group_membership", "event_id": "4728", "outcome": "unknown",
        "actor": "operator", "target_account": "member", "group": "admins",
        "source_host": "dc01", "q": "operator",
    }
    with pytest.raises(RequestInputError, match="invalid_semantic_relation_filter"):
        routes_semantic.try_handle_get(Handler(), "/api/v1/semantic/relations", {
            "domain_id": ["7", "8"], "time_from": ["x"], "time_to": ["y"], "timezone": ["UTC"],
        })


def test_relation_reader_reuses_one_report_filter_contract_for_each_matching_atom(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A relation cannot combine actor from one event with group from another."""

    candidate = _preflight("00000000-0000-0000-0000-000000000011", 7, 7)
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        reporting,
        "_read_candidate_preflight",
        lambda **kwargs: captured.update(kwargs) or ([candidate], False),
    )
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(ids[0])])

    payload = reporting.get_semantic_relations(
        _access(scoped_semantic_review=True), domain_id=7,
        time_from="2026-09-01T09:00:00.123456Z", time_to="2026-09-01T11:00:00.654321Z",
        timezone_name="UTC", category="group_membership", event_id=4728,
        outcome="unknown", actor="operator", target_account="member", group="admins",
        source_host="dc01.example.test", q="operator", entity_id=42, event_db_id=100,
    )

    assert payload["time_bounds"] == {
        "from_utc": "2026-09-01T09:00:00.123456Z",
        "to_utc_exclusive": "2026-09-01T11:00:00.654321Z",
    }
    assert captured["filters"] == {
        "category": "group_membership", "event_id": 4728, "outcome": "unknown",
        "actor": "operator", "target_account": "member", "group": "admins",
        "source_host": "dc01.example.test", "q": "operator", "entity_id": 42,
        "event_db_id": 100,
    }


def test_relation_preflight_applies_combined_report_filters_to_one_evidence_atom(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Cursor:
        def __init__(self): self.sql: list[str] = []
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def execute(self, sql, _params=()): self.sql.append(" ".join(sql.split()).lower())
        def fetchall(self): return []

    class Connection:
        def __init__(self, cursor): self._cursor = cursor
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def cursor(self): return self._cursor

    cursor = Cursor()
    monkeypatch.setattr(reporting, "_connect", lambda: Connection(cursor))
    reporting._read_candidate_preflight(
        domain_id=7,
        start=datetime(2026, 9, 1, 9, 0, 0, 123456, tzinfo=UTC),
        end=datetime(2026, 9, 1, 11, 0, 0, 654321, tzinfo=UTC),
        filters={
            "category": "group_membership", "event_id": 4728, "actor": "operator",
            "group": "admins", "entity_id": 42,
        }, limit=10, before=None,
        rule_snapshot=(("investigation.account.unlock.after-lock", 2, "shadow"),),
    )

    sql = cursor.sql[1]
    # The selected EXISTS atom owns every filter; aliases/link blocks are the
    # report owner's identity predicate, not a relation-local approximation.
    assert "selected_evidence.candidate_id=candidate.candidate_id" in sql
    assert "selected_event.event_id=any(%s)" in sql
    assert "selected_event.event_id=%s" in sql
    assert "selected_event.subject_user_sid" in sql
    assert "selected_facts.membership_member_sid" in sql
    assert "ad_context_entity_aliases alias" in sql
    assert "event_entity_link_blocks_v2 block" in sql
    assert "candidate.rule_id=%s and candidate.rule_version=%s" in sql
    assert "newer_rule" not in sql


def test_hidden_candidate_is_indistinguishable_from_empty_authorized_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hidden = _preflight("00000000-0000-0000-0000-000000000012", 8)
    monkeypatch.setattr(reporting, "_domain_access_allowed", lambda *_args: "potential")
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([hidden], False))
    monkeypatch.setattr(
        reporting, "_read_authorized_candidates",
        lambda *_args, **_kwargs: pytest.fail("hidden candidate must not hydrate"),
    )

    payload = reporting.get_semantic_relations(
        _access(scoped_semantic_review=True), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z", timezone_name="UTC",
    )

    assert payload["state"] == "empty"
    assert payload["items"] == []
    assert payload["has_more"] is False and payload["next_cursor"] is None
    assert payload["coverage"]["matched_relation_count"] is None
    assert hidden["candidate_id"] not in repr(payload)


def test_reader_scans_past_hidden_candidates_without_hidden_pagination_signal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _preflight("00000000-0000-0000-0000-000000000013", 7)
    hidden = _preflight("00000000-0000-0000-0000-000000000014", 8)
    later = _preflight("00000000-0000-0000-0000-000000000015", 7)
    calls: list[object] = []

    def preflight(**kwargs):
        calls.append(kwargs["before"])
        return ([first, hidden], True) if kwargs["before"] is None else ([later], False)

    monkeypatch.setattr(reporting, "_domain_access_allowed", lambda *_args: "potential")
    monkeypatch.setattr(reporting, "_read_candidate_preflight", preflight)
    monkeypatch.setattr(reporting, "_read_authorized_candidates", lambda ids: [_hydrated(candidate_id) for candidate_id in ids])

    payload = reporting.get_semantic_relations(
        _access(scoped_semantic_review=True), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC", limit=2,
    )

    assert [item["candidate_id"] for item in payload["items"]] == [first["candidate_id"], later["candidate_id"]]
    assert len(calls) == 2
    assert payload["has_more"] is False and payload["next_cursor"] is None
    assert hidden["candidate_id"] not in repr(payload)


def test_no_saved_candidates_is_empty_not_an_authorization_denial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(reporting, "_read_candidate_preflight", lambda **_kwargs: ([], False))
    monkeypatch.setattr(
        reporting, "_read_authorized_candidates",
        lambda *_args, **_kwargs: pytest.fail("empty preflight must not hydrate"),
    )

    payload = reporting.get_semantic_relations(
        _access(), domain_id=7,
        time_from="2026-09-01T09:00:00Z", time_to="2026-09-01T11:00:00Z",
        timezone_name="UTC",
    )

    assert payload["state"] == "empty"


def test_relation_sql_reads_only_matched_same_domain_exact_entity_and_semantic_type(monkeypatch: pytest.MonkeyPatch) -> None:
    class Cursor:
        def __init__(self):
            self.sql: list[str] = []

        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def execute(self, sql, _params=()): self.sql.append(" ".join(sql.split()).lower())
        def fetchall(self): return []

    class Connection:
        def __init__(self, cursor): self._cursor = cursor
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def cursor(self): return self._cursor

    preflight_cursor = Cursor()
    monkeypatch.setattr(reporting, "_connect", lambda: Connection(preflight_cursor))
    reporting._read_candidate_preflight(
        domain_id=7,
        start=datetime(2026, 9, 1, 9, tzinfo=UTC),
        end=datetime(2026, 9, 1, 11, tzinfo=UTC),
        filters={"entity_id": 42}, limit=10, before=None,
    )
    preflight_sql = preflight_cursor.sql[1]
    assert "candidate.candidate_status='matched'" in preflight_sql
    assert "block.entity_id=resolve_entity_identity_v2(%s)" in preflight_sql
    assert "domain_event.domain_id<>%s" in preflight_sql

    hydrated_cursor = Cursor()
    monkeypatch.setattr(reporting, "_connect", lambda: Connection(hydrated_cursor))
    reporting._read_authorized_candidates(["00000000-0000-0000-0000-000000000001"])
    hydrated_sql = hydrated_cursor.sql[1]
    assert "normalized.semantic_type" in hydrated_sql
    assert "facts_json->>'semantic_type'" not in hydrated_sql
