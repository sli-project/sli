from __future__ import annotations

from scripts.maintenance import catalog_required_fields_audit as audit


def test_required_fields_audit_is_explicitly_read_only_and_payload_free() -> None:
    source = audit.__file__
    text = open(source, encoding="utf-8").read()

    assert "repeatable read read only" in text
    assert "transaction_read_only" in text
    assert "record_xml" not in text
    assert "delete " not in text.lower()
    assert "update " not in text.lower()
    assert "insert " not in text.lower()


def test_required_fields_query_uses_only_validated_identifiers() -> None:
    query = audit._aggregate_query(
        ("event_id", "time_created_utc", "source_facts_sha256")
    )
    rendered = query.as_string()

    assert '"e"."event_id"' in rendered
    assert '"e"."time_created_utc"' in rendered
    assert '"f"."source_facts_sha256"' in rendered
    assert "storage_v2_channel" in rendered
