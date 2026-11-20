"""Registry SQL adapter contracts with fakes; no database connections."""
from datetime import datetime, timedelta, timezone
import json
from uuid import UUID

import pytest

from server.sli.sigma import registry

INSTALLATION = str(UUID(int=1))
RULE = str(UUID(int=2))
OVERLAY = str(UUID(int=3))
SCOPE = registry.RegistryScope(INSTALLATION, "synthetic.plugin", "synthetic-source")
RAW_HASH = "a" * 64
CANONICAL_HASH = "b" * 64


class Cursor:
    def __init__(self, row=None, error=None):
        self.row = row
        self.error = error
        self.calls = []

    def execute(self, sql, params):
        self.calls.append((sql, params))
        if self.error:
            raise self.error

    def fetchone(self):
        return self.row


def revision(**changes):
    return dict(raw_yaml=b"id: " + RULE.encode() + b"\n",
                canonical_rule={"id": RULE, "title": "Synthetic rule"},
                upstream_commit="c" * 40, status="test", level="low", tags=["attack.t1003"],
                author="Synthetic team", license_id="DRL-1.1", source_uri="urn:synthetic:sigma",
                requirements={"logsource": "security", "required_fields": ["EventID"]}, **changes)


def overlay():
    return dict(overlay_id=OVERLAY, version=1, rule_id=RULE, base_raw_sha256=RAW_HASH,
                base_canonical_sha256=CANONICAL_HASH, mapping_version="synthetic.mapping.v1",
                predicate={"version": "sli.sigma.overlay.v1", "all_of": [{"field": "EventID", "equals": 1}]},
                reason="Synthetic exception", expires_at=datetime(2100, 1, 1, tzinfo=timezone.utc))


def test_revision_and_requirements_are_one_statement_with_exact_scope_and_attribution():
    cursor = Cursor((RAW_HASH, CANONICAL_HASH, "d" * 64))
    result = registry.register_revision(cursor, SCOPE, **revision())
    assert result == cursor.row and len(cursor.calls) == 1
    sql, params = cursor.calls[0]
    assert sql.count("insert into") == 2 and "from revision" in sql
    assert "on conflict" not in sql.lower() and "update" not in sql.lower()
    assert params[:4] == (*SCOPE.params, RULE)
    assert json.loads(params[5]) == revision()["canonical_rule"]
    assert params[10:13] == ("Synthetic team", "DRL-1.1", "urn:synthetic:sigma")
    assert json.loads(params[-1]) == revision()["requirements"]
    assert RAW_HASH not in params and CANONICAL_HASH not in params
    assert "created_by" not in sql and "created_at" not in sql


def test_overlay_pins_both_base_hashes_mapping_scope_and_explicit_version():
    cursor = Cursor(("e" * 64,))
    data = overlay()
    data["expires_at"] = data["expires_at"].astimezone(timezone(timedelta(hours=7)))
    assert registry.register_overlay(cursor, SCOPE, **data) == cursor.row
    sql, params = cursor.calls[0]
    assert params[:9] == (*SCOPE.params, OVERLAY, 1, RULE, RAW_HASH, CANONICAL_HASH, "synthetic.mapping.v1")
    assert json.loads(params[9]) == data["predicate"]
    assert params[-1].tzinfo == timezone.utc
    assert "update" not in sql.lower() and "on conflict" not in sql.lower()


@pytest.mark.parametrize("operation", ["revision", "overlay", "read_revision", "read_overlay"])
def test_permission_or_conflict_errors_fail_closed_without_retry_or_leaking_values(operation):
    cursor = Cursor(error=RuntimeError("synthetic private diagnostic"))
    with pytest.raises(registry.RegistryError, match="^sigma_registry_query_failed$") as error:
        if operation == "revision":
            registry.register_revision(cursor, SCOPE, **revision())
        elif operation == "overlay":
            registry.register_overlay(cursor, SCOPE, **overlay())
        elif operation == "read_revision":
            registry.read_revision(cursor, SCOPE, RULE, RAW_HASH)
        else:
            registry.read_overlay(cursor, SCOPE, OVERLAY, 1)
    assert len(cursor.calls) == 1
    assert error.value.__suppress_context__
    assert "private" not in str(error.value)


@pytest.mark.parametrize("reader,args", [(registry.read_revision, (RULE, RAW_HASH)),
                                       (registry.read_overlay, (OVERLAY, 1))])
def test_reads_are_exact_and_preserve_not_visible_as_none(reader, args):
    cursor = Cursor()
    assert reader(cursor, SCOPE, *args) is None
    sql, params = cursor.calls[0]
    assert params == (*SCOPE.params, *args)
    for field in ("installation_id", "plugin_id", "source_instance_id"):
        assert f"{field}=%s" in sql
    assert "expires_at>" not in sql and "max(version)" not in sql
    assert "using (installation_id,plugin_id,source_instance_id,rule_id,raw_sha256)" in sql or reader == registry.read_overlay


@pytest.mark.parametrize("field,value", [("raw_yaml", b"\xff"), ("raw_yaml", b""),
                                        ("canonical_rule", {"id": "invalid"}),
                                        ("canonical_rule", {"id": RULE, "number": float("nan")}),
                                        ("requirements", [])])
def test_invalid_revision_never_reaches_cursor(field, value):
    cursor = Cursor()
    data = revision()
    data[field] = value
    with pytest.raises(registry.RegistryError, match="^sigma_registry_document_invalid$"):
        registry.register_revision(cursor, SCOPE, **data)
    assert cursor.calls == []


@pytest.mark.parametrize("field,value", [("version", True), ("version", 0),
                                        ("predicate", []), ("expires_at", datetime(2100, 1, 1))])
def test_invalid_overlay_never_reaches_cursor(field, value):
    cursor = Cursor()
    data = overlay()
    data[field] = value
    with pytest.raises(registry.RegistryError, match="^sigma_registry_overlay_invalid$"):
        registry.register_overlay(cursor, SCOPE, **data)
    assert cursor.calls == []


@pytest.mark.parametrize("values", [("invalid", "plugin", "source"), (INSTALLATION, "", "source"),
                                    (INSTALLATION, "plugin", ""), (INSTALLATION, "p" * 129, "source")])
def test_scope_rejects_wildcards_or_missing_dimensions(values):
    with pytest.raises(registry.RegistryError, match="^sigma_registry_scope_invalid$"):
        registry.RegistryScope(*values)


def test_scope_repr_does_not_expose_identifiers():
    assert INSTALLATION not in repr(SCOPE)
    assert SCOPE.source_instance_id not in repr(SCOPE)
