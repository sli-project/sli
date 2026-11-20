"""Admin queue evidence defaults, composed by the real PDP against a fake DB."""

import json
import re
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.sli.access import access_control_v4 as access
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.reports.security_problems import REPORT


MIGRATION = Path(__file__).resolve().parents[2] / "config/postgres_migrations/259_admin_problem_evidence.sql"
FIELDS = {"security", "identity_basic", "technical", "raw_evidence"}
CAPABILITIES = {"workspace.view", "field.security", "field.identity_basic", "field.technical",
                "field.raw_evidence", "evidence.exact"}


def migration_sql():
    assert MIGRATION.exists(), "Admin evidence defaults require a new migration"
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_grants_only_the_dedicated_admin_package_and_audits_it():
    sql = migration_sql()
    assert sql.splitlines()[1] == "begin;" and sql.strip().endswith("commit;")
    assert "version=258 and name='workstation_device_seen'" in sql
    assert "version>=259" in sql
    assert "values(259,'admin_problem_evidence')" in sql
    role_grant = sql.split("insert into public.access_role_packages", 1)[1].split(";", 1)[0]
    assert "select 'admin',id" in role_grant
    assert "package_key='admin_problem_evidence'" in role_grant
    assert "'viewer'" not in sql and "'operator'" not in sql
    for table in ("access_subject_packages", "access_report_assignments", "access_capability_assignments"):
        assert table not in sql
    assert not re.search(r"\b(update|delete from) public.access_", sql)
    capability_grant = sql.split("insert into public.access_package_capabilities", 1)[1].split(";", 1)[0]
    assert set(re.findall(r"'(workspace\.[^']+|field\.[^']+|evidence\.[^']+)'", capability_grant)) == CAPABILITIES
    report_grant = sql.split("insert into public.access_package_reports", 1)[1].split(";", 1)[0]
    assert "'security.queue'" in report_grant
    assert "array['view']" in report_grant and "'{\"kind\":\"all\"}'::jsonb" in report_grant
    assert "insert into public.access_audit_v4" in sql
    assert "'package_assignment_created'" in sql and "'system'" in sql
    assert "'coarse_role','admin'" in sql and "'effect','allow'" in sql


class Cursor:
    def __init__(self, *, role, owner, deny, denied_capability, legacy_registry):
        self.role, self.owner, self.deny = role, owner, deny
        self.denied_capability = denied_capability
        sql = migration_sql()
        registry_update = sql.split("update public.report_registry_v4", 1)[1].split(";", 1)[0]
        self.categories = json.loads(re.search(r"'(\[\"security\"[^']+)'::jsonb", registry_update).group(1))
        dataset_update = sql.split("update public.report_datasets_v4", 1)[1].split(";", 1)[0]
        self.dataset_fields = [{"category": "security"}, {"category": "raw_evidence"}] + json.loads(
            re.search(r"'(\[\{[^']+)'::jsonb", dataset_update).group(1))
        capability_grant = sql.split("insert into public.access_package_capabilities", 1)[1].split(";", 1)[0]
        self.capabilities = set(re.findall(r"'(workspace\.[^']+|field\.[^']+|evidence\.[^']+)'", capability_grant))
        report_grant = sql.split("insert into public.access_package_reports", 1)[1].split(";", 1)[0]
        self.grant_fields = re.findall(r"'([^']+)'", re.search(r"array\[([^]]+)\]", report_grant).group(1))
        if legacy_registry:
            self.categories = ["security"]
            self.dataset_fields = [{"category": "security"}, {"category": "raw_evidence"}]
        self.sql = ""

    def execute(self, sql, params=()):
        self.sql = " ".join(sql.split())

    def fetchone(self):
        assert "access_platform_owners" in self.sql
        return {"is_owner": self.owner}

    def fetchall(self):
        sql = self.sql
        if "from access_role_packages" in sql or "from access_packages order by" in sql:
            return [{"id": 1, "package_key": "admin_problem_evidence", "name": "fixture package",
                     "source_kind": "role", "source_key": self.role, "effect": "allow"}] if self.role == "admin" else []
        if "from access_package_capabilities" in sql:
            return [{"capability_key": key, "package_key": "admin_problem_evidence"} for key in self.capabilities]
        if "from access_capabilities order by" in sql:
            return [{"capability_key": key} for key in CAPABILITIES]
        if "from access_capability_assignments" in sql and self.denied_capability:
            return [{"capability_key": self.denied_capability, "effect": "deny", "scope_json": {"kind": "all"},
                     "subject_type": "user", "subject_id": 7, "source_type": "direct"}]
        if "from access_package_reports" in sql:
            return [{"report_key": "security.queue", "package_key": "admin_problem_evidence",
                     "field_categories": self.grant_fields, "allowed_actions": ["view"], "scope_json": {"kind": "all"}}]
        if "from access_report_assignments" in sql and self.deny:
            return [{"report_key": "security.queue", "effect": "deny"}]
        if "from report_registry_v4 r join report_datasets_v4" in sql:
            return [{"report_key": "security.queue", "version": 1, "name": "fixture report", "owner_name": "fixture",
                     "purpose": "fixture", "sensitivity": "restricted", "status": "published",
                     "dataset_key": "security.problems", "dataset_version": 1,
                     "definition_json": {"field_categories": self.categories, "actions": ["view"],
                                         "required_capabilities": ["workspace.view"]},
                     "fields_json": self.dataset_fields, "actions_json": ["view"],
                     "discoverable": True, "requestable": False}]
        return []


def effective(monkeypatch, *, role="admin", owner=False, deny=False, denied_capability=None, legacy_registry=False):
    cursor = Cursor(role=role, owner=owner, deny=deny, denied_capability=denied_capability,
                    legacy_registry=legacy_registry)
    monkeypatch.setattr(access, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(access, "_connect", lambda: nullcontext(SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    return access.effective_access({"type": "session", "id": 7, "role": role})


@pytest.mark.parametrize("owner", [False, True])
def test_admin_can_read_evidence_and_every_column(monkeypatch, owner):
    declaration = ReportAccess(REPORT, effective(monkeypatch, owner=owner)).declaration()
    assert declaration["access"]["hidden_categories"] == []
    assert declaration["detail"]["access"]["allowed"]
    assert {column["key"] for column in declaration["columns"]} == {column.key for column in REPORT.columns}
    assert {column["key"] for column in declaration["detail"]["columns"]} == {column.key for column in REPORT.detail.columns}


def test_legacy_registry_hides_evidence_even_from_owner(monkeypatch):
    declaration = ReportAccess(REPORT, effective(monkeypatch, owner=True, legacy_registry=True)).declaration()
    assert set(declaration["access"]["hidden_categories"]) == FIELDS - {"security"}
    assert not declaration["detail"]["access"]["allowed"]
    assert declaration["detail"]["columns"] == []


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_role_without_grant_cannot_read_queue_or_evidence(monkeypatch, role):
    with pytest.raises(PermissionError, match="report_access_denied"):
        ReportAccess(REPORT, effective(monkeypatch, role=role))


def test_explicit_report_deny_still_wins_over_admin_default(monkeypatch):
    with pytest.raises(PermissionError, match="report_access_denied"):
        ReportAccess(REPORT, effective(monkeypatch, deny=True))


@pytest.mark.parametrize("capability", ["evidence.exact", "field.raw_evidence", "field.technical"])
def test_explicit_capability_deny_still_masks_admin_fields(monkeypatch, capability):
    declaration = ReportAccess(REPORT, effective(monkeypatch, denied_capability=capability)).declaration()
    if capability == "field.technical":
        assert {column["key"] for column in declaration["detail"]["columns"]} == {"event_id", "time_created_utc"}
    else:
        assert not declaration["detail"]["access"]["allowed"]
        assert declaration["detail"]["columns"] == []


def test_registry_and_dataset_publish_all_queue_field_groups():
    sql = migration_sql()
    registry_update = sql.split("update public.report_registry_v4", 1)[1].split(";", 1)[0]
    fields = json.loads(re.search(r"'(\[\"security\"[^']+)'::jsonb", registry_update).group(1))
    assert set(fields) == FIELDS
    assert "report_key='security.queue'" in registry_update and "status='published'" in registry_update
    dataset_update = sql.split("update public.report_datasets_v4", 1)[1].split(";", 1)[0]
    assert "dataset_key='security.problems'" in dataset_update
    for category in ("identity_basic", "technical"):
        assert f'"category":"{category}"' in dataset_update
