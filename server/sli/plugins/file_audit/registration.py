"""Reviewed file-audit entry point; no DDL, collection or audit management."""
import importlib


def _deferred(module, name):
    def invoke(*args, **kwargs):
        return getattr(importlib.import_module(module), name)(*args, **kwargs)
    return invoke


def register(contribution):
    contribution.hooks.update({
        "validate_scope_targets": _deferred("server.sli.plugins.file_audit.access", "validate_scope_targets"),
        "health": lambda: True,
        "normalizer:windows-file-audit-v1": _deferred("server.sli.plugins.file_audit.normalizers", "normalizer"),
        "file_audit_agent_policy": _deferred("sli_agent.file_audit_policy", "policy"),
        "retain_assignment_policy": _deferred("server.sli.plugins.file_audit.management", "retain_assignment_policy"),
        "file_audit_agent_rows": _deferred("server.sli.plugins.file_audit.agent_ingest", "admitted_rows"),
        "import_file_audit_agent_packet": _deferred("server.sli.plugins.file_audit.importer", "import_packet"),
        "file_audit_activity_findings": _deferred("server.sli.plugins.file_audit.rules", "activity_findings"),
        "file_audit_permission_findings": _deferred("server.sli.plugins.file_audit.rules", "permission_findings"),
        "audit_requirements": _deferred("sli_agent.file_audit_policy", "audit_requirements"),
        "audit_command": _deferred("sli_agent.file_audit_policy", "audit_command"),
        "enqueue_audit": _deferred("server.sli.plugins.file_audit.management", "enqueue"),
        "enqueue_audit_batch": _deferred("server.sli.plugins.file_audit.management", "enqueue_batch"),
        "ingest_audit": _deferred("server.sli.plugins.file_audit.management", "ingest"),
        "audit_status": _deferred("server.sli.plugins.file_audit.management", "status"),
        "require_access": _deferred("server.sli.plugins.file_audit.access", "require_access"),
        "report_contracts": _deferred("server.sli.plugins.file_audit.contracts", "report_contracts"),
        "reports": _deferred("server.sli.plugins.file_audit.reports", "reports"),
        "manifest": _deferred("server.sli.plugins.file_audit.manifest", "load_manifest"),
    })
