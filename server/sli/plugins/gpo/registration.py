"""Reviewed GPO snapshot entry point; no acquisition or background work."""
from __future__ import annotations

import importlib


def register(contribution):
    contribution.hooks["reports"] = _reports
    contribution.hooks["import_snapshot_cycle"] = _import_snapshot_cycle
    contribution.hooks["schedule_jobs"] = _deferred("schedule")
    contribution.hooks["job_source"] = _deferred("job_source")
    for handler_id in ("gpo-snapshot", "gpo-acquisition"):
        contribution.jobs[handler_id] = (_deferred("stage"), _deferred("apply"))


def _reports():
    return (importlib.import_module("server.sli.plugins.gpo.reports.definition").REPORT,)


def _deferred(attribute):
    def invoke(*args, **kwargs):
        return getattr(importlib.import_module("server.sli.plugins.gpo.jobs"), attribute)(*args, **kwargs)
    return invoke


def _import_snapshot_cycle(*args, **kwargs):
    module = importlib.import_module("server.sli.plugins.gpo.snapshot_import")
    return module.import_gpo_cycle(*args, **kwargs)
