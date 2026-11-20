"""GPO-owned handlers sharing the immutable snapshot store and publication fence."""
from __future__ import annotations

import importlib


def _snapshots():
    return importlib.import_module("server.sli.plugins.ad.jobs")


def job_source(handler: dict, source: dict, generation: str) -> tuple[dict, str]:
    return _snapshots().job_source(handler, source, generation)


def schedule(cur, handlers, profile: str) -> None:
    _snapshots().schedule_snapshot_sources(cur, handlers, profile, "sli.gpo")


def stage(conn, job: dict) -> dict:
    return _snapshots().stage_projection(conn, job, projection_keys=("ad.gpo.v2",), required_part="gpo")


def apply(conn, job: dict, result: dict) -> None:
    _snapshots().apply_projection(conn, job, result, stage_handler=stage, projection_keys=("ad.gpo.v2",))
