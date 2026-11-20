from __future__ import annotations

import json
import sys
from types import SimpleNamespace


def test_dpapi_enforced_values_override_inherited_environment(monkeypatch, tmp_path) -> None:
    from server.sli.ops import worker_supervisor_secrets as module

    profile = tmp_path / "worker.env.dpapi"
    profile.write_bytes(b"protected")
    clear = json.dumps(
        {
            "version": 2,
            "owner_sid": "synthetic-owner",
            "environment": {
                "ADLOG_DB_BACKEND": "sqlite",
                "ADLOG_COLLECTION_MAX_EVENTS_PER_CHANNEL": "5000",
                "ADLOG_PG_DSN": "postgresql://profile",
            },
        }
    ).encode("utf-8")
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module, "_current_user_sid", lambda: "synthetic-owner")
    monkeypatch.setitem(
        sys.modules,
        "win32crypt",
        SimpleNamespace(CryptUnprotectData=lambda *_args: (None, clear)),
    )
    target = {
        "ADLOG_DB_BACKEND": "sqlite-from-parent",
        "ADLOG_COLLECTION_MAX_EVENTS_PER_CHANNEL": "1",
        "ADLOG_PG_DSN": "postgresql://parent",
    }

    module.load_supervisor_environment(target=target, path=profile)

    assert target["ADLOG_DB_BACKEND"] == "postgres"
    assert target["ADLOG_COLLECTION_MAX_EVENTS_PER_CHANNEL"] == "50000"
    assert target["ADLOG_PG_DSN"] == "postgresql://parent"


def test_managed_dpapi_values_override_inherited_storage_route(monkeypatch, tmp_path) -> None:
    from server.sli.ops import worker_supervisor_secrets as module

    profile = tmp_path / "worker.env.dpapi"
    profile.write_bytes(b"protected")
    clear = json.dumps(
        {
            "version": 2,
            "owner_sid": "synthetic-owner",
            "environment": {
                "ADLOG_PG_DSN": "postgresql://profile",
                "ADLOG_STORAGE_READ_MODE": "v2",
                "ADLOG_STORAGE_WRITE_MODE": "v2",
            },
        }
    ).encode("utf-8")
    monkeypatch.setattr(module.os, "name", "nt")
    monkeypatch.setattr(module, "_current_user_sid", lambda: "synthetic-owner")
    monkeypatch.setitem(
        sys.modules,
        "win32crypt",
        SimpleNamespace(CryptUnprotectData=lambda *_args: (None, clear)),
    )
    target = {
        "ADLOG_PG_DSN": "postgresql://parent",
        "ADLOG_STORAGE_READ_MODE": "v2",
        "ADLOG_STORAGE_WRITE_MODE": "v2_primary_compat",
    }

    module.load_supervisor_environment(
        target=target,
        path=profile,
        override_existing=True,
    )

    assert target["ADLOG_PG_DSN"] == "postgresql://profile"
    assert target["ADLOG_STORAGE_READ_MODE"] == "v2"
    assert target["ADLOG_STORAGE_WRITE_MODE"] == "v2"
