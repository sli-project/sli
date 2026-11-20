"""File-only MSI group bootstrap, restart and the disabled pending boundary."""
import json
import os
from datetime import datetime, timedelta, timezone
from threading import Event
from types import SimpleNamespace

import pytest

from sli_agent import msi
from sli_agent.config import AgentConfig
from sli_agent.enrollment import IdentityStore
from tests.unit.test_sli_agent_enrollment import FakeServer
from tests.unit.test_sli_agent_msi import fake_provisioning


def bootstrap(root, *, expires=None):
    body = {"kind": "group", "token": "t" * 43, "computer_entity_id": 3,
            "expires_at": (expires or datetime.now(timezone.utc) + timedelta(days=7)).isoformat()}
    path = root / "enrollment.group"
    path.write_text(json.dumps(body))
    path.chmod(0o600)
    return path, body


def test_pending_restart_then_approval_keeps_key_and_removes_group_file(tmp_path):
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state",
                         collection_enabled=False)
    path, body = bootstrap(tmp_path)
    store = IdentityStore(config)
    public = store.prepare()
    # An old file is valid for its server-issued batch expiry, not MSI's hour.
    stamp = datetime.now(timezone.utc).timestamp() - 2 * 3600
    os.utime(path, (stamp, stamp))
    server = FakeServer()
    post = server.post
    approved = False

    def respond(route, payload, **kwargs):
        if route.endswith("/group-enroll"):
            assert payload["token"] == body["token"]
            assert payload["computer_entity_id"] == 3
            assert payload["host_id"] == public["host_id"]
            assert set(payload) == {"token", "computer_entity_id", "host_id", "csr_pem"}
            return {"status": "approved", "token": "s" * 43} if approved else {"status": "pending"}
        assert route.endswith("/enroll") and payload["token"] == "s" * 43
        return post(route, payload, **kwargs)

    server.post = respond
    for _ in range(2):
        store = IdentityStore(config)
        assert msi.enroll_once(config, store, server) == "agent_approval_pending"
        assert store.load() is None and store.prepare() == public and path.exists()
        assert config.collection_enabled is False
    approved = True
    assert msi.enroll_once(config, IdentityStore(config), server) == "enrolled"
    assert not path.exists() and store.load() is not None
    assert store.prepare() == public
    assert msi.enroll_once(config, IdentityStore(config), server) == "enrolled"
    assert not any(body["token"] in file.read_text(errors="ignore") or "s" * 43 in file.read_text(errors="ignore")
                   for file in tmp_path.rglob("*") if file.is_file())


def test_provision_consumes_local_group_file_and_keeps_only_protected_pending_copy(tmp_path, monkeypatch):
    _, secured = fake_provisioning(monkeypatch)
    source, body = bootstrap(tmp_path)
    source.write_bytes(b"\xef\xbb\xbf" + source.read_bytes())
    stamp = source.stat().st_mtime - msi.BOOTSTRAP_TTL - 1
    os.utime(source, (stamp, stamp))
    root = tmp_path / "Agent"

    def consume(path, sid):
        assert (root / "agent.json").exists()
        raw = path.read_bytes()
        path.unlink()
        return raw

    monkeypatch.setattr(msi, "consume_file", consume)
    msi.provision("https://core.invalid", "", "a" * 64, str(source), "LocalSystem", root=root)
    config = AgentConfig.load(root / "agent.json")
    assert not source.exists() and not (root / "enrollment.token").exists()
    assert json.loads((root / "enrollment.group").read_bytes()) == body
    assert (root / "enrollment.group", "S-1-5-18") in secured
    assert body["token"] not in (root / "agent.json").read_text()
    assert not config.collection_enabled and config.event_channels == ()


def test_repeated_provisioning_preserves_pending_group_file_and_key(tmp_path, monkeypatch):
    root = tmp_path / "Agent"
    root.mkdir()
    config_file = root / "agent.json"
    config_file.write_text(json.dumps(msi.configuration("https://core.invalid", root, "S-1-5-18")))
    config = AgentConfig.load(config_file)
    store = IdentityStore(config)
    public = store.prepare()
    group_file, _ = bootstrap(root)
    before = {file: file.read_bytes() for file in (config_file, group_file, store.root / "identity-key.json")}
    fake_provisioning(monkeypatch)
    monkeypatch.setattr(msi, "consume_file", lambda *a: pytest.fail("rerun cannot consume a new bootstrap"))
    with pytest.raises(ValueError, match="agent_msi_state_unmanaged"):
        msi.provision("https://core.invalid", "", "a" * 64, "synthetic-path", "LocalSystem", root=root)
    assert all(file.read_bytes() == raw for file, raw in before.items())
    assert IdentityStore(config).prepare() == public


def test_offline_retry_preserves_group_file_without_echo_or_one_time_fallback(tmp_path, capsys):
    path, _ = bootstrap(tmp_path)
    config = SimpleNamespace(state_dir=tmp_path / "state", service_identity_sid="S-1-5-18")
    calls = []

    def fail(*args):
        calls.append(1)
        raise OSError("synthetic-private-error")

    store = SimpleNamespace(load=lambda: None, enroll_group=fail,
                            enroll=lambda *args: pytest.fail("one-time fallback"))
    for _ in range(2):
        assert msi.enroll_once(config, store, object()) == "group_enrollment_failed"
    assert path.exists() and len(calls) == 2
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("delta", [-1, msi.GROUP_TTL + 120])
def test_group_expiry_stops_without_contact_or_using_envelope_ttl(tmp_path, delta):
    path, _ = bootstrap(tmp_path, expires=datetime.now(timezone.utc) + timedelta(seconds=delta))
    config = SimpleNamespace(state_dir=tmp_path / "state", service_identity_sid="S-1-5-18")
    store = SimpleNamespace(load=lambda: None, enroll_group=lambda *a: pytest.fail("expired group"))
    assert msi.enroll_once(config, store, object()) == "bootstrap_expired"
    assert not path.exists()


@pytest.mark.parametrize("change", ["credential", "entity", "kind", "utc", "token", "oversized"])
def test_group_file_rejects_unknown_fields_and_invalid_scope(tmp_path, change):
    _, body = bootstrap(tmp_path)
    if change == "credential":
        body["password"] = "synthetic-forbidden"
    elif change == "entity":
        body["computer_entity_id"] = True
    elif change == "kind":
        body["kind"] = "one-time"
    elif change == "utc":
        body["expires_at"] = "2026-01-01T00:00:00"
    elif change == "token":
        body["token"] = "x\n" * 22
    raw = json.dumps(body).encode()
    if change == "oversized":
        raw += b" " * msi.MAX_TOKEN
    with pytest.raises(ValueError, match="^agent_msi_bootstrap_invalid$"):
        msi.group_bootstrap(raw)


@pytest.mark.parametrize("allowed", [False, True], ids=["acl-denied", "acl-allowed"])
def test_group_acl_denial_never_reads_or_submits(tmp_path, monkeypatch, allowed):
    from pathlib import Path

    path, body = bootstrap(tmp_path)
    config = SimpleNamespace(state_dir=tmp_path / "state", service_identity_sid="S-1-5-18")
    checked, reads, enrollments = [], [], []
    original_open = Path.open
    transport = SimpleNamespace(post=lambda *a, **kw: pytest.fail("unexpected transport use"))

    def check(actual):
        assert actual == path
        checked.append(actual)
        if not allowed:
            raise ValueError("synthetic-private-detail")

    def open_bootstrap(actual, *args, **kwargs):
        if actual == path:
            if not allowed:
                pytest.fail("ACL-denied bootstrap was opened")
            assert checked == [path]
            reads.append(actual)
        return original_open(actual, *args, **kwargs)

    def enroll_group(token, entity, actual_transport):
        if not allowed:
            pytest.fail("ACL-denied bootstrap reached enrollment")
        assert (token, entity, actual_transport) == (body["token"], 3, transport)
        enrollments.append((token, entity))

    store = SimpleNamespace(load=lambda: None, enroll_group=enroll_group,
                            enroll=lambda *a: pytest.fail("unexpected one-time enrollment"))
    monkeypatch.setattr(Path, "open", open_bootstrap)
    assert msi.enroll_once(config, store, transport, check=check) == (
        "agent_approval_pending" if allowed else "group_enrollment_failed")
    assert checked == [path]
    assert reads == ([path] if allowed else [])
    assert enrollments == ([(body["token"], 3)] if allowed else [])
    assert path.exists()


@pytest.mark.parametrize("attributes,links,valid", [(0x20, 1, True), (0x400, 1, False), (0x20, 2, False)])
def test_windows_pending_file_retained_only_after_same_handle_validation(tmp_path, monkeypatch, attributes, links, valid):
    import sys

    path, _ = bootstrap(tmp_path)
    raw = path.read_bytes()
    calls = []
    handle = SimpleNamespace(Close=lambda: calls.append("close"))
    monkeypatch.setattr(msi, "os", SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(GENERIC_READ=0x80000000, DELETE=0x10000,
        READ_CONTROL=0x20000, OPEN_EXISTING=3, FILE_ATTRIBUTE_REPARSE_POINT=0x400))
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(FILE_FLAG_OPEN_REPARSE_POINT=0x200000,
        CreateFile=lambda *args: handle, GetFileInformationByHandle=lambda h: (attributes, 0, 0, 0, 0, 0, 0, links),
        GetFileSize=lambda h: len(raw), ReadFile=lambda h, size: (0, raw[:size]),
        SetFileInformationByHandle=lambda *args: pytest.fail("pending file must survive")))
    monkeypatch.setitem(sys.modules, "win32security", SimpleNamespace(SE_FILE_OBJECT=1,
        DACL_SECURITY_INFORMATION=4, OWNER_SECURITY_INFORMATION=1, GetSecurityInfo=lambda *args: "descriptor"))
    monkeypatch.setattr(msi, "private_descriptor", lambda descriptor, sid: calls.append(descriptor))
    if valid:
        assert msi.consume_file(path, "S-1-5-18", check=lambda path: None, retain=True) == raw
        assert calls == ["descriptor", "close"]
    else:
        with pytest.raises(ValueError, match="agent_msi_bootstrap_acl"):
            msi.consume_file(path, "S-1-5-18", check=lambda path: None, retain=True)
        assert calls == ["close"]
    assert path.read_bytes() == raw


def test_managed_service_never_starts_runtime_while_pending(tmp_path, monkeypatch):
    import sli_agent.probe
    import sli_agent.runtime
    import sli_agent.transport

    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state",
                         collection_enabled=False, service_identity_sid="S-1-5-18")
    bootstrap(tmp_path)
    stop = Event()
    monkeypatch.setattr(sli_agent.probe, "service_identity_verified", lambda config: True)
    monkeypatch.setattr(msi, "ensure_ca", lambda config: None)
    monkeypatch.setattr(sli_agent.transport, "Transport", lambda config: object())
    monkeypatch.setattr(IdentityStore, "enroll_group", lambda *a: stop.set())
    monkeypatch.setattr(sli_agent.runtime, "run", lambda *a: pytest.fail("pending must not collect"))
    msi.run_managed(config, stop)
    state = json.loads((config.storage_dir / "status.json").read_bytes())
    assert state == {"collection_enabled": False, "error_code": "agent_approval_pending"}
    assert IdentityStore(config).load() is None
