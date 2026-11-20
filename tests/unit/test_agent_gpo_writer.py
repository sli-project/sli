"""Stage 1 uses fakes only; no database or directory connection."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sli_agent import gpo_writer as writer
from sli_agent import gpo_writer_service as service


SID = "S-1-5-21-100-200-300"
OU = "11111111-1111-4111-8111-111111111111"
GPO = "22222222-2222-4222-8222-222222222222"


def config(**changes):
    return writer.WriterConfig(**(dict(domain_dns="directory.invalid", domain_sid=SID,
        dc="dc.directory.invalid", writer_sid=SID + "-1100", allowed_ou_guids=(OU,),
        msi_path=r"C:\SLI\package.msi", msi_sha256="a" * 64, signer_sha256="b" * 64) | changes))


def available(cfg):
    rows = {key: {"status": "available", "reason": "verified"} for key in writer.expected_checks(cfg)}
    if cfg.managed_gpo_guid is None:
        for key in ("gpo_edit", "gpo_acl", "gpt_edit"):
            rows[key] = {"status": "not_applicable", "reason": "no_managed_gpo"}
    return rows


def inspect(cfg, rows):
    return writer.preflight(cfg, reader=SimpleNamespace(inspect=lambda _: rows))


def test_create_readiness_requires_every_ou_and_never_enables_writes():
    cfg = config(allowed_ou_guids=(OU, GPO))
    rows = available(cfg)
    assert inspect(cfg, rows)["ready"] is True
    rows["ou_1"] = {"status": "denied", "reason": "access_denied"}
    report = inspect(cfg, rows)
    assert report["ready"] is False
    assert report["write_enabled"] is False and report["mode"] == "read_only"
    assert report["allowed_ou_count"] == 2
    assert report["checks"][-1] == dict(check="ou_1", status="denied", reason="access_denied", required=True)


@pytest.mark.parametrize("check", ["identity", "domain", "gpo_create", "gpt_create", "ou_0", "package"])
def test_missing_delegation_or_evidence_blocks_readiness(check):
    cfg = config()
    rows = available(cfg)
    rows[check] = {"status": "denied", "reason": "access_denied"}
    assert inspect(cfg, rows)["ready"] is False
    del rows[check]
    assert inspect(cfg, rows)["ready"] is False


def test_existing_gpo_requires_edit_acl_and_gpt_without_requiring_create_rights():
    cfg = config(managed_gpo_guid=GPO)
    rows = available(cfg)
    for key in ("gpo_create", "gpt_create"):
        rows[key] = {"status": "denied", "reason": "access_denied"}
    assert inspect(cfg, rows)["ready"] is True
    for key in ("gpo_edit", "gpo_acl", "gpt_edit"):
        broken = rows | {key: {"status": "not_applicable", "reason": "no_managed_gpo"}}
        assert inspect(cfg, broken)["ready"] is False


@pytest.mark.parametrize("bad", [None, [], "ready", {}, {"status": []},
    {"status": "available", "reason": {}}, {"status": "available", "reason": "access_denied"},
    {"status": "not_applicable", "reason": "no_managed_gpo"}])
def test_malformed_or_skipped_identity_never_becomes_ready(bad):
    cfg = config()
    rows = available(cfg) | {"identity": bad}
    assert inspect(cfg, rows)["ready"] is False


def test_exception_and_native_extra_fields_cannot_disclose_directory_data():
    cfg = config()
    marker = "PRIVATE_SOURCE_MARKER"
    def failed(_):
        raise RuntimeError(marker)
    report = writer.preflight(cfg, reader=SimpleNamespace(inspect=failed))
    assert report["ready"] is False and marker not in json.dumps(report)
    rows = available(cfg)
    rows["identity"]["private"] = marker
    rows[marker] = marker
    report = inspect(cfg, rows)
    assert report["ready"] is True
    body = json.dumps(report)
    assert all(value not in body for value in (marker, cfg.domain_dns, SID, OU, cfg.msi_path))


@pytest.mark.parametrize("change", [dict(allowed_ou_guids=()), dict(allowed_ou_guids=(OU, OU.upper())),
    dict(allowed_ou_guids=("not-guid",)), dict(allowed_ou_guids=("00000000-0000-0000-0000-000000000000",)),
    dict(allowed_ou_guids=(OU,) * 129), dict(allowed_ou_guids=[OU]), dict(writer_sid="S-1-5-18"),
    dict(writer_sid=SID + "-512"), dict(writer_sid="S-1-5-21-1-2-3-1100"), dict(domain_sid="invalid"),
    dict(dc="dc/RootDSE"), dict(domain_dns="https://directory.invalid"),
    dict(msi_path=r"\\host\share\package.msi"), dict(msi_path=r"C:\SLI\..\package.msi"),
    dict(msi_path=r"C:\SLI\package.msi:stream"), dict(msi_path="package.msi"), dict(msi_sha256="bad"),
    dict(signer_sha256=None), dict(managed_gpo_guid="not-guid")])
def test_invalid_local_scope_or_package_configuration_is_rejected(change):
    with pytest.raises(ValueError, match="^gpo_writer_config_invalid$"):
        config(**change)


def test_config_is_strict_and_cli_has_no_apply_or_delegation_command(tmp_path, capsys, monkeypatch):
    path = tmp_path / "writer.json"
    path.write_text(json.dumps(config().payload()), encoding="utf-8")
    assert writer.WriterConfig.load(path) == config()
    monkeypatch.setattr(writer.WindowsPreflightReader, "inspect", lambda _, cfg: available(cfg))
    assert writer.main(["--config", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["write_enabled"] is False
    path.write_text(json.dumps(config().payload() | {"apply": True}), encoding="utf-8")
    assert writer.main(["--config", str(path)]) == 1
    assert "gpo_writer_config_invalid" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        writer.main(["--config", str(path), "apply"])


def test_native_reader_uses_only_fixed_script_stdin_and_a_timeout(monkeypatch):
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="{}")
    monkeypatch.setattr(writer, "os", SimpleNamespace(name="nt", environ={}))
    monkeypatch.setattr(writer.subprocess, "run", run)
    assert writer.WindowsPreflightReader().inspect(config()) == {}
    args, kwargs = calls[0]
    assert args[-2:] == ["-File", str(Path(writer.__file__).with_suffix(".ps1"))]
    assert kwargs["timeout"] == 90 and kwargs["capture_output"] is True
    assert kwargs.get("shell", False) is False
    assert config().writer_sid not in " ".join(args)
    assert json.loads(kwargs["input"])["allowed_ou_guids"] == [OU]


def test_native_failure_exit_cannot_report_ready(monkeypatch):
    monkeypatch.setattr(writer, "os", SimpleNamespace(name="nt", environ={}))
    monkeypatch.setattr(writer.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1, stdout="{}"))
    assert writer.preflight(config())["ready"] is False


def test_native_timeout_is_sanitized_and_blocks_readiness(monkeypatch):
    monkeypatch.setattr(writer, "os", SimpleNamespace(name="nt", environ={}))
    def timeout(*args, **kwargs):
        raise writer.subprocess.TimeoutExpired("PRIVATE_COMMAND_MARKER", 90, output="PRIVATE_SOURCE_MARKER")
    monkeypatch.setattr(writer.subprocess, "run", timeout)
    report = writer.preflight(config())
    assert report["ready"] is False
    assert "PRIVATE_" not in json.dumps(report)


@pytest.mark.parametrize("owner,aces,expected", [
    ("S-1-5-18", [(0, 0, 0x1f01ff, "S-1-5-18"), (0, 0, 0x120089, "S-1-5-11")], True),
    ("S-1-5-18", [(0, 0, 0x2, SID + "-1100")], False),
    ("S-1-5-18", [(0, 0, 0x40000000, "S-1-1-0")], False),
    ("S-1-5-18", None, False), (SID + "-1100", [], False),
    ("S-1-5-18", [(5, 0, 0, "S-1-5-11")], False),
])
def test_service_binaries_and_map_are_not_writable_by_writer_or_users(owner, aces, expected):
    assert service._restricted_descriptor(owner, aces) is expected


def test_diagnostics_service_is_separate_from_collector_and_never_receives_commands(tmp_path):
    cfg = config()
    path = tmp_path / "writer.json"
    path.write_text(json.dumps(cfg.payload()), encoding="utf-8")
    calls, saved = [], []
    stop = SimpleNamespace(is_set=lambda: bool(saved), wait=lambda _: None)
    service.run_diagnostics(path, stop, check_installation=lambda p: calls.append(p),
        inspect=lambda c: inspect(c, available(c)), save=lambda p, data: saved.append((p, json.loads(data))))
    assert calls == [path]
    assert saved[0][0] == tmp_path / "state" / "preflight.json"
    assert saved[0][1]["write_enabled"] is False
    assert service.SERVICE_NAME != "SLIAgent"


def test_unprotected_installation_stops_before_any_source_read(tmp_path):
    calls = []
    def reject(_):
        raise ValueError("gpo_writer_local_protection_failed")
    with pytest.raises(ValueError, match="local_protection_failed"):
        service.run_diagnostics(tmp_path / "writer.json", SimpleNamespace(is_set=lambda: False),
            check_installation=reject, inspect=lambda _: calls.append("read"), save=lambda *args: calls.append("save"))
    assert calls == []


def test_scm_wrapper_uses_its_own_name_config_and_sanitized_errors(monkeypatch):
    import sys
    class Framework:
        def __init__(self, args):
            self.statuses = []

        def ReportServiceStatus(self, status):
            self.statuses.append(status)
    errors, runs = [], []
    manager = SimpleNamespace(LogErrorMsg=errors.append)
    monkeypatch.setitem(sys.modules, "win32serviceutil", SimpleNamespace(ServiceFramework=Framework))
    monkeypatch.setitem(sys.modules, "win32service", SimpleNamespace(SERVICE_STOP_PENDING=3))
    monkeypatch.setitem(sys.modules, "servicemanager", manager)
    monkeypatch.setattr(service, "os", SimpleNamespace(name="nt", environ={}))
    monkeypatch.setattr(service, "run_diagnostics", lambda path, stop: runs.append((path, stop)))
    cls = service.service_class()
    instance = cls([service.SERVICE_NAME])
    instance.SvcDoRun()
    assert cls._svc_name_ == "SLIGpoWriter"
    assert runs[0][0] == Path(r"C:\ProgramData") / "SLI" / "GpoWriter" / "writer.json"
    instance.SvcStop()
    assert instance.stop.is_set() and instance.statuses == [3]
    def fail(*args):
        raise ValueError("PRIVATE_SOURCE_MARKER")
    monkeypatch.setattr(service, "run_diagnostics", fail)
    with pytest.raises(RuntimeError, match="^gpo_writer_diagnostics_failed$"):
        instance.SvcDoRun()
    assert errors == ["SLI GPO writer stopped: gpo_writer_diagnostics_failed"]
