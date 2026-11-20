"""Notification credentials: protected local files and value-free diagnostics."""

import json
import os
from pathlib import Path

import pytest

from deploy.linux import sli_secrets as provision
from server.sli.core import notification_secrets as subject

SMTP = "notification_smtp_password"
TELEGRAM = "notification_telegram_token"
SYNTHETIC_VALUES = {SMTP: " synthetic smtp password ", TELEGRAM: "12345:synthetic_telegram_token"}


@pytest.fixture
def ownership(monkeypatch):
    if os.name == "nt":
        monkeypatch.setattr(provision, "_windows_acl", lambda *args, **kwargs: None)
    else:
        monkeypatch.setattr(provision.os, "geteuid", lambda: 0)
        monkeypatch.setattr(provision.os, "chown", lambda *args: None)
        monkeypatch.setattr(provision, "_check_owner", lambda *args: None)


def protected_import(tmp_path, ref, value=None):
    path = tmp_path / (ref + "_import")
    path.write_text(value if value is not None else SYNTHETIC_VALUES[ref], encoding="utf-8")
    path.chmod(0o640)
    return path


@pytest.mark.parametrize("ref", [SMTP, TELEGRAM])
def test_import_read_status_and_idempotence(tmp_path, ownership, ref, caplog, capsys):
    source = protected_import(tmp_path, ref)
    directory = tmp_path / "secrets"
    assert provision.ensure(directory, names=[ref], imports={ref: source}) == 1
    target = directory / ref
    before = (target.read_bytes(), target.stat().st_mtime_ns)
    assert provision.ensure(directory, names=[ref], imports={ref: source}) == 0
    assert (target.read_bytes(), target.stat().st_mtime_ns) == before
    environ = {subject.NOTIFICATION_SECRET_SETTINGS[ref] + "_FILE": str(target)}
    assert subject.read_notification_secret(ref, environ=environ) == SYNTHETIC_VALUES[ref]
    assert subject.notification_secret_status(ref, environ=environ) == {
        "secret_status": "available", "secret_error": None,
    }
    assert environ == {subject.NOTIFICATION_SECRET_SETTINGS[ref] + "_FILE": str(target)}
    assert not caplog.text and not capsys.readouterr().out


@pytest.mark.parametrize("ref", [SMTP, TELEGRAM])
def test_absent_notification_credential_is_never_generated(tmp_path, ownership, ref):
    with pytest.raises(provision.SecretError, match="^notifications: import_required$"):
        provision.ensure(tmp_path / "secrets", names=["runtime_password", ref])
    assert list((tmp_path / "secrets").iterdir()) == []
    assert subject.notification_secret_status(ref, environ={}) == {
        "secret_status": "not_configured", "secret_error": "notification_secret_not_configured",
    }


def test_disabled_notifications_do_not_change_default_provisioning(tmp_path, ownership):
    directory = tmp_path / "secrets"
    provision.ensure(directory, tls_names=["127.0.0.1"])
    assert not any((directory / ref).exists() for ref in subject.NOTIFICATION_SECRET_SETTINGS)


@pytest.mark.parametrize("ref,body", [
    (SMTP, b""), (SMTP, b"synthetic\n"), (SMTP, b"synthetic\x00"),
    (SMTP, b"\xff"), (SMTP, b"x" * 65537),
    (TELEGRAM, b"synthetic-invalid"), (TELEGRAM, b"123:with spaces"),
    (TELEGRAM, b"0:synthetic"), (TELEGRAM, b"123:"),
])
def test_invalid_import_is_refused_before_any_publication(tmp_path, ownership, ref, body, caplog, capsys):
    source = protected_import(tmp_path, ref)
    source.write_bytes(body)
    with pytest.raises(provision.SecretError) as error:
        provision.ensure(tmp_path / "secrets", names=["runtime_password", ref], imports={ref: source})
    assert str(error.value) in {f"{ref}: invalid_format", "notifications: secret_unavailable_or_unprotected"}
    assert list((tmp_path / "secrets").iterdir()) == []
    assert not caplog.text and not capsys.readouterr().out


@pytest.mark.parametrize("ref", [SMTP, TELEGRAM])
def test_plaintext_environment_and_path_references_are_refused(tmp_path, ref, caplog):
    setting = subject.NOTIFICATION_SECRET_SETTINGS[ref]
    environ = {setting: SYNTHETIC_VALUES[ref], setting + "_FILE": str(tmp_path / "private")}
    assert subject.notification_secret_status(ref, environ=environ) == {
        "secret_status": "invalid", "secret_error": "notification_secret_file_required",
    }
    with pytest.raises(subject.NotificationSecretError, match="^notification_secret_ref_invalid$"):
        subject.read_notification_secret(str(tmp_path / "private"), environ=environ)
    assert not caplog.text


@pytest.mark.parametrize("ref", [SMTP, TELEGRAM])
@pytest.mark.parametrize("kind", ["missing", "directory", "invalid_utf8", "empty", "permission"])
def test_unreadable_files_have_fixed_diagnostics(tmp_path, monkeypatch, ref, kind, caplog):
    path = tmp_path / "private"
    if kind == "directory":
        path.mkdir()
    elif kind in {"invalid_utf8", "empty"}:
        path.write_bytes(b"\xff" if kind == "invalid_utf8" else b"")
    elif kind == "permission":
        def denied(*args, **kwargs):
            raise PermissionError("synthetic-private-path-and-value")
        monkeypatch.setattr(Path, "open", denied)
    environ = {subject.NOTIFICATION_SECRET_SETTINGS[ref] + "_FILE": str(path)}
    status = subject.notification_secret_status(ref, environ=environ)
    assert status == {"secret_status": "unavailable", "secret_error": "notification_secret_unavailable"}
    assert "private" not in json.dumps(status) and not caplog.text


def test_bad_telegram_format_has_fixed_error_and_does_not_expose_material(tmp_path, caplog):
    path = protected_import(tmp_path, TELEGRAM, "synthetic-invalid-private-value")
    environ = {subject.NOTIFICATION_SECRET_SETTINGS[TELEGRAM] + "_FILE": str(path)}
    assert subject.notification_secret_status(TELEGRAM, environ=environ) == {
        "secret_status": "invalid", "secret_error": "notification_secret_invalid",
    }
    with pytest.raises(subject.NotificationSecretError) as error:
        subject.read_notification_secret(TELEGRAM, environ=environ)
    assert str(error.value) == "notification_secret_invalid" and not caplog.text


@pytest.mark.parametrize("ref", [SMTP, TELEGRAM])
def test_explicit_atomic_replacement_is_required(tmp_path, ownership, ref, monkeypatch):
    source = protected_import(tmp_path, ref)
    directory = tmp_path / "secrets"
    provision.ensure(directory, names=[ref], imports={ref: source})
    before = (directory / ref).read_bytes()
    replacement = "synthetic replacement" if ref == SMTP else "67890:synthetic_replacement"
    source.write_text(replacement, encoding="utf-8")
    with pytest.raises(provision.SecretError, match="replacement_required"):
        provision.ensure(directory, names=[ref], imports={ref: source})
    assert (directory / ref).read_bytes() == before
    replace = provision.os.replace
    calls = []
    def atomic(source_path, target_path):
        assert target_path.read_bytes() == before
        assert source_path.read_text("utf-8") == replacement
        if os.name != "nt":
            assert source_path.stat().st_mode & 0o777 == 0o640
        calls.append(target_path)
        replace(source_path, target_path)
    monkeypatch.setattr(provision.os, "replace", atomic)
    assert provision.ensure(directory, names=[ref], imports={ref: source}, replace=True) == 1
    assert calls == [directory / ref]
    assert (directory / ref).read_text("utf-8") == replacement
    assert list(directory.iterdir()) == [directory / ref]


def test_invalid_replacement_preserves_existing_credential(tmp_path, ownership):
    source = protected_import(tmp_path, TELEGRAM)
    directory = tmp_path / "secrets"
    provision.ensure(directory, names=[TELEGRAM], imports={TELEGRAM: source})
    source.write_bytes(b"synthetic-invalid-replacement")
    with pytest.raises(provision.SecretError, match="invalid_format"):
        provision.ensure(directory, names=[TELEGRAM], imports={TELEGRAM: source}, replace=True)
    assert (directory / TELEGRAM).read_text("utf-8") == SYNTHETIC_VALUES[TELEGRAM]


def test_failed_atomic_replacement_preserves_existing_credential(tmp_path, ownership, monkeypatch, capsys):
    source = protected_import(tmp_path, SMTP)
    directory = tmp_path / "secrets"
    provision.ensure(directory, names=[SMTP], imports={SMTP: source})
    source.write_text("synthetic replacement", encoding="utf-8")

    def failed_replace(*args):
        raise PermissionError("synthetic-private-path-and-value")

    monkeypatch.setattr(provision.os, "replace", failed_replace)
    assert provision.main(["ensure", "--directory", str(directory), "--replace",
                           "--import-file", f"{SMTP}={source}"]) == 1
    assert (directory / SMTP).read_text("utf-8") == SYNTHETIC_VALUES[SMTP]
    assert list(directory.iterdir()) == [directory / SMTP]
    output = capsys.readouterr()
    assert output.err == "sli-secrets: operation_failed_check_directory_and_permissions\n"
    assert not output.out


def test_replace_cannot_rotate_other_platform_credentials(tmp_path, ownership):
    source = protected_import(tmp_path, SMTP)
    with pytest.raises(provision.SecretError, match="single_import_required_for_replacement"):
        provision.ensure(tmp_path / "secrets", names=["runtime_password"],
                         imports={"runtime_password": source}, replace=True)
    assert not (tmp_path / "secrets").exists()


@pytest.mark.parametrize("bad", ["missing", "directory", "symlink", "broad_mode"])
def test_cli_refuses_unsafe_import_without_disclosing_path_or_value(tmp_path, ownership, capsys, caplog, bad):
    if os.name == "nt" and bad in {"symlink", "broad_mode"}:
        pytest.skip("POSIX path permissions")
    source = tmp_path / "synthetic-private-source"
    if bad == "directory":
        source.mkdir()
    elif bad == "symlink":
        source.symlink_to(protected_import(tmp_path, SMTP))
    elif bad == "broad_mode":
        source.write_text(SYNTHETIC_VALUES[SMTP], encoding="utf-8")
        source.chmod(0o644)
    assert provision.main(["ensure", "--directory", str(tmp_path / "secrets"),
                           "--import-file", f"{SMTP}={source}"]) == 1
    output = capsys.readouterr()
    assert output.err == "sli-secrets: notifications: secret_unavailable_or_unprotected\n"
    assert not output.out and not caplog.text


def test_cli_import_and_replacement_work_without_generating_core_or_tls(tmp_path, ownership, capsys):
    source = protected_import(tmp_path, SMTP)
    directory = tmp_path / "secrets"
    args = ["ensure", "--directory", str(directory), "--import-file", f"{SMTP}={source}"]
    assert provision.main(args) == 0
    assert list(directory.iterdir()) == [directory / SMTP]
    source.write_text("synthetic replacement", encoding="utf-8")
    assert provision.main([*args, "--replace"]) == 0
    assert (directory / SMTP).read_text("utf-8") == "synthetic replacement"
    output = capsys.readouterr()
    assert output.out == "sli-secrets: checked; created 1 files\n" * 2
    assert not output.err


def delivery_config():
    return {"secrets": {ref: {"file": "${SLI_SECRETS_DIR}/" + ref}
                        for ref in subject.NOTIFICATION_SECRET_SETTINGS},
            "services": {subject.NOTIFICATION_DELIVERY_SERVICE: {
                "secrets": list(subject.NOTIFICATION_SECRET_SETTINGS),
                "environment": {setting + "_FILE": "/run/secrets/" + ref
                                for ref, setting in subject.NOTIFICATION_SECRET_SETTINGS.items()},
            }}}


def test_delivery_process_can_mount_both_credentials():
    provision.validate_compose(delivery_config())


@pytest.mark.parametrize("service", ["api", "collection", "semantic", "storage"])
def test_other_processes_cannot_mount_notification_credentials(service):
    config = delivery_config()
    config["services"][service] = config["services"].pop(subject.NOTIFICATION_DELIVERY_SERVICE)
    with pytest.raises(provision.SecretError, match="delivery_only_mount_required"):
        provision.validate_compose(config)


@pytest.mark.parametrize("bad", ["plaintext", "inherited_mapping", "inherited_list", "missing_mount",
                                 "arbitrary_path", "wrong_source"])
def test_delivery_config_rejects_unsafe_secret_settings(bad):
    config = delivery_config()
    worker = config["services"][subject.NOTIFICATION_DELIVERY_SERVICE]
    setting = subject.NOTIFICATION_SECRET_SETTINGS[SMTP]
    if bad == "plaintext":
        worker["environment"][setting] = SYNTHETIC_VALUES[SMTP]
    elif bad == "inherited_mapping":
        worker["environment"][setting] = None
    elif bad == "inherited_list":
        worker["environment"] = [setting]
    elif bad == "missing_mount":
        worker["secrets"] = []
    elif bad == "arbitrary_path":
        worker["environment"][setting + "_FILE"] = "/synthetic-private"
    else:
        worker["secrets"] = [TELEGRAM, {"source": "runtime_password", "target": SMTP}]
    with pytest.raises(provision.SecretError, match="notifications:"):
        provision.validate_compose(config)


def test_shipped_compose_does_not_require_or_mount_notifications_when_disabled():
    import yaml

    root = Path(__file__).resolve().parents[2]
    for path in (root / "deploy").rglob("*compose*.y*ml"):
        config = yaml.safe_load(path.read_text("utf-8"))
        assert not set(config.get("secrets", {})) & subject.NOTIFICATION_SECRET_SETTINGS.keys()
        provision.validate_compose(config)
