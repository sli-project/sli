from __future__ import annotations

import pytest

from scripts.maintenance import apply_selected_migrations as tool


def test_confirmation_names_exactly_the_selected_versions() -> None:
    assert tool.confirmation_token([144, 145]) == "APPLY-MIGRATIONS-144-145"


def test_apply_refuses_without_matching_confirmation() -> None:
    with pytest.raises(SystemExit, match="APPLY-MIGRATIONS-144-145"):
        tool.main(["apply", "--versions", "145,144", "--confirm", "APPLY-MIGRATIONS-144"])


def test_unknown_versions_are_refused() -> None:
    with pytest.raises(SystemExit, match="unknown migration versions"):
        tool.main(["plan", "--versions", "13"])


def test_migration_domain_is_validated_and_forwarded_without_discarding_options() -> None:
    environment = tool.migration_environment({
        "ADLOG_REPORT_DOMAIN_FQDN": " Corp.Example.TEST ",
        "PGOPTIONS": "-c statement_timeout=3000",
    })
    assert environment["PGOPTIONS"] == "-c statement_timeout=3000 -c sli.report_domain_fqdn=corp.example.test"
    assert environment["PGCLIENTENCODING"] == "UTF8"


def test_unset_migration_domain_is_not_invented() -> None:
    assert "PGOPTIONS" not in tool.migration_environment({})


@pytest.mark.parametrize("value", ["bad value.test", "x.test -c role=other", ""])
def test_invalid_migration_domain_cannot_inject_connection_options(value) -> None:
    if not value:
        assert "PGOPTIONS" not in tool.migration_environment({"ADLOG_REPORT_DOMAIN_FQDN": value})
    else:
        with pytest.raises(ValueError, match="value_must_be_dns_name"):
            tool.migration_environment({"ADLOG_REPORT_DOMAIN_FQDN": value})


def _resolved_connection(monkeypatch, values):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import psycopg

    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.pgconn.info = [
        SimpleNamespace(keyword=key.encode(), val=value.encode() if value is not None else None)
        for key, value in values.items()
    ]
    connect = MagicMock(return_value=connection)
    monkeypatch.setattr(psycopg, "connect", connect)
    return connect


def test_complete_libpq_contract_is_private_and_round_trips(monkeypatch):
    import os
    from pathlib import Path

    from psycopg import pq

    values = {
        "service": "original-service", "host": "db.example.invalid", "hostaddr": "192.0.2.8",
        "port": "5444", "dbname": "synthetic_db", "user": "synthetic_admin",
        "password": " synthetic\npassword ", "sslmode": "verify-full",
        "sslrootcert": "/synthetic certs/ca.pem", "sslcert": "/synthetic/client.pem",
        "sslkey": "/synthetic/key.pem", "sslpassword": "synthetic key 'secret'\\value",
        "require_auth": "scram-sha-256", "target_session_attrs": "read-write",
        "keepalives_idle": "42", "connect_timeout": "12",
        "options": "-c statement_timeout=3000", "application_name": "synthetic migration",
    }
    connect = _resolved_connection(monkeypatch, values)
    monkeypatch.setenv("PGSERVICE", "original-service")
    monkeypatch.setenv("PGHOST", "wrong.example.invalid")
    monkeypatch.setenv("PGPASSWORD", "old synthetic password")
    monkeypatch.setenv("PGTZ", "UTC")
    monkeypatch.setenv("PGDATESTYLE", "ISO, MDY")
    monkeypatch.setenv("ADLOG_REPORT_DOMAIN_FQDN", "EXAMPLE.TEST")
    before = dict(os.environ)
    parts = {"service": "original-service", "password": values["password"], "connect_timeout": "12"}
    with tool._connection_contract(parts) as contract:
        assert contract == {"service": tool.SERVICE_NAME}
        connect.assert_called_once_with(**parts)
        path = Path(os.environ["PGSERVICEFILE"])
        assert path.is_file()
        if os.name != "nt":
            assert path.stat().st_mode & 0o777 == 0o600
            assert path.parent.stat().st_mode & 0o777 == 0o700
        assert "PGHOST" not in os.environ
        assert os.environ["PGTZ"] == "UTC"
        assert os.environ["PGDATESTYLE"] == "ISO, MDY"
        assert os.environ["PGPASSWORD"] == values["password"]
        assert values["password"] not in path.read_text()
        # This calls libpq's real service parser without connecting anywhere.
        actual = {item.keyword.decode(): item.val.decode() for item in pq.Conninfo.get_defaults()
                  if item.val is not None}
        for key, value in values.items():
            if key not in {"service", "options"}:
                assert actual[key] == value
        assert actual["options"] == "-c statement_timeout=3000 -c sli.report_domain_fqdn=example.test"
        assert actual["client_encoding"] == "UTF8"
    assert dict(os.environ) == before
    assert not path.exists()


@pytest.mark.parametrize("value", ["trailing ", "two\nlines", "two\rlines", "nul\0byte", "x" * 1020])
def test_unrepresentable_options_fail_closed_without_disclosing_value(monkeypatch, value):
    values = {"password": "synthetic password", "sslpassword": value}
    _resolved_connection(monkeypatch, values)
    with pytest.raises(tool.MigrationConnectionError, match="connection_option_not_service_representable") as exc:
        with tool._connection_contract(values):
            pytest.fail("must not admit lossy connection options")
    assert value not in str(exc.value)


def test_contract_cleans_up_after_failure(monkeypatch):
    import os
    from pathlib import Path

    _resolved_connection(monkeypatch, {"password": "synthetic", "dbname": "example"})
    before = dict(os.environ)
    with pytest.raises(RuntimeError):
        with tool._connection_contract({"password": "synthetic"}):
            path = Path(os.environ["PGSERVICEFILE"])
            raise RuntimeError("fixture failure")
    assert dict(os.environ) == before
    assert not path.exists()


def test_admin_parts_preserves_service_hostaddr_tls_and_timeout(monkeypatch):
    monkeypatch.setenv("ADLOG_PG_DSN", "service=synthetic hostaddr=192.0.2.8 sslmode=verify-full connect_timeout=12")
    monkeypatch.setenv("ADLOG_PG_ADMIN_USER", "synthetic_admin")
    monkeypatch.setenv("ADLOG_PG_ADMIN_PASSWORD", "synthetic_secret")
    assert tool._admin_parts() == {
        "service": "synthetic", "hostaddr": "192.0.2.8", "sslmode": "verify-full",
        "connect_timeout": "12", "user": "synthetic_admin", "password": "synthetic_secret",
        "client_encoding": "UTF8",
    }


def test_unknown_libpq_option_is_rejected_before_connect(monkeypatch, capsys):
    import psycopg

    monkeypatch.setenv("ADLOG_PG_DSN", "dbname=synthetic unknown_option=synthetic_secret")
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: pytest.fail("must not connect"))
    assert tool.main(["plan", "--versions", "144"]) == 1
    assert capsys.readouterr().out == '{"error": "migration_connection_or_configuration_failed"}\n'


def _run_fixture(monkeypatch, tmp_path, *, returncode=0, after_identity=None):
    from types import SimpleNamespace

    before = {"applied": {}, "target_identity": "a" * 32}
    after = {"applied": {144: "synthetic"}, "target_identity": after_identity or "a" * 32}
    ledgers = iter([before, after])
    connections = []

    def ledger(parts, versions):
        connections.append((parts, versions))
        return next(ledgers)

    monkeypatch.setattr(tool, "_ledger", ledger)
    invocations = []

    def run(command, **kwargs):
        invocations.append((command, kwargs))
        return SimpleNamespace(returncode=returncode, stderr="synthetic_secret\npassword=do-not-print", stdout="secret")

    monkeypatch.setattr(tool.subprocess, "run", run)
    args = SimpleNamespace(action="apply", bin_dir=tmp_path)
    inventory = {144: SimpleNamespace(path=tmp_path / "synthetic.sql")}
    return args, inventory, connections, invocations


def test_guard_precedes_file_in_same_psql_session_with_no_credentials_in_argv(monkeypatch, tmp_path, capsys):
    args, inventory, connections, invocations = _run_fixture(monkeypatch, tmp_path)
    connection = {"service": tool.SERVICE_NAME}
    monkeypatch.setenv("PGPASSWORD", "synthetic_secret")
    assert tool._run_selected(args, [144], inventory, connection) == 0
    assert connections == [(connection, [144]), (connection, [144])]
    assert len(invocations) == 1
    command, kwargs = invocations[0]
    assert "--no-psqlrc" in command
    assert "--no-password" in command
    assert command.index("--command") < command.index("--file")
    assert command[command.index("--command") + 1] == tool._target_guard("a" * 32)
    assert "--host" not in command and "--dbname" not in command and "--username" not in command
    assert "synthetic_secret" not in repr(command)
    assert kwargs["env"]["PGPASSWORD"] == "synthetic_secret"
    assert "synthetic_secret" not in capsys.readouterr().out


@pytest.mark.parametrize("returncode", [1, 2, 3])
def test_psql_failure_stops_without_retry_downgrade_or_raw_stderr(monkeypatch, tmp_path, capsys, returncode):
    args, inventory, connections, invocations = _run_fixture(monkeypatch, tmp_path, returncode=returncode)
    assert tool._run_selected(args, [144], inventory, {"service": tool.SERVICE_NAME}) == 1
    assert len(invocations) == len(connections) == 1
    output = capsys.readouterr().out
    assert f'"psql_exit_code": {returncode}' in output
    assert "synthetic_secret" not in output and "do-not-print" not in output


def test_readback_checks_identity_not_just_matching_versions(monkeypatch, tmp_path):
    args, inventory, _, _ = _run_fixture(monkeypatch, tmp_path, after_identity="b" * 32)
    with pytest.raises(tool.MigrationConnectionError, match="readback_target_mismatch"):
        tool._run_selected(args, [144], inventory, {"service": tool.SERVICE_NAME})


def test_guard_rejects_untrusted_identity():
    with pytest.raises(tool.MigrationConnectionError, match="invalid_target_identity"):
        tool._target_guard("'; select 'synthetic-injection")


def test_connection_errors_do_not_disclose_credentials(monkeypatch, capsys):
    import psycopg

    monkeypatch.setattr(tool, "_admin_parts", lambda: {"password": "synthetic_secret"})

    def fail(**parts):
        raise psycopg.OperationalError("password=synthetic_secret sslpassword=another_secret")

    monkeypatch.setattr(psycopg, "connect", fail)
    assert tool.main(["plan", "--versions", "144"]) == 1
    assert capsys.readouterr().out == '{"error": "migration_connection_or_configuration_failed"}\n'


def test_already_applied_selection_never_starts_psql(monkeypatch, tmp_path):
    from types import SimpleNamespace

    before = {"applied": {144: "synthetic"}, "target_identity": "a" * 32}
    monkeypatch.setattr(tool, "_ledger", lambda *args: before)
    monkeypatch.setattr(tool.subprocess, "run", lambda *args, **kwargs: pytest.fail("must not write"))
    args = SimpleNamespace(action="apply", bin_dir=tmp_path)
    assert tool._run_selected(args, [144], {}, {"service": tool.SERVICE_NAME}) == 0


@pytest.mark.parametrize(("explicit", "service", "environment", "expected"), [
    ("12", "34", "56", "12"),
    (None, "34", "56", "34"),
    (None, None, "56", "56"),
    (None, None, None, "5"),
    (None, "0", "56", "0"),
])
def test_timeout_precedence_is_resolved_before_fallback(monkeypatch, tmp_path, explicit, service, environment, expected):
    import os

    values = {"password": "synthetic", "connect_timeout": expected}
    connect = _resolved_connection(monkeypatch, values)
    path = tmp_path / "timeout-service.conf"
    path.write_text("[synthetic]\n" + (f"connect_timeout={service}\n" if service else ""), encoding="utf-8")
    monkeypatch.setenv("PGSERVICEFILE", str(path))
    # Explicit service must take precedence over the inherited selector.
    monkeypatch.setenv("PGSERVICE", "wrong-service")
    if environment is None:
        monkeypatch.delenv("PGCONNECT_TIMEOUT", raising=False)
    else:
        monkeypatch.setenv("PGCONNECT_TIMEOUT", environment)
    parts = {"service": "synthetic", "password": "synthetic"}
    if explicit is not None:
        parts["connect_timeout"] = explicit
    with tool._connection_contract(parts):
        assert connect.call_args.kwargs["connect_timeout"] == expected
    assert os.environ["PGSERVICE"] == "wrong-service"


@pytest.mark.parametrize(("application", "fallback", "expected"), [
    ("explicit-name", "fallback-name", "explicit-name"),
    (None, "fallback-name", "fallback-name"),
    (None, None, tool.SERVICE_NAME),
])
def test_application_name_preserves_configured_fallback(monkeypatch, application, fallback, expected):
    from psycopg import pq

    values = {"password": "synthetic", "application_name": application, "fallback_application_name": fallback}
    _resolved_connection(monkeypatch, values)
    with tool._connection_contract({"password": "synthetic"}):
        actual = {item.keyword.decode(): item.val.decode() for item in pq.Conninfo.get_defaults()
                  if item.val is not None}
        assert actual["application_name"] == expected


def test_admin_parts_does_not_preempt_service_or_environment_timeout(monkeypatch):
    monkeypatch.setenv("ADLOG_PG_DSN", "service=synthetic")
    monkeypatch.setenv("ADLOG_PG_ADMIN_USER", "synthetic_admin")
    monkeypatch.setenv("ADLOG_PG_ADMIN_PASSWORD", "synthetic_password")
    monkeypatch.setenv("PGCONNECT_TIMEOUT", "56")
    assert "connect_timeout" not in tool._admin_parts()
