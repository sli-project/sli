"""Cold PostgreSQL placement contracts; synthetic host and subprocesses only."""
import json
import os
from pathlib import Path
import subprocess
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from deploy.linux import native_clickhouse_endpoint as site
from deploy.linux import native_host as host


@pytest.mark.parametrize("value", ["relative", "/", "/mnt/../cold", "/mnt/cold/", "/mnt//cold",
                                  "/srv/sli-db/cold", "/var/lib/postgresql/cold", "/etc/cold",
                                  "/mnt/cold space", "/mnt/cold'", "/mnt/cold%", True])
def test_cold_path_rejects_unsafe_or_system_locations(value):
    with pytest.raises(ValueError, match="native_site_cold_tablespace_root_invalid"):
        site.parse_site("cold_tablespace_root = " + json.dumps(value))


def test_optional_site_setting_and_mount_generation():
    legacy = site.parse_site("")
    assert "cold_tablespace_root" not in legacy
    config = site.parse_site('cold_tablespace_root = "/mnt/cold"')
    assert config["cold_tablespace_root"] == "/mnt/cold"
    body = host.cold_mount_dropin("/mnt/cold")
    assert "RequiresMountsFor=/mnt/cold" in body
    assert "check-cold-mount" in body
    assert "ExecStartPre=+" in body


def test_tablespace_creation_is_idempotent_and_refuses_foreign_location():
    sql = host.cold_tablespace_sql("/mnt/cold")
    assert "CREATE TABLESPACE" in sql and "\\gexec" in sql
    assert "/mnt/cold/pg-tablespace" in sql
    assert "pg_tablespace_location" in sql and "spcowner" in sql
    assert "native_cold_tablespace_conflict" in sql
    assert "GRANT" not in sql and "default_tablespace" not in sql


def rows():
    return [{"oid": 100 + i, "table": name, "tablespace": "pg_default"}
            for i, name in enumerate(host.COLD_TABLES)]


def test_move_sql_keeps_indexes_and_checks_relation_identity():
    sql = host.cold_move_sql(rows(), rollback=False)
    for row in rows():
        assert f'ALTER TABLE public."{row["table"]}" SET TABLESPACE "sli_temp_hdd"' in sql
        assert str(row["oid"]) in sql
    assert sql.startswith("BEGIN;") and sql.rstrip().endswith("COMMIT;")
    assert "ALTER INDEX" not in sql and "CREATE INDEX" not in sql
    assert "statement_timeout=0" in sql and "lock_timeout=0" in sql
    assert "native_cold_relation_changed" in sql
    original = rows()
    original[0]["tablespace"] = 'original"space'
    reverse = host.cold_move_sql(original, rollback=True)
    assert 'SET TABLESPACE "original""space"' in reverse


@pytest.mark.parametrize("change", [lambda data: data.pop(),
                                       lambda data: data[0].update(table="events_v2_core"),
                                       lambda data: data[0].update(oid="1;drop table x"),
                                       lambda data: data[0].update(tablespace="bad\nname")])
def test_invalid_journal_cannot_generate_sql(change):
    data = rows()
    change(data)
    with pytest.raises(host.HostError, match="native_cold_journal_invalid"):
        host.cold_move_sql(data, rollback=True)


@pytest.fixture
def machine(tmp_path, monkeypatch):
    machine = host.Host(tmp_path)
    monkeypatch.setattr(host.clickhouse, "site_configuration", lambda root: {"cold_tablespace_root": "/mnt/cold"})
    monkeypatch.setattr(machine, "receipt", lambda: None)
    monkeypatch.setattr(machine, "validate_cold_root", lambda value: {"root": value, "uuid": "synthetic-volume", "fsroot": "/"})
    monkeypatch.setattr(machine, "configure_cold_storage", lambda: "/mnt/cold")
    monkeypatch.setattr(machine, "require_cold_mount", lambda: "/mnt/cold")
    monkeypatch.setattr(machine, "validate_receipt_file", lambda path: None)
    calls = []
    monkeypatch.setattr(host, "run", lambda argv: "")
    monkeypatch.setattr(host, "pg_cold", lambda sql: calls.append(sql) or json.dumps(rows()))
    monkeypatch.setattr(machine, "write", lambda name, body, *args, **kwargs:
                        (machine.path(name).parent.mkdir(parents=True, exist_ok=True),
                         machine.path(name).write_text(body)))
    return machine, calls


def test_plan_is_read_only_and_explains_lock_and_reverse(machine, capsys):
    machine, calls = machine
    machine.place_cold_tables("plan")
    assert len(calls) == 1 and "SELECT" in calls[0]
    assert not machine.path(host.STATE).exists()
    output = capsys.readouterr().out
    assert "rollback" in output and "TOAST" in output
    assert "блокиров" in output


def test_apply_saves_original_placement_before_move_and_rollback_reuses_it(machine, monkeypatch):
    machine, calls = machine
    journal = machine.path(host.STATE + "/cold-tablespace-move.json")
    def pg(sql):
        calls.append(sql)
        if sql.startswith("BEGIN;"):
            assert journal.exists(), "rollback intent must survive a killed command"
        return json.dumps(rows())
    monkeypatch.setattr(host, "pg_cold", pg)
    machine.place_cold_tables("apply")
    saved = journal.read_bytes()
    assert json.loads(saved)["tables"] == rows()
    machine.place_cold_tables("rollback")
    assert journal.read_bytes() == saved
    assert 'SET TABLESPACE "pg_default"' in calls[-1]


def test_failed_move_can_retry_without_losing_original_placement(machine, monkeypatch):
    machine, calls = machine
    journal = machine.path(host.STATE + "/cold-tablespace-move.json")
    def fail(sql):
        if sql.startswith("BEGIN;"):
            raise host.HostError("native_cold_sql_failed")
        return json.dumps(rows())
    monkeypatch.setattr(host, "pg_cold", fail)
    with pytest.raises(host.HostError, match="native_cold_sql_failed"):
        machine.place_cold_tables("apply")
    saved = journal.read_bytes()
    monkeypatch.setattr(host, "pg_cold", lambda sql: calls.append(sql) or json.dumps(rows()))
    machine.place_cold_tables("apply")
    machine.place_cold_tables("rollback")
    assert journal.read_bytes() == saved


def test_replaced_relation_is_rejected_before_move(machine, monkeypatch):
    machine, calls = machine
    machine.place_cold_tables("apply")
    different = rows()
    different[0]["oid"] += 100
    monkeypatch.setattr(host, "pg_cold", lambda sql: json.dumps(different))
    with pytest.raises(host.HostError, match="native_cold_relation_changed"):
        machine.place_cold_tables("apply")


@pytest.mark.parametrize("defect,code", [("missing", "native_cold_root_invalid"),
                                       ("permissions", "native_cold_root_untrusted"),
                                       ("same_device", "native_cold_root_same_device"),
                                       ("readonly", "native_cold_root_invalid"),
                                       ("network", "native_cold_root_invalid"),
                                       ("uuid", "native_cold_root_invalid"), (None, None)])
def test_second_disk_validation(monkeypatch, defect, code):
    source = SimpleNamespace(is_dir=lambda: defect != "missing", parents=[],
                             lstat=lambda: SimpleNamespace(st_uid=host.ROOT_UID,
                                                           st_mode=0o777 if defect == "permissions" else 0o755))
    machine = host.Host()
    monkeypatch.setattr(machine, "path", lambda value: source if value == "/mnt/cold" else None)
    monkeypatch.setattr(machine, "backup_device", lambda path: 1 if path is None or defect == "same_device" else 2)
    fs = {"uuid": None if defect == "uuid" else "synthetic-volume", "fsroot": "/",
          "fstype": "nfs" if defect == "network" else "ext4", "options": "ro" if defect == "readonly" else "rw"}
    monkeypatch.setattr(host, "run", lambda argv: json.dumps({"filesystems": [fs]}))
    if code:
        with pytest.raises(host.HostError, match=code):
            machine.validate_cold_root("/mnt/cold")
    else:
        assert machine.validate_cold_root("/mnt/cold")["uuid"] == "synthetic-volume"


def test_changed_mount_refused(machine, monkeypatch):
    machine, _ = machine
    saved = machine.path(host.STATE + "/cold-tablespace.json")
    saved.parent.mkdir(parents=True)
    saved.write_text(json.dumps({"root": "/mnt/cold", "uuid": "original-volume", "fsroot": "/"}))
    with pytest.raises(host.HostError, match="native_cold_mount_mismatch"):
        host.Host.require_cold_mount(machine)


def test_legacy_install_has_no_cold_storage_side_effects(tmp_path, monkeypatch):
    monkeypatch.setattr(host.clickhouse, "site_configuration", lambda root: {})
    assert host.Host(tmp_path).configure_cold_storage() is None
    assert not list(tmp_path.iterdir())


def test_configure_creates_private_directory_and_persistent_mount_guard(machine, monkeypatch):
    machine, _ = machine
    created = []
    def directory(name, mode, owner, group):
        created.append((name, mode, owner, group))
        machine.path(name).mkdir(parents=True)
    monkeypatch.setattr(machine, "directory", directory)
    assert host.Host.configure_cold_storage(machine) == "/mnt/cold"
    assert created == [("/mnt/cold/pg-tablespace", 0o700, "postgres", "postgres")]
    saved = json.loads(machine.path(host.STATE + "/cold-tablespace.json").read_text())
    assert saved == {"root": "/mnt/cold", "uuid": "synthetic-volume", "fsroot": "/"}
    unit = machine.path("/etc/systemd/system/sli-postgresql.service.d/85-sli-cold-mount.conf").read_text()
    assert "RequiresMountsFor=/mnt/cold" in unit and "check-cold-mount" in unit
    monkeypatch.setattr(machine, "validate_cold_root", lambda root: dict(saved, uuid="replacement-volume"))
    with pytest.raises(host.HostError, match="native_cold_mount_mismatch"):
        host.Host.configure_cold_storage(machine)
    assert created == [("/mnt/cold/pg-tablespace", 0o700, "postgres", "postgres")]


def test_foreign_tablespace_directory_is_not_adopted(machine, monkeypatch):
    machine, _ = machine
    target = machine.path("/mnt/cold/pg-tablespace")
    target.mkdir(parents=True)
    retained = target / "foreign-data"
    retained.write_text("synthetic bytes")
    monkeypatch.setattr(host, "account", lambda name: None)
    with pytest.raises(host.HostError, match="native_cold_directory_conflict"):
        host.Host.configure_cold_storage(machine)
    assert retained.read_text() == "synthetic bytes"
    assert not machine.path(host.STATE + "/cold-tablespace.json").exists()


def test_setup_site_renderer_keeps_cold_path():
    from deploy.linux import native_setup
    value = site.parse_site('cold_tablespace_root = "/mnt/cold"')
    assert site.parse_site(native_setup.render_site(value)) == value


def test_setup_accepts_capacity_disk_option(monkeypatch):
    from deploy.linux import native_setup
    seen = []
    monkeypatch.setattr(native_setup.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(native_setup, "setup_lock", nullcontext)
    monkeypatch.setattr(native_setup, "configure", lambda args: seen.append(args.cold_tablespace_root))
    assert native_setup.main(["--cold-tablespace-root", "/mnt/cold", "--server", "example.test", "--non-interactive"]) == 0
    assert seen == ["/mnt/cold"]


def test_cli_routes_under_administrative_lock(monkeypatch):
    calls = []
    monkeypatch.setattr(host.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(host, "administrative_lock", nullcontext)
    monkeypatch.setattr(host, "Host", lambda: SimpleNamespace(place_cold_tables=calls.append))
    assert host.main(["cold-tables", "apply"]) == 0
    assert calls == ["apply"]


def test_pg_process_heartbeats_without_deadline(monkeypatch, capsys):
    calls = []
    class Process:
        pid, returncode = 123, 0
        def communicate(self, body=None, timeout=None):
            calls.append(timeout)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired("synthetic psql", timeout)
            return "[]", ""
        def poll(self):
            return 0
    monkeypatch.setattr(host.subprocess, "Popen", lambda *args, **kwargs: Process())
    assert host.pg_cold("SELECT 1") == "[]"
    assert calls == [10, 10]
    assert "123" in capsys.readouterr().out


def test_disposable_postgres_moves_toast_preserves_indexes_and_reverses(tmp_path, monkeypatch):
    """Opt-in private cluster; never uses an existing socket, data dir or stand."""
    import socket
    import time
    tools = os.environ.get("SLI_TABLESPACE_TEST_PG_BIN")
    if not tools:
        pytest.skip("set SLI_TABLESPACE_TEST_PG_BIN for a disposable PostgreSQL integration test")
    tools = Path(tools)
    suffix = ".exe" if os.name == "nt" else ""
    data, cold = tmp_path / "pg", tmp_path / "cold"
    cold.mkdir()
    (cold / "pg-tablespace").mkdir()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    def tool(name, args, body=None, *, check=True):
        result = subprocess.run([str(tools / (name + suffix)), *args], input=body,
                                text=True, capture_output=True, check=False)
        if check:
            assert result.returncode == 0, result.stderr
        return result
    tool("initdb", ["-D", str(data), "-U", "postgres", "--auth=trust", "--no-locale", "-E", "UTF8"])
    def sql(body, *, check=True):
        return tool("psql", ["-XqAt", "-w", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres",
                             "-d", "postgres", "-v", "ON_ERROR_STOP=1"], body, check=check).stdout.strip()
    log = (tmp_path / "postgres.log").open("w")
    process = subprocess.Popen([str(tools / ("postgres" + suffix)), "-D", str(data), "-h", "127.0.0.1", "-p", str(port)],
                               stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    try:
        for _ in range(100):
            result = sql("SHOW data_directory;", check=False)
            if result:
                assert Path(result).resolve() == data.resolve()
                break
            assert process.poll() is None, (tmp_path / "postgres.log").read_text()
            time.sleep(0.1)
        else:
            pytest.fail("disposable PostgreSQL did not become ready")
        monkeypatch.setattr(site, "cold_tablespace_root_path", lambda path: path)
        creation = host.cold_tablespace_sql(cold.as_posix())
        sql(creation)
        # Windows returns backslashes from the catalog. Production uses POSIX
        # paths; adapt only this disposable test's location literal.
        actual = sql("SELECT pg_tablespace_location(oid) FROM pg_tablespace WHERE spcname='sli_temp_hdd';")
        assert Path(actual).resolve() == (cold / "pg-tablespace").resolve()
        creation = creation.replace(cold.as_posix() + "/pg-tablespace", actual)
        sql(creation)  # idempotent
        conflicting = tmp_path / "other"
        (conflicting / "pg-tablespace").mkdir(parents=True)
        assert "native_cold_tablespace_conflict" in tool(
            "psql", ["-XqAt", "-w", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres",
                     "-d", "postgres", "-v", "ON_ERROR_STOP=1"],
            host.cold_tablespace_sql(conflicting.as_posix()), check=False).stderr
        for name in host.COLD_TABLES:
            sql(f'CREATE TABLE public."{name}" (id int PRIMARY KEY, payload text); '
                f'ALTER TABLE public."{name}" ALTER COLUMN payload SET STORAGE EXTERNAL; '
                f'INSERT INTO public."{name}" SELECT 1,repeat(md5(\'synthetic\'),10000);')
        before = json.loads(sql(host.cold_rows_sql()))
        indexes = "SELECT oid,reltablespace FROM pg_class WHERE relkind='i' AND relnamespace='public'::regnamespace ORDER BY oid;"
        original_indexes = sql(indexes)
        sql(host.cold_move_sql(before, rollback=False))
        sql(host.cold_move_sql(before, rollback=False))  # repeat after uncertain commit
        after = json.loads(sql(host.cold_rows_sql()))
        assert {row["tablespace"] for row in after} == {host.COLD_TABLESPACE}
        assert sql(indexes) == original_indexes
        assert sql("SELECT count(*) FROM pg_class c JOIN pg_class t ON t.oid=c.reltoastrelid "
                   "JOIN pg_tablespace s ON s.oid=t.reltablespace WHERE c.relnamespace='public'::regnamespace "
                   "AND s.spcname='sli_temp_hdd';") == "4"
        sql(host.cold_move_sql(before, rollback=True))
        assert json.loads(sql(host.cold_rows_sql())) == before
        assert sql(indexes) == original_indexes
        for name in host.COLD_TABLES:
            assert sql(f'SELECT length(payload) FROM public."{name}" WHERE id=1;') == "320000"
        # A later table conflict cancels earlier moves within the transaction.
        stale = [dict(row) for row in before]
        stale[-1]["oid"] += 100000
        result = tool("psql", ["-XqAt", "-w", "-h", "127.0.0.1", "-p", str(port), "-U", "postgres",
                               "-d", "postgres", "-v", "ON_ERROR_STOP=1"], host.cold_move_sql(stale, rollback=False), check=False)
        assert result.returncode != 0 and "native_cold_relation_changed" in result.stderr
        assert json.loads(sql(host.cold_rows_sql())) == before
    finally:
        if process.poll() is None:
            tool("pg_ctl", ["-D", str(data), "-m", "fast", "-w", "stop"])
        process.wait()
        log.close()
