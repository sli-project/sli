"""Package DDL upgrades: pinned SQL, no application credentials or live DBs."""

import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time

import pytest

from deploy.linux import native_pg_inventory as inventory

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def release(tmp_path):
    root = tmp_path / "release"
    (root / "config/postgres_migrations").mkdir(parents=True)
    (root / "deploy/linux").mkdir(parents=True)
    (root / "config/postgres_schema_v8.sql").write_bytes(
        b"insert into schema_migrations(version,name) values "
        b"(333,'storage_lifecycle_wait') on conflict(version) do nothing;\n")
    for path in (ROOT / "config/postgres_migrations").glob("*.sql"):
        if path.name.startswith(("334_", "335_")):
            (root / "config/postgres_migrations" / path.name).write_bytes(path.read_bytes())
    (root / "deploy/linux/native_pg_ledger.json").write_text(
        json.dumps(inventory.build_manifest(root)), encoding="utf-8")
    return root


def test_changed_package_sql_is_refused_before_connecting(release, monkeypatch):
    from deploy.linux import native_pg_migrate as subject

    path = release / "config/postgres_migrations/335_event_storage_s2.sql"
    path.write_bytes(path.read_bytes() + b"\nselect 'changed';\n")
    monkeypatch.setattr(subject, "run_sql", lambda _: pytest.fail("SQL must not reach PostgreSQL"))
    with pytest.raises(ValueError, match="^native_pg_sql_inventory_mismatch$"):
        subject.migrate(release)


@pytest.mark.parametrize("error", ["native_pg_migration_checksum_mismatch", "private-synthetic-row"])
def test_peer_runner_redacts_errors_and_never_inherits_credentials(monkeypatch, capsys, error):
    from deploy.linux import native_pg_migrate as subject

    monkeypatch.setenv("PGPASSWORD", "synthetic-only")
    monkeypatch.setenv("PGHOST", "foreign.example.test")
    monkeypatch.setenv("PGPASSFILE", "must-not-read")
    calls = []

    class Process:
        pid = 144
        returncode = None

        def communicate(self, body=None, timeout=None):
            calls.append((body, timeout))
            if body is not None:
                raise subprocess.TimeoutExpired("psql", 10, output=b"PostgreSQL: migration 334\nprivate-synthetic-row\n")
            self.returncode = 1
            return "", "ERROR: " + error + "\n"

        def poll(self):
            return self.returncode

        def terminate(self):
            pytest.fail("a live migration must not be terminated by a polling interval")

    def launch(argv, **options):
        assert argv[:4] == ["runuser", "-u", "postgres", "--"]
        assert argv[argv.index("-h") + 1] == "/var/run/postgresql"
        assert argv[argv.index("-U") + 1] == "postgres"
        assert "-w" in argv and "-XqAt" in argv
        assert not any(key in options["env"] for key in ("PGPASSWORD", "PGHOST", "PGPASSFILE"))
        return Process()

    monkeypatch.setattr(subject.subprocess, "Popen", launch)
    expected = error if error.startswith("native_pg_") else "native_pg_migration_failed"
    with pytest.raises(RuntimeError) as failure:
        subject.run_sql("select 1;")
    assert str(failure.value) == expected
    assert calls == [("select 1;", 10), (None, 10)]
    output = capsys.readouterr().out
    assert "334" in output and "144" in output
    assert "private-synthetic-row" not in output and "synthetic-only" not in output


def test_peer_runner_reports_postgres_error_without_sql_rows_or_credentials(monkeypatch, capsys):
    from deploy.linux import native_pg_migrate as subject

    class Process:
        returncode = 3

        def communicate(self, *args, **kwargs):
            return "", (
                "NOTICE: setup\n" * 30
                + "ERROR: permission denied for table entity_states\n"
                + "DETAIL: private-synthetic-row\n"
                + "DETAIL: ERROR: private-synthetic-row\n"
                + "CONTEXT: SQL statement insert into private_table\n"
                + "LINE 1: select 'private-synthetic-row'\n"
                + "ERROR: connection postgresql://example:example-secret@db.example.test/sli\n"
                + "ERROR: host=db.example.test user=synthetic password='synthetic secret'\n"
                + 'psql:stdin:8: ERROR: invalid input syntax for type uuid: "private-synthetic-value"\n'
            )

        def poll(self):
            return self.returncode

    monkeypatch.setattr(subject.subprocess, "Popen", lambda *a, **kw: Process())
    with pytest.raises(RuntimeError, match="native_pg_migration_failed") as failure:
        subject.run_sql("select 1;")
    output = capsys.readouterr().err
    assert "ERROR: permission denied for table entity_states" in output
    assert "ERROR: permission denied for table entity_states" in "\n".join(failure.value.__notes__)
    for private in ("private-synthetic-row", "private_table", "postgresql://", "example-secret",
                    "db.example.test", "synthetic secret", "NOTICE", "private-synthetic-value"):
        assert private not in output


def test_upgrade_348_with_legacy_state_permissions_to_357(tmp_path, postgres):
    """The real baseline and migrations, with the installed cross-owner ACLs."""
    from deploy.linux import native_pg_migrate as subject
    from scripts.maintenance import existing_postgres_bootstrap as bootstrap

    # This regression exercises the 357 index release, independently of later
    # releases which intentionally remove the legacy tables asserted below.
    release = tmp_path / "release357"
    (release / "config/postgres_migrations").mkdir(parents=True)
    (release / "deploy/linux").mkdir(parents=True)
    (release / "config/postgres_schema_v8.sql").write_bytes((ROOT / "config/postgres_schema_v8.sql").read_bytes())
    for path in (ROOT / "config/postgres_migrations").glob("*.sql"):
        if path.name[:3].isdigit() and int(path.name[:3]) <= 357:
            (release / "config/postgres_migrations" / path.name).write_bytes(path.read_bytes())
    (release / "deploy/linux/native_pg_ledger.json").write_text(json.dumps(inventory.build_manifest(release)))

    def execute(body):
        result = postgres(body)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    assert 180000 <= int(execute("show server_version_num;")) < 190000
    execute("create role adlog_user login;")
    migrations = bootstrap.forward_migration_inventory(ROOT / "config/postgres_migrations")
    baseline = bootstrap.load_baseline(ROOT / "config/postgres_baseline", migrations)
    rendered = bootstrap.render_baseline_schema(baseline, "example.test", tmp_path / "baseline.sql")
    execute(baseline.roles_path.read_text(encoding="utf-8"))
    execute(rendered.read_text(encoding="utf-8"))
    execute("insert into auth_users(username,password_hash,role) "
            "values('platform-owner','synthetic-unusable-hash','admin');")
    for item in migrations:
        if baseline.version < item.version <= 348:
            execute(item.path.read_text(encoding="utf-8"))
    assert execute("select max(version) from schema_migrations;") == "348"
    # entity_states originates in the runtime-owned schema; projection 019 is
    # storage-owned. Never repair this fixture by granting runtime membership.
    execute("""
        alter table public.entity_states owner to adlog_user;
        alter table public.entity_state_current owner to adlog_storage_owner;
        revoke all on public.entity_states from adlog_storage_owner;
        revoke select(evidence_event_id) on public.entity_states from adlog_storage_owner;
    """)
    assert execute("select has_column_privilege('adlog_storage_owner',"
                   "'public.entity_states','evidence_event_id','SELECT');") == "f"
    assert execute("select has_table_privilege('adlog_storage_owner',"
                   "'public.entity_state_current','SELECT');") == "t"
    denied = postgres("set role adlog_storage_owner; select evidence_event_id from public.entity_states "
                      "union select source_event_db_id from public.entity_state_current;")
    assert denied.returncode != 0 and "permission denied for table entity_states" in denied.stderr
    execute("""
        insert into servers(id,domain_id,hostname,fqdn,role)
            values(194,1,'dc194','dc194.example.test','domain_controller');
        insert into storage_v2_channel(id,value) values(194,'Security');
        insert into storage_v2_entity_type(id,value) values(194,'user');
        insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            values(194,194,'S-1-5-21-100000001-200000002-300000003-194','synthetic-user',1,decode(repeat('a',64),'hex'));
        insert into events_v2_core(id,server_id,domain_id,log_source_id,event_record_id,event_id,channel_id,
                                  time_created_utc,normalized_at,normalized_hash,source_core_sha256,noise_catalog_version)
            select id,194,1,1,id,4624,194,'2026-11-16T00:00:00Z',now(),
                   decode(repeat('a',64),'hex'),decode(repeat('b',64),'hex'),
                   (select version from event_catalog_revisions order by id limit 1)
            from generate_series(19401,19402) id;
        insert into entity_states(entity_id,state_type,observed_at_utc,evidence_event_id,summary)
            values(194,'synthetic-state','2026-11-16T00:00:00Z',19401,'preserve-state');
        insert into entity_state_current(entity_id,state_type,status,observed_at,source_event_db_id,rule_id,rule_version)
            values(194,'synthetic-state','observed','2026-11-16T00:00:00Z',19402,'synthetic-rule','1');
    """)
    retained_states = execute("select row_to_json(s) from entity_states s; select row_to_json(s) from entity_state_current s;")
    assert execute("select count(*) from storage_v2_event_identity_allocations where id in (19401,19402);") == "0"
    state_acl = execute("select relname,relowner,relacl from pg_class where oid in "
                        "('public.entity_states'::regclass,'public.entity_state_current'::regclass) order by relname;")
    execute(subject.upgrade_sql(release))
    assert execute("select max(version) from schema_migrations;") == "357"
    ledger_sql = "select json_agg(m order by version) from (select version,name,sha256 from schema_migrations) m;"
    actual = json.loads(execute(ledger_sql))
    assert actual == inventory.expected_ledger(release)
    assert execute("select relname,relowner,relacl from pg_class where oid in "
                   "('public.entity_states'::regclass,'public.entity_state_current'::regclass) order by relname;") == state_acl
    assert execute("select confrelid::regclass from pg_constraint where conname in "
                   "('entity_states_evidence_event_id_v2_fkey','entity_state_current_source_event_db_id_fkey') "
                   "order by conname;") == "storage_v2_event_identity_allocations\nstorage_v2_event_identity_allocations"
    assert execute("select string_agg(id::text,',' order by id) from storage_v2_event_identity_allocations;") == "19401,19402"
    execute("delete from events_v2_core where id in (19401,19402);")
    assert execute("select row_to_json(s) from entity_states s; select row_to_json(s) from entity_state_current s;") == retained_states
    execute(subject.upgrade_sql(release))
    assert json.loads(execute(ledger_sql)) == actual


@contextmanager
def private_postgres(tmp_path):
    """Only a cluster created by this test; never inspect or use an existing DB."""
    tools = os.environ.get("SLI_UPGRADE_TEST_PG_BIN")
    if not tools:
        pytest.skip("set SLI_UPGRADE_TEST_PG_BIN for the private PostgreSQL upgrade test")
    tools = Path(tools)
    tmp_path.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if os.name == "nt" else ""
    data = tmp_path / "pg"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]

    def tool(name, args, body=None):
        return subprocess.run([str(tools / (name + suffix)), *args], input=body,
                              text=True, encoding="utf-8", capture_output=True, check=False,
                              env={"PATH": os.environ.get("PATH", ""), "SystemRoot": os.environ.get("SystemRoot", ""),
                                   "LC_ALL": "C", "PGCLIENTENCODING": "UTF8", "PGTZ": "UTC"})

    result = tool("initdb", ["-D", str(data), "-U", "postgres", "--auth=trust", "--no-locale", "-E", "UTF8"])
    assert result.returncode == 0, result.stderr
    args = ["-XqAt", "-w", "-h", "127.0.0.1", "-p", str(port), "-v", "ON_ERROR_STOP=1"]

    def sql(body, *, user="postgres", database="postgres"):
        return tool("psql", [*args, "-U", user, "-d", database], body)

    sql.port = port
    sql.tools = tools
    # PostgreSQL resolves a relative socket directory inside its private data directory.
    socket_args = [] if os.name == "nt" else ["-k", "."]
    with (tmp_path / "postgres.log").open("w") as log:
        process = subprocess.Popen([str(tools / ("postgres" + suffix)), "-D", str(data),
                                    "-h", "127.0.0.1", "-p", str(port), *socket_args],
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            for _ in range(100):
                result = sql("show data_directory;")
                if result.returncode == 0:
                    assert Path(result.stdout.strip()).resolve() == data.resolve()
                    break
                assert process.poll() is None, (tmp_path / "postgres.log").read_text()
                time.sleep(0.1)
            else:
                pytest.fail("private PostgreSQL did not start")
            yield sql
        finally:
            if process.poll() is None:
                # Wait for our own PostgreSQL process, including its shutdown checkpoint.
                stopped = tool("pg_ctl", ["-D", str(data), "-m", "fast", "-W", "stop"])
                assert stopped.returncode == 0, stopped.stderr
            assert process.wait() == 0, (tmp_path / "postgres.log").read_text()


@pytest.fixture
def postgres(tmp_path):
    with private_postgres(tmp_path) as query:
        yield query


def test_native_407_upgrade_uses_index_to_copy_exact_finding_evidence(tmp_path, postgres):
    from deploy.linux import native_pg_migrate as subject
    from scripts.maintenance import existing_postgres_bootstrap as bootstrap

    def execute(body, *, database="sli"):
        result = postgres(body, database=database)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    migrations = bootstrap.forward_migration_inventory(ROOT / "config/postgres_migrations")
    baseline = bootstrap.load_baseline(ROOT / "config/postgres_baseline", migrations)
    rendered = bootstrap.render_baseline_schema(baseline, "example.test", tmp_path / "baseline.sql",
                                                seed_report_domain=False)
    execute("""
        create role sli_migration login noinherit;
        create role adlog_user login noinherit;
        create database sli owner sli_migration;
    """, database="postgres")
    linux = ROOT / "deploy/linux"
    grants = (linux / "runtime_grants.sql").read_text(encoding="utf-8")
    execute("\n".join(("begin;", baseline.roles_path.read_text(encoding="utf-8"),
                       rendered.read_text(encoding="utf-8"), grants,
                       (linux / "default_semantic_policy.sql").read_text(encoding="utf-8"), "commit;")))
    execute("\n".join(item.path.read_text(encoding="utf-8") for item in migrations
                      if baseline.version < item.version <= 407))
    execute(grants)
    assert execute("select max(version) from public.schema_migrations;") == "407"

    execute("""
        create role synthetic_evidence_login login noinherit;
        grant adlog_semantic_worker to synthetic_evidence_login;
        insert into public.sli_agents(id,host_id,key_fingerprint,registration_host_name,status,assigned_modules)
        values ('00000000-0000-4000-8000-000000000408','00000000-0000-4000-8000-000000000408',
            repeat('c',64),'evidence.example.test','active',
            '[{"module_id":"sli.windows.ad-dc","enabled":true,"config":{"channels":{"Security":true}}}]');
        select public.create_event_storage_partitions(current_date-1,current_date);
        begin;
        set local session_replication_role='replica';
        insert into public.event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256)
        select g.id,date_trunc('day',now())-
            case when g.id=1 then interval '1 hour' else interval '0' end,
            4625,1,'fixture',jsonb_build_object('$channel','Security','$origin',jsonb_build_object(
                'installation_id',i.installation_id::text,'plugin_id','sli.windows.ad-dc',
                'source_instance_id','fixture-evidence','source_generation','fixture-generation',
                'collection_scope_id','','log_source_id',88,'agent_id','00000000-0000-4000-8000-000000000408')),
            '{}','{}',sha256(convert_to(g.id::text,'UTF8'))
        from generate_series(1,60001) g(id) cross join public.semantic_default_installation i;
        insert into public.event_hot(event_id,time_created_utc,event_kind,domain_id,computer,method,outcome,fields,source_sha256)
        select event_id,date_trunc('day',now()),event_kind,domain_id,computer,
            jsonb_set(method,'{$origin,source_instance_id}','"fixture-other-source"'),
            outcome,fields,decode(repeat('ef',32),'hex') from public.event_hot where event_id=1;
        commit;
        analyze public.event_hot;
        insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
            source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
        select r.oid,r.rolname,i.installation_id,'sli.windows.ad-dc','fixture-evidence','fixture-generation',
            '','core_event',88,'00000000-0000-4000-8000-000000000408'
        from pg_roles r cross join public.semantic_default_installation i where r.rolname='synthetic_evidence_login';
        insert into public.findings(id,fingerprint,rule_code,title,severity,status,evidence_count) values
            (40801,'synthetic-before-408','semantic.qw.password-brute-force','fixture','high','new',1),
            (40802,'synthetic-after-408','semantic.qw.password-brute-force','fixture','high','new',1),
            (40803,'synthetic-plan-408','semantic.qw.password-brute-force','fixture','high','new',1);
    """)
    definition = """select pg_get_functiondef('public.copy_finding_event337(bigint,text,text,text,text)'::regprocedure);"""
    metadata = """
        select proowner::regrole,proacl,prosecdef,provolatile,proconfig from pg_proc
        where oid='public.copy_finding_event337(bigint,text,text,text,text)'::regprocedure;
    """
    original, permissions = execute(definition), execute(metadata)
    assert permissions.startswith("adlog_storage_owner|")
    assert execute("""
        select has_function_privilege('adlog_semantic_worker',
            'public.copy_finding_event337(bigint,text,text,text,text)','execute');
    """) == "f"

    def plan_for_copy():
        statement = re.search(r"(?s)(insert into public\.finding_event_copies337\b.*?on conflict do nothing);",
                              execute(definition)).group(1)
        parameters = {"p_finding": "$1", "p_native": "$2", "p_hash": "$3", "p_role": "$4", "p_note": "$5"}
        statement = re.sub(r"\bp_(finding|native|hash|role|note)\b",
                           lambda match: parameters[match.group()], statement)
        plan = execute(f"""
            begin;
            set local plan_cache_mode='force_generic_plan';
            prepare evidence_copy(bigint,text,text,text,text) as {statement};
            explain (analyze, format json) execute evidence_copy(
                40803,'1','{digest}','semantic_scenario',null);
            rollback;
        """)
        return json.loads(plan)[0]

    def nodes(node):
        yield node
        for child in node.get("Plans", []):
            yield from nodes(child)

    def link(finding, source="fixture-evidence", event_hash=None):
        return postgres(f"""
            set session authorization synthetic_evidence_login;
            set role adlog_semantic_worker;
            select public.link_finding_evidence_ref({finding},'{installation}','sli.windows.ad-dc',
                '{source}','fixture-generation','','core_event','1','{event_hash or digest}');
        """, database="sli")

    def copied(finding):
        return execute(f"""
            select count(*),count(distinct source_sha256) from public.finding_event_copies337 where finding_id={finding};
        """)

    digest = hashlib.sha256(b"1").hexdigest()
    installation = execute("select installation_id from public.semantic_default_installation;")
    before = plan_for_copy()
    result = link(40801)
    assert (result.returncode, result.stdout.strip()) == (0, "t"), result.stderr
    assert copied(40801) == "1|1"

    release = tmp_path / "release-408"
    scripts = release / "config/postgres_migrations"
    scripts.mkdir(parents=True)
    shutil.copytree(ROOT / "config/postgres_baseline", release / "config/postgres_baseline")
    shutil.copyfile(ROOT / "config/postgres_schema_v8.sql", release / "config/postgres_schema_v8.sql")
    for path in (ROOT / "config/postgres_migrations").glob("*.sql"):
        version = path.name.partition("_")[0]
        if not version.isdigit() or int(version) <= 408:
            shutil.copyfile(path, scripts / path.name)
    (release / "deploy/linux").mkdir(parents=True)
    (release / "deploy/linux/native_pg_ledger.json").write_text(json.dumps(inventory.build_manifest(release)))
    upgrade = subject.upgrade_sql(release)
    execute(upgrade)

    after = plan_for_copy()
    assert any("event_id" in n.get("Index Cond", "") for n in nodes(after["Plan"]))
    removed_before = sum(n.get("Rows Removed by Filter", 0) for n in nodes(before["Plan"]))
    removed_after = sum(n.get("Rows Removed by Filter", 0) for n in nodes(after["Plan"]))
    assert removed_before >= 60000
    assert removed_after <= 1
    assert before["Plan"]["Tuples Inserted"] == after["Plan"]["Tuples Inserted"] == 1
    print(f"Evidence copy before: {before['Execution Time']:.3f} ms, {removed_before} rows filtered; "
          f"after: {after['Execution Time']:.3f} ms, {removed_after} rows filtered")
    assert execute(metadata) == permissions
    assert execute("select max(version) from public.schema_migrations;") == "408"
    for source, event_hash in (("fixture-other-source", "ef" * 32), ("fixture-evidence", "ef" * 32)):
        denied = link(40802, source, event_hash)
        assert denied.returncode != 0 and "evidence_unavailable_or_denied" in denied.stderr
    for added in ("t", "f"):
        result = link(40802)
        assert (result.returncode, result.stdout.strip()) == (0, added), result.stderr
    assert copied(40802) == "1|1"
    assert execute(f"""
        select bool_or(public.copy_finding_event337(40803,n,'{digest}','semantic_scenario',null))
        from (values (null::text),('01'),('+1'),(' 1'),('9223372036854775808'),('native-id')) v(n);
    """) == "f"
    assert copied(40803) == "0|0"
    execute("insert into public.finding_evidence(finding_id,event_id,evidence_role,note) "
            "values (40803,1,'semantic_scenario','legacy');")
    assert copied(40803) == "2|2"

    execute("delete from public.event_hot where event_id=1;")
    archived = """select jsonb_agg(to_jsonb(c) order by finding_id,time_created_utc)::text
        from public.finding_event_copies337 c;"""
    retained = execute(archived)
    rollback = scripts / "408_index_finding_evidence_copy.rollback.sql"
    execute(rollback.read_text(encoding="utf-8"))
    assert execute(definition) == original
    assert execute(metadata) == permissions
    assert execute(archived) == retained
    execute(upgrade)
    assert execute(archived) == retained


def test_native_404_upgrade_installs_radius_admission_with_unchanged_schema_acl(tmp_path, postgres):
    from deploy.linux import native_pg_migrate as subject
    from scripts.maintenance import existing_postgres_bootstrap as bootstrap

    def execute(body, *, database="sli"):
        result = postgres(body, database=database)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    linux = ROOT / "deploy/linux"
    migrations = bootstrap.forward_migration_inventory(ROOT / "config/postgres_migrations")
    baseline = bootstrap.load_baseline(ROOT / "config/postgres_baseline", migrations)
    rendered = bootstrap.render_baseline_schema(baseline, "example.test", tmp_path / "baseline.sql",
                                                seed_report_domain=False)
    execute("""
        create role sli_migration login noinherit;
        create role adlog_user login noinherit;
        create database sli owner sli_migration;
    """, database="postgres")
    execute("""
        revoke all on database sli from public;
        grant connect on database sli to adlog_user;
        revoke create on schema public from public;
        grant usage on schema public to adlog_user;
    """)
    grants = (linux / "runtime_grants.sql").read_text(encoding="utf-8")
    execute("\n".join(("begin;", baseline.roles_path.read_text(encoding="utf-8"),
                       rendered.read_text(encoding="utf-8"), grants,
                       (linux / "default_semantic_policy.sql").read_text(encoding="utf-8"), "commit;")))
    execute("\n".join(item.path.read_text(encoding="utf-8") for item in migrations
                      if baseline.version < item.version <= 404))
    execute(grants)

    schema_acl = "select nspowner::regrole, nspacl from pg_namespace where nspname='public';"
    predecessor_acl = execute(schema_acl)
    assert execute("""
        select has_schema_privilege('adlog_storage_owner','public','create'),
               has_schema_privilege('adlog_storage_owner','public','create with grant option'),
               has_schema_privilege('adlog_plugin_lifecycle_owner','public','create');
    """) == "t|f|f"
    assert execute("select max(version) from public.schema_migrations;") == "404"

    release = tmp_path / "release-406"
    scripts = release / "config/postgres_migrations"
    scripts.mkdir(parents=True)
    shutil.copytree(ROOT / "config/postgres_baseline", release / "config/postgres_baseline")
    shutil.copyfile(ROOT / "config/postgres_schema_v8.sql", release / "config/postgres_schema_v8.sql")
    for path in (ROOT / "config/postgres_migrations").glob("*.sql"):
        version = path.name.partition("_")[0]
        if not version.isdigit() or int(version) <= 406:
            shutil.copyfile(path, scripts / path.name)
    (release / "deploy/linux").mkdir(parents=True)
    (release / "deploy/linux/native_pg_ledger.json").write_text(json.dumps(inventory.build_manifest(release)))

    upgrade = subject.upgrade_sql(release)
    execute(upgrade)
    assert execute(schema_acl) == predecessor_acl
    assert execute("""
        select proowner::regrole from pg_proc where oid in (
            'public.radius_accounting_plugin_ready406()'::regprocedure,
            'public.radius_accounting_source_ready406(text,text,text,text,boolean)'::regprocedure
        ) order by proname;
    """) == "adlog_plugin_lifecycle_owner\nadlog_storage_owner"
    ledger = "select json_agg(m order by version) from (select version,name,sha256 from public.schema_migrations) m;"
    assert json.loads(execute(ledger)) == inventory.expected_ledger(release)
    execute(upgrade)
    assert execute(schema_acl) == predecessor_acl
    assert json.loads(execute(ledger)) == inventory.expected_ledger(release)


def test_native_396_queue_upgrade_preserves_published_397(tmp_path, postgres, monkeypatch):
    from deploy.linux import native_install, native_pg_migrate as subject, native_upgrade
    from scripts.maintenance import existing_postgres_bootstrap as bootstrap

    def execute(body, *, user="postgres", database="sli"):
        result = postgres(body, user=user, database=database)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    linux = ROOT / "deploy/linux"
    migrations = bootstrap.forward_migration_inventory(ROOT / "config/postgres_migrations")
    baseline = bootstrap.load_baseline(ROOT / "config/postgres_baseline", migrations)
    rendered = bootstrap.render_baseline_schema(baseline, "example.test", tmp_path / "baseline.sql",
                                                seed_report_domain=False)
    execute("""
        create role sli_migration login noinherit;
        create role adlog_user login noinherit;
        create database sli owner sli_migration;
    """, database="postgres")
    execute("""
        revoke all on database sli from public;
        grant connect on database sli to adlog_user;
        revoke create on schema public from public;
        grant usage on schema public to adlog_user;
    """)
    grants = (linux / "runtime_grants.sql").read_text(encoding="utf-8")
    execute("\n".join(("begin;", baseline.roles_path.read_text(encoding="utf-8"),
                       rendered.read_text(encoding="utf-8"), grants,
                       (linux / "default_semantic_policy.sql").read_text(encoding="utf-8"), "commit;")))
    execute("\n".join(item.path.read_text(encoding="utf-8") for item in migrations
                      if baseline.version < item.version <= 396))
    execute(grants)

    release = tmp_path / "release-397"
    scripts = release / "config/postgres_migrations"
    scripts.mkdir(parents=True)
    shutil.copytree(ROOT / "config/postgres_baseline", release / "config/postgres_baseline")
    shutil.copyfile(ROOT / "config/postgres_schema_v8.sql", release / "config/postgres_schema_v8.sql")
    for path in (ROOT / "config/postgres_migrations").glob("*.sql"):
        version = path.name.partition("_")[0]
        if not version.isdigit() or int(version) <= 397:
            (scripts / path.name).write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))
    (release / "deploy/linux").mkdir(parents=True)
    (release / "deploy/linux/native_pg_ledger.json").write_text(json.dumps(inventory.build_manifest(release)))
    published = inventory.expected_ledger(release)
    predecessor = published[:-1]
    assert published[-1] == {"version": 397, "name": "problem_queue_workflow",
                             "sha256": "7cc816e0c92586a2b61c398416798749aaa273429c63288eda98a083db1d1f83"}
    migration = scripts / "397_problem_queue_workflow.sql"
    rollback = migration.with_suffix(".rollback.sql")
    assert hashlib.sha256(rollback.read_bytes()).hexdigest() == (
        "980d876c17a958c1c9e622ded1c4c7ed914823acbeb77f448312f3d8f4137909"
    )

    ledger_sql = """
        select json_agg(m order by version) from (select version,name,sha256 from public.schema_migrations) m;
    """
    execute(f"""
        alter table public.schema_migrations add column if not exists sha256 text;
        update public.schema_migrations m set sha256=e.sha256
        from json_to_recordset('{json.dumps(predecessor)}') as e(version int,name text,sha256 text)
        where (m.version,m.name)=(e.version,e.name);
    """)
    inventory.verify_ledger(json.loads(execute(ledger_sql)), predecessor, root=release)

    catalog_sql = """
        select jsonb_build_array(to_jsonb(r), to_jsonb(d))
        from public.report_registry_v4 r join public.report_datasets_v4 d on d.id=r.dataset_id
        where r.report_key='security.queue' and r.status='published';
    """
    rights_sql = """
        select c.relname, c.relowner::regrole, c.relacl, a.attname, a.attacl
        from pg_class c join pg_attribute a on a.attrelid=c.oid and a.attnum>0
        where c.oid in ('public.report_registry_v4'::regclass,'public.report_datasets_v4'::regclass)
        order by c.relname,a.attnum;
    """
    before_catalog = execute(catalog_sql, user="adlog_user")
    report, dataset = json.loads(before_catalog)
    assert report["definition_json"]["export_policy"] == "disabled"
    assert "export" not in report["definition_json"]["actions"] and "export" not in dataset["actions_json"]
    before_rights = execute(rights_sql)
    before_roles = execute("select * from pg_auth_members order by oid;")
    assert all("|sli_migration|" in line for line in before_rights.splitlines())
    assert execute("""
        select session_user, current_user, rolinherit, rolsuper from pg_roles where rolname=session_user;
    """, user="sli_migration") == "sli_migration|sli_migration|f|f"

    old_entry = "set role adlog_storage_owner;\n" + migration.read_text(encoding="utf-8")
    failed = postgres(old_entry, database="sli")
    assert failed.returncode != 0 and "permission denied for table report_registry_v4" in failed.stderr
    assert execute("select max(version),to_regclass('public.finding_queue_deferrals') from schema_migrations;") == "396|"

    manifest = {"python": "python", "python_sha256": "synthetic", "postgres_version": "18.6",
                "plugins": {}, "roles": [], "migration_ledger": published}
    # Temporary releases are not installed as root. Still compare their real bytes.
    monkeypatch.setattr(native_install, "trusted", Path.read_bytes)
    assert native_upgrade.migration_required({**manifest, "migration_ledger": predecessor}, manifest, "", release)
    assert not native_upgrade.migration_required(manifest, manifest, "", release)
    monkeypatch.setattr(subject, "run_sql", execute)
    subject.migrate(release)
    assert execute("select relowner::regrole from pg_class where oid='public.finding_queue_deferrals'::regclass;") == "adlog_storage_owner"
    assert execute(catalog_sql, user="adlog_user") == before_catalog
    assert execute(rights_sql) == before_rights
    assert execute("select * from pg_auth_members order by oid;") == before_roles
    inventory.verify_ledger(json.loads(execute(ledger_sql)), published, root=release)
    subject.migrate(release)
    inventory.verify_ledger(json.loads(execute(ledger_sql)), published, root=release)

    # A standalone migration/rollback caller is explicitly allowed to SET ROLE.
    # This fixture-only grant leaves the authenticated migration login NOINHERIT.
    execute("grant adlog_storage_owner to sli_migration with inherit false;")
    execute("insert into public.schema_migrations(version,name) values (398,'synthetic_successor');")
    failed = postgres(rollback.read_text(encoding="utf-8"), user="sli_migration", database="sli")
    assert failed.returncode != 0 and "problem_queue_workflow397_rollback_preflight" in failed.stderr
    execute("delete from public.schema_migrations where version=398;")
    execute(rollback.read_text(encoding="utf-8"), user="sli_migration")
    assert execute("select max(version),to_regclass('public.finding_queue_deferrals') from schema_migrations;") == "396|"
    failed = postgres(old_entry, user="sli_migration", database="sli")
    assert failed.returncode != 0 and "permission denied for table report_registry_v4" in failed.stderr
    execute(migration.read_text(encoding="utf-8"), user="sli_migration")
    execute(rollback.read_text(encoding="utf-8"), user="sli_migration")
    assert execute(catalog_sql, user="adlog_user") == before_catalog
    assert execute(rights_sql) == before_rights


def prepare_333(sql, release):
    digest = hashlib.sha256((release / "config/postgres_schema_v8.sql").read_bytes()).hexdigest()
    result = sql(f"""
        create role adlog_storage_owner nologin;
        create role adlog_user nologin;
        create role adlog_semantic_worker nologin;
        create role adlog_storage_worker nologin;
        create role adlog_storage_lifecycle_worker nologin;
        grant usage,create on schema public to adlog_storage_owner;
        set role adlog_storage_owner;
        create table public.schema_migrations(version int primary key,name text not null,sha256 text);
        insert into public.schema_migrations values(333,'storage_lifecycle_wait','{digest}');
        create function public.read_account_decoy_events(uuid,text,text,text,text,uuid)
            returns text language sql stable as 'select ''326''::text';
        create table public.detector_definitions327(signature text,definition text);
        insert into public.detector_definitions327
            select oid::regprocedure::text,pg_get_functiondef(oid) from pg_proc
            where oid='public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure;
        create or replace function public.read_account_decoy_events(uuid,text,text,text,text,uuid)
            returns text language sql stable as 'select ''327''::text';
        reset role;
    """)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("manual_334", [False, True])
def test_upgrade_333_to_335_attests_manual_sql_and_repeats_without_changes(release, postgres, manual_334):
    from deploy.linux import native_pg_migrate as subject

    prepare_333(postgres, release)
    if manual_334:
        result = postgres((release / "config/postgres_migrations/334_account_decoy_restore.sql").read_text())
        assert result.returncode == 0, result.stderr
        assert postgres("select sha256 is null from schema_migrations where version=334;").stdout.strip() == "t"
    script = subject.upgrade_sql(release)
    result = postgres(script)
    assert result.returncode == 0, result.stderr
    actual = postgres("select json_agg(m order by version) from schema_migrations m;").stdout.strip()
    assert json.loads(actual) == inventory.expected_ledger(release)
    assert postgres("select public.read_account_decoy_events(null,null,null,null,null,null);").stdout.strip() == "326"
    assert postgres("select relowner::regrole from pg_class where oid='public.event_hot'::regclass;").stdout.strip() == "adlog_storage_owner"
    before = postgres("select oid from pg_class where oid='public.event_hot'::regclass;").stdout
    result = postgres(script)
    assert result.returncode == 0, result.stderr
    assert postgres("select json_agg(m order by version) from schema_migrations m;").stdout.strip() == actual
    assert postgres("select oid from pg_class where oid='public.event_hot'::regclass;").stdout == before


@pytest.mark.parametrize("defect", ["checksum", "name", "hole", "foreign"])
def test_bad_database_ledger_refuses_before_applying_sql(release, postgres, defect):
    from deploy.linux import native_pg_migrate as subject

    prepare_333(postgres, release)
    changes = {
        "checksum": "update schema_migrations set sha256=repeat('0',64);",
        "name": "update schema_migrations set name='foreign';",
        "hole": "delete from schema_migrations; insert into schema_migrations values(334,'account_decoy_restore',null);",
        "foreign": "insert into schema_migrations values(336,'foreign',null);",
    }
    assert postgres(changes[defect]).returncode == 0
    before = postgres("select json_agg(m order by version) from schema_migrations m;").stdout
    result = postgres(subject.upgrade_sql(release))
    assert result.returncode != 0
    code = "checksum_mismatch" if defect == "checksum" else "ledger_mismatch"
    assert "native_pg_migration_" + code in result.stderr
    assert postgres("select to_regclass('public.account_decoy_definition334'),to_regclass('public.event_hot');").stdout.strip() == "|"
    assert postgres("select json_agg(m order by version) from schema_migrations m;").stdout == before


@pytest.fixture
def s5_release(tmp_path, postgres):
    """Exercise the real S5 SQL and the migrator, including psql conditionals.

    Subsequent migrations are synthetic, private release inputs. Each consumes
    the preceding migration's result, so reversed/skipped execution fails in PG.
    """
    root = tmp_path / "beta-release"
    migrations = root / "config/postgres_migrations"
    migrations.mkdir(parents=True)
    (root / "deploy/linux").mkdir(parents=True)
    schema = root / "config/postgres_schema_v8.sql"
    schema.write_text("insert into schema_migrations(version,name) values (340,'default_policy_reconcile') "
                      "on conflict(version) do nothing;\n", newline="\n")
    for path in (ROOT / "config/postgres_migrations").glob("342_*.sql"):
        (migrations / path.name).write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))
    # Deliberately create the later file first: directory order is not SQL order.
    (migrations / "344_synthetic_readback.sql").write_text("""
        do $$ begin
            if not exists(select 1 from public.upgrade_probe where step=343) then
                raise exception 'synthetic_predecessor_missing';
            end if;
        end $$;
        insert into public.upgrade_probe values(344,'later');
        insert into public.schema_migrations(version,name) values(344,'synthetic_readback');
    """, newline="\n")
    (migrations / "343_synthetic_after_s5.sql").write_text("""
        do $$ begin
            if to_regprocedure('public.expire_short_storage_partitions342(timestamptz,timestamptz,timestamptz)') is null then
                raise exception 'synthetic_s5_missing';
            end if;
        end $$;
        insert into public.upgrade_probe values(343,'after-s5');
        insert into public.schema_migrations(version,name) values(343,'synthetic_after_s5');
    """, newline="\n")
    (root / "deploy/linux/native_pg_ledger.json").write_text(json.dumps(inventory.build_manifest(root)))
    result = postgres("""
        create role adlog_storage_owner nologin;
        create role adlog_user nologin;
        create role adlog_context_worker nologin;
        create role adlog_storage_lifecycle_worker nologin;
        create role adlog_storage_lifecycle_delete nologin;
        grant usage,create on schema public to adlog_storage_owner;
        set role adlog_storage_owner;
        create table public.schema_migrations(version int primary key,name text not null,sha256 text);
        create table public.ad_snapshot_change_history(id int primary key,body text);
        create table public.ad_snapshot_history_confirmations(id int primary key);
        create function public.create_ad_snapshot_change_partition(timestamptz) returns void language sql as 'select';
        create table public.upgrade_probe(step int primary key,body text);
        insert into public.ad_snapshot_change_history values(1,'preserve-snapshot');
        insert into public.upgrade_probe values(340,'preserve-customer-data');
        reset role;
    """ + schema.read_text())
    assert result.returncode == 0, result.stderr
    return root


def test_upgrade_from_pre_s5_applies_342_then_later_sql_and_preserves_rows(s5_release, postgres, monkeypatch):
    from deploy.linux import native_pg_migrate as subject

    root = s5_release

    def run_sql(body):
        result = postgres(body)
        assert result.returncode == 0, result.stderr

    monkeypatch.setattr(subject, "run_sql", run_sql)
    subject.migrate(root)
    actual = postgres("select json_agg(m order by version) from public.schema_migrations m;").stdout.strip()
    assert json.loads(actual) == inventory.expected_ledger(root)
    assert postgres("select string_agg(step::text,',' order by step) from public.upgrade_probe;").stdout.strip() == "340,343,344"
    assert postgres("select body from public.upgrade_probe where step=340;").stdout.strip() == "preserve-customer-data"
    assert postgres("select body from public.ad_snapshot_change_history where id=1;").stdout.strip() == "preserve-snapshot"
    subject.migrate(root)
    assert postgres("select json_agg(m order by version) from public.schema_migrations m;").stdout.strip() == actual
    assert postgres("select string_agg(step::text,',' order by step) from public.upgrade_probe;").stdout.strip() == "340,343,344"


@pytest.mark.parametrize("failure", ["sql", "readback", "autocommit"])
def test_third_migration_failure_rolls_back_entire_batch_and_can_retry(s5_release, postgres, failure):
    from deploy.linux import native_pg_migrate as subject

    migrations = s5_release / "config/postgres_migrations"
    assert postgres("create index upgrade_probe_existing on public.upgrade_probe(body);").returncode == 0
    previous_index = postgres("select 'upgrade_probe_existing'::regclass::oid;").stdout
    second = migrations / "343_synthetic_after_s5.sql"
    second.write_text("begin;\n" + second.read_text() + r"""
        drop index concurrently public.upgrade_probe_existing;
        create index concurrently upgrade_probe_step on public.upgrade_probe(step);
        select format('create index concurrently %I on public.upgrade_probe(body)', 'upgrade_probe_body')
        \gexec
        commit;
    """)
    third = migrations / "344_synthetic_readback.sql"
    original = third.read_text()
    bad = {
        "sql": original + "select * from public.synthetic_missing_table;",
        "readback": original + "update schema_migrations set name='wrong_name' where version=344;",
        "autocommit": original + "vacuum public.upgrade_probe;",
    }[failure]
    third.write_text("begin;\n" + bad + "\ncommit;")
    manifest = s5_release / "deploy/linux/native_pg_ledger.json"
    manifest.write_text(json.dumps(inventory.build_manifest(s5_release)))
    ledger_query = "select json_agg(m order by version) from schema_migrations m;"
    before = postgres(ledger_query).stdout
    failed = postgres(subject.upgrade_sql(s5_release))
    assert failed.returncode != 0
    assert {"sql": "synthetic_missing_table", "readback": "native_pg_migration_readback_failed",
            "autocommit": "cannot run inside a transaction block"}[failure] in failed.stderr
    assert postgres(ledger_query).stdout == before
    assert postgres("select 'upgrade_probe_existing'::regclass::oid;").stdout == previous_index
    assert postgres("select step,body from upgrade_probe;").stdout.strip() == "340|preserve-customer-data"
    assert postgres("select body from ad_snapshot_change_history;").stdout.strip() == "preserve-snapshot"
    assert postgres("select to_regclass('upgrade_probe_step'),to_regclass('upgrade_probe_body'),"
                    "to_regprocedure('expire_short_storage_partitions342(timestamptz,timestamptz,timestamptz)');").stdout.strip() == "||"
    third.write_text("begin;\n" + original + "\ncommit;")
    manifest.write_text(json.dumps(inventory.build_manifest(s5_release)))
    for _ in range(2):
        result = postgres(subject.upgrade_sql(s5_release))
        assert result.returncode == 0, result.stderr
        assert json.loads(postgres(ledger_query).stdout) == inventory.expected_ledger(s5_release)
        assert postgres("select to_regclass('upgrade_probe_existing');").stdout.strip() == ""
        assert postgres("select bool_and(indisvalid and indisready) from pg_index "
                        "where indexrelid in ('upgrade_probe_step'::regclass,'upgrade_probe_body'::regclass);").stdout.strip() == "t"


def test_batch_preserves_function_bodies_quoted_values_and_nested_comments(postgres):
    from deploy.linux import native_pg_migrate as subject

    body = """
        /* outer /* commit; */ begin; */ BEGIN /* commit; */ TRANSACTION;
        create function public.batch_text() returns text language plpgsql as $body$
        begin
            return 'commit; create index concurrently';
        end;
        $body$;
        create table public.batch_literals("commit;" text);
        insert into public.batch_literals values ('begin; -- create index concurrently');
        COMMIT WORK;
    """
    result = postgres("begin;\n" + subject.transactional_sql(body) + "\nrollback;")
    assert result.returncode == 0, result.stderr
    assert postgres("select to_regclass('batch_literals'),to_regprocedure('batch_text()');").stdout.strip() == "|"
    result = postgres("begin;\n" + subject.transactional_sql(body)
                      + '\nselect batch_text(); select "commit;" from batch_literals; commit;')
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["commit; create index concurrently", "begin; -- create index concurrently"]


@pytest.mark.parametrize("body", ["commit and chain;", "rollback;", "\\connect other", "select 'commit'\n\\gexec"])
def test_unsupported_transaction_control_is_refused(body):
    from deploy.linux import native_pg_migrate as subject

    with pytest.raises(ValueError, match="^native_pg_migration_sql_unsupported$"):
        subject.transactional_sql(body)
