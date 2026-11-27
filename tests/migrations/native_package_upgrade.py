"""Exercise the package migration on a previous native install in CI."""

from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import psycopg

from deploy.linux import native_pg_inventory, native_pg_migrate


PG_BIN = Path("/usr/lib/postgresql/18/bin")
ROOT = Path(__file__).resolve().parents[2]


def seed(connection):
    connection.execute(r"""
        insert into public.findings(fingerprint,rule_code,title,severity,status,
                                    first_seen_utc,last_seen_utc,evidence_count)
        values ('synthetic:upgrade-421','semantic.security.dc_service_installed','Fixture','high',
                'new',now()::text,now()::text,1),
               ('synthetic:unrelated','synthetic.rule','Fixture','high','new',now()::text,now()::text,0);
        insert into public.finding_event_copies337(finding_id,event_id,time_created_utc,event_kind,
                    domain_id,computer,method,outcome,fields,source_sha256,evidence_role,event_record_id)
        select id,1,now(),4697,1,'dc.example.test',
               '{"$channel":"Security","$provider":"Microsoft-Windows-Security-Auditing"}',
               '{}',jsonb_build_object('ServiceName','SLIAgentNet',
                   'ServiceFileName',$path$C:\Program Files\SLI\AgentNet\SliAgent.exe$path$),
               sha256(convert_to('synthetic:upgrade-421','UTF8')),'semantic_scenario',1
        from public.findings where fingerprint='synthetic:upgrade-421';
    """)


def verify_acl(connection):
    assert connection.execute("""
        select c.relname, pg_get_userbyid(c.relowner)
        from pg_class c where c.oid in ('public.findings'::regclass,'public.finding_status_history'::regclass)
        order by c.relname
    """).fetchall() == [("finding_status_history", "sli_migration"), ("findings", "sli_migration")]
    assert connection.execute("""
        select has_column_privilege('adlog_storage_owner','public.findings','status_reason','UPDATE')
    """).fetchone() == (False,)


def verify_backfill(connection):
    assert connection.execute("""
        select f.fingerprint,f.status,f.status_reason,
               (select count(*) from public.finding_event_copies337 c where c.finding_id=f.id),
               (select count(*) from public.finding_status_history h where h.finding_id=f.id
                and h.old_status='new' and h.new_status='closed' and h.changed_by='migration:421'
                and h.note=f.status_reason)
        from public.findings f where f.fingerprint in ('synthetic:upgrade-421','synthetic:unrelated')
        order by f.fingerprint
    """).fetchall() == [
        ("synthetic:unrelated", "new", None, 0, 0),
        ("synthetic:upgrade-421", "closed", "Действие SLI", 1, 1),
    ]


def verify_ledger(connection, release):
    native_pg_inventory.verify_ledger(
        native_pg_inventory.read_ledger(connection), native_pg_inventory.expected_ledger(release), root=release,
    )


def verify_problem_queue(connection):
    assert connection.execute("""
        select f.fingerprint,q.status,e.domain_ids
        from public.findings f
        join public.problem_queue_entries443 q on q.id=f.id
        left join public.problem_queue_evidence443 e on e.finding_id=f.id
        where f.fingerprint in ('synthetic:upgrade-421','synthetic:unrelated')
        order by f.fingerprint
    """).fetchall() == [
        ("synthetic:unrelated", "new", None),
        ("synthetic:upgrade-421", "closed", [1]),
    ]
    with connection.transaction():
        connection.execute("""
            update public.findings set status='active'
            where fingerprint='synthetic:unrelated'
        """)
        assert connection.execute("""
            select q.status from public.problem_queue_entries443 q
            join public.findings f on f.id=q.id
            where f.fingerprint='synthetic:unrelated'
        """).fetchone() == ("active",)
        connection.execute("""
            update public.findings set status='new'
            where fingerprint='synthetic:unrelated'
        """)


def exercise(previous, work):
    # Match the installer and package runner's endpoints inside the private namespaces.
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    socket = work / "socket"
    socket.mkdir()
    shutil.chown(socket, user="postgres", group="postgres")
    subprocess.run(["mount", "--bind", str(socket), "/run/postgresql"], check=True)
    data = work / "data"
    data.mkdir(mode=0o700)
    shutil.chown(data, user="postgres", group="postgres")
    credentials = work / "credentials"
    credentials.mkdir(mode=0o700)
    shutil.chown(credentials, user="postgres", group="postgres")

    # The old release creates its own credentials, database roles and schema.
    env = {"PATH": f"{PG_BIN}:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"}
    if libraries := os.environ.get("LD_LIBRARY_PATH"):
        env["LD_LIBRARY_PATH"] = libraries
    bootstrap_names = ("postgres_password", "migration_password", "runtime_password")
    install = """
import os, sys
from deploy.linux import native_install, sli_secrets

env = native_install.environment()
files = [os.path.basename(path) for key, path in env.items() if key.endswith('_FILE')]
sli_secrets.ensure(native_install.SECRETS, names=sorted(set(files + sys.argv[1:])))
"""
    subprocess.run([sys.executable, "-B", "-c", install, *bootstrap_names], cwd=previous, env=env, check=True)
    for name in bootstrap_names:
        target = credentials / name
        shutil.copyfile(Path("/etc/sli/secrets") / name, target)
        target.chmod(0o600)
        shutil.chown(target, user="postgres", group="postgres")

    # The runner home is not readable by the postgres account; give it a readable copy of the old release code.
    readable = work / "previous"
    for part in ("deploy", "config"):
        shutil.copytree(previous / part, readable / part)
    postgres = ["runuser", "-u", "postgres", "--"]
    subprocess.run([*postgres, PG_BIN / "initdb", "-D", data, "-U", "postgres", "--auth-local=peer",
                    "--auth-host=scram-sha-256", "--pwfile", credentials / "postgres_password",
                    "--locale=C.UTF-8", "--encoding=UTF8"], env=env, check=True)
    control = [*postgres, PG_BIN / "pg_ctl", "-D", data]
    subprocess.run([*control, "-l", data / "server.log", "-o",
                    "-h 127.0.0.1 -p 5432 -k /var/run/postgresql -c timezone=UTC", "-w", "start"], env=env, check=True)
    try:
        bootstrap = """
import sys
from pathlib import Path
from deploy.linux import native_host

native_host.BOOTSTRAP_MARKER = Path(sys.argv[1])
native_host.bootstrap_pg()
"""
        subprocess.run([*postgres, "/usr/bin/python3", "-B", "-c", bootstrap, data / ".sli-bootstrap.json"],
                       cwd=readable, env={**env, "CREDENTIALS_DIRECTORY": str(credentials)}, check=True)
        migrate = """
import os, sys
from deploy.linux import native_install

env = native_install.environment()
env.update(SLI_INSTALL_DOMAIN='example.test', SLI_NATIVE_OWNER_SETUP='1',
           SLI_BACKUP_ROOT=sys.argv[1], SLI_HELPER_RUNTIME_ROOT=sys.argv[2])
if libraries := os.environ.get('LD_LIBRARY_PATH'):
    env['LD_LIBRARY_PATH'] = libraries
os.execve(sys.executable, [sys.executable, '-B', '-m', 'deploy.linux.entrypoint', 'migrate'], env)
"""
        subprocess.run([sys.executable, "-B", "-c", migrate, work, work / "helpers"],
                       cwd=previous, env=env, check=True)
        # Peer authentication admits only the OS postgres account to this socket.
        # Use the generated CI password for fixture setup/readback over TCP.
        password = (credentials / "postgres_password").read_text(encoding="ascii").strip()
        with psycopg.connect(host="127.0.0.1", dbname="sli", user="postgres", password=password,
                             autocommit=True) as connection:
            assert 180000 <= connection.info.server_version < 190000
            assert connection.execute("select max(version) from public.schema_migrations").fetchone() == (420,)
            verify_ledger(connection, previous)
            verify_acl(connection)
            seed(connection)
            native_pg_migrate.migrate(ROOT)
            verify_ledger(connection, ROOT)
            verify_acl(connection)
            verify_backfill(connection)
            verify_problem_queue(connection)
    finally:
        subprocess.run([*control, "-m", "fast", "-w", "stop"], env=env, check=True)
        subprocess.run(["umount", "/run/postgresql"], check=True)


if __name__ == "__main__":
    for namespace in ("mnt", "net"):
        if Path(f"/proc/self/ns/{namespace}").readlink() == Path(f"/proc/1/ns/{namespace}").readlink():
            raise SystemExit("The native upgrade test requires private mount and network namespaces.")
    with ExitStack() as cleanup:
        # Refuse an existing installation and remove only directories created by this test.
        for path in (Path("/etc/sli"), Path("/var/lib/sli")):
            path.mkdir()
            cleanup.callback(shutil.rmtree, path)
        work = Path(cleanup.enter_context(tempfile.TemporaryDirectory(prefix="sli-upgrade-ci.", dir="/run")))
        work.chmod(0o755)
        exercise(Path(sys.argv[1]).resolve(strict=True), work)
