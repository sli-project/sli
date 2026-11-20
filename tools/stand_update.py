"""Operator-configured main-only development deployment via the signed host updater."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import time


class DeploymentError(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise DeploymentError(reason)


def atomic(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    os.replace(temporary, path)


@contextmanager
def deployment_lock(home):
    """OS-owned lock, released on process death, shared by every dispatcher."""
    with (home / "stand.lock").open("a+b") as stream:
        if os.name == "nt":
            import msvcrt
            stream.seek(0)
            stream.write(b"0")
            stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def release_version(base, epoch):
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", base), "stand_invalid_version")
    # Main may advance several times without changing VERSION. The immutable
    # commit timestamp supplies a monotonic patch version for development only.
    major, minor, _ = base.split(".")
    return f"{int(major)}.{int(minor)}.{epoch}"


class Deployment:
    def __init__(self, config):
        self.config = config
        self.home = Path(config["home"])
        self.repository = Path(config["repository"])
        self.runtime = config["runtime"]
        self.state = {"result": "in_progress", "stage": "preflight", "reason": "none"}
        self.log = None

    def run(self, args, *, cwd=None, data=None, timeout=3600, env=None, check=True):
        result = subprocess.run(args, cwd=cwd, input=data, capture_output=True, timeout=timeout, check=False, env=env)
        # CLI diagnostics remain private. Only stable reason codes enter status.
        if self.log:
            with self.log.open("ab") as stream:
                stream.write(result.stdout + result.stderr)
        if check:
            require(result.returncode == 0, "stand_" + self.state["stage"] + "_failed")
        return result.stdout

    def remote(self, args, **kwargs):
        config = self.config
        return self.run(["ssh", "-i", str(Path.home() / ".ssh" / config["key"]),
                         "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                         "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
                         "-o", "ServerAliveCountMax=3", config["target"],
                         shlex.join(["sudo", "-n", *args])], **kwargs)

    def report(self, **values):
        self.state.update(values, updated_utc=datetime.now(timezone.utc).isoformat())
        atomic(self.home / "stand-result.json", json.dumps(self.state, indent=2) + "\n")
        details = []
        if self.state.get("daily_backup"):
            selected = self.state["daily_backup"]
            details = ["Точка отката: " + selected["backup_id"],
                       "При откате данные с " + selected["backup_started_at_utc"]
                       + " могут быть потеряны: подтверждённые пакеты удалены из буфера агентов и автоматически "
                       "не восстановятся. Неподтверждённые пакеты сохраняются для повторной доставки; "
                       "после отката серверных курсоров её успешность не гарантирована."]
        atomic(self.home / "LAST-STAND.md", "# SLI stand update\n\n" + "\n\n".join([
            "Обновление SLI на стенде: " + self.state["result"],
            "Этап: " + self.state["stage"], "Причина: " + self.state["reason"],
            "Целевой коммит: " + self.state.get("source_commit", "unknown"),
            "Ready: " + str(self.state.get("ready_http", "unknown")),
            "Время: " + self.state["updated_utc"],
        ] + details) + "\n")

    def installed(self):
        return json.loads(self.remote(["cat", self.runtime + "/state/installed.json"], timeout=40))

    def native_args(self, source, action, archive):
        runtime = self.runtime
        return ["env", "PYTHONPATH=" + source + "/host-libs:" + source + "/source",
                "python3", "-B", "-m", "deploy.linux.sli_update", action,
                "--runtime", runtime, "--trust-store", self.config["trust_store"],
                "--compose", runtime + "/compose/compose.json",
                "--compose", runtime + "/state/install-compose.json",
                "--ca-file", runtime + "/secrets/tls_ca", "--package", archive, "--json"]

    def native_result(self, source, action, archive, *, extra=()):
        result = json.loads(self.remote(self.native_args(source, action, archive) + list(extra),
                                        timeout=2700, check=False))
        require(isinstance(result, dict), "stand_invalid_updater_result")
        return result

    @staticmethod
    def require_native(result, status, fallback):
        reason = result.get("reason_code")
        require(result.get("status") == status,
                reason if isinstance(reason, str) and re.fullmatch(r"update_[a-z0-9_]+", reason) else fallback)

    def resume_pending(self, source, archive):
        journal = json.loads(self.remote(["python3", "-c", PENDING_JOURNAL, self.runtime], timeout=40))
        if journal["status"] in {"absent", "committed", "rolled_back", "rejected"}:
            return
        # Never guess whether restoring a checkpoint would discard newer data.
        require(journal["status"] in {"rolling_back", "recovery_required"}, "update_resume_required")
        require(journal.get("migration_started") is False and journal.get("recovery_started") is False,
                "stand_recovery_restore_requires_operator")
        operation = journal.get("operation")
        require(isinstance(operation, str) and re.fullmatch(r"[a-f0-9]{32}", operation), "stand_invalid_update_operation")
        # This path cannot restore data: both mutation flags were checked above.
        self.report(stage="resume", recovery_operation=operation)
        result = self.native_result(source, "resume", archive, extra=("--operation-id", operation))
        self.require_native(result, "rolled_back", "stand_recovery_not_completed")
        require(result.get("operation") == operation, "stand_recovery_operation_mismatch")

    def provision_trust(self):
        """Provision the operator key once; never replace an existing policy."""
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private = Ed25519PrivateKey.from_private_bytes(Path(self.config["signing_key"]).read_bytes())
        policy = {"schema_version": 1, "keys": [{"key_id": self.config["key_id"], "public_key":
            base64.b64encode(private.public_key().public_bytes_raw()).decode(), "package_ids": ["sli.core"],
            "revoked": False}]}
        program = """import json,os,sys
from pathlib import Path
p=Path(sys.argv[1]);raw=sys.stdin.buffer.read();policy=json.loads(raw)
p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
if p.exists():
 assert not p.is_symlink() and json.loads(p.read_bytes())==policy,'stand_trust_policy_changed'
else:
 with os.fdopen(os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as stream:stream.write(raw)
"""
        self.remote(["python3", "-c", program, self.config["trust_store"]],
                    data=json.dumps(policy).encode(), timeout=40)

    def execute(self, *, dry_run=False, force=False, check_only=False):
        self.state["stage"] = "origin"
        remote = self.run(["git", "-C", str(self.repository), "ls-remote", "origin", "refs/heads/main"],
                          timeout=60).decode().split()[0]
        require(re.fullmatch(r"[a-f0-9]{40}", remote), "stand_invalid_main")
        if check_only:
            return "current" if remote == self.installed().get("source_commit") else "update_available"
        installed = self.installed()
        if remote == installed.get("source_commit"):
            return "current"
        if dry_run:
            return "dry_run"
        self.home.mkdir(parents=True, exist_ok=True)
        with deployment_lock(self.home):
            attempt = self.home / "stand-last-attempt"
            if attempt.exists() and not force:
                elapsed = time.time() - int(attempt.read_text())
                if elapsed < self.config.get("interval_seconds", 1800):
                    return "cooldown"
            atomic(attempt, str(int(time.time())) + "\n")
            self.log = self.home / "logs" / f"stand-{int(time.time())}.log"
            self.log.parent.mkdir(exist_ok=True)
            self.report(stage="fetch", source_commit=remote)
            self.run(["git", "-C", str(self.repository), "fetch", "--quiet", "origin", "main"], timeout=120)
            sha = self.run(["git", "-C", str(self.repository), "rev-parse", "origin/main"]).decode().strip()
            require(re.fullmatch(r"[a-f0-9]{40}", sha), "stand_invalid_main")
            installed = self.installed()
            if sha == installed.get("source_commit"):
                return "current"
            previous_sha = installed.get("source_commit")
            require(isinstance(previous_sha, str) and re.fullmatch(r"[a-f0-9]{40}", previous_sha),
                    "stand_unknown_installed_commit")
            self.run(["git", "-C", str(self.repository), "merge-base", "--is-ancestor", previous_sha, sha])
            epoch = int(self.run(["git", "-C", str(self.repository), "show", "-s", "--format=%ct", sha]))
            base = self.run(["git", "-C", str(self.repository), "show", sha + ":VERSION"]).decode().strip()
            version = release_version(base, epoch)
            self.report(stage="export", source_commit=sha, version=version)
            directory = Path(self.config["scratch"]) / (sha[:12] + "-" + str(time.time_ns()))
            directory.mkdir(parents=True)
            source = directory / "source"
            # The exporter reads Git objects, never the dirty development tree.
            export = "from pathlib import Path;from tools.release_artifacts import export_source;import sys;export_source(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]))"
            self.run([sys.executable, "-c", export, str(self.repository), sha, str(source)], cwd=self.repository,
                     env=export_environment())
            self.report(stage="build")
            tag = "sli-stand-build:" + sha
            self.run(["docker", "build", "--platform", "linux/amd64", "--build-arg", "SLI_VERSION=" + version,
                      "--label", "org.opencontainers.image.revision=" + sha,
                      "-f", str(source / "deploy/linux/Dockerfile"), "-t", tag, str(source)], timeout=3600)
            payload = directory / "payload"
            payload.mkdir()
            self.report(stage="package")
            actual_max = int(self.remote(["docker", "exec", "sli-postgres-1", "psql", "-X", "-qAt", "-U",
                "postgres", "-d", "sli", "-c", "SELECT max(version) FROM public.schema_migrations"], timeout=40))
            self.run(["docker", "image", "save", "--output", str(directory / "image.tar"), tag], timeout=600)
            image_digest = self.run(["docker", "image", "inspect", "--format", "{{.Id}}", tag]).decode().strip()
            private_input = directory / "build-input.json"
            private_input.write_text(json.dumps({"installed": installed, "version": version, "sha": sha,
                "image_digest": image_digest, "actual_max": actual_max,
                "key": self.config["signing_key"], "key_id": self.config["key_id"]}), encoding="utf-8")
            self.run([sys.executable, "-c", PACKAGE_BUILD, str(directory)], cwd=source, timeout=1200)
            manifest = json.loads((directory / "manifest.json").read_text())
            self.report(package=str(directory / "update.zip"), inventory_max=max(
                int(Path(path).name.split("_", 1)[0]) for path in manifest["migrations"]
                if Path(path).name.split("_", 1)[0].isdigit()))
            # Recovery must itself come from main; never copy a worktree patch to
            # the running stand, and never rewrite its migration ledger/cache.
            supports_reconcile = "def reconcile(self," in (source / "deploy/linux/sli_update.py").read_text()
            ledger_max = max(row["version"] for row in installed["migration_ledger"])
            self.report(stage="preflight")
            if actual_max != ledger_max:
                require(supports_reconcile, "stand_main_reconciliation_required")
            self.provision_trust()
            self.report(stage="host_libraries")
            self.run([sys.executable, "-c", HOST_LIBRARIES, str(directory), self.config.get("host_python", "3.13")],
                     cwd=source, timeout=600)
            transfer = directory / "transfer.tar"
            with tarfile.open(transfer, "w") as archive:
                for name in ("source", "host-libs", "update.zip"):
                    archive.add(directory / name, arcname=name)
            remote_directory = self.config["remote_home"].rstrip("/") + "/" + directory.name
            self.report(stage="transfer")
            self.remote(["install", "-d", "-m", "700", remote_directory])
            with transfer.open("rb") as stream:
                # Passing a stream avoids keeping a full image in host memory.
                config = self.config
                command = ["ssh", "-i", str(Path.home() / ".ssh" / config["key"]), "-o", "BatchMode=yes",
                           "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", config["target"],
                           shlex.join(["sudo", "-n", "tar", "-xf", "-", "-C", remote_directory])]
                result = subprocess.run(command, stdin=stream, capture_output=True, timeout=900, check=False)
                require(result.returncode == 0, "stand_transfer_failed")
            archive = remote_directory + "/update.zip"
            self.resume_pending(remote_directory, archive)
            require(self.installed() == installed, "stand_recovery_installed_changed")
            if actual_max != ledger_max:
                self.report(stage="reconcile")
                result = json.loads(self.remote(self.native_args(remote_directory, "reconcile", archive), timeout=1200))
                require(result["status"] == "reconciled", "stand_reconciliation_failed")
            self.report(stage="apply")
            result = self.native_result(remote_directory, "apply", archive)
            if result.get("daily_backup"):
                self.report(daily_backup=result["daily_backup"])
            if result.get("reason_code") in {"update_fresh_daily_backup_required", "update_daily_backup_schema_mismatch"}:
                self.report(result="waiting", stage="backup", reason="нет свежей суточной копии; "
                            "ожидание следующего окна обновления", reason_code=result["reason_code"])
                return "waiting"
            self.require_native(result, "committed", "stand_update_not_committed")
            require(result.get("source_commit") == sha, "stand_update_commit_mismatch")
            self.report(stage="readback")
            observed = self.installed()
            require(observed["source_commit"] == sha, "stand_commit_readback_failed")
            http = self.remote(["curl", "--silent", "--show-error", "--cacert", self.runtime + "/secrets/tls_ca",
                "--max-time", "15", "--output", "/dev/null", "--write-out", "%{http_code}",
                "https://127.0.0.1:8443/api/health/ready"], timeout=30).decode()
            require(http == "200", "stand_ready_failed")
            rows = container_rows(self.remote(["docker", "compose", "-p", "sli", "-f", self.runtime + "/compose/compose.json",
                "-f", self.runtime + "/state/install-compose.json", "ps", "--all", "--format", "json"], timeout=40).decode())
            services = [row for row in rows if row["Service"] != "migrate"]
            require(services and all(row["State"] == "running" and row.get("Health") == "healthy" for row in services),
                    "stand_services_not_healthy")
            metrics = json.loads(self.remote(["python3", "-c", METRICS], timeout=40))
            atomic(self.home / "stand-metrics.json", json.dumps(metrics, indent=2) + "\n")
            self.report(result="verified", stage="complete", reason="updated_ready_200", ready_http=200,
                        healthy_services=len(services), metrics=metrics)
            return "verified"


def container_rows(raw):
    return json.loads(raw) if raw.lstrip().startswith("[") else [json.loads(row) for row in raw.splitlines() if row.strip()]


def export_environment():
    # git archive performs checkout conversion too. Its bytes must be independent
    # of Windows core.autocrlf/core.eol, especially for immutable SQL inventories.
    return {**os.environ, "GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "core.autocrlf", "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_KEY_1": "core.eol", "GIT_CONFIG_VALUE_1": "lf"}


PENDING_JOURNAL = r'''
import json,sys
from pathlib import Path
p=Path(sys.argv[1])/'state/update-journal.json'
if not p.exists():
 print(json.dumps({'status':'absent'}))
else:
 j=json.loads(p.read_bytes())
 print(json.dumps({**{k:j.get(k) for k in ('status','operation','migration_started')},
                   'recovery_started':j.get('recovery_started',False)}))
'''


PACKAGE_BUILD = r'''
import hashlib,json,sys,tarfile
from pathlib import Path
from tools.release_artifacts import compact_image,manifest
from server.sli.release_package import build_package,extract_payload,verify_package
from deploy.linux.sli_update import image_inventory
d=Path(sys.argv[1]);p=json.loads((d/'build-input.json').read_text());old=p['installed']
compact_image(d/'image.tar',d/'payload/images.tar')
migrations={f.relative_to(Path.cwd()).as_posix():hashlib.sha256(f.read_bytes()).hexdigest() for f in Path('config/postgres_migrations').resolve().glob('*.sql')}
draft=manifest({'from_version':old['version'],'version':p['version'],'source_commit':p['sha']},migrations)
draft['build_id']='main-'+p['sha']
with tarfile.open(d/'payload/images.tar') as saved:
 record=json.load(saved.extractfile('manifest.json'))[0]
 image_digest='sha256:'+hashlib.sha256(saved.extractfile(record['Config']).read()).hexdigest()
draft['image']={'path':'images.tar','digest':image_digest}
draft['files']=[{'path':'images.tar'}]
draft['compatibility'].update(migration_ledger_max=max(int(f.split('/')[-1].split('_')[0]) for f in migrations if f.split('/')[-1].split('_')[0].isdigit()),plugins={k:{'min_version':v['version'],'max_version':v['version'],'enabled':True} for k,v in old.get('plugins',{}).items()})
# The expected ledger is read from the real DB by the dispatcher, not the new inventory.
draft['compatibility']['migration_ledger_max']=int(p['actual_max'])
build_package(d/'payload',d/'update.zip',draft,signing_key=Path(p['key']),key_id=p['key_id'])
import zipfile
with zipfile.ZipFile(d/'update.zip') as z: signed=json.loads(z.read('SLI_RELEASE.json'))
image_inventory(d/'payload/images.tar',signed,d/'checked.tar',applied_ledger=old['migration_ledger'])
(d/'manifest.json').write_text(json.dumps(signed))
(d/'checked.tar').unlink();(d/'image.tar').unlink()
'''


HOST_LIBRARIES = r'''
import subprocess,sys
from pathlib import Path
d=Path(sys.argv[1]);version=sys.argv[2];names={'cryptography','cffi','pycparser'}
locked=[line.strip() for line in Path('requirements.lock.txt').read_text().splitlines() if line.split('==')[0].lower() in names]
assert len(locked)==3
subprocess.run([sys.executable,'-m','pip','install','--disable-pip-version-check','--only-binary=:all:','--no-deps','--no-compile','--python-version',version,'--implementation','cp','--abi','cp'+version.replace('.',''),'--platform','manylinux_2_28_x86_64','--platform','manylinux_2_17_x86_64','--platform','manylinux2014_x86_64','--target',str(d/'host-libs'),*locked],check=True)
'''


METRICS = r'''
import json,subprocess
query="""BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL statement_timeout='15s'; SET LOCAL lock_timeout='1s';
SELECT json_build_object('observed_utc',now(),
 'semantic',(SELECT json_object_agg(status,n) FROM (SELECT status,count(*) n FROM semantic_processing_outbox GROUP BY status) s),
 'dispatch',(SELECT json_object_agg(dispatch_status,n) FROM (SELECT dispatch_status,count(*) n FROM semantic_correlation_dispatch_jobs GROUP BY dispatch_status) s),
 'risk',(SELECT json_object_agg(evaluation_status,n) FROM (SELECT evaluation_status,count(*) n FROM semantic_risk_evaluation_jobs GROUP BY evaluation_status) s),
 'last_cycle',(SELECT json_build_object('heartbeat_at',heartbeat_at,'status',status,
    'completed',details_json->'last_result'->'completed',
    'processing_completed',details_json->'last_result'->'processing'->'completed',
    'dispatch_completed',details_json->'last_result'->'dispatch'->'completed',
    'failed',details_json->'last_result'->'failed')
    FROM runtime_worker_heartbeats WHERE worker_name='semantic' ORDER BY heartbeat_at DESC LIMIT 1),
 'inbox',(SELECT json_build_object('packets',count(*),'pending',count(*) FILTER (WHERE imported_at IS NULL),
    'imported',count(*) FILTER (WHERE imported_at IS NOT NULL),'latest_received_at',max(received_at)) FROM sli_agent_packet_inbox));
ROLLBACK;"""
r=subprocess.run(['docker','exec','-i','sli-postgres-1','psql','-X','-qAt','-U','postgres','-d','sli','-v','ON_ERROR_STOP=1','--file','-'],input=query.encode(),capture_output=True,timeout=30,check=True)
metrics=json.loads(r.stdout)
# An in-progress heartbeat may have overwritten last_result. Recover only
# numeric cycle counters from logs at or before this same snapshot timestamp.
cycles=[]
try:
 logs=subprocess.run(['docker','logs','--timestamps','--until',metrics['observed_utc'],'--tail','300','sli-semantic-1'],capture_output=True,timeout=15,check=True)
 for line in (logs.stdout+logs.stderr).decode(errors='replace').splitlines():
  stamp,_,raw=line.partition(' ')
  try:item=json.loads(raw)
  except ValueError:continue
  if not isinstance(item,dict):continue
  safe={'log_utc':stamp}
  for key in ['completed','failed','risk_queued','claimed']:
   if type(item.get(key)) is int:safe[key]=item[key]
  for stage in ['processing','dispatch']:
   result=item.get(stage)
   if isinstance(result,dict):safe[stage]={k:v for k,v in result.items() if k in ['completed','claimed','failed'] and type(v) is int}
  if len(safe)>1:cycles.append(safe)
except (subprocess.SubprocessError,OSError):pass
metrics['last_completed_cycle_from_log']=max(cycles,key=lambda item:item['log_utc']) if cycles else {'cycle_counts_available':False}
print(json.dumps(metrics))
'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--check-only", action="store_true", help="Compare main without changing files or services.")
    parser.add_argument("--force", action="store_true", help="Ignore the retry interval; never the OS lock.")
    args = parser.parse_args(argv)
    deployment = Deployment(json.loads(args.config.read_text(encoding="utf-8")))
    try:
        print(deployment.execute(dry_run=args.dry_run, force=args.force or os.environ.get("SLI_STAND_NOW") == "1",
                                 check_only=args.check_only))
        return 0
    except (BlockingIOError, PermissionError):
        print("stand_busy_or_access_denied")
        return 1
    except Exception as exc:
        reason = str(exc) if isinstance(exc, DeploymentError) else "stand_" + deployment.state["stage"] + "_failed"
        if not args.dry_run and not args.check_only:
            deployment.home.mkdir(parents=True, exist_ok=True)
            deployment.report(result="failed", reason=reason)
        print(reason)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
