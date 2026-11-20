#!/usr/bin/env python3
"""Disposable installed-update drill; owner acceptance is always a separate decision."""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from deploy.linux import sli_update as update
from scripts.maintenance import release_package as packages

STATES = ("implemented", "tested", "staged", "installed", "accepted")
STATE_RU = dict(zip(STATES, ("реализовано", "проверено", "подготовлено", "установлено", "принято"), strict=True))
SCENARIOS = {
    "bootstrap": "Создание / подключение синтетической установленной копии A",
    "update": "Обновление A → B и проверка здоровья",
    "restore_baseline": "Возврат к A перед отрицательными сценариями",
    "migrate": "Сбой после миграции и автоматический откат",
    "activate": "Сбой после активации и автоматический откат",
    "health": "Сбой проверки здоровья и автоматический откат",
    "resume_stage": "Прерывание после stage и продолжение операции",
    "resume_migrate": "Прерывание после миграции и восстановление через resume",
    "bad_signature": "Отказ при неверной подписи до изменения runtime",
    "incompatible_version": "Отказ при несовместимой версии до изменения runtime",
    "insufficient_disk": "Отказ при нехватке диска до изменения runtime",
}
LABEL = "io.sli.update-drill"
SQL_A = """CREATE TABLE schema_migrations(version integer PRIMARY KEY, name text NOT NULL, checksum text, sha256 text);
CREATE TABLE installed_release_v1(singleton boolean PRIMARY KEY, installation_key text NOT NULL,
    operation text NOT NULL, inventory jsonb NOT NULL, updated_at_utc timestamptz NOT NULL DEFAULT now());
CREATE TABLE plugin_installations_v1(plugin_id text PRIMARY KEY, package_version text NOT NULL,
    package_lifecycle text NOT NULL, revision bigint NOT NULL DEFAULT 0);
CREATE TABLE drill_data(id integer PRIMARY KEY, value integer NOT NULL);
INSERT INTO drill_data VALUES (1, 10), (2, 20), (3, 30);
INSERT INTO schema_migrations(version,name) VALUES(1,'drill_base');
"""
SQL_B = "ALTER TABLE drill_data ADD COLUMN updated boolean NOT NULL DEFAULT false;\nINSERT INTO schema_migrations(version,name) VALUES(2,'drill_update');\n"
MIGRATIONS = {"config/postgres_migrations/001_drill.sql": SQL_A,
              "config/postgres_migrations/002_drill.sql": SQL_B}
OBSERVE_SQL = """SELECT json_build_object(
'migration_ledger_max', (SELECT coalesce(max(version),0) FROM schema_migrations),
'ledger', (SELECT json_agg(json_build_array(version,checksum) ORDER BY version) FROM schema_migrations),
'migration_ledger', (SELECT json_agg(json_build_object('version',version,'name',name,'sha256',sha256) ORDER BY version) FROM schema_migrations),
'installed_release', (SELECT json_build_object('installation_key',installation_key,'operation',operation,'inventory',inventory) FROM installed_release_v1),
'data_counts', json_build_object('drill_data', (SELECT count(*) FROM drill_data)),
'data_digest', (SELECT md5(string_agg(id::text || ':' || value::text, ',' ORDER BY id)) FROM drill_data),
'plugins', '[]'::json);"""
API_SOURCE = """from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == '/api/health/ready' else 404)
        self.end_headers()
    def log_message(self, *args):
        pass
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
"""


def require(condition, code):
    update.require(condition, "update_drill_" + code)


def validate_project(project):
    # No general-purpose target override: even a typo cannot select production.
    require(bool(re.fullmatch(r"sli-update-drill-[a-z0-9][a-z0-9-]{0,39}", project)), "unsafe_project")


def test_trust(directory):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private, public = directory / "test-only.key", directory / "test-only-trust.json"
    private.write_bytes(key.private_bytes_raw())
    private.chmod(0o600)
    update.atomic_json(public, {"schema_version": 1, "keys": [{
        "key_id": "drill-only", "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "package_ids": ["sli.core"], "revoked": False}]})
    return private, public


def metadata(version, previous, digest, architecture, migrations):
    return {"schema_version": 2, "package_type": "core-update", "package_id": "sli.core",
            "version": version, "platform": "linux-" + architecture, "source_commit": "0" * 40,
            "build_id": "synthetic-drill-" + version, "minimum_updater": 1, "deletions": [],
            "restart_profile": "docker-compose", "component": "server", "from_version": previous,
            "to_version": version, "required_free_disk": 1024, "files": [{"path": "image.tar"}],
            "image": {"path": "image.tar", "digest": digest}, "migrations": migrations,
            "compose_delta": None, "config_delta": None,
            "compatibility": {"core_api": 1, "ui_api": 1, "from_version": previous,
                              "min_version": previous, "max_version": previous, "os": "linux",
                              "architecture": architecture, "migration_ledger_max": 0 if version == "1.0.0" else 1,
                              "plugins": {}}}


def build_releases(host, directory, private):
    releases = {}
    for name, version, previous, count in (("A", "1.0.0", "0.0.0", 1), ("B", "1.1.0", "1.0.0", 2)):
        root = directory / name
        root.mkdir()
        sql = dict(list(MIGRATIONS.items())[:count])
        digest, architecture = host.export_image(root, version, sql)
        inventory = {path: hashlib.sha256(body.encode()).hexdigest() for path, body in sql.items()}
        manifest = metadata(version, previous, digest, architecture, inventory)
        archive = directory / (name + ".zip")
        packages.build_package(root, archive, manifest, signing_key=private, key_id="drill-only")
        # The builder returns a summary; bootstrap needs the finalized signed inventory.
        with zipfile.ZipFile(archive) as package:
            manifest = packages.read_json(package.read(packages.MANIFEST_NAME))
        releases[name] = (archive, manifest)
    return releases


def negative_package(source, destination, private, scenario):
    with zipfile.ZipFile(source) as archive:
        contents = {name: archive.read(name) for name in archive.namelist()}
    manifest = packages.read_json(contents[packages.MANIFEST_NAME])
    if scenario == "incompatible_version":
        manifest["from_version"] = "0.9.0"
        manifest["compatibility"].update(from_version="0.9.0", min_version="0.9.0", max_version="0.9.0")
    elif scenario == "insufficient_disk":
        # Exercise the real verifier's disk gate without filling the engine disk.
        manifest["required_free_disk"] = 2**100
    raw = packages.canonical_json(manifest)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signature = Ed25519PrivateKey.from_private_bytes(private.read_bytes()).sign(packages.SIGNING_CONTEXT + raw)
    if scenario == "bad_signature":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    contents[packages.MANIFEST_NAME] = raw
    contents[packages.SIGNATURE_NAME] = packages.canonical_json({"algorithm": "ed25519", "key_id": "drill-only",
                                                               "signature": base64.b64encode(signature).decode()})
    with zipfile.ZipFile(destination, "w") as archive:
        for name, body in contents.items():
            archive.writestr(name, body)
    return destination


class Interrupted(BaseException):
    """Simulate loss of the host between an external action and durable completion."""


class FaultHost:
    def __init__(self, host, phase, interrupt=False):
        self.host, self.phase, self.interrupt = host, phase, interrupt
        self.triggered = False

    def __getattr__(self, name):
        value = getattr(self.host, name)
        if name != self.phase:
            return value

        def action(*args, **kwargs):
            result = value(*args, **kwargs)
            if not self.triggered:
                self.triggered = True
                if self.interrupt:
                    raise Interrupted()
                raise update.UpdateError("update_drill_forced_" + self.phase)
            return result

        return action


def snapshot(updater, host):
    from deploy.linux.installed_state import validate

    installed = packages.read_json(updater.installed_path.read_bytes())
    observed = host.observe()
    require(set(observed["services"]) == {"api", "backup"} and all(
        all(row[key] == installed[key] for key in ("version", "image_tag", "image_digest"))
        for row in observed["services"].values()), "runtime_readback_failed")
    expected = sorted([int(Path(path).name.split("_", 1)[0]), checksum]
                      for path, checksum in installed["migrations"].items())
    require(observed["ledger"] == expected, "ledger_readback_failed")
    require(observed.get("installed_release") is not None, "registry_readback_failed")
    validate(installed, observed, updater.runtime)
    # A rollback republishes the same release under its current operation ID.
    # Compare installation authority and inventory, not publication history.
    observed["installed_release"] = {key: value for key, value in observed["installed_release"].items()
                                     if key != "operation"}
    return {"installed": installed, "runtime": observed}


def assert_restored(updater, host, before, status):
    require(status == "rolled_back", "rollback_not_terminal")
    host.health(updater.operation())
    require(snapshot(updater, host) == before, "rollback_readback_failed")


def protocol(report):
    lines = ["Учение по обновлению", "", "Статусы: " + " / ".join(
        f"{state} — {STATE_RU[state]}" for state in STATES),
        "accepted устанавливает только владелец; учение этого статуса не выдаёт.",
        "Контур: синтетическая установленная копия; не production и не приёмка всего релиза.",
        "Bootstrap/adopt, PostgreSQL checkpoint и HTTP health — адаптер стенда, не installer/TLS продукта.", ""]
    for item in report["scenarios"]:
        lines.append(f"{SCENARIOS[item['id']]}: {item['state']} ({STATE_RU[item['state']]}); "
                     f"результат={item['outcome']}; код={item['reason_code'] or '-'}")
    lines.extend(["", "Общий результат: " + report["result"],
                  "Ресурсы Docker: " + report["resources"],
                  "Не подтверждены: installer/adopt #441, self-update #442, агент #444, офлайн-комплект #445."])
    return "\n".join(lines) + "\n"


def public_evidence(value):
    """Do not publish local runtime paths (which can contain operator names)."""
    if isinstance(value, dict):
        return {key: public_evidence(item) for key, item in value.items() if key != "override"}
    if isinstance(value, list):
        return [public_evidence(item) for item in value]
    return value


def run_drill(runtime, output, host, *, existing=False):
    """The injectable host performs IO; only the canonical updater changes update state."""
    runtime, output = Path(runtime).resolve(), Path(output).resolve()
    require(output != runtime and not output.is_relative_to(runtime), "output_inside_runtime")
    rows = [{"id": name, "state": "implemented", "outcome": "not_run", "reason_code": None}
            for name in SCENARIOS]
    report = {"schema_version": 1, "scope": "synthetic-installed-updater", "accepted": False,
              "states": list(STATES), "result": "failed", "resources": "retained", "scenarios": rows,
              "evidence": {}, "unverified": ["installer_adopt", "updater_self_update", "agent_update", "offline_kit"]}

    def started(identifier):
        row = next(item for item in rows if item["id"] == identifier)
        # A started scenario fails unless every verification completes.
        row.update(outcome="failed")
        return row

    def passed(identifier, evidence=None):
        row = next(item for item in rows if item["id"] == identifier)
        if evidence is not None:
            report["evidence"][identifier] = public_evidence(evidence)
        row.update(state="installed" if host.installed_evidence else "staged", outcome="passed")

    current = started("bootstrap")
    try:
        host.guard(existing=existing)
        # The key and test-only trust root never persist in the runtime or output.
        with tempfile.TemporaryDirectory(prefix="sli-update-drill-") as temporary:
            directory = Path(temporary)
            private, trust = test_trust(directory)
            releases = build_releases(host, directory, private)
            host.bootstrap(releases["A"], trust, existing=existing)
            updater = update.Updater(runtime, trust, host)
            before = snapshot(updater, host)
            host.health(None)
            passed("bootstrap", before)
            candidate = releases["B"][0]
            current = started("update")
            require(updater.apply(candidate) == "committed", "update_not_committed")
            after = snapshot(updater, host)
            require(after["installed"]["version"] == "1.1.0" and after["runtime"]["migration_ledger_max"] == 2,
                    "candidate_readback_failed")
            require(after["runtime"]["data_counts"] == before["runtime"]["data_counts"]
                    and after["runtime"]["data_digest"] == before["runtime"]["data_digest"], "data_changed")
            host.health(updater.operation())
            passed("update", after)
            current = started("restore_baseline")
            assert_restored(updater, host, before, updater.resume(rollback=True))
            passed("restore_baseline", snapshot(updater, host))
            for phase in ("migrate", "activate", "health"):
                current = started(phase)
                faulty = FaultHost(host, phase)
                operation = update.Updater(runtime, trust, faulty)
                status = operation.apply(candidate)
                require(faulty.triggered and operation.operation()["reason"] == "update_drill_forced_" + phase,
                        "fault_not_exercised")
                assert_restored(operation, host, before, status)
                passed(phase, snapshot(operation, host))
            for phase in ("stage", "migrate"):
                identifier = "resume_" + phase
                current = started(identifier)
                faulty = FaultHost(host, phase, interrupt=True)
                operation = update.Updater(runtime, trust, faulty)
                try:
                    operation.apply(candidate)
                except Interrupted:
                    pass
                require(faulty.triggered and operation.operation()["status"] == "running"
                        and phase not in operation.operation()["completed"], "interruption_not_exercised")
                # A new instance reads the durable journal; no in-memory continuation.
                resumed = update.Updater(runtime, trust, host)
                status = resumed.resume(operation_id=operation.operation()["operation"])
                if phase == "stage":
                    require(status == "committed", "resume_not_committed")
                    resumed_snapshot = snapshot(resumed, host)
                    require(resumed_snapshot["installed"]["version"] == "1.1.0"
                            and resumed_snapshot["runtime"]["migration_ledger_max"] == 2, "resume_readback_failed")
                    assert_restored(resumed, host, before, resumed.resume(rollback=True))
                else:
                    assert_restored(resumed, host, before, status)
                passed(identifier, {"resume_status": status, "restored": snapshot(resumed, host)})
            for scenario, reason in (("bad_signature", "invalid package signature"),
                                     ("incompatible_version", "update_incompatible_version"),
                                     ("insufficient_disk", "update_insufficient_disk")):
                current = started(scenario)
                invalid = negative_package(candidate, directory / (scenario + ".zip"), private, scenario)
                mutation_count = host.mutations
                try:
                    updater.apply(invalid)
                except packages.PackageError as exc:
                    require(str(exc) == reason, "wrong_refusal")
                else:
                    require(False, "negative_package_accepted")
                require(updater.operation()["status"] == "rejected" and updater.operation()["phase"] == "verify"
                        and host.mutations == mutation_count, "refusal_changed_runtime")
                require(snapshot(updater, host) == before, "refusal_changed_data")
                passed(scenario, {"refusal": reason, "runtime_unchanged": True})
            report["result"] = "passed"
    except Exception as exc:
        current.update(outcome="failed", reason_code=update.reason_code(exc, "update_drill_failed"))
    finally:
        output.mkdir(parents=True, exist_ok=True)
        update.atomic_json(output / "result.json", report)
        (output / "protocol.txt").write_text(protocol(report), encoding="utf-8")
    return report


class DockerDrillHost(update.DockerHost):
    """Synthetic fixture IO, isolated from the production-only DockerHost defaults."""

    installed_evidence = True

    def __init__(self, runtime, project, timeout=120):
        validate_project(project)
        require(not any(path.is_symlink() for path in (Path(runtime), *Path(runtime).parents)), "unsafe_runtime")
        self.runtime = Path(runtime).resolve()
        self.project, self.timeout, self.mutations = project, timeout, 0
        self.files = [self.runtime / "compose.json"]
        self.marker_path = self.runtime / "drill.json"
        self.fixture = None
        self.allowed = False

    def command(self, args, *, stdin=None):
        result = subprocess.run(args, input=stdin, capture_output=True, timeout=900, check=False)
        require(result.returncode == 0, "command_failed")
        return result.stdout.decode("utf-8")

    def compose(self, args, override=None, *, stdin=None):
        require(self.allowed, "guard_required")
        command = ["docker", "compose", "-p", self.project, "-f", str(self.files[0])]
        if override:
            command.extend(["-f", str(override)])
        return self.command([*command, *args], stdin=stdin)

    def config(self):
        return update.parse_json(self.compose(["config", "--format", "json"]))

    def guard(self, *, existing):
        validate_project(self.project)
        require(not self.runtime.is_symlink() and self.runtime != Path("/srv/sli"), "unsafe_runtime")
        if existing:
            marker = packages.read_json(self.marker_path.read_bytes())
            require(marker["project"] == self.project and marker["synthetic_only"] is True
                    and re.fullmatch(r"[a-f0-9]{32}", marker["fixture"]), "foreign_runtime")
            require(update.sha256(self.files[0]) == marker["compose_sha256"], "compose_changed")
            self.fixture = marker["fixture"]
            self.allowed = True
            self.isolation()
        else:
            require(not self.runtime.exists() or not any(self.runtime.iterdir()), "runtime_not_empty")
            for kind, command in (("containers", ["docker", "ps", "-aq"]),
                                  ("volumes", ["docker", "volume", "ls", "-q"]),
                                  ("networks", ["docker", "network", "ls", "-q"])):
                require(not self.command([*command, "--filter", "label=com.docker.compose.project=" + self.project]).strip(),
                        "project_" + kind + "_exists")
            require(self.project + "_postgres" not in self.command(
                ["docker", "volume", "ls", "-q"]).splitlines(), "volume_exists")
            require(self.project + "_default" not in self.command(
                ["docker", "network", "ls", "--format", "{{.Name}}"]).splitlines(), "network_exists")
            self.runtime.mkdir(parents=True, exist_ok=True)
            self.fixture = uuid.uuid4().hex
            self.allowed = True

    def isolation(self):
        config = self.config()
        require(config["name"] == self.project and set(config["services"]) == {*update.INFRA, "api", "backup", "migrate"},
                "foreign_compose")
        require(set(config.get("volumes", {})) == {"postgres"}, "foreign_volumes")
        volume = config["volumes"]["postgres"]
        require(volume["name"] == self.project + "_postgres" and not volume.get("external")
                and not volume.get("driver_opts"), "foreign_volume")
        require(set(config.get("networks", {})) == {"default"}
                and not config["networks"]["default"].get("external")
                and config["networks"]["default"].get("internal") is True
                and config["networks"]["default"]["name"] == self.project + "_default", "foreign_network")
        for name, service in config["services"].items():
            require(service.get("labels", {}).get(LABEL) == self.fixture
                    and not any(service.get(key) for key in ("ports", "devices", "privileged", "network_mode",
                                                             "pid", "container_name", "secrets", "configs")), "unsafe_service")
            mounts = service.get("volumes", [])
            require(not mounts or (name == "postgres" and len(mounts) == 1
                                  and mounts[0]["type"] == "volume" and mounts[0]["source"] == "postgres"
                                  and mounts[0]["target"] == "/var/lib/postgresql"), "unsafe_mount")
        ids = self.command(["docker", "ps", "-aq", "--no-trunc", "--filter",
                            "label=com.docker.compose.project=" + self.project]).split()
        for identifier in ids:
            facts = update.parse_json(self.command(["docker", "inspect", identifier]))[0]
            require(facts["Config"]["Labels"].get(LABEL) == self.fixture, "foreign_container")
            require(set(facts["NetworkSettings"]["Networks"]) == {self.project + "_default"}, "shared_network")
            for mount in facts.get("Mounts", []):
                require(mount["Type"] == "volume" and mount["Name"] == volume["name"], "foreign_container_mount")
        volumes = self.command(["docker", "volume", "ls", "-q", "--filter",
                                "label=com.docker.compose.project=" + self.project]).split()
        require(not set(volumes) - {volume["name"]}, "orphan_volume")
        if volumes:
            facts = update.parse_json(self.command(["docker", "volume", "inspect", volume["name"]]))[0]
            require((facts.get("Labels") or {}).get(LABEL) == self.fixture
                    and facts["Labels"].get("com.docker.compose.project") == self.project, "foreign_volume")
            consumers = self.command(["docker", "ps", "-aq", "--no-trunc", "--filter", "volume=" + volume["name"]]).split()
            require(set(consumers) <= set(ids), "shared_volume")
        networks = self.command(["docker", "network", "ls", "--format", "{{.Name}}"]).splitlines()
        if self.project + "_default" in networks:
            facts = update.parse_json(self.command(["docker", "network", "inspect", self.project + "_default"]))[0]
            require(facts.get("Internal") is True and (facts.get("Labels") or {}).get(LABEL) == self.fixture
                    and facts["Labels"].get("com.docker.compose.project") == self.project, "foreign_network")
            require(set(facts.get("Containers", {})) <= set(ids), "shared_network")

    def export_image(self, root, version, migrations):
        require(self.allowed, "guard_required")
        if version == "1.0.0" and self.marker_path.exists():
            installed = packages.read_json((self.runtime / "state/installed.json").read_bytes())
            require(installed["version"] == version, "existing_not_baseline")
            tag = installed["image_tag"]
            require(self.image_id(tag) == installed["image_digest"], "existing_image_changed")
        else:
            context = root / "context"
            context.mkdir()
            for name, body in migrations.items():
                target = context / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body.encode("utf-8"))
            (context / "api.py").write_text(API_SOURCE, encoding="utf-8")
            (context / "Dockerfile").write_text(
                "FROM python:3.12-alpine\nCOPY . /opt/sli/\n"
                f"LABEL org.opencontainers.image.version={version} {LABEL}={self.fixture}\n"
                'CMD ["python", "/opt/sli/api.py"]\n', encoding="utf-8")
            tag = self.project + ":build-" + uuid.uuid4().hex
            self.command(["docker", "build", "--tag", tag, str(context)])
        info = update.parse_json(self.command(["docker", "image", "inspect", tag]))[0]
        require(info["Os"] == "linux" and info["Architecture"] in {"amd64", "arm64"}
                and info["Config"]["Labels"].get(LABEL) == self.fixture, "foreign_image")
        self.command(["docker", "image", "save", "--output", str(root / "image.tar"), tag])
        return info["Id"], info["Architecture"]

    def bootstrap(self, release, trust, *, existing):
        archive, manifest = release
        verified = packages.verify_package(archive, trust)
        require(verified.manifest == manifest, "package_changed")
        installed = {"component": "server", "version": "1.0.0", "os": "linux",
                     "architecture": manifest["compatibility"]["architecture"], "compose_project": self.project,
                     "image_tag": self.project + ":a-" + self.fixture, "image_digest": manifest["image"]["digest"],
                     "migrations": manifest["migrations"], "volumes": {"postgres": self.project + "_postgres"},
                     "migration_ledger": [{"version": 1, "name": "drill_base", "sha256": next(iter(manifest["migrations"].values()))}]}
        if existing:
            require(packages.read_json((self.runtime / "state/installed.json").read_bytes()) == installed,
                    "adopt_inventory_mismatch")
            self.inspect_installation(installed)
            return
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            packages.extract_payload(verified, payload)
            self.stage(payload, manifest, installed["image_tag"])
        health = {"test": ["CMD", "python", "-c",
                           "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health/ready')"],
                  "interval": "2s", "timeout": "2s", "retries": 30}
        services = {name: {"image": installed["image_tag"], "labels": {LABEL: self.fixture}, "healthcheck": health}
                    for name in ("api", "backup", "clickhouse", "warm-tier", "migrate")}
        services["migrate"]["profiles"] = ["migration"]
        services["postgres"] = {"image": "postgres:18", "labels": {LABEL: self.fixture},
                                "environment": {"POSTGRES_DB": "sli", "POSTGRES_HOST_AUTH_METHOD": "trust"},
                                "volumes": ["postgres:/var/lib/postgresql"],
                                "healthcheck": {"test": ["CMD", "pg_isready", "-U", "postgres", "-d", "sli"],
                                                "interval": "2s", "timeout": "2s", "retries": 30}}
        update.atomic_json(self.files[0], {"services": services, "volumes": {"postgres": {"labels": {LABEL: self.fixture}}},
                                          "networks": {"default": {"internal": True, "labels": {LABEL: self.fixture}}}})
        self.isolation()
        self.compose(["up", "-d", "--wait", "--wait-timeout", str(self.timeout), "postgres"])
        self.apply_sql(None, manifest["migrations"], 0)
        self.publish_installed(installed, installed, self.fixture)
        self.compose(["up", "-d", "--wait", "--wait-timeout", str(self.timeout)])
        update.atomic_json(self.runtime / "state/installed.json", installed)
        update.atomic_json(self.marker_path, {"project": self.project, "fixture": self.fixture,
                                             "synthetic_only": True, "compose_sha256": update.sha256(self.files[0])})

    def sql(self, statement, database="sli"):
        return self.compose(["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", database,
                             "-XAtq", "-v", "ON_ERROR_STOP=1"], stdin=statement.encode())

    def observe(self):
        # Only synthetic counts/ledger and selected image fields enter the protocol.
        result = update.parse_json(self.sql(OBSERVE_SQL))
        result["services"] = {}
        for row in self.containers():
            if row["Service"] in {"api", "backup"} and row["State"] == "running":
                facts = update.parse_json(self.command(["docker", "inspect", row["ID"]]))[0]
                info = update.parse_json(self.command(["docker", "image", "inspect", facts["Image"]]))[0]
                result["services"][row["Service"]] = {"version": info["Config"]["Labels"]["org.opencontainers.image.version"],
                                                     "image_digest": facts["Image"], "image_tag": facts["Config"]["Image"]}
        return result

    def preflight(self, installed, manifest):
        self.isolation()
        self.inspect_installation(installed)
        free = int(self.compose(["exec", "-T", "postgres", "df", "--output=avail", "-B1", "/"]).splitlines()[-1])
        require(free >= manifest["required_free_disk"], "insufficient_engine_disk")
        self.health(None)
        return self.observe()

    def stage(self, directory, manifest, tag):
        self.mutations += 1
        return super().stage(directory, manifest, tag)

    def drain(self, journal):
        self.mutations += 1
        return super().drain(journal)

    def stop_operation(self, journal):
        # This fixture's one-off read containers have --rm and never write to DB.
        pass

    def check_backup(self, journal):
        # The synthetic drill has PostgreSQL only and no production backup service.
        database = "sli_backup_check_" + uuid.uuid4().hex
        dump = self.compose(["exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-d", "sli"])
        self.compose(["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "postgres",
                      "-v", "ON_ERROR_STOP=1", "-c", f"CREATE DATABASE {database} TEMPLATE template0"])
        try:
            self.compose(["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", database,
                          "-v", "ON_ERROR_STOP=1"], stdin=dump.encode("utf-8"))
        finally:
            self.compose(["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "postgres",
                          "-v", "ON_ERROR_STOP=1", "-c", f"DROP DATABASE {database} WITH (FORCE)"])

    def checkpoint(self, journal):
        require(bool(re.fullmatch(r"[a-f0-9]{32}", journal["operation"])), "invalid_checkpoint")
        backup_id = "update-checkpoints/" + journal["operation"] + "/" + datetime.now(timezone.utc).strftime(
            "%Y%m%dT%H%M%S.%fZ")
        path = self.runtime / backup_id / "postgres.sql"
        path.parent.mkdir(parents=True, mode=0o700)
        update.protected_path(path.parent, directory=True)
        dump = self.compose(["exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-d", "sli", "--clean", "--if-exists"])
        raw = dump.encode("utf-8")
        with path.open("xb") as stream:
            stream.write(raw)
        return {"backup_id": backup_id, "checkpoint_sha256": hashlib.sha256(raw).hexdigest()}

    def apply_sql(self, override, migrations, previous):
        for path, checksum in sorted(migrations.items()):
            number = int(Path(path).name.split("_", 1)[0])
            if number <= previous:
                continue
            body = self.compose(["run", "--rm", "--no-deps", "--pull", "never", "-T", "--entrypoint", "cat",
                                 "migrate", "/opt/sli/" + path], override)
            require(hashlib.sha256(body.encode()).hexdigest() == checksum, "migration_changed")
            self.mutations += 1
            self.sql("BEGIN;\n" + body + f"\nUPDATE schema_migrations SET checksum='{checksum}', sha256='{checksum}' WHERE version={number};\nCOMMIT;")

    def migrate(self, journal):
        self.apply_sql(journal["candidate_override"], journal["manifest"]["migrations"],
                       journal["manifest"]["compatibility"]["migration_ledger_max"])

    def ownership_preflight(self, installed, config):
        require(installed["compose_project"] == self.project and config["name"] == self.project
                and installed["volumes"] == {"postgres": self.project + "_postgres"}, "foreign_installation")
        self.isolation()

    def activate(self, journal, previous=False):
        self.mutations += 1
        return super().activate(journal, previous=previous)

    def health(self, journal):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            healthy = {row["Service"] for row in self.containers()
                       if row["State"] == "running" and row.get("Health") == "healthy"}
            if {*update.INFRA, "api", "backup"} <= healthy:
                self.compose(["exec", "-T", "api", "python", "-c", health_probe()])
                return
            time.sleep(1)
        raise update.UpdateError("update_drill_health_timeout")

    def restore(self, journal):
        require(bool(re.fullmatch(r"[a-f0-9]{32}", journal["operation"])) and bool(re.fullmatch(
            r"update-checkpoints/" + journal["operation"] + r"/\d{8}T\d{6}\.\d{6}Z", journal["backup_id"])),
            "invalid_checkpoint")
        path = self.runtime / journal["backup_id"] / "postgres.sql"
        update.protected_path(path)
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == journal["checkpoint_sha256"], "invalid_checkpoint")
        self.mutations += 1
        # Execute the same bytes that were checked against the authenticated journal.
        self.sql(raw.decode("utf-8"))


def health_probe():
    return "import urllib.request; assert urllib.request.urlopen('http://127.0.0.1:8080/api/health/ready').status == 200"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, help="sli-update-drill-<synthetic suffix>; production is refused")
    parser.add_argument("--runtime", type=Path, required=True, help="empty directory, or an existing drill fixture")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--existing", action="store_true", help="adopt only a previously created synthetic fixture at A")
    args = parser.parse_args(argv)
    try:
        host = DockerDrillHost(args.runtime, args.project)
        report = run_drill(args.runtime, args.output, host, existing=args.existing)
    except Exception:
        print("update_drill_invalid_target", file=sys.stderr)
        return 1
    print("update_drill_" + report["result"])
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
