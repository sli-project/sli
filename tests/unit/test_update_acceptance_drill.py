"""Acceptance drill contracts with a fake installed host; no Docker or database."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import tarfile
from pathlib import Path

import pytest

from deploy.linux import sli_update as update
from scripts.maintenance import release_package as packages
from scripts.maintenance import update_acceptance_drill as drill


def tar_blob(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, body in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            archive.addfile(member, io.BytesIO(body))
    return stream.getvalue()


class FakeHost:
    installed_evidence = False
    validate_snapshot_binding = update.DockerHost.validate_snapshot_binding
    operation_override = update.DockerHost.operation_override

    def validate_operation_overrides(self, journal):
        # This fixture has no Compose renderer: replacement snapshots require
        # the real Docker host. Legacy paths still use authenticated hashes.
        assert "compose_snapshot" not in journal, "synthetic_host_requires_legacy_overrides"
        for key in ("previous_override", "candidate_override"):
            self.operation_override(journal, key)
        return {}

    def __init__(self, runtime, *, corrupt=None):
        self.runtime = runtime
        self.files = [runtime / "compose.json"]
        self.mutations = 0
        self.stopped = False
        self.corrupt = corrupt
        self.calls = []
        self.installed_release = None

    def guard(self, *, existing):
        self.calls.append("guard")
        self.runtime.mkdir()
        self.files[0].write_text('{"services":{}}')

    def export_image(self, root, version, migrations):
        layer = tar_blob({"opt/sli/" + path: body.encode() for path, body in migrations.items()})
        config = packages.canonical_json({"os": "linux", "architecture": "amd64",
            "config": {"Labels": {"org.opencontainers.image.version": version}},
            "rootfs": {"diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}})
        digest = hashlib.sha256(config).hexdigest()
        (root / "image.tar").write_bytes(tar_blob({digest + ".json": config, "layer.tar": layer,
            "manifest.json": packages.canonical_json([{"Config": digest + ".json", "Layers": ["layer.tar"],
                                                        "RepoTags": []}])}))
        return "sha256:" + digest, "amd64"

    def bootstrap(self, release, trust, *, existing):
        from deploy.linux.installed_state import installation_key, inventory

        path, manifest = release
        assert packages.verify_package(path, trust).manifest == manifest
        self.installed = {"component": "server", "version": "1.0.0", "os": "linux", "architecture": "amd64",
                          "compose_project": "sli-update-drill-unit", "image_tag": "synthetic:a",
                          "image_digest": manifest["image"]["digest"], "migrations": manifest["migrations"], "volumes": {},
                          "migration_ledger": [{"version": 1, "name": "drill_base", "sha256": next(iter(manifest["migrations"].values()))}]}
        update.atomic_json(self.runtime / "state/installed.json", self.installed)
        self.active = {key: self.installed[key] for key in ("version", "image_tag", "image_digest")}
        self.ledger = sorted([int(Path(path).name.split("_", 1)[0]), checksum]
                             for path, checksum in manifest["migrations"].items())
        self.counts, self.data_digest = {"drill_data": 3}, "synthetic-data-digest"
        self.installed_release = {"installation_key": installation_key(self.installed), "operation": "0" * 32,
                                  "inventory": inventory(self.installed)}

    def observe(self):
        return copy.deepcopy({"migration_ledger_max": max(row[0] for row in self.ledger), "ledger": self.ledger,
            "migration_ledger": [{"version": version, "name": "drill_base" if version == 1 else "drill_update", "sha256": checksum}
                                 for version, checksum in self.ledger], "installed_release": self.installed_release,
            "data_counts": self.counts, "data_digest": self.data_digest, "plugins": [],
            "services": {name: self.active for name in ("api", "backup")}})

    def publish_installed(self, previous, candidate, operation):
        from deploy.linux.installed_state import installation_key, inventory
        self.mutations += 1
        if self.installed_release:
            assert self.installed_release["inventory"] in (inventory(previous), inventory(candidate))
        self.installed_release = {"installation_key": installation_key(candidate), "operation": operation,
                                  "inventory": inventory(candidate)}

    def ensure_secrets(self, installed):
        assert not self.stopped

    def preflight(self, installed, manifest):
        self.calls.append("preflight")
        return self.observe()

    def deployment_fingerprint(self):
        return "synthetic-config"

    def stage(self, directory, manifest, tag):
        self.mutations += 1
        self.calls.append("stage")
        update.image_inventory(directory / "image.tar", manifest, directory / "sanitized.tar")

    def drain(self, journal):
        self.mutations += 1
        self.stopped = True

    def check_backup(self, journal):
        assert not self.stopped

    def checkpoint(self, journal):
        assert self.stopped
        self.backup = self.observe()
        return {"backup_id": "update-checkpoints/" + journal["operation"] + "/20000101T000000.000000Z",
                "checkpoint_sha256": hashlib.sha256(packages.canonical_json(self.backup)).hexdigest()}

    def migrate(self, journal):
        assert self.stopped and journal["migration_started"] and journal["backup_id"]
        self.mutations += 1
        self.ledger = sorted([int(Path(path).name.split("_", 1)[0]), checksum]
                             for path, checksum in journal["manifest"]["migrations"].items())
        if self.corrupt == "update_counts":
            self.counts["drill_data"] += 1

    def activate(self, journal, previous=False):
        self.mutations += 1
        self.active = {key: journal["previous"][key] for key in ("version", "image_tag", "image_digest")} if previous else {
            "version": journal["manifest"]["to_version"], "image_tag": journal["candidate_tag"],
            "image_digest": journal["manifest"]["image"]["digest"]}
        self.stopped = False

    def health(self, journal):
        assert not self.stopped

    def runtime_matches(self, journal, previous=False):
        # Run the real updater's version/digest/tag and ledger verification.
        return update.DockerHost.runtime_matches(self, journal, previous=previous)

    def stop_operation(self, journal):
        pass

    def restore(self, journal):
        self.mutations += 1
        assert self.stopped
        self.ledger = copy.deepcopy(self.backup["ledger"])
        self.installed_release = copy.deepcopy(self.backup["installed_release"])
        self.counts = copy.deepcopy(self.backup["data_counts"])
        self.data_digest = self.backup["data_digest"]
        if self.corrupt == "restore_counts":
            self.counts["drill_data"] += 1
        elif self.corrupt == "restore_ledger":
            self.ledger[0][1] = "0" * 64
        elif self.corrupt == "restore_data":
            self.data_digest = "changed"



@pytest.mark.parametrize("changed", ["previous_override", "candidate_override"])
def test_synthetic_host_rejects_tampered_legacy_override(tmp_path, changed):
    host = FakeHost(tmp_path / "runtime")
    host.guard(existing=False)
    journal = {}
    for key in ("previous_override", "candidate_override"):
        path = host.runtime / (key + ".json")
        update.atomic_json(path, {"services": {}})
        journal[key] = str(path)
        journal[key + "_sha256"] = update.sha256(path)
    assert host.validate_operation_overrides(journal) == {}
    update.atomic_json(Path(journal[changed]), {"services": {"api": {"image": "changed"}}})
    with pytest.raises(update.UpdateError, match="update_override_changed"):
        host.validate_operation_overrides(journal)
    assert host.mutations == 0 and host.calls == ["guard"]


def test_synthetic_host_requires_renderer_for_replacement_snapshot(tmp_path):
    host = FakeHost(tmp_path / "runtime")
    with pytest.raises(AssertionError, match="synthetic_host_requires_legacy_overrides"):
        host.validate_operation_overrides({"compose_snapshot": {"mode": "replace-installation-v1"}})
    assert host.mutations == 0 and host.calls == []


def test_build_releases_returns_finalized_signed_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(drill.subprocess, "run", lambda *args, **kwargs: pytest.fail("host process called"))
    host = FakeHost(tmp_path / "runtime")
    private, trust = drill.test_trust(tmp_path)
    releases = drill.build_releases(host, tmp_path, private)
    assert set(releases) == {"A", "B"}
    for name, version, count in (("A", "1.0.0", 1), ("B", "1.1.0", 2)):
        archive, manifest = releases[name]
        assert manifest == packages.verify_package(archive, trust).manifest
        assert manifest["to_version"] == version
        assert len(manifest["migrations"]) == count
        assert manifest["files"] == [{
            "path": "image.tar", "size": (tmp_path / name / "image.tar").stat().st_size,
            "sha256": update.sha256(tmp_path / name / "image.tar"),
        }]


def test_complete_drill_uses_real_signatures_updater_and_resume(tmp_path, monkeypatch):
    monkeypatch.setattr(drill.subprocess, "run", lambda *args, **kwargs: pytest.fail("host process called"))
    host = FakeHost(tmp_path / "runtime")
    report = drill.run_drill(host.runtime, tmp_path / "output", host)
    assert report["result"] == "passed", report
    assert set(drill.STATES) == set(report["states"])
    assert all(row["outcome"] == "passed" and row["state"] == "staged" for row in report["scenarios"])
    assert report["accepted"] is False
    assert report["evidence"]["resume_stage"]["resume_status"] == "committed"
    assert report["evidence"]["resume_migrate"]["resume_status"] == "rolled_back"
    assert report["evidence"]["update"]["runtime"]["migration_ledger_max"] == 2
    assert report["evidence"]["health"]["runtime"]["migration_ledger_max"] == 1
    assert json.loads((tmp_path / "output/result.json").read_text()) == report
    protocol = (tmp_path / "output/protocol.txt").read_text("utf-8")
    assert "Учение по обновлению" in protocol and "принято" in protocol
    # The offline signing key and test-only trust root must be removed. Only the
    # persistent host-only HMAC key may remain, so later resume can authenticate
    # the journal; it cannot sign release packages and is not mounted in apps.
    assert "test-only.key" not in (host.runtime / "state/update-journal.json").read_text()
    journal_key = host.runtime / "state/update-journal.key"
    assert set(tmp_path.rglob("*.key")) == {journal_key}
    assert len(journal_key.read_bytes()) == 32
    assert not list(tmp_path.rglob("*trust.json"))
    if os.name != "nt":
        assert journal_key.stat().st_mode & 0o777 == 0o600
        assert journal_key.parent.stat().st_mode & 0o777 == 0o700


def test_snapshot_compares_release_authority_without_operation_history(tmp_path):
    host = FakeHost(tmp_path / "runtime")
    host.guard(existing=False)
    private, trust = drill.test_trust(tmp_path)
    releases = drill.build_releases(host, tmp_path, private)
    host.bootstrap(releases["A"], trust, existing=False)
    updater = update.Updater(host.runtime, trust, host)
    before = drill.snapshot(updater, host)
    assert before["runtime"]["installed_release"] is not None
    host.installed_release["operation"] = "1" * 32
    assert drill.snapshot(updater, host) == before


def test_docker_bootstrap_publishes_initial_release_authority(tmp_path, monkeypatch):
    private, trust = drill.test_trust(tmp_path)
    releases = drill.build_releases(FakeHost(tmp_path / "export"), tmp_path, private)
    host = drill.DockerDrillHost(tmp_path / "runtime", "sli-update-drill-unit")
    host.fixture = "a" * 32
    events = []
    monkeypatch.setattr(host, "stage", lambda *args: None)
    monkeypatch.setattr(host, "isolation", lambda: None)
    monkeypatch.setattr(host, "compose", lambda *args, **kwargs: None)
    monkeypatch.setattr(host, "apply_sql", lambda *args: events.append("migrations"))

    def publish(previous, candidate, operation):
        assert previous == candidate
        assert candidate["version"] == "1.0.0"
        assert candidate["migration_ledger"] == [{"version": 1, "name": "drill_base",
            "sha256": hashlib.sha256(drill.SQL_A.encode()).hexdigest()}]
        assert operation == host.fixture
        events.append("registry")

    monkeypatch.setattr(host, "publish_installed", publish)
    host.bootstrap(releases["A"], trust, existing=False)
    assert events == ["migrations", "registry"]
    assert json.loads((host.runtime / "state/installed.json").read_text())["version"] == "1.0.0"


@pytest.mark.parametrize("change,reason", [
    ("foreign_installation", "update_foreign_installation"),
    ("release_inventory", "update_installed_registry_mismatch"),
    ("missing_registry", "update_drill_registry_readback_failed"),
    ("exact_ledger", "update_migration_ledger_mismatch"),
])
def test_snapshot_rejects_changed_installed_authority(tmp_path, change, reason):
    host = FakeHost(tmp_path / "runtime")
    host.guard(existing=False)
    private, trust = drill.test_trust(tmp_path)
    releases = drill.build_releases(host, tmp_path, private)
    host.bootstrap(releases["A"], trust, existing=False)
    updater = update.Updater(host.runtime, trust, host)
    if change == "foreign_installation":
        host.installed_release["installation_key"] = "f" * 64
    elif change == "release_inventory":
        host.installed_release["inventory"]["version"] = "9.9.9"
    elif change == "missing_registry":
        host.installed_release = None
    else:
        host.installed["migration_ledger"][0]["name"] = "foreign_marker"
        update.atomic_json(updater.installed_path, host.installed)
    with pytest.raises(update.UpdateError, match=reason):
        drill.snapshot(updater, host)


@pytest.mark.parametrize("corrupt,scenario", [("update_counts", "update"), ("restore_counts", "restore_baseline"),
                                            ("restore_ledger", "restore_baseline"), ("restore_data", "restore_baseline")])
def test_report_does_not_claim_success_from_terminal_journal_only(tmp_path, corrupt, scenario):
    host = FakeHost(tmp_path / "runtime", corrupt=corrupt)
    report = drill.run_drill(host.runtime, tmp_path / "output", host)
    assert report["result"] == "failed"
    row = next(row for row in report["scenarios"] if row["id"] == scenario)
    assert row["outcome"] == "failed" and row["state"] == "implemented"
    assert report["scenarios"][-1]["outcome"] == "not_run"
    assert report["accepted"] is False


@pytest.mark.parametrize("scenario,readback", [
    ("bootstrap", 1), ("update", 2), ("restore_baseline", 3),
    ("migrate", 5), ("activate", 7), ("health", 9),
    ("resume_stage", 11), ("resume_migrate", 14),
    ("bad_signature", 16), ("incompatible_version", 17), ("insufficient_disk", 18),
])
def test_failed_verification_marks_only_started_scenario_failed(tmp_path, monkeypatch, scenario, readback):
    host = FakeHost(tmp_path / "runtime")
    original = drill.snapshot
    calls = 0

    def snapshot(updater, host):
        nonlocal calls
        calls += 1
        if calls == readback:
            raise update.UpdateError("update_drill_runtime_readback_failed")
        return original(updater, host)

    monkeypatch.setattr(drill, "snapshot", snapshot)
    report = drill.run_drill(host.runtime, tmp_path / "output", host)
    assert calls == readback
    assert report["result"] == "failed" and report["accepted"] is False
    index = list(drill.SCENARIOS).index(scenario)
    assert all(row["outcome"] == "passed" for row in report["scenarios"][:index])
    assert report["scenarios"][index] == {
        "id": scenario, "state": "implemented", "outcome": "failed",
        "reason_code": "update_drill_runtime_readback_failed",
    }
    assert all(row["outcome"] == "not_run" for row in report["scenarios"][index + 1:])
    assert scenario not in report["evidence"]
    assert json.loads((tmp_path / "output/result.json").read_text()) == report


def test_failed_evidence_does_not_promote_scenario(tmp_path, monkeypatch):
    host = FakeHost(tmp_path / "runtime")
    original = drill.public_evidence

    def public_evidence(value):
        if isinstance(value, dict) and value.get("installed", {}).get("version") == "1.1.0":
            raise RuntimeError("synthetic-private-marker")
        return original(value)

    monkeypatch.setattr(drill, "public_evidence", public_evidence)
    report = drill.run_drill(host.runtime, tmp_path / "output", host)
    assert report["result"] == "failed" and report["accepted"] is False
    assert report["scenarios"][0]["outcome"] == "passed"
    assert report["scenarios"][1] == {
        "id": "update", "state": "implemented", "outcome": "failed", "reason_code": "update_drill_failed",
    }
    assert all(row["outcome"] == "not_run" for row in report["scenarios"][2:])
    assert set(report["evidence"]) == {"bootstrap"}
    assert json.loads((tmp_path / "output/result.json").read_text()) == report
    assert "synthetic-private-marker" not in (tmp_path / "output/protocol.txt").read_text("utf-8")


@pytest.mark.parametrize("project", ["sli", "production", "sli-update-drill-", "sli-update-drill-X",
                                     "sli-update-drill-test;anything", "sli-update-drill-a/../sli"])
def test_refuse_production_and_unsafe_names_before_docker(tmp_path, project, monkeypatch):
    monkeypatch.setattr(drill.subprocess, "run", lambda *args, **kwargs: pytest.fail("Docker called"))
    with pytest.raises(update.UpdateError, match="unsafe_project"):
        drill.DockerDrillHost(tmp_path / "runtime", project)


def test_refuse_nonempty_runtime_without_docker(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "unrelated.txt").write_text("synthetic")
    host = drill.DockerDrillHost(runtime, "sli-update-drill-unit")
    monkeypatch.setattr(host, "command", lambda *args, **kwargs: pytest.fail("Docker called"))
    with pytest.raises(update.UpdateError, match="runtime_not_empty"):
        host.guard(existing=False)


def test_refuse_existing_foreign_or_changed_compose(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    host = drill.DockerDrillHost(runtime, "sli-update-drill-unit")
    host.files[0].write_text("synthetic")
    update.atomic_json(host.marker_path, {"project": "sli", "fixture": "a" * 32, "synthetic_only": True,
                                         "compose_sha256": update.sha256(host.files[0])})
    monkeypatch.setattr(host, "command", lambda *args, **kwargs: pytest.fail("Docker called"))
    with pytest.raises(update.UpdateError, match="foreign_runtime"):
        host.guard(existing=True)
    marker = json.loads(host.marker_path.read_text())
    marker["project"] = host.project
    update.atomic_json(host.marker_path, marker)
    host.files[0].write_text("changed")
    with pytest.raises(update.UpdateError, match="compose_changed"):
        host.guard(existing=True)


def test_docker_compose_never_uses_production_project(tmp_path, monkeypatch):
    host = drill.DockerDrillHost(tmp_path / "runtime", "sli-update-drill-unit")
    calls = []
    monkeypatch.setattr(host, "command", lambda args, **kwargs: calls.append(args))
    with pytest.raises(update.UpdateError, match="guard_required"):
        host.compose(["up", "-d"])
    host.allowed = True
    host.compose(["ps"], tmp_path / "candidate.json")
    assert calls == [["docker", "compose", "-p", "sli-update-drill-unit", "-f", str(host.files[0]),
                      "-f", str(tmp_path / "candidate.json"), "ps"]]


@pytest.mark.parametrize("fail_restore", [False, True])
def test_drill_precheck_uses_disposable_database_and_always_cleans_up(tmp_path, monkeypatch, fail_restore):
    host = drill.DockerDrillHost(tmp_path / "runtime", "sli-update-drill-unit")
    calls = []
    def compose(args, **kwargs):
        calls.append((args, kwargs))
        if "pg_dump" in args:
            return "synthetic dump"
        if kwargs.get("stdin") and fail_restore:
            raise RuntimeError("synthetic_restore_failure")
        return ""
    monkeypatch.setattr(host, "compose", compose)
    if fail_restore:
        with pytest.raises(RuntimeError, match="synthetic_restore_failure"):
            host.check_backup({})
    else:
        host.check_backup({})
    assert len(calls) == 4
    name = calls[1][0][-1].split()[2]
    assert re.fullmatch(r"sli_backup_check_[a-f0-9]{32}", name)
    assert calls[2][0][calls[2][0].index("-d") + 1] == name
    assert calls[2][1] == {"stdin": b"synthetic dump"}
    assert calls[3][0][-1] == f"DROP DATABASE {name} WITH (FORCE)"


def test_failure_output_redacts_raw_host_errors(tmp_path):
    class FailedHost(FakeHost):
        def guard(self, *, existing):
            raise RuntimeError("synthetic-private-marker")

    host = FailedHost(tmp_path / "runtime")
    report = drill.run_drill(host.runtime, tmp_path / "output", host)
    assert report["scenarios"][0]["reason_code"] == "update_drill_failed"
    assert "synthetic-private-marker" not in json.dumps(report)
    assert "synthetic-private-marker" not in (tmp_path / "output/protocol.txt").read_text("utf-8")


def test_new_script_registered_in_acceptance_component():
    from scripts.maintenance.repository_relevance_audit import COMPONENTS

    assert "scripts/maintenance/update_acceptance_drill.py" in COMPONENTS["разработка_и_приёмка"]


@pytest.mark.parametrize("scenario,reason", [("bad_signature", "invalid package signature"),
                                           ("incompatible_version", "update_incompatible_version"),
                                           ("insufficient_disk", "update_insufficient_disk")])
def test_negative_packages_refused_without_any_host_call(tmp_path, scenario, reason):
    host = FakeHost(tmp_path / "runtime")
    host.guard(existing=False)
    private, trust = drill.test_trust(tmp_path)
    releases = drill.build_releases(host, tmp_path, private)
    host.bootstrap(releases["A"], trust, existing=False)
    updater = update.Updater(host.runtime, trust, host)
    before = drill.snapshot(updater, host)
    installed_bytes = updater.installed_path.read_bytes()
    invalid = drill.negative_package(releases["B"][0], tmp_path / "invalid.zip", private, scenario)
    with pytest.raises(packages.PackageError, match=reason):
        updater.apply(invalid)
    assert host.calls == ["guard"] and host.mutations == 0
    assert updater.installed_path.read_bytes() == installed_bytes
    assert drill.snapshot(updater, host) == before
    assert updater.operation()["status"] == "rejected" and updater.operation()["phase"] == "verify"


def synthetic_config(host):
    return {"name": host.project, "services": {name: {"labels": {drill.LABEL: host.fixture}}
            for name in (*update.INFRA, "api", "backup", "migrate")},
            "volumes": {"postgres": {"name": host.project + "_postgres"}},
            "networks": {"default": {"name": host.project + "_default", "internal": True}}}


@pytest.mark.parametrize("unsafe", ["project", "external_volume", "bind_mount", "port", "network"])
def test_isolation_refuses_unsafe_compose_before_resource_actions(tmp_path, monkeypatch, unsafe):
    host = drill.DockerDrillHost(tmp_path / "runtime", "sli-update-drill-unit")
    host.fixture = "a" * 32
    config = synthetic_config(host)
    if unsafe == "project":
        config["name"] = "sli"
    elif unsafe == "external_volume":
        config["volumes"]["postgres"]["external"] = True
    elif unsafe == "bind_mount":
        config["services"]["api"]["volumes"] = [{"type": "bind", "source": "/synthetic", "target": "/data"}]
    elif unsafe == "port":
        config["services"]["api"]["ports"] = [{"published": "8080", "target": 8080}]
    else:
        config["networks"]["default"]["internal"] = False
    monkeypatch.setattr(host, "config", lambda: config)
    monkeypatch.setattr(host, "command", lambda *args, **kwargs: pytest.fail("resource command called"))
    with pytest.raises(update.UpdateError):
        host.isolation()


@pytest.mark.parametrize("unsafe", ["shared_volume", "shared_network", "foreign_container"])
def test_isolation_refuses_existing_shared_resources(tmp_path, monkeypatch, unsafe):
    host = drill.DockerDrillHost(tmp_path / "runtime", "sli-update-drill-unit")
    host.fixture = "a" * 32
    config = synthetic_config(host)
    monkeypatch.setattr(host, "config", lambda: config)

    def command(args):
        if args[:3] == ["docker", "ps", "-aq"]:
            return "other" if any(arg.startswith("volume=") for arg in args) else "owned"
        if args[:2] == ["docker", "inspect"]:
            return json.dumps([{"Config": {"Labels": {drill.LABEL: "other" if unsafe == "foreign_container" else host.fixture}},
                                "NetworkSettings": {"Networks": {host.project + "_default": {}}}, "Mounts": []}])
        if args[:3] == ["docker", "volume", "ls"]:
            return host.project + "_postgres" if unsafe == "shared_volume" else ""
        if args[:3] == ["docker", "volume", "inspect"]:
            return json.dumps([{"Labels": {drill.LABEL: host.fixture, "com.docker.compose.project": host.project}}])
        if args[:3] == ["docker", "network", "ls"]:
            return host.project + "_default"
        if args[:3] == ["docker", "network", "inspect"]:
            return json.dumps([{"Internal": True, "Labels": {drill.LABEL: host.fixture,
                "com.docker.compose.project": host.project}, "Containers": {"other": {}}}])
        pytest.fail("unexpected command")

    monkeypatch.setattr(host, "command", command)
    with pytest.raises(update.UpdateError, match=unsafe):
        host.isolation()


def test_migration_uses_candidate_override_and_records_verified_checksum(tmp_path, monkeypatch):
    host = drill.DockerDrillHost(tmp_path / "runtime", "sli-update-drill-unit")
    calls, statements = [], []
    body = drill.SQL_B
    path = "config/postgres_migrations/002_drill.sql"
    checksum = hashlib.sha256(body.encode()).hexdigest()
    monkeypatch.setattr(host, "compose", lambda args, override: calls.append((args, override)) or body)
    monkeypatch.setattr(host, "sql", lambda statement: statements.append(statement))
    host.apply_sql("synthetic-candidate.json", {path: checksum}, 1)
    assert calls == [(["run", "--rm", "--no-deps", "--pull", "never", "-T", "--entrypoint", "cat",
                      "migrate", "/opt/sli/" + path], "synthetic-candidate.json")]
    assert statements == ["BEGIN;\n" + body +
                          f"\nUPDATE schema_migrations SET checksum='{checksum}', sha256='{checksum}' WHERE version=2;\nCOMMIT;"]
    statements.clear()
    with pytest.raises(update.UpdateError, match="migration_changed"):
        host.apply_sql(None, {path: "0" * 64}, 1)
    assert statements == []


def test_drill_checkpoint_round_trip_pins_dump_bytes(tmp_path, monkeypatch):
    host = drill.DockerDrillHost(tmp_path / "runtime", "sli-update-drill-unit")
    dump = "-- synthetic checkpoint\nSELECT 1;\n"
    monkeypatch.setattr(host, "compose", lambda *args, **kwargs: dump)
    statements = []
    monkeypatch.setattr(host, "sql", statements.append)
    journal = {"operation": "a" * 32}
    checkpoint = host.checkpoint(journal)
    assert re.fullmatch(r"update-checkpoints/" + journal["operation"] + r"/\d{8}T\d{6}\.\d{6}Z",
                        checkpoint["backup_id"])
    assert checkpoint["checkpoint_sha256"] == hashlib.sha256(dump.encode()).hexdigest()
    assert (host.runtime / checkpoint["backup_id"] / "postgres.sql").read_bytes() == dump.encode()
    host.restore({**journal, **checkpoint})
    assert statements == [dump] and host.mutations == 1


@pytest.mark.parametrize("corrupt", ["dump", "digest", "operation", "symlink"])
def test_drill_restore_refuses_changed_or_foreign_checkpoint_before_sql(tmp_path, monkeypatch, corrupt):
    host = drill.DockerDrillHost(tmp_path / "runtime", "sli-update-drill-unit")
    monkeypatch.setattr(host, "compose", lambda *args, **kwargs: "-- synthetic checkpoint\n")
    monkeypatch.setattr(host, "sql", lambda *args: pytest.fail("restore SQL called"))
    journal = {"operation": "a" * 32}
    journal.update(host.checkpoint(journal))
    path = host.runtime / journal["backup_id"] / "postgres.sql"
    if corrupt == "dump":
        path.write_text("-- changed checkpoint\n")
    elif corrupt == "digest":
        journal["checkpoint_sha256"] = "0" * 64
    elif corrupt == "operation":
        journal["operation"] = "b" * 32
    else:
        target = tmp_path / "synthetic.sql"
        path.rename(target)
        path.symlink_to(target)
    with pytest.raises(update.UpdateError, match="update_(drill_invalid_checkpoint|unsafe_state)"):
        host.restore(journal)
    assert host.mutations == 0


def test_public_evidence_omits_local_paths():
    assert drill.public_evidence({"installed": {"version": "1.0.0", "override": "/synthetic/local/path"}}) == {
        "installed": {"version": "1.0.0"}}


def test_adopt_mode_is_explicitly_forwarded(tmp_path):
    class AdoptHost(FakeHost):
        def guard(self, *, existing):
            assert existing is True
            super().guard(existing=existing)

        def bootstrap(self, release, trust, *, existing):
            assert existing is True
            super().bootstrap(release, trust, existing=existing)

    host = AdoptHost(tmp_path / "runtime")
    assert drill.run_drill(host.runtime, tmp_path / "output", host, existing=True)["result"] == "passed"


def test_installed_evidence_never_grants_owner_acceptance(tmp_path):
    host = FakeHost(tmp_path / "runtime")
    host.installed_evidence = True  # Emulate the real host's capability after its readbacks.
    report = drill.run_drill(host.runtime, tmp_path / "output", host)
    assert report["result"] == "passed"
    assert all(row["state"] == "installed" for row in report["scenarios"])
    assert report["accepted"] is False


def test_report_directory_cannot_mutate_runtime_on_refusal(tmp_path):
    host = FakeHost(tmp_path / "runtime")
    with pytest.raises(update.UpdateError, match="output_inside_runtime"):
        drill.run_drill(host.runtime, host.runtime / "output", host)
    assert host.calls == [] and not host.runtime.exists()
