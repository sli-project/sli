"""Package contracts and lifecycle fakes; no real DB, services or APT mutations."""
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_backup, native_dotnet_generator, native_preinstall, native_upgrade
from deploy.linux import native_host as host
from deploy.linux import native_install as install
from deploy.linux import native_package as package
from deploy.linux import native_runtime as runtime

VERSION = "1.0-1~deb13"


def test_candidate_start_failure_records_unit_exit_and_safe_error_line(monkeypatch, capsys):
    stderr = (b'Job for sli-health.service failed because the control process exited with error code.\n'
              b'synthetic-private-data\n')
    monkeypatch.setattr(install.subprocess, 'run', lambda *a, **kw: SimpleNamespace(returncode=1, stderr=stderr))
    with pytest.raises(RuntimeError) as caught:
        install.command(['systemctl', 'start', 'sli-health.service'])
    journal = SimpleNamespace(value={'status': 'candidate_testing'}, write=lambda: None)
    native_upgrade.record_failure(journal, caught.value)
    assert journal.value['failure_detail'] == {
        'phase': 'candidate_testing', 'unit': 'sli-health.service', 'exit_code': 1,
        'error': 'Job for sli-health.service failed because the control process exited with error code.',
    }
    assert 'synthetic-private-data' not in capsys.readouterr().err


@pytest.mark.parametrize("wrapped", [True, False])
def test_wait_api_rejects_untrusted_tls_without_retry(monkeypatch, wrapped):
    import ssl
    from urllib.error import URLError

    monkeypatch.setattr(ssl, "create_default_context", lambda **kwargs: object())
    error = ssl.SSLCertVerificationError("private certificate details")
    def urlopen(*args, **kwargs):
        raise URLError(error) if wrapped else error
    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    monkeypatch.setattr(install.time, "sleep", lambda _: pytest.fail("TLS failure must not be retried"))
    with pytest.raises(RuntimeError, match="^native_api_tls_untrusted$") as caught:
        install.wait_api({"health_url": "https://127.0.0.1:443/api/health/ready"})
    assert caught.value.__suppress_context__


@pytest.fixture(autouse=True)
def native_clickhouse_mode(monkeypatch):
    monkeypatch.setattr(host.clickhouse, "configured_mode", lambda root=Path("/"): "native")


@pytest.fixture
def payload(tmp_path):
    root = tmp_path / "release"
    root.mkdir()
    manifest = {"schema_version": 1, "python": "/opt/sli/runtimes/test/bin/python3.14",
                "python_sha256": "a" * 64, "migration_ledger": [{"version": 1}],
                "roles": [["sli_test", False]], "plugins": {
                    key: {"version": "1.0.0", "migrations": {}}
                    for key in ("sli.ad", "sli.gpo", "sli.file-audit", "sli.workstations", "sli.sigma")}}
    (root / "native-runtime.json").write_text(json.dumps(manifest))
    plugin = root / "config/plugin_packages/sli.remote-access.json"
    plugin.parent.mkdir(parents=True)
    shutil.copyfile(Path(__file__).resolve().parents[2] / "config/plugin_packages/sli.remote-access.json", plugin)
    (root / "app.py").write_text("pass\n")
    return root


@pytest.fixture
def dotnet_payload(tmp_path):
    published = tmp_path / "published"
    published.mkdir()
    (published / "Sli.Server").write_text("synthetic-apphost")
    (published / "Sli.Server.runtimeconfig.json").write_text("{}")
    return published


def test_package_requires_dotnet_before_writing(payload, tmp_path):
    output = tmp_path / "out"
    with pytest.raises(ValueError, match="^native_dotnet_payload_required$"):
        package.build(payload, output, "new", VERSION, VERSION)
    assert not output.exists()


def test_beta_package_does_not_install_clickhouse_or_docker(payload, dotnet_payload, tmp_path, monkeypatch):
    captured = {}

    def build(argv, **kwargs):
        root = Path(argv[3])
        captured[root.name] = {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8")
                               for p in root.rglob("*") if p.is_file()}

    monkeypatch.setattr(package.subprocess, "run", build)
    package.build(payload, tmp_path / "out", "new", VERSION, VERSION, dotnet_published=dotnet_payload)
    for files in captured.values():
        dependencies = files["DEBIAN/control"].lower()
        assert "clickhouse" not in dependencies and "docker" not in dependencies
        assert not any("sli-clickhouse-" in name or name.endswith("image.tar") for name in files)


def test_clean_apt_install_needs_no_manual_postgresql_common_step(payload, dotnet_payload, tmp_path, monkeypatch):
    """A fake dpkg honours package ordering and refuses a conffile prompt.

    PostgreSQL-common must own its config before SLI's real preinst guard edits
    it. Otherwise its later unpack needs a manual keep/replace decision.
    """
    from email import message_from_string
    import stat

    from deploy.linux import native_preinstall as preinstall

    controls = {}

    def build(argv, **kwargs):
        root = Path(argv[3])
        controls[root.name] = message_from_string((root / 'DEBIAN/control').read_text())

    monkeypatch.setattr(package.subprocess, 'run', build)
    package.build(payload, tmp_path / 'out', 'new', VERSION, VERSION, dotnet_published=dotnet_payload)
    root = tmp_path / 'debian'
    config = root / 'etc/postgresql-common/createcluster.conf'
    installed = set()

    def dependencies(field):
        for dependency in controls['sli-host'].get(field, '').split(','):
            name = dependency.strip().split(' ')[0]
            if name != 'postgresql-common' or name in installed:
                continue
            assert not config.exists(), 'dpkg would ask whether to replace the unowned createcluster.conf'
            config.parent.mkdir(parents=True, exist_ok=True)
            config.write_text('# Debian default\n')
            installed.add(name)

    # Model POSIX metadata, as in test_linux_native_preinstall.debian_tree.
    original_lstat = Path.lstat

    def metadata(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        return SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755 if stat.S_ISDIR(info.st_mode)
                               else stat.S_IFREG | 0o644)

    monkeypatch.setattr(Path, 'lstat', metadata)
    monkeypatch.setattr(preinstall, 'ensure_directory', lambda path, *a, **kw: path.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(preinstall, 'postgres_uid', lambda: 123)
    dependencies('Pre-Depends')
    preinstall.prepare(root)
    dependencies('Depends')
    # Fake postgresql-18 postinst: a default cluster must never be created.
    settings = dict(line.split('=', 1) for line in config.read_text().splitlines() if '=' in line)
    vendor_cluster = root / 'var/lib/postgresql/18/main'
    if settings.get('create_main_cluster ', '').strip() != 'false':
        vendor_cluster.mkdir(parents=True)
    assert not vendor_cluster.exists()
    assert (root / 'var/lib/sli/state/createcluster.conf.before').read_text() == '# Debian default\n'


def test_package_split_exact_dependencies_and_previous_retention(payload, dotnet_payload, tmp_path, monkeypatch):
    captured = {}

    def build(argv, **kwargs):
        assert argv[:3] == ["dpkg-deb", "--root-owner-group", "--build"]
        root = Path(argv[3])
        captured[root.name] = {p.relative_to(root).as_posix(): p.read_text(encoding="utf-8") for p in root.rglob("*") if p.is_file()}
        if os.name != "nt":
            assert all(p.stat().st_mode & 0o111 for p in (root / "DEBIAN").iterdir() if p.name != "control")
        assert kwargs["check"] is True

    monkeypatch.setattr(package.subprocess, "run", build)
    result = package.build(payload, tmp_path / "out", "new", VERSION, VERSION, ("old", VERSION, VERSION), dotnet_published=dotnet_payload)
    assert len(result) == 5
    assert captured["sli-release-new"]["opt/sli/releases/new/app.py"] == "pass\n"
    inventory = json.loads(captured["sli-release-new"]["opt/sli/releases/new/native-runtime.json"])
    assert len(inventory["plugins"]) == 6
    assert inventory["plugins"]["sli.remote-access"]["version"] == "0.1.0"
    assert inventory["plugins"]["sli.remote-access"]["manifest_sha256"] == (
        "78ae9bcc2e65f54c8469dd0494f5c951df0cfa53ae33cff84478bc70eaa958bf")
    assert "sli.remote-access" not in json.loads((payload / "native-runtime.json").read_text())["plugins"]
    assert "sli-runtime-test (= 1.0-1~deb13)" in captured["sli-release-new"]["DEBIAN/control"]
    public = captured["sli"]["DEBIAN/control"]
    assert "sli-host (= 1.0-1~deb13)" in public and "postgresql-18" in public
    assert all(value not in public for value in ("Docker", "pip", "gcc", "nodejs", "git,"))
    hold = captured["sli-rollback-hold"]["DEBIAN/control"]
    assert "Protected: yes" not in hold
    assert "sli-host (= 1.0-1~deb13)" in hold
    assert "Installed-Size: " in captured["sli-release-new"]["DEBIAN/control"]
    assert "sli-release-old (= 1.0-1~deb13)" in hold
    assert "sli-runtime-old" not in hold  # Retained release owns its runtime dependency.
    assert "sli-rollback-hold (= 1.0-1~deb13)" in public
    assert "usr/lib/sli/native_install.py" in captured["sli-host"]
    assert 'native_remove.py "$@"' in captured["sli-host"]["usr/sbin/sli-remove"]
    assert captured["sli-host"]["DEBIAN/prerm"] == captured["sli-rollback-hold"]["DEBIAN/prerm"]
    assert "--owner-recovery" in captured["sli-host"]["usr/lib/sli/native_setup.py"]
    assert 'native_setup.py "$@"' in captured["sli-host"]["usr/sbin/sli-setup"]
    assert 'native_host.py cold-tables "$@"' in captured["sli-host"]["usr/sbin/sli-cold-tables"]
    assert "usr/lib/sli/native_backup.py" in captured["sli-host"]
    assert 'native_backup.py launch "$@"' in captured["sli-host"]["usr/sbin/sli-native-backup"]
    assert "usr/lib/sli/native_upgrade.py" in captured["sli-host"]
    assert 'native_upgrade.py launch "$@"' in captured["sli-host"]["usr/sbin/sli-native-upgrade"]
    for files in captured.values():
        for name, body in files.items():
            if name.startswith(("DEBIAN/", "usr/sbin/")):
                for line in body.splitlines():
                    if "/usr/bin/python3 " in line:
                        assert "/usr/bin/python3 -I -B " in line
    for body in captured["sli"].values():
        assert "apt-get" not in body and "dpkg --" not in body and "rm -rf" not in body


def test_required_dotnet_package_is_isolated_and_loads_required_credentials(payload, tmp_path, monkeypatch):
    project = tmp_path / "Sli.Server.csproj"
    project.write_text("<Project/>\n")
    captured = {}

    def run(argv, **kwargs):
        if argv[:2] == ["dotnet", "publish"]:
            assert argv[argv.index("-r") + 1] == "linux-x64"
            assert argv[argv.index("--self-contained") + 1] == "true"
            target = Path(argv[argv.index("-o") + 1])
            target.mkdir(parents=True)
            (target / "Sli.Server").write_text("binary")
            (target / "Sli.Server.runtimeconfig.json").write_text("{}")
        else:
            root = Path(argv[3])
            captured[root.name] = {p.relative_to(root).as_posix(): (p.read_text(encoding="utf-8"), p.stat().st_mode & 0o777)
                                   for p in root.rglob("*") if p.is_file()}

    monkeypatch.setattr(package.subprocess, "run", run)
    result = package.build(payload, tmp_path / "out", "new", VERSION, VERSION, dotnet_project=project)
    assert len(result) == 5
    files = captured["sli-server-dotnet"]
    release_files = captured["sli-release-new"]
    assert "opt/sli/dotnet/new/Sli.Server" in release_files and "opt/sli/dotnet/new/Sli.Server" not in files
    if os.name != "nt":
        assert release_files["opt/sli/dotnet/new/Sli.Server"][1] & 0o111
        assert release_files["opt/sli/dotnet/new/Sli.Server.runtimeconfig.json"][1] & 0o022 == 0
    assert "usr/lib/systemd/system/sli-dotnet-api.service" not in files
    generator = files["usr/lib/systemd/system-generators/sli-dotnet-api"][0]
    assert '/usr/bin/python3 -I -B /usr/lib/sli/native_dotnet_generator.py "$@"' in generator
    assert files["usr/lib/sli/native_dotnet_generator.py"][0] == Path(native_dotnet_generator.__file__).read_text(encoding="utf-8")
    from deploy.linux import native_plugin_runtime
    assert files["usr/lib/sli/native_plugin_runtime.py"][0] == Path(native_plugin_runtime.__file__).read_text(encoding="utf-8")
    assert '/usr/bin/python3 -I -B /usr/lib/sli/native_plugin_runtime.py --release new "$@"' in files["usr/sbin/sli-plugin-runtime-dotnet"][0]
    assert f"sli-host (= {VERSION})" in files["DEBIAN/control"][0]
    assert "systemctl daemon-reload" in files["DEBIAN/postinst"][0]
    for name in ("DEBIAN/postinst", "DEBIAN/prerm", "DEBIAN/postrm"):
        assert all(command not in files[name][0] for command in ("systemctl start", "systemctl enable", "sli-runtime.target", "sli-api.service"))
    assert "systemctl stop sli-dotnet.target 'sli-dotnet-*.service'" in files["DEBIAN/prerm"][0]
    assert "adduser --system" not in files["DEBIAN/postinst"][0]
    # The selected kit requires its .NET runtime. Retained immutable releases
    # may coexist and must not force incompatible versions of that package.
    assert f"sli-server-dotnet (= {VERSION})" in captured["sli-rollback-hold"]["DEBIAN/control"][0]
    assert "sli-server-dotnet" not in captured["sli-release-new"]["DEBIAN/control"][0]


@pytest.mark.parametrize("agents,ad_credentials", [(False, False), (True, False), (False, True), (True, True)])
@pytest.mark.parametrize("bind,health_host,port", [("192.0.2.10", "192.0.2.10", 9443),
                                                  ("0.0.0.0", "127.0.0.1", 443),
                                                  ("::", "[::1]", 8443)])
def test_dotnet_unit_uses_site_binding_api_credentials_and_data_paths(agents, ad_credentials, bind, health_host, port):
    config = {"radius_pilot": False, "profiles": ["light"], "bind": bind, "https_port": port,
              "health_url": f"https://{health_host}:{port}/api/health/ready",
              "agents": agents, "ad_credentials": ad_credentials}
    unit = runtime.dotnet_unit("new", config)
    assert f'Environment="SLI_BIND={bind}"\n' in unit
    assert f'Environment="SLI_HEALTH_URL={config["health_url"]}"\n' in unit
    assert "ASPNETCORE_URLS" not in unit and "Kestrel__" not in unit
    secrets = {"runtime_password", "tls_certificate", "tls_key", "tls_ca"}
    if agents:
        secrets |= {"agent_root_certificate", "agent_issuer_certificate", "agent_issuer_key", "agent_mtls_ca"}
    if ad_credentials:
        secrets.add("ad_credentials_master_key")
    assert {line for line in unit.splitlines() if line.startswith("LoadCredential=")} == {
        "LoadCredential=sli-installation:/var/lib/sli/state/installed.json",
        *(f"LoadCredential={secret}:/etc/sli/secrets/{secret}" for secret in secrets),
    }
    env, api_secrets = runtime.environment("api", config)
    assert secrets == api_secrets
    for key, value in env.items():
        assert f'Environment="{key}={value}"\n' in unit
    assert "ReadWritePaths=/run/sli/api /var/lib/sli/ingress /var/lib/sli/spool /var/lib/sli/evidence /var/lib/sli/logs /var/lib/sli/runtime\n" in unit
    assert "User=sli-api\nGroup=sli-api\n" in unit
    assert "ProtectSystem=strict\n" in unit
    assert "InaccessiblePaths=/var/lib/sli/state /var/lib/sli/transactions /var/lib/sli/recovery\n" in unit
    assert "InaccessiblePaths=/etc/sli/secrets\n" in unit
    assert ("AmbientCapabilities=CAP_NET_BIND_SERVICE\n" in unit) == (port < 1024)
    assert "[Install]" not in unit
    assert "Conflicts=" not in unit
    assert "After=sli-api.service" not in unit


@pytest.mark.parametrize("profiles", [["light"], ["light", "heavy"], ["light", "long"], ["light", "heavy", "long"]])
@pytest.mark.parametrize("radius_pilot", [False, True])
def test_dotnet_generator_covers_selected_services_with_python_policy(tmp_path, monkeypatch, profiles, radius_pilot):
    config = {"schema_version": 1, "profiles": profiles, "radius_pilot": radius_pilot,
              "radius_source_instance": "radius01", "bind": "192.0.2.20", "https_port": 443,
              "health_url": "https://192.0.2.20:443/api/health/ready", "agents": True,
              "ad_credentials": True, "owner_setup": True, "notification_proxy": ""}
    monkeypatch.setattr(runtime, "CONFIG", tmp_path / "runtime.json")
    monkeypatch.setattr(runtime, "trusted", lambda path: path.read_bytes())
    runtime.CONFIG.write_text(json.dumps(config))
    destination = tmp_path / "generated"
    destination.mkdir()
    native_dotnet_generator.generate(runtime, "new", destination)
    commands = {
        "api": "", "post-collection": "post-collection-worker --poll-seconds 30",
        "what-where-when": "what-where-when-projection-worker", "semantic": "semantic-production-worker",
        "entity-state": "entity-state-worker", "storage-lifecycle": "storage-lifecycle-worker --interval-seconds 21600",
        "ad-snapshot-manifest-coordinator": "ad-snapshot-manifest-coordinator-worker --no-initial-delay",
        "remote-access": "radius-session-observation --component radius-session-observation",
        "notification-delivery": "notification-delivery-worker", "notification-setup": "notification-setup",
        **{f"executor-{p}": f"core-job-executor --profile {p}" for p in ("light", "heavy", "long")},
    }
    selected = runtime.selected(config)
    names = {service: f"sli-dotnet-{service}.service" for service in selected}
    assert {path.name for path in destination.iterdir()} == {"sli-dotnet.target", *names.values()}
    target = (destination / "sli-dotnet.target").read_text()
    assert "Wants=sli-health.timer " + " ".join(names.values()) + "\n" in target
    assert "Conflicts=" not in target
    assert "PartOf=sli.target\n" in target
    assert "[Install]" not in target
    policies = {service: runtime.application_unit(config, service, runtime.SERVICES[service], selected)
                for service in selected}
    for service in selected:
        body = (destination / names[service]).read_text()
        lines = body.splitlines()
        assert f"ExecStart=/opt/sli/dotnet/new/Sli.Server{' ' if commands[service] else ''}{commands[service]}" in lines
        assert not any(line.startswith("Conflicts=") for line in lines)
        assert "PartOf=sli-dotnet.target" in lines and "[Install]" not in lines
        # Preserve the Python policy except for the isolated .NET lifecycle login.
        original = policies[service].split("[Service]\n", 1)[1].splitlines()
        preserved = [line for line in original if not line.startswith(("ExecStart=", "WorkingDirectory="))]
        if service == "storage-lifecycle":
            # The lifecycle role replaces both shared runtime and storage logins;
            # sandboxing, permissions, limits and all other settings stay intact.
            shared_credentials = {
                'Environment="ADLOG_PG_DSN=host=127.0.0.1 port=5432 dbname=sli user=adlog_user"',
                'Environment="ADLOG_PG_PASSWORD_FILE=%d/runtime_password"',
                'Environment="ADLOG_STORAGE_V2_WORKER_DSN=host=127.0.0.1 port=5432 dbname=sli user=sli_storage_login"',
                'Environment="ADLOG_STORAGE_V2_WORKER_PASSWORD_FILE=%d/storage_password"',
                "LoadCredential=runtime_password:/etc/sli/secrets/runtime_password",
                "LoadCredential=storage_password:/etc/sli/secrets/storage_password",
            }
            isolated_credentials = {
                'Environment="ADLOG_PG_DSN=host=127.0.0.1 port=5432 dbname=sli user=sli_storage_lifecycle_login"',
                'Environment="ADLOG_PG_PASSWORD_FILE=%d/storage_lifecycle_password"',
                "LoadCredential=storage_lifecycle_password:/etc/sli/secrets/storage_lifecycle_password",
                "LoadCredential=storage_lifecycle_delete_password:/etc/sli/secrets/storage_lifecycle_delete_password",
                'Environment="ADLOG_STORAGE_LIFECYCLE_DELETE_DSN=host=127.0.0.1 port=5432 dbname=sli user=sli_storage_lifecycle_delete_login"',
                'Environment="ADLOG_STORAGE_LIFECYCLE_DELETE_PASSWORD_FILE=%d/storage_lifecycle_delete_password"',
            }
            assert shared_credentials.issubset(preserved)
            assert shared_credentials.isdisjoint(lines)
            preserved = (set(preserved) - shared_credentials) | isolated_credentials
            assert {line for line in lines if line.startswith("LoadCredential=")} == {
                line for line in preserved if line.startswith("LoadCredential=")}
        assert all(line in lines for line in preserved)
        assert f"User={runtime.SERVICES[service][0]}" in lines
        dependencies = {name for line in lines if line.startswith("Requires=") for name in line.split("=", 1)[1].split()}
        assert not dependencies.intersection(map(runtime.unit_name, selected))
        ordered = {name for line in lines if line.startswith("After=") for name in line.split("=", 1)[1].split()}
        assert not ordered.intersection(map(runtime.unit_name, selected))
        if service in {"api", "notification-delivery"}:
            assert "Requires=sli-dotnet-notification-setup.service" in lines
        assert "After=sli-ready.service" in lines


def test_dotnet_published_package_needs_no_sdk(payload, tmp_path, monkeypatch):
    published = tmp_path / "linux-x64"
    published.mkdir()
    (published / "Sli.Server").write_bytes(b"synthetic-apphost")
    (published / "Sli.Server.runtimeconfig.json").write_text("{}")
    (published / "Sli.Server.dll").write_bytes(b"synthetic-assembly")
    msi = tmp_path / "fixture-agent.msi"
    msi.write_bytes(b"synthetic agent package")
    captured = {}

    def run(argv, **kwargs):
        assert argv[:3] == ["dpkg-deb", "--root-owner-group", "--build"]
        root = Path(argv[3])
        if root.name == "sli-server-dotnet":
            launcher = root / "usr/sbin/sli-agent-command"
            assert launcher.is_file()
            if os.name == "posix":
                assert launcher.stat().st_mode & 0o100
        if root.name in {"sli-server-dotnet", "sli-release-new"}:
            captured.update({p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()})

    monkeypatch.setattr(package.subprocess, "run", run)
    result = package.build(payload, tmp_path / "out", "new", VERSION, VERSION, dotnet_published=published, agent_msi=msi)
    assert len(result) == 5
    assert captured["opt/sli/dotnet/new/Sli.Server"] == b"synthetic-apphost"
    assert captured["opt/sli/dotnet/new/Sli.Server.dll"] == b"synthetic-assembly"
    assert captured["opt/sli/releases/new/agent/SliAgent.msi"] == msi.read_bytes()


@pytest.mark.parametrize("invalid", ["missing", "incomplete", "private", "both"])
def test_dotnet_published_payload_refuses_invalid_input(payload, tmp_path, monkeypatch, invalid):
    published = tmp_path / "linux-x64"
    project = tmp_path / "Sli.Server.csproj"
    project.write_text("<Project/>")
    if invalid != "missing":
        published.mkdir()
        (published / "Sli.Server").write_bytes(b"synthetic-apphost")
        if invalid != "incomplete":
            (published / "Sli.Server.runtimeconfig.json").write_text("{}")
        if invalid == "private":
            (published / "secrets").mkdir()
            (published / "secrets/credential").write_text("synthetic-private")
    monkeypatch.setattr(package.subprocess, "run", lambda *args, **kwargs: pytest.fail("invalid input must not invoke tools"))
    with pytest.raises(ValueError, match="native_dotnet_|native_package_private_payload"):
        package.build(payload, tmp_path / "out", "new", VERSION, VERSION,
                      dotnet_published=published, dotnet_project=project if invalid == "both" else None)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink contract; Linux CI")
def test_dotnet_published_payload_refuses_symlinks_before_copy(payload, tmp_path, monkeypatch):
    published = tmp_path / "linux-x64"
    published.mkdir()
    (published / "Sli.Server").symlink_to(payload / "app.py")
    (published / "Sli.Server.runtimeconfig.json").write_text("{}")
    monkeypatch.setattr(package.subprocess, "run", lambda *args, **kwargs: pytest.fail("invalid input must not invoke tools"))
    with pytest.raises(ValueError, match="native_package_payload_invalid"):
        package.build(payload, tmp_path / "out", "new", VERSION, VERSION, dotnet_published=published)


def test_dotnet_generator_reads_installed_config_and_refuses_untrusted_or_invalid_site(tmp_path, monkeypatch):
    config = {"schema_version": 1, "profiles": ["light"], "radius_pilot": False, "agents": True,
              "ad_credentials": True, "bind": "192.0.2.20", "https_port": 9443,
              "health_url": "https://192.0.2.20:9443/api/health/ready"}
    monkeypatch.setattr(runtime, "CONFIG", tmp_path / "runtime.json")
    monkeypatch.setattr(runtime, "trusted", lambda path: path.read_bytes())
    destination = tmp_path / "generator"
    destination.mkdir()
    unit = destination / "sli-dotnet-api.service"
    native_dotnet_generator.generate(runtime, "new", destination)
    assert not unit.exists()  # Fresh unpack before initial site setup.
    runtime.CONFIG.write_text(json.dumps(config))
    native_dotnet_generator.generate(runtime, "new", destination)
    assert unit.read_text() == runtime.dotnet_unit("new", config)
    with pytest.raises(FileExistsError):
        native_dotnet_generator.generate(runtime, "new", destination)
    unit.unlink()
    with pytest.raises(runtime.RuntimeErrorCode, match="native_release_invalid"):
        native_dotnet_generator.generate(runtime, "../bad", destination)
    runtime.CONFIG.write_text(json.dumps(dict(config, health_url='https://192.0.2.20:9443/invalid')))
    with pytest.raises(runtime.RuntimeErrorCode, match="native_health_url_invalid"):
        native_dotnet_generator.generate(runtime, "new", destination)
    runtime.CONFIG.write_text(json.dumps(config))
    monkeypatch.setattr(runtime, "trusted", lambda path: (_ for _ in ()).throw(runtime.RuntimeErrorCode("native_path_untrusted")))
    with pytest.raises(runtime.RuntimeErrorCode, match="native_path_untrusted"):
        native_dotnet_generator.generate(runtime, "new", destination)
    assert not unit.exists()


def test_generator_follows_restored_release_after_candidate_unpack(tmp_path, monkeypatch):
    config = {'schema_version': 1, 'profiles': ['light'], 'radius_pilot': False,
              'bind': '192.0.2.20', 'health_url': 'https://192.0.2.20:8443/api/health/ready'}
    monkeypatch.setattr(runtime, 'CONFIG', tmp_path / 'runtime.json')
    monkeypatch.setattr(runtime, 'CURRENT', tmp_path / 'current')
    monkeypatch.setattr(runtime, 'trusted', lambda path: path.read_bytes())
    runtime.CONFIG.write_text(json.dumps(config))
    runtime.CURRENT.mkdir()  # The release fixture below supplies the resolved pointer.
    selected = {'release': 'candidate'}
    monkeypatch.setattr(runtime, 'release', lambda: (tmp_path / 'releases' / selected['release'], {}, 'digest'))
    monkeypatch.setattr(native_dotnet_generator, 'DOTNET', tmp_path / 'dotnet')
    # The legacy .deb used to own this publication; APT removes it on unpack.
    accepted = tmp_path / 'releases/accepted/dotnet'
    candidate = tmp_path / 'dotnet/candidate'
    for directory in (accepted, candidate):
        directory.mkdir(parents=True)
        (directory / 'Sli.Server').write_text(directory.parent.name)
    for release in ('candidate', 'accepted'):
        selected['release'] = release
        destination = tmp_path / ('units-' + release)
        destination.mkdir()
        native_dotnet_generator.generate_installed(runtime, destination)
        unit = (destination / 'sli-dotnet-executor-light.service').read_text()
        binary = candidate if release == 'candidate' else accepted
        assert f'ExecStart={binary.as_posix()}/Sli.Server core-job-executor' in unit
        assert f'WorkingDirectory={binary.as_posix()}\n' in unit
        setup = (destination / 'sli-dotnet-notification-setup.service').read_text()
        assert f'ExecStartPre={binary.as_posix()}/Sli.Server notification-setup --repair-public-urls\n' in setup


@pytest.mark.skipif(os.name != 'posix', reason='dpkg and POSIX file permissions; Linux CI')
def test_dotnet_preinst_preserves_legacy_publication_before_dpkg_removes_it(tmp_path, monkeypatch):
    accepted = tmp_path / 'opt/sli/releases/accepted'
    accepted.mkdir(parents=True)
    (accepted / 'native-runtime.json').write_text('{}')
    (tmp_path / 'opt/sli/current').symlink_to(accepted)
    publication = tmp_path / 'opt/sli/dotnet/accepted'
    publication.mkdir(parents=True)
    (publication / 'Sli.Server').write_bytes(b'accepted apphost')
    (publication / 'Sli.Server').chmod(0o755)
    (publication / 'Sli.Server.dll').write_bytes(b'accepted assembly')
    monkeypatch.setattr(native_preinstall, 'trusted', lambda path: None)
    monkeypatch.setattr(native_preinstall.subprocess, 'run', lambda *a, **kw: SimpleNamespace(stdout=''))
    native_preinstall.retain_legacy_dotnet(root=tmp_path)
    shutil.rmtree(publication)  # Simulate dpkg removing files owned by the old unversioned package.
    native_preinstall.retain_legacy_dotnet(root=tmp_path)  # Safe to retry after unpack.
    assert (accepted / 'dotnet/Sli.Server').read_bytes() == b'accepted apphost'
    assert (accepted / 'dotnet/Sli.Server').stat().st_mode & 0o111
    assert (accepted / 'dotnet/Sli.Server.dll').read_bytes() == b'accepted assembly'


@pytest.mark.parametrize("name", ["secrets/password", ".env", "key.pem", "node_modules/code.js"])
def test_private_payload_refused_before_build(payload, dotnet_payload, tmp_path, name):
    path = payload / name
    path.parent.mkdir(exist_ok=True)
    path.write_text("private")
    with pytest.raises(ValueError, match="native_package_private_payload"):
        package.build(payload, tmp_path / "out", "test", VERSION, VERSION, dotnet_published=dotnet_payload)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink contract; Linux CI")
def test_symlink_payload_refused(payload, dotnet_payload, tmp_path):
    (payload / "link").symlink_to("app.py")
    with pytest.raises(ValueError, match="native_package_payload_invalid"):
        package.build(payload, tmp_path / "out", "test", VERSION, VERSION, dotnet_published=dotnet_payload)


@pytest.mark.parametrize("release,version", [("../bad", VERSION), ("bad;exit", VERSION), ("good", "1\nDepends: evil")])
def test_control_injection_refused(payload, tmp_path, release, version):
    with pytest.raises(ValueError, match="native_package_identity_invalid"):
        package.build(payload, tmp_path / "out", release, version, VERSION)


@pytest.mark.parametrize("action,old,expected", [("install", "", 0), ("upgrade", VERSION, 0),
                                                ("upgrade", "0.9-1~deb13", 1),
                                                ("upgrade", "2.0-1~deb13", 1), ("invalid", "", 1)])
@pytest.mark.skipif(os.name == "nt", reason="Debian /bin/sh maintainer scripts; Linux CI")
def test_preinst_works_without_unpacked_helper(tmp_path, action, old, expected):
    path = tmp_path / "preinst"
    saved = tmp_path / "recovery/test/native_upgrade.py"
    saved.parent.mkdir(parents=True)
    saved.write_text("import sys\n"
                     f"assert sys.argv[1:] == ['dispatch', 'check-package', {VERSION!r}]\n"
                     "raise SystemExit(1)\n")
    # Execute the shell contract against a fake saved CLI, even if the machine
    # running pytest happens to have a real native installation.
    body = package.scripts("test", VERSION)["preinst"]
    body = body.replace("readlink -f /opt/sli/current", "printf '%s' /accepted/test")
    body = body.replace("sli_preinstall --recovery-kind", "printf '%s' accepted")
    body = body.replace("/var/lib/sli/recovery/", str(tmp_path / "recovery") + "/")
    # The marker writer touches the host state root; package_install has its own
    # rooted tests. Here only record that preinst requests it for install/upgrade.
    marker_call = 'sli_preinstall --package-install "$1" test ;;'
    assert marker_call in body
    body = body.replace(marker_call, f'printf "%s\\n" "$1" >> {tmp_path / "marker-calls"} ;;')
    path.write_text(body)
    result = subprocess.run(["/bin/sh", str(path), action, old], capture_output=True, check=False)
    assert (result.returncode == 0) == (expected == 0)
    calls = (tmp_path / "marker-calls").read_text().split() if (tmp_path / "marker-calls").exists() else []
    assert calls == ([action] if action in {"install", "upgrade"} else [])


def test_upgrade_scripts_use_accepted_recovery_after_host_unpack():
    scripts = package.scripts('new', VERSION)
    for name in ('preinst', 'prerm'):
        assert 'accepted=$(readlink -f /opt/sli/current)' in scripts[name]
        assert '/var/lib/sli/recovery/${accepted##*/}/native_upgrade.py' in scripts[name]
        assert '/usr/lib/sli/native_upgrade.py' not in scripts[name]
    assert '/usr/lib/sli/native_upgrade.py dispatch configure-package new' in scripts['postinst']


@pytest.mark.skipif(os.name == 'nt', reason='Debian /bin/sh maintainer contract; Linux CI')
@pytest.mark.parametrize('action,old,target', [('upgrade', '2.0-1~deb13', '2.0-1~deb13'),
                                            ('upgrade', VERSION, None),
                                            ('failed-upgrade', '0.9-1~deb13', VERSION)])
def test_prerm_prepares_actual_target_including_old_beta_fallback(tmp_path, action, old, target):
    record = tmp_path / 'arguments.json'
    saved = tmp_path / 'recovery/test/native_upgrade.py'
    saved.parent.mkdir(parents=True)
    saved.write_text('import json, sys\nfrom pathlib import Path\n'
                     'assert sys.dont_write_bytecode\n'
                     f'Path({str(record)!r}).write_text(json.dumps(sys.argv[1:]))\n')
    body = package.scripts('new', VERSION)['prerm']
    # Cleanup is exercised separately against sealed trees; isolate shell
    # argument dispatch here without touching any installed administrative tree.
    source = body.split("<<'SLI_BYTECODE'\n", 1)[1].split('\nSLI_BYTECODE\n', 1)[0]
    body = body.replace(source, 'pass')
    body = body.replace('sli_preinstall --recovery-kind', "printf '%s' accepted")
    body = body.replace('readlink -f /opt/sli/current', "printf '%s' /accepted/test")
    body = body.replace('/var/lib/sli/recovery/', str(tmp_path / 'recovery') + '/')
    body = body.replace('/usr/bin/python3', sys.executable)
    script = tmp_path / 'prerm'
    script.write_text(body)
    result = subprocess.run(['/bin/sh', str(script), action, old], capture_output=True, check=False)
    assert result.returncode == 0
    if target is None:
        assert not record.exists()
    else:
        assert json.loads(record.read_text()) == ['dispatch', 'prepare-package', target]


@pytest.mark.parametrize("action", ["remove", "purge", "upgrade", "failed-upgrade", "abort-install", "abort-upgrade", "disappear"])
@pytest.mark.skipif(os.name == "nt", reason="Debian /bin/sh maintainer scripts; Linux CI")
def test_postrm_needs_no_payload_and_keeps_data(tmp_path, action):
    path = tmp_path / "postrm"
    body = package.scripts("test", VERSION)["postrm"]
    path.write_text(body)
    assert subprocess.run(["/bin/sh", str(path), action], capture_output=True, check=False).returncode == 0
    assert "/var/lib" not in body and "/etc/sli" not in body


@pytest.mark.parametrize('working', [False, True])
def test_package_scripts_reinstall_and_remove_without_adopting_data(tmp_path, working):
    shell = shutil.which('sh')
    if not shell:
        pytest.skip('POSIX shell is required for Debian maintainer scripts')
    state = tmp_path / 'var/lib/sli/state'
    state.mkdir(parents=True)
    receipt = {'schema_version': 1, 'release': 'test', 'status': 'configured' if working else 'failed',
               'first_start_pending': not working, 'site_sha256': '1' * 64}
    (state / 'package-install.json').write_text(json.dumps(receipt))
    if working:
        (state / 'installed.json').write_text('{}')
    data = tmp_path / 'srv/sli-db/pgdata/PG_VERSION'
    data.parent.mkdir(parents=True)
    data.write_bytes(b'18\n')
    conf = tmp_path / 'etc/postgresql/18/sli/postgresql.conf'
    conf.parent.mkdir(parents=True)
    conf.write_bytes(b'# synthetic configuration\n')
    record = tmp_path / 'commands'
    launcher = tmp_path / 'sli-native-install'
    launcher.write_text(f'printf "%s\\n" "$*" >> {shlex.quote(record.as_posix())}\n', newline='\n')
    scripts = package.scripts('test', VERSION)

    def run(body, *args):
        python = shlex.quote(Path(sys.executable).as_posix())
        body = body.replace('/usr/bin/python3', python)
        body = body.replace('/usr/sbin/sli-native-install',
                            'sh ' + shlex.quote(launcher.as_posix()))
        body = body.replace('/var/lib/sli/state/reuse-package.json', (state / 'reuse-package.json').as_posix())
        body = body.replace('receipt=/var/lib/sli/state/installed.json',
                            'receipt=' + shlex.quote((state / 'installed.json').as_posix()))
        body = body.replace('current=/opt/sli/current',
                            'current=' + shlex.quote((tmp_path / 'opt/sli/current').as_posix()))
        # Use the real embedded state logic against an isolated Debian tree.
        # This filesystem belongs to the test runner, which need not be root.
        body = body.replace("if __name__ == '__main__':",
                            "trusted = lambda path: None\nos.geteuid = lambda: 0\nif __name__ == '__main__':")
        body = body.replace('recovery_required() else', f'recovery_required(root=Path({str(tmp_path)!r})) else')
        body = body.replace('package_install(sys.argv[2], sys.argv[3])',
                            f'package_install(sys.argv[2], sys.argv[3], root=Path({str(tmp_path)!r}))')
        body = body.replace('readlink -f /opt/sli/current', "printf '%s' /opt/sli/releases/test")
        body = body.replace('cleanup_recovery(accepted.name)',
                            f"cleanup_recovery(accepted.name, recovery=Path({str(tmp_path / 'recovery')!r}))")
        body = body.replace('logger -t sli-setup native_host_still_installed', ':')
        script = tmp_path / 'maintainer.sh'
        script.write_text(body, newline='\n')
        return subprocess.run([shell, script.as_posix(), *args], capture_output=True, text=True, check=False)

    for name, args in [('prerm', ('upgrade', '2.0-1~deb13')),
                       ('prerm', ('failed-upgrade', '0.9-1~deb13')),
                       ('preinst', ('upgrade', '0.9-1~deb13')), ('postinst', ('configure',))]:
        result = run(scripts[name], *args)
        assert result.returncode == int(working), result.stderr
    retain = package.retain_recovery_prerm()
    result = run(retain, 'remove')
    assert result.returncode == int(working), result.stderr
    if working:
        assert not record.exists()
        installed = state / 'installed.json'
        parked = installed.with_name('installed.json.sli-removing')
        installed.rename(parked)
        assert run(retain, 'remove').returncode == 0
        assert run(retain, 'deconfigure').returncode == 1
        installed.write_bytes(parked.read_bytes())
        assert run(retain, 'remove').returncode == 1
    else:
        assert run(scripts['prerm'], 'remove').returncode == 0
        assert run(scripts['preinst'], 'install').returncode == 0
        assert run(scripts['postinst'], 'configure').returncode == 0
        assert record.read_text().splitlines() == ['stage test', 'remove', 'stage test']
    assert json.loads((state / 'package-install.json').read_text()) == receipt
    assert data.read_bytes() == b'18\n' and conf.read_bytes() == b'# synthetic configuration\n'


@pytest.mark.parametrize('accepted', [False, True])
def test_remove_stops_services_without_release_runtime(tmp_path, monkeypatch, accepted):
    state = tmp_path / 'state'
    state.mkdir()
    receipt = state / 'package-install.json'
    status = 'configured' if accepted else 'failed'
    receipt.write_text(json.dumps({'schema_version': 1, 'release': 'old', 'status': status,
                                   'first_start_pending': not accepted, 'site_sha256': '1' * 64}))
    if accepted:
        (state / 'installed.json').write_text(json.dumps({'release': '/opt/sli/releases/old'}))
    monkeypatch.setattr(native_preinstall, 'trusted', lambda path: None)
    monkeypatch.setattr(install, 'STATE', state)
    monkeypatch.setattr(install, 'RECOVERY', tmp_path / 'recovery')
    monkeypatch.setattr(install, 'CURRENT', tmp_path / 'current')
    monkeypatch.setattr(install.os, 'geteuid', lambda: 0, raising=False)
    monkeypatch.setattr(install, 'inventory', lambda release: pytest.fail('removal needs no staged runtime'))
    calls = []
    monkeypatch.setattr(install, 'command', lambda argv, **kwargs: calls.append(argv))
    monkeypatch.setattr(install.subprocess, 'run', lambda argv, **kwargs: SimpleNamespace(
        stdout='sli-postgresql.service loaded active running\npostgresql.service loaded active running\n'))
    assert install.main(['remove']) == 0
    expected = ['/usr/sbin/sli-remove', '--stop-services'] if accepted else ['systemctl', 'stop', 'sli-postgresql.service']
    assert calls == [expected]
    assert json.loads(receipt.read_text())['status'] == status


@pytest.fixture
def lifecycle(tmp_path, monkeypatch):
    # This fake host creates a temporary tree without system ownership changes.
    monkeypatch.setattr(install, "ensure_directory", lambda path, mode=0o755, **options:
                        path.mkdir(mode=mode, parents=True, exist_ok=options.get("exist_ok", True)))
    if os.name == "nt":
        pytest.skip("POSIX atomic state/current symlink lifecycle; portable EXTCH fakes cover mode selection")
    state = tmp_path / "state"
    state.mkdir()
    root = tmp_path / "releases/test"
    helpers = root / "deploy/linux"
    helpers.mkdir(parents=True)
    for name in ("native_host.py", "native_runtime.py", "native_install.py", "native_backup.py", "native_upgrade.py",
                 "native_clickhouse_endpoint.py", "native_preinstall.py", "native_remove.py", "native_pins.json",
                 "backup_policy.py", "operation_wait.py"):
        (helpers / name).write_text("# accepted helper\n")
    manifest = {"schema_version": 1, "python": "/test/python", "roles": [], "plugins": {}, "migration_ledger": [],
                "postgres_version": "18.6", "clickhouse_version": host.clickhouse.endpoint("history", "native").version}
    calls = []
    for attr, value in {"STATE": state, "CURRENT": tmp_path / "current", "RECOVERY": tmp_path / "recovery",
                        "SITE": tmp_path / "site.toml"}.items():
        monkeypatch.setattr(install, attr, value)
    monkeypatch.setattr(install, "inventory", lambda release: (root, deepcopy(manifest), "digest"))
    monkeypatch.setattr(install.platform, "freedesktop_os_release", lambda: {"ID": "debian", "VERSION_ID": "13"})
    monkeypatch.setattr(install.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(install, "trusted", lambda path: path.read_bytes())
    monkeypatch.setattr(native_preinstall, "trusted", lambda path: None)
    monkeypatch.setattr(install, "command", lambda argv, **kwargs: calls.append(argv))
    monkeypatch.setattr(install, "wait_api", lambda config: calls.append("api-ready"))
    monkeypatch.setattr(install, "wait_health", lambda: calls.append("workers-healthy"))
    monkeypatch.setattr(native_backup, "configure", lambda: calls.append("backup-configured"))
    monkeypatch.setattr(native_upgrade, "save_recovery", lambda *args: calls.append("recovery-saved"))
    monkeypatch.setattr(host, "administrative_lock", nullcontext)
    monkeypatch.setattr(host, "validate_identity", lambda: calls.append("identity"))
    machine = SimpleNamespace(receipt=lambda: calls.append("mount"), configure=lambda: calls.append("host-configure"),
                              postgres_system_identifier=lambda: '123456789')
    monkeypatch.setattr(host, "Host", lambda: machine)
    monkeypatch.setattr(host, "MOUNT", str(tmp_path / "db"))
    monkeypatch.setattr(runtime, "no_transaction", lambda: calls.append("transactions"))
    monkeypatch.setattr(runtime, "wait_databases", lambda: calls.append("databases-ready"))
    monkeypatch.setattr(runtime, "configure", lambda config: calls.append("runtime-configure"))
    monkeypatch.setattr(runtime, "configuration", dict)
    monkeypatch.setattr(runtime, "selected", lambda config: ["api"])
    monkeypatch.setattr(runtime, "systemd", lambda service: {"ActiveState": "active", "MainPID": "42"})
    monkeypatch.setattr(runtime, "stop_writers", lambda: calls.append("stop-writers"))
    return SimpleNamespace(state=state, root=root, manifest=manifest, calls=calls, machine=machine)


def test_fresh_order_and_reinstall_preserves_registry_and_recovery(lifecycle):
    install.configure("test")
    calls = list(lifecycle.calls)
    assert calls.index("mount") < calls.index("host-configure") < calls.index("runtime-configure") < calls.index(["systemctl", "start", "sli-ready.service"])
    migrations = [c for c in calls if isinstance(c, list) and "migrate" in c]
    assert len(migrations) == 1
    assert calls.index("api-ready") < calls.index(["systemctl", "enable", "sli.target"])
    assert calls.index("workers-healthy") < calls.index(["systemctl", "enable", "sli.target"])
    assert calls.index("backup-configured") < calls.index("recovery-saved") < calls.index(["systemctl", "enable", "sli.target"])
    registry = (lifecycle.state / "installed.json").read_bytes()
    recovery = (install.RECOVERY / "test/native_install.py").read_bytes()
    lifecycle.calls.clear()
    install.configure("test")
    assert "host-configure" not in lifecycle.calls and "runtime-configure" not in lifecycle.calls
    assert lifecycle.calls.index("stop-writers") < lifecycle.calls.index(["systemctl", "stop", "sli-ready.service"])
    assert all(not isinstance(c, list) or "migrate" not in c for c in lifecycle.calls)
    assert (lifecycle.state / "installed.json").read_bytes() == registry
    assert (install.RECOVERY / "test/native_install.py").read_bytes() == recovery
    assert json.loads((lifecycle.state / "package-install.json").read_text())["status"] == "configured"


def test_fresh_migrates_postgres_without_warm_schema(lifecycle):
    install.configure("test")
    migration = next(call for call in lifecycle.calls if isinstance(call, list) and "migrate" in call)
    assert lifecycle.calls.index(migration) < lifecycle.calls.index("runtime-configure")
    assert not any(isinstance(call, list) and any("clickhouse" in value.lower() or "docker" in value.lower()
                                                for value in call) for call in lifecycle.calls)


def test_fresh_places_cold_tables_after_migrations_and_never_on_reinstall(lifecycle):
    install.SITE.write_text('cold_tablespace_root = "/mnt/cold"\n')
    lifecycle.machine.place_cold_tables = lambda action: lifecycle.calls.append("cold-" + action)
    install.configure("test")
    calls = lifecycle.calls
    migration = next(call for call in calls if isinstance(call, list) and "migrate" in call)
    assert calls.index(migration) < calls.index("cold-apply") < calls.index("runtime-configure")
    calls.clear()
    install.configure("test")
    assert "cold-apply" not in calls



def test_mount_failure_performs_no_writes(lifecycle):
    lifecycle.machine.receipt = lambda: (_ for _ in ()).throw(RuntimeError("mount"))
    with pytest.raises(RuntimeError, match="mount"):
        install.configure("test")
    assert not list(lifecycle.state.iterdir())
    assert "host-configure" not in lifecycle.calls


def test_wrong_os_refused_before_writes(lifecycle, monkeypatch):
    monkeypatch.setattr(install.platform, "freedesktop_os_release", lambda: {"ID": "ubuntu", "VERSION_ID": "24.04"})
    with pytest.raises(RuntimeError, match="native_debian13_amd64_required"):
        install.configure("test")
    assert not lifecycle.calls and not list(lifecycle.state.iterdir())


def test_failed_early_install_does_not_stop_units_that_do_not_exist(lifecycle):
    lifecycle.machine.configure = lambda: (_ for _ in ()).throw(RuntimeError("configure"))
    with pytest.raises(RuntimeError, match="configure"):
        install.configure("test")
    assert "stop-writers" not in lifecycle.calls
    assert json.loads((lifecycle.state / "package-install.json").read_text())["status"] == "failed"


def test_failed_worker_health_never_enables_autostart(lifecycle, monkeypatch):
    monkeypatch.setattr(install, "wait_health", lambda: (_ for _ in ()).throw(RuntimeError("unhealthy")))
    with pytest.raises(RuntimeError, match="unhealthy"):
        install.configure("test")
    assert ["systemctl", "enable", "sli.target"] not in lifecycle.calls
    assert ["systemctl", "disable", "sli.target"] in lifecycle.calls
    assert "stop-writers" in lifecycle.calls
    assert json.loads((lifecycle.state / "package-install.json").read_text())["status"] == "failed"


def test_recovery_failure_never_accepts_install_or_enables_autostart(lifecycle, monkeypatch):
    monkeypatch.setattr(native_upgrade, "save_recovery", lambda *args: (_ for _ in ()).throw(RuntimeError("recovery")))
    with pytest.raises(RuntimeError, match="recovery"):
        install.configure("test")
    assert ["systemctl", "enable", "sli.target"] not in lifecycle.calls
    assert "stop-writers" in lifecycle.calls
    assert json.loads((lifecycle.state / "package-install.json").read_text())["status"] == "failed"


def test_remove_unconfigured_package_is_idempotent(lifecycle, monkeypatch):
    monkeypatch.setattr(install.os, "geteuid", lambda: 0)
    assert install.main(["remove"]) == 0
    assert not lifecycle.calls


def test_fresh_refuses_foreign_data(lifecycle):
    (Path(host.MOUNT) / "pgdata").mkdir(parents=True)
    with pytest.raises(RuntimeError, match="native_install_foreign_data"):
        install.configure("test")
    assert "host-configure" not in lifecycle.calls


def test_failure_stops_writers_and_retry_requires_recovery(lifecycle, monkeypatch):
    def command(argv, **kwargs):
        if argv == ["systemctl", "start", "sli-ready.service"]:
            raise RuntimeError("readback")
        lifecycle.calls.append(argv)

    monkeypatch.setattr(install, "command", command)
    with pytest.raises(RuntimeError, match="readback"):
        install.configure("test")
    assert "stop-writers" in lifecycle.calls
    assert lifecycle.calls[-1] == ["systemctl", "disable", "sli.target"]
    assert json.loads((lifecycle.state / "package-install.json").read_text())["status"] == "failed"
    with pytest.raises(RuntimeError, match="native_install_interrupted_requires_recovery"):
        install.configure("test")


def test_reinstall_rejects_changed_manifest_without_mutation(lifecycle):
    install.configure("test")
    registry = lifecycle.state / "installed.json"
    value = json.loads(registry.read_text())
    value["manifest_sha256"] = "changed"
    registry.write_text(json.dumps(value))
    lifecycle.calls.clear()
    with pytest.raises(RuntimeError, match="native_upgrade_requires_coordinator"):
        install.configure("test")
    assert "host-configure" not in lifecycle.calls


def test_remove_stops_writers_without_touching_registry_recovery_or_link(lifecycle, monkeypatch):
    install.configure("test")
    assert lifecycle.calls.index("workers-healthy") < lifecycle.calls.index("backup-configured")
    assert ["systemctl", "enable", "--now", "sli-backup.timer"] in lifecycle.calls
    before = {p: p.read_bytes() for p in lifecycle.state.iterdir()}
    lifecycle.calls.clear()
    monkeypatch.setattr(install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(install, "inventory", lambda release: pytest.fail("removal needs no release runtime"))
    assert install.main(["remove"]) == 0
    assert lifecycle.calls == [["/usr/sbin/sli-remove", "--stop-services"]]
    assert install.CURRENT.resolve() == lifecycle.root
    assert {p: p.read_bytes() for p in lifecycle.state.iterdir()} == before
    assert (install.RECOVERY / "test/installed.json").is_file()
    assert (install.RECOVERY / "test/native_backup.py").is_file()


def test_migration_environment_uses_file_secrets_and_is_not_inherited(monkeypatch):
    monkeypatch.setenv("ADLOG_PG_DSN", "must-not-be-inherited")
    monkeypatch.delenv("SLI_CORE_JOB_WORKSTATIONS_RETENTION", raising=False)
    monkeypatch.delenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", raising=False)
    env = install.environment()
    assert "ADLOG_PG_DSN" not in env
    assert env["SLI_DEPLOYMENT_MODE"] == "native"
    assert env["SLI_CORE_JOB_WORKSTATIONS_RETENTION"] == "0"
    assert env["SLI_CORE_JOB_WORKSTATIONS_PROJECTION"] == "0"
    assert env["SLI_INSTALL_SEED_REPORT_DOMAIN"] == "0"
    assert all(k.endswith("_FILE") for k in env if "PASSWORD" in k)


def test_site_configuration_defaults_and_explicit_root_owned_file(lifecycle):
    assert install.site_configuration() == {"domain_fqdn": "example.invalid", "bind": "127.0.0.1"}
    install.SITE.write_text('domain_fqdn="lab.invalid"\nbind="127.0.0.2"\n')
    assert install.site_configuration() == {"domain_fqdn": "lab.invalid", "bind": "127.0.0.2"}


@pytest.mark.parametrize("body", ['password="hidden"', 'domain_fqdn="invalid"', 'bind="invalid"',
                                  'domain_fqdn="a.invalid;select"', 'mode="restore"'])
def test_invalid_site_file_refused_before_changes(lifecycle, body):
    install.SITE.write_text(body)
    with pytest.raises((RuntimeError, ValueError)):
        install.configure("test")
    assert not lifecycle.calls and not list(lifecycle.state.iterdir())


def test_reinstall_does_not_silently_change_site(lifecycle):
    install.configure("test")
    lifecycle.calls.clear()
    install.SITE.write_text('bind="127.0.0.2"\n')
    with pytest.raises(RuntimeError, match="native_site_reconfigure_requires_coordinator"):
        install.configure("test")
    assert "stop-writers" not in lifecycle.calls


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes and directory fsync; Linux CI")
def test_atomic_state_is_private_and_refuses_symlink(tmp_path):
    path = tmp_path / "state.json"
    install.atomic(path, {"status": "configured"})
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())["status"] == "configured"
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(RuntimeError, match="native_install_symlink"):
        install.atomic(link, {})


def test_inventory_rejects_runtime_tamper(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX immutable executable prefix; Linux CI")
    monkeypatch.setattr(install, "RELEASES", tmp_path / "releases")
    monkeypatch.setattr(install, "RUNTIMES", tmp_path / "runtimes")
    monkeypatch.setattr(install, "trusted", lambda path: path.read_bytes())
    root = install.RELEASES / "test"
    root.mkdir(parents=True)
    python = install.RUNTIMES / "test/bin/python3.14"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"accepted")
    python.chmod(0o755)
    manifest = {"schema_version": 1, "python": str(python), "python_sha256": hashlib.sha256(b"accepted").hexdigest(),
                "migration_ledger": [1], "roles": [1], "plugins": {"test": 1}}
    (root / "native-runtime.json").write_text(json.dumps(manifest))
    assert install.inventory("test")[1] == manifest
    python.write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="native_install_runtime_mismatch"):
        install.inventory("test")


def test_health_retries_startup_and_has_a_deadline(monkeypatch):
    attempts = []
    clock = [0]
    monkeypatch.setattr(install.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(install.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    def command(argv, **kwargs):
        assert argv == ["systemctl", "start", "sli-health.service"]
        attempts.append(argv)
        if len(attempts) < 3:
            raise RuntimeError("unhealthy")

    monkeypatch.setattr(install, "command", command)
    install.wait_health()
    assert len(attempts) == 3 and clock[0] == 60
    monkeypatch.setattr(install, "command", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("unhealthy")))
    with pytest.raises(RuntimeError, match="native_install_workers_unhealthy"):
        install.wait_health()
