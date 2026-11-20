"""Shared native-product ClickHouse endpoints (stdlib only, no daemon effects).

Mode is frozen in the host preparation receipt. Docker uses a verified local
image config SHA256: unlike registry RepoDigests it survives docker save/load.
Administrative callers supply command adapters; application users never need
the Docker socket. SQL and backup formats do not depend on the implementation.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # Test runner CPython 3.10; Debian 13 has tomllib.
    import tomli as tomllib

INSTANCES = {"history": (8123, 9000, "sli_history", "history_password"),
             "warm": (8124, 9001, "default", "warm_password")}
SOCKET_SANDBOX = "InaccessiblePaths=-/run/docker.sock -/var/run/docker.sock\n"
PINS = Path(__file__).with_name("native_pins.json")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def pins():
    return json.loads(PINS.read_text(encoding="utf-8"))["clickhouse_modes"]


def select_mode(settings, cpuinfo):
    if "clickhouse_mode" in settings:
        mode = settings["clickhouse_mode"]
        require(isinstance(mode, str) and mode in {"native", "docker"}, "native_clickhouse_mode_invalid")
        return mode
    flags = re.findall(r"(?mi)^flags\s*:\s*([^\r\n]*)", cpuinfo)
    require(flags, "native_cpu_flags_unavailable")
    return "native" if all("avx2" in line.split() for line in flags) else "docker"


def require_same_mode(receipt, mode):
    require(receipt.get("clickhouse_mode", "native") == mode,
            "native_clickhouse_mode_change_requires_migration")


def trusted_text(path):
    for item in (path, *path.parents):
        info = item.lstat()
        require(not item.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022,
                "native_clickhouse_untrusted_configuration")
    require(path.is_file(), "native_clickhouse_untrusted_configuration")
    return path.read_text(encoding="utf-8")


def allowed_container_names(value):
    require(isinstance(value, list) and len(value) <= 8 and all(
        isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,62}", name)
        and not name.startswith(("sli-clickhouse-", "sli-drill-")) for name in value)
        and len(set(value)) == len(value), "native_site_docker_allowed_containers_invalid")
    return value


def backup_root_path(value):
    # Deliberately exclude systemd specifiers, escapes and whitespace. Canonical
    # POSIX spelling is required even when the contract tests run on Windows.
    require(isinstance(value, str) and re.fullmatch(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", value)
            and all(part not in {".", ".."} for part in value.split("/")[1:]),
            "native_site_backup_root_invalid")
    path = PurePosixPath(value)
    for reserved in map(PurePosixPath, ("/var/backups/sli", "/srv/sli-db", "/var/lib/sli-db", "/var/lib/sli", "/etc/sli", "/opt/sli")):
        require(not (path == reserved or path in reserved.parents or reserved in path.parents),
                "native_site_backup_root_invalid")
    return value


def notification_proxy(value):
    """Explicit credential-free HTTP CONNECT proxy, safe in a systemd setting."""
    code = "native_site_notification_proxy_invalid"
    require(isinstance(value, str) and len(value) <= 1024, code)
    if value == "":
        return value
    require(value.startswith("http://") and not any(ord(c) <= 32 or ord(c) >= 127 for c in value)
            and not any(c in value for c in "@?#\\%\""), code)
    try:
        url = urlsplit(value)
        require(url.hostname and not url.path and not url.query and not url.fragment
                and 1 <= (url.port or 0) <= 65535
                and re.fullmatch(r"[0-9]{1,5}", url.netloc.rsplit(":", 1)[-1]), code)
        host = url.hostname
        if url.netloc.startswith("[") or re.fullmatch(r"[0-9.]+", host):
            ipaddress.ip_address(host)
        else:
            require(len(host) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                    for part in host.split(".")), code)
    except ValueError:
        raise ValueError(code) from None
    return value


def cold_tablespace_root_path(value):
    code = "native_site_cold_tablespace_root_invalid"
    require(isinstance(value, str) and len(value) <= 512
            and re.fullmatch(r"/(?:mnt|srv)/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", value)
            and not (value == "/srv/sli-db" or value.startswith("/srv/sli-db/")), code)
    return value


def parse_site(text):
    """One bounded site contract for installer, host and runtime mode readers."""
    try:
        supplied = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise ValueError("native_site_toml_invalid") from None
    config = {"domain_fqdn": "example.invalid", "bind": "127.0.0.1"}
    require(set(supplied) <= set(config) | {"clickhouse_mode", "docker_allowed_containers", "agents", "backup_root",
                                          "https_port", "server_name", "owner_setup", "notification_proxy",
                                          "operation_stall_minutes", "cold_tablespace_root"},
            "native_site_setting_unsupported")
    if "operation_stall_minutes" in supplied:
        require(type(supplied["operation_stall_minutes"]) is int
                and 1 <= supplied["operation_stall_minutes"] <= 180,
                "native_site_operation_stall_invalid")
    if "https_port" in supplied:
        require(type(supplied["https_port"]) is int and 1 <= supplied["https_port"] <= 65535,
                "native_site_port_invalid")
    if "owner_setup" in supplied:
        require(type(supplied["owner_setup"]) is bool, "native_site_owner_setup_invalid")
    if "server_name" in supplied:
        server_name(supplied["server_name"])
    if "agents" in supplied:
        require(type(supplied["agents"]) is bool, "native_site_agents_invalid")
    if "backup_root" in supplied:
        backup_root_path(supplied["backup_root"])
    if "cold_tablespace_root" in supplied:
        cold_tablespace_root_path(supplied["cold_tablespace_root"])
    if "notification_proxy" in supplied:
        notification_proxy(supplied["notification_proxy"])
    if "clickhouse_mode" in supplied:
        select_mode(supplied, "")
    if "docker_allowed_containers" in supplied:
        allowed_container_names(supplied["docker_allowed_containers"])
    config.update(supplied)
    domain = config["domain_fqdn"]
    require(isinstance(domain, str) and 1 < len(domain.split(".")) and len(domain) <= 253
            and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in domain.split(".")), "native_site_domain_invalid")
    try:
        require(isinstance(config["bind"], str), "native_site_bind_invalid")
        address = ipaddress.ip_address(config["bind"])
    except ValueError:
        raise ValueError("native_site_bind_invalid") from None
    require(str(address) == config["bind"], "native_site_bind_invalid")
    # Omitted optional keys stay omitted, preserving legacy installation hashes.
    return config


def health_host(bind):
    """Wildcard addresses are listeners, never TLS probe destinations."""
    address = ipaddress.ip_address(bind)
    host = ('127.0.0.1' if address.version == 4 else '::1') if address.is_unspecified else str(address)
    return '[' + host + ']' if ':' in host else host


def server_name(value):
    require(isinstance(value, str) and 1 <= len(value) <= 253, "native_site_server_name_invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in value.split(".")), "native_site_server_name_invalid")
    else:
        require(not address.is_unspecified and not address.is_multicast and '%' not in value and str(address) == value,
                "native_site_server_name_invalid")
    return value


def site_configuration(root=Path("/")):
    site = root / "etc/sli/site.toml"
    return parse_site(trusted_text(site) if site.exists() or site.is_symlink() else "")


def database_directory_path(value):
    require(isinstance(value, str)
            and (re.fullmatch(r'/(?:var/lib|srv|mnt)/[A-Za-z0-9_-]+', value)
                 or re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)+sli-db', value))
            and not value.startswith(('/srv/sli-db/', '/var/lib/sli/', '/var/lib/postgresql/',
                                      '/var/lib/clickhouse/', '/var/backups/sli/', '/opt/sli/',
                                      '/home/', '/root/', '/run/', '/tmp/', '/var/tmp/'))
            and value not in {'/srv/sli-db', '/var/lib/sli', '/var/lib/postgresql', '/var/lib/clickhouse'},
            'native_database_directory_invalid')
    return value


def database_directory(root=Path('/')):
    """Validated alias used by copy admission and disposable DB sandboxes."""
    receipt = root / 'var/lib/sli/state/host-prepared.json'
    if not receipt.exists() and not receipt.is_symlink():
        return None
    saved = json.loads(trusted_text(receipt))
    if saved.get('storage_mode', 'uuid') != 'directory':
        return None
    return database_directory_path(saved.get('directory'))


def configured_mode(root=Path("/")):
    settings = site_configuration(root)
    receipt = root / "var/lib/sli/state/host-prepared.json"
    if receipt.exists() or receipt.is_symlink():
        saved = json.loads(trusted_text(receipt))
        mode = saved.get("clickhouse_mode", "native")
        require(isinstance(mode, str) and mode in {"native", "docker"}, "native_clickhouse_mode_invalid")
        if "clickhouse_mode" in settings:
            require_same_mode(saved, select_mode(settings, ""))
        return mode
    cpuinfo = "" if "clickhouse_mode" in settings else (root / "proc/cpuinfo").read_text()
    return select_mode(settings, cpuinfo)


class Endpoint:
    mode = "native"

    def __init__(self, name):
        require(name in INSTANCES, "native_clickhouse_instance_invalid")
        self.name = name
        self.http, self.tcp, self.user, self.secret = INSTANCES[name]
        self.unit = f"sli-clickhouse-{name}.service"
        self.os_user = f"sli-ch-{name}"
        self.config = f"/etc/sli/clickhouse/{name}"
        self.data = f"/srv/sli-db/clickhouse/{name}"
        self.logs = f"/var/log/sli-clickhouse/{name}"
        self.backup_host = f"/var/backups/sli/staging/{name}"
        self.backup_server = self.backup_host
        self.memory = (3 if name == "history" else 2) * 1024**3
        self.cpus = 2

    @property
    def version(self):
        return pins()[self.mode]["version"]

    def server_command(self, uid=None, gid=None, **paths):
        config = paths.get("config", self.config)
        return ["/usr/bin/clickhouse-server", "--config-file=" + config + "/config.xml"]

    def version_command(self):
        return ["/usr/bin/clickhouse-server", "--version"]

    def request(self, statement, password):
        from urllib.request import Request
        return Request(f"http://127.0.0.1:{self.http}/", data=statement.encode("utf-8"),
                       headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": password})

    def version_request(self, password):
        from urllib.request import Request
        return Request(f"http://127.0.0.1:{self.http}/?query=SELECT%20version()",
                       headers={"X-ClickHouse-User": self.user, "X-ClickHouse-Key": password})

    def backup_settings(self):
        return {f"SLI_{self.name.upper()}_CLICKHOUSE_BACKUP_ROOT": self.backup_host}

    def require_stopped(self, run):
        row = dict(line.split("=", 1) for line in run([
            "systemctl", "show", self.unit, "-p", "ActiveState", "-p", "MainPID"]).splitlines() if "=" in line)
        require(row.get("ActiveState") in {"inactive", "failed"} and row.get("MainPID") == "0",
                "native_clickhouse_unit_still_running")


class DockerEndpoint(Endpoint):
    mode = "docker"

    def __init__(self, name):
        super().__init__(name)
        self.backup_server = "/var/lib/clickhouse/backups"
        self.container = "sli-clickhouse-" + name

    @property
    def image_id(self):
        value = pins()["docker"]["image"]["id"]
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", value), "native_clickhouse_image_pin_invalid")
        return value

    def server_command(self, uid=None, gid=None, **paths):
        require(type(uid) is int and type(gid) is int and uid > 0 and gid > 0,
                "native_clickhouse_container_identity_invalid")
        config = paths.get("config", self.config)
        data = paths.get("data", self.data)
        logs = paths.get("logs", self.logs)
        backup = paths.get("backup", self.backup_host)
        credentials = paths.get("credentials", f"/run/sli-ch-{self.name}")
        argv = ["/usr/bin/docker", "run", "--name", paths.get("container", self.container),
                "--rm", "--pull", "never", "--restart", "no", "--network", "bridge",
                "--user", f"{uid}:{gid}", "--read-only", "--cap-drop=ALL",
                "--label", f"org.sli.clickhouse.instance={self.name}",
                "--security-opt=no-new-privileges", "--memory", str(paths.get("memory", self.memory)),
                "--cpus", str(self.cpus), "--pids-limit=512", "--ulimit=nofile=262144:262144",
                "--stop-timeout=120", "--log-driver=none", "--env=CLICKHOUSE_WATCHDOG_ENABLE=0",
                "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size=67108864,uid={uid},gid={gid},mode=1700",
                "--entrypoint=/usr/bin/clickhouse-server",
                "--publish", f"127.0.0.1:{paths.get('http', self.http)}:{paths.get('http', self.http)}",
                "--publish", f"127.0.0.1:{paths.get('tcp', self.tcp)}:{paths.get('tcp', self.tcp)}"]
        # Explicit data bind also covers the image's declared VOLUME: no anonymous volumes.
        mounts = {}
        for source, target, access in ((data, data, "rw"), (data, "/var/lib/clickhouse", "rw"),
                                       (logs, logs, "rw"), (config, config, "ro"),
                                       (credentials, credentials, "ro"),
                                       (backup, self.backup_server, "rw")):
            require(target not in mounts or mounts[target] == (source, access),
                    "native_clickhouse_mount_conflict")
            if target in mounts:
                continue
            mounts[target] = (source, access)
            argv += ["--volume", f"{source}:{target}:{access}"]
        return argv + [self.image_id, "--config-file=" + config + "/config.xml"]

    def version_command(self):
        # Never invoke the image entrypoint (which may chown/init); never pull.
        return ["/usr/bin/docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                "--user=65534:65534", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--entrypoint=/usr/bin/clickhouse-server", self.image_id, "--version"]

    def backup_settings(self):
        return super().backup_settings() | {
            f"SLI_{self.name.upper()}_CLICKHOUSE_BACKUP_SERVER_ROOT": self.backup_server}

    def require_stopped(self, run):
        super().require_stopped(run)
        require_stopped(run, self.container)


def endpoint(name, mode="native"):
    require(isinstance(mode, str) and mode in {"native", "docker"}, "native_clickhouse_mode_invalid")
    return (DockerEndpoint if mode == "docker" else Endpoint)(name)


def manifest_version(manifest, mode):
    expected = endpoint("history", mode).version
    versions = manifest.get("clickhouse_versions", {})
    require(isinstance(versions, dict), "native_clickhouse_manifest_invalid")
    declared = versions.get(mode, manifest.get("clickhouse_version"))
    require(declared == expected and manifest.get("clickhouse_mode", mode) == mode,
            "native_clickhouse_manifest_version_mismatch")
    return expected


def database_units():
    return ("sli-postgresql.service", *(endpoint(n).unit for n in INSTANCES))


def check_containers(run, *, drills=(), allowed_containers=None):
    """Keep CH/drill confinement; admit exact site-listed foreign names only."""
    foreign = set(allowed_container_names(allowed_containers) if allowed_containers is not None else [])
    identifiers = run(["/usr/bin/docker", "container", "ls", "--all", "--quiet", "--no-trunc"]).split()
    if not identifiers:
        return
    rows = json.loads(run(["/usr/bin/docker", "container", "inspect", *identifiers]))
    require(isinstance(rows, list) and len(rows) == len(identifiers), "native_docker_inventory_invalid")
    allowed = {"sli-clickhouse-" + n: n for n in INSTANCES} | dict(drills)
    for row in rows:
        name = row.get("Name", "").removeprefix("/")
        if name in foreign:
            project = (row.get("Config", {}).get("Labels") or {}).get("com.docker.compose.project", "")
            require(isinstance(project, str) and project != "sli" and not project.startswith("sli-")
                    and not any(m.get(key) in {"/run/docker.sock", "/var/run/docker.sock"}
                                for m in row.get("Mounts", []) for key in ("Source", "Destination")),
                    "native_docker_foreign_container")
            continue
        drill = re.fullmatch(r"sli-drill-[a-f0-9]{16}-(history|warm)", name)
        if name not in allowed and drill:
            # Disposable restore databases must be owned by a live, bounded
            # root-only systemd unit. A label alone never grants this exception.
            properties = dict(line.split("=", 1) for line in run([
                "systemctl", "show", name + ".service", "-p", "ActiveState", "-p", "User",
                "-p", "RuntimeMaxUSec"]).splitlines() if "=" in line)
            require(properties.get("ActiveState") in {"active", "activating"}
                    and properties.get("User") == "root"
                    and properties.get("RuntimeMaxUSec") in {"1h", "3600000000"},
                    "native_docker_unowned_drill")
            allowed[name] = drill[1]
        config = row.get("Config", {})
        labels = config.get("Labels") or {}
        host = row.get("HostConfig", {})
        require(name in allowed and labels.get("org.sli.clickhouse.instance") == allowed[name]
                and not any(k.startswith("com.docker.compose.") for k in labels)
                and row.get("Image") == endpoint(allowed.get(name, "history"), "docker").image_id
                and host.get("NetworkMode") == "bridge"
                and host.get("RestartPolicy", {}).get("Name") in {"no", ""}
                and host.get("ReadonlyRootfs") is True
                and not host.get("Privileged") and "ALL" in (host.get("CapDrop") or [])
                and "no-new-privileges" in (host.get("SecurityOpt") or [])
                and re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", config.get("User", ""))
                and all(binding.get("HostIp") == "127.0.0.1" for bindings in
                        (host.get("PortBindings") or {}).values() for binding in (bindings or []))
                and not any(m.get("Destination") in {"/run/docker.sock", "/var/run/docker.sock"}
                            for m in row.get("Mounts", [])), "native_docker_foreign_container")


def require_stopped(run, container):
    names = run(["/usr/bin/docker", "container", "ls", "--all", "--format", "{{.Names}}"]).splitlines()
    if container not in names:
        return
    rows = json.loads(run(["/usr/bin/docker", "container", "inspect", container]))
    require(len(rows) == 1 and rows[0].get("State", {}).get("Running") is False,
            "native_clickhouse_container_still_running")


def cleanup_container(run, container, instance):
    """Only stop/remove our exact pinned container, including a lost attach CLI."""
    names = run(["/usr/bin/docker", "container", "ls", "--all", "--format", "{{.Names}}"]).splitlines()
    if container not in names:
        return
    rows = json.loads(run(["/usr/bin/docker", "container", "inspect", container]))
    require(len(rows) == 1 and rows[0].get("Name") == "/" + container
            and rows[0].get("Image") == endpoint(instance, "docker").image_id
            and (rows[0].get("Config", {}).get("Labels") or {}).get("org.sli.clickhouse.instance") == instance,
            "native_docker_foreign_container")
    if rows[0].get("State", {}).get("Running"):
        run(["/usr/bin/docker", "stop", "--time=120", container])
    require_stopped(run, container)
    names = run(["/usr/bin/docker", "container", "ls", "--all", "--format", "{{.Names}}"]).splitlines()
    if container in names:  # --rm normally removes it; retain no stale name.
        run(["/usr/bin/docker", "container", "rm", container])
    require_stopped(run, container)


def load_image(path, run):
    identifier = verify_image_archive(path)
    run(["/usr/bin/docker", "load", "--input", str(path)])
    row = json.loads(run(["/usr/bin/docker", "image", "inspect", identifier]))
    require(len(row) == 1 and row[0].get("Id") == identifier
            and row[0].get("Os") == "linux" and row[0].get("Architecture") == "amd64",
            "native_clickhouse_loaded_image_mismatch")
    run(["/usr/bin/docker", "tag", identifier, pins()["docker"]["image"]["reference"]])


def file_sha256(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def verify_image_archive(path):
    """Bind the complete offline tar and its image ID, never extract or execute."""
    image = pins()["docker"]["image"]
    require(not path.is_symlink() and path.is_file() and file_sha256(path) == image["archive_sha256"],
            "native_clickhouse_image_archive_mismatch")
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        names = {m.name: m for m in members}
        require(len(names) == len(members) and all(
            not PurePosixPath(m.name).is_absolute() and ".." not in PurePosixPath(m.name).parts
            and (m.isfile() or m.isdir()) for m in members), "native_clickhouse_image_archive_invalid")
        def read(name):
            member = names.get(name)
            require(member is not None and member.isfile() and member.size <= 1024**2,
                    "native_clickhouse_image_metadata_invalid")
            return archive.extractfile(member).read()
        manifest = json.loads(read("manifest.json"))
        require(isinstance(manifest, list) and len(manifest) == 1, "native_clickhouse_image_count_invalid")
        record = manifest[0]
        require(image["archive_tag"] in record.get("RepoTags", []) and record.get("Layers")
                and all(n in names and names[n].isfile() for n in record["Layers"]),
                "native_clickhouse_image_layers_invalid")
        raw = read(record["Config"])
        config = json.loads(raw)
        require("sha256:" + hashlib.sha256(raw).hexdigest() == image["id"]
                and config.get("os") == "linux" and config.get("architecture") == "amd64",
                "native_clickhouse_image_id_mismatch")
    return image["id"]


def main(argv=None):
    import argparse
    import os
    import subprocess
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("load-image", "mode"))
    parser.add_argument("archive", type=Path, nargs="?")
    args = parser.parse_args(argv)
    def run(command):
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=600,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"})
        require(result.returncode == 0, "native_clickhouse_image_command_failed")
        return result.stdout
    try:
        if args.action == "mode":
            print(configured_mode())
            return 0
        require(os.geteuid() == 0, "native_root_required")
        require(args.archive is not None, "native_clickhouse_image_archive_required")
        trusted_text(PINS)
        for path in (args.archive, *args.archive.parents):
            info = path.lstat()
            require(not path.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022,
                    "native_clickhouse_image_untrusted")
        load_image(args.archive, run)
    except Exception:  # noqa: BLE001 -- never emit command/image metadata or private diagnostics.
        print("native_clickhouse_image_failed")
        return 1
    print("native_clickhouse_image_loaded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
