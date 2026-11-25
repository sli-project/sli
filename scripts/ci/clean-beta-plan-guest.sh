#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
stage=provision
input=/mnt/beta-input
private_log=/run/beta-readme-install.log
probe_log=/run/beta-readme-auth.log
auth_file=/run/beta-browser-session.json
menu_log=/run/beta-browser-evidence.log
candidate=6a454ca4abc8c6960eb5823748afd4848f3faddf
operator=debian

for _ in {1..10}; do
    [[ -c /dev/virtio-ports/beta.readme.evidence ]] && break
    sleep 1
done
if [[ -c /dev/virtio-ports/beta.readme.evidence ]]; then
    exec 3>/dev/virtio-ports/beta.readme.evidence
else
    exec 3>/dev/ttyS0
fi

evidence() { printf 'BETA_README_EVIDENCE %s\n' "$*" >&3; }
finish() {
    local status=$?
    if ((status)); then
        for unit in sli-postgresql.service sli-bootstrap-pg.service sli-ready.service sli-dotnet-api.service; do
            while read -r info; do
                if [[ $info =~ ^(LoadState|ActiveState|Result|ExecMainStatus)=[A-Za-z0-9_-]+$ ]]; then
                    evidence "unit=$unit $info"
                fi
            done < <(systemctl show "$unit" --property=LoadState,ActiveState,Result,ExecMainStatus)
        done
        journalctl -b -t sli-setup -o cat --no-pager |
            grep -oE '\bnative_[a-z0-9_]+\b' | sort -u |
            while read -r tag; do evidence "installer_code=$tag"; done || true
        if [[ -f $probe_log ]]; then
            grep -E '^BETA_README_EVIDENCE (probe_phase|probe_status)=[A-Za-z0-9_-]+$' "$probe_log" >&3 || true
        fi
    fi
    if [[ -n ${results:-} && -d $results && -c /dev/virtio-ports/beta.readme.menu ]]; then
        if tar -czf /run/beta-menu-screens.tar.gz -C "$results" .; then
            cat /run/beta-menu-screens.tar.gz >/dev/virtio-ports/beta.readme.menu || true
        fi
    fi
    if [[ -f $auth_file ]]; then unlink "$auth_file"; fi
    evidence "status=$status stage=$stage"
    sync
    systemctl poweroff --no-block
}
trap finish EXIT

[[ $(systemd-detect-virt) == qemu || $(systemd-detect-virt) == kvm ]]
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 && $(uname -m) == x86_64 ]]
[[ $(getconf _NPROCESSORS_ONLN) == 4 ]]
ram_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
(( ram_kib >= 8050000 && ram_kib <= 8388608 ))
[[ $(blockdev --getsize64 /dev/vda) == 42949672960 ]]
[[ $(findmnt -n -o FSTYPE /) == ext4 ]]
[[ ! -e /etc/sli && ! -e /var/lib/sli && ! -e /srv/sli-db ]]
! dpkg-query -W -f='${db:Status-Status}\n' sli-host 2>/dev/null | grep -Fxq installed
evidence "debian=$VERSION_ID vcpus=4 ram_kib=$ram_kib disk_bytes=42949672960 root_fs=ext4"

# The preconfigured runner transports only signed Debian APT reads.
mkdir -p /run/preconfigured-apt
find /etc/apt/sources.list.d -maxdepth 1 -type f \( -name '*.list' -o -name '*.sources' \) \
    -exec mv -t /run/preconfigured-apt -- {} +
cat >/etc/apt/sources.list <<'APT'
deb http://10.0.2.100:3142/debian trixie main
deb http://10.0.2.100:3142/debian trixie-updates main
deb http://10.0.2.100:3142/debian-security trixie-security main
APT
printf 'Acquire::Retries "2";\nAcquire::http::Timeout "30";\n' >/etc/apt/apt.conf.d/99-sli-guest-timeouts

[[ $(runuser -u "$operator" -- sudo -n id -u) == 0 ]]
download="/home/$operator/beta-download"
install -d -o "$operator" -g "$operator" -m 0750 "$download"
for file in sli-debian-beta-kit.tar.gz SHA256SUMS; do
    install -o "$operator" -g "$operator" -m 0644 "$input/$file" "$download/$file"
done

stage=readme_install
cd "$download"
started=$(date +%s)
evidence "install_started=$started route=readme_actions_artifact"
runuser -u "$operator" -- sudo ss -ltn 'sport = :5432' >"$private_log" 2>&1
[[ $(wc -l <"$private_log") == 1 ]]
evidence 'command_1=readme_port_check'
runuser -u "$operator" -- bash -c 'sha256sum --check --strict SHA256SUMS && tar -xzf sli-debian-beta-kit.tar.gz' >>"$private_log" 2>&1
evidence 'command_2=readme_checksum_and_unpack'
runuser -u "$operator" -- bash sli-debian-beta-kit/install-beta-kit >>"$private_log" 2>&1
finished=$(date +%s)
evidence "command_3=readme_installer install_finished=$finished elapsed_seconds=$((finished - started)) manual_commands=3 manual_file_edits=0"
if (( finished - started <= 1800 )); then evidence 'install_within_30m=yes'; else evidence 'install_within_30m=no'; fi
evidence "post_install_root_free_bytes=$(df --output=avail -B1 / | tail -1 | tr -d ' ')"
systemctl is-active --quiet sli-dotnet-api.service

stage=clean_database
quiet=$(runuser -u postgres -- psql -XqAtw -h /var/run/postgresql -d sli -v ON_ERROR_STOP=1 -c \
    "SELECT concat_ws(',', (SELECT count(*) FROM public.sli_agents),(SELECT count(*) FROM public.sli_agent_receipts),(SELECT count(*) FROM public.event_hot),(SELECT count(*) FROM public.findings),(SELECT max(version) FROM public.schema_migrations))")
[[ $quiet =~ ^[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+$ ]]
evidence "agents_receipts_hot_events_findings_schema=$quiet"
[[ $quiet == 0,0,0,0,415 ]]

stage=first_login
python3 -I -B - "$candidate" "$private_log" "$input/install-guide.md" "$auth_file" >"$probe_log" 2>&1 <<'PY'
import hashlib
import http.client
import json
import re
import secrets
import ssl
import sys
import time
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

def mark(phase, status=None):
    print(f"BETA_README_EVIDENCE probe_phase={phase}", flush=True)
    if status is not None:
        print(f"BETA_README_EVIDENCE probe_status={status}", flush=True)

candidate, install_log, guide, auth_file = sys.argv[1:]
mark("installed_provenance")
release_root = Path("/opt/sli/current")
manifest = json.loads((release_root / "native-package.json").read_text())
inventory = json.loads((release_root / "native-runtime.json").read_text())
assert manifest["release"] == "beta1-" + candidate[:12]
assert inventory["provenance"]["source_commit"] == candidate
print(f"BETA_README_EVIDENCE installed_release={manifest['release']} installed_commit={candidate}", flush=True)

mark("runtime_https")
url = urlsplit(json.loads(Path("/etc/sli/runtime.json").read_text())["health_url"])
assert url.scheme == "https" and url.hostname
origin = "https://" + url.netloc
mark("documented_ca_fingerprint")
ca = Path("/var/lib/sli/tls-ca.crt")
observed = hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text())).hexdigest().upper()
fingerprints = re.findall(r"CA SHA-256 fingerprint:\s*((?:[0-9A-F]{2}:){31}[0-9A-F]{2})", Path(install_log).read_text())
assert {item.replace(":", "") for item in fingerprints} == {observed}
context = ssl.create_default_context(cafile=str(ca))

cookie = None
cookie_value = None

def call(path, name, *, method="GET", payload=None, update_session=False):
    global cookie, cookie_value
    headers = {"Origin": origin, "Accept": "application/json, text/html"}
    if cookie:
        headers["Cookie"] = cookie
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode()
    connection = http.client.HTTPSConnection(url.hostname, url.port, context=context, timeout=30)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        mark(name, response.status)
        if update_session:
            value = SimpleCookie()
            value.load(response.getheader("Set-Cookie") or "")
            selected = value["adlog_session"]
            assert selected.value and selected["secure"] and selected["httponly"]
            cookie = "adlog_session=" + selected.coded_value
            cookie_value = selected.value
        return response.status, response.getheader("Location") or "", response.getheader("Content-Type") or "", response.read(8 * 1024 * 1024)
    finally:
        connection.close()

status, _, _, ready = call(url.path, "readiness")
assert status == 200 and json.loads(ready)["ready"] is True and json.loads(ready)["code"] == "ready"
status, _, _, live = call(url.path.rsplit("/", 1)[0] + "/live", "runtime_identity")
assert status == 200 and json.loads(live)["runtime_identity"]["git_commit"] == candidate

mark("documented_initial_credentials")
initial, = re.findall(r"На чистой установке войдите с логином и паролем `([^`\r\n]+)`", Path(guide).read_text())
started_login = time.monotonic()
status, _, _, login = call("/api/auth/login", "initial_login", method="POST",
                           payload={"username": initial, "password": initial}, update_session=True)
assert status == 200 and json.loads(login)["password_change_required"] is True
status, location, _, _ = call("/app", "app_before_change")
assert status in {301, 302, 303, 307, 308} and urlsplit(location).path == "/login/change-password"
status, _, mime, _ = call(location, "change_password_screen")
assert status == 200 and mime.startswith("text/html")
restricted_cookie = cookie
password = secrets.token_urlsafe(30)
status, _, _, changed = call("/api/auth/change-initial-password", "change_initial_password", method="POST",
                             payload={"password": password, "repeat": password}, update_session=True)
assert status == 200 and json.loads(changed)["authenticated"] is True and cookie != restricted_cookie
status, _, mime, _ = call("/app", "app_after_change")
assert status == 200 and mime.startswith("text/html")
status, _, _, me = call("/api/auth/me", "authenticated_identity")
assert status == 200 and json.loads(me)["authenticated"] is True
Path(auth_file).write_text(json.dumps({"url": origin, "token": cookie_value, "commit": candidate}))
login_milliseconds = round((time.monotonic() - started_login) * 1000)
print(f"BETA_README_EVIDENCE first_login=passed ca_fingerprint_match=yes runtime_dotnet=yes login_milliseconds={login_milliseconds}", flush=True)

PY
grep -E '^BETA_README_EVIDENCE [A-Za-z0-9_= -]+$' "$probe_log" >&3

stage=browser_dependencies
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    nodejs chromium-headless-shell libnss3-tools fonts-dejavu-core >/run/beta-browser-apt.log 2>&1
db="/home/$operator/.pki/nssdb"
results="/home/$operator/menu-evidence"
install -d -m 0700 -o "$operator" -g "$operator" "/home/$operator/.pki" "$db" "$results"
runuser -u "$operator" -- certutil -N --empty-password -d "sql:$db"
runuser -u "$operator" -- certutil -A -d "sql:$db" -t "C,," -n sli-guest -i /var/lib/sli/tls-ca.crt
evidence "browser_ca=guest_nss"

driver="/home/$operator/menu-driver"
cp -a "$input/menu" "$driver"
chown -R "$operator:$operator" "$driver"

stage=msi_t10_probe
probe_status=0
python3 -I -B - "$candidate" "$results" >/run/beta-msi-t10.log 2>&1 <<'PY' || probe_status=$?
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
from urllib.parse import urlsplit

commit, result_dir = sys.argv[1:]
expected_msi = "f85c9b0df4faf37bd979b357925f780113ee0283dbc8690499c7039951fe2791"
expected_version = "26.0.166"
base_jobs = ("api", "post-collection", "semantic", "entity-state", "storage-lifecycle",
             "ad-snapshot-manifest-coordinator", "notification-delivery", "notification-setup")
excluded = ("what-where-when", "remote-access", "report-producer")
profiles = ("light", "heavy", "long")
legacy = [f"sli-{name}.service" for name in (*base_jobs, "what-where-when", "remote-access")]
legacy += [f"sli-executor@{profile}.service" for profile in profiles]
report = {"commit": commit}

def unit_state(unit):
    picked = "LoadState,ActiveState,SubState,MainPID,ExecStart,Result"
    cmd = ["systemctl", "show", "--property=" + picked, unit]
    raw = subprocess.run(cmd, capture_output=True, text=True, timeout=4).stdout
    fields = dict(part.split("=", 1) for part in raw.splitlines() if "=" in part)
    result = {key: fields.get(key) for key in ("LoadState", "ActiveState", "SubState", "Result")}
    pid = int(fields.get("MainPID") or 0)
    result["MainPID"] = pid
    expected = f"/opt/sli/dotnet/beta1-{commit[:12]}/Sli.Server"
    result["dotnet_exec_start"] = "path=" + expected in fields.get("ExecStart", "")
    if pid > 0:
        try: result["dotnet_process"] = os.readlink(f"/proc/{pid}/exe") == expected
        except FileNotFoundError: result["dotnet_process"] = False
    return result

def python_writers():
    matches = []
    names = set(base_jobs) | set(excluded) | {"executor", *("executor-" + p for p in profiles)}
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            if not Path(os.readlink(process / "exe")).name.startswith("python"):
                continue
            args = (process / "cmdline").read_bytes().decode("utf-8", errors="replace").strip("\0").split("\0")
        except (FileNotFoundError, ProcessLookupError):
            continue
        for index, arg in enumerate(args[:-1]):
            if arg == "deploy.linux.entrypoint" and args[index + 1] in names:
                matches.append(args[index + 1])
            if arg.endswith("/native_runtime.py") and args[index + 1] == "launch" and index + 2 < len(args):
                if args[index + 2] in names:
                    matches.append(args[index + 2])
    return sorted(matches)

def record_units(config):
    chosen = config.get("profiles")
    assert isinstance(chosen, list) and set(chosen) <= set(profiles)
    selected = (*base_jobs, *[f"executor-{profile}" for profile in profiles if profile in chosen])
    dotnet = {name: unit_state(f"sli-dotnet-{name}.service") for name in selected}
    old = {unit: unit_state(unit) for unit in legacy}
    outside = {name: unit_state(f"sli-dotnet-{name}.service") for name in excluded}
    writers = python_writers()
    old_stopped = all(row["ActiveState"] == "inactive" and row["MainPID"] == 0 for row in old.values())
    outside_stopped = all(row["ActiveState"] == "inactive" and row["MainPID"] == 0 for row in outside.values())
    active = [name for name, row in dotnet.items() if row["ActiveState"] == "active"
              and row["dotnet_exec_start"] and row.get("dotnet_process")]
    healthy_setup = ("notification-setup" in active
                     or dotnet["notification-setup"]["Result"] == "success"
                     and dotnet["notification-setup"]["dotnet_exec_start"]
                     and dotnet["notification-setup"]["ActiveState"] in ("active", "inactive"))
    passed = set(selected) - {"notification-setup"} <= set(active) and healthy_setup \
        and old_stopped and outside_stopped and not writers
    return {"passed": passed, "active_dotnet": active, "dotnet": dotnet,
            "legacy": old, "excluded_dotnet": outside, "legacy_python_writers": writers}

def probe_msi(config):
    url = urlsplit(config["health_url"])
    assert url.scheme == "https" and url.hostname
    ca = Path("/var/lib/sli/tls-ca.crt")
    context = ssl.create_default_context(cafile=str(ca))
    context.hostname_checks_common_name = False
    installed = Path("/opt/sli/current/agent/SliAgent.msi")
    with installed.open("rb") as file:
        server = hashlib.file_digest(file, "sha256").hexdigest()
    sidecar = json.loads(installed.with_suffix(".msi.json").read_text())
    connection = http.client.HTTPSConnection(url.hostname, url.port, context=context, timeout=12)
    try:
        connection.connect()
        san_verified = bool(connection.sock.getpeercert().get("subjectAltName"))
        connection.request("GET", "/api/v1/agent/installer/SliAgent.msi")
        response = connection.getresponse()
        status = response.status
        assert status == 200
        header = response.getheader("X-SLI-Package-SHA256")
        version = response.getheader("X-SLI-Package-Version")
        digest = hashlib.sha256()
        size = 0
        while data := response.read(1 << 20):
            size += len(data)
            assert size <= 100_000_000
            digest.update(data)
        downloaded = digest.hexdigest()
    finally:
        connection.close()
    manifest = sidecar.get("sha256")
    passed = san_verified and header == downloaded == manifest == server == expected_msi \
        and version == sidecar.get("product_version") == expected_version and size > 0
    return {"passed": passed, "http": status, "san_verified": san_verified, "version": version,
            "sha256_header": header, "sha256_download": downloaded, "sha256_server": server,
            "sha256_manifest": manifest, "bytes": size}

config = json.loads(Path("/etc/sli/runtime.json").read_text())
for key, probe in (("msi", probe_msi), ("t10", record_units)):
    try:
        report[key] = probe(config)
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError, http.client.HTTPException) as error:
        report[key] = {"passed": False, "error": type(error).__name__}
Path(result_dir, "msi-t10.json").write_text(json.dumps(report, sort_keys=True))
print("BETA_README_EVIDENCE msi_t10=" + json.dumps(report, separators=(",", ":")))
sys.exit(0 if report["msi"]["passed"] and report["t10"]["passed"] else 1)
PY
grep -aE '^BETA_README_EVIDENCE msi_t10=\{.*\}$' /run/beta-msi-t10.log >&3 || true

stage=agent_command_ui
ui_status=0
runuser -u "$operator" -- env NODE_EXTRA_CA_CERTS=/var/lib/sli/tls-ca.crt \
    timeout --kill-after=5s 60s node "$driver/installed-menu-walk.mjs" "$results" \
    <"$auth_file" >"$menu_log" 2>&1 || ui_status=$?
grep -aE '^BETA_README_EVIDENCE agent_command_ui=\{.*\}$' "$menu_log" >&3 || true
evidence "msi_t10_exit=$probe_status agent_command_ui_exit=$ui_status"
[[ $probe_status == 0 && $ui_status == 0 ]]
stage=msi_t10_verified
