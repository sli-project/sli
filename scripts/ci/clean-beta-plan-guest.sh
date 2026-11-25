#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
stage=provision
input=/mnt/beta-input
private_log=/run/beta-readme-install.log
probe_log=/run/beta-readme-auth.log
auth_file=/run/beta-browser-session.json
menu_log=/run/beta-browser-evidence.log
candidate=812533c4b118a43510de75bdac257ade326aae96
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

status, _, _, home = call("/api/v1/home/summary?contract=v4&period=24h&tz=UTC", "home_baseline")
if status == 200:
    summary = json.loads(home)
    problems = summary.get("problems")
    count = problems.get("open_count") if isinstance(problems, dict) else None
    if type(count) is int and count >= 0:
        print(f"BETA_README_EVIDENCE home_open_problems={count}", flush=True)
    else:
        print("BETA_README_EVIDENCE home_open_problems=unavailable", flush=True)
else:
    print("BETA_README_EVIDENCE home_open_problems=unavailable", flush=True)
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

walk_menu() {
    local phase=$1 code=0
    install -d -m 0700 -o "$operator" -g "$operator" "$results/$phase"
    runuser -u "$operator" -- env NODE_EXTRA_CA_CERTS=/var/lib/sli/tls-ca.crt SLI_MENU_PHASE="$phase" \
        node "$driver/installed-menu-walk.mjs" "$results/$phase" <"$auth_file" >"$menu_log" 2>&1 || code=$?
    grep -aE '^BETA_README_EVIDENCE (installed_chromium=[0-9.]+|menu_row=\{.*\}|menu_summary=\{.*\})$' "$menu_log" >&3 || true
    evidence "menu_phase=$phase browser_status=$code"
    [[ -s "$results/$phase/menu.json" ]] || return 2
    return "$code"
}

stage=vpn_prepare
prepare_status=0
python3 -I -B "$input/prepare-local-vpn-menu-guest.py" >/run/beta-vpn-prepare.log 2>&1 || prepare_status=$?
grep -Ex '^vpn_fixture_[a-z0-9_]+=[A-Za-z0-9_]+$' /run/beta-vpn-prepare.log |
    while read -r line; do evidence "$line"; done || true
evidence "vpn_prepare_status=$prepare_status"
[[ $prepare_status == 0 ]]

stage=vpn_systemd
systemctl daemon-reload
for unit in sli-dotnet-api.service sli-dotnet-post-collection.service; do
    systemctl cat "$unit" | grep -F 'LoadCredential=radius-agent-route:/etc/sli/radius-accounting/radius-agent-route' >/dev/null
done
systemctl cat sli-dotnet-post-collection.service |
    grep -F 'LoadCredential=radius-agent-dsn:/etc/sli/radius-accounting/radius-agent-dsn' >/dev/null
systemctl restart sli-dotnet-api.service sli-dotnet-post-collection.service
systemctl is-active --quiet sli-dotnet-api.service sli-dotnet-post-collection.service
evidence 'vpn_native_units_credentials=verified'

stage=vpn_readiness
python3 -I -B - "$candidate" <<'PY'
import http.client
import json
from pathlib import Path
import ssl
import sys
import time
from urllib.parse import urlsplit

url = urlsplit(json.loads(Path("/etc/sli/runtime.json").read_text())["health_url"])
context = ssl.create_default_context(cafile="/var/lib/sli/tls-ca.crt")
for _ in range(30):
    connection = http.client.HTTPSConnection(url.hostname, url.port, context=context, timeout=3)
    try:
        connection.request("GET", "/api/health")
        response = connection.getresponse()
        if response.status == 200:
            body = json.loads(response.read(1024 * 1024))
            if body.get("status") == "ok" and body.get("runtime_identity", {}).get("git_commit") == sys.argv[1]:
                sys.exit(0)
    except (OSError, http.client.HTTPException, ValueError):
        pass
    finally:
        connection.close()
    time.sleep(2)
sys.exit(1)
PY
evidence 'vpn_readiness_same_runtime=verified'

stage=menu_walk
menu_status=0
walk_menu full || menu_status=$?
[[ -s "$results/full/menu.json" ]]

stage=vpn_diagnostic
python3 -I -B - "$results/full/menu.json" <<'PY'
import json
import sys
from pathlib import Path
rows = json.loads(Path(sys.argv[1]).read_text())["rows"]
assert len(rows) == 1 and rows[0]["id"] == "vpn-connections" and rows[0]["vpnDiagnostics"]
PY
evidence 'vpn_diagnostic=recorded'
stage=browser_verified
