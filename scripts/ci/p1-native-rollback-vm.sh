#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

if [[ $1 == guest ]]; then
    stage=provision_guest
    initial_log=/var/tmp/p1-predecessor.log
    scenario_log=/var/tmp/p1-rollback.log
    exec >/dev/ttyS0 2>&1

    finish_guest() {
        local code=$?
        trap - EXIT
        set +e
        if [[ -f $scenario_log ]]; then
            grep -E '^(Ready: beta1-[0-9a-f]{12}|\{"phase": "(upgraded|rolled-back)",.*\})$' "$scenario_log" |
                sed 's/^/P1_EVIDENCE /'
        fi
        if (( code != 0 )); then
            grep -hEo '(native|sli|postgres)_[a-z0-9_]+|AssertionError|PermissionError|FileNotFoundError' \
                "$initial_log" "$scenario_log" /var/tmp/sli-p1-acceptance.*/{upgrade,rollback}.log 2>/dev/null |
                sort -u | head -n 30 | sed 's/^/P1_EVIDENCE diagnostic=/'
            python3 -I -B - <<'PY'
import json
import re
from pathlib import Path

fields = ("status", "step", "failure_reason_code", "reason_code")
for directory in sorted(Path("/var/lib/sli/transactions").glob("*"))[-4:]:
    if not re.fullmatch(r"[a-f0-9]{32}", directory.name):
        continue
    for name in ("journal.json", "result.json"):
        try:
            payload = json.loads((directory / name).read_text())
        except (OSError, ValueError):
            continue
        value = {key: payload[key] for key in fields if isinstance(payload.get(key), str)
                 and re.fullmatch(r"[A-Za-z0-9_-]{1,100}", payload[key])}
        if value:
            print("P1_EVIDENCE transaction=" + json.dumps({"id": directory.name, "record": name, **value}))
PY
        fi
        printf 'P1_EVIDENCE status=%s stage=%s\n' "$code" "$stage"
        sync
        systemctl poweroff --no-block
    }
    trap finish_guest EXIT

    mkdir -p /run/p1-old-apt /srv/sli-db /var/backups/sli
    find /etc/apt/sources.list.d -maxdepth 1 -type f \( -name '*.list' -o -name '*.sources' \) \
        -exec mv -t /run/p1-old-apt -- {} +
    cat >/etc/apt/sources.list <<'APT'
deb http://10.0.2.100:3142/debian trixie main
deb http://10.0.2.100:3142/debian trixie-updates main
deb http://10.0.2.100:3142/debian-security trixie-security main
APT
    printf 'Acquire::Retries "2";\nAcquire::http::Timeout "30";\n' >/etc/apt/apt.conf.d/99-p1-timeouts
    apt-get update >"$initial_log" 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends \
        ca-certificates curl e2fsprogs sudo >>"$initial_log" 2>&1

    database=/dev/disk/by-id/virtio-p1-pg
    backup=/dev/disk/by-id/virtio-p1-backup
    [[ -b $database && -b $backup && $(readlink -f "$database") != "$(readlink -f "$backup")" ]]
    mkfs.ext4 -F -q "$database"
    mkfs.ext4 -F -q "$backup"
    database_uuid=$(blkid -s UUID -o value "$database")
    backup_uuid=$(blkid -s UUID -o value "$backup")
    [[ -n $database_uuid && -n $backup_uuid && $database_uuid != "$backup_uuid" ]]
    printf 'UUID=%s /srv/sli-db ext4 defaults 0 2\nUUID=%s /var/backups/sli ext4 defaults 0 2\n' \
        "$database_uuid" "$backup_uuid" >>/etc/fstab
    systemctl daemon-reload
    mount /srv/sli-db
    mount /var/backups/sli
    printf 'P1_EVIDENCE database_mount=%s backup_mount=%s\n' \
        "$(findmnt -n -o SOURCE /srv/sli-db)" "$(findmnt -n -o SOURCE /var/backups/sli)"

    input=/mnt/p1-input
    stage=install_410
    base=$(mktemp -d /var/tmp/p1-predecessor.XXXXXXXX)
    tar -xzf "$input/predecessor.tar.gz" -C "$base"
    bash "$base/sli-debian-beta-kit/install-beta-kit" --server 127.0.0.1 --bind 127.0.0.1 --port 443 \
        --uuid "$database_uuid" --backup-root /var/backups/sli --non-interactive >>"$initial_log" 2>&1
    printf 'P1_EVIDENCE predecessor_install=completed\n'
    install -o root -g root -m 0600 /proc/sys/kernel/random/boot_id /run/sli-p1-acceptance.boot-id

    stage=upgrade_and_rollback
    read -r commit checksum <"$input/candidate.pin"
    bash "$input/p1-native-410-411-rollback.sh" "$input/predecessor.tar.gz" \
        "$input/candidate.tar.gz" "$commit" "$checksum" >"$scenario_log" 2>&1
    stage=verified
    exit 0
fi

[[ $# == 4 && $1 == runner ]]
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == Linux && ${GITHUB_REPOSITORY:-} == sli-project/sli ]]
old_dir=$2
new_dir=$3
new_commit=$4
old_commit=0f6093b3a9afcecb28fcdd47c7ed50522e50a156
old_hash=38115eee4fe10dbf5a422d13ccbb644ff5c0837cb371cb397579c0fb56b0338e
evidence="$RUNNER_TEMP/p1-rollback-evidence"
vm="$RUNNER_TEMP/p1-rollback-vm"
mkdir -p "$evidence" "$vm/input"
printf 'base=%s\ncandidate=%s\n' "$old_commit" "$new_commit" >"$evidence/pins.txt"

verify_archive() (
    cd "$1"
    sha256sum sli-debian-beta-kit.tar.gz | cmp - SHA256SUMS
    PYTHONPATH="$GITHUB_WORKSPACE" python3 -B -c \
        'import sys; from pathlib import Path; from deploy.linux.build_beta_kit import verify_offline_kit; verify_offline_kit(Path(sys.argv[1]), sys.argv[2])' \
        sli-debian-beta-kit.tar.gz "$2"
)
verify_archive "$old_dir" "$old_commit"
verify_archive "$new_dir" "$new_commit"
printf '%s  %s\n' "$old_hash" "$old_dir/sli-debian-beta-kit.tar.gz" | sha256sum --check --strict
new_hash=$(sha256sum "$new_dir/sli-debian-beta-kit.tar.gz" | cut -d' ' -f1)
printf 'base_tar_sha256=%s\ncandidate_tar_sha256=%s\n' "$old_hash" "$new_hash" | tee -a "$evidence/pins.txt"

sudo apt-get update
sudo apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils acl netcat-openbsd
if [[ -c /dev/kvm && ! -w /dev/kvm ]]; then
    sudo setfacl -m "u:$(id -u):rw" /dev/kvm
fi
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    accelerator=(-accel kvm -cpu host)
else
    accelerator=(-accel tcg,thread=multi -cpu max)
fi
printf 'accelerator=%s\n' "${accelerator[1]}" >>"$evidence/pins.txt"

cd "$vm"
mirror=https://cloud.debian.org/images/cloud/trixie/latest
image=debian-13-genericcloud-amd64.qcow2
curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 "$mirror/SHA512SUMS" -o cloud-checksums
curl -fsSL --proto '=https' --proto-redir '=https' --retry 2 "$mirror/$image" -o "$image"
awk -v file="$image" '
    { name=$2; sub(/^\*/, "", name) }
    name == file { exact=$1; exact_count++ }
    name ~ /^debian-13-genericcloud-amd64-[a-zA-Z0-9.-]+\.qcow2$/ { tagged=$1; tagged_count++ }
    END {
        if (exact_count == 1) print exact "  " file
        else if (exact_count == 0 && tagged_count == 1) print tagged "  " file
        else exit 1
    }
' cloud-checksums >cloud-image.sha512
[[ $(wc -l <cloud-image.sha512) == 1 ]]
sha512sum --check --strict cloud-image.sha512
cat cloud-image.sha512 >>"$evidence/pins.txt"

cp --reflink=auto "$old_dir/sli-debian-beta-kit.tar.gz" input/predecessor.tar.gz
cp --reflink=auto "$new_dir/sli-debian-beta-kit.tar.gz" input/candidate.tar.gz
cp "$GITHUB_WORKSPACE/scripts/ci/p1-native-410-411-rollback.sh" input/
cp "$GITHUB_WORKSPACE/scripts/ci/p1-native-rollback-vm.sh" input/
printf '%s %s\n' "$new_commit" "$new_hash" >input/candidate.pin
input_bytes=$(du -sb input | cut -f1)
truncate -s "$(( input_bytes + 512 * 1024 * 1024 ))" input.ext4
mkfs.ext4 -q -F -m 0 -L P1INPUT -d input input.ext4

cat >user-data <<'CLOUD'
#cloud-config
hostname: sli-p1-acceptance
manage_etc_hosts: true
ssh_pwauth: false
disable_root: true
runcmd:
  - |
    if mkdir -p /mnt/p1-input && mount -o ro,nosuid,nodev LABEL=P1INPUT /mnt/p1-input; then
      bash /mnt/p1-input/p1-native-rollback-vm.sh guest
    else
      printf 'P1_EVIDENCE status=1 stage=mount_input\n' >/dev/ttyS0
      systemctl poweroff --no-block
    fi
CLOUD
printf 'instance-id: p1-native-rollback-%s\nlocal-hostname: sli-p1-acceptance\n' "$GITHUB_RUN_ID" >meta-data
cloud-localds seed.img user-data meta-data
qemu-img create -q -f qcow2 -F qcow2 -b "$vm/$image" root.qcow2
qemu-img resize -q root.qcow2 24G
qemu-img create -q -f qcow2 db.qcow2 32G
qemu-img create -q -f qcow2 backup.qcow2 32G

# SLIRP restricts all outbound connections. This endpoint forwards only Debian APT reads
# to a single HTTPS origin, including any redirects on that same origin.
python3 -B - <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from shutil import copyfileobj
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

def allowed(url):
    parts = urlsplit(url)
    return (parts.scheme == "https" and parts.netloc == "deb.debian.org"
            and parts.path.startswith(("/debian/", "/debian-security/"))
            and not parts.query and not parts.fragment
            and all(token not in parts.path for token in ("%", "\\", "/../", "//"))
            and not parts.path.endswith("/.."))

class Redirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed(newurl):
            raise HTTPError(newurl, 403, "mirror redirect denied", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

class Mirror(BaseHTTPRequestHandler):
    def do_GET(self):
        url = "https://deb.debian.org" + self.path
        if not self.path.startswith("/") or not allowed(url):
            self.send_error(403)
            return
        headers = {key: self.headers[key] for key in ("Range", "If-Modified-Since") if key in self.headers}
        try:
            response = build_opener(Redirect()).open(Request(url, headers=headers, method=self.command), timeout=45)
        except HTTPError as error:
            self.send_error(error.code)
            return
        except (URLError, TimeoutError):
            self.send_error(502)
            return
        with response:
            self.send_response(response.status)
            for key in ("Content-Length", "Content-Range", "Last-Modified", "Content-Type"):
                if key in response.headers:
                    self.send_header(key, response.headers[key])
            self.end_headers()
            if self.command == "GET":
                try:
                    copyfileobj(response, self.wfile)
                except (BrokenPipeError, ConnectionResetError):
                    pass

    do_HEAD = do_GET

ThreadingHTTPServer(("127.0.0.1", 3142), Mirror).serve_forever()
PY
mirror_pid=$!
trap 'kill "$mirror_pid" 2>/dev/null || true' EXIT
for _ in {1..20}; do
    if curl -fsS --max-time 5 -I http://127.0.0.1:3142/debian/dists/trixie/InRelease >/dev/null; then
        break
    fi
    sleep 1
done
curl -fsS --max-time 10 -I http://127.0.0.1:3142/debian/dists/trixie/InRelease >/dev/null

set +e
timeout --signal=TERM --kill-after=20s 70m qemu-system-x86_64 \
    "${accelerator[@]}" -m 6144 -smp 4 -display none -monitor none -serial file:guest-console.log \
    -drive if=none,id=os,format=qcow2,file=root.qcow2 -device virtio-blk-pci,drive=os,bootindex=1 \
    -drive file=seed.img,if=virtio,format=raw,readonly=on \
    -drive file=input.ext4,if=virtio,format=raw,readonly=on \
    -drive if=none,id=db,format=qcow2,file=db.qcow2 -device virtio-blk-pci,drive=db,serial=p1-pg \
    -drive if=none,id=backup,format=qcow2,file=backup.qcow2 -device virtio-blk-pci,drive=backup,serial=p1-backup \
    -nic 'user,model=virtio-net-pci,restrict=on,guestfwd=tcp:10.0.2.100:3142-cmd:/usr/bin/nc 127.0.0.1 3142' \
    -no-reboot
qemu_status=$?
set -e
if [[ -f guest-console.log ]]; then
    tr -d '\r' <guest-console.log | grep -a '^P1_EVIDENCE ' >"$evidence/guest.log" || true
    cat "$evidence/guest.log"
fi
printf 'qemu_exit=%s\n' "$qemu_status" | tee -a "$evidence/pins.txt"
[[ $qemu_status == 0 ]] && grep -Fxq 'P1_EVIDENCE status=0 stage=verified' "$evidence/guest.log"
