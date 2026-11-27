#!/usr/bin/env bash
set -euo pipefail
umask 077

[[ $# == 3 && ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == Linux && ${GITHUB_REPOSITORY:-} == sli-project/sli ]]
kit=$(realpath -e "$1")
commit=$2
results=$3
vm="$RUNNER_TEMP/beta-acceptance-vm"
scripts="$GITHUB_WORKSPACE/scripts/ci"
mkdir -p "$results" "$vm/input"

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
sha512sum --check --strict cloud-image.sha512

cp "$kit/sli-debian-beta-kit.tar.gz" "$kit/SHA256SUMS" "$scripts/beta_acceptance_guest.sh" "$scripts/beta_acceptance.py" input/
printf '%s\n' "$commit" >input/commit
input_bytes=$(du -sb input | cut -f1)
truncate -s "$(( input_bytes + 512 * 1024 * 1024 ))" input.ext4
mkfs.ext4 -q -F -m 0 -L BETAINPUT -d input input.ext4

cat >user-data <<'CLOUD'
#cloud-config
hostname: sli-clean-beta
manage_etc_hosts: true
ssh_pwauth: false
disable_root: true
runcmd:
  - |
    if mkdir -p /mnt/beta-input && mount -o ro,nosuid,nodev LABEL=BETAINPUT /mnt/beta-input; then
      bash /mnt/beta-input/beta_acceptance_guest.sh
    fi
    sync
    systemctl poweroff --no-block
CLOUD
printf 'instance-id: sli-beta-acceptance-%s-%s\nlocal-hostname: sli-clean-beta\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" >meta-data
cloud-localds seed.img user-data meta-data
qemu-img create -q -f qcow2 -F qcow2 -b "$vm/$image" root.qcow2
qemu-img resize -q root.qcow2 40G

# Restrict the guest to HTTPS-backed Debian APT reads, as in the README harness.
python3 -B - <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
from shutil import copyfileobj
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


def allowed(url):
    parts = urlsplit(url)
    if re.search(r"%(?!2[bB]|7[eE])", parts.path):
        return False
    path = unquote(parts.path)
    return (
        parts.scheme == "https"
        and parts.netloc == "deb.debian.org"
        and path.startswith(("/debian/", "/debian-security/"))
        and not parts.query and not parts.fragment
        and re.fullmatch(r"/[A-Za-z0-9._+~/-]+", path) is not None
        and all(segment not in {"", ".", ".."} for segment in path[1:].split("/"))
    )


class Redirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed(newurl):
            raise HTTPError(newurl, 403, "mirror redirect denied", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Mirror(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

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
    kill -0 "$mirror_pid"
    if curl -fsSI --max-time 5 http://127.0.0.1:3142/debian/dists/trixie/InRelease >/dev/null; then
        break
    fi
    sleep 1
done
curl -fsSI --max-time 10 http://127.0.0.1:3142/debian/dists/trixie/InRelease >/dev/null

timeout --signal=TERM --kill-after=20s 50m qemu-system-x86_64 \
    "${accelerator[@]}" -m 8192 -smp 4 -display none -monitor none -serial file:guest-console.log \
    -device virtio-serial-pci -chardev "file,id=proof,path=$results/guest.json" \
    -device virtserialport,chardev=proof,name=beta.acceptance \
    -drive if=none,id=os,format=qcow2,file=root.qcow2 -device virtio-blk-pci,drive=os,bootindex=1 \
    -drive file=seed.img,if=virtio,format=raw,readonly=on \
    -drive file=input.ext4,if=virtio,format=raw,readonly=on \
    -nic 'user,model=virtio-net-pci,restrict=on,net=192.0.2.0/24,guestfwd=tcp:192.0.2.100:3142-cmd:/usr/bin/nc 127.0.0.1 3142' \
    -no-reboot
[[ -s "$results/guest.json" ]] || { echo 'The Debian guest ended without acceptance results.' >&2; exit 1; }
