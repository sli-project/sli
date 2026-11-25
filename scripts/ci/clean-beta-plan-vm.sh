#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

[[ $# == 1 && ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == Linux && ${GITHUB_REPOSITORY:-} == sli-project/sli ]]
kit=$(realpath -e "$1")
commit=2323cfa48cf8c8d3e66705b1b09a7e20e140309f
evidence="$RUNNER_TEMP/beta-clean-readme-evidence"
vm="$RUNNER_TEMP/beta-clean-readme-vm"
mkdir -p "$evidence" "$vm/input"
[[ $BETA_SOURCE_ARTIFACT =~ ^[0-9]+$ && $BETA_SOURCE_DIGEST =~ ^sha256:[a-f0-9]{64}$ ]]
printf 'archived_commit=%s\nsource_workflow=45528985945\nsource_artifact=%s\nsource_zip_digest=%s\n' \
    "$commit" "$BETA_SOURCE_ARTIFACT" "$BETA_SOURCE_DIGEST" >"$evidence/pins.txt"
printf 'guest_transport_source=fe958b97829a4f4c72918173988e5e86c5a21a2b\nconfigured_vcpus=4\nconfigured_ram_mib=8192\nconfigured_system_disk_bytes=42949672960\n' >>"$evidence/pins.txt"

(
    cd "$kit"
    sha256sum sli-debian-beta-kit.tar.gz | cmp - SHA256SUMS
    PYTHONPATH="$GITHUB_WORKSPACE" python3 -B -c \
        'import sys; from pathlib import Path; from deploy.linux.build_beta_kit import verify_offline_kit; verify_offline_kit(Path(sys.argv[1]), sys.argv[2])' \
        sli-debian-beta-kit.tar.gz "$commit"
    cat SHA256SUMS >>"$evidence/pins.txt"
)
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

cp "$kit/sli-debian-beta-kit.tar.gz" "$kit/SHA256SUMS" input/
cp "$GITHUB_WORKSPACE/scripts/ci/clean-beta-plan-guest.sh" input/
guide="$GITHUB_WORKSPACE/docs/ru/install.md"
[[ $(git hash-object "$guide") == b03944dbf3ece0e94d35572e0c1f4136c707f28c ]]
cp "$guide" input/install-guide.md
checks="$GITHUB_WORKSPACE/frontend/tests/menu-walk/checks.mjs"
registry="$GITHUB_WORKSPACE/config/navigation_v3.json"
[[ $(git hash-object "$checks") == 6e6bb968e97615de12319165cb583f0c2f9ba679 ]]
[[ $(git hash-object "$registry") == 0ed2280e50535e48621874e7f2d9d32cc4bdf24e ]]
mkdir -p input/menu/node_modules
cp "$checks" "$registry" "$GITHUB_WORKSPACE/scripts/ci/installed-menu-walk.mjs" input/menu/
cp -a "$GITHUB_WORKSPACE/node_modules/playwright-core" input/menu/node_modules/
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
      bash /mnt/beta-input/clean-beta-plan-guest.sh
    else
      printf 'BETA_README_EVIDENCE status=1 stage=mount_input\n' >/dev/ttyS0
      systemctl poweroff --no-block
    fi
CLOUD
printf 'instance-id: clean-beta-readme-%s\nlocal-hostname: sli-clean-beta\n' "$GITHUB_RUN_ID" >meta-data
cloud-localds seed.img user-data meta-data
qemu-img create -q -f qcow2 -F qcow2 -b "$vm/$image" root.qcow2
qemu-img resize -q root.qcow2 40G

# SLIRP restricts all outbound connections. This endpoint forwards only Debian APT reads
# to a single HTTPS origin, including any redirects on that same origin.
python3 -B - <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
from shutil import copyfileobj
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

def allowed(url):
    parts = urlsplit(url)
    # APT escapes the literal plus and tilde in Debian package versions.
    if re.search(r"%(?!2[bB]|7[eE])", parts.path):
        return False
    path = unquote(parts.path)
    return (parts.scheme == "https" and parts.netloc == "deb.debian.org"
            and path.startswith(("/debian/", "/debian-security/"))
            and not parts.query and not parts.fragment
            and re.fullmatch(r"/[A-Za-z0-9._+~/-]+", path) is not None
            and all(segment not in {"", ".", ".."} for segment in path[1:].split("/")))

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

assert allowed("https://deb.debian.org/debian/pool/example_1%2bdeb13u1.deb")
assert allowed("https://deb.debian.org/debian-security/pool/example_1%7edeb13u1.deb")
assert not allowed("https://deb.debian.org/debian/%2e%2e/private")
assert not allowed("https://deb.debian.org/debian/../private")
assert not allowed("https://example.invalid/debian/pool/example.deb")

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
timeout --signal=TERM --kill-after=20s 50m qemu-system-x86_64 \
    "${accelerator[@]}" -m 8192 -smp 4 -display none -monitor none -serial file:guest-console.log \
    -device virtio-serial-pci -chardev file,id=proof,path=guest-evidence.log \
    -device virtserialport,chardev=proof,name=beta.readme.evidence \
    -chardev file,id=menu,path=menu-screens.tar.gz \
    -device virtserialport,chardev=menu,name=beta.readme.menu \
    -drive if=none,id=os,format=qcow2,file=root.qcow2 -device virtio-blk-pci,drive=os,bootindex=1 \
    -drive file=seed.img,if=virtio,format=raw,readonly=on \
    -drive file=input.ext4,if=virtio,format=raw,readonly=on \
    -nic 'user,model=virtio-net-pci,restrict=on,guestfwd=tcp:10.0.2.100:3142-cmd:/usr/bin/nc 127.0.0.1 3142' \
    -no-reboot
qemu_status=$?
set -e
touch guest-console.log guest-evidence.log
cat guest-console.log guest-evidence.log | tr -d '\r' |
    grep -a '^BETA_README_EVIDENCE ' >"$evidence/guest.log" || true
cat "$evidence/guest.log"
printf 'qemu_exit=%s\n' "$qemu_status" | tee -a "$evidence/pins.txt"
if [[ -s menu-screens.tar.gz ]]; then
    gzip -t menu-screens.tar.gz
    cp menu-screens.tar.gz "$evidence/"
fi
[[ $qemu_status == 0 && -s "$evidence/menu-screens.tar.gz" ]]
grep -Fxq 'BETA_README_EVIDENCE status=0 stage=browser_verified' "$evidence/guest.log"
