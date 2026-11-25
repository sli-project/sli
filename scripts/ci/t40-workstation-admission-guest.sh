#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

input=/mnt/p1-input
database_uuid=$1
backup_root=$2
initial_log=$3
initial_trace=$4
read -r commit tar_hash <"$input/candidate.pin"
[[ "$commit" == 4a6f14c815e07ff2a01346700d79507689d657e9 && "$tar_hash" =~ ^[0-9a-f]{64}$ ]]
grep -qxF 'ID=debian' /etc/os-release
grep -qxE 'VERSION_ID="?13"?' /etc/os-release
printf '%s  %s\n' "$tar_hash" "$input/candidate.tar.gz" | sha256sum --check --strict
release="beta1-${commit:0:12}"
candidate=$(mktemp -d /var/tmp/t40-kit.XXXXXXXX)
tar -xzf "$input/candidate.tar.gz" -C "$candidate"
printf 'P1_EVIDENCE t40_stage=stock_install git=%s tar_sha256=%s\n' "$commit" "$tar_hash"
(
    exec 9>"$initial_trace"
    BASH_XTRACEFD=9 bash -x "$candidate/sli-debian-beta-kit/install-beta-kit" \
        --server 127.0.0.1 --bind 127.0.0.1 --port 443 \
        --uuid "$database_uuid" --backup-root "$backup_root" --non-interactive
) >>"$initial_log" 2>&1
mountpoint -q /var/backups/sli
[[ "$backup_root" -ef /var/backups/sli ]]
for unit in sli-dotnet-api.service sli-dotnet-semantic.service sli-postgresql.service; do
    systemctl is-active --quiet "$unit"
done
[[ -z $(dpkg --audit) ]]
python3 -I -B - "$commit" "$release" "$candidate/sli-debian-beta-kit/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

commit, release, manifest = sys.argv[1:]
root = Path("/opt/sli/current").resolve(strict=True)
assert root == Path("/opt/sli/releases") / release
inventory = json.loads((root / "native-runtime.json").read_text())
package = json.loads((root / "native-package.json").read_text())
assert inventory["provenance"]["source_commit"] == commit
assert package["release"] == release
assert package["version"] == json.loads(Path(manifest).read_text())["version"]
site = json.loads(Path("/etc/sli/runtime.json").read_text())
assert site["health_url"] == "https://127.0.0.1/api/health/ready" or site["health_url"] == "https://127.0.0.1:443/api/health/ready"
print("P1_EVIDENCE t40_package=" + json.dumps(package, sort_keys=True))
PY
curl -q --proto '=https' --noproxy '*' --fail --silent --show-error --max-time 15 \
    --cacert /var/lib/sli/tls-ca.crt https://127.0.0.1/api/health/ready |
    python3 -I -B -c 'import json,sys; assert json.load(sys.stdin)["ready"] is True'
printf 'P1_EVIDENCE t40_readiness=ready\n'


systemctl is-active --quiet sli-dotnet-post-collection.service
python=$(python3 -I -B -c 'import json; print(json.load(open("/opt/sli/current/native-runtime.json"))["python"])')
test -x "$python"
if ! "$python" -I -B -c 'import cryptography' 2>/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt-get -y install --no-install-recommends python3-cryptography > /var/tmp/t40-fixture-dependencies.log
    python=/usr/bin/python3
fi
"$python" -B "$input/t40-workstation-admission.py" "$input"
