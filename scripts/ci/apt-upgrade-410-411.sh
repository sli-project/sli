#!/usr/bin/env bash
# Sourced after the pinned Debian guest script verified schema 410 and seeded its two receipts.
# Only this disposable guest receives the test APT source and signing key.
repo_root=/srv/sli-apt-acceptance
tools=/mnt/p1-input/apt-tools
[[ ! -e "$repo_root" && $(< /proc/1/comm) == systemd ]]
install -d -m 0755 "$repo_root"
key_home="$work/apt-key-home"
install -d -m 0700 "$key_home"
gpg --homedir "$key_home" --batch --no-options --pinentry-mode loopback --passphrase '' \
    --quick-generate-key 'SLI isolated APT acceptance <sli-apt@example.invalid>' ed25519 sign 1d \
    >"$work/key.log" 2>&1
fingerprint=$(gpg --homedir "$key_home" --batch --no-options --with-colons --list-secret-keys |
    awk -F: '$1=="fpr" && !seen++ {print $10}')
[[ "$fingerprint" =~ ^[A-F0-9]{40}$ ]]
gpg --homedir "$key_home" --batch --no-options --export-secret-keys "$fingerprint" >"$work/apt-signing.key"
[[ -s "$work/apt-signing.key" ]]
# The qualified kit replaces the original build input with a rewrapped
# runtime. Adapt only the test index pin to the delivery proven by the kit.
(
    cd "$tools"
    python3 -B - "$new_kit" "$work/apt-delivery-pins.json" <<'PY'
import json
from pathlib import Path
import sys

from deploy.linux.build_beta_kit import N03_RUNTIME_DELIVERY, input_pins, sha256, verify_runtime_delivery

kit, output = map(Path, sys.argv[1:])
pins = json.loads(Path("deploy/linux/native_pins.json").read_text())
manifest = json.loads((kit / "manifest.json").read_text())
assert pins["runtime_delivery"] == manifest["runtime_delivery"] == N03_RUNTIME_DELIVERY
verify_runtime_delivery(manifest)
_, prior_name, prior_packages = input_pins(pins)
delivery = manifest["runtime_delivery"]
pins["runtime_build"]["version"] = delivery["version"]
pins["runtime_artifact"].update(version=delivery["version"], sha256=delivery["sha256"])
_, actual_name, actual_packages = input_pins(pins)
assert actual_name != prior_name
assert sha256(kit / actual_name) == actual_packages[actual_name] == delivery["sha256"]
assert {k:v for k,v in prior_packages.items() if k != prior_name} == {
    k:v for k,v in actual_packages.items() if k != actual_name
}
output.write_text(json.dumps(pins, sort_keys=True) + "\n")
print("P1_EVIDENCE apt_delivery_pin=" + json.dumps(dict(package=actual_name, sha256=delivery["sha256"])))
PY
)
printf 'P1_EVIDENCE apt_local_size_cap=pages_limit=100000000 local_limit=104269128\n'
printf 'P1_EVIDENCE apt_index_command=%s\n' \
    'build_apt_repo.main() with local MAX_FILE_SIZE=104269128 --debs VERIFIED_411_KIT --pins VERIFIED_DELIVERY_PINS --output LOCAL_REPO --signing-key TEMPORARY_TEST_KEY'
(
    cd "$tools"
    python3 -B -c 'from deploy.linux import build_apt_repo as builder; builder.MAX_FILE_SIZE = 104269128; builder.main()' \
        --debs "$new_kit" \
        --pins "$work/apt-delivery-pins.json" --output "$repo_root/repo" \
        --signing-key "$work/apt-signing.key"
) >"$work/index.log" 2>&1 || {
    grep -E '^APT repository build failed:' "$work/index.log" |
        sed 's/^/P1_EVIDENCE apt_index_failure=/' || true
    exit 1
}
rm -f -- "$work/apt-signing.key"
gpgconf --homedir "$key_home" --kill gpg-agent
chmod -R a+rX "$repo_root/repo"

# Keep package resolution entirely in the signed local snapshot.
mv -- /etc/apt/sources.list "$work/debian-sources.list"
if find /etc/apt/sources.list.d -maxdepth 1 \( -name '*.list' -o -name '*.sources' \) -print -quit | grep -q .; then
    fail 'unexpected APT source in the disposable guest'
fi
(
    cd "$tools"
    python3 -B -m deploy.linux.native_apt bootstrap \
        --key "$repo_root/repo/sli-archive-keyring.gpg" --fingerprint "$fingerprint" \
        --uri "file://$repo_root/repo" --component main
)
index_digest=$(sha256sum "$repo_root/repo/dists/trixie/InRelease" | cut -d' ' -f1)
printf 'P1_EVIDENCE apt_index=local_signed fingerprint=%s inrelease_sha256=%s\n' "$fingerprint" "$index_digest"

candidate_version=$(python3 -I -B - "$new_kit/manifest.json" <<'PY'
import json
import sys
from pathlib import Path

print(json.loads(Path(sys.argv[1]).read_text())["version"])
PY
)
base_version=$(dpkg-query -W -f='${Version}' sli)
[[ "$base_version" != "$candidate_version" ]]
dpkg --compare-versions "$candidate_version" gt "$base_version"
printf 'P1_EVIDENCE apt_before=git=%s package=%s readiness=ready\n' "$old_commit" "$base_version"
printf 'P1_EVIDENCE apt_refresh_command=apt update\n'
if apt update >"$work/apt-update.log" 2>&1; then
    printf 'P1_EVIDENCE apt_update_exit=0\n'
else
    code=$?
    printf 'P1_EVIDENCE apt_update_exit=%s\n' "$code"
    grep -E '^(Err:|W:|E:)' "$work/apt-update.log" | tail -n 12 | sed 's/^/P1_EVIDENCE apt_diagnostic=/' || true
    exit "$code"
fi
policy=$(apt-cache policy sli)
printf '%s\n' "$policy" | grep -Fxq "  Installed: $base_version"
printf '%s\n' "$policy" | grep -Fxq "  Candidate: $candidate_version"
printf 'P1_EVIDENCE apt_selection=installed=%s candidate=%s\n' "$base_version" "$candidate_version"
apt --simulate upgrade >"$work/apt-plan.log" 2>&1
grep -Eq '^Inst sli \[' "$work/apt-plan.log"
if grep -Eq '^Remv ' "$work/apt-plan.log"; then fail 'unexpected package removal in APT plan'; fi
grep -E '^Inst ' "$work/apt-plan.log" | sed 's/^/P1_EVIDENCE apt_plan=/'

# Show the same capture-space estimate used by the stock preparation code.
# Root capacity covers the conservative unpacked size of all input packages.
(
    cd "$tools"
    python3 -B - "$new_kit" <<'PY'
import json
from pathlib import Path
import shutil
import subprocess
import sys

from deploy.linux import backup_policy, native_backup, native_host

debs = sorted(Path(sys.argv[1]).glob("*.deb"))
required_root = sum(p.stat().st_size + int(subprocess.check_output(
                    ["dpkg-deb", "-f", str(p), "Installed-Size"], text=True)) * 1024 for p in debs)
backup_root = native_backup.ROOT
estimate = native_host.Host().backup_space_estimate(backup_root)
requirements = backup_policy.space_requirements(backup_root, native_backup.DRILLS, estimate, include_drill=False)
assert set(requirements) == {backup_root}
root_free = shutil.disk_usage("/").free
db_free = shutil.disk_usage("/srv/sli-db").free
backup_free = shutil.disk_usage(backup_policy.existing_parent(backup_root)).free
capacity = dict(root_free=root_free, root_conservative_required=required_root, db_free=db_free,
                backup_free=backup_free, checkpoint_required=requirements[backup_root])
print("P1_EVIDENCE apt_space=" + json.dumps(capacity, sort_keys=True))
assert root_free >= required_root and backup_free >= requirements[backup_root]
assert db_free >= backup_policy.DATA_RESERVE
PY
)

# The only operation between these markers is the package manager. Its stock
# maintainer hooks prepare, verify, migrate and activate the exact candidate.
printf 'P1_EVIDENCE apt_upgrade_command=%s\n' \
    'DEBIAN_FRONTEND=noninteractive apt --assume-yes -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade'
if DEBIAN_FRONTEND=noninteractive apt --assume-yes \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade \
    >"$work/upgrade.log" 2>&1; then
    upgrade_exit=0
else
    upgrade_exit=$?
fi
printf 'P1_EVIDENCE apt_upgrade_exit=%s\n' "$upgrade_exit"
if (( upgrade_exit != 0 )); then
    grep -Ei '^(E:|dpkg: error|Errors were encountered|SLI:|native_upgrade_)|unable to|insufficient|not enough' "$work/upgrade.log" |
        tail -n 16 | sed 's/^/P1_EVIDENCE apt_diagnostic=/' || true
    exit "$upgrade_exit"
fi
[[ $(dpkg-query -W -f='${Version}' sli) == "$candidate_version" ]]
installed_ready "$new_commit" "$new_kit"
printf 'P1_EVIDENCE apt_after=git=%s package=%s readiness=ready\n' "$new_commit" "$candidate_version"
snapshot > "$work/upgraded.json"
