#!/usr/bin/env bash
# Build here and keep the completed kit inside this disposable CI job.
set -euo pipefail

[[ -f /.dockerenv && $EUID -eq 0 && ${GITHUB_ACTIONS:-} == true &&
   ${GITHUB_REPOSITORY:-} == sli-project/sli &&
   ${GITHUB_REF:-} == refs/heads/beta1/n03-full-kit-rehearsal-local &&
   ${GITHUB_SHA:-} =~ ^[a-f0-9]{40}$ ]]
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 && $(dpkg --print-architecture) == amd64 ]]
cd -- "$GITHUB_WORKSPACE"

mkdir -p .net-local
work=$(mktemp -d "$GITHUB_WORKSPACE/.net-local/n03-kit-rehearsal.XXXXXXXX")
[[ $work == "$GITHUB_WORKSPACE/.net-local/n03-kit-rehearsal."* ]]
trap 'rm -r -- "$work"' EXIT
mkdir "$work/cache" "$work/predecessor" "$work/sources.list.d" "$work/lists"
touch "$work/sources.list"
archive=sli-debian-beta-kit.tar.gz
previous_commit=1b5daf4e66640b7390105b4b5345332deca6f9ce
previous_sha=ae98209ccaa7d11ea5c322484d39076fd45c92ac00c9974b02ccbdfbfb56e4a6
(
    cd -- "$RUNNER_TEMP/n03-predecessor"
    [[ -f $archive && ! -L $archive && -f SHA256SUMS && ! -L SHA256SUMS ]]
    printf '%s  %s\n' "$previous_sha" "$archive" | cmp - SHA256SUMS
    sha256sum --strict -c SHA256SUMS
    install -m 0400 -- "$archive" "$work/$archive"
)
GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0="$(pwd -P)" \
    python3 -B -m deploy.linux.build_beta_kit \
    --commit "$previous_commit" --verify-offline-kit "$work/$archive"
tar --no-same-owner --no-same-permissions -xzf "$work/$archive" -C "$work/predecessor"
historical="$work/predecessor/sli-debian-beta-kit"
runtime="$historical/sli-runtime-cp3146-n03-20261026_3.14.6-1~deb13_amd64.deb"
printf '%s  %s\n' 46986d230f363f3af7e2fd4c4f25ee3da9ae3964982812f404f24b6d654a44d9 "$runtime" | sha256sum -c

python3 -B - "$work/cache" <<'PY'
import hashlib
from pathlib import Path, PurePosixPath
import sys
from urllib.request import urlopen

from deploy.linux import n03_kit_rehearsal as rehearsal

target = Path(sys.argv[1])
origin = "https://deb.debian.org/debian/"
rows = rehearsal.system_inputs(Path.cwd())["packages"]
if rows.keys() != rehearsal.SYSTEM_NAMES:
    raise SystemExit("Unexpected Debian package names")
for row in rows.values():
    path = PurePosixPath(row["Filename"])
    size = int(row["Size"])
    if not path.as_posix().startswith(("pool/main/o/openssl/", "pool/main/g/glibc/", "pool/main/z/zlib/")):
        raise SystemExit("Unexpected Debian pool path")
    with urlopen(origin + path.as_posix(), timeout=30) as response:
        if not response.geturl().startswith(origin):
            raise SystemExit("Unexpected Debian package redirect")
        body = response.read(size + 1)
    if len(body) != size or hashlib.sha256(body).hexdigest() != row["SHA256"]:
        raise SystemExit(f"Debian package SHA-256 mismatch: {path.name}")
    with (target / path.name).open("xb") as output:
        output.write(body)
PY
current=("$work"/cache/*.deb)
[[ ${#current[@]} -eq 6 && $(dpkg-query -W -f='${db:Status-Status}' base-files) == installed ]]
dpkg --compare-versions "$(dpkg-query -W -f='${Version}' base-files)" ge '13.3~'

# Install the complete predecessor OS closure with the six exact replacements.
# Preserve any unrelated system package already installed at a newer version.
install_packages=("${current[@]}")
for file in "$historical"/*.deb; do
    package=$(dpkg-deb -f "$file" Package)
    case "$package" in
        sli|sli-*|libssl3t64|openssl|openssl-provider-legacy|libc6|libc-bin|zlib1g) continue ;;
    esac
    want=$(dpkg-deb -f "$file" Version)
    arch=$(dpkg-deb -f "$file" Architecture)
    query=$package
    [[ $arch == all ]] || query+=:$arch
    if row=$(dpkg-query -W -f='${db:Status-Status} ${Version}' "$query" 2>/dev/null); then
        read -r status present <<< "$row"
        if [[ $status == installed ]] && dpkg --compare-versions "$present" gt "$want"; then
            continue
        fi
    fi
    install_packages+=("$file")
done
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
# APT acquires the verified local archives; its configured repositories are empty.
apt=(apt-get -y --no-remove --no-install-recommends -o APT::Get::allow-downgrades=false
     -o "Dir::Etc::sourcelist=$work/sources.list" -o "Dir::Etc::sourceparts=$work/sources.list.d"
     -o "Dir::State::lists=$work/lists")
chmod 0755 "$work"
DEBIAN_FRONTEND=noninteractive "${apt[@]}" -s install "${install_packages[@]}"
DEBIAN_FRONTEND=noninteractive "${apt[@]}" install "${install_packages[@]}"
[[ -z $(dpkg --audit) ]]
for file in "${current[@]}"; do
    package=$(dpkg-deb -f "$file" Package)
    want=$(dpkg-deb -f "$file" Version)
    [[ $(dpkg-query -W -f='${db:Status-Status} ${Version}' "$package") == "installed $want" ]]
done

msi="SliAgent-$GITHUB_SHA.msi"
for name in "$msi" "$msi.json"; do
    source="$RUNNER_TEMP/n03-candidate-agent/$name"
    [[ -f $source && ! -L $source ]]
    install -m 0644 -- "$source" "$work/cache/$name"
done
# Builder interpreter only. The legacy runtime is not installed using APT.
dpkg-deb --extract "$runtime" /
python=/opt/sli/runtimes/cp3146-n03-20261026/bin/python3.14
printf '%s  %s\n' 91bfcab33152d5afbaf5fd6bd50fb82a90f3b0ae7adfc06edc2ecce30dbc40f8 "$python" | sha256sum -c
useradd --create-home sli-builder
chown -R sli-builder:sli-builder "$GITHUB_WORKSPACE"
runuser -u sli-builder -- "$python" -B -m deploy.linux.build_beta_kit \
    --commit "$GITHUB_SHA" --require-agent-sdk --debs "$work/cache" \
    --rehearsal-previous-kit "$work/$archive" --output "$work/kit"
runuser -u sli-builder -- "$python" -B -m deploy.linux.build_beta_kit \
    --commit "$GITHUB_SHA" --verify-rehearsal --verify-offline-kit "$work/kit/$archive"
printf 'Verified the private full Debian kit for %s.\n' "$GITHUB_SHA"
