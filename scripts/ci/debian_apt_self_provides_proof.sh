#!/usr/bin/env bash
# Synthetic package-manager proof for a new, disposable Debian 13 container.
set -euo pipefail

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ -f /.dockerenv && ${SLI_SYNTHETIC_APT_ROOT:-} == sli-runtime-self-provides-proof ]] \
    || fail 'A disposable Docker root and the synthetic proof marker are required.'
[[ $EUID -eq 0 ]] || fail 'Run as root inside the disposable container.'
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 ]] || fail 'Debian 13 is required.'
export LC_ALL=C DEBIAN_FRONTEND=noninteractive

library=sli-fixture-library
runtime=sli-fixture-runtime
consumer=sli-fixture-old-consumer
hold=sli-fixture-hold
old=1.0-1
new=1.0-2
payload=/usr/share/sli-apt-proof/$runtime.txt

for package in "$library" "$runtime" "$consumer" "$hold"; do
    if dpkg-query -W "$package" >/dev/null 2>&1; then
        fail "Fixture package already present: $package. Use a new container."
    fi
done

work=$(mktemp -d)
chmod 0755 "$work"
make_deb() {
    local label=$1 name=$2 version=$3 depends=$4 provides=$5 content=$6
    local dir="$work/$label" archive
    archive="$dir/${name}_${version}_all.deb"
    mkdir -p "$dir/root/DEBIAN" "$dir/root/usr/share/sli-apt-proof"
    {
        printf 'Package: %s\nVersion: %s\nArchitecture: all\n' "$name" "$version"
        printf 'Maintainer: SLI synthetic fixture <fixture@example.invalid>\n'
        printf 'Description: Synthetic package-manager proof fixture\n'
        if [[ -n $depends ]]; then printf 'Depends: %s\n' "$depends"; fi
        if [[ -n $provides ]]; then printf 'Provides: %s\n' "$provides"; fi
    } > "$dir/root/DEBIAN/control"
    printf '%s\n' "$content" > "$dir/root/usr/share/sli-apt-proof/$name.txt"
    dpkg-deb --root-owner-group --build "$dir/root" "$archive" >/dev/null
    printf '%s\n' "$archive"
}

assert_installed() {
    local status
    status=$(dpkg-query -W -f='${db:Status-Status} ${Version}' "$1")
    [[ $status == "installed $2" ]] || fail "$1: expected installed $2, got $status"
}

assert_old_consumers() {
    local audit
    assert_installed "$consumer" "$old"
    assert_installed "$hold" "$old"
    [[ $(dpkg-query -W -f='${Depends}' "$consumer") == "$runtime (= $old)" ]] \
        || fail 'The old consumer no longer declares its exact runtime dependency.'
    [[ $(dpkg-query -W -f='${Depends}' "$hold") == "$consumer (= $old), $runtime (= $old)" ]] \
        || fail 'The old hold no longer declares its exact dependencies.'
    [[ $(sha256sum "$payload") == "$baseline_hash" ]] || fail 'Runtime payload changed.'
    audit=$(dpkg --audit)
    [[ -z $audit ]] || fail 'dpkg has incomplete or inconsistent packages.'
}

lib_old=$(make_deb library-old "$library" "$old" '' '' 'synthetic library v1')
lib_new=$(make_deb library-new "$library" "$new" '' '' 'synthetic library v2')
runtime_old=$(make_deb runtime-old "$runtime" "$old" "$library (= $old)" '' 'synthetic runtime payload')
runtime_bad=$(make_deb runtime-negative "$runtime" "$new" "$library (>= $old)" '' 'synthetic runtime payload')
runtime_new=$(make_deb runtime-compat "$runtime" "$new" "$library (>= $old)" "$runtime (= $old)" 'synthetic runtime payload')
consumer_deb=$(make_deb consumer "$consumer" "$old" "$runtime (= $old)" '' 'synthetic old consumer')
hold_deb=$(make_deb hold "$hold" "$old" "$consumer (= $old), $runtime (= $old)" '' 'synthetic old hold')

apt-get --version | sed -n '1p'
dpkg --version | sed -n '1p'
apt-get -y --no-remove install "$lib_old" "$runtime_old" "$consumer_deb" "$hold_deb"
assert_installed "$runtime" "$old"
assert_installed "$library" "$old"
baseline_hash=$(sha256sum "$payload")
assert_old_consumers

negative_status=0
negative_log=$(apt-get -s --no-remove install "$runtime_bad" 2>&1) || negative_status=$?
printf '%s\n' "$negative_log"
[[ $negative_status -eq 100 && ( $negative_log == *"$consumer"* || $negative_log == *"$runtime"* ) ]] \
    || fail "The negative control did not fail as expected (APT exit $negative_status)."
assert_installed "$runtime" "$old"
assert_installed "$library" "$old"
assert_old_consumers

apt-get -s --no-remove install "$runtime_new"
apt-get -y --no-remove install "$runtime_new"
assert_installed "$runtime" "$new"
assert_installed "$library" "$old"
[[ $(dpkg-query -W -f='${Provides}' "$runtime") == "$runtime (= $old)" ]] \
    || fail 'The installed runtime does not provide the original version.'
assert_old_consumers

apt-get -s --no-remove install "$lib_new"
apt-get -y --no-remove install "$lib_new"
assert_installed "$runtime" "$new"
assert_installed "$library" "$new"
assert_old_consumers
printf 'PASS: the old consumer and hold remain configured with unchanged runtime payload.\n'
