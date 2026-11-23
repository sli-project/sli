#!/usr/bin/env bash
# Real n03 package transactions with inert reverse dependencies in a disposable root.
set -euo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive

fail() { printf 'n03 APT fixture: %s\n' "$*" >&2; exit 1; }
[[ -f /.dockerenv && ${SLI_REAL_APT_FIXTURE:-} == pinned-n03-three-library-wrapper && $EUID -eq 0 ]] \
    || fail 'A disposable Docker root and the explicit fixture marker are required.'
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 && $(dpkg --print-architecture) == amd64 ]] \
    || fail 'Use the pinned Debian 13 amd64 root.'
mode=${1:-}
[[ $mode == upgrade || $mode == clean-current ]] || fail 'Expected upgrade or clean-current.'

runtime=sli-runtime-cp3146-n03-20261026
old='3.14.6-1~deb13'
wrapper='3.14.6-3~deb13'
floor='3.5.7-1~deb13u3'
current='3.5.9-1~deb13u1'
glibc_floor='2.41-12+deb13u4'
glibc_current='2.41-12+deb13u5'
zlib_floor='1:1.3.dfsg+really1.3.1-1+b1'
zlib_current='1:1.3.dfsg+really1.3.1-1+deb13u1'
consumer=sli-fixture-n03-old-release
hold=sli-fixture-n03-old-hold
fixture_version=1.0-1
old_dep="$runtime (= $old)"
hold_deps="$consumer (= $fixture_version), $old_dep"
prefix=/opt/sli/runtimes/cp3146-n03-20261026
inputs=/fixture/inputs
original="$inputs/runtime-old.deb"
previous="$inputs/runtime-ssl-only.deb"
compatible="$inputs/runtime-wrapper.deb"
common=("$inputs"/common/*.deb)
old_libs=("$inputs"/floor/*.deb)
new_libs=("$inputs"/current/*.deb)
work=$(mktemp -d /tmp/sli-real-n03-apt.XXXXXXXX)
chmod 0755 "$work"
touch "$work/sources.list"
mkdir "$work/sources.list.d" "$work/lists"
# APT must acquire the verified local archives to pass absolute paths to dpkg.
# The container has no network and its APT sources and indexes start empty.
apt=(apt-get -y --no-remove --no-install-recommends -o APT::Get::allow-downgrades=false
     -o "Dir::Etc::sourcelist=$work/sources.list" -o "Dir::Etc::sourceparts=$work/sources.list.d"
     -o "Dir::State::lists=$work/lists")

assert_installed() {
    local status
    status=$(dpkg-query -W -f='${db:Status-Status} ${Version}' "$1")
    [[ $status == "installed $2" ]] || fail "$1: expected installed $2, got $status"
}

assert_archive_packages() {
    local file
    for file; do
        assert_installed "$(dpkg-deb -f "$file" Package)" "$(dpkg-deb -f "$file" Version)"
    done
}

install_exact() {
    local file name wanted present
    for file; do
        [[ $file == /* && -f $file && ! -L $file ]] || fail 'An absolute local archive path is required.'
        name=$(dpkg-deb -f "$file" Package)
        wanted=$(dpkg-deb -f "$file" Version)
        present=$(dpkg-query -W -f='${Version}' "$name" 2>/dev/null || true)
        if [[ -n $present ]] && dpkg --compare-versions "$present" gt "$wanted"; then
            fail "$name would require a downgrade from $present to $wanted."
        fi
    done
    "${apt[@]}" -s install "$@"
    "${apt[@]}" install "$@"
    assert_archive_packages "$@"
}

expect_blocked() {
    local needle=$1 status=0 log
    shift
    log=$("${apt[@]}" -s install "$@" 2>&1) || status=$?
    printf '%s\n' "$log"
    [[ $status -eq 100 && $log == *"$needle"* ]] || fail "Expected an APT refusal involving $needle."
}

audit_packages() {
    local result
    result=$(dpkg --audit)
    [[ -z $result ]] || fail "$result"
    "${apt[@]}" check
}

inventory() {
    (
        cd "$1"
        find . -printf '%y %m %U %G %p %l\n'
        find . -type f -exec sha256sum {} +
    ) | sort
}

synthetic_package() {
    local name=$1 depends=$2 temp="$work/build-$1"
    mkdir -p "$temp/DEBIAN" "$temp/usr/share/sli-n03-apt-fixture"
    {
        printf 'Package: %s\nVersion: %s\nArchitecture: all\nDepends: %s\n' "$name" "$fixture_version" "$depends"
        printf 'Maintainer: SLI synthetic fixture <fixture@example.invalid>\n'
        printf 'Description: Inert reverse dependency for the real n03 APT fixture\n'
    } > "$temp/DEBIAN/control"
    printf '%s\n' "$name" > "$temp/usr/share/sli-n03-apt-fixture/$name"
    dpkg-deb --root-owner-group --build "$temp" "$work/$name.deb" >/dev/null
}

assert_consumers() {
    assert_installed "$consumer" "$fixture_version"
    assert_installed "$hold" "$fixture_version"
    [[ $(dpkg-query -W -f='${Depends}' "$consumer") == "$old_dep" ]]
    [[ $(dpkg-query -W -f='${Depends}' "$hold") == "$hold_deps" ]]
}

assert_wrapper() {
    assert_installed "$runtime" "$wrapper"
    [[ $(dpkg-query -W -f='${Provides}' "$runtime") == "$old_dep" ]]
    assert_archive_packages "${common[@]}" "${new_libs[@]}"
    assert_consumers
    compare_payload
    audit_packages
}

compare_payload() {
    printf '%s  %s\n' 91bfcab33152d5afbaf5fd6bd50fb82a90f3b0ae7adfc06edc2ecce30dbc40f8 "$prefix/bin/python3.14" \
        | sha256sum -c
    inventory "$prefix" > "$work/actual-tree"
    cmp -- "$work/reference-tree" "$work/actual-tree"
}

smoke() {
    local ssl=$1 cert_dir
    cert_dir=$(mktemp -d "$work/smoke.XXXXXXXX")
    (
        umask 077
        openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=sli-apt.invalid' \
            -addext 'subjectAltName=DNS:sli-apt.invalid' -keyout "$cert_dir/key.pem" -out "$cert_dir/cert.pem" 2>/dev/null
    )
    "$prefix/bin/python3.14" -I -B /fixture/smoke.py "$ssl" "$cert_dir/cert.pem" "$cert_dir/key.pem"
    rm -- "$cert_dir/key.pem" "$cert_dir/cert.pem"
}

[[ ${#common[@]} -eq 16 && ${#old_libs[@]} -eq 6 && ${#new_libs[@]} -eq 6 ]]
[[ ! -e $prefix && ! -L $prefix ]]
for package in "$runtime" "$consumer" "$hold"; do
    if dpkg-query -W "$package" >/dev/null 2>&1; then fail "Fixture package already present: $package"; fi
done
apt-get --version | sed -n '1p'
dpkg --version | sed -n '1p'
assert_installed libc6 "$glibc_floor"
assert_installed libc-bin "$glibc_floor"
assert_installed zlib1g "$zlib_floor"
base_files=$(dpkg-query -W -f='${Version}' base-files)
dpkg --compare-versions "$base_files" ge '13.3~' || fail "libc6 $glibc_current breaks base-files $base_files."
audit_packages
(cd "$inputs"; sha256sum --strict -c sha256sums.txt)
printf '%s  %s\n' 46986d230f363f3af7e2fd4c4f25ee3da9ae3964982812f404f24b6d654a44d9 "$original" | sha256sum -c
[[ $(dpkg-deb -f "$original" Package) == "$runtime" && $(dpkg-deb -f "$original" Version) == "$old" ]]
printf '%s  %s\n' c36ed9b1170fd83120144711d81e91f333f0e5a49975316bc1226ba794dacdd8 "$previous" | sha256sum -c
[[ $(dpkg-deb -f "$compatible" Package) == "$runtime" && $(dpkg-deb -f "$compatible" Version) == "$wrapper" ]]
[[ $(dpkg-deb -f "$compatible" Provides) == "$old_dep" ]]
old_dependencies=$(dpkg-deb -f "$original" Depends)
old_ssl="libssl3t64 (= $floor)"
old_glibc="libc6 (= $glibc_floor)"
old_zlib="zlib1g (= $zlib_floor)"
[[ $old_dependencies == *"$old_ssl"* && $old_dependencies == *"$old_glibc"* && $old_dependencies == *"$old_zlib"* ]]
expected=${old_dependencies/"$old_ssl"/"libssl3t64 (>= $floor)"}
expected=${expected/"$old_glibc"/"$old_glibc | libc6 (= $glibc_current)"}
expected=${expected/"$old_zlib"/"$old_zlib | zlib1g (= $zlib_current)"}
[[ $(dpkg-deb -f "$compatible" Depends) == "$expected" ]]
[[ $(dpkg-deb --fsys-tarfile "$original" | sha256sum) == "$(dpkg-deb --fsys-tarfile "$compatible" | sha256sum)" ]]

dpkg-deb -x "$original" "$work/reference"
inventory "$work/reference$prefix" > "$work/reference-tree"
synthetic_package "$consumer" "$old_dep"
synthetic_package "$hold" "$hold_deps"
consumer_deb="$work/$consumer.deb"
hold_deb="$work/$hold.deb"

if [[ $mode == upgrade ]]; then
    install_exact "${common[@]}" "${old_libs[@]}" "$original" "$consumer_deb" "$hold_deb"
    assert_consumers
    compare_payload
    audit_packages
    smoke "${floor%%-*}"
    expect_blocked "$runtime" "${new_libs[@]}"
    expect_blocked 'libc6' "$previous" "${new_libs[@]}"
    assert_installed "$runtime" "$old"
    assert_archive_packages "${old_libs[@]}"
    assert_consumers
    # glibc and the Essential libc-bin upgrade together. All archives remain local.
    install_exact "$compatible" "${new_libs[@]}"
else
    install_exact "${common[@]}" "${new_libs[@]}"
    expect_blocked 'libssl3t64' "$original"
    expect_blocked 'libc6' "$previous"
    [[ ! -e $prefix && ! -L $prefix ]]
    install_exact "$compatible"
    install_exact "$consumer_deb" "$hold_deb"
fi
assert_wrapper
smoke "${current%%-*}"

simulation=$("${apt[@]}" -s --reinstall install "$consumer_deb" "$hold_deb")
printf '%s\n' "$simulation"
grep -E "^Inst $consumer([[:space:]]|:)" <<< "$simulation"
grep -E "^Inst $hold([[:space:]]|:)" <<< "$simulation"
if grep -Eq "^(Remv|Purg) |^Inst ($runtime|libssl3t64|openssl|openssl-provider-legacy|libc6|libc-bin|zlib1g)([[:space:]]|:)" <<< "$simulation"; then
    fail 'Reinstalling the exact old reverse dependencies would change the runtime or tested libraries, or remove packages.'
fi
assert_wrapper
printf 'PASS real n03 APT %s, wrapper %s, OpenSSL %s, glibc %s, zlib %s, old dependents retained\n' \
    "$mode" "$wrapper" "$current" "$glibc_current" "$zlib_current"
