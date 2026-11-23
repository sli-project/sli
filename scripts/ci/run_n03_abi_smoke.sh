#!/usr/bin/env bash
# Run only with the original read-only package and no network in a disposable Docker root.
set -euo pipefail
export LC_ALL=C
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONHOME PYTHONPATH OPENSSL_CONF OPENSSL_MODULES

[[ -f /.dockerenv && ${SLI_NATIVE_ABI_FIXTURE:-} == n03-openssl-abi && $EUID -eq 0 ]] \
    || { echo 'A disposable Docker root and the n03 ABI fixture marker are required.' >&2; exit 1; }
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 && $(dpkg --print-architecture) == amd64 ]]
version=${1:?expected Debian libssl3t64 version}
case "$version" in
    '3.5.7-1~deb13u3')
        ssl_sha=9592038e92d1f41affcbb625334d0b6e788714c889104fa6d5b107cf9fd657f2
        crypto_sha=8ae56f0a9481280a68c19f59809cd242a07a91ad7142944d21a878221992244b ;;
    '3.5.9-1~deb13u1')
        ssl_sha=a890bcf10b78b752135a035809a10792330ff9b9c2ae3bb2239d7a08a5a6610b
        crypto_sha=a4e00ad0bb09d820ba5c41672567e965d4ca03153f7842751ef243355a569805 ;;
    *) exit 1 ;;
esac
{
    printf '%s  %s\n' "$ssl_sha" /usr/lib/x86_64-linux-gnu/libssl.so.3
    printf '%s  %s\n' "$crypto_sha" /usr/lib/x86_64-linux-gnu/libcrypto.so.3
} | sha256sum -c
for package in libssl3t64 openssl openssl-provider-legacy; do
    [[ $(dpkg-query -W -f='${Status}\t${Version}' "$package") == "install ok installed"$'\t'"$version" ]]
done
dependencies=$(dpkg-query -W -f='${binary:Package}\t${Version}\n' \
    ca-certificates libbz2-1.0 libc6 libffi8 libgcc-s1 libgdbm-compat4t64 libgdbm6t64 liblzma5 \
    libncursesw6 libreadline8t64 libsqlite3-0 libtinfo6 libuuid1 libzstd1 zlib1g | sort)
printf '%s\n' "$dependencies"
printf 'N03_NON_SSL_DEPS_SHA256 %s\n' "$(printf '%s\n' "$dependencies" | sha256sum | cut -d' ' -f1)"

runtime=/fixture/runtime.deb
prefix=/opt/sli/runtimes/cp3146-n03-20261026
python="$prefix/bin/python3.14"
[[ ! -e $prefix && ! -L $prefix && -f /fixture/abi-memory-bio.py ]]
printf '%s  %s\n' 46986d230f363f3af7e2fd4c4f25ee3da9ae3964982812f404f24b6d654a44d9 "$runtime" | sha256sum -c
[[ $(dpkg-deb --field "$runtime" Package) == sli-runtime-cp3146-n03-20261026 ]]
[[ $(dpkg-deb --field "$runtime" Version) == 3.14.6-1~deb13 ]]
ar p "$runtime" data.tar.gz | sha256sum | grep -Fx '6510d97a1a18f7c0f18e5182627fe8bf3d56b00d2f4cd4232a7fd43d1f0adad2  -'
dpkg-deb -x "$runtime" /
printf '%s  %s\n' 91bfcab33152d5afbaf5fd6bd50fb82a90f3b0ae7adfc06edc2ecce30dbc40f8 "$python" | sha256sum -c

work=$(mktemp -d /tmp/sli-n03-abi.XXXXXXXX)
trap 'rm -f -- "$work/cert.pem" "$work/key.pem" "$work/before" "$work/after"; rmdir -- "$work"' EXIT
inventory() {
    (
        cd "$prefix"
        find . -printf '%y %m %U %G %p %l\n'
        find . -type f -exec sha256sum {} +
    ) | sort
}
inventory > "$work/before"
/usr/bin/openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$work/key.pem" -out "$work/cert.pem" -days 1 -subj /CN=sli-abi.invalid \
    -addext subjectAltName=DNS:sli-abi.invalid
"$python" -I -B "$prefix/share/sli-runtime/smoke.py"
"$python" -I -B /fixture/abi-memory-bio.py "$work/cert.pem" "$work/key.pem" --openssl-release "${version%%-*}"
inventory > "$work/after"
cmp -- "$work/before" "$work/after"
printf 'N03_RUNTIME_TREE_SHA256 %s\n' "$(sha256sum < "$work/after" | cut -d' ' -f1)"
echo "PASS n03 payload and system OpenSSL $version"
