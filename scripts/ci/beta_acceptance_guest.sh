#!/usr/bin/env bash
set -euo pipefail
umask 077

input=/mnt/beta-input
install_log=/run/beta-acceptance-install.log
operator=debian

# Match the clean VM used by the previous README acceptance run.
case $(systemd-detect-virt) in qemu|kvm) ;; *) exit 1 ;; esac
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 && $(uname -m) == x86_64 ]]
[[ $(getconf _NPROCESSORS_ONLN) == 4 ]]
ram_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
(( ram_kib >= 8050000 && ram_kib <= 8388608 ))
[[ $(blockdev --getsize64 /dev/vda) == 42949672960 ]]
[[ $(findmnt -n -o FSTYPE /) == ext4 ]]
[[ ! -e /etc/sli && ! -e /var/lib/sli && ! -e /srv/sli-db ]]
if dpkg-query -W -f='${db:Status-Status}\n' sli-host 2>/dev/null | grep -Fxq installed; then
    exit 1
fi

# VM provisioning supplies configured APT sources through the read-only runner mirror.
mkdir -p /run/preconfigured-apt
find /etc/apt/sources.list.d -maxdepth 1 -type f \( -name '*.list' -o -name '*.sources' \) \
    -exec mv -t /run/preconfigured-apt -- {} +
cat >/etc/apt/sources.list <<'APT'
deb http://192.0.2.100:3142/debian trixie main
deb http://192.0.2.100:3142/debian trixie-updates main
deb http://192.0.2.100:3142/debian-security trixie-security main
APT
printf 'Acquire::Retries "2";\nAcquire::http::Timeout "30";\n' >/etc/apt/apt.conf.d/99-sli-guest-timeouts

[[ $(runuser -u "$operator" -- sudo -n id -u) == 0 ]]
download="/home/$operator/beta-download"
install -d -o "$operator" -g "$operator" -m 0750 "$download"
for file in sli-debian-beta-kit.tar.gz SHA256SUMS; do
    install -o "$operator" -g "$operator" -m 0644 "$input/$file" "$download/$file"
done
read -r commit <"$input/commit"
cd "$download"

# README.md links to docs/en/install.md. The runner has already staged the two
# public assets, so follow the guide's commands for an archive already on disk.
commands=0
phase=port_check
run_readme() {
    commands=1
    runuser -u "$operator" -- sudo ss -ltn 'sport = :5432' || return
    [[ $(wc -l <"$install_log") == 1 ]] || return
    phase=archive_check
    commands=2
    runuser -u "$operator" -- bash -c 'sha256sum --check --strict SHA256SUMS && tar -xzf sli-debian-beta-kit.tar.gz' || return
    phase=installer
    commands=3
    runuser -u "$operator" -- bash sli-debian-beta-kit/install-beta-kit || return
    phase=readiness
}

started=$(python3 -B -c 'import time; print(time.monotonic())')
run_readme >"$install_log" 2>&1 || true
python3 -I -B "$input/beta_acceptance.py" probe "$commit" "$install_log" "$phase" "$commands" "$started" \
    >/dev/virtio-ports/beta.acceptance
