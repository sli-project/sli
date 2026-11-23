#!/usr/bin/env bash
# Synthetic mount-propagation proof for a disposable Debian 13 container.
set -euo pipefail
export LC_ALL=C

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

[[ -f /.dockerenv && ${SLI_SYNTHETIC_MOUNT_ROOT:-} == sli-native-private-mount-proof && $EUID -eq 0 ]] \
    || fail 'A disposable root Docker container and the synthetic proof marker are required.'
. /etc/os-release
[[ $ID == debian && $VERSION_ID == 13 ]] || fail 'Debian 13 is required.'
[[ $(findmnt --raw --noheadings --output FSTYPE,PROPAGATION --mountpoint /tmp) == "tmpfs private" ]] \
    || fail 'An isolated private tmpfs at /tmp is required.'

work=$(mktemp -d /tmp/sli-mount-proof.XXXXXXXX)
volume="$work/volume"
child=
cleanup() {
    if [[ -n $child ]]; then
        kill "$child" 2>/dev/null || true
        wait "$child" || true
    fi
    if mountpoint -q "$volume"; then
        umount -l -- "$volume"
    fi
    rm -f -- "$work/ready" "$work/proceed" "$work/verified" "$volume/sentinel" "$volume/payload"
    rmdir -- "$volume" "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -- "$volume"
mount -n -t tmpfs -o size=1m,nodev,nosuid,noexec tmpfs "$volume"
mount --make-shared "$volume"
[[ $(findmnt --raw --noheadings --output PROPAGATION --mountpoint "$volume") == shared ]] \
    || fail 'The synthetic source mount must begin as shared.'
printf '%s\n' original-tmpfs > "$volume/sentinel"
parent_namespace=$(readlink /proc/self/ns/mnt)

/usr/bin/timeout --kill-after=2s 15s /usr/bin/unshare --mount --propagation private -- \
    /bin/bash -s -- "$work" "$parent_namespace" <<'CHILD' &
set -euo pipefail
work=$1
parent_namespace=$2
volume="$work/volume"
[[ $(readlink /proc/self/ns/mnt) != "$parent_namespace" ]]
[[ $(findmnt --raw --noheadings --output FSTYPE,PROPAGATION --mountpoint "$volume") == "tmpfs private" ]]
[[ $(< "$volume/sentinel") == original-tmpfs ]]
: > "$work/ready"
for ((attempt = 0; attempt < 100; attempt++)); do
    [[ ! -f "$work/proceed" ]] || break
    sleep 0.05
done
[[ -f "$work/proceed" ]]
[[ $(findmnt --raw --noheadings --output FSTYPE,PROPAGATION --mountpoint "$volume") == "tmpfs private" ]]
[[ $(< "$volume/sentinel") == original-tmpfs ]]
printf '%s\n' synthetic-backup-after-detach > "$volume/payload"
[[ $(< "$volume/payload") == synthetic-backup-after-detach ]]
: > "$work/verified"
CHILD
child=$!

for ((attempt = 0; attempt < 100; attempt++)); do
    [[ ! -f "$work/ready" ]] || break
    kill -0 "$child" 2>/dev/null || fail 'The private child exited before it became ready.'
    sleep 0.05
done
[[ -f "$work/ready" ]] || fail 'Timed out waiting for the private child.'
umount -l -- "$volume"
if mountpoint -q "$volume"; then
    fail 'The source mount remains attached in the parent.'
fi
[[ -z $(find "$volume" -mindepth 1 -maxdepth 1 -print -quit) ]] \
    || fail 'The parent backing directory is not empty before the child write.'
: > "$work/proceed"
if ! wait "$child"; then
    child=
    fail 'The private child failed after the parent detach.'
fi
child=
[[ -f "$work/verified" ]] || fail 'The private child did not verify its payload.'
[[ -z $(find "$volume" -mindepth 1 -maxdepth 1 -print -quit) ]] \
    || fail 'The child wrote to the parent backing directory.'
printf '%s\n' 'PASS: private tmpfs retained the child payload after lazy detach; parent backing directory is empty.'
