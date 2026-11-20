"""Copy the root-only inventory key to private API tmpfs, then drop privileges."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from deploy.linux.sli_secrets import _read_master_key
from server.sli.core.ad_credential_secrets import MASTER_KEY_REF, MASTER_KEY_SETTING, decode_master_key

SOURCE = Path('/run/ad-credentials-source') / MASTER_KEY_REF
DESTINATION = Path('/run/ad-credentials') / MASTER_KEY_REF
MOUNTS = Path('/proc/mounts')
RUNTIME_UID = 10001


def deliver():
    if (os.geteuid() != 0 or MASTER_KEY_SETTING in os.environ
            or os.environ.get(MASTER_KEY_SETTING + '_FILE') != str(DESTINATION)):
        raise ValueError('ad_credentials_delivery_rejected')
    body = _read_master_key(SOURCE)
    decode_master_key(body.decode('ascii'))
    # A disk-backed directory is never an acceptable delivery destination.
    mount = next((line.split() for line in MOUNTS.read_text().splitlines()
                  if line.split()[1] == str(DESTINATION.parent)), None)
    if not mount or mount[2] != 'tmpfs':
        raise ValueError('ad_credentials_delivery_rejected')
    info = DESTINATION.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('ad_credentials_delivery_rejected')
    fd = os.open(DESTINATION, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(body)
        stream.flush()
        os.fchown(stream.fileno(), RUNTIME_UID, RUNTIME_UID)
    os.chown(DESTINATION.parent, RUNTIME_UID, RUNTIME_UID)


def main():
    try:
        if len(sys.argv) < 2 or sys.argv[1] != 'api':
            raise ValueError('ad_credentials_delivery_rejected')
        deliver()
        os.setgroups([])
        os.setgid(RUNTIME_UID)
        os.setuid(RUNTIME_UID)
        os.execv(sys.executable, [sys.executable, '-m', 'deploy.linux.entrypoint', *sys.argv[1:]])
    except Exception:
        print('ad_credentials_delivery_failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
