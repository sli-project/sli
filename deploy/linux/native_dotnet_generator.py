"""Render .NET services and connect them to the installed boot target.

systemd runs generators at boot and daemon-reload, including after initial
site setup. No build-host settings or generated unit enter the Debian payload.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


DOTNET = Path('/opt/sli/dotnet')


def generate(runtime, release, destination, *, publication=None):
    if not runtime.CONFIG.exists() and not runtime.CONFIG.is_symlink():
        return  # sli-host may be installed before the site is configured.
    units = runtime.dotnet_units(release, runtime.configuration())
    # systemd supplies a fresh, root-owned generator directory. Never replace
    # an existing unit or follow a service-name symlink.
    for name, body in units.items():
        if publication is not None:
            packaged = f'/opt/sli/dotnet/{release}'
            for directive in ('ExecStart', 'ExecStartPre'):
                body = body.replace(f'{directive}={packaged}/Sli.Server', f'{directive}={publication.as_posix()}/Sli.Server')
            body = body.replace(f'WorkingDirectory={packaged}\n', f'WorkingDirectory={publication.as_posix()}\n')
        with (destination / name).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(body)


def generate_installed(runtime, destination):
    if not runtime.CURRENT.exists() and not runtime.CURRENT.is_symlink():
        return  # First setup reloads after publishing the installed pointer.
    root, _, _ = runtime.release()
    if not hasattr(runtime, 'dotnet_units'):
        return  # A retained installation can predate the .NET units.
    publication = DOTNET / root.name
    executable = publication / 'Sli.Server'
    if not executable.exists() and not executable.is_symlink():
        publication = root / 'dotnet'
        executable = publication / 'Sli.Server'
    runtime.trusted(executable)
    generate(runtime, root.name, destination, publication=publication)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if os.geteuid() != 0 or len(args) != 3:
            raise ValueError("native_dotnet_generator_arguments_invalid")
        os.umask(0o022)
        spec = importlib.util.spec_from_file_location("sli_native_runtime", Path(__file__).with_name("native_runtime.py"))
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        generate_installed(runtime, Path(args[0]))
    except Exception:  # noqa: BLE001 - never expose private config or file diagnostics
        print("native_dotnet_unit_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
