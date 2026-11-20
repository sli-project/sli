"""Render .NET services and connect them to the installed boot target.

systemd runs generators at boot and daemon-reload, including after initial
site setup. No build-host settings or generated unit enter the Debian payload.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


def generate(runtime, release, destination):
    if not runtime.CONFIG.exists() and not runtime.CONFIG.is_symlink():
        return  # sli-host may be installed before the site is configured.
    units = runtime.dotnet_units(release, runtime.configuration())
    # systemd supplies a fresh, root-owned generator directory. Never replace
    # an existing unit or follow a service-name symlink.
    for name, body in units.items():
        with (destination / name).open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(body)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if os.geteuid() != 0 or len(args) != 4:
            raise ValueError("native_dotnet_generator_arguments_invalid")
        os.umask(0o022)
        spec = importlib.util.spec_from_file_location("sli_native_runtime", Path(__file__).with_name("native_runtime.py"))
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        generate(runtime, args[0], Path(args[1]))
    except Exception:  # noqa: BLE001 - never expose private config or file diagnostics
        print("native_dotnet_unit_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
