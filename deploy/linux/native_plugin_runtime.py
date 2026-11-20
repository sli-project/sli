"""Host adapter for the reviewed .NET plugin drain/health CLI.

Uses the same two methods as plugin_update.run/rollback. Installation inventory,
signature verification and durable pointer writes remain owned by that updater.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys


class NativePluginFailure(RuntimeError):
    def __init__(self, returncode):
        super().__init__("update_plugin_runtime_failed")
        self.returncode = returncode


class NativePluginRuntime:
    def __init__(self, release):
        if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]{0,63}", release):
            raise ValueError("native_release_invalid")
        self.executable = f"/opt/sli/dotnet/{release}/Sli.Server"

    def invoke(self, runtime, action, plugin_id, version=None):
        if action not in {"drain", "health"} or not re.fullmatch(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+", plugin_id):
            raise ValueError("update_plugin_runtime_arguments_invalid")
        if (action == "health" and (not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version))
                or action == "drain" and version is not None):
            raise ValueError("update_plugin_runtime_arguments_invalid")
        command = [self.executable, "plugin-update-runtime", action, plugin_id]
        if version is not None:
            command += ["--version", version]
        try:
            # Inherit output so heartbeat remains observable. Never run a shell or read
            # service credentials; registration health is read-only and needs none.
            result = subprocess.run(command, check=False, env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8",
                "SLI_PLUGIN_RUNTIME_DIR": str(Path(runtime) / "plugins"),
                "SLI_PLUGIN_LOCK_DIR": "/opt/sli/current/config/plugin_packages/v3",
                "SLI_PLUGIN_UI_DIR": "/opt/sli/current/web/app/plugin-ui",
            })
        except OSError:
            raise NativePluginFailure(127) from None
        if result.returncode:
            # Preserve the real process code for the CLI/caller; never turn failure
            # into successful health. plugin_update rolls back on this exception.
            raise NativePluginFailure(result.returncode)

    def plugin_drain(self, runtime, manifest):
        self.invoke(runtime, "drain", manifest["plugin_id"])

    def plugin_health(self, runtime, manifest):
        self.invoke(runtime, "health", manifest["plugin_id"], manifest["plugin_version"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True)
    parser.add_argument("action", choices=("drain", "health"))
    parser.add_argument("plugin_id")
    parser.add_argument("--version")
    args = parser.parse_args(argv)
    try:
        NativePluginRuntime(args.release).invoke("/var/lib/sli", args.action, args.plugin_id, args.version)
    except NativePluginFailure as error:
        print("update_plugin_runtime_failed", file=sys.stderr)
        # subprocess represents signal termination as a negative signal number.
        return error.returncode if error.returncode > 0 else 128 - error.returncode
    except ValueError:
        print("update_plugin_runtime_arguments_invalid", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
