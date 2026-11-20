"""Assemble Debian packages from an accepted release and an existing N03 runtime.

No compilation, dependency resolution, signing or installation happens here.
The input release includes its immutable native-runtime.json acceptance inventory.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath


ID = re.compile(r"[a-z0-9][a-z0-9.+-]{0,63}")
VERSION = re.compile(r"[0-9][a-zA-Z0-9.+~]*-[0-9]+~deb13")
HELPERS = ("native_host.py", "native_runtime.py", "native_install.py", "native_backup.py", "native_upgrade.py",
           "operation_wait.py",
           "native_clickhouse_endpoint.py", "native_setup.py", "native_diagnostics.py", "native_preinstall.py", "native_pins.json", "secrets-manifest.json", "backup_policy.py")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def write(root, name, body, mode=0o644):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(mode)


def control(root, name, version, depends, description):
    write(root, "DEBIAN/control", f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
          "Maintainer: SLI packaging <packages@example.invalid>\nSection: admin\nPriority: optional\n"
          + (f"Depends: {depends}\n" if depends else "") + f"Description: {description}\n")


def maintainer_header():
    preinstall = Path(__file__).with_name('native_preinstall.py').read_text(encoding='utf-8')
    return ("#!/bin/sh\nset -eu\numask 022\nsli_preinstall() {\n"
            '/usr/bin/python3 -I -B - "$@" <<\'SLI_BYTECODE\'\n' + preinstall +
            '\nSLI_BYTECODE\n}\nsli_clean_bytecode() {\n  sli_preinstall --clean-recovery "$accepted"\n}\n')


def retain_recovery_prerm():
    return (maintainer_header() + 'case "$1" in\n'
            ' remove|deconfigure) recovery=$(sli_preinstall --recovery-kind)\n'
            '  if test "$recovery" = accepted; then\n'
            # sli-remove stops services before parking these paths in trusted directories.
            '   receipt=/var/lib/sli/state/installed.json\n'
            '   current=/opt/sli/current\n'
            '   if test "$1" = remove && test ! -e "$receipt" && test ! -L "$receipt" &&\n'
            '      test ! -e "$current" && test ! -L "$current" &&\n'
            '      { { test -f "$receipt.sli-removing" && test ! -L "$receipt.sli-removing"; } ||\n'
            '        test -L "$current.sli-removing"; }; then exit 0; fi\n'
            '   logger -t sli-setup native_host_still_installed\n'
            "   echo 'SLI database state is retained. Keep the SLI host and rollback packages for recovery.' >&2\n"
            '   exit 1\n  fi ;;\nesac\n')


def scripts(release, version):
    """preinst must work before the new host/release is unpacked."""
    header = maintainer_header()
    guard = (header + f'case "$1" in install|upgrade) sli_preinstall --package-install "$1" {release} ;; esac\n' + "case \"$1\" in\n"
             f"  upgrade) test \"${{2:-}}\" = '{version}' || {{\n"
             '    recovery=$(sli_preinstall --recovery-kind)\n'
             '    if test "$recovery" = unfinished; then exit 0; fi\n'
             "    accepted=$(readlink -f /opt/sli/current)\n"
             "    sli_clean_bytecode\n"
             f"    /usr/bin/python3 -I -B \"/var/lib/sli/recovery/${{accepted##*/}}/native_upgrade.py\" dispatch check-package '{version}'; }} ;;\n"
             "  install) ;;\n  abort-upgrade) ;;\n  *) exit 1 ;;\nesac\n")
    return {
        "preinst": guard,
        "postinst": (header + "case \"$1\" in\n"
                     # Marker comes from this package's preinst install, including
                     # config-files state after remove. Never use old code here.
                     f"  configure) if test -e /var/lib/sli/state/reuse-package.json; then exec /usr/sbin/sli-native-install stage {release}; fi\n"
                     '    recovery=$(sli_preinstall --recovery-kind)\n'
                     '    if test "$recovery" = accepted; then\n'
                     "    accepted=$(readlink -f /opt/sli/current)\n"
                     "    sli_clean_bytecode\n"
                     f"    exec /usr/bin/python3 -I -B /usr/lib/sli/native_upgrade.py dispatch configure-package {release} '{version}'\n"
                     f"    else exec /usr/sbin/sli-native-install stage {release}; fi ;;\n"
                     "  abort-upgrade|abort-remove|abort-deconfigure) exit 0 ;;\n  *) exit 1 ;;\nesac\n"),
        "prerm": (header + "case \"$1\" in\n"
                  '  remove|deconfigure) exec /usr/sbin/sli-native-install remove ;;\n'
                  "  upgrade|failed-upgrade) target=${2:-}\n"
                  f"    if test \"$1\" = failed-upgrade; then target='{version}'; fi\n"
                  f"    if test \"$1\" = failed-upgrade || test \"$target\" != '{version}'; then\n"
                  '    recovery=$(sli_preinstall --recovery-kind)\n'
                  '    if test "$recovery" = unfinished; then exit 0; fi\n'
                  "    accepted=$(readlink -f /opt/sli/current)\n"
                  "    sli_clean_bytecode\n"
                  "    exec /usr/bin/python3 -I -B \"/var/lib/sli/recovery/${accepted##*/}/native_upgrade.py\" dispatch prepare-package \"$target\"; fi ;;\n"
                  "  *) exit 1 ;;\nesac\n"),
        "postrm": ("#!/bin/sh\nset -eu\numask 022\n# Data, configuration, secrets and recovery intentionally survive purge.\n"
                   "case \"$1\" in\n  remove|purge|upgrade|failed-upgrade|abort-install|abort-upgrade|disappear) exit 0 ;;\n"
                   "  *) exit 1 ;;\nesac\n"),
    }


def validate_dotnet_payload(target):
    require(target.is_dir() and not target.is_symlink(), "native_dotnet_publish_invalid")
    require((target / "Sli.Server").is_file() and (target / "Sli.Server.runtimeconfig.json").is_file(),
            "native_dotnet_publish_invalid")
    for path in target.rglob("*"):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), "native_package_payload_invalid")
        require(path.name not in {".env", ".git"} and path.suffix not in {".key", ".pem", ".pfx"}
                and "secrets" not in path.relative_to(target).parts, "native_package_private_payload")


def build(source, output, release, version, runtime_version, previous=None, *, clickhouse_mode="native", image_archive=None,
          dotnet_project=None, dotnet_published=None):
    require(ID.fullmatch(release) and VERSION.fullmatch(version) and VERSION.fullmatch(runtime_version),
            "native_package_identity_invalid")
    if previous:
        require(len(previous) == 3 and ID.fullmatch(previous[0]) and previous[0] != release
                and VERSION.fullmatch(previous[1]) and VERSION.fullmatch(previous[2]),
                "native_previous_package_invalid")
    require(source.is_dir() and not source.is_symlink(), "native_package_source_invalid")
    require(dotnet_project is None or dotnet_published is None, "native_dotnet_inputs_exclusive")
    require(dotnet_project is not None or dotnet_published is not None, "native_dotnet_payload_required")
    if dotnet_published is not None:
        # Validate before copytree: copying could dereference a forbidden symlink.
        validate_dotnet_payload(dotnet_published)
    # Reject secret-bearing/special payloads rather than silently shipping them.
    for path in source.rglob("*"):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), "native_package_payload_invalid")
        require(path.name not in {".env", ".git"} and path.suffix not in {".key", ".pem", ".pfx"}
                and not {"secrets", "__pycache__", "node_modules"}.intersection(path.relative_to(source).parts),
                "native_package_private_payload")
    manifest = json.loads((source / "native-runtime.json").read_text())
    require(manifest.get("schema_version") == 1 and manifest.get("migration_ledger")
            and manifest.get("roles") and manifest.get("plugins"), "native_package_inventory_required")
    python = PurePosixPath(manifest["python"])
    require(python.parts[:4] == ("/", "opt", "sli", "runtimes") and len(python.parts) == 7
            and ID.fullmatch(python.parts[4]) and python.parts[5:] == ("bin", "python3.14")
            and re.fullmatch(r"[0-9a-f]{64}", manifest.get("python_sha256", "")), "native_package_runtime_invalid")
    runtime = python.parts[4]
    from deploy.linux.native_plugins import release_inventory
    manifest["plugins"] = release_inventory(source, manifest["plugins"])
    output.mkdir(parents=True, exist_ok=True)
    names = []
    with tempfile.TemporaryDirectory(prefix="sli-deb-") as temporary:
        staging = Path(temporary)
        host = staging / "sli-host"
        control(host, "sli-host", version, "python3, systemd, adduser, ca-certificates, tzdata, openssl",
                "SLI native host management")
        with (host / 'DEBIAN/control').open('a', encoding='utf-8') as stream:
            stream.write('Pre-Depends: python3, postgresql-common\n')
        helpers = Path(__file__).parent
        preinstall = (helpers / 'native_preinstall.py').read_text(encoding='utf-8')
        write(host, 'DEBIAN/preinst', '#!/bin/sh\nset -eu\numask 022\ncase "$1" in\n install|upgrade)\n'
              "/usr/bin/python3 -I -B - <<'SLI_PREINSTALL'\n" + preinstall +
              '\nSLI_PREINSTALL\n ;;\n abort-upgrade) ;;\n *) exit 1 ;;\nesac\n', 0o755)
        for name in HELPERS:
            write(host, "usr/lib/sli/" + name, (helpers / name).read_text(encoding='utf-8'), 0o640 if name.endswith(".json") else 0o644)
        write(host, "usr/sbin/sli-native-install", "#!/bin/sh\nset -eu\numask 022\nexec /usr/bin/python3 -I -B /usr/lib/sli/native_install.py \"$@\"\n", 0o755)
        write(host, "usr/sbin/sli-setup", "#!/bin/sh\nset -eu\numask 022\nexec /usr/bin/python3 -I -B /usr/lib/sli/native_setup.py \"$@\"\n", 0o755)
        write(host, "usr/sbin/sli-cold-tables", "#!/bin/sh\nset -eu\numask 022\nexec /usr/bin/python3 -I -B /usr/lib/sli/native_host.py cold-tables \"$@\"\n", 0o755)
        write(host, "usr/sbin/sli-native-backup", "#!/bin/sh\nset -eu\numask 022\nexec /usr/bin/python3 -I -B /usr/lib/sli/native_backup.py launch \"$@\"\n", 0o755)
        write(host, "usr/sbin/sli-native-upgrade", "#!/bin/sh\nset -eu\numask 022\nexec /usr/bin/python3 -I -B /usr/lib/sli/native_upgrade.py launch \"$@\"\n", 0o755)
        write(host, "usr/lib/sli/native_remove.py", (helpers / 'native_remove.py').read_text(encoding='utf-8'))
        write(host, "usr/sbin/sli-remove", "#!/bin/sh\nset -eu\nexec /usr/bin/python3 -I -B /usr/lib/sli/native_remove.py \"$@\"\n", 0o755)
        write(host, "DEBIAN/prerm", retain_recovery_prerm(), 0o755)
        payload = staging / ("sli-release-" + release)
        control(payload, payload.name, version,
                f"sli-runtime-{runtime} (= {runtime_version}), sli-server-dotnet (= {version})",
                "SLI immutable application release")
        shutil.copytree(source, payload / "opt/sli/releases" / release)
        write(payload, f"opt/sli/releases/{release}/native-runtime.json",
              json.dumps(manifest, sort_keys=True) + "\n")
        write(payload, f"opt/sli/releases/{release}/native-package.json",
              json.dumps({"schema_version": 1, "release": release, "version": version}, sort_keys=True) + "\n")
        for path in (payload / "opt").rglob("*"):
            path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
        hold = staging / "sli-rollback-hold"
        dependencies = [f"sli-host (= {version})", f"{payload.name} (= {version})",
                        f"sli-runtime-{runtime} (= {runtime_version})"]
        if previous:
            # The retained immutable release pins its own exact runtime. Its ID
            # need not equal that runtime's ID (compatible releases may share it).
            dependencies += [f"sli-release-{previous[0]} (= {previous[1]})"]
        # Retain the recovery dependency for an accepted database, while an
        # unfinished first start can uninstall the complete kit.
        control(hold, hold.name, version, ", ".join(dependencies), "SLI retained application and recovery packages")
        write(hold, "DEBIAN/prerm", retain_recovery_prerm(), 0o755)
        public = staging / "sli"
        control(public, "sli", version, f"sli-host (= {version}), sli-rollback-hold (= {version}), "
                f"{payload.name} (= {version}), postgresql-18, postgresql-client-18",
                "SLI platform native installer")
        for name, body in scripts(release, version).items():
            write(public, "DEBIAN/" + name, body, 0o755)
        packages = [host, payload, hold, public]
        if dotnet_project is not None or dotnet_published is not None:
            dotnet = staging / "sli-server-dotnet"
            control(dotnet, dotnet.name, version, f"sli-host (= {version}), systemd, adduser, libicu76, libssl3t64, zlib1g",
                    "SLI .NET site services")
            target = dotnet / "opt/sli/dotnet" / release
            if dotnet_published is not None:
                shutil.copytree(dotnet_published, target)
            else:
                require(dotnet_project.is_file() and not dotnet_project.is_symlink(), "native_dotnet_project_invalid")
                subprocess.run(["dotnet", "publish", str(dotnet_project), "-c", "Release", "-r", "linux-x64",
                                "--self-contained", "true", "-o", str(target)], check=True, capture_output=True, timeout=900)
            validate_dotnet_payload(target)
            for path in target.rglob("*"):
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 or path.name == "Sli.Server" else 0o644)
            write(dotnet, "usr/lib/sli/native_dotnet_generator.py",
                  (helpers / "native_dotnet_generator.py").read_text(encoding="utf-8"))
            write(dotnet, "usr/lib/sli/native_plugin_runtime.py",
                  (helpers / "native_plugin_runtime.py").read_text(encoding="utf-8"))
            write(dotnet, "usr/sbin/sli-plugin-runtime-dotnet",
                  "#!/bin/sh\nset -eu\nexec /usr/bin/python3 -I -B /usr/lib/sli/native_plugin_runtime.py --release "
                  + release + ' "$@"\n', 0o755)
            write(dotnet, "usr/lib/systemd/system-generators/sli-dotnet-api",
                  "#!/bin/sh\nset -eu\nexec /usr/bin/python3 -I -B /usr/lib/sli/native_dotnet_generator.py "
                  + release + ' "$@"\n', 0o755)
            write(dotnet, "DEBIAN/postinst", '#!/bin/sh\nset -eu\ncase "$1" in\n configure)\n'
                  '  systemctl daemon-reload ;;\n abort-upgrade|abort-remove|abort-deconfigure) ;;\n'
                  ' *) exit 1 ;;\nesac\n', 0o755)
            write(dotnet, "DEBIAN/prerm", '#!/bin/sh\nset -eu\ncase "$1" in\n'
                  " remove|upgrade|deconfigure) systemctl stop sli-dotnet.target 'sli-dotnet-*.service' || true ;;\n"
                  ' failed-upgrade) ;;\n *) exit 1 ;;\nesac\n', 0o755)
            write(dotnet, "DEBIAN/postrm", '#!/bin/sh\nset -eu\ncase "$1" in\n'
                  ' remove|purge) systemctl daemon-reload ;;\n'
                  ' upgrade|failed-upgrade|abort-install|abort-upgrade|disappear) ;;\n'
                  ' *) exit 1 ;;\nesac\n', 0o755)
            packages.append(dotnet)
        for package in packages:
            size = sum(max(1, (path.lstat().st_size + 1023) // 1024) for path in package.rglob("*")
                       if "DEBIAN" not in path.relative_to(package).parts)
            with (package / "DEBIAN/control").open("a", encoding="utf-8") as stream:
                stream.write(f"Installed-Size: {size}\n")
            destination = output / f"{package.name}_{version}_amd64.deb"
            subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(package), str(destination)],
                           check=True, capture_output=True, timeout=300)
            names.append(destination)
    return names


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--release", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--runtime-version", required=True)
    parser.add_argument("--previous", nargs=3, metavar=("RELEASE", "VERSION", "RUNTIME_VERSION"))
    dotnet = parser.add_mutually_exclusive_group()
    dotnet.add_argument("--dotnet-project", type=Path, help=".NET server project to publish for linux-x64")
    dotnet.add_argument("--dotnet-published", type=Path, help="Ready self-contained linux-x64 publish directory; no SDK needed")
    args = parser.parse_args(argv)
    try:
        build(args.source, args.output, args.release, args.version, args.runtime_version, args.previous,
              dotnet_project=args.dotnet_project,
              dotnet_published=args.dotnet_published)
    except ValueError as error:
        if str(error) == "native_dotnet_payload_required":
            print("native_dotnet_payload_required")
            return 1
        print("native_package_build_failed")
        return 1
    except Exception:  # noqa: BLE001 - payload paths or subprocess diagnostics may contain private data
        print("native_package_build_failed")
        return 1
    print("native_packages_built")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
