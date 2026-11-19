"""Build the Debian 13 amd64 beta kit from a trusted Git commit on Linux."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from deploy.linux import native_package, native_pg_inventory


ROOT = Path(__file__).resolve().parents[2]
RELEASE_PATHS = ('server', 'scripts', 'sli_collect', 'sli_agent', 'config', 'deploy/linux',
                 'web/app', 'requirements.lock.txt', 'VERSION')
POSTGRES_ROLES = """SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, rolinherit
FROM pg_roles WHERE rolname ~ '^(sli_|adlog_)' ORDER BY rolname"""


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def git(root, *args):
    return command(['git', '-C', root, *args], encoding='utf-8', stdout=subprocess.PIPE).stdout.strip()


def export_commit(root, commit, checkout, archive):
    git(root, 'archive', '--format=tar', f'--output={archive}', commit)
    with tarfile.open(archive) as stream:
        stream.extractall(checkout, filter='data')


def package_pins(pins):
    """Follow the pinned PostgreSQL dependency closure plus the runtime dependencies."""
    spec = pins['runtime_build']
    rows = {row['name']: row for row in spec['debian_artifacts']}
    rows.update({row['name']: row for row in pins['packages']})
    required = {row['name'] for row in spec['debian_runtime']}
    required.update(name for name in pins['roots'] if not name.startswith('clickhouse-'))
    pending = set(required)
    while pending:
        name = pending.pop()
        for edge in pins['dependency_edges']:
            if edge['from'] == name and edge['to'] not in required:
                required.add(edge['to'])
                pending.add(edge['to'])
    for dependency in spec['debian_runtime']:
        if dependency['version'] != rows[dependency['name']]['version']:
            raise ValueError(f"Runtime dependency version differs from the package pin for {dependency['name']}")
    return {Path(rows[name]['filename']).name: rows[name]['sha256'] for name in sorted(required)}


def checked_inputs(cache, pins):
    """Use pinned bytes regardless of APT's epoch-escaped cache filenames."""
    if not cache.is_dir():
        raise ValueError('Provide a directory with pinned .deb inputs')
    found = {}
    wanted = set(pins.values())
    for path in sorted(cache.glob('*.deb')):
        if path.is_file() and not path.is_symlink():
            digest = sha256(path)
            if digest in wanted:
                found[digest] = path
    missing = sorted(name for name, digest in pins.items() if digest not in found)
    if missing:
        raise ValueError('Missing packages or SHA-256 mismatch: ' + ', '.join(missing))
    return {name: found[digest] for name, digest in pins.items()}


def copy_inputs(cache, output, pins):
    sources = checked_inputs(cache, pins)
    for name, digest in sorted(pins.items()):
        path = output / name
        shutil.copyfile(sources[name], path)
        if sha256(path) != digest:
            raise ValueError(f'Package changed during copy: {name}')


def input_pins(pins):
    spec = pins['runtime_build']
    artifact = pins.get('runtime_artifact')
    if artifact is None:
        # Commits predating this command used the same accepted runtime.
        builder_pins = ROOT / 'deploy/linux/native_pins.json'
        builder_data = builder_pins.read_bytes()
        builder = json.loads(builder_data)
        if spec != builder['runtime_build']:
            raise ValueError('The selected commit does not identify a pinned runtime artifact')
        artifact = builder['runtime_artifact']
        pin_source = {'source': 'builder_checkout', 'native_pins_sha256': hashlib.sha256(builder_data).hexdigest()}
    else:
        pin_source = {'source': 'release_commit'}
    if (artifact['runtime_id'], artifact['version']) != (spec['id'], spec['version']):
        raise ValueError('The selected commit does not identify a pinned runtime artifact')
    runtime_filename = f"sli-runtime-{artifact['runtime_id']}_{artifact['version']}_amd64.deb"
    return {**artifact, 'pin_source': pin_source}, runtime_filename, {
        **package_pins(pins), runtime_filename: artifact['sha256'],
    }


def nuget_graph_without_local_versions(entries):
    local_projects = {name.casefold() for name, entry in entries.items() if entry['type'] == 'Project'}
    graph = {}
    for name, entry in entries.items():
        if entry['type'] == 'Project' and 'dependencies' in entry:
            # These projects are built from the selected archive. NuGet may
            # refresh their version ranges without changing any package bytes.
            references = {ref: None if ref.casefold() in local_projects else version
                          for ref, version in entry['dependencies'].items()}
            entry = {**entry, 'dependencies': references}
        graph[name] = entry
    return graph


def verify_generated_runtime_lock(pinned, restored):
    expected, dependencies = pinned['dependencies'], restored['dependencies']
    if pinned['version'] != restored['version'] or any(
        target not in dependencies or nuget_graph_without_local_versions(dependencies[target])
        != nuget_graph_without_local_versions(entries) for target, entries in expected.items()
    ):
        raise ValueError('The Linux restore changed the committed NuGet lock')
    for target in dependencies.keys() - expected.keys():
        framework, _, runtime = target.partition('/')
        if runtime != 'linux-x64' or framework not in expected or any(
            expected[framework].get(name) != entry for name, entry in dependencies[target].items()
        ):
            raise ValueError('A Linux runtime dependency is not pinned in the committed NuGet lock')


def publish_dotnet(project, output, commit, env, *, source_root=None):
    lock_file = project.with_name('packages.lock.json')
    lock = json.loads(lock_file.read_text(encoding='utf-8'))
    restore = ['dotnet', 'restore', project, '-r', 'linux-x64', '-p:SelfContained=true']
    if not any(target.endswith('/linux-x64') for target in lock['dependencies']):
        # Older commits have a portable lock. Accept the NuGet-generated RID
        # view only when every entry, including its digest, was already pinned.
        command([*restore, '--force-evaluate'], cwd=project.parent, env=env)
        verify_generated_runtime_lock(lock, json.loads(lock_file.read_text(encoding='utf-8')))
    command([*restore, '--locked-mode'], cwd=project.parent, env=env)
    command(['dotnet', 'publish', project, '-c', 'Release', '-r', 'linux-x64', '--self-contained', 'true', '--no-restore',
             f'-p:SourceRevisionId={commit}', f'-p:PathMap={source_root or project.parent}=/_/',
             '-p:ContinuousIntegrationBuild=true', '-o', output],
            cwd=project.parent, env=env)
    native_package.validate_dotnet_payload(output)
    with (output / 'Sli.Server').open('rb') as apphost:
        if apphost.read(4) != b'\x7fELF' or not all((output / name).is_file() for name in
                                                    ('libcoreclr.so', 'libhostfxr.so')):
            raise ValueError('The .NET publication is missing its Linux apphost or bundled runtime')


def runtime_inventory(checkout, pg_bin, expected_version):
    """Observe production SQL and roles in a fresh, private PostgreSQL 18 cluster."""
    import psycopg

    # Do not inherit DSNs, credentials, plugin settings or systemd descriptors.
    with tempfile.TemporaryDirectory(prefix='sli-pg-') as temporary:
        work = Path(temporary)
        data, sock, password = work / 'data', work / 'socket', work / 'pg-password'
        sock.mkdir(mode=0o700)
        password.write_text(secrets.token_urlsafe(32) + '\n', encoding='ascii')
        password.chmod(0o600)
        env = {'PATH': str(pg_bin) + os.pathsep + os.defpath, 'LC_ALL': 'C.UTF-8'}
        command([pg_bin / 'initdb', '-D', data, '-U', 'postgres', '--auth-local=trust', '--auth-host=scram-sha-256',
                 f'--pwfile={password}', '--locale=C.UTF-8', '--encoding=UTF8'], env=env, stdout=subprocess.DEVNULL)
        with socket.socket() as candidate:
            candidate.bind(('127.0.0.1', 0))
            port = candidate.getsockname()[1]
        with (work / 'postgres.log').open('w+', encoding='utf-8') as log:
            with subprocess.Popen([pg_bin / 'postgres', '-D', data, '-p', str(port), '-h', '127.0.0.1',
                                   '-k', sock], env=env, stdout=log, stderr=log) as postgres:
                try:
                    connection = {'host': str(sock), 'port': port, 'user': 'postgres'}
                    while subprocess.run([pg_bin / 'pg_isready', '-h', sock, '-p', str(port)],
                                         env=env, stdout=subprocess.DEVNULL).returncode:
                        if postgres.poll() is not None:
                            log.seek(0)
                            raise ValueError('Temporary PostgreSQL could not start: ' + log.read())
                        time.sleep(0.25)
                    with psycopg.connect(**connection, dbname='postgres', autocommit=True) as conn:
                        actual_version = conn.execute('SHOW server_version').fetchone()[0]
                        if actual_version.split('.')[0] != expected_version.split('.')[0]:
                            raise ValueError(f'The builder needs PostgreSQL {expected_version.split(".")[0]}')
                        conn.execute('CREATE ROLE sli_migration LOGIN NOINHERIT')
                        conn.execute('CREATE ROLE adlog_user LOGIN NOINHERIT')
                        conn.execute('CREATE DATABASE sli OWNER sli_migration')
                    with psycopg.connect(**connection, dbname='sli') as conn:
                        conn.execute('REVOKE ALL ON DATABASE sli FROM PUBLIC')
                        conn.execute('GRANT CONNECT ON DATABASE sli TO adlog_user')
                        conn.execute('REVOKE ALL ON DATABASE postgres FROM PUBLIC')
                        conn.execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
                        conn.execute('GRANT USAGE ON SCHEMA public TO adlog_user')
                    return observe_migrations(checkout, connection, password, work, env, actual_version)
                finally:
                    if postgres.poll() is None:
                        postgres.terminate()


def observe_migrations(checkout, connection, password, work, env, actual_version):
    import psycopg

    env.update(SLI_PG_HOST='127.0.0.1', SLI_PG_PORT=str(connection['port']), SLI_PG_ADMIN_USER='postgres',
               SLI_INSTALL_DOMAIN='example.test', SLI_INSTALL_SEED_REPORT_DOMAIN='0', SLI_NATIVE_OWNER_SETUP='1',
               SLI_BACKUP_ROOT=str(work), SLI_PG_ADMIN_PASSWORD_FILE=str(password))
    settings = ('SLI_PLATFORM_OWNER_PASSWORD', 'SLI_NOTIFICATION_DB_PASSWORD', 'SLI_REPORT_PRODUCER_PG_PASSWORD',
                'ADLOG_SEMANTIC_WORKER_PASSWORD', 'ADLOG_STORAGE_V2_WORKER_PASSWORD', 'ADLOG_AD_CONTEXT_WORKER_PASSWORD',
                'ADLOG_STORAGE_LIFECYCLE_PASSWORD', 'ADLOG_STORAGE_LIFECYCLE_DELETE_PASSWORD',
                'SLI_JOB_DISPATCHER_LIGHT_PASSWORD', 'SLI_JOB_EXECUTOR_LIGHT_PASSWORD', 'SLI_JOB_PUBLISHER_LIGHT_PASSWORD')
    for setting in settings:
        private_file = work / setting
        private_file.write_text(secrets.token_urlsafe(32) + '\n', encoding='ascii')
        private_file.chmod(0o600)
        env[setting + '_FILE'] = str(private_file)
    # Run the checkout's own migration and registration code without invoking the
    # host installer, which manages system services and /etc/sli.
    migration = (
        'import psycopg, sys\n'
        'from deploy.linux import migrate, native_plugins\n'
        'migrate.migrate()\n'
        'with psycopg.connect(host=sys.argv[1], port=int(sys.argv[2]), user="postgres", dbname="sli") as conn:\n'
        '    native_plugins.bootstrap(conn)\n'
    )
    python_env = dict(env)
    if 'LD_LIBRARY_PATH' in os.environ:
        python_env['LD_LIBRARY_PATH'] = os.environ['LD_LIBRARY_PATH']
    command([sys.executable, '-B', '-c', migration, connection['host'], str(connection['port'])],
            cwd=checkout, env=python_env)
    with psycopg.connect(**connection, dbname='sli') as conn:
        ledger = native_pg_inventory.read_ledger(conn)
        native_pg_inventory.verify_ledger(ledger, native_pg_inventory.expected_ledger(checkout), root=checkout)
        roles = [list(row) for row in conn.execute(POSTGRES_ROLES)]
        plugins = {key: {'version': version, 'generation': None} for key, version in conn.execute(
            "SELECT plugin_id, package_version FROM public.plugin_installations_v1 "
            "WHERE package_lifecycle = 'registered' ORDER BY plugin_id")}
        return ledger, roles, plugins, actual_version


def prepare_release(checkout, release, runtime_path, artifact, postgres_version, observed, commit, epoch):
    for name in RELEASE_PATHS:
        source, target = checkout / name, release / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, symlinks=True)
        else:
            shutil.copy2(source, target, follow_symlinks=False)
    ledger, roles, plugins, build_pg_version = observed
    python_path = f"/opt/sli/runtimes/{artifact['runtime_id']}/bin/python3.14"
    with tempfile.TemporaryDirectory(prefix='sli-runtime-') as temporary:
        extracted = Path(temporary)
        command(['dpkg-deb', '-x', runtime_path, extracted])
        python = extracted / python_path.lstrip('/')
        if python.is_symlink() or not python.is_file() or not os.access(python, os.X_OK):
            raise ValueError('The pinned runtime has no executable python3.14')
        python_digest = sha256(python)
        if python_digest != artifact['python_sha256']:
            raise ValueError('The Python executable does not match its pin')
        evidence = release / 'native-evidence'
        evidence.mkdir()
        share = python.parents[1] / 'share/sli-runtime'
        for name in ('build-spec.json', 'sbom.json', 'shared-libraries.json'):
            shutil.copyfile(share / name, evidence / name)
        write_json(evidence / 'artifact.json', {
            'filename': runtime_path.name, 'sha256': sha256(runtime_path),
            'size': runtime_path.stat().st_size, 'python_sha256': python_digest,
            'pin_source': artifact['pin_source'],
        })
    write_json(release / 'native-runtime.json', {
        'schema_version': 1, 'python': python_path, 'python_sha256': python_digest,
        'postgres_version': postgres_version, 'migration_ledger': ledger, 'roles': roles,
        # The selected commit's native_package finalizes and validates this registry.
        'plugins': plugins,
        'provenance': {'source_commit': commit, 'source_date_epoch': epoch, 'inventory_postgres_version': build_pg_version,
                       'runtime_evidence': {path.name: sha256(path) for path in sorted(evidence.iterdir())}},
    })


def finish(output, commit, release, version, *, toolchain):
    rows = []
    for path in sorted(output.glob('*.deb')):
        command(['dpkg-deb', '--info', path], stdout=subprocess.DEVNULL)
        name, deb_version, arch = command(['dpkg-deb', '--showformat=${Package}\n${Version}\n${Architecture}',
                                           '--show', path], text=True, stdout=subprocess.PIPE).stdout.splitlines()
        rows.append({'filename': path.name, 'package': name, 'version': deb_version,
                     'architecture': arch, 'size': path.stat().st_size, 'sha256': sha256(path)})
    installer = output / 'install-beta-kit'
    installer_source = ROOT / 'deploy/linux/install-beta-kit'
    installer.write_text(installer_source.read_text(encoding='utf-8'), encoding='utf-8', newline='\n')
    manifest = {'schema_version': 1, 'git_commit': commit, 'release': release, 'version': version,
                'target': 'debian-13-amd64', 'toolchain': toolchain, 'packages': rows,
                'installer': {'filename': installer.name, 'sha256': sha256(installer)}}
    write_json(output / 'manifest.json', manifest)
    sums = {row['filename']: row['sha256'] for row in rows}
    sums[installer.name] = manifest['installer']['sha256']
    sums['manifest.json'] = sha256(output / 'manifest.json')
    (output / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name, digest in sorted(sums.items())),
                                      encoding='utf-8')
    return manifest


def include_agent(source, destination):
    files = {'SliAgent.msi', 'SliAgent-publish-win-x64.zip'}
    checksum = source / 'SHA256SUMS'
    if source.is_symlink() or checksum.is_symlink() or not checksum.is_file():
        raise ValueError('Provide the matching MSI workflow artifact with SHA256SUMS')
    lines = checksum.read_text(encoding='utf-8-sig').splitlines()
    pinned = {}
    for line in lines:
        digest, _, name = line.partition('  ')
        if not re.fullmatch(r'[0-9a-f]{64}', digest) or name not in files or name in pinned:
            raise ValueError('Invalid agent SHA256SUMS')
        pinned[name] = digest
    if pinned.keys() != files:
        raise ValueError('The agent artifact must include the MSI and portable ZIP')

    destination.mkdir()
    for name, digest in pinned.items():
        path = source / name
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise ValueError(f'Missing or unsafe agent artifact: {name}')
        copied = destination / name
        shutil.copyfile(path, copied)
        if sha256(copied) != digest:
            raise ValueError(f'Agent SHA-256 verification failed: {name}')
    (destination / 'SHA256SUMS').write_text('\n'.join(lines) + '\n', encoding='ascii', newline='\n')


def archive_kit(packages):
    files = sorted(packages.iterdir())
    with tarfile.open(packages / 'sli-debian-beta-kit.tar.gz', 'w:gz') as archive:
        for path in files:
            archive.add(path, arcname='sli-debian-beta-kit/' + path.name)


def build(root, ref, cache, output, pg_bin):
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or os.geteuid() == 0:
        raise ValueError('Run the build as an ordinary user on an amd64 Linux runner')
    if not cache.is_dir() or output.exists() or output.is_symlink():
        raise ValueError('Provide a pinned .deb cache and a new output directory')
    os.umask(0o022)
    commit = git(root, 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}')
    epoch = int(git(root, 'show', '-s', '--format=%ct', commit))
    release = 'beta1-' + commit[:12]
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch), TZ='UTC', LC_ALL='C.UTF-8',
               PYTHONDONTWRITEBYTECODE='1', DOTNET_CLI_TELEMETRY_OPTOUT='1', DOTNET_NOLOGO='1',
               DOTNET_GENERATE_ASPNET_CERTIFICATE='false')
    # The final rename occurs on the output filesystem. Failed or overlapping
    # builds leave an existing kit intact.
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.sli-beta-kit-', dir=output.parent) as temporary:
        work = Path(temporary)
        checkout, packages, agent = work / 'source', work / 'packages', work / 'agent'
        include_agent(cache / f'sli-agent-dotnet-msi-{commit}', agent)
        checkout.mkdir()
        packages.mkdir()
        export_commit(root, commit, checkout, work / 'source.tar')
        version = f"{(checkout / 'VERSION').read_text(encoding='utf-8').strip()}-{epoch}{int(commit[:8], 16):010}~deb13"
        if not native_package.VERSION.fullmatch(version):
            raise ValueError('VERSION is not valid for the Debian beta kit')
        pins = json.loads((checkout / 'deploy/linux/native_pins.json').read_text(encoding='utf-8'))
        artifact, runtime_filename, locked = input_pins(pins)
        print(f'Verifying pinned packages for {commit}', flush=True)
        copy_inputs(cache, packages, locked)
        pg_deb_version = next(row['version'] for row in pins['packages'] if row['name'] == 'postgresql-18')
        pg_version = f"{pg_deb_version.split('-')[0]} (Debian {pg_deb_version})"
        ledger = json.loads((checkout / 'deploy/linux/native_pg_ledger.json').read_text(encoding='utf-8'))
        native_pg_inventory.verify_manifest(checkout, ledger)
        print('Observing the release migrations in temporary PostgreSQL', flush=True)
        observed = runtime_inventory(checkout, pg_bin, pg_version)

        print('Building the web app and .NET server', flush=True)
        toolchain = {'python': platform.python_version(), 'postgresql_inventory': observed[3]}
        for key, executable in (('node', 'node'), ('npm', 'npm'), ('dotnet_sdk', 'dotnet')):
            toolchain[key] = command([executable, '--version'], text=True, stdout=subprocess.PIPE,
                                     cwd=checkout / 'server-dotnet', env=env).stdout.strip()
        command(['npm', 'ci', '--no-audit', '--no-fund'], cwd=checkout / 'frontend', env=env)
        command(['npm', 'run', 'build'], cwd=checkout / 'frontend', env=env)
        command([sys.executable, '-B', 'scripts/maintenance/publish_react_build.py', '--source',
                 'artifacts/frontend/react-build', '--apply', '--confirm', 'PUBLISH-REACT-BUILD'], cwd=checkout, env=env)
        published = work / 'dotnet'
        publish_dotnet(checkout / 'server-dotnet/src/Sli.Server/Sli.Server.csproj', published, commit, env, source_root=checkout)
        payload = work / 'release'
        print(f'Assembling Debian packages for {release}', flush=True)
        prepare_release(checkout, payload, packages / runtime_filename, artifact, pg_version, observed, commit, epoch)
        agent.rename(payload / 'web/app/installers')
        command([sys.executable, '-B', '-m', 'deploy.linux.native_package', '--source', payload, '--output', packages,
                 '--release', release, '--version', version, '--runtime-version', artifact['version'],
                 '--dotnet-published', published], cwd=checkout, env=env)
        finish(packages, commit, release, version, toolchain=toolchain)
        archive_kit(packages)
        packages.rename(output)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--commit', default='HEAD', help='Git commit to build, default HEAD')
    parser.add_argument('--debs', type=Path, required=True,
                        help='pinned .debs and the trusted sli-agent-dotnet-msi-<commit> artifact directory')
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument('--output', type=Path, help='new directory for the finished kit')
    output.add_argument('--verify-inputs', action='store_true', help='verify the pinned cache without building')
    parser.add_argument('--pg-bin', type=Path, default=Path('/usr/lib/postgresql/18/bin'),
                        help='PostgreSQL 18 tools for the disposable migration inventory')
    args = parser.parse_args()
    try:
        cache = args.debs.resolve()
        if args.verify_inputs:
            commit = git(ROOT, 'rev-parse', '--verify', '--end-of-options', args.commit + '^{commit}')
            pins = json.loads(git(ROOT, 'show', f'{commit}:deploy/linux/native_pins.json'))
            _, _, locked = input_pins(pins)
            print(f'{len(checked_inputs(cache, locked))} pinned packages verified for {commit}')
        else:
            print(build(ROOT, args.commit, cache, args.output.absolute(), args.pg_bin.resolve()))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'Beta kit build failed: {error}\n')


if __name__ == '__main__':
    main()
