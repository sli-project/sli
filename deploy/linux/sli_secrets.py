"""Provision host secret files before Compose can mount them. Never print material."""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from itertools import pairwise
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# Older signed updater snapshots have a fixed file list and contain no
# native installer. Keep those snapshots on their original dependency set.
_STANDALONE_UPDATER = not Path(__file__).with_name("native_install.py").is_file()
if _STANDALONE_UPDATER:
    from server.sli.agents.ca import IssuingCA
    from server.sli.core.ad_credential_secrets import (
        MASTER_KEY_REF, MASTER_KEY_SETTING, MASTER_KEY_SPEC, decode_master_key,
    )
    from server.sli.core.notification_secrets import (
        NOTIFICATION_DELIVERY_SERVICE, NOTIFICATION_SECRET_SETTINGS, validate_notification_secret,
    )
    from server.sli.release_package import PackageError
else:
    from deploy.linux.release_package import PackageError
    from deploy.linux.sli_core.ad_credential_secrets import (
        MASTER_KEY_REF, MASTER_KEY_SETTING, MASTER_KEY_SPEC, decode_master_key,
    )
    from deploy.linux.sli_core.ca import IssuingCA
    from deploy.linux.sli_core.notification_secrets import (
        NOTIFICATION_DELIVERY_SERVICE, NOTIFICATION_SECRET_SETTINGS, validate_notification_secret,
    )

MANIFEST = Path(__file__).with_name('secrets-manifest.json')
MAX_BYTES = 1024 * 1024
AGENT_FILE_SETTINGS = {'agent_root_certificate': 'SLI_AGENT_CA_ROOT_CERT_FILE',
                       'agent_issuer_certificate': 'SLI_AGENT_CA_ISSUER_CERT_FILE',
                       'agent_issuer_key': 'SLI_AGENT_CA_ISSUER_KEY_FILE',
                       'agent_mtls_ca': 'SLI_AGENT_MTLS_CA_FILE'}


class SecretError(PackageError):
    """Only fixed diagnostics and validated manifest names may reach the CLI."""


def load_manifest(path=MANIFEST):
    try:
        value = json.loads(Path(path).read_text('utf-8'))
        specs = value['secrets']
        if value['version'] != 1 or not isinstance(specs, dict) or not specs:
            raise ValueError
        for name, spec in specs.items():
            if (not re.fullmatch(r'[a-z][a-z0-9_]*', name)
                    or spec['kind'] not in {'password', 'certificate', 'private_key', 'symmetric_key'}
                    or spec['group'] not in {'core', 'tls', 'agents', 'offline', 'notifications', 'ad_credentials'}
                    or ((name == MASTER_KEY_REF or spec['kind'] == 'symmetric_key' or spec['group'] == 'ad_credentials')
                        and (name != MASTER_KEY_REF or spec != MASTER_KEY_SPEC))
                    or (spec['group'] == 'notifications' and
                        (name not in NOTIFICATION_SECRET_SETTINGS or spec['kind'] != 'password'))
                    or (name in NOTIFICATION_SECRET_SETTINGS and spec['group'] != 'notifications')):
                raise ValueError
        return specs
    except (OSError, ValueError, KeyError, TypeError):
        raise SecretError('manifest_invalid') from None


def validate_compose(config, manifest=None):
    manifest = load_manifest() if manifest is None else manifest
    referenced = set(config.get('secrets', {}))
    missing_mount = False
    for service_name, service in config.get('services', {}).items():
        targets = set()
        for item in service.get('secrets', []):
            source = item if isinstance(item, str) else item.get('source')
            referenced.add(source)
            if source == MASTER_KEY_REF and service_name != 'api':
                raise SecretError('ad_credentials: api_only_mount_required')
            if source in NOTIFICATION_SECRET_SETTINGS and service_name != NOTIFICATION_DELIVERY_SERVICE:
                raise SecretError('notifications: delivery_only_mount_required')
            target = source if isinstance(item, str) else item.get('target', source)
            targets.add(target if target.startswith('/') else '/run/secrets/' + target)
        environment = service.get('environment') or {}
        if isinstance(environment, list):
            environment = {item.partition('=')[0]: item.partition('=')[2] if '=' in item else None
                           for item in environment}
        for name, value in environment.items():
            if name == MASTER_KEY_SETTING:
                raise SecretError('ad_credentials: plaintext_environment_forbidden')
            if name == MASTER_KEY_SETTING + '_FILE' and (
                    service_name != 'api' or value != '/run/ad-credentials/' + MASTER_KEY_REF
                    or MASTER_KEY_REF not in [item if isinstance(item, str) else item.get('source')
                                               for item in service.get('secrets', [])]):
                raise SecretError('ad_credentials: private_delivery_required')
            if name in NOTIFICATION_SECRET_SETTINGS.values():
                raise SecretError('notifications: plaintext_environment_forbidden')
            if name.removesuffix('_FILE') in NOTIFICATION_SECRET_SETTINGS.values() and name.endswith('_FILE'):
                # The isolated setup writer owns this bounded directory. Delivery
                # sees only its read-only bind, never the installation secret root.
                if (service_name == NOTIFICATION_DELIVERY_SERVICE
                        and (name, value) in {
                            ('SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE', '/var/lib/notification-secrets/notification_telegram_token'),
                            ('SLI_NOTIFICATION_SMTP_PASSWORD_FILE', '/var/lib/notification-secrets/notification_smtp_password')}
                        and any((isinstance(mount, dict) and mount.get('type') == 'bind'
                                 and mount.get('target') == '/var/lib/notification-secrets'
                                 and str(mount.get('source', '')).endswith('/notifications')
                                 and mount.get('read_only') is True)
                                or (isinstance(mount, str)
                                    and mount.endswith('/notifications:/var/lib/notification-secrets:ro'))
                                for mount in service.get('volumes', []))):
                    continue
                expected = next(ref for ref, setting in NOTIFICATION_SECRET_SETTINGS.items()
                                if setting == name.removesuffix('_FILE'))
                if (service_name != NOTIFICATION_DELIVERY_SERVICE
                        or value != '/run/secrets/' + expected
                        or expected not in [item if isinstance(item, str) else item.get('source')
                                            for item in service.get('secrets', [])]):
                    raise SecretError('notifications: delivery_only_mount_required')
            if (name.endswith('_FILE') and isinstance(value, str)
                    and value.startswith('/run/secrets/') and value not in targets):
                missing_mount = True
        if any((item if isinstance(item, str) else item.get('source')) == MASTER_KEY_REF
               for item in service.get('secrets', [])):
            # File-backed Compose secrets preserve host root:root 0600. Only
            # the privileged entrypoint may copy this key into API-only tmpfs.
            mounts = [item for item in service.get('secrets', []) if isinstance(item, dict)
                      and item.get('source') == MASTER_KEY_REF]
            tmpfs = service.get('tmpfs', [])
            if (service_name != 'api' or len(mounts) != 1
                    or mounts[0].get('target') != '/run/ad-credentials-source/' + MASTER_KEY_REF
                    or str(service.get('user')) != '0:0'
                    or service.get('entrypoint') != ['python', '-m', 'deploy.linux.ad_credentials_entrypoint']
                    or not any(item.startswith('/run/ad-credentials:') and 'mode=0700' in item for item in tmpfs)
                    or environment.get(MASTER_KEY_SETTING + '_FILE') != '/run/ad-credentials/' + MASTER_KEY_REF):
                raise SecretError('ad_credentials: private_delivery_required')
    if referenced - manifest.keys():
        raise SecretError('compose: manifest_missing')
    if any(manifest[name]['group'] == 'offline' for name in referenced):
        raise SecretError('compose: offline_key_mount_forbidden')
    if missing_mount:
        raise SecretError('compose: secret_file_mount_missing')


def _windows_acl(path, *, create=False):
    # Windows and Docker Desktop share NTFS files. POSIX chmod inside a bind
    # mount cannot establish their host ACL; run this CLI on the Windows host.
    script = r'''
$ErrorActionPreference = 'Stop'
$path = $env:SLI_SECRET_ACL_PATH
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($env:SLI_SECRET_ACL_CREATE -eq '1') {
    $acl = Get-Acl -LiteralPath $path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($rule) }
    $acl.SetOwner($sid)
    $inherit = if (Test-Path -LiteralPath $path -PathType Container) {
        [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    } else { [System.Security.AccessControl.InheritanceFlags]::None }
    foreach ($id in @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')) {
        $identity = [System.Security.Principal.SecurityIdentifier]::new($id)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $path -AclObject $acl
}
$acl = Get-Acl -LiteralPath $path
$allowed = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')
if (!$acl.AreAccessRulesProtected -or $acl.GetOwner(
    [System.Security.Principal.SecurityIdentifier]).Value -notin $allowed) { exit 1 }
foreach ($rule in $acl.Access) {
    if ($rule.IsInherited -or ($rule.AccessControlType -eq 'Allow' -and
        $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -notin $allowed)) { exit 1 }
}
'''
    env = dict(os.environ, SLI_SECRET_ACL_PATH=str(path), SLI_SECRET_ACL_CREATE='1' if create else '0')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, timeout=30, check=False, env=env)
    if result.returncode:
        raise SecretError('permissions_too_broad_or_acl_unavailable')


def _check_owner(info, offline=False):
    if info.st_uid != 0 or info.st_gid != (0 if offline else 10001):
        raise SecretError('root_owner_and_container_group_required')


def _lstat(path):
    try:
        return path.lstat()
    except PermissionError:
        raise SecretError('permission_denied: cannot inspect secret paths; check directory access and host ACLs') from None


def _exists(path):
    # Path.exists()/is_symlink() suppress OSError on Python 3.14. Only ENOENT
    # means absent: inaccessible material must never trigger generation.
    try:
        _lstat(path)
    except FileNotFoundError:
        return False
    return True


def _check_path(path, *, directory=False, offline=False):
    info = _lstat(path)
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise SecretError(f'{path.name if not directory else "directory"}: regular_file_required')
    if os.name == 'nt':
        if info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise SecretError('reparse_point_forbidden')
        _windows_acl(path)
    else:
        allowed = (0o700 if directory else 0o600) if offline else (0o750 if directory else 0o640)
        if stat.S_IMODE(info.st_mode) & ~allowed:
            label = 'directory' if directory else path.name
            raise SecretError(
                f'{label}: permissions_too_broad (mode={stat.S_IMODE(info.st_mode):04o}; allowed={allowed:04o}); '
                'Linux permissions are required; for Docker Desktop Windows bind mounts, '
                'validate NTFS ACLs with python -m deploy.linux.sli_secrets on the Windows host '
                'or use a Linux filesystem')
        if not directory and not offline and not info.st_mode & stat.S_IRGRP:
            raise SecretError('container_group_read_required')
        _check_owner(info, offline)
        if hasattr(os, 'listxattr') and any(name.startswith('system.posix_acl_') for name in os.listxattr(path)):
            raise SecretError('extended_or_inherited_acl_forbidden')


def _protect(path, *, directory=False, offline=False):
    if os.name == 'nt':
        _windows_acl(path, create=True)
    else:
        # Remove inherited ACLs only on newly created material. Existing files
        # with ACLs are refused by preflight and are never silently repaired.
        if hasattr(os, 'listxattr'):
            for name in os.listxattr(path):
                if name.startswith('system.posix_acl_'):
                    os.removexattr(path, name)
        os.chown(path, 0, 0 if offline else 10001)
        path.chmod((0o700 if directory else 0o600) if offline else (0o750 if directory else 0o640))


def _directory(path, offline=False):
    if not _exists(path):
        path.mkdir(mode=0o700, parents=True)
        _protect(path, directory=True, offline=offline)
    _check_path(path, directory=True, offline=offline)


def _read(path, name):
    # Bound memory and reject empty files without ever echoing their bytes.
    try:
        with path.open('rb') as stream:
            body = stream.read(MAX_BYTES + 1)
    except PermissionError:
        raise SecretError(f'{name}: permission_denied; check file read access and host ACLs') from None
    if not body or len(body) > MAX_BYTES:
        raise SecretError(f'{name}: invalid_format')
    return body


def _read_master_key(path):
    """Pin a root-owned import; never follow a replaced symlink after preflight."""
    if os.name == 'nt':
        # The inventory KEK is delivered only by the Linux host profile.
        raise SecretError('ad_credentials: linux_root_required')
    try:
        _check_path(path, offline=True)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) & ~0o600
                    or any(name.startswith('system.posix_acl_') for name in os.listxattr(stream.fileno()))):
                raise ValueError
            _check_owner(info, True)
            body = stream.read(45)
            if len(body) != 44:
                raise ValueError
            return base64.b64encode(decode_master_key(body.decode('ascii')))
    except (OSError, ValueError):
        raise SecretError('ad_credentials: secret_unavailable_or_unprotected') from None


def _validate(name, spec, body):
    try:
        if name == MASTER_KEY_REF:
            decode_master_key(body.decode('ascii'))
        elif spec['group'] == 'notifications':
            validate_notification_secret(name, body.decode('utf-8'))
        elif spec['kind'] == 'password':
            if not body or len(body) > MAX_BYTES or any(c in body for c in (b'\r', b'\n', b'\x00')):
                raise ValueError
            body.decode('ascii')
        elif spec['kind'] == 'certificate':
            certificates = x509.load_pem_x509_certificates(body)
            now = datetime.now(timezone.utc)
            if not certificates or any(not cert.not_valid_before_utc <= now < cert.not_valid_after_utc
                                       for cert in certificates):
                raise ValueError
        else:
            serialization.load_pem_private_key(body, password=None)
    except Exception:  # noqa: BLE001 -- cryptography errors must not expose material
        raise SecretError(f'{name}: invalid_format') from None


def _certificate(key, name, *, ca, signer=None, issuer=None, eku, days, sans=None, path_length=None):
    now = datetime.now(timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                   (signer or key).public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                   key_encipherment=False, data_encipherment=False, key_agreement=False,
                   key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.ExtendedKeyUsage([eku]), critical=False))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return builder.sign(signer or key, hashes.SHA256())


def _pem(value):
    if isinstance(value, x509.Certificate):
        return value.public_bytes(serialization.Encoding.PEM).rstrip(b'\n')
    return value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()).rstrip(b'\n')


def _tls_bundle(names):
    if not names:
        raise SecretError('tls: names_required_for_initial_generation')
    sans = []
    for name in names:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    ca_key, key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
    ca = _certificate(ca_key, 'SLI TLS CA', ca=True, eku=ExtendedKeyUsageOID.SERVER_AUTH,
                      days=3650, path_length=0)
    cert = _certificate(key, 'SLI server', ca=False, signer=ca_key, issuer=ca.subject,
                        eku=ExtendedKeyUsageOID.SERVER_AUTH, days=365, sans=sans)
    return {'tls_ca': _pem(ca), 'tls_certificate': _pem(cert), 'tls_key': _pem(key)}


def _agent_bundle():
    root_key, key = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1())
    root = _certificate(root_key, 'SLI agent root', ca=True, eku=ExtendedKeyUsageOID.CLIENT_AUTH,
                        days=3650, path_length=1)
    issuer = _certificate(key, 'SLI agent issuer', ca=True, signer=root_key, issuer=root.subject,
                          eku=ExtendedKeyUsageOID.CLIENT_AUTH, days=1825, path_length=0)
    return {'agent_root_certificate': _pem(root), 'agent_mtls_ca': _pem(root),
            'agent_issuer_certificate': _pem(issuer), 'agent_issuer_key': _pem(key)}, _pem(root_key)


def _strict_tls(material):
    """Perform an in-memory OpenSSL handshake before publishing any files."""
    with tempfile.TemporaryDirectory(prefix='sli-tls-check-') as temporary:
        certificate, key = Path(temporary) / 'certificate', Path(temporary) / 'key'
        certificate.write_bytes(material['tls_certificate'])
        key.write_bytes(material['tls_key'])
        key.chmod(0o600)
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(certificate, key)
        client = ssl.create_default_context(cadata=material['tls_ca'].decode('ascii'))
        client.verify_flags |= ssl.VERIFY_X509_STRICT
        client.check_hostname = False
        client_in, client_out, server_in, server_out = (ssl.MemoryBIO() for _ in range(4))
        peers = (client.wrap_bio(client_in, client_out, server_side=False),
                 server.wrap_bio(server_in, server_out, server_side=True))
        done = [False, False]
        for _ in range(20):
            for index, peer in enumerate(peers):
                if not done[index]:
                    try:
                        peer.do_handshake()
                        done[index] = True
                    except ssl.SSLWantReadError:
                        pass
            server_in.write(client_out.read())
            client_in.write(server_out.read())
            if all(done):
                return
        raise ValueError('tls_handshake_incomplete')


def agent_imports(directory):
    """Accept only a complete protected online bundle; never load the root key."""
    directory = Path(directory)
    _check_path(directory, directory=True)
    manifest = load_manifest()
    members = {name: directory / name for name, spec in manifest.items() if spec['group'] == 'agents'}
    material = {}
    for name, path in members.items():
        _check_path(path)
        material[name] = _read(path, name)
        _validate(name, manifest[name], material[name])
    _validate_bundles(material, manifest)
    return members


def check_agent_bundle():
    """Validate the restored container's file-backed issuer and mTLS trust."""
    manifest = load_manifest()
    material = {name: _read(Path(os.environ[setting]), name) for name, setting in AGENT_FILE_SETTINGS.items()}
    for name, body in material.items():
        _validate(name, manifest[name], body)
    _validate_bundles(material, manifest)


def _validate_bundles(material, manifest):
    for group in ('tls', 'agents'):
        members = {name for name, spec in manifest.items() if spec['group'] == group}
        if not members & material.keys():
            continue
        if not members <= material.keys():
            raise SecretError(f'{group}: incomplete_bundle_restore_required')
        try:
            if group == 'tls':
                cert = x509.load_pem_x509_certificate(material['tls_certificate'])
                key = serialization.load_pem_private_key(material['tls_key'], password=None)
                if cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
                    raise ValueError
                # Check a supplied PEM chain and its trust anchor, including validity.
                chain = x509.load_pem_x509_certificates(material['tls_certificate'])
                for child, parent in pairwise(chain):
                    child.verify_directly_issued_by(parent)
                anchors = x509.load_pem_x509_certificates(material['tls_ca'])
                if chain[-1] not in anchors:
                    for anchor in anchors:
                        try:
                            chain[-1].verify_directly_issued_by(anchor)
                            break
                        except Exception:  # noqa: BLE001, S112 -- never log certificate material
                            continue
                    else:
                        raise ValueError
                _strict_tls(material)
            else:
                root = x509.load_pem_x509_certificate(material['agent_root_certificate'])
                issuer = x509.load_pem_x509_certificate(material['agent_issuer_certificate'])
                key = serialization.load_pem_private_key(material['agent_issuer_key'], password=None)
                IssuingCA(root, issuer, key).validate()
                if root not in x509.load_pem_x509_certificates(material['agent_mtls_ca']):
                    raise ValueError
        except Exception:  # noqa: BLE001 -- fixed safe diagnostic
            raise SecretError(f'{group}: invalid_certificate_bundle') from None


def _publish(path, body, *, offline=False, replace=False):
    # Publish a complete, permissioned file; replacement is explicitly opt-in.
    fd, temporary = tempfile.mkstemp(prefix='.sli-secret-', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        _protect(temporary, offline=offline)
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)
        if os.name != 'nt':
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except FileExistsError:
        raise SecretError('concurrent_creation_retry_required') from None
    finally:
        temporary.unlink(missing_ok=True)


def ensure(directory, *, names=None, imports=None, tls_names=None, offline_root_dir=None, replace=False):
    manifest = load_manifest()
    selected = list(names) if names is not None else [name for name, spec in manifest.items()
                                                    if spec['group'] in {'core', 'tls'}]
    if set(selected) - manifest.keys() or any(manifest[name]['group'] == 'offline' for name in selected):
        raise SecretError('compose: manifest_missing_or_offline_key')
    imports = imports or {}
    if imports.keys() - set(selected):
        raise SecretError('import_arguments_invalid')
    if replace and (len(imports) != 1 or imports.keys() - NOTIFICATION_SECRET_SETTINGS.keys()):
        raise SecretError('notifications: single_import_required_for_replacement')
    if os.name != 'nt' and os.geteuid() != 0:
        raise SecretError('linux_root_required')
    directory = Path(directory)
    _directory(directory)
    material, pending = {}, {}
    # Compose may reference only part of an established certificate bundle.
    # Inspect all its members on disk before deciding it needs generation.
    inspected = dict.fromkeys(selected)
    for group in ('tls', 'agents'):
        members = {name for name, spec in manifest.items() if spec['group'] == group}
        if members & inspected.keys():
            inspected.update(dict.fromkeys(sorted(members)))
    # Complete preflight precedes publication, even when the offending file is
    # later than a newly introduced password in the manifest.
    for name in inspected:
        path = directory / name
        if name == MASTER_KEY_REF:
            # Never generate a replacement KEK on upgrade/restore. Provision
            # requires an explicit protected import, even on first use.
            if _exists(path):
                material[name] = _read_master_key(path)
                if name in imports:
                    if _read_master_key(Path(imports[name])) != material[name]:
                        raise SecretError('ad_credentials: rotation_required')
            elif name in imports:
                material[name] = pending[name] = _read_master_key(Path(imports[name]))
            else:
                raise SecretError('ad_credentials: protected_import_required')
            continue
        if manifest[name]['group'] == 'notifications':
            # Imports must already be protected on the host. Never echo their
            # untrusted filenames or turn an absent credential into random data.
            try:
                existing = None
                if _exists(path):
                    _check_path(path)
                    existing = _read(path, name)
                if name in imports:
                    source = Path(imports[name])
                    _check_path(source)
                    imported = _read(source, name)
                    if existing is not None and imported != existing and not replace:
                        raise SecretError('notifications: replacement_required')
                    material[name] = imported
                    if imported != existing:
                        pending[name] = imported
                elif existing is not None:
                    material[name] = existing
                else:
                    raise SecretError('notifications: import_required')
            except SecretError as exc:
                if str(exc) in {'notifications: replacement_required', 'notifications: import_required'}:
                    raise
                raise SecretError('notifications: secret_unavailable_or_unprotected') from None
            except OSError:
                raise SecretError('notifications: secret_unavailable_or_unprotected') from None
            continue
        if _exists(path):
            _check_path(path)
            material[name] = _read(path, name)
            if (manifest[name]['group'] == 'agents' and name in imports
                    and _read(Path(imports[name]), name) != material[name]):
                raise SecretError('import_conflicts_with_existing_secret')
        elif name in imports:
            material[name] = pending[name] = _read(Path(imports[name]), name)
        elif manifest[name]['kind'] == 'password':
            material[name] = pending[name] = secrets.token_urlsafe(48).encode('ascii')
    root_key = None
    for group in ('tls', 'agents'):
        members = {name for name, spec in manifest.items() if spec['group'] == group}
        requested = members & set(selected)
        if not requested or members <= material.keys():
            continue
        if requested != members or members & material.keys():
            raise SecretError(f'{group}: incomplete_bundle_restore_required')
        if group == 'tls':
            bundle = _tls_bundle(tls_names)
        else:
            if offline_root_dir is None:
                raise SecretError('agents: offline_root_directory_required')
            offline = Path(offline_root_dir)
            if offline.resolve() == directory.resolve() or offline.resolve().is_relative_to(directory.resolve()):
                raise SecretError('agents: offline_root_directory_must_be_separate')
            _directory(offline, offline=True)
            if _exists(offline / 'agent_root_key'):
                raise SecretError('agents: incomplete_bundle_restore_required')
            bundle, root_key = _agent_bundle()
        material.update(bundle)
        pending.update(bundle)
    for name, body in material.items():
        _validate(name, manifest[name], body)
    _validate_bundles(material, manifest)
    if root_key is not None:
        _publish(offline / 'agent_root_key', root_key, offline=True)
    for name, body in pending.items():
        _publish(directory / name, body, offline=name == MASTER_KEY_REF, replace=replace and name in imports)
    return len(pending)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['ensure', 'check-compose'])
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--compose', type=Path, action='append', default=[])
    parser.add_argument('--agents', action='store_true')
    parser.add_argument('--offline-root-dir', type=Path)
    parser.add_argument('--tls-name', action='append')
    parser.add_argument('--import-file', action='append', default=[], metavar='NAME=PATH')
    parser.add_argument('--replace', action='store_true',
                        help='Atomically replace one explicitly imported notification credential')
    parser.add_argument('--agent-secrets-from', type=Path,
                        help='Import the protected existing online agent trust bundle')
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest()
        selected = set()
        if args.compose:
            import yaml
            for path in args.compose:
                config = yaml.safe_load(path.read_text('utf-8'))
                validate_compose(config, manifest)
                selected.update(config.get('secrets', {}))
                for service in config.get('services', {}).values():
                    selected.update(item if isinstance(item, str) else item['source']
                                    for item in service.get('secrets', []))
                # Provisioning always uses one host directory. Refuse custom
                # paths rather than falsely claim that Compose will mount it.
                for name, definition in config.get('secrets', {}).items():
                    source = definition.get('file', '')
                    expected = re.fullmatch(r'\$\{SLI_SECRETS_DIR(?::\?[^}]*)?\}/' + re.escape(name), source)
                    if name in AGENT_FILE_SETTINGS:
                        setting = AGENT_FILE_SETTINGS[name]
                        fallback = '${' + setting + ':-${SLI_SECRETS_DIR}/' + name + '}'
                        if source == fallback:
                            target = args.directory or os.environ.get('SLI_SECRETS_DIR')
                            override = os.environ.get(setting)
                            expected = not override or (target is not None and
                                                        Path(override) == Path(target) / name)
                    if args.action == 'ensure' and not expected:
                        raise SecretError('compose: secret_directory_layout_required')
        if args.action == 'check-compose':
            if not args.compose:
                raise SecretError('compose_files_required')
            print('sli-secrets: compose manifest checked')
            return 0
        directory = args.directory or (Path(os.environ['SLI_SECRETS_DIR'])
                                       if os.environ.get('SLI_SECRETS_DIR') else None)
        if directory is None:
            raise SecretError('secret_directory_required')
        if not selected:
            notification_only = (args.import_file and not args.agents and not args.agent_secrets_from
                                 and all(item.partition('=')[0] in {*NOTIFICATION_SECRET_SETTINGS, MASTER_KEY_REF}
                                         for item in args.import_file))
            groups = set() if notification_only else {'agents'} if args.agent_secrets_from else {'core', 'tls'}
            selected = {name for name, spec in manifest.items() if spec['group'] in groups}
        if args.agents or args.agent_secrets_from:
            selected.update(name for name, spec in manifest.items() if spec['group'] == 'agents')
        imports = agent_imports(args.agent_secrets_from) if args.agent_secrets_from else {}
        for item in args.import_file:
            name, separator, path = item.partition('=')
            if not separator or name not in manifest or name in imports:
                raise SecretError('import_arguments_invalid')
            if name in NOTIFICATION_SECRET_SETTINGS or name == MASTER_KEY_REF:
                selected.add(name)
            if name not in selected:
                raise SecretError('import_arguments_invalid')
            imports[name] = Path(path)
        count = ensure(directory, names=sorted(selected), imports=imports, tls_names=args.tls_name,
                       offline_root_dir=args.offline_root_dir, replace=args.replace)
        print(f'sli-secrets: checked; created {count} files')
        return 0
    except SecretError as exc:
        print(f'sli-secrets: {exc}', file=sys.stderr)
    except Exception:  # noqa: BLE001 -- never expose OS paths, material or tracebacks
        print('sli-secrets: operation_failed_check_directory_and_permissions', file=sys.stderr)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())

