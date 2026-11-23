"""Exercise native restores with private files and real certificates."""
from contextlib import nullcontext
import json
from pathlib import Path
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from deploy.linux import native_restore as restore, sli_secrets
from server.sli.agents.ca import IssuingCA


def issuing_ca(material):
    return IssuingCA(x509.load_pem_x509_certificate(material['agent_root_certificate']),
                     x509.load_pem_x509_certificate(material['agent_issuer_certificate']),
                     serialization.load_pem_private_key(material['agent_issuer_key'], password=None))


@pytest.mark.parametrize('fresh', [True, False])
def test_restore_returns_files_settings_and_original_agent_trust(tmp_path, monkeypatch, fresh):
    companion = tmp_path / 'companion'
    source = companion / 'secrets'
    source.mkdir(parents=True)
    agents, _ = sli_secrets._agent_bundle()
    tls = sli_secrets._tls_bundle(['example.test'])
    credentials = agents | tls | {'platform_owner_password': b'fixture-owner-password'}
    for name, body in credentials.items():
        (source / name).write_bytes(body)
    agent = '00000000-0000-4000-8000-000000000001'
    host = '00000000-0000-4000-8000-000000000002'
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).sign(key, sli_secrets.hashes.SHA256())
    registered = issuing_ca(agents).issue(csr, agent, host).public_bytes(serialization.Encoding.DER)
    data = tmp_path / 'backup' / 'data'
    (data / 'files' / 'spool').mkdir(parents=True)
    (data / 'files' / 'spool' / 'packet').write_text('saved packet')
    live = tmp_path / 'live'
    live.mkdir()
    if not fresh:
        (live / 'superseded').write_text('later packet')
    monkeypatch.setattr(restore.native, 'DATA', live)
    monkeypatch.setattr(restore.restore_existing, 'native_files_destination', lambda path: False)
    site = {'server_name': 'example.test', 'bind': '192.0.2.17', 'https_port': 443, 'agents': True}
    config = {'agents': True, 'profiles': ['light'], 'bind': '192.0.2.17'}
    local_site = tmp_path / 'site.toml'
    local_runtime = tmp_path / 'runtime.json'
    local_secrets = tmp_path / 'live-secrets'
    local_secrets.mkdir()
    monkeypatch.setattr(restore.install, 'SITE', local_site)
    monkeypatch.setattr(restore.install, 'SECRETS', local_secrets)
    monkeypatch.setattr(restore.runtime, 'CONFIG', local_runtime)
    monkeypatch.setattr(restore, 'write_secret', Path.write_bytes)
    monkeypatch.setattr(restore, 'replace_text', lambda path, body, **kw: path.write_text(body))
    configure = []
    monkeypatch.setattr(restore.runtime, 'configure', configure.append)
    monkeypatch.setattr(sli_secrets, '_check_path', lambda path, **kw: None)
    postgres = []
    monkeypatch.setattr(restore.restore_existing, 'restore_postgres', lambda *args, **kw: postgres.append((args, kw)))
    monkeypatch.setattr(restore.install, 'command', lambda *args, **kw: None)

    material = restore.secret_material(companion, config)
    postgres_manifest = {'components': {'postgres': {'row_counts': {'agents': 1}}}}
    restore.apply_data(data, postgres_manifest, config, site, material, fresh=fresh)

    assert (live / 'spool' / 'packet').read_text() == 'saved packet'
    assert not (live / 'superseded').exists()
    assert configure == [config]
    assert postgres == [((data, postgres_manifest), {'replace_existing': True, 'use_default_tablespace': True})]
    if not fresh:
        assert restore.parse_site(local_site.read_text())['server_name'] == 'example.test'
        assert json.loads(local_runtime.read_text())['agents'] is True
    restored = {path.name: path.read_bytes() for path in local_secrets.iterdir()}
    assert restored['tls_ca'] == tls['tls_ca']
    assert issuing_ca(restored).verify_client(registered).public_bytes(serialization.Encoding.DER) == registered


def test_rollback_preserves_current_data_before_replaying_the_accepted_checkpoint(tmp_path, monkeypatch):
    commands = []
    timer = SimpleNamespace(state='disabled')
    source = SimpleNamespace(path=tmp_path / 'source', value={'previous': 'beta-old',
                             'previous_version': '1.0-1~deb13', 'checkpoint': 'backup'})
    journal = SimpleNamespace(path=tmp_path / 'rollback', value={'status': 'recovering'}, write=lambda: None)
    monkeypatch.setattr(restore, 'setup_lock', nullcontext)
    monkeypatch.setattr(restore.host, 'Host', lambda: SimpleNamespace(require_backup_mount=lambda: None))
    monkeypatch.setattr(restore.upgrade, 'operation_lock', lambda _: nullcontext())
    monkeypatch.setattr(restore, 'pending', lambda _: None)
    monkeypatch.setattr(restore.runtime, 'no_transaction', lambda: None)
    monkeypatch.setattr(restore.runtime, 'release', lambda: (Path('/opt/sli/releases/beta-new'),))
    monkeypatch.setattr(restore, 'previous_update', lambda release: source if release == 'beta-new' else None)
    monkeypatch.setattr(restore.install, 'inventory', lambda release: (tmp_path / release, {}, 'digest'))
    monkeypatch.setattr(restore.upgrade, 'verify_recovery', lambda _: ('recovery', None))
    monkeypatch.setattr(restore.upgrade, 'checkpoint_receipt', lambda _: commands.append('verify'))
    monkeypatch.setattr(restore.upgrade, 'checkpoint_root', lambda _: tmp_path)
    monkeypatch.setattr(restore.native, 'verify', lambda _: None)
    def apt(*args, download_only=False):
        commands.append('download' if download_only else 'downgrade')
        if not download_only:
            timer.state = 'enabled'  # Old package postinst did this during downgrade.

    def systemctl(argv, **kwargs):
        assert argv == ['systemctl', 'disable', '--now', 'sli-backup.timer']
        commands.append('disable-backup')
        timer.state = 'disabled'

    monkeypatch.setattr(restore, 'apt_rollback', apt)
    monkeypatch.setattr(restore.install, 'command', systemctl)
    monkeypatch.setattr(restore.install, 'backup_schedule', lambda: timer.state)
    monkeypatch.setattr(restore, 'begin', lambda *args, **kw: journal)
    monkeypatch.setattr(restore.upgrade, 'fence', lambda: commands.append('fence'))
    monkeypatch.setattr(restore, 'save_current', lambda _: commands.append('preserve'))
    monkeypatch.setattr(restore.upgrade, 'restore_checkpoint', lambda _, committed_source: commands.append(committed_source.path.name))
    monkeypatch.setattr(restore.upgrade, 'switch', lambda root, *_: commands.append(root.name))
    monkeypatch.setattr(restore.upgrade, 'testing_units', lambda: None)
    monkeypatch.setattr(restore.upgrade, 'publish', lambda *args, **kw: None)
    monkeypatch.setattr(restore.upgrade, 'retained_runtime', lambda recovery: recovery)
    monkeypatch.setattr(restore, 'finish', lambda *args: commands.append('start'))

    restore.rollback()

    assert commands == ['verify', 'download', 'fence', 'preserve', 'source', 'beta-old', 'downgrade', 'disable-backup', 'start']
    assert journal.value['accepted_release'] == 'beta-old'
    assert journal.value['backup_schedule'] == timer.state == 'disabled'
