"""Telegram proxy installation and real updater lifecycle, no network/Docker."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import installation, sli_install, sli_secrets
from tests.unit.test_sli_update import release as release, retained_volume_overlay
from tests.unit.test_sli_installation import fake_backup_volume_layout as fake_backup_volume_layout, fresh as fresh


@pytest.fixture
def config_files(tmp_path, monkeypatch):
    monkeypatch.setattr(installation, 'validate_compose', lambda config: None)
    monkeypatch.setattr(installation, 'ensure', lambda *args, **kwargs: None)
    monkeypatch.setattr(sli_secrets, '_check_owner', lambda *args: None)
    monkeypatch.setattr(sli_secrets.os, 'chown', lambda *args: None)
    directory = tmp_path / 'secrets'
    directory.mkdir()
    config = {'services': {'notification-setup': {'environment': {'SLI_PUBLIC_URL': 'https://sli.example.invalid/api/health/ready'}}}}
    return config, directory


def test_create_secrets_writes_proxy_to_existing_telegram_file_without_touching_other_values(config_files):
    config, directory = config_files
    private = directory / 'notifications'
    sli_secrets._directory(private)
    prior = {'base_url': 'https://sli.example.invalid/app','recipients': {'1':'synthetic-chat'},'names':{'1':'Synthetic'}}
    sli_secrets._publish(private/'telegram.json', json.dumps(prior).encode())
    sli_secrets._publish(private/'notification_telegram_token', b'synthetic-token')
    installation.create_secrets(config,directory,{},notification={'proxy_url':'http://proxy.example.invalid:3128'})
    saved = json.loads((private/'telegram.json').read_text())
    assert saved == prior | {'proxy_url':'http://proxy.example.invalid:3128'}
    token = (private/'notification_telegram_token').read_bytes()
    before = (private/'telegram.json').read_bytes()
    installation.create_secrets(config,directory,{})
    assert (private/'telegram.json').read_bytes() == before
    installation.create_secrets(config,directory,{},notification={'proxy_url':''})
    assert json.loads((private/'telegram.json').read_text()) == prior | {'proxy_url':''}
    assert (private/'notification_telegram_token').read_bytes() == token
    assert (private/'telegram.json').stat().st_mode & 0o777 == 0o640


def test_fresh_config_proxy_uses_existing_setup_base_url_contract(config_files):
    config,directory = config_files
    installation.create_secrets(config,directory,{},notification={'proxy_url':'http://proxy.example.invalid:3128'})
    saved=json.loads((directory/'notifications/telegram.json').read_text())
    assert saved == {'base_url':'https://sli.example.invalid/app','recipients':{},'names':{},'proxy_url':'http://proxy.example.invalid:3128'}


@pytest.mark.parametrize('proxy', ['https://proxy:443','http://user:secret@proxy:3128','http://proxy:3128/','http://proxy','http://proxy:0'])
def test_invalid_proxy_is_rejected_before_secret_provisioning(config_files,monkeypatch,proxy):
    from server.sli.core.telegram_setup import TelegramSetupError
    config,directory=config_files
    writes=[]
    monkeypatch.setattr(installation,'ensure',lambda *args,**kwargs:writes.append('ensure'))
    with pytest.raises(TelegramSetupError):
        installation.create_secrets(config,directory,{},notification={'proxy_url':proxy})
    assert not writes
    assert not (directory/'notifications').exists()


def test_install_cli_forwards_explicit_notification_proxy(tmp_path,monkeypatch,capsys):
    seen={}
    monkeypatch.setattr(sli_install,'InstallationHost',lambda *args:SimpleNamespace(environment={}))
    monkeypatch.setattr(sli_install,'install',lambda *args,**kwargs:seen.update(kwargs) or {'status':'fixture'})
    argv=['--package','fixture.zip','--compose','fixture.yml','--ca-file','ca.pem','--tls-certificate','cert.pem',
          '--tls-key','key.pem','--evaluation','--kit','kit','--inventory-sha256','a'*64,'--notification-proxy-url','http://proxy.example.invalid:3128']
    assert sli_install.main(argv)==0
    assert seen['notification']=={'proxy_url':'http://proxy.example.invalid:3128'}
    assert 'synthetic-token' not in capsys.readouterr().out


def test_real_updater_apply_preserves_setup_saved_proxy_and_notification_mount(release,monkeypatch):
    updater,host,archive,*_=release
    target,_,_=retained_volume_overlay(release,monkeypatch)
    private=updater.runtime/'secrets/notifications'
    private.mkdir(parents=True)
    path=private/'telegram.json'
    before=b'{"base_url":"https://sli.example.invalid/app","recipients":{"1":"synthetic"},"names":{},"proxy_url":"http://proxy.example.invalid:3128"}\n'
    path.write_bytes(before)
    token=private/'notification_telegram_token'
    token.write_bytes(b'synthetic-token')
    overlay=json.loads(target.read_text())
    mount={'type':'bind','source':str(private),'target':'/var/lib/notification-secrets','read_only':True}
    overlay['services']['notification-delivery']['volumes']=[mount]
    from deploy.linux.sli_update import atomic_json
    atomic_json(target,overlay)
    assert updater.apply(archive)=='committed'
    assert path.read_bytes()==before and token.read_bytes()==b'synthetic-token'
    saved=json.loads(target.read_text())
    assert saved['services']['notification-delivery']['volumes']==[mount]
    assert any(m['target']=='/run/notification-setup' for m in saved['services']['api']['volumes'])

def test_actual_install_forwards_notification_into_protected_config(fresh, monkeypatch):
    archive,trust,runtime,host,tls=fresh
    original=host.fresh_config

    def with_setup(path):
        config,override=original(path)
        config['services']['notification-setup']={'environment':{'SLI_PUBLIC_URL':'https://sli.example.invalid/api/health/ready'}}
        return config,override

    monkeypatch.setattr(host,'fresh_config',with_setup)
    result=installation.install(archive,trust,runtime,host,tls,notification={'proxy_url':'http://proxy.example.invalid:3128'})
    assert result['status']=='installed'
    path=runtime/'secrets/notifications/telegram.json'
    assert json.loads(path.read_text())=={'base_url':'https://sli.example.invalid/app','recipients':{},'names':{},'proxy_url':'http://proxy.example.invalid:3128'}
    assert path.stat().st_mode & 0o777==0o640
