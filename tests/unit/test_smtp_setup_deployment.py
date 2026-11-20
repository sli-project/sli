"""The managed SMTP extension retains the existing private mounts and identities."""
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml

from deploy.linux import sli_secrets, sli_update
from server.sli.core import notification_outbox as outbox
from tests.unit.test_notification_channels import Connection

ROOT = Path(__file__).resolve().parents[2]


def test_static_and_canonical_smtp_use_existing_readonly_directory():
    static = yaml.safe_load((ROOT / "deploy/linux/docker-compose.yml").read_text())
    dynamic = sli_update.notification_services("synthetic-image", "/synthetic/notifications-root", "https://example.invalid")
    for services in (static["services"], dynamic):
        worker = services["notification-delivery"]
        assert worker["environment"]["SLI_NOTIFICATION_SMTP_PASSWORD_FILE"] == "/var/lib/notification-secrets/notification_smtp_password"
        assert worker["environment"]["SLI_NOTIFICATION_SMTP_CONFIG_FILE"] == "/var/lib/notification-secrets/smtp.json"
        assert worker["secrets"] == ["notification_db_password"]
        assert len(worker["volumes"]) == 1
        sli_secrets.validate_compose({"services": {"notification-delivery": worker}, "secrets": {"notification_db_password": {}}})


@pytest.mark.parametrize("service,path,readonly", [("api", "/var/lib/notification-secrets/notification_smtp_password", True),
    ("notification-delivery", "/var/lib/notification-secrets/other", True),
    ("notification-delivery", "/var/lib/notification-secrets/notification_smtp_password", False)])
def test_smtp_private_exception_stays_exact(service, path, readonly):
    config = {"services": {service: {"environment": {"SLI_NOTIFICATION_SMTP_PASSWORD_FILE": path},
        "volumes": [{"type": "bind", "source": "/synthetic/notifications", "target": "/var/lib/notification-secrets", "read_only": readonly}]}}}
    with pytest.raises(sli_secrets.SecretError):
        sli_secrets.validate_compose(config)


def test_managed_worker_claim_is_bounded_to_notifications(monkeypatch):
    conn = Connection(conflict=True)
    monkeypatch.setattr(outbox, "connect", lambda: conn)
    assert outbox.claim_job(telegram=True, notification_only=True) is None
    sql = conn.events[0][0]
    assert "channel in ('telegram','smtp')" in sql
    assert "object_kind in ('test_problem','semantic_finding')" in sql
    assert "next_delivery_at" in sql


def test_managed_mode_routes_claim_to_bounded_filter(monkeypatch):
    claim = Mock(return_value=None)
    monkeypatch.setattr(outbox, "claim_job", claim)
    assert not outbox.process_one(smtp=True, telegram=True, notification_only=True)
    claim.assert_called_once_with(telegram=True, notification_only=True)
