"""Opt-in deployment and console helper boundaries; no host policy changes."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_ca_overlay_limits_file_secrets_to_api_and_migrate():
    overlay = yaml.safe_load((ROOT / "deploy/linux/docker-compose.agent.yml").read_text("utf-8"))
    expected_secrets = {
        "agent_root_certificate": "SLI_AGENT_CA_ROOT_CERT_FILE",
        "agent_issuer_certificate": "SLI_AGENT_CA_ISSUER_CERT_FILE",
        "agent_issuer_key": "SLI_AGENT_CA_ISSUER_KEY_FILE",
        "agent_mtls_ca": "SLI_AGENT_MTLS_CA_FILE",
    }
    # Restore verifies the existing online trust bundle through migrate.
    assert set(overlay["services"]) == {"api", "migrate"}
    assert set(overlay["secrets"]) == set(expected_secrets)
    for service in overlay["services"].values():
        assert service["environment"] == {
            setting: env_value(secret) for secret, setting in expected_secrets.items()
        }
        assert set(service["secrets"]) == set(expected_secrets)
    for secret, setting in expected_secrets.items():
        assert overlay["secrets"][secret]["file"] == (
            "${" + setting + ":-${SLI_SECRETS_DIR}/" + secret + "}"
        )
    assert not any("root_key" in name for name in overlay["secrets"])


def env_value(secret):
    return "/run/secrets/" + secret
