"""The source gate rejects new tenant defaults without disclosing their values."""

from pathlib import Path

import pytest

from scripts.maintenance.check_ui_domain_binding import ROOT, findings, scan


@pytest.mark.parametrize("value", [
    "tenant.local", "dc1.tenant.lan", "tenant.ru", "tenant.com", "TENANT.INTERNAL",
    "https://tenant.unlisted/path", "https://tenant.example.com.evil/path", "10.23.45.67",
])
def test_rejects_embedded_hosts_without_printing_them(value):
    result = findings("frontend/src/new.tsx", f'const host = "{value}";')
    assert result == ["frontend/src/new.tsx:1:embedded_host"]
    assert value not in "".join(result)


@pytest.mark.parametrize("value", [
    "corp.example", "dc1.corp.example.test", "corp.example.com", "example.invalid",
    "http://127.0.0.1:8080", "http://[::1]:8080", "192.0.2.13",
    "https://learn.microsoft.com/path", "http://schemas.microsoft.com/win/2004/08/events/event",
])
def test_allows_only_reserved_examples_loopback_and_exact_service_hosts(value):
    assert findings("server/new.py", f'HOST = "{value}"') == []


def test_language_identifiers_are_exempt_only_in_their_own_files():
    text = '"shell.profile.language.ru": "Русский"'
    assert findings("frontend/src/i18n/ru.ts", text) == []
    assert findings("frontend/src/new.tsx", text)
    assert findings("frontend/src/i18n/ru.ts", text + '\n"tenant.ru"')


@pytest.mark.parametrize("text", [
    'const defaultDomain = "tenant.unlisted";',
    '"hostname": "dc1.tenant.unlisted"',
    '"email": "fixture@tenant.unlisted"',
])
def test_configuration_and_mail_literals_cannot_bypass_the_suffix_list(text):
    assert findings("frontend/src/new.tsx", text) == ["frontend/src/new.tsx:1:embedded_host"]


def test_template_urls_query_values_and_url_validation_patterns_are_not_hosts():
    assert findings("frontend/src/new.tsx", '`http://localhost${path}`') == []
    assert findings("frontend/src/new.tsx", '"?return_to=https://outside.invalid&key=value"') == []
    assert findings("server/new.py", 'r"https://raw\\.githubusercontent\\.com/path"') == []


def test_scan_includes_frontend_tests_and_server_sources(tmp_path: Path):
    for name in ("frontend/src/new.test.tsx", "server/new.py"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('HOST = "tenant.local"', encoding="utf-8")
    assert scan(tmp_path) == [
        "frontend/src/new.test.tsx:1:embedded_host", "server/new.py:1:embedded_host",
    ]


def test_ui_and_api_have_no_embedded_installation_hosts():
    # Paths only: an injected real host must not leak through pytest diagnostics.
    assert scan(ROOT) == []
