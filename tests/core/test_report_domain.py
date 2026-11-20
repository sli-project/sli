from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from server.sli.core import platform_settings, report_domain
from server.sli.core.report_domain import ReportDomainNotConfiguredError, report_domain_fqdn

ENV_NAME = "ADLOG_REPORT_DOMAIN_FQDN"

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _no_stored_value(monkeypatch: pytest.MonkeyPatch):
    platform_settings.clear_cache()
    monkeypatch.setattr(platform_settings.database, "query_rows", lambda *_a, **_k: [])
    yield
    platform_settings.clear_cache()


def test_not_configured_raises_specific_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_NAME, raising=False)
    with pytest.raises(ReportDomainNotConfiguredError, match="report_domain_not_configured"):
        report_domain_fqdn()
    with pytest.raises(ReportDomainNotConfiguredError):
        platform_settings.get_setting("reports.domain_fqdn")


def test_blank_environment_counts_as_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_NAME, "   ")
    with pytest.raises(ReportDomainNotConfiguredError):
        report_domain_fqdn()


def test_not_configured_is_not_a_value_error() -> None:
    # Route handlers map ValueError to HTTP 400; an unset domain is an installation state.
    assert not issubclass(ReportDomainNotConfiguredError, ValueError)


@pytest.mark.parametrize("name", [ENV_NAME, "SLI_INSTALL_DOMAIN", "REPORT_DOMAIN", "DEFAULT_DOMAIN"])
def test_environment_cannot_supply_runtime_domain(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv(name, "env.example.invalid")
    with pytest.raises(ReportDomainNotConfiguredError):
        report_domain_fqdn()


def test_database_setting_is_normalized(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_NAME, " Corp.Example.TEST ")
    monkeypatch.setattr(platform_settings.database, "query_rows", lambda *_a, **_k: [{"value": " DB.Example.Invalid "}])
    assert report_domain_fqdn() == "db.example.invalid"


@pytest.mark.parametrize("value", ["example", "a'b.test", "a b.test", "-a.test", "a.test;drop", "a..test"])
def test_rejects_values_unsafe_for_sql_literal(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setattr(platform_settings.database, "query_rows", lambda *_a, **_k: [{"value": value}])
    with pytest.raises(ValueError):
        report_domain_fqdn()


def test_report_domain_module_has_no_built_in_domain() -> None:
    path = ROOT / "server/sli/core/report_domain.py"
    dns_like = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+", re.IGNORECASE)
    strings = [
        node.value for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    # A built-in default would be a short DNS-like string constant.
    offenders = [text for text in strings if len(text) < 80 and "\n" not in text and dns_like.fullmatch(text.strip())]
    assert offenders == []
    assert not hasattr(report_domain, "_DEFAULT_FQDN")
