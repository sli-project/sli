from __future__ import annotations

import hashlib
import io
import json
from copy import deepcopy
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler

import pytest

from server.api import http_server
from server.api.routes import plugin_ui
from server.sli.plugins import ui_assets

PLUGIN_ID = "sli.remote-access"
PAYLOAD = b"export function createPlugin() { return {mount() {}, unmount() {}}; }\n"


@pytest.fixture
def package(tmp_path, monkeypatch):
    root = tmp_path / "ui"
    directory = root / PLUGIN_ID
    directory.mkdir(parents=True)
    descriptor = {
        "plugin_id": PLUGIN_ID,
        "ui_api": ui_assets.UI_API,
        "version": "1.0.0",
        "routes": [f"/extensions/{PLUGIN_ID}/accounts"],
        "entry": {"path": "entry.js", "sha256": hashlib.sha256(PAYLOAD).hexdigest()},
        "required_capabilities": ["reports.catalog"],
    }
    (directory / "entry.js").write_bytes(PAYLOAD)
    (directory / "descriptor.json").write_text(json.dumps(descriptor), encoding="utf-8")
    monkeypatch.setenv("SLI_PLUGIN_UI_DIR", str(root))
    return directory, descriptor


@pytest.mark.parametrize("path", [
    "../entry.js", "assets/../entry.js", "/entry.js", "C:/entry.js",
    "assets\\entry.js", "assets/%2e%2e/entry.js", "https://example.invalid/entry.js",
    "//example.invalid/entry.js", "entry.js?cache=1", "entry.js#fragment",
])
def test_rejects_remote_or_traversing_asset_paths(package, path):
    _, descriptor = package
    descriptor["entry"]["path"] = path
    with pytest.raises(ui_assets.PluginUiError, match="plugin_ui_invalid_descriptor"):
        ui_assets.validate_descriptor(descriptor, PLUGIN_ID)


@pytest.mark.parametrize("plugin_id", ["../plugin", "sli/remote-access", "%2e%2e", "sli\\remote-access"])
def test_rejects_plugin_directory_traversal(plugin_id):
    with pytest.raises(ui_assets.PluginUiError, match="plugin_ui_invalid_descriptor"):
        ui_assets.load_package(plugin_id)


def test_unknown_ui_api_is_rejected(package):
    _, descriptor = package
    descriptor["ui_api"] = "sli.plugin-ui.v99"
    with pytest.raises(ui_assets.PluginUiError, match="plugin_ui_unsupported_api"):
        ui_assets.validate_descriptor(descriptor, PLUGIN_ID)


@pytest.mark.parametrize("change", [
    {"version": "future"}, {"routes": ["/settings"]},
    {"routes": [f"/extensions/{PLUGIN_ID}/../settings"]},
    {"routes": [f"/extensions/{PLUGIN_ID}/accounts"] * 2},
    {"required_capabilities": ["reports.catalog"] * 2},
    {"required_capabilities": [42]}, {"remote_url": "https://example.invalid"},
])
def test_invalid_descriptor_contract(package, change):
    _, descriptor = package
    descriptor.update(change)
    with pytest.raises(ui_assets.PluginUiError, match="plugin_ui_invalid_descriptor"):
        ui_assets.validate_descriptor(descriptor, PLUGIN_ID)


def test_hash_mismatch_is_rejected_before_serving_descriptor(package):
    directory, _ = package
    (directory / "entry.js").write_bytes(b"changed")
    with pytest.raises(ui_assets.PluginUiError, match="plugin_ui_integrity_failed"):
        ui_assets.load_package(PLUGIN_ID)


def test_missing_package_is_distinct_from_a_corrupt_package(package):
    with pytest.raises(ui_assets.PluginUiError, match="plugin_ui_not_installed"):
        ui_assets.load_package("sli.fixture")
    directory, _ = package
    (directory / "descriptor.json").write_text("{", encoding="utf-8")
    with pytest.raises(ui_assets.PluginUiError, match="plugin_ui_invalid_descriptor"):
        ui_assets.load_package(PLUGIN_ID)


@pytest.mark.parametrize("target", ["entry.js", "descriptor.json", "directory"])
def test_symlinks_are_rejected(package, tmp_path, target):
    directory, descriptor = package
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "entry.js").write_bytes(PAYLOAD)
    (outside / "descriptor.json").write_text(json.dumps(descriptor), encoding="utf-8")
    if target == "directory":
        for child in directory.iterdir():
            child.unlink()
        directory.rmdir()
        directory.symlink_to(outside, target_is_directory=True)
    else:
        (directory / target).unlink()
        (directory / target).symlink_to(outside / target)
    with pytest.raises(ui_assets.PluginUiError, match="plugin_ui_invalid_descriptor"):
        ui_assets.load_package(PLUGIN_ID)


def _handler(monkeypatch, path, denied=None):
    monkeypatch.setattr(BaseHTTPRequestHandler, "end_headers", lambda self: None)
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    handler = object.__new__(http_server.RequestHandler)
    handler.path = path
    handler.wfile = io.BytesIO()
    handler.sent_headers = []
    handler.responses = []
    handler.json_responses = []
    handler.capabilities = []
    handler.send_response = lambda status: handler.responses.append(status)
    handler.send_header = lambda key, value: handler.sent_headers.append((key, value))
    handler._secure_transport = lambda: False

    def require(capability):
        handler.capabilities.append(capability)
        if capability == denied:
            handler._send_json({"error": "insufficient_permissions"}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def send_json(payload, status=HTTPStatus.OK):
        handler.json_responses.append((deepcopy(payload), status))
        handler.send_response(status)
        handler.end_headers()

    handler._require_capability = require
    handler._send_json = send_json
    return handler


def test_descriptor_dispatches_through_existing_authenticated_ui_policy(package, monkeypatch):
    _, descriptor = package
    handler = _handler(monkeypatch, f"{plugin_ui.PREFIX}{PLUGIN_ID}/descriptor")
    handler._do_GET()
    assert handler.json_responses == [(descriptor, HTTPStatus.OK)]
    assert set(handler.capabilities) == {"workspace.view", "reports.catalog"}


@pytest.mark.parametrize("denied", ["workspace.view", "reports.catalog"])
def test_missing_capability_never_delivers_plugin_code(package, monkeypatch, denied):
    _, descriptor = package
    path = f"{plugin_ui.PREFIX}{PLUGIN_ID}/assets/{descriptor['entry']['sha256']}/entry.js"
    handler = _handler(monkeypatch, path, denied=denied)
    handler._do_GET()
    assert handler.responses == [HTTPStatus.FORBIDDEN]
    assert handler.wfile.getvalue() == b""


def test_descriptor_and_asset_require_a_session(package, monkeypatch):
    monkeypatch.setattr(http_server, "principal_from_headers", lambda headers: None)
    for suffix in ["descriptor", f"assets/{'a' * 64}/entry.js"]:
        handler = _handler(monkeypatch, f"{plugin_ui.PREFIX}{PLUGIN_ID}/{suffix}")
        monkeypatch.setattr(http_server, "auth_required", lambda: True)
        handler.headers = {}
        handler._do_GET()
        assert handler.responses == [HTTPStatus.UNAUTHORIZED]
        assert not handler.capabilities
        assert handler.wfile.getvalue() == b""


def test_asset_response_uses_checked_bytes_and_unchanged_csp(package, monkeypatch):
    _, descriptor = package
    path = f"{plugin_ui.PREFIX}{PLUGIN_ID}/assets/{descriptor['entry']['sha256']}/entry.js"
    handler = _handler(monkeypatch, path)
    handler._do_GET()
    assert handler.responses == [HTTPStatus.OK]
    assert handler.wfile.getvalue() == PAYLOAD
    headers = dict(handler.sent_headers)
    assert headers["Content-Type"] == "application/javascript; charset=utf-8"
    assert headers["Content-Length"] == str(len(PAYLOAD))
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store, max-age=0"
    assert headers["Content-Security-Policy"] == (
        "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; "
        "img-src 'self' data:; style-src 'self'; style-src-attr 'unsafe-inline'; "
        "script-src 'self'; script-src-attr 'none'"
    )


@pytest.mark.parametrize("suffix", [f"assets/{'0' * 64}/entry.js", "assets/{digest}/../entry.js", "assets/{digest}/other.js"])
def test_asset_address_cannot_bypass_integrity_or_path_binding(package, monkeypatch, suffix):
    _, descriptor = package
    handler = _handler(monkeypatch, f"{plugin_ui.PREFIX}{PLUGIN_ID}/" + suffix.format(digest=descriptor["entry"]["sha256"]))
    handler._do_GET()
    assert handler.responses == [HTTPStatus.CONFLICT]
    assert handler.wfile.getvalue() == b""


def test_update_between_descriptor_read_and_import_fails_closed(package, monkeypatch):
    directory, descriptor = package
    old_hash = descriptor["entry"]["sha256"]
    new_payload = PAYLOAD + b"// updated\n"
    (directory / "entry.js").write_bytes(new_payload)
    descriptor["entry"]["sha256"] = hashlib.sha256(new_payload).hexdigest()
    (directory / "descriptor.json").write_text(json.dumps(descriptor), encoding="utf-8")
    handler = _handler(monkeypatch, f"{plugin_ui.PREFIX}{PLUGIN_ID}/assets/{old_hash}/entry.js")
    handler._do_GET()
    assert handler.responses == [HTTPStatus.CONFLICT]
    assert handler.wfile.getvalue() == b""


def test_corrupt_installed_package_returns_honest_unavailable_state(package, monkeypatch):
    directory, _ = package
    (directory / "entry.js").write_bytes(b"changed")
    handler = _handler(monkeypatch, f"{plugin_ui.PREFIX}{PLUGIN_ID}/descriptor")
    handler._do_GET()
    assert handler.json_responses == [({"error": "plugin_ui_integrity_failed", "state": "unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)]


def test_serves_nested_local_asset(package, monkeypatch):
    directory, descriptor = package
    (directory / "assets").mkdir()
    (directory / "entry.js").rename(directory / "assets" / "entry.js")
    descriptor["entry"]["path"] = "assets/entry.js"
    (directory / "descriptor.json").write_text(json.dumps(descriptor), encoding="utf-8")
    handler = _handler(monkeypatch, f"{plugin_ui.PREFIX}{PLUGIN_ID}/assets/{descriptor['entry']['sha256']}/assets/entry.js")
    handler._do_GET()
    assert handler.wfile.getvalue() == PAYLOAD
