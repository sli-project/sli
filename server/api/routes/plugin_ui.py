"""Authenticated local UI descriptors and content-addressed entry modules."""
from __future__ import annotations

from http import HTTPStatus

from server.sli.plugins.ui_assets import PluginUiError, load_package

PREFIX = "/api/v1/ui/plugins/"
ROUTES = (("GET", "/api/v1/ui/plugins/*"),)


def try_handle_get(handler, path: str, query: dict) -> bool:
    if not path.startswith(PREFIX):
        return False
    parts = path[len(PREFIX):].split("/")
    descriptor_request = len(parts) == 2 and parts[1] == "descriptor"
    asset_request = len(parts) >= 4 and parts[1] == "assets"
    if not descriptor_request and not asset_request:
        handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return True
    if not handler._require_capability("workspace.view"):
        return True
    try:
        descriptor, payload = load_package(parts[0])
    except PluginUiError as exc:
        code = str(exc)
        status = HTTPStatus.NOT_FOUND if code == "plugin_ui_not_installed" else HTTPStatus.SERVICE_UNAVAILABLE
        handler._send_json({"error": code, "state": "unavailable"}, status)
        return True
    for capability in descriptor["required_capabilities"]:
        if not handler._require_capability(capability):
            return True
    if descriptor_request:
        handler._send_json(descriptor)
        return True
    # Bind both the verification fetch and the native ESM import to the same
    # bytes. Never re-open the file after checking its hash (update race).
    if parts[2] != descriptor["entry"]["sha256"] or "/".join(parts[3:]) != descriptor["entry"]["path"]:
        handler._send_json({"error": "plugin_ui_integrity_failed", "state": "unavailable"}, HTTPStatus.CONFLICT)
        return True
    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", "application/javascript; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)
    return True
