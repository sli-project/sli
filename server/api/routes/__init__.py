"""Domain route modules for the SLI HTTP API.

Each module exports `try_handle_get(handler, path, query) -> bool` and,
where the domain has mutation routes, `try_handle_post(handler, path) ->
bool` (no `body` argument -- the handler reads it lazily itself via
`handler._read_json_body()` once a route has actually matched). A domain
module never imports `server.api.http_server`; it may import
`server.app.*`, `server.jobs.*`, `server.api.errors`, `server.api.net_utils`,
`server.api.routes.*`, and the standard library. Each module also declares
`ROUTES` -- the `(method, pattern)` pairs it serves -- and `http_server.py`
dispatches through `server.api.route_registry`, which picks the most
specific match instead of relying on module order (ADR 0014, plan 4.3).
"""
