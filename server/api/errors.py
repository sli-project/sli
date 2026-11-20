"""Shared HTTP-adjacent error type with no dependency on RequestHandler.

Exists so that both `server.api.http_server` (which catches this in its
`do_GET`/`do_POST` wrappers) and a domain module in `server.api.routes`
(which must not import `server.api.http_server`, to avoid a
domain_routes -> http_server -> domain_routes cycle) can raise the same
error type without duplicating it.
"""
from __future__ import annotations

from http import HTTPStatus


class RequestInputError(ValueError):
    """A safe, client-visible error for malformed or oversized API input."""

    def __init__(self, code: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        super().__init__(code)
        self.code = code
        self.status = status
