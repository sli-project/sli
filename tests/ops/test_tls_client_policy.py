from __future__ import annotations

import pytest

from server.sli.ops.tls_client import tls_context_for_url


def test_tls_verification_is_default_even_for_loopback() -> None:
    assert tls_context_for_url("https://127.0.0.1:8080/api/health") is None
    assert tls_context_for_url("https://localhost/api/health") is None


def test_explicit_insecure_tls_is_loopback_only() -> None:
    assert tls_context_for_url("https://127.0.0.1:8080/api/health", insecure=True) is not None
    assert tls_context_for_url("https://[::1]:8080/api/health", insecure=True) is not None
    with pytest.raises(ValueError, match="limited_to_loopback"):
        tls_context_for_url("https://example.com/api/health", insecure=True)
    with pytest.raises(ValueError, match="requires_https"):
        tls_context_for_url("http://127.0.0.1:8080/api/health", insecure=True)
