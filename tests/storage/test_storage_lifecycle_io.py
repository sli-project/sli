from __future__ import annotations

import base64
import io

import pytest

from server.sli.storage import permanent_fact_history as history
from server.sli.storage import storage_lifecycle_io as transport
from server.sli.storage import warm_tier_incremental_copy_runtime as warm_copy


@pytest.fixture(autouse=True)
def isolated_warm_settings(monkeypatch):
    for prefix in (transport.WARM_ENV_PREFIX, "ADLOG_HISTORY_CLICKHOUSE_"):
        for key in ("HOST", "PORT", "USER", "PASSWORD", "PASSWORD_FILE"):
            monkeypatch.delenv(prefix + key, raising=False)
    monkeypatch.setattr(transport, "_docker", lambda *a, **kw: pytest.fail("unexpected Docker call"))


@pytest.fixture
def network_settings(monkeypatch, tmp_path):
    secret = tmp_path / "warm_password"
    secret.write_text("synthetic-password\n", encoding="utf-8")
    monkeypatch.setenv("ADLOG_WARM_CLICKHOUSE_HOST", "warm-tier")
    monkeypatch.setenv("ADLOG_WARM_CLICKHOUSE_PASSWORD_FILE", str(secret))
    return secret


@pytest.fixture
def http_calls(monkeypatch):
    calls = []

    class Connection:
        def __init__(self, host, port, *, timeout):
            self.call = {"host": host, "port": port, "timeout": timeout, "closed": False}
            calls.append(self.call)

        def request(self, method, path, *, body, headers):
            self.call.update(method=method, path=path, body=body, headers=headers)

        def getresponse(self):
            body = self.call["body"]
            payload = b"1\n" if body.startswith(b"SELECT count()") else b'{"value":1}\n'
            response = io.BytesIO(payload)
            response.status = 200
            return response

        def close(self):
            self.call["closed"] = True

    monkeypatch.setattr(transport.http.client, "HTTPConnection", Connection)
    return calls


def test_network_and_windows_fallback_send_identical_sql_and_batches(
    monkeypatch, network_settings, http_calls,
):
    rows = [{"event_id": 41}, {"event_id": 42}]
    monkeypatch.setenv("ADLOG_HISTORY_CLICKHOUSE_HOST", "clickhouse")

    def requests():
        port = transport._container_port(transport.CONTAINER)
        assert warm_copy._session_schema_present(port)
        assert warm_copy._clickhouse_json(port, "SELECT 1 value;") == [{"value": 1}]
        assert transport._http_insert_json_rows(
            port, "sli_warm.placement_input", iter(rows), timeout=45,
        ) == (2, False)
        transport._drop_database(port, "sli_warm_stage_test")
        assert list(transport._http_stream_json_rows(
            port, "SELECT 1 value FORMAT JSONEachRow", timeout=75,
            params={"readonly": "1", "max_threads": "1"},
        )) == [{"value": 1}]

    monkeypatch.setattr(transport.sys, "platform", "linux")
    requests()
    network = list(http_calls)
    assert all(call["host"] == "warm-tier" and call["port"] == 8123 for call in network)
    expected_auth = "Basic " + base64.b64encode(b"default:synthetic-password").decode("ascii")
    assert all(call["headers"]["Authorization"] == expected_auth for call in network)
    assert network[2]["body"] == (
        b'INSERT INTO sli_warm.placement_input FORMAT JSONEachRow\n'
        b'{"event_id":41}\n{"event_id":42}'
    )
    assert network[-1]["path"] == "/?readonly=1&max_threads=1"
    assert network[2]["timeout"] == 45
    assert network[-1]["timeout"] == 75

    for key in ("HOST", "PASSWORD_FILE"):
        monkeypatch.delenv(transport.WARM_ENV_PREFIX + key)
    monkeypatch.setattr(transport.sys, "platform", "win32")
    docker_calls = []

    def docker(args):
        docker_calls.append(args)
        return "127.0.0.1:57846"

    monkeypatch.setattr(transport, "_docker", docker)
    http_calls.clear()
    requests()
    assert docker_calls == [["port", "sli-warm-tier-step1", "8123/tcp"]]
    assert all(call["host"] == "127.0.0.1" and call["port"] == 57846 for call in http_calls)
    assert all("Authorization" not in call["headers"] for call in http_calls)
    assert [call["body"] for call in http_calls] == [call["body"] for call in network]
    assert all(call["closed"] for call in [*network, *http_calls])


def test_network_port_and_user_overrides(monkeypatch, network_settings, http_calls):
    monkeypatch.setenv("ADLOG_WARM_CLICKHOUSE_PORT", "18123")
    monkeypatch.setenv("ADLOG_WARM_CLICKHOUSE_USER", "warm_writer")
    port = transport._container_port(transport.CONTAINER)
    transport._http_query(port, "SELECT 1", timeout=15, params={"readonly": "1"})
    assert http_calls[0]["port"] == 18123
    assert http_calls[0]["headers"]["Authorization"] == (
        "Basic " + base64.b64encode(b"warm_writer:synthetic-password").decode("ascii")
    )
    assert http_calls[0]["path"] == "/?readonly=1"


def test_linux_without_network_settings_never_uses_docker(monkeypatch):
    monkeypatch.setattr(transport.sys, "platform", "linux")
    with pytest.raises(RuntimeError, match="^warm_clickhouse_settings_required$"):
        transport._container_port(transport.CONTAINER)


@pytest.mark.parametrize("key", ["HOST", "PORT", "USER", "PASSWORD_FILE"])
def test_partial_settings_never_fall_back_to_docker(monkeypatch, key):
    monkeypatch.setattr(transport.sys, "platform", "win32")
    monkeypatch.setenv(transport.WARM_ENV_PREFIX + key, "synthetic")
    with pytest.raises(RuntimeError, match="^warm_clickhouse_settings_incomplete$"):
        transport._container_port(transport.CONTAINER)


@pytest.mark.parametrize("port", ["invalid", "0", "65536"])
def test_invalid_network_port_is_rejected(monkeypatch, network_settings, port):
    monkeypatch.setenv("ADLOG_WARM_CLICKHOUSE_PORT", port)
    with pytest.raises(RuntimeError, match="^warm_clickhouse_port_invalid$"):
        transport._container_port(transport.CONTAINER)


@pytest.mark.parametrize("content", ["", "synthetic\nembedded", "synthetic\0password"])
def test_invalid_password_file_is_rejected(network_settings, content):
    network_settings.write_text(content, encoding="utf-8")
    with pytest.raises(RuntimeError, match="^warm_clickhouse_password_file_invalid$"):
        transport._container_port(transport.CONTAINER)


def test_missing_password_file_has_fixed_error(network_settings):
    network_settings.unlink()
    with pytest.raises(RuntimeError, match="^warm_clickhouse_password_file_unreadable$"):
        transport._container_port(transport.CONTAINER)


def test_configured_worker_secret_failure_never_falls_back_to_admin(monkeypatch, tmp_path):
    import psycopg

    monkeypatch.setenv('ADLOG_STORAGE_V2_WORKER_DSN', 'host=worker.invalid dbname=sli user=sli_storage_login')
    monkeypatch.setenv('ADLOG_STORAGE_V2_WORKER_PASSWORD_FILE', str(tmp_path / 'missing'))
    monkeypatch.setenv('ADLOG_PG_ADMIN_USER', 'postgres')
    monkeypatch.setenv('ADLOG_PG_ADMIN_PASSWORD', 'synthetic-forbidden-fallback')
    monkeypatch.setattr(psycopg, 'connect', lambda **kw: pytest.fail('connected after invalid worker secret'))
    with pytest.raises(ValueError, match='ADLOG_STORAGE_V2_WORKER_PASSWORD: secret file is unreadable or invalid'):
        transport._connect()


def test_empty_insert_does_not_open_http_connection(network_settings, http_calls):
    assert transport._http_insert_json_rows(8123, "sli_warm.placement_input", []) == (0, False)
    assert http_calls == []


@pytest.mark.parametrize("host", ["127.0.0.1", "clickhouse"])
def test_warm_settings_do_not_redirect_history(monkeypatch, network_settings, http_calls, host):
    if host != "127.0.0.1":
        monkeypatch.setenv("ADLOG_HISTORY_CLICKHOUSE_HOST", host)
    monkeypatch.setenv(history.USER_ENV, "history_reader")
    monkeypatch.setenv(history.PASSWORD_ENV, "synthetic-history-password")
    history._http_query(57847, "SELECT 1 value FORMAT JSONEachRow")
    history._http_insert_json_rows(57847, "sli_history.events", [{"event_db_id": 41}])
    assert list(history._stream_rows(57847, "SELECT 1 value")) == [{"value": 1}]
    assert all(call["host"] == host and call["port"] == 57847 for call in http_calls)
    expected_auth = "Basic " + base64.b64encode(
        b"history_reader:synthetic-history-password",
    ).decode("ascii")
    assert all(call["headers"]["Authorization"] == expected_auth for call in http_calls)


@pytest.mark.parametrize("stream", [False, True])
def test_explicit_endpoint_overrides_history_and_warm_settings(
    monkeypatch, network_settings, http_calls, stream,
):
    monkeypatch.setenv("ADLOG_HISTORY_CLICKHOUSE_HOST", "clickhouse")
    auth = ("explicit_reader", "synthetic-explicit-password")
    query = "SELECT 1 value FORMAT JSONEachRow"
    if stream:
        assert list(transport._http_stream_json_rows(
            18123, query, host="explicit-tier", auth=auth,
        )) == [{"value": 1}]
    else:
        transport._http_query(18123, query, host="explicit-tier", auth=auth)
    assert http_calls[0]["host"] == "explicit-tier"
    assert http_calls[0]["port"] == 18123
    expected_auth = "Basic " + base64.b64encode(
        b"explicit_reader:synthetic-explicit-password",
    ).decode("ascii")
    assert http_calls[0]["headers"]["Authorization"] == expected_auth
    assert http_calls[0]["closed"]
