"""docs/api/openapi.yaml describes every route of the server (task T088).

Two checks:

* completeness: the routes the server really dispatches (the ``ROUTES`` tables of ``server/api/routes/*`` through the
  route registry, plus the few routes served before the ambient auth gate) are exactly the routes in the YAML. A new route
  without a description, or a description of a route that does not exist, fails this test;
* the agent protocol contract: what the server's own handlers answer, and the request bodies the agents send
  (``agent-dotnet/tests/vectors``), satisfy the schemas of the YAML.

No database and no network. The schema checker below is a deliberately small subset of JSON Schema (no new dependency).
"""
from __future__ import annotations

import ast
import base64
import json
import re
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from server.api import http_server
from server.api.routes import agents, static, workspace
from server.sli.access import domain_scope
from server.sli.agent_ingest import receive_packet
from server.sli.agents import registry

ROOT = Path(__file__).resolve().parents[2]
SPEC_PATH = ROOT / "docs" / "api" / "openapi.yaml"
VECTORS = ROOT / "agent-dotnet" / "tests" / "vectors"
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

# Routes answered before the ambient auth gate; they are not in any ROUTES table. The call list of
# ``RequestHandler._do_GET`` is checked against this so a new pre-gate handler cannot be forgotten.
PRE_GATE = {
    "routes/health.py": "try_handle_liveness_get",
    "routes/auth.py": "try_handle_account_get",
    "routes/static.py": "try_handle_login_get",
}


def normalize(path: str) -> str:
    """Comparable form: ``{name}`` -> ``{}``; a trailing ``*`` (prefix route) -> ``{}``."""
    if path.endswith("*"):
        path = path[:-1] + "{}"
    return re.sub(r"\{[^}/]*\}", "{}", path)


def _path_constants(function: ast.FunctionDef) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "path":
            for comparator in node.comparators:
                values = comparator.elts if isinstance(comparator, (ast.Set, ast.Tuple, ast.List)) else [comparator]
                found.update(item.value for item in values if isinstance(item, ast.Constant) and isinstance(item.value, str))
    return found


def server_routes() -> set[tuple[str, str]]:
    routes = {(method, normalize(pattern)) for _module, method, pattern in http_server.ROUTE_REGISTRY.entries()}
    for relative, name in PRE_GATE.items():
        tree = ast.parse((ROOT / "server" / "api" / relative).read_text("utf-8"))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        routes.update(("GET", normalize(path)) for path in _path_constants(function))
    routes.update(("GET", path) for path in static._LOGIN_STATIC_ASSETS)
    return routes


def load_spec() -> dict:
    return yaml.safe_load(SPEC_PATH.read_text("utf-8"))


def spec_routes(spec: dict) -> set[tuple[str, str]]:
    return {(method.upper(), normalize(path)) for path, item in spec["paths"].items() for method in item if method in METHODS}


def test_pre_gate_handlers_are_the_known_ones():
    tree = ast.parse((ROOT / "server" / "api" / "http_server.py").read_text("utf-8"))
    do_get = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_do_GET")
    called = {node.func.attr for node in ast.walk(do_get)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr.startswith("try_handle_")}
    # try_handle_get of the agents module is covered by its ROUTES table.
    assert called - {"try_handle_get"} == set(PRE_GATE.values()), (
        "_do_GET calls a pre-gate handler that this test does not know: add it to PRE_GATE")


def test_every_server_route_is_described_and_nothing_else():
    described = spec_routes(load_spec())
    actual = server_routes()
    # The first-login contract is owned by .NET. Its integration tests exercise
    # password change and verify that the frozen Python activation route is gone.
    described.discard(("POST", "/api/auth/change-initial-password"))
    actual -= {("GET", "/api/auth/bootstrap"), ("POST", "/api/auth/bootstrap")}
    missing = sorted(actual - described)
    extra = sorted(described - actual)
    assert not missing and not extra, (
        "docs/api/openapi.yaml is out of step with the server routes.\n"
        f"Routes without a description ({len(missing)}): {missing}\n"
        f"Described routes the server does not have ({len(extra)}): {extra}")


def test_spec_has_no_duplicate_normalized_routes():
    spec = load_spec()
    seen: dict[tuple[str, str], str] = {}
    for path, item in spec["paths"].items():
        for method in item:
            if method in METHODS:
                key = (method.upper(), normalize(path))
                assert key not in seen, f"{key} is described twice: {seen[key]!r} and {path!r}"
                seen[key] = path


def _resolve(spec: dict, node, problems: list[str], where: str) -> None:
    """Walk the document: every $ref must point to an existing component."""
    if isinstance(node, dict):
        target = node.get("$ref")
        if isinstance(target, str):
            current = spec
            for part in target.removeprefix("#/").split("/"):
                if not isinstance(current, dict) or part not in current:
                    problems.append(f"{where}: unresolved {target}")
                    break
                current = current[part]
        for value in node.values():
            _resolve(spec, value, problems, where)
    elif isinstance(node, list):
        for value in node:
            _resolve(spec, value, problems, where)


def test_spec_is_structurally_valid_openapi_3_1():
    spec = load_spec()
    problems: list[str] = []
    assert str(spec.get("openapi", "")).startswith("3.1."), spec.get("openapi")
    assert spec["info"]["title"] and spec["info"]["version"]
    assert isinstance(spec["paths"], dict) and spec["paths"]
    schemes = spec["components"]["securitySchemes"]
    for requirement in spec.get("security", []):
        problems += [f"global security: unknown scheme {name}" for name in requirement if name not in schemes]
    operation_ids: set[str] = set()
    for path, item in spec["paths"].items():
        if not path.startswith("/"):
            problems.append(f"{path}: must start with /")
        template = re.findall(r"\{([^}]+)\}", path)
        for method, operation in item.items():
            where = f"{method.upper()} {path}"
            if method not in METHODS:
                problems.append(f"{where}: unknown path item key")
                continue
            op_id = operation.get("operationId")
            if not op_id or op_id in operation_ids:
                problems.append(f"{where}: operationId missing or duplicated ({op_id})")
            operation_ids.add(op_id)
            if not operation.get("summary"):
                problems.append(f"{where}: summary missing")
            if not operation.get("responses"):
                problems.append(f"{where}: responses missing")
            for code, response in operation.get("responses", {}).items():
                if not re.fullmatch(r"[1-5][0-9X]{2}|default", str(code)):
                    problems.append(f"{where}: bad response code {code}")
                if "$ref" not in response and not response.get("description"):
                    problems.append(f"{where}: response {code} has no description")
            declared = {(p["name"], p["in"]) for p in operation.get("parameters", []) if "name" in p}
            for name in template:
                if (name, "path") not in declared:
                    problems.append(f"{where}: path parameter {name} is not declared")
            for parameter in operation.get("parameters", []):
                if parameter.get("in") == "path" and parameter.get("required") is not True:
                    problems.append(f"{where}: path parameter {parameter.get('name')} must be required")
            for requirement in operation.get("security", []):
                problems += [f"{where}: unknown security scheme {name}" for name in requirement if name not in schemes]
            _resolve(spec, operation, problems, where)
    _resolve(spec, spec["components"], problems, "components")
    assert not problems, "\n".join(problems)


# ---------------------------------------------------------------------------------------------------------------------
# A small JSON Schema subset: enough for the agent protocol schemas of the YAML.
# ---------------------------------------------------------------------------------------------------------------------

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _type_ok(value, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, {"string": str, "object": dict, "array": list}[name])


def schema_errors(spec: dict, schema: dict, value, where: str = "$") -> list[str]:
    if "$ref" in schema:
        node = spec
        for part in schema["$ref"].removeprefix("#/").split("/"):
            node = node[part]
        return schema_errors(spec, node, value, where)
    errors: list[str] = []
    if "oneOf" in schema:
        matches = [option for option in schema["oneOf"] if not schema_errors(spec, option, value, where)]
        if len(matches) != 1:
            return [f"{where}: matches {len(matches)} of the oneOf options"]
        return []
    if "const" in schema and value != schema["const"]:
        return [f"{where}: expected {schema['const']!r}, got {value!r}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{where}: {value!r} not in {schema['enum']}")
    declared = schema.get("type")
    if declared is not None:
        names = declared if isinstance(declared, list) else [declared]
        if not any(_type_ok(value, name) for name in names):
            return errors + [f"{where}: expected {names}, got {type(value).__name__}"]
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{where}: does not match {schema['pattern']}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{where}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{where}: longer than {schema['maxLength']}")
        if schema.get("format") == "uuid" and not _UUID.match(value):
            errors.append(f"{where}: not a UUID")
        if schema.get("format") == "date-time":
            try:
                datetime.fromisoformat(value)
            except ValueError:
                errors.append(f"{where}: not a date-time")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{where}: below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{where}: above {schema['maximum']}")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{where}: more than {schema['maxItems']} items")
        for index, item in enumerate(value):
            if "items" in schema:
                errors += schema_errors(spec, schema["items"], item, f"{where}[{index}]")
    if isinstance(value, dict):
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{where}: missing {name}")
        properties = schema.get("properties", {})
        for name, item in value.items():
            if name in properties:
                errors += schema_errors(spec, properties[name], item, f"{where}.{name}")
            elif schema.get("additionalProperties") is False:
                errors.append(f"{where}: unexpected {name}")
    return errors


@pytest.fixture(scope="module")
def spec() -> dict:
    return load_spec()


def check(spec: dict, name: str, value) -> None:
    wire = json.loads(json.dumps(value, default=str))  # what the client receives
    errors = schema_errors(spec, {"$ref": f"#/components/schemas/{name}"}, wire)
    assert not errors, errors


def rejects(spec: dict, name: str, value) -> bool:
    return bool(schema_errors(spec, {"$ref": f"#/components/schemas/{name}"}, json.loads(json.dumps(value, default=str))))


def _domain_vectors():
    return json.loads((ROOT / "server-dotnet/tests/Sli.Server.Tests/Domains/domain-contract-vectors.json").read_text("utf-8"))


def _domain_response_schema(spec, status):
    return spec["paths"]["/api/v1/domains"]["get"]["responses"][str(status)]["content"]["application/json"]["schema"]


def test_domain_operation_has_concrete_schemas_and_explicit_contract_boundaries(spec):
    operation = spec["paths"]["/api/v1/domains"]["get"]

    def concrete(node, seen):
        assert "TODO" not in json.dumps(node)
        if isinstance(node, dict):
            ref = node.get("$ref")
            if ref and ref not in seen:
                seen.add(ref)
                resolved = spec
                for part in ref.removeprefix("#/").split("/"):
                    resolved = resolved[part]
                concrete(resolved, seen)
            for value in node.values():
                concrete(value, seen)
        elif isinstance(node, list):
            for value in node:
                concrete(value, seen)

    concrete(operation, set())
    assert "requestBody" not in operation
    assert operation["security"] == [{"sessionCookie": []}, {"bearerApiKey": []}, {"headerApiKey": []}]
    assert operation["x-sli-capability"] == "workspace.view"
    for field in ("x-sli-auth", "x-sli-scope", "x-sli-limits", "x-sli-raw-http", "x-sli-contract-tests", "x-sli-verification"):
        assert operation[field]
    for status in (200, 400, 401, 403, 429, 500, 501, 503):
        assert _domain_response_schema(spec, status)


def test_domain_query_vectors_match_raw_python_parser_and_actual_source_handler(spec, monkeypatch):
    class DomainHandler(Handler):
        def _access_decision(self):
            return {"capabilities": ["workspace.view"]}

    monkeypatch.setattr(domain_scope, "_permitted_ids", lambda access: [])

    def no_rows(ids):
        assert ids == []
        return []

    monkeypatch.setattr(domain_scope, "_domain_rows", no_rows)
    for vector in _domain_vectors()["queries"]:
        query = parse_qs(vector["raw"].removeprefix("?"))
        assert bool(query) == vector["rejected"]
        handler = DomainHandler()
        assert workspace.try_handle_get(handler, "/api/v1/domains", query)
        payload, status, _headers = handler.responses[-1]
        expected_status = 400 if vector["rejected"] else 200
        assert status == expected_status
        assert payload == ({"error": "domain_parameters_invalid"} if vector["rejected"] else {"items": []})
        assert not schema_errors(spec, _domain_response_schema(spec, status), payload)


def test_domain_dto_vectors_match_executed_source_and_openapi(spec, monkeypatch):
    class DomainHandler(Handler):
        def _access_decision(self):
            return {"capabilities": ["workspace.view"]}

    monkeypatch.setattr(domain_scope, "_permitted_ids", lambda access: None)
    timestamp_fields = {"snapshot_at_utc", "published_at_utc", "observed_at_utc", "default_observed_at_utc"}
    for vector in _domain_vectors()["responses"]:
        rows = [{key: datetime.fromisoformat(value) if key in timestamp_fields and value is not None else value
                 for key, value in row.items()} for row in vector["rows"]]
        monkeypatch.setattr(domain_scope, "_domain_rows", lambda ids: rows)
        handler = DomainHandler()
        assert workspace.try_handle_get(handler, "/api/v1/domains", {})
        payload, status, _headers = handler.responses[-1]
        assert status == 200
        assert payload == vector["expected"]
        assert not schema_errors(spec, _domain_response_schema(spec, 200), payload)


@pytest.mark.parametrize("failure,status,code", [
    (PermissionError, 403, "workspace_view_required"),
    (ValueError, 400, "domain_parameters_invalid"),
])
def test_domain_source_selection_failures_match_concrete_error_schema(spec, monkeypatch, failure, status, code):
    class DomainHandler(Handler):
        def _access_decision(self):
            return {"capabilities": ["workspace.view"]}

    def fail_selection(access, query):
        raise failure("synthetic")

    monkeypatch.setattr(workspace, "resolve_domain_selection", fail_selection)
    handler = DomainHandler()
    assert workspace.try_handle_get(handler, "/api/v1/domains", {})
    payload, actual_status, _headers = handler.responses[-1]
    assert actual_status == status
    assert payload == {"error": code}
    assert not schema_errors(spec, _domain_response_schema(spec, status), payload)


def test_domain_schemas_reject_missing_null_wrong_type_and_extra_fields(spec):
    response = _domain_vectors()["responses"][1]["expected"]
    assert not rejects(spec, "DomainResponse", response)
    assert rejects(spec, "DomainResponse", {"items": None})
    assert rejects(spec, "DomainResponse", {})
    item = response["items"][0]
    assert rejects(spec, "DomainItem", {**item, "id": True})
    assert rejects(spec, "DomainItem", {**item, "id": 0})
    assert rejects(spec, "DomainItem", {**item, "id": 2**63})
    assert rejects(spec, "DomainItem", {**item, "display_name": None})
    assert rejects(spec, "DomainItem", {**item, "freshness": None})
    assert rejects(spec, "DomainItem", {**item, "private_data": "synthetic"})
    freshness = item["freshness"]
    assert rejects(spec, "DomainFreshness", {key: value for key, value in freshness.items() if key != "snapshot_state"})
    assert rejects(spec, "DomainFreshness", {**freshness, "snapshot_at_utc": "not-a-timestamp"})


@pytest.mark.parametrize("status,payload", [
    (400, {"error": "domain_parameters_invalid"}),
    (401, {"error": "authentication_required", "message": {
        "code": "login.error.authenticationRequired", "params": {}, "text": "Необходимо войти в систему."}}),
    (403, {"error": "secure_transport_required", "message": {
        "code": "login.error.https", "params": {}, "text": "Вход разрешён только через защищённое HTTPS-соединение."}}),
    (403, {"error": "explicit_deny", "required_capability": "workspace.view"}),
    (403, {"error": "workspace_view_required"}),
    (403, {"error": "insufficient_permissions"}),
    (403, {"error": "report_key_route_denied"}),
    (429, {"error": "server_busy"}),
    (429, {"error": "rate_limit_exceeded"}),
    (500, {"error": "internal_server_error", "internal_error_id": "00000000-0000-4000-8000-000000000001"}),
    (501, {"error": "not_implemented"}),
    (503, {"error": "report_read_timeout", "state": "unavailable"}),
])
def test_domain_concrete_error_schemas(spec, status, payload):
    schema = _domain_response_schema(spec, status)
    assert not schema_errors(spec, schema, payload)
    assert schema_errors(spec, schema, {})
    assert schema_errors(spec, schema, {**payload, "private_data": "synthetic"})


def test_schema_checker_catches_a_wrong_value(spec):
    assert rejects(spec, "UpdateResultRequest", {"sha256": "z", "status": "updated", "reason": None, "version": "1.0.0"})
    assert rejects(spec, "RemovalResultRequest", {"command_id": "x", "state": "state_cleaned", "reason": None})
    assert rejects(spec, "AgentReceipt", {"status": "committed"})


# ----- packets and receipts: the vectors the .NET agent is also tested against --------------------------------------


class Ledger:
    """The few ledger calls ``receive_packet`` makes, kept in memory."""

    def __init__(self):
        self.entries = []

    def binding(self, *_):
        return None

    def get(self, _agent, _module, sequence):
        return next((item for item in self.entries if item["envelope"]["sequence"] == sequence), None)

    def latest(self, *_):
        return self.entries[-1]["envelope"] if self.entries else None

    def packet_exists(self, *_):
        return False

    def quota_error(self, *_):
        return None

    def commit(self, value, receipt, envelope_hash, rows):
        self.entries.append({"envelope": value["envelope"], "receipt": receipt, "envelope_sha256": envelope_hash})


def _vectors():
    document = json.loads((VECTORS / "packets.json").read_text("utf-8"))
    key = serialization.load_der_public_key(base64.b64decode(document["public_key_spki_b64"]))
    packet = next(item for item in document["packets"] if item["name"] == "ad-dc-security")
    identity = {"id": document["agent_id"], "host_id": document["host_id"], "assigned_modules": [
        {"module_id": "sli.windows.ad-dc", "enabled": True,
         "config": {"source_name": "fixture-dc", "connect_address": "fixture-endpoint",
                    "channels": {"System": False, "Directory Service": False}, "batch_size": 3}}]}
    return document, key, packet, identity


def test_vector_packets_satisfy_the_request_schema(spec):
    document, _key, _packet, _identity = _vectors()
    for item in document["packets"]:
        check(spec, "AgentPacket", item["packet"])


def test_committed_duplicate_and_rejected_receipts_satisfy_the_receipt_schema(spec):
    _document, key, packet, identity = _vectors()
    now = datetime.fromisoformat(packet["now"])
    ledger = Ledger()
    committed = receive_packet(ledger, identity=identity, public_key=key, value=packet["packet"], now=now)
    assert committed["status"] == "committed"
    check(spec, "AgentReceipt", committed)
    duplicate = receive_packet(ledger, identity=identity, public_key=key, value=packet["packet"], now=now)
    assert duplicate["status"] == "duplicate"
    check(spec, "AgentReceipt", duplicate)
    stale = receive_packet(Ledger(), identity=identity, public_key=key, value=packet["packet"], now=now + timedelta(days=30))
    assert stale["status"] == "rejected" and stale["error_code"] == "agent_replay_window"
    check(spec, "AgentReceipt", stale)
    assert not rejects(spec, "AgentReceipt", stale)
    assert rejects(spec, "AgentReceipt", {**stale, "status": "ok"})


# ----- handlers: the same way the existing agent API tests drive them ------------------------------------------------


class Handler:
    def __init__(self):
        self.headers = {}
        self.body = {}
        self.responses = []
        self._principal = {"type": "session", "id": 1, "role": "admin"}

    def _read_json_body(self, **kwargs):
        return self.body

    def _send_json(self, result, status=HTTPStatus.OK, *, headers=None):
        self.responses.append((result, status, headers))

    def send_response(self, status):
        self.responses.append((None, status, None))


class Cursor:
    def __init__(self, rows=None, script=None):
        self.rows = list(rows or [])
        self.script = None if script is None else list(script)  # successive fetchone() answers
        self.sql = []

    def execute(self, sql, params=None):
        self.sql.append(sql)

    def fetchone(self):
        if self.script is not None:
            return self.script.pop(0) if self.script else None
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)


def serve(monkeypatch, cursor: Cursor, *, agent=None):
    """Run a handler against a scripted cursor; mTLS is replaced by an already authenticated agent."""
    @contextmanager
    def connect():
        yield SimpleNamespace(cursor=lambda: _cursor_context(cursor), commit=lambda: None)

    monkeypatch.setattr(agents, "connect", connect)
    monkeypatch.setattr(agents, "peer_certificate", lambda _handler: b"verified")
    monkeypatch.setattr(agents, "require_enrollment_tls", lambda _handler: None)
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    if agent is not None:
        monkeypatch.setattr(agents.registry, "authenticate", lambda *_a, **_k: agent)
    monkeypatch.setattr(agents.updates, "advertisement", lambda *_a: None)


@contextmanager
def _cursor_context(cursor):
    yield cursor


AGENT_ID = "00000000-0000-4000-8000-000000000001"


def active_agent(**extra):
    return {"id": AGENT_ID, "host_id": "00000000-0000-4000-8000-000000000002", "assigned_modules": [
        {"module_id": "sli.windows.ad-dc", "enabled": True, "config": {"source_name": "dc", "connect_address": "dc.example"}}],
        "policy_revision": 7, "rights_probe": {}, "collection_policy": {"state": "active"},
        "applied_policy_revision": 0, **extra}


def test_check_in_response_satisfies_the_schema(spec, monkeypatch):
    serve(monkeypatch, Cursor(), agent=active_agent())
    handler = Handler()
    assert agents.try_handle_get(handler, "/api/v1/agent/identity", {})
    result = handler.responses[-1][0]
    check(spec, "CheckInResponse", result)
    assert "manage_windows_audit" not in result["collection_policy"]  # old agents check keys strictly
    managed = active_agent(collection_policy={"state": "paused", "manage_windows_audit": True})
    serve(monkeypatch, Cursor(), agent=managed)
    handler = Handler()
    agents.try_handle_get(handler, "/api/v1/agent/identity", {})
    check(spec, "CheckInResponse", handler.responses[-1][0])
    assert handler.responses[-1][0]["collection_policy"]["audit_process_command_line"] is False


def test_check_in_offer_and_removal_command_satisfy_the_schema(spec, monkeypatch):
    serve(monkeypatch, Cursor(), agent=active_agent())
    offer = {"sha256": "a" * 64, "version": "1.1.0"}
    monkeypatch.setattr(agents.updates, "advertisement", lambda *_a: offer)
    handler = Handler()
    agents.try_handle_get(handler, "/api/v1/agent/identity", {})
    check(spec, "CheckInResponse", handler.responses[-1][0])
    assert handler.responses[-1][0]["agent_update"] == offer

    command = {"command_id": "00000000-0000-4000-8000-000000000003", "state": "pending", "requested_at": None}

    def authenticate(_cur, _ca, _der, removal_only=False):
        if not removal_only:
            raise agents.AgentError("agent_certificate_rejected", 401)
        return active_agent()

    serve(monkeypatch, Cursor([command]))
    monkeypatch.setattr(agents.registry, "authenticate", authenticate)
    handler = Handler()
    agents.try_handle_get(handler, "/api/v1/agent/identity", {})
    check(spec, "CheckInResponse", handler.responses[-1][0])
    assert "agent_removal" in handler.responses[-1][0]


def test_policy_report_request_and_response_satisfy_the_schema(spec, monkeypatch):
    request = {"applied_policy_revision": 7, "collection_state": "active"}
    check(spec, "PolicyReportRequest", request)
    assert rejects(spec, "PolicyReportRequest", {**request, "other": 1})
    serve(monkeypatch, Cursor(), agent=active_agent())
    handler = Handler()
    handler.body = request
    assert agents.try_handle_post(handler, "/api/v1/agent/policy-report")
    result, status, _headers = handler.responses[-1]
    assert status == HTTPStatus.OK, result
    check(spec, "PolicyReportResponse", result)
    assert result["applied_policy_revision"] == 7


def test_removal_flow_satisfies_the_schemas(spec, monkeypatch):
    command_id = "00000000-0000-4000-8000-000000000003"
    pending = {"command_id": command_id, "state": "pending", "requested_at": None}
    serve(monkeypatch, Cursor([pending]), agent=active_agent())
    handler = Handler()
    handler.body = {}
    assert agents.try_handle_post(handler, "/api/v1/agent/uninstall")
    check(spec, "RemovalCommand", handler.responses[-1][0])

    for body in ({"command_id": command_id, "state": "state_cleaned", "reason": None},
                 {"command_id": command_id, "state": "cleanup_failed", "reason": "agent_removal_cleanup_failed"}):
        check(spec, "RemovalResultRequest", body)
        serve(monkeypatch, Cursor([pending]), agent=active_agent())
        handler = Handler()
        handler.body = body
        assert agents.try_handle_post(handler, "/api/v1/agent/removal-result")
        result, status, _headers = handler.responses[-1]
        assert status == HTTPStatus.OK, result
        check(spec, "RemovalResultResponse", result)
        assert result == {"state": body["state"]}


def test_update_result_satisfies_the_schemas(spec, monkeypatch):
    for body in ({"sha256": "b" * 64, "status": "updated", "reason": None, "version": "1.2.3"},
                 {"sha256": "b" * 64, "status": "rolled_back", "reason": "agent_update_msi_required", "version": "1.2.3"}):
        check(spec, "UpdateResultRequest", body)
        # package is assigned, the result row is inserted, no update wave follows
        serve(monkeypatch, Cursor(script=[{"sha256": "b" * 64}, {"agent_id": AGENT_ID}]), agent=active_agent())
        handler = Handler()
        handler.body = body
        assert agents.try_handle_post(handler, "/api/v1/agent/update-result")
        result, status, _headers = handler.responses[-1]
        assert status == HTTPStatus.OK, result
        check(spec, "UpdateResultResponse", result)
    assert rejects(spec, "UpdateResultRequest", {"sha256": "b" * 64, "status": "unknown", "reason": None, "version": "1.2.3"})


def test_revocation_feed_satisfies_the_schema(spec, monkeypatch):
    rows = [{"id": 5, "agent_id": AGENT_ID, "serial": "1f", "revoked_at": datetime(2026, 10, 1, tzinfo=UTC)}]
    serve(monkeypatch, Cursor(rows))
    handler = Handler()
    assert agents.try_handle_get(handler, "/api/v1/agent/revocations", {"after": ["0"]})
    result = handler.responses[-1][0]
    check(spec, "RevocationFeed", result)
    assert result["next_cursor"] == 5
    serve(monkeypatch, Cursor([]))
    handler = Handler()
    agents.try_handle_get(handler, "/api/v1/agent/revocations", {})
    check(spec, "RevocationFeed", handler.responses[-1][0])


def _issued_certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, AGENT_ID)])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(0x1F2E3D).not_valid_before(now).not_valid_after(now + timedelta(days=30))
                   .sign(key, hashes.SHA256()))
    return certificate


def test_enrollment_and_renewal_response_satisfy_the_schema(spec):
    class CA:
        @staticmethod
        def chain_pem():
            return "-----BEGIN CERTIFICATE-----\nsynthetic\n-----END CERTIFICATE-----\n"

    response = registry._certificate_response(CA, _issued_certificate(), AGENT_ID)
    check(spec, "CertificateResponse", response)
    assert response["serial"] == "1f2e3d"
    check(spec, "EnrollRequest", {"token": "A" * 43, "csr_pem": "pem", "instance_name": "sli"})
    assert rejects(spec, "EnrollRequest", {"token": "short", "csr_pem": "pem"})
    check(spec, "RenewRequest", {"csr_pem": "pem"})


def test_group_enrollment_responses_satisfy_the_schema(spec):
    check(spec, "GroupEnrollRequest", {"token": "t", "computer_entity_id": 12, "host_id": AGENT_ID, "csr_pem": "pem"})
    check(spec, "GroupEnrollResponse", {"request_id": "r1", "status": "pending"})
    check(spec, "GroupEnrollResponse", {"request_id": "r1", "status": "approved", "token": "x", "expires_at": "2026-10-25T00:00:00+00:00"})
    assert rejects(spec, "GroupEnrollResponse", {"request_id": "r1", "status": "maybe"})
