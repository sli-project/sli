from datetime import datetime, timedelta, timezone

import pytest

from server.sli.access import report_api_key as keys


def test_restricted_key_routes_are_get_only_and_bounded():
    p = {"type": "api_key", "report_subject_id": 42}
    assert keys.request_allowed(p, "GET", "/api/v2/reports/ad.gpo.v2/data")
    assert keys.request_allowed(p, "GET", "/api/v1/events/123")
    for report in (*keys.FILE_REPORTS, *keys.WORKSTATION_REPORTS, 'ad.users.v2', 'ad.computers.v6', 'security.events.chains'):
        assert keys.request_allowed(p, 'GET', '/api/v2/reports/' + report + '/data')
        assert not keys.request_allowed(p, 'POST', '/api/v2/reports/' + report + '/data')
        assert not keys.request_allowed(p, 'GET', '/api/v2/reports/' + report + '/export.csv')
    for method, path in [("POST", "/api/v2/reports/ad.gpo.v2/data"),
                         ("GET", "/api/v1/admin/agents"),
                         ("GET", "/api/v2/reports/ad.gpo.v2/export.csv"),
                         ("GET", "/api/auth/me"), ("GET", "/api/v1/events/batch")]:
        assert not keys.request_allowed(p, method, path)
    assert keys.request_allowed({"type": "session"}, "POST", "/api/auth/logout")


def test_computer_verification_route_does_not_allow_other_versions_or_operations():
    principal = {"type": "api_key", "report_subject_id": 42}
    assert keys.request_allowed(principal, "GET", "/api/v2/reports/ad.computers.v6/rows/123/detail")
    for method, path in (
        ("PUT", "/api/v2/reports/ad.computers.v6/data"),
        ("DELETE", "/api/v2/reports/ad.computers.v6/rows/123/detail"),
        ("GET", "/api/v2/reports/ad.computers.v6/export.csv"),
        ("GET", "/api/v2/reports/ad.computers.v5/data"),
        ("GET", "/api/v2/reports/ad.computers.v6/options"),
    ):
        assert not keys.request_allowed(principal, method, path)


@pytest.mark.parametrize("report", ["vpn.accounts", "vpn.connections"])
def test_vpn_key_routes_allow_only_exact_get_data(report):
    principal = {"type": "api_key", "report_subject_id": 42}
    path = f"/api/v2/reports/{report}/data"
    assert keys.request_allowed(principal, "GET", path)
    for method in ("POST", "PUT", "DELETE"):
        assert not keys.request_allowed(principal, method, path)
    for denied_path in (
        f"/api/v2/reports/{report}",
        f"/api/v2/reports/{report}/export.csv",
        f"/api/v2/reports/{report}/rows/123/detail",
        f"{path}/extra",
        "/api/v2/reports/vpn.audit/data",
        "/api/v2/reports/vpn.other/data",
        "/api/v1/reports/vpn.audit/sessions/evidence",
        "/api/v1/admin/agents",
        "/api/auth/me",
    ):
        assert not keys.request_allowed(principal, "GET", denied_path)


@pytest.fixture
def vpn_access():
    return {"subject": {"type": "report_reader", "id": 42}, "capabilities": [],
            "capability_policies": [{"capability_key": "vpn.sessions.view", "effect": "allow",
                                     "valid": True, "scope": {"kind": "domain", "ids": [7]}}],
            "reports": [{"report_key": "vpn.audit", "allowed": True, "allowed_actions": ["view"],
                         "grants": [{"scope": {"kind": "domain", "ids": [7]},
                                     "field_categories": ["identity_basic", "technical", "security"],
                                     "allowed_actions": ["view"]}]}]}


@pytest.mark.parametrize("report,tab", [
    ("vpn.accounts", None),
    *(("vpn.connections", tab) for tab in (
        "employees", "session_overlap", "daily", "departments", "entitlements",
        "failed", "authorizations", "policy_denials", "policy_denials_growth",
        "policy_denials_events", "windows", "windows_heatmap")),
])
@pytest.mark.parametrize("assigned", [True, False])
def test_vpn_gets_reach_the_existing_report_grant_boundary(monkeypatch, vpn_access, report, tab, assigned):
    from dataclasses import replace
    from types import SimpleNamespace

    from server.api import http_server
    from server.api.routes import reports_v2
    from server.sli.reporting.v2.access import resolve_domain_scope
    from server.sli.reporting.v2.definition import result
    from server.sli.reporting.v2.reports import vpn_audit, vpn_connections

    definition = vpn_audit.REPORT if report == "vpn.accounts" else vpn_connections.REPORT
    assert definition.access.report_key == "vpn.audit"
    if tab:
        assert tab in {view.key for view in definition.views}
    if not assigned:
        vpn_access["reports"] = []
    principal = {"type": "api_key", "report_subject_id": 42}
    monkeypatch.setattr(http_server, "principal_from_headers", lambda _headers: principal)
    monkeypatch.setattr(keys.auth, "_connect", lambda: pytest.fail("unexpected_database_access"))
    calls = []

    def fake_query(context):
        assert context.access is vpn_access
        assert resolve_domain_scope(context.access, definition.access) == [7]
        assert context.tab == tab
        calls.append(context)
        return result(definition, state="empty")

    monkeypatch.setattr(reports_v2, "get_report", lambda key: replace(definition, query=fake_query) if key == report else None)
    monkeypatch.setattr(reports_v2, "annotate_plugin_report", lambda *_args: None)
    replies = []
    handler = SimpleNamespace(headers={"Authorization": "Bearer synthetic"}, command="GET",
                              _access_decision=lambda: vpn_access,
                              _send_json=lambda body, status=200: replies.append((body, int(status))))
    path = f"/api/v2/reports/{report}/data"
    assert http_server.RequestHandler._require_secure_api_transport(handler, path)
    assert handler._principal is principal
    query = {"tz": ["UTC"], "limit": ["1"]}
    if tab:
        query.update(domain=["7"], period=["custom"], **{"from": ["2026-10-01"], "to": ["2026-10-02"]}, tab=[tab])
    assert reports_v2.try_handle_get(handler, path, query)
    assert len(replies) == 1
    assert replies[0][1] == (200 if assigned else 403)
    assert len(calls) == int(assigned)
    if assigned:
        assert replies[0][0]["state"] == "empty"
    else:
        assert replies[0][0]["error"] == "report_access_denied"


@pytest.mark.parametrize("domain,assigned,session_domain,directory_allowed,sessions_allowed", [
    (7, True, 7, True, True),
    (8, True, 7, False, False),
    (7, False, 7, False, False),
    (7, True, 8, True, False),
])
def test_vpn_sources_require_matching_domain_and_independent_capability(
        vpn_access, domain, assigned, session_domain, directory_allowed, sessions_allowed):
    from server.sli.plugins.remote_access.reports.vpn_report_composition import vpn_report_composition_decision

    if not assigned:
        vpn_access["reports"] = []
    vpn_access["capability_policies"][0]["scope"]["ids"] = [session_domain]
    decision = vpn_report_composition_decision(vpn_access, source_domain_id=domain)
    assert decision.directory.allowed is directory_allowed
    assert decision.sessions.allowed is sessions_allowed
    assert not decision.session_evidence.allowed
    exported = vpn_report_composition_decision(vpn_access, source_domain_id=domain, action="export")
    assert not exported.directory.allowed and not exported.sessions.allowed


@pytest.mark.parametrize("report", ["ad.computers.v6", "vpn.audit"])
@pytest.mark.parametrize("sessions_required", [False, True])
def test_domain_verification_key_issues_domain_view_grant(monkeypatch, report, sessions_required):
    import json
    from contextlib import nullcontext
    from types import SimpleNamespace

    from server.sli.access import access_control_v4 as access

    definition = {"required_capabilities": ["objects.view"],
                  "field_categories": ["identity_basic", "technical", "security"],
                  "actions": ["view", "export"]}
    if sessions_required:
        definition["required_capabilities"].append("vpn.sessions.view")
    assignments = []
    audits = []
    policies = []

    class Cursor:
        rows = []

        def execute(self, sql, params):
            if "from domains" in sql:
                assert params == (7,)
                self.rows = [{"id": 7}]
            elif "report_registry_v4" in sql:
                assert report in params[0]
                self.rows = [{"report_key": report, "definition_json": definition} for report in params[0]]
            elif "select id,capability_key" in sql:
                self.rows = [{"id": i, "capability_key": cap} for i, cap in enumerate(params[0], 1)]
                self.capabilities = {row["id"]: row["capability_key"] for row in self.rows}
            elif "insert into access_capability_assignments" in sql:
                assert params[0] == 42
                capability = self.capabilities[params[1]]
                expected = {"kind": "all"} if capability in {"objects.view", "evidence.exact"} else {"kind": "domain", "ids": [7]}
                assert json.loads(params[2]) == expected
                policies.append({"capability_key": capability, "effect": "allow", "valid": True,
                                 "scope": json.loads(params[2])})
            elif "insert into auth_api_keys" in sql:
                assert params[-1] == 42
                self.rows = [{"id": 8}]
            else:
                raise AssertionError(sql)

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return self.rows[0] if self.rows else None

    cursor = Cursor()
    monkeypatch.setattr(keys.auth, "_connect", lambda: nullcontext(
        SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    monkeypatch.setattr(keys.auth, "create_user", lambda **kw: {"id": 42})
    monkeypatch.setattr(keys.auth, "_audit", lambda *a, **kw: None)
    monkeypatch.setattr(access, "create_report_assignment", lambda payload, **kw: assignments.append(payload))
    monkeypatch.setattr(access, "record_access_audit_with_cursor", lambda **kw: audits.append(kw))

    item, _secret = keys.issue_report_key(label="synthetic-verification", domain_id=7)

    assert item["id"] == 8 and item["domain_id"] == 7
    assert len(assignments) == len(keys.REPORTS)
    grant = next(grant for grant in assignments if grant["report_key"] == report)
    assert grant["scope"] == {"kind": "domain", "ids": [7]}
    assert grant["allowed_actions"] == ["view"]
    assert grant["field_categories"] == ["identity_basic", "technical", "security"]
    assert grant["valid_until"] == item["expires_at"]
    assert audits[-1]["action"] == "report_api_key_issued"
    assert report in audits[-1]["details"]["reports"]
    assert "vpn.sessions.view" in audits[0]["details"]["capabilities"]
    assert "vpn.session.evidence.read" not in audits[0]["details"]["capabilities"]
    assert "reports.export" not in audits[0]["details"]["capabilities"]
    decision = {"reports": [{"report_key": report, "allowed": True, "grants": [grant]}]}
    for domain_id, allowed in ((7, True), (8, False)):
        assert access.report_action_decision(decision, report, "view",
            resource_groups=[[{"kind": "domain", "id": domain_id}]],
            required_field_categories=["identity_basic", "technical", "security"])["allowed"] is allowed
    assert not access.report_action_decision(decision, report, "export",
        resource_groups=[[{"kind": "domain", "id": 7}]])["allowed"]
    from server.sli.plugins.remote_access.reports.vpn_report_composition import vpn_report_composition_decision

    vpn_grant = next(grant for grant in assignments if grant["report_key"] == "vpn.audit")
    issued_access = {"capability_policies": policies,
                     "reports": [{"report_key": "vpn.audit", "allowed": True, "grants": [vpn_grant]}]}
    for domain_id, allowed in ((7, True), (8, False)):
        branches = vpn_report_composition_decision(issued_access, source_domain_id=domain_id)
        assert branches.directory.allowed is allowed
        assert branches.sessions.allowed is allowed
        assert not branches.session_evidence.allowed
        exported = vpn_report_composition_decision(issued_access, source_domain_id=domain_id, action="export")
        assert not exported.directory.allowed and not exported.sessions.allowed
    issued_access["capability_policies"].append({"capability_key": "vpn.sessions.view", "effect": "deny",
                                               "valid": True, "scope": {"kind": "domain", "ids": [7]}})
    assert not vpn_report_composition_decision(issued_access, source_domain_id=7).sessions.allowed


def test_key_without_vpn_report_does_not_acquire_session_capability(monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    from server.sli.access import access_control_v4 as access

    class Cursor:
        def execute(self, sql, params):
            if "select id,capability_key" in sql:
                assert params == (["evidence.exact"],)
                self.rows = [{"id": 1, "capability_key": "evidence.exact"}]
            elif "insert into auth_api_keys" in sql:
                self.rows = [{"id": 8}]
            else:
                assert "insert into access_capability_assignments" in sql

        def fetchall(self):
            return self.rows

        def fetchone(self):
            return self.rows[0]

    cursor = Cursor()
    monkeypatch.setattr(keys.auth, "_connect", lambda: nullcontext(
        SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    monkeypatch.setattr(keys.auth, "_audit", lambda *_a, **_kw: None)
    monkeypatch.setattr(access, "record_access_audit_with_cursor", lambda **_kw: None)
    monkeypatch.setattr(access, "create_report_assignment", lambda *_a, **_kw: None)
    item, _secret = keys._issue_for_subject({"id": 42}, {"ad.computers.v6": {}},
                                          "synthetic-verification", 7, datetime.now(timezone.utc))
    assert item["id"] == 8


def test_computer_grant_options_offer_the_supported_domain_scope(monkeypatch):
    from contextlib import nullcontext

    from server.sli.access import access_control_v4 as access

    class Cursor:
        def execute(self, sql):
            assert "report_registry_v4" in sql

        def fetchall(self):
            return [{"report_key": "ad.computers.v6", "version": 1, "name": "Synthetic computers",
                     "purpose": "Verification", "sensitivity": "restricted", "dataset_key": "ad.assets.computers.v6",
                     "definition_json": {"field_categories": ["technical"], "actions": ["view", "export"]},
                     "fields_json": [{"category": "technical"}], "actions_json": ["view", "export"]}]

        def cursor(self):
            return nullcontext(self)

    monkeypatch.setattr(access, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(access, "_connect", lambda: nullcontext(Cursor()))
    item, = access.list_report_grant_options()["items"]
    assert item["report_key"] == "ad.computers.v6"
    assert item["scope_kinds"] == ["all", "domain"]


def test_workstation_scope_is_explicit_and_does_not_expand_to_all_stations():
    agent = '00000000-0000-4000-8000-000000000001'

    class Cursor:
        def __init__(self):
            self.rows = []

        def execute(self, sql, params):
            assert "a.status='active'" in sql and "m->>'enabled'='true'" in sql
            assert params == ([agent],)

        def fetchall(self):
            return self.rows

    cur = Cursor()
    with pytest.raises(ValueError, match='not_assigned'):
        keys.workstation_scope(cur, [agent])
    cur.rows = [{'agent_id': agent, 'source_instance_id': 'selected-station'}]
    from server.sli.access.scope import AccessScope

    scope = AccessScope.from_dict(keys.workstation_scope(cur, [agent]))
    assert scope.allows(plugin_id='sli.workstations', source_instance_id='selected-station')
    assert not scope.allows(plugin_id='sli.workstations', source_instance_id='another-station')
    assert not scope.allows(plugin_id='sli.ad', source_instance_id='selected-station')


def test_file_scope_rejects_other_domain_and_is_bound_to_selected_sources():
    agent = '00000000-0000-4000-8000-000000000001'
    class Cursor:
        def __init__(self):
            self.rows = []
        def execute(self, sql, params):
            assert 's.domain_id=%s' in sql and params == ([agent], 1275)
        def fetchall(self):
            return self.rows
    cur = Cursor()
    with pytest.raises(ValueError, match='domain_mismatch'):
        keys.file_scope(cur, 1275, [agent])
    cur.rows = [{'agent_id': agent, 'source_instance_id': 'synthetic-source'}]
    scope = keys.file_scope(cur, 1275, [agent])
    from server.sli.access.scope import AccessScope
    access = AccessScope.from_dict(scope)
    assert access.allows(plugin_id='sli.file-audit', source_instance_id='synthetic-source')
    assert not access.allows(plugin_id='sli.file-audit', source_instance_id='another-domain-source')


def test_file_grant_validates_binding_without_ad_entity_and_rejects_unknown_sources():
    from server.sli.access.access_control_v4 import _validate_scope_targets
    from server.sli.access.scope import ScopeClause
    from server.sli.plugins.file_audit.access import validate_scope_targets
    class Cursor:
        def __init__(self):
            self.rows = [{'device_id': 'synthetic-device', 'source_instance_id': 'synthetic-source'}]
        def execute(self, sql, params):
            assert 'sli_agents' in sql and params == (['synthetic-source'],)
        def fetchall(self):
            return self.rows
    cur = Cursor()
    clause = ScopeClause(plugin_ids=('sli.file-audit',), source_instance_ids=('synthetic-source',))
    assert validate_scope_targets(cur, clause)
    _validate_scope_targets(cur, 'scope', {'mode': 'restricted', 'clauses': [
        {'plugin_ids': ['sli.file-audit'], 'source_instance_ids': ['synthetic-source']}]})
    cur.rows = []
    with pytest.raises(ValueError, match='target_not_found'):
        validate_scope_targets(cur, clause)
    assert not validate_scope_targets(cur, ScopeClause(plugin_ids=('sli.file-audit',)))


def test_expiry_rejects_unbounded_or_expired_windows():
    now = datetime.now(timezone.utc)
    assert keys.validate_expiry(now + timedelta(days=7), now=now)
    for expiry in (None, now, now - timedelta(seconds=1), now + timedelta(days=8), now.replace(tzinfo=None)):
        with pytest.raises(ValueError):
            keys.validate_expiry(expiry, now=now)


def test_workstation_only_key_ignores_unrelated_report_contracts(monkeypatch):
    from contextlib import nullcontext
    from types import SimpleNamespace

    agent = '00000000-0000-4000-8000-000000000001'
    scope = {'mode': 'restricted', 'clauses': [{'plugin_ids': ['sli.workstations'],
                                             'source_instance_ids': ['selected-station']}]}

    class Cursor:
        def execute(self, sql, params):
            self.sql = sql
            if 'report_registry_v4' in sql:
                # The legacy core reader has a broken field contract. A station
                # key must neither load it nor acquire its domain data grants.
                assert set(params[0]) == set(keys.WORKSTATION_REPORTS)

        def fetchone(self):
            return {'id': 1275}

        def fetchall(self):
            return [{'report_key': key, 'definition_json': {'field_categories': ['security']}}
                    for key in keys.WORKSTATION_REPORTS]

    cursor = Cursor()
    monkeypatch.setattr(keys.auth, '_connect', lambda: nullcontext(
        SimpleNamespace(cursor=lambda: nullcontext(cursor))))
    monkeypatch.setattr(keys, 'workstation_scope', lambda cur, ids: scope if ids == [agent] else None)
    monkeypatch.setattr(keys.auth, 'create_user', lambda **kw: {'id': 42})

    def issue(subject, definitions, label, domain, expiry, *, scopes):
        assert subject == {'id': 42} and set(definitions) == set(keys.WORKSTATION_REPORTS)
        assert scopes == dict.fromkeys(keys.WORKSTATION_REPORTS, scope)
        return {'id': 1}, 'fixture-secret'

    monkeypatch.setattr(keys, '_issue_for_subject', issue)
    assert keys.issue_report_key(label='station', domain_id=1275, workstation_agent_ids=[agent],
                                 workstations_only=True) == ({'id': 1}, 'fixture-secret')


@pytest.mark.parametrize('agents,files,only', [([], [], True), (['station'], ['file'], True),
                                            (['station'], [], 'true')])
def test_workstation_only_requires_selected_agents_and_rejects_mixed_mode(monkeypatch, agents, files, only):
    monkeypatch.setattr(keys.auth, '_connect', lambda: pytest.fail('invalid mode opened the database'))
    with pytest.raises(ValueError, match='report_key_parameters_invalid'):
        keys.issue_report_key(label='station', domain_id=1275, workstation_agent_ids=agents,
                              file_agent_ids=files, workstations_only=only)


@pytest.mark.parametrize("report,dataset", [
    ("security.events.chains", "security.events.atomic"),
    ("ad.users.v2", "ad.accounts.users.reference.v2"),
    ("ad.computers.v6", "ad.assets.computers.v6"),
    ("vpn.audit", "ad.accounts.vpn"),
])
@pytest.mark.parametrize("scope_kind,domain_exists", [("domain", True), ("domain", False),
                                                       ("server", True), ("channel", True)])
def test_verification_reports_use_real_assignment_scope_contract(monkeypatch, report, dataset,
                                                                 scope_kind, domain_exists):
    import json

    from server.sli.access import access_control_v4 as access

    class Cursor:
        inserted = None
        row = None

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def cursor(self):
            return self

        def execute(self, statement, params):
            if "join report_datasets_v4" in statement:
                assert params == (report,)
                self.row = {"dataset_key": dataset,
                            "definition_json": {"field_categories": ["security"], "actions": ["view"]},
                            "fields_json": [{"category": "security"}], "actions_json": ["view"]}
            elif "from auth_users" in statement:
                self.row = {"id": 42}
            elif "from domains" in statement:
                assert params == ([1275],)
                self.row = {"id": 1275} if domain_exists else None
            elif "from servers" in statement:
                assert report == "vpn.audit" and params == ([1275],)
                self.row = None  # No registered source matches this synthetic server scope.
            elif "insert into access_report_assignments" in statement:
                self.inserted = json.loads(params[4])
                assert params[6] == ["view"]
                self.row = {"id": 1}
            else:
                raise AssertionError(statement)

        def fetchone(self):
            return self.row

        def fetchall(self):
            return [self.row] if self.row else []

    cur = Cursor()
    monkeypatch.setattr(access, "ensure_access_schema", lambda: None)
    monkeypatch.setattr(access, "_connect", lambda: cur)
    audit = []
    monkeypatch.setattr(access, "record_access_audit_with_cursor", lambda **kw: audit.append(kw))
    scope = {"kind": scope_kind, "values" if scope_kind == "channel" else "ids":
             ["Security"] if scope_kind == "channel" else [1275]}
    payload = {"subject_type": "user", "subject_id": 42, "report_key": report,
               "scope": scope, "allowed_actions": ["view"], "business_reason": "verification"}
    if scope_kind == "domain" and domain_exists:
        assert access.create_report_assignment(payload, actor={"type": "local_operator"})["id"] == 1
        assert cur.inserted == scope and audit[0]["action"] == "report_assignment_created"
    else:
        with pytest.raises(ValueError, match="scope_not_supported_by_dataset|report_scope_target_not_found"):
            access.create_report_assignment(payload, actor={"type": "local_operator"})
        assert cur.inserted is None and not audit


def test_subject_does_not_inherit_role_or_owner_authority():
    from server.sli.access.access_control_v4 import _access_subject
    role, user_id, restricted = _access_subject({"type": "api_key", "id": 8,
                                               "role": "admin", "report_subject_id": 42})
    assert (role, user_id, restricted) == ("report_reader", 42, True)
    assert _access_subject({"type": "session", "id": 8, "role": "admin"}) == ("admin", 8, False)


@pytest.mark.parametrize('family', ['logons', 'processes', 'usb', 'protection'])
@pytest.mark.parametrize('rule,source_exists', [('delegated', True), ('delegated', False),
                                              ('no_opt_in', True), ('domain', True), ('other_key', True)])
def test_workstation_keys_use_real_grant_scope_contract(monkeypatch, family, rule, source_exists):
    import json
    from dataclasses import replace

    from server.sli.access import access_control_v4 as access
    from server.sli.plugins import registry as plugins
    from server.sli.plugins.workstations import reports
    from server.sli.reporting.v2 import registry

    definition = reports.make_report(family)
    registered_rule = replace(definition.access,
                              accepts_generic_scope=rule != 'no_opt_in',
                              scope='domain' if rule == 'domain' else 'delegated',
                              report_key='other.report' if rule == 'other_key' else definition.key)
    monkeypatch.setattr(registry, 'registered_reports', lambda: (replace(definition, access=registered_rule),))
    monkeypatch.setattr(plugins, 'plugin_hook', lambda *args: None)

    class Cursor:
        inserted = None
        row = None

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def cursor(self):
            return self

        def execute(self, statement, params):
            if 'join report_datasets_v4' in statement:
                self.row = {'dataset_key': 'workstations.security',
                            'definition_json': {'field_categories': sorted(reports.FIELDS), 'actions': ['view']},
                            'fields_json': [{'category': f} for f in reports.FIELDS], 'actions_json': ['view']}
            elif 'from auth_users' in statement:
                self.row = {'id': 42}
            elif 'core_entity_scope_resources' in statement:
                assert params in ((['sli.workstations'],), (['selected-station'],))
                self.row = {'value': params[0][0]} if source_exists else None
            elif 'insert into access_report_assignments' in statement:
                self.inserted = json.loads(params[4])
                assert params[6] == ['view'] and set(params[5]) == reports.FIELDS
                self.row = {'id': 1}
            else:
                raise AssertionError(statement)

        def fetchone(self):
            return self.row

        def fetchall(self):
            return [self.row] if self.row else []

    cur = Cursor()
    monkeypatch.setattr(access, 'ensure_access_schema', lambda: None)
    monkeypatch.setattr(access, '_connect', lambda: cur)
    audits = []
    monkeypatch.setattr(access, 'record_access_audit_with_cursor', lambda **kw: audits.append(kw))
    scope = {'mode': 'restricted', 'clauses': [{'plugin_ids': ['sli.workstations'],
                                             'source_instance_ids': ['selected-station']}]}
    payload = {'subject_type': 'user', 'subject_id': 42, 'report_key': definition.key,
               'scope': scope, 'field_categories': sorted(reports.FIELDS),
               'allowed_actions': ['view'], 'business_reason': 'verification'}
    if rule == 'delegated' and source_exists:
        assert access.create_report_assignment(payload, actor={'type': 'local_operator'})['id'] == 1
        assert cur.inserted == scope and audits[0]['action'] == 'report_assignment_created'
    else:
        with pytest.raises(ValueError, match='scope_not_supported_by_dataset|report_scope_target_not_found'):
            access.create_report_assignment(payload, actor={'type': 'local_operator'})
        assert cur.inserted is None and not audits


def test_http_gate_rejects_key_before_dispatch(monkeypatch):
    from types import SimpleNamespace

    from server.api import http_server
    monkeypatch.setattr(http_server, "principal_from_headers", lambda _h: {"report_subject_id": 42})
    replies = []
    handler = SimpleNamespace(headers={"Authorization": "Bearer test"}, command="POST",
                              _send_json=lambda body, status: replies.append((body, status)))
    assert not http_server.RequestHandler._require_secure_api_transport(handler, "/api/auth/logout")
    assert replies[0][0] == {"error": "report_key_route_denied"}


@pytest.mark.parametrize("report", ["events.journal", "ad.computers.v6"])
def test_http_gate_binds_restricted_principal_with_optional_auth(monkeypatch, report):
    from types import SimpleNamespace

    from server.api import http_server
    principal = {"type": "api_key", "report_subject_id": 42}
    monkeypatch.setattr(http_server, "principal_from_headers", lambda _h: principal)
    monkeypatch.setattr(http_server, "auth_required", lambda: False)
    handler = SimpleNamespace(headers={"Authorization": "Bearer test"}, command="GET")
    assert http_server.RequestHandler._require_secure_api_transport(handler, f"/api/v2/reports/{report}/data")
    assert handler._principal is principal


def test_exact_evidence_requires_same_domain_grant_before_read(monkeypatch):
    from server.sli.access import access_control_v4 as access

    class Cursor:
        domain_id = 2
        def __enter__(self):
            return self
        def __exit__(self, *_):
            pass
        def cursor(self):
            return self
        def execute(self, sql, params):
            assert sql == 'select domain_id from events_v2_core where id=%s'
            assert params == (123,)
        def fetchone(self):
            return {'domain_id': self.domain_id}

    cursor = Cursor()
    monkeypatch.setattr(keys.auth, '_connect', lambda: cursor)
    monkeypatch.setattr(access, 'effective_access', lambda _p: {'reports': [{
        'report_key': 'events.explorer', 'allowed': True, 'grants': [{
            'scope': {'kind': 'domain', 'ids': [1275]}, 'allowed_actions': ['view'],
            'field_categories': ['raw_evidence', 'technical', 'security']}]}]})
    p = {'type': 'api_key', 'report_subject_id': 42}
    assert not keys.exact_event_allowed(p, '/api/v1/events/123')
    cursor.domain_id = 1275
    assert keys.exact_event_allowed(p, '/api/v1/events/123')
    cursor.domain_id = None
    assert not keys.exact_event_allowed(p, '/api/v1/events/123')
