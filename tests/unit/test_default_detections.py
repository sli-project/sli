"""Native default detectors and publication use only in-memory storage fakes."""
from contextlib import contextmanager, nullcontext
from dataclasses import asdict
from datetime import timedelta
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.sli.semantic import default_detections as defaults, password_attacks as passwords
from server.sli.semantic import nps_threshold_runtime
from server.sli.semantic import semantic_risk_runtime_repository as runtime
from server.sli.semantic.semantic_risk_policy import compile_risk_policy
from tests.unit.test_finding_evidence_refs import reference
from tests.unit.test_qw_publication import Cursor, evaluate
from tests.unit.test_detection_match_risk import NOW

SCOPE = reference("core_event").scope


def _default_result(*, sources, jobs, failed):
    return {"sources": sources, "jobs": jobs, "failed": failed,
        "coverage_counts": dict.fromkeys(("healthy", "partial", "error", "unknown", "stale", "disabled", "failed"), 0),
        "password_work_counts": dict.fromkeys(("native_items", "xml_bytes", "retained_queries", "reservation_occurrences",
            "window_queries", "reservation_calls", "tracking_calls", "completion_calls"), 0)}


def events(count=10, *, accounts=1, address="192.0.2.1", status="0xc000006a", event_id=4625):
    return [{"source_event_id": i + 1, "event_id": event_id,
             "occurred_at_utc": NOW - timedelta(seconds=20 - i), "sha256": f"{i + 1:064x}",
             "event_data": {"TargetUserName": f"fixture-{i % accounts}", "TargetDomainName": "fixture",
                            "IpAddress": address, "Status": status}}
            for i in range(count)]


def detect(rows):
    return passwords.evaluate(SCOPE, rows, now=NOW)


@pytest.mark.parametrize("accounts,expected", [(1, "qw.password-brute-force"), (5, "qw.password-spray")])
def test_password_attack_threshold_and_replay(accounts, expected):
    rows = events(accounts=accounts)
    item, = detect(rows)
    assert item.rule_id == expected and len(item.evidence_refs) == 10
    assert detect(rows + rows) == (item,)
    assert not detect(rows[:9])
    assert "fixture-0" not in json.dumps(item.document)
    pin = passwords.execution(SCOPE, expected)
    policy = passwords.risk_policy(SCOPE, expected, policy_id=defaults.policy_id(pin))
    assert compile_risk_policy(policy).selector_value == expected
    assert policy.definition["source_selector"]["execution"] == item.execution


@pytest.mark.parametrize("address", ["", "-", "not-an-ip", "0.0.0.0", "127.0.0.1"])
def test_missing_or_non_client_address_cannot_establish_spray(address):
    assert not detect(events(accounts=5, address=address))


@pytest.mark.parametrize("status", ["0xc0000064", "0xc000006d", "0xc0000234", "0x0", "unknown"])
def test_unknown_account_generic_failure_lockout_and_success_are_not_bad_passwords(status):
    assert not detect(events(status=status))


def test_disabled_account_and_kerberos_bad_password_have_distinct_rules():
    disabled, = detect(events(1, status="0xc0000072"))
    assert disabled.rule_id == "qw.disabled-account-logon"
    kerberos, = detect(events(status="0x18", event_id=4771))
    assert kerberos.rule_id == "qw.password-brute-force"
    assert not detect(events(status="0x18", event_id=4625))
    assert not detect(events(event_id=4624))


def test_windows_source_time_buckets_do_not_merge_or_accept_future_events():
    rows = events()
    for row in rows[:5]:
        row["occurred_at_utc"] -= timedelta(seconds=300)
    assert not detect(rows)
    for row in rows:
        row["occurred_at_utc"] = NOW + timedelta(seconds=1)
    assert not detect(rows)
    with pytest.raises(ValueError, match="truncated"):
        detect(events() * 1001)


def test_password_scenario_is_published_and_visible_in_domain_queue(monkeypatch):
    item, = detect(events())
    cur = Cursor(item)
    policy = passwords.risk_policy(SCOPE, item.rule_id, policy_id=defaults.policy_id(item.execution))
    cur.policies = [(policy, "enabled")]
    monkeypatch.setattr(runtime, "record_scenario_identity_supersessions", lambda *a, **k: None)
    monkeypatch.setattr(runtime, "record_finding_identity_supersessions", lambda *a, **k: None)
    result = evaluate(cur, item)
    replay = evaluate(cur, item)
    assert result.finding_created and not replay.finding_created
    assert len(cur.findings) == len(cur.publications) == 1

    from server.sli.semantic import findings
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **k: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **k: {})
    def query(sql, params=()):
        if "from findings_active findings" not in sql:
            return []
        assert "is_semantic_finding_published_v1(findings.id)" in sql
        assert "semantic_finding_in_domains_v265(findings.id,?::bigint[])" in sql
        # Fake domain projection: every native witness is in fixture domain 7.
        if params[0] != [7] or not cur.publications or len(cur.links) != 10:
            return []
        if "group by" in sql:
            return [{"severity": "high", "status": "new", "count": 1}]
        return [dict(row) for row in cur.findings.values()]
    monkeypatch.setattr(findings, "query_rows", query)
    queue = findings.get_security_problems_data(domain_ids=[7], compact=True)
    assert [row["id"] for row in queue["items"]] == [result.finding_id]
    assert not findings.get_security_problems_data(domain_ids=[8], compact=True)["items"]


def test_disabled_default_is_not_run_and_all_selected_policies_are_compilable(monkeypatch):
    policies, evaluated = [], []
    def admit(cur, policy):
        compile_risk_policy(policy)
        policies.append(policy)
        return False
    monkeypatch.setattr(defaults, "_admit", admit)
    monkeypatch.setattr(defaults, "read_password_events", lambda *a: pytest.fail("disabled detector read evidence"))
    for module in (defaults.account_decoy_runtime, defaults.account_watch_runtime, nps_threshold_runtime):
        monkeypatch.setattr(module, "run_once", lambda *a, **k: evaluated.append(k) or {"jobs": 1})
    assert defaults.run_source(object(), {"scope": asdict(SCOPE)}, now=NOW) == defaults.SourceOutcome(jobs=0)
    assert len(policies) == 4 and not evaluated


def test_file_defaults_keep_the_native_agent_root_and_mass_threshold(monkeypatch):
    scope = reference("file_audit_observation").scope
    policies, rules = [], []
    monkeypatch.setattr(defaults, "_admit", lambda cur, policy: policies.append(compile_risk_policy(policy)) or True)
    for module in (defaults.file_decoy_runtime, defaults.file_ransom_runtime):
        monkeypatch.setattr(module, "run_once", lambda cur, *, rule, now: rules.append(rule) or {"jobs": 1})
    assert defaults.run_source(FileDefaultConnection(), {"scope": asdict(scope),
        "agent_id": "00000000-0000-0000-0000-000000000003",
        "config": {"policy_revision": "3", "mass_operation_files": 25, "mass_operation_seconds": 60}}, now=NOW) == defaults.SourceOutcome(jobs=2)
    assert {policy.scenario_kind for policy in policies} == {"qw.file-decoy", "qw.file-ransom"}
    assert all(rule.scope == scope and rule.evaluation_mode == "enabled" for rule in rules)
    assert rules[1].threshold == 25 and rules[1].source_policy_revision == "3"


def test_enabled_l1_seed_scenario_publishes_to_domain_queue(monkeypatch):
    from server.sli.semantic import findings
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    from tests.semantic.test_decision_chain import PublicationCursor
    seed = (Path(__file__).resolve().parents[2] / "deploy/linux/default_semantic_policy.sql").read_text("utf-8")
    definition = json.loads(seed.split("$policy$")[1])
    class L1Cursor(PublicationCursor):
        finding = None
        published = False
        def execute(self, sql, params=()):
            super().execute(sql, params)
            normalized = " ".join(sql.split()).lower()
            if "from semantic_security_scenarios" in normalized:
                self.rows[0].update(scenario_kind=definition["scenario_kind"], title=definition["title"])
            elif "insert into findings(" in normalized:
                self.finding = {"id": 1, "rule_code": params[1], "title": params[2], "severity": params[3], "status": "new"}
            elif "select id,rule_code from findings" in normalized:
                self.rows = [self.finding]
            elif "insert into semantic_finding_publications" in normalized:
                self.published = True
    cur = L1Cursor()
    result = publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario")
    assert result["created"] and cur.published
    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **k: {"route": "v2"})
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **k: {})
    def query(sql, params=()):
        if "from findings_active findings" not in sql:
            return []
        assert "is_semantic_finding_published_v1" in sql and "semantic_finding_in_domains_v265" in sql
        if params[0] != [7] or not cur.published:
            return []
        return [{"severity": "high", "status": "new", "count": 1}] if "group by" in sql else [dict(cur.finding)]
    monkeypatch.setattr(findings, "query_rows", query)
    queue = findings.get_security_problems_data(domain_ids=[7], compact=True)
    assert queue["items"][0]["rule_code"] == "semantic.security.audit_controls_changed"
    assert not findings.get_security_problems_data(domain_ids=[8], compact=True)["items"]


@pytest.mark.parametrize("kind,code", [("password-spray", "password_spray"),
                                     ("password-brute-force", "password_brute"),
                                     ("disabled-account-logon", "password_disabled")])
def test_password_presentation_has_localized_observation_and_next_step(kind, code):
    from server.sli.reporting.v2.reports.security_problems import presentation
    view = presentation({"rule_code": "semantic.qw." + kind})
    assert view["presentation_code"] == code
    assert view["title_code"].startswith("security.problems.presentation.")
    assert view["next_step_code"] == "security.problems.presentation.password_next"
    assert view["presentation_messages"]["wording_limitation"]["code"].endswith("password_limitation")


def test_managed_native_stage_isolates_failed_scope_and_rolls_back(monkeypatch):
    sources = [{"scope": {"fixture": "broken"}}, {"scope": {"fixture": "working"}}]
    class Fake:
        def __init__(self):
            self.info = SimpleNamespace(transaction_status=defaults.TransactionStatus.IDLE)

        @contextmanager
        def transaction(self):
            self.info.transaction_status = defaults.TransactionStatus.INTRANS
            try:
                yield
            finally:
                self.info.transaction_status = defaults.TransactionStatus.IDLE
        def cursor(self):
            return nullcontext(self)
        def execute(self, *args):
            pass
        def fetchall(self):
            return [{"source": source} for source in sources]
        def fetchone(self):
            return {"page": {"items": [], "has_more": False, "next_key": None}}
    def run(cur, source, **kwargs):
        if source is sources[0]:
            raise RuntimeError("fixture")
        return defaults.SourceOutcome(jobs=2)
    monkeypatch.setattr(defaults, "run_source", run)
    assert defaults.run_default_detections(Fake()) == _default_result(**{"sources": 2, "jobs": 2, "failed": 1})


def test_ad_defaults_without_remote_access_skip_only_its_detector(monkeypatch):
    policies = []
    monkeypatch.setattr(defaults, "plugin_hook", lambda *args: None, raising=False)
    monkeypatch.setattr(defaults, "_admit", lambda cur, policy: policies.append(compile_risk_policy(policy)) or False)
    assert defaults.run_source(object(), {"scope": asdict(SCOPE)}, now=NOW) == defaults.SourceOutcome(jobs=0)
    assert len(policies) == 3
    assert all(policy.selector_value != "qw.nps-denials" for policy in policies)


class ACLDefaultConnection:
    """Orchestration-only fake; native authority is covered by real SQL gates."""

    def __init__(self, *, legacy=(), page=None, failure=None):
        from tests.unit.test_file_acl_input import RESOURCE
        self.legacy = list(legacy)
        self.page = page if page is not None else {'items': [RESOURCE], 'has_more': True, 'next_key': ['later']}
        self.failure = failure
        self.kind = None
        self.commits = []
        self.rollbacks = []
        self.queries = []
        self.native = 0
        self.info = SimpleNamespace(transaction_status=defaults.TransactionStatus.IDLE)

    @contextmanager
    def transaction(self):
        before = self.native
        self.info.transaction_status = defaults.TransactionStatus.INTRANS
        self.kind = None
        try:
            yield
            if self.failure == 'commit' and self.kind == 'acl_resource':
                raise RuntimeError('synthetic secret must not enter logs')
        except Exception:
            self.native = before
            self.rollbacks.append(self.kind)
            raise
        else:
            self.commits.append(self.kind)
        finally:
            self.info.transaction_status = defaults.TransactionStatus.IDLE

    def cursor(self):
        return nullcontext(self)

    def execute(self, statement, params=()):
        self.queries.append((statement, params))
        if 'default_detection_sources()' in statement:
            self.kind = 'legacy_discovery'
        elif 'read_default_file_acl_resources' in statement:
            self.kind = 'acl_discovery'
            assert 'null,1' in statement.replace(' ', '').lower()
        elif 'pg_advisory_xact_lock' in statement:
            self.kind = 'legacy_resource'
        if self.failure is not None and self.failure == self.kind:
            raise RuntimeError('synthetic raw detail must not enter logs')

    def fetchall(self):
        return [{'source': source} for source in self.legacy]

    def fetchone(self):
        return {'page': self.page}


def configure_acl_defaults(monkeypatch, *, admit=True, diagnostics=None):
    from server.sli.semantic import file_acl_runtime
    calls, policies, logs = [], [], []

    def admission(cur, policy):
        assert [sql for sql, _ in cur.queries[-2:]] == [
            "set local statement_timeout='20s'", "set local lock_timeout='1s'",
        ], 'admission itself must inherit the bounded resource transaction'
        cur.kind = 'acl_resource'
        policies.append(compile_risk_policy(policy))
        return admit

    def run(cur, *, resource, now):
        calls.append((cur, resource, now))
        cur.native += 2
        if cur.failure == 'resource':
            raise RuntimeError('synthetic path/SID must not enter logs')
        return {'jobs': 2, 'portions': 1, 'diagnostics': diagnostics or {}, 'has_more': True, 'byte_count': 20}

    monkeypatch.setattr(defaults, '_admit', admission)
    monkeypatch.setattr(file_acl_runtime, 'run_once', run)
    monkeypatch.setattr(defaults, 'log_event', lambda *args, **kwargs: logs.append((args, kwargs)), raising=False)
    monkeypatch.setattr(defaults, 'run_source', lambda *args, **kwargs: defaults.SourceOutcome(jobs=1))
    return calls, policies, logs


def test_ordinary_defaults_reach_snapshot_only_acl_resource_once_and_medium(monkeypatch):
    from tests.unit.test_file_acl_input import RESOURCE
    calls, policies, _ = configure_acl_defaults(monkeypatch)
    conn = ACLDefaultConnection()  # no observation/core sources
    assert defaults.run_default_detections(conn) == _default_result(**{'sources': 1, 'jobs': 2, 'failed': 0})
    assert len(calls) == len(policies) == 1
    assert calls[0][0] is conn and calls[0][1] == RESOURCE
    assert policies[0].scenario_kind == 'qw.file-acl-broad-write'
    assert policies[0].risk_class.value == 'medium'
    assert policies[0].qw_execution_sha256
    assert conn.commits == ['legacy_discovery', 'acl_discovery', 'acl_resource']
    assert sum('read_default_file_acl_resources' in sql for sql, _ in conn.queries) == 1
    assert all('findings' not in sql for sql, _ in conn.queries)


def test_acl_owner_disabled_admission_precedes_any_native_read(monkeypatch):
    calls, policies, _ = configure_acl_defaults(monkeypatch, admit=False)
    conn = ACLDefaultConnection()
    assert defaults.run_default_detections(conn) == _default_result(**{'sources': 1, 'jobs': 0, 'failed': 0})
    assert len(policies) == 1 and calls == [] and conn.native == 0
    assert 'acl_resource' in conn.commits


@pytest.mark.parametrize('failure,expected', [
    ('legacy_discovery', {'sources': 1, 'jobs': 2, 'failed': 1}),
    ('acl_discovery', {'sources': 1, 'jobs': 1, 'failed': 1}),
    ('resource', {'sources': 2, 'jobs': 1, 'failed': 1}),
    ('commit', {'sources': 2, 'jobs': 1, 'failed': 1}),
])
def test_acl_and_legacy_failures_are_independent_and_job_counts_follow_commit(monkeypatch, failure, expected):
    _, _, logs = configure_acl_defaults(monkeypatch)
    conn = ACLDefaultConnection(legacy=[{'scope': {'synthetic': 'legacy'}}], failure=failure)
    assert defaults.run_default_detections(conn) == _default_result(**expected)
    if failure in ('resource', 'commit'):
        assert conn.native == 0 and conn.rollbacks[-1] == 'acl_resource'
        assert 'acl_discovery' in conn.commits
    encoded = json.dumps(logs)
    assert 'secret' not in encoded and 'SID' not in encoded and 'raw detail' not in encoded


@pytest.mark.parametrize('diagnostics,failed', [
    ({'verified_excluded': 2}, 0),
    ({'unsupported_descriptor': 1, 'blocked_direct_ad_proof_unsupported': 2}, 1),
    ({'private-synthetic-path-and-identity': 1}, 1),
])
def test_acl_partial_native_diagnostics_are_aggregate_and_readonly_is_not_failure(monkeypatch, diagnostics, failed):
    _, _, logs = configure_acl_defaults(monkeypatch, diagnostics=diagnostics)
    conn = ACLDefaultConnection()
    assert defaults.run_default_detections(conn) == _default_result(**{'sources': 1, 'jobs': 2, 'failed': failed})
    assert conn.native == 2 and conn.commits[-1] == 'acl_resource'
    assert logs, 'native exclusion/blocked diagnostics must remain visible'
    encoded = json.dumps(logs)
    assert 'private-synthetic-path-and-identity' not in encoded
    assert 'synthetic-root' not in encoded and 'synthetic-source' not in encoded
    assert all(key not in encoded for key in ('acl_context', 'evidence_refs', 'high'))


class FileDefaultConnection:
    """Unit orchestration fake; separate PostgreSQL tests exercise SQL aborts."""

    def __init__(self, *, exit_failure=None):
        self.connection = self
        self.info = SimpleNamespace(transaction_status=defaults.TransactionStatus.IDLE)
        self.recovery_status = None
        self.depth = 0
        self.writes = []
        self.exit_failure = exit_failure
        self.rows = []
        self.source = False
        self.savepoint_writes = []

    @contextmanager
    def transaction(self):
        before = list(self.writes)
        self.info.transaction_status = defaults.TransactionStatus.INTRANS
        self.depth += 1
        depth = self.depth
        try:
            yield
            if self.source and self.exit_failure == ('commit', depth):
                raise RuntimeError('synthetic commit failure')
        except Exception:
            self.writes[:] = before
            if self.source and self.exit_failure == ('rollback', depth):
                raise RuntimeError('synthetic rollback failure') from None
            raise
        finally:
            self.depth -= 1
            if depth == 1:
                self.source = False
                # UNKNOWN models a broken outer rollback and remains fatal.
                if self.info.transaction_status != defaults.TransactionStatus.UNKNOWN:
                    self.info.transaction_status = defaults.TransactionStatus.IDLE

    def cursor(self):
        return nullcontext(self)

    def execute(self, statement, params=()):
        if statement == 'savepoint default_file_ransom':
            self.savepoint_writes = list(self.writes)
        elif statement == 'rollback to savepoint default_file_ransom':
            if self.exit_failure == ('rollback', 2):
                raise RuntimeError('synthetic rollback failure')
            self.writes[:] = self.savepoint_writes
            if self.recovery_status is not None:
                self.info.transaction_status = self.recovery_status
        elif statement == 'release savepoint default_file_ransom':
            if self.exit_failure == ('commit', 2):
                raise RuntimeError('synthetic release failure')
        elif 'default_detection_sources()' in statement:
            self.rows = [{'source': file_source()}]
        elif 'read_default_file_acl_resources' in statement:
            self.rows = [{'page': {'items': []}}]
        elif 'pg_advisory_xact_lock' in statement:
            self.source = True

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0]


def file_source():
    return {'scope': asdict(reference('file_audit_observation').scope),
            'agent_id': '00000000-0000-0000-0000-000000000003',
            'config': {'policy_revision': '3', 'mass_operation_files': 25, 'mass_operation_seconds': 60}}


def configure_file_defaults(monkeypatch, *, failure=None, disabled=False):
    def admit(cur, policy):
        if compile_risk_policy(policy).scenario_kind == 'qw.file-ransom':
            cur.writes.append('ransom-admission')
            if failure == 'admission':
                raise ValueError('synthetic admission failure')
            return not disabled
        return True

    def decoy(cur, **kwargs):
        cur.writes.append('decoy')
        return {'jobs': 2}

    def ransom(cur, **kwargs):
        cur.writes.append('ransom-runtime')
        if failure == 'runtime':
            raise ValueError('synthetic runtime failure')
        return {'jobs': 3}

    monkeypatch.setattr(defaults, '_admit', admit)
    monkeypatch.setattr(defaults.file_decoy_runtime, 'run_once', decoy)
    monkeypatch.setattr(defaults.file_ransom_runtime, 'run_once', ransom)


@pytest.mark.parametrize('failure', ['construction', 'admission', 'runtime'])
def test_r01_failure_keeps_decoy_and_counts_one_failed_detector(monkeypatch, failure):
    configure_file_defaults(monkeypatch, failure=failure)
    if failure == 'construction':
        def invalid(**kwargs):
            raise ValueError('synthetic invalid R01 input')
        monkeypatch.setattr(defaults.file_ransom, 'RansomRule', invalid)
    conn = FileDefaultConnection()
    assert defaults.run_default_detections(conn) == _default_result(**{'sources': 1, 'jobs': 2, 'failed': 1})
    assert conn.writes == ['decoy']


@pytest.mark.parametrize('failure', [('commit', 1), ('commit', 2), ('rollback', 2)])
def test_r01_outer_commit_or_nested_rollback_failure_counts_no_source_jobs(monkeypatch, failure):
    configure_file_defaults(monkeypatch, failure='runtime' if failure[0] == 'rollback' else None)
    conn = FileDefaultConnection(exit_failure=failure)
    assert defaults.run_default_detections(conn) == _default_result(**{'sources': 1, 'jobs': 0, 'failed': 1})
    assert conn.writes == []


def test_r01_disabled_skips_runtime_without_failure_and_success_adds_both(monkeypatch):
    configure_file_defaults(monkeypatch, disabled=True)
    conn = FileDefaultConnection()
    assert defaults.run_default_detections(conn) == _default_result(**{'sources': 1, 'jobs': 2, 'failed': 0})
    assert 'ransom-runtime' not in conn.writes
    configure_file_defaults(monkeypatch)
    conn = FileDefaultConnection()
    assert defaults.run_default_detections(conn) == _default_result(**{'sources': 1, 'jobs': 5, 'failed': 0})


@pytest.mark.parametrize('status', [defaults.TransactionStatus.IDLE, defaults.TransactionStatus.INERROR,
                                  defaults.TransactionStatus.UNKNOWN])
def test_r01_uncertain_recovery_discards_entire_source(monkeypatch, status):
    configure_file_defaults(monkeypatch, failure='runtime')
    conn = FileDefaultConnection()
    conn.recovery_status = status
    if status == defaults.TransactionStatus.UNKNOWN:
        with pytest.raises(defaults.ProducerConnectionFatal):
            defaults.run_default_detections(conn)
        assert conn.rows == [{'source': file_source()}]  # No following ACL discovery.
    else:
        assert defaults.run_default_detections(conn) == _default_result(**{'sources': 1, 'jobs': 0, 'failed': 1})
    assert conn.writes == []


def test_outer_commit_after_isolated_r01_failure_does_not_double_count(monkeypatch):
    configure_file_defaults(monkeypatch, failure='runtime')
    conn = FileDefaultConnection(exit_failure=('commit', 1))
    assert defaults.run_default_detections(conn) == _default_result(**{'sources': 1, 'jobs': 0, 'failed': 1})
    assert conn.writes == []
