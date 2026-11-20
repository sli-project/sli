"""Run built-in native detectors inside the managed findings worker.

Only already admitted/imported agent sources are discovered. Each source owns
a legacy transaction followed by separate managed password producer attempts.
A recoverable scope failure cannot prevent other scopes or L1 jobs progressing. Native readers retain their receipt and evidence checks.
"""
import json
from collections import OrderedDict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from psycopg.pq import TransactionStatus

from server.sli.ops import shutdown
from server.sli.ops.logging_config import log_event
from server.sli.plugins.registry import plugin_hook
from server.sli.semantic import (
    account_decoy,
    account_decoy_runtime,
    account_watch,
    account_watch_runtime,
    file_acl_input,
    file_acl_runtime,
    file_decoy,
    file_decoy_runtime,
    file_ransom,
    file_ransom_runtime,
    password_attack_policy,
    password_attack_producer,
    password_attack_v2,
    password_attacks,
)
from server.sli.semantic.password_attack_producer import (
    ProducerConnectionFatal,
    require_password_connection_idle,
)
from server.sli.semantic.qw_input import _digest, enqueue_qw_signal_risk_jobs
from server.sli.storage.evidence_ref import EvidenceScope
from server.sli.storage.xml_safety import parse_bounded_xml

_ACL_DIAGNOSTIC_CODES = frozenset({
    "source_unbound", "result_hash_mismatch", "snapshot_proof_mismatch", "producer_identity_mismatch",
    "blocked_result_detail_subset", "owner_denied", "unsupported_descriptor", "verified_excluded",
    "blocked_direct_ad_proof_unsupported", "blocked_broad_principal_unsupported",
})


def _acl_diagnostics(result):
    diagnostics = result.get("diagnostics", {})
    if not isinstance(diagnostics, dict):
        raise ValueError("file_acl_diagnostics_invalid")
    counts = {}
    for code, count in diagnostics.items():
        if type(count) is not int or not 0 <= count <= 32:
            raise ValueError("file_acl_diagnostics_invalid")
        if count:
            safe_code = code if code in _ACL_DIAGNOSTIC_CODES else "unrecognized_status"
            counts[safe_code] = counts.get(safe_code, 0) + count
    return counts


# Process-local retry state is bounded. Source discovery still revalidates retained
# policy every cycle; even an unchanged assignment may become ready later.
_RANSOM_RETRY_SECONDS = 60
_RANSOM_WAITS = OrderedDict()
_RANSOM_WAIT_LIMIT = 1024


def _ransom_wait_key(rule):
    return rule.checkpoint_key


def _ransom_wait_pending(rule, now):
    entry = _RANSOM_WAITS.get(_ransom_wait_key(rule))
    return entry is not None and entry[0] <= now.timestamp() < entry[1]


def _ransom_wait(rule, now):
    key = _ransom_wait_key(rule)
    first = key not in _RANSOM_WAITS
    _RANSOM_WAITS[key] = (now.timestamp(), now.timestamp() + _RANSOM_RETRY_SECONDS)
    _RANSOM_WAITS.move_to_end(key)
    while len(_RANSOM_WAITS) > _RANSOM_WAIT_LIMIT:
        _RANSOM_WAITS.popitem(last=False)
    if first:
        log_event("semantic", "file_ransom_source_policy_waiting",
                  "Source policy changed or is not retained; waiting for matching policy and data.",
                  retry_after_seconds=_RANSOM_RETRY_SECONDS)


def _ransom_policy_mismatch(exc):
    # Never classify an authorization, continuity or arbitrary application error
    # as an expected policy transition; do not put raw database text in status.
    return (getattr(exc, "sqlstate", None) == "P0001"
            and getattr(getattr(exc, "diag", None), "message_primary", None)
            == "file_ransom_source_policy_mismatch")


def policy_id(pin):
    return "default:" + pin["rule_id"] + ":" + _digest(pin)[:32]


def _admit(cur, policy):
    # The definer permits only the enumerated built-ins in an authorized scope.
    # ON CONFLICT preserves every administrator decision, including disable.
    cur.execute("select public.ensure_default_qw_policy(%s,%s,%s) as enabled",
                (policy.policy_id, policy.policy_version, policy.definition_json))
    return (cur.fetchone() or {}).get("enabled") is True


def read_password_events(cur, scope):
    cur.execute("select * from public.read_default_password_events(%s::jsonb)", (json.dumps(asdict(scope)),))
    rows = list(cur.fetchall() or [])
    if len(rows) > 10000:
        raise ValueError("password_attack_window_truncated")
    result = []
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    for row in rows:
        root = parse_bounded_xml(row.pop("source_xml"))
        data = root.find(ns + "EventData")
        fields = {}
        if data is not None:
            for node in data:
                name = node.get("Name")
                if node.tag != ns + "Data" or not name or name in fields or len(node):
                    raise ValueError("password_attack_event_data_invalid")
                fields[name] = node.text or ""
        result.append(row | {"event_data": fields})
    return result


@dataclass(frozen=True)
class SourceOutcome:
    jobs: int
    failed: int = 0
    waiting: int = 0


def run_source(cur, source, *, now) -> SourceOutcome:
    scope = EvidenceScope(**source["scope"])
    jobs = 0
    if scope.plugin_id == "sli.windows.ad-dc":
        for module, runtime, cls in (
            (account_decoy, account_decoy_runtime, account_decoy.DecoyRule),
            (account_watch, account_watch_runtime, account_watch.WatchRule),
        ):
            rule = cls(scope=scope, evaluation_mode="enabled")
            policy = module.risk_policy(rule, policy_id=policy_id(rule.execution))
            if _admit(cur, policy):
                jobs += runtime.run_once(cur, rule=rule, now=now)["jobs"]
        rule_id = "qw.disabled-account-logon"
        pin = password_attacks.execution(scope, rule_id)
        policy = password_attacks.risk_policy(scope, rule_id, policy_id=policy_id(pin))
        if _admit(cur, policy):
            for signal in password_attacks.evaluate(scope, read_password_events(cur, scope), now=now):
                if signal.rule_id == rule_id:
                    jobs += len(enqueue_qw_signal_risk_jobs(cur, signal=signal))
    if scope.plugin_id in {"sli.windows.ad-dc", "sli.vpn-nps"}:
        hook = plugin_hook("sli.remote-access", "default_detections")
        if hook is not None:
            jobs += hook(cur, scope, now=now, admit=_admit, policy_id=policy_id)
    if scope.plugin_id == "sli.file-audit":
        rule = file_decoy.FileDecoyRule(scope=scope, agent_id=source["agent_id"], evaluation_mode="enabled")
        if _admit(cur, file_decoy.risk_policy(rule, policy_id=policy_id(rule.execution))):
            jobs += file_decoy_runtime.run_once(cur, rule=rule, now=now)["jobs"]
        # Static SAVEPOINT commands leave driver nesting unchanged if entry fails.
        cur.execute("savepoint default_file_ransom")
        ransom_jobs = 0
        try:
            config = source["config"]
            rule = file_ransom.RansomRule(scope=scope, agent_id=source["agent_id"],
                source_policy_revision=config.get("policy_revision", "1"), evaluation_mode="enabled",
                threshold=config.get("mass_operation_files", 100), window_seconds=config.get("mass_operation_seconds", 300))
            if _admit(cur, file_ransom.risk_policy(rule, policy_id=policy_id(rule.execution))):
                if _ransom_wait_pending(rule, now):
                    cur.execute("release savepoint default_file_ransom")
                    return SourceOutcome(jobs=jobs, failed=1, waiting=1)
                readiness = source.get("ransom_policy")
                if readiness is not None and readiness.get("state") != "ready":
                    _ransom_wait(rule, now)
                    cur.execute("release savepoint default_file_ransom")
                    return SourceOutcome(jobs=jobs, failed=1, waiting=1)
                ransom_jobs = file_ransom_runtime.run_once(cur, rule=rule, now=now)["jobs"]
                _RANSOM_WAITS.pop(_ransom_wait_key(rule), None)
        except ProducerConnectionFatal:
            raise
        except Exception as exc:
            # Failed rollback/release propagates to the outer source transaction.
            cur.execute("rollback to savepoint default_file_ransom")
            cur.execute("release savepoint default_file_ransom")
            if cur.connection.info.transaction_status != TransactionStatus.INTRANS:
                raise
            if _ransom_policy_mismatch(exc):
                _ransom_wait(rule, now)
                return SourceOutcome(jobs=jobs, failed=1, waiting=1)
            return SourceOutcome(jobs=jobs, failed=1)
        cur.execute("release savepoint default_file_ransom")
        jobs += ransom_jobs
    return SourceOutcome(jobs=jobs)


_PASSWORD_COVERAGE_KEYS = ("healthy", "partial", "error", "unknown", "stale", "disabled", "failed")
_PASSWORD_HEALTH_STATUSES = frozenset(("healthy", "partial", "error", "unknown", "stale"))
_PASSWORD_WORK_KEYS = ("native_items", "xml_bytes", "retained_queries", "reservation_occurrences",
    "window_queries", "reservation_calls", "tracking_calls", "completion_calls")


def _password_counts(outcome, coverage, work):
    # The public producer returns jobs only after its owned COMMIT. Disabled
    # decisions and failed attempts must never look like healthy observations.
    if outcome.failed is not False:
        coverage["failed"] += 1
        return 0, 1
    if outcome.status == "disabled":
        coverage["disabled"] += 1
        return 0, 0
    if outcome.status != "committed" or type(outcome.jobs) is not int or outcome.jobs < 0:
        raise ValueError("password_v2_outcome_invalid")
    status = outcome.health.get("status") if isinstance(outcome.health, dict) else None
    status = status if type(status) is str and status in _PASSWORD_HEALTH_STATUSES else "unknown"
    coverage[status] += 1
    if isinstance(outcome.work, dict):
        for key in _PASSWORD_WORK_KEYS:
            count = outcome.work.get(key)
            if type(count) is int and count >= 0:
                work[key] += count
    return outcome.jobs, 0


def run_default_detections(conn):
    require_password_connection_idle(conn)
    now = datetime.now(timezone.utc)
    jobs = failed = waiting = 0
    coverage = dict.fromkeys(_PASSWORD_COVERAGE_KEYS, 0)
    work = dict.fromkeys(_PASSWORD_WORK_KEYS, 0)
    sources = []
    try:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("select source from public.default_detection_sources()")
            discovered = [row["source"] for row in cur.fetchall() or []]
        require_password_connection_idle(conn)
        sources = discovered
    except ProducerConnectionFatal:
        raise
    except Exception:
        require_password_connection_idle(conn)
        failed += 1
        log_event("semantic", "default_legacy_discovery_failed", "Native source discovery failed.")
    for source in sources:
        if shutdown.requested():
            break
        try:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute("select pg_advisory_xact_lock(hashtextextended(%s,0))", (_digest(source["scope"]),))
                outcome = run_source(cur, source, now=now)
            require_password_connection_idle(conn)
            jobs += outcome.jobs
            failed += outcome.failed
            waiting += outcome.waiting
        except ProducerConnectionFatal:
            raise
        except Exception:
            require_password_connection_idle(conn)
            # No XML, identity or source values in worker status/logs.
            failed += 1
        if source.get("scope", {}).get("plugin_id") == "sli.windows.ad-dc":
            for kind in ("brute", "spray"):
                if shutdown.requested():
                    break
                try:
                    require_password_connection_idle(conn)
                    rule = password_attack_v2.Rule(EvidenceScope(**source["scope"]), kind)
                    policy = password_attack_policy.risk_policy(rule)
                    outcome = password_attack_producer.run_password_producer(conn, rule=rule, managed_policy=policy)
                    require_password_connection_idle(conn)
                    committed_jobs, attempt_failed = _password_counts(outcome, coverage, work)
                    jobs += committed_jobs
                    failed += attempt_failed
                except ProducerConnectionFatal:
                    raise
                except Exception:
                    # Continue only after recovery to a known-IDLE connection.
                    require_password_connection_idle(conn)
                    failed += 1
                    coverage["failed"] += 1
    resources = []
    try:
        # Configured resource discovery is independent of observation sources.
        # Its owner-held persisted cursor wraps at EOF; one page per cycle
        # prevents a failed/disabled early root from starving later resources.
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("set local statement_timeout='20s'")
            cur.execute("set local lock_timeout='1s'")
            cur.execute("select public.read_default_file_acl_resources(null,1) as page")
            page = (cur.fetchone() or {}).get("page")
            page = json.loads(page) if isinstance(page, str) else page
            if not isinstance(page, dict) or not isinstance(page.get("items"), list) or len(page["items"]) > 1:
                raise ValueError("file_acl_discovery_invalid")
            discovered = page["items"]
        require_password_connection_idle(conn)
        resources = discovered
    except ProducerConnectionFatal:
        raise
    except Exception:
        require_password_connection_idle(conn)
        failed += 1
        log_event("semantic", "default_acl_discovery_failed", "ACL resource discovery failed.")
    for resource in resources:
        if shutdown.requested():
            break
        try:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute("set local statement_timeout='20s'")
                cur.execute("set local lock_timeout='1s'")
                policy = file_acl_input.risk_policy(resource, policy_id=policy_id(file_acl_input.execution(resource)))
                if not _admit(cur, policy):
                    continue
                result = file_acl_runtime.run_once(cur, resource=resource, now=now)
                resource_jobs = int(result["jobs"])
                diagnostics = _acl_diagnostics(result)
            require_password_connection_idle(conn)
            # Failed commit cannot count rolled-back jobs as durable work.
            jobs += resource_jobs
            if diagnostics:
                failed += int(any(code != "verified_excluded" for code in diagnostics))
                log_event("semantic", "default_acl_diagnostics", "ACL native input diagnostics.", counts=diagnostics)
        except ProducerConnectionFatal:
            raise
        except Exception:
            require_password_connection_idle(conn)
            failed += 1
            log_event("semantic", "default_acl_resource_failed", "ACL resource transaction failed.")
        finally:
            # Also runs after an intentionally disabled resource continues.
            require_password_connection_idle(conn)
    result = {"sources": len(sources) + len(resources), "jobs": jobs, "failed": failed,
        "coverage_counts": coverage, "password_work_counts": work}

    if waiting:
        result["file_ransom_status"] = {
            "code": "source_policy_waiting", "sources": waiting,
            "message_code": "operations.actions.fileRansomPolicyWaiting",
            "retry_after_seconds": _RANSOM_RETRY_SECONDS,
        }
    return result
