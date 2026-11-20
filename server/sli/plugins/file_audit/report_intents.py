"""Acceptance passports for the executable file-audit products."""
from server.sli.plugins.file_audit.contracts import RETENTION
from server.sli.reporting.v2.definition import ReportIntent

# Product requirements are not installed acceptance evidence.
PRODUCTS = {
    "overview": (
        "Which configured file-audit roots have confirmed observations and audit coverage?",
        "Summarize each configured root independently; event counts do not prove coverage.",
        "Keep unconfirmed roots and unavailable audit state unknown instead of zero activity.",
    ),
    "actions": (
        "Which file actions are supported by retained native observations in the selected window?",
        "Use native event, access mask, outcome and correlation state; reads do not prove copying.",
        "Incomplete or ambiguous correlation retains native observations without asserting a completed action.",
    ),
    "mass-operations": (
        "Which observed file-operation groups meet the configured count and time thresholds?",
        "Apply the agent policy revision's mass-operation count/window and explicit service-account exclusions.",
        "Missing policy, identity or window coverage prevents a confirmed mass-operation interpretation.",
    ),
    "permission-changes": (
        "Which file permission changes have native event or retained ACL comparison evidence?",
        "Separate native permission-change events from retained before/after ACL comparisons.",
        "Missing prior ACL leaves the change comparison unknown rather than an invented before state.",
    ),
    "access-denials": (
        "Which file-access failures are supported by native failure observations?",
        "Use recorded failure outcome and access mask; absence of success is not an access denial.",
        "Unknown outcome or incomplete audit coverage cannot confirm denied access.",
    ),
    "out-of-hours": (
        "Which observed file actions fall outside the configured working hours?",
        "Interpret source UTC timestamps only against an explicitly configured schedule and timezone.",
        "Missing schedule or timezone leaves out-of-hours classification not evaluated.",
    ),
    "permissions": (
        "Which file ACL permissions are supported by the latest retained inventory?",
        "Describe observed ACL and inheritance within configured roots; do not infer unobserved effective rights.",
        "Unreadable ACL, missing membership or incomplete inventory remains unknown.",
    ),
    "audit-state": (
        "Which configured roots have confirmed audit policy and SACL state?",
        "Separate observed subcategory/SACL state, requested policy revision and confirmed application.",
        "An unacknowledged request never becomes applied; missing readback keeps audit state unknown.",
    ),
}


def make_intent(key):
    question, policy, fallback = PRODUCTS[key]
    report_key = f"file-audit.{key}"
    intent = ReportIntent(
        version=1, user_role="File-audit security reviewer", question=question,
        action="Review authorized observations and limitations; report reads never manage Windows audit.",
        scope="Server-authorized agent, source instance, configured local root and selected observation window.",
        exclusions="No inferred copying, unobserved activity, organization compliance or implicit audit mutation.",
        sources=("Canonical: native Windows Security file-audit observations and source-confirmed ACL/audit inventory.",),
        freshness_expectation="Per-source event time and latest confirmed inventory/readback; request time is not confirmation.",
        rights=f"{report_key} grant, file-audit capabilities and server-built agent/root/field scope; export independently granted.",
        field_classes=("identity_basic", "technical", "security", "privilege"),
        coverage="Configured authorized roots and expected audit channels over the selected window.",
        completeness="Confirmed root/channel/window intervals divided by expected intervals; unknown without continuity evidence.",
        denominator="Authorized configured roots multiplied by expected audit channels and selected window duration.",
        retention=f"Raw payload: {RETENTION['source_payload_days']} days; facts: {RETENTION['facts']}; ACL history: {RETENTION['acl_history_days']} days; cleanup remains disabled.",
        provenance="Agent, source instance, channel generation, native record/event ID, policy revision, collection scope and payload hash.",
        primary_archetype="list", product_archetype="investigation-evidence",
        deterministic_policy=policy,
        result_limits="Pages of 50 to 100 rows, up to 31 days and 1000 authorized roots; CSV up to 10000 rows. Native identity remains visible when enrichment is absent.",
        fallback=fallback,
        acceptance_lanes={
            "product_user": f"The {key} product answers: {question}",
            "authorization": f"{report_key}, file-audit.view/export and atomic field scope must constrain agent/root evidence; audit management is separate.",
            "deterministic_interpretation": policy,
            "api_view_model": f"{report_key} uses sli.report-result.v2 with server-bound cursors, exact time windows and independently authorized CSV.",
            "ui_honest_states": f"When published, {key} must expose missing, denied, partial, stale and unavailable evidence: {fallback}",
            "evidence_audit": f"{key} must preserve native identity, source generation, policy revision and payload retention boundaries.",
        },
    )
    intent.validate()
    return intent


def report_intent(key):
    from server.sli.plugins.file_audit.reports import REPORTS

    return next(report for report in REPORTS if report.key == f"file-audit.{key}").intent_contract()
