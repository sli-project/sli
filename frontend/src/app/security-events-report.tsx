import { EMPTY_VALUE } from "../shared/format";
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ApiResponseError, api, type SecurityEventItem, type SemanticRelationItem, type VpnSessionEvidence, type VpnSessionReport } from "../api/client";
import { formatDateTime } from "../shared/date-time";
import { Badge, Button, Callout } from "../design-system";
import { legacySecurityEventsHref } from "./report-v2/legacy";
import { переходДоТекст, переходПослеТекст } from "./ad-account-change-history";
import { t } from "../i18n";
import { codedText } from "../i18n/event-metadata";

export type SecurityEventsFilterState = {
  domainId?: number;
  timeFrom: string;
  timeTo: string;
  timeZone: string;
  category: string;
  eventId: string;
  outcome: string;
  actor: string;
  target: string;
  group: string;
  source: string;
  q: string;
  entityId?: number | string;
  eventDbId?: number | string;
  limit: number;
  cursor?: string;
};

export function getActionByEventId(id: number): string | undefined {
  const map: Record<number, import("../i18n").MessageKey> = {
    4624: "security.events.action.4624",
    4625: "security.events.action.4625",
    1102: "security.events.action.1102",
    4719: "security.events.action.4719",
    4720: "security.events.action.4720",
    4722: "security.events.action.4722",
    4723: "security.events.action.4723",
    4724: "security.events.action.4724",
    4725: "security.events.action.4725",
    4726: "security.events.action.4726",
    4727: "security.events.action.4727",
    4728: "security.events.action.4728",
    4729: "security.events.action.4729",
    4730: "security.events.action.4730",
    4731: "security.events.action.4731",
    4732: "security.events.action.4732",
    4733: "security.events.action.4733",
    4734: "security.events.action.4734",
    4735: "security.events.action.4735",
    4737: "security.events.action.4737",
    4738: "security.events.action.4738",
    4740: "security.events.action.4740",
    4754: "security.events.action.4754",
    4755: "security.events.action.4755",
    4756: "security.events.action.4756",
    4757: "security.events.action.4757",
    4758: "security.events.action.4758",
    4764: "security.events.action.4764",
    4767: "security.events.action.4767",
    4771: "security.events.action.4771",
    4776: "security.events.action.4776",
    4781: "security.events.action.4781",
  };
  const key = map[id];
  return key ? t(key) : undefined;
}

export function getSecurityEventFamilies() {
  return [
    ["", t("security.events.family.significant")],
    ["authentication", t("security.events.family.authentication")],
    ["account_lock", t("security.events.family.account_lock")],
    ["password_operation", t("security.events.family.password_operation")],
    ["account_lifecycle", t("security.events.family.account_lifecycle")],
    ["account_change", t("security.events.family.account_change")],
    ["group_membership", t("security.events.family.group_membership")],
    ["group_lifecycle", t("security.events.family.group_lifecycle")],
    ["audit_configuration", t("security.events.family.audit_configuration")],
  ] as const;
}

export const SECURITY_EVENT_FAMILIES = getSecurityEventFamilies();

const observedName = (principal: SecurityEventItem["actor"]): string =>
  principal.state === "observed" ? principal.name || principal.sid || t("security.events.actor.undefined") : t("security.events.actor.undefined");

function boundedChangeValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim().slice(0, 160) : null;
}

function sourceNativeChangeText(change: SecurityEventItem["change"]): string | null {
  if (!change) return null;
  if (change.state === "partial") {
    return change.detail?.reason
      ? t("security.events.change.partial_reason")
      : t("security.events.change.partial");
  }
  if (change.state !== "observed") return null;
  const attributes = Object.entries(change.attributes ?? {})
    .map(([name, value]) => {
      const safeValue = boundedChangeValue(value);
      return safeValue ? `${name.replaceAll("_", " ")}: ${safeValue}` : null;
    })
    .filter((value): value is string => value !== null);
  const directValues = Object.entries(change)
    .filter(([name, value]) => name !== "attributes" && name !== "detail" && typeof value === "string" && (name === "observed_value" || name.startsWith("old_") || name.startsWith("new_")))
    .map(([name, value]) => [name, boundedChangeValue(value)] as const)
    .filter((entry): entry is readonly [string, string] => entry[1] !== null);
  const oldValues = new Map(directValues.filter(([name]) => name.startsWith("old_")).map(([name, value]) => [name.slice(4), value]));
  const directText = directValues
    .filter(([name]) => !name.startsWith("old_"))
    .map(([name, value]) => name.startsWith("new_")
      ? oldValues.has(name.slice(4))
        ? `${name.slice(4).replaceAll("_", " ")}: ${oldValues.get(name.slice(4))} → ${value}`
        : `${name.slice(4).replaceAll("_", " ")}: ${value}`
      : `${name.replaceAll("_", " ")}: ${value}`);
  const parts = [...attributes, ...directText];
  return parts.length ? t("security.events.change.observed_parts", { parts: parts.join("; ") }) : change.kind ? t("security.events.change.observed_kind", { kind: change.kind }) : null;
}

function sourceNativeContext(item: SecurityEventItem): string | null {
  const caller = item.caller_computer?.state === "observed" ? t("security.events.context.caller", { host: item.caller_computer.hostname }) : null;
  const change = sourceNativeChangeText(item.change);
  return [caller, change].filter(Boolean).join(" · ") || null;
}

export function SecurityEventSourceContext({ source }: { source: string }) {
  return <span>{source}</span>;
}

export function securityEventsParams(filters: SecurityEventsFilterState): URLSearchParams {
  const params = new URLSearchParams({
    domain_id: String(filters.domainId ?? ""),
    time_from: filters.timeFrom,
    time_to: filters.timeTo,
    timezone: filters.timeZone,
    limit: String(filters.limit),
  });
  const optional: Array<[string, string | undefined]> = [
    ["category", filters.category], ["event_id", filters.eventId], ["outcome", filters.outcome],
    ["actor", filters.actor], ["target", filters.target], ["group", filters.group],
    ["source", filters.source], ["q", filters.q],
    ["entity_id", filters.entityId === undefined || filters.entityId === "" ? undefined : String(filters.entityId)],
    ["event_db_id", filters.eventDbId === undefined || filters.eventDbId === "" ? undefined : String(filters.eventDbId)],
    ["cursor", filters.cursor],
  ];
  for (const [name, value] of optional) if (value) params.set(name, value);
  return params;
}

export function securityReportReturnHref(
  filters: SecurityEventsFilterState,
  tab: "events" | "chains" = "events",
): string {
  const parameters = securityEventsParams(filters);
  parameters.delete("cursor");
  if (tab === "chains") parameters.set("tab", "chains");
  return legacySecurityEventsHref(`?${parameters.toString()}`);
}

export function securityEntityHref(
  entityId: number | null | undefined,
  filters: SecurityEventsFilterState,
  tab: "events" | "chains" = "events",
): string | null {
  if (!Number.isSafeInteger(entityId) || Number(entityId) <= 0) return null;
  const parameters = new URLSearchParams({
    time_from: filters.timeFrom,
    time_to: filters.timeTo,
    timezone: filters.timeZone,
    return_to: securityReportReturnHref(filters, tab),
  });
  return `/app/entities/${entityId}?${parameters.toString()}`;
}

export function securityRelationParams(filters: SecurityEventsFilterState): URLSearchParams {
  const params = securityEventsParams({ ...filters, limit: Math.min(200, filters.limit) });
  params.delete("cursor");
  return params;
}

export function shouldRestartSemanticRelations(error: unknown): boolean {
  return error instanceof ApiResponseError && error.code === "invalid_semantic_relation_filter";
}

export function semanticRelationsQueryKey(
  filters: SecurityEventsFilterState,
  cursorGeneration: number,
) {
  return ["security-relations", filters, { cursorGeneration }] as const;
}

export function vpnAccountingIsolatedByWindowsFilters(filters: SecurityEventsFilterState): boolean {
  return Boolean(
    filters.category || filters.eventId || filters.outcome || filters.actor || filters.target
    || filters.group || filters.source || filters.q || filters.entityId || filters.eventDbId,
  );
}

function invalidExactSelector(value: number | string | undefined): boolean {
  if (value === undefined || value === "") return false;
  const text = String(value);
  return !/^[1-9]\d*$/.test(text) || !Number.isSafeInteger(Number(text));
}

export function securityEventsExactSelectorError(filters: SecurityEventsFilterState): string | null {
  if (invalidExactSelector(filters.entityId)) return t("security.events.error.entity_id");
  if (invalidExactSelector(filters.eventDbId)) return t("security.events.error.event_id");
  return null;
}

export function vpnAccountingSessionParams(
  filters: SecurityEventsFilterState,
  offset = 0,
): URLSearchParams {
  const parameters = new URLSearchParams({
    domain_id: String(filters.domainId ?? ""),
    time_from: filters.timeFrom,
    time_to: filters.timeTo,
    timezone: filters.timeZone,
    limit: String(Math.min(200, filters.limit)),
  });
  if (offset > 0) parameters.set("offset", String(offset));
  return parameters;
}

export function vpnAccountingRows(
  report: VpnSessionReport,
  formatTime: (value?: string | null) => string,
) {
  return report.items.map((item) => {
    const stopped = Boolean(item.stopped_at_utc);
    const presentation = item.lifecycle_state === "closed"
      ? { lifecycle: t("security.events.vpn.lifecycle.closed"), completion: t("security.events.vpn.completion.closed") }
      : item.lifecycle_state === "partial_closed"
        ? { lifecycle: t("security.events.vpn.lifecycle.partial_closed"), completion: t("security.events.vpn.completion.no_start") }
        : item.lifecycle_state === "open_observed"
          ? { lifecycle: t("security.events.vpn.lifecycle.open"), completion: t("security.events.vpn.completion.no_stop") }
          : { lifecycle: t("security.events.vpn.lifecycle.interim"), completion: t("security.events.vpn.completion.none") };
    return {
      ...item,
      startedAt: formatTime(item.started_at_utc),
      lastObservedAt: formatTime(item.last_observed_at_utc),
      stoppedAt: stopped ? formatTime(item.stopped_at_utc) : null,
      ...presentation,
    };
  });
}

export function vpnAccountingCoverageText(
  report: Pick<VpnSessionReport, "state" | "coverage"> | undefined,
): string | null {
  if (!report || report.state === "available" || report.state === "not_authorized") return null;
  const unresolved = report.coverage
    ? report.coverage.identity_unresolved_count + report.coverage.timestamp_unresolved_count
    : 0;
  if (report.state === "processing") return t("security.events.vpn.coverage.processing");
  if (report.state === "not_collected") return t("security.events.vpn.coverage.not_collected");
  if (report.state === "identity_incomplete") return unresolved ? t("security.events.vpn.coverage.identity_incomplete_unresolved", { count: unresolved }) : t("security.events.vpn.coverage.identity_incomplete");
  return unresolved ? t("security.events.vpn.coverage.partial_unresolved", { count: unresolved }) : t("security.events.vpn.coverage.partial");
}

export function semanticRelationTitle(kind: string): string {
  const map: Record<string, import("../i18n").MessageKey> = {
    "authentication.account.lockout_preceded_by_failures_observed": "security.events.relation.title.lockout",
    "authentication.account.unlock_after_lock_observed": "security.events.relation.title.unlock",
    "directory.group.membership_reverted_observed": "security.events.relation.title.group_reverted",
    "directory.account.group_membership_added_observed": "security.events.relation.title.account_group",
    "authentication.password_reset_followed_by_logon_observed": "security.events.relation.title.password_logon",
  };
  const key = map[kind];
  return key ? t(key) : t("security.events.relation.title.default");
}

export function semanticRelationExplanation(
  relation: Pick<SemanticRelationItem, "relation_kind" | "explanation">,
): string {
  const map: Record<string, import("../i18n").MessageKey> = {
    "authentication.account.lockout_preceded_by_failures_observed": "security.events.relation.expl.lockout",
    "authentication.account.unlock_after_lock_observed": "security.events.relation.expl.unlock",
    "directory.group.membership_reverted_observed": "security.events.relation.expl.group_reverted",
    "directory.account.group_membership_added_observed": "security.events.relation.expl.account_group",
    "authentication.password_reset_followed_by_logon_observed": "security.events.relation.expl.password_logon",
  };
  const key = map[relation.relation_kind];
  return key ? t(key) : relation.explanation;
}

export function semanticRelationIdentityBasis(
  basis: SemanticRelationItem["identity_basis"],
): string | null {
  if (!basis) return null;
  if (basis.kind === "exact_domain_account_sid") {
    return t("security.events.relation.basis.account", { domain: basis.domain_id, sid: basis.account_sid });
  }
  if (basis.kind === "exact_domain_member_group_sid") {
    return t("security.events.relation.basis.group", { domain: basis.domain_id, member: basis.member_sid, group: basis.group_sid });
  }
  return t("security.events.relation.basis.generic", { domain: basis.domain_id, sid: basis.account_member_sid });
}

export function semanticRelationPresentation(relation: Pick<SemanticRelationItem, "continuation_state" | "possible_continuation_count">): string | null {
  if (relation.continuation_state === "unique" && relation.possible_continuation_count === 1) {
    return t("security.events.relation.presentation.unique");
  }
  if (relation.continuation_state === "ambiguous" && (relation.possible_continuation_count ?? 0) > 1) {
    return t("security.events.relation.presentation.ambiguous", { count: relation.possible_continuation_count ?? 0 });
  }
  return null;
}

function semanticEvidenceRoleLabel(role?: SemanticRelationItem["evidence"][number]["evidence_role"]): string | null {
  return role === "anchor" ? t("security.events.relation.role.anchor") : role === "alternative_continuation" ? t("security.events.relation.role.alternative") : null;
}

export function securityEventRows(items: SecurityEventItem[], formatTime: (value: string) => string) {
  return items.map((item) => {
    const targetPrincipal = item.event_family === "group_membership" ? item.member : item.affected_account;
    const before = item.account_change
      ? переходДоТекст(item.account_change.observed_transition.before)
      : undefined;
    const after = item.account_change
      ? переходПослеТекст(item.account_change.observed_transition.after)
      : undefined;
    return {
    key: item.event_db_id,
    time: formatTime(item.time_created_utc),
    action: getActionByEventId(item.event_id) ?? t("security.events.action.default", { id: item.event_id }),
    eventId: item.event_id,
    actor: observedName(item.actor),
    target: observedName(targetPrincipal),
    group: observedName(item.group),
    actorEntityId: item.actor.state === "observed" ? item.actor.entity_id : undefined,
    targetEntityId: targetPrincipal.state === "observed" ? targetPrincipal.entity_id : undefined,
    groupEntityId: item.group.state === "observed" ? item.group.entity_id : undefined,
    sourceText: [
      item.source_host.state === "observed" ? item.source_host.hostname : t("security.events.actor.undefined"),
      sourceNativeContext(item),
    ].filter(Boolean).join(" · "),
    result: item.outcome.state === "observed"
      ? item.outcome.value === "success" ? t("security.events.rows.result.success") : t("security.events.rows.result.failure")
      : t("security.events.rows.result.unconfirmed"),
    resultTone: item.outcome.state !== "observed" ? "warn" as const : item.outcome.value === "success" ? "good" as const : "bad" as const,
    evidenceState: item.evidence.state,
    eventHref: `/app/events/${item.event_db_id}`,
    before,
    after,
    };
  });
}

export function VpnAccountingIsolationNotice() {
  return <section className="sli-ds-panel"><div className="sli-ds-note">{t("security.events.vpn.isolation_notice")}</div></section>;
}

export function RelationCursorRestartNotice() {
  return <Callout role="status" icon="warning" title={t("security.events.chains.restart.title")}>{t("security.events.chains.restart.text")}</Callout>;
}

export function SecurityRelationsPanel({ items, state, coverage, loading, failed, hasMore, fetchingMore, fetchMore, filters }: { items: SemanticRelationItem[]; state?: string; coverage?: import("../api/client").SemanticRelationsReport["coverage"]; loading: boolean; failed: boolean; hasMore: boolean; fetchingMore: boolean; fetchMore: () => void; filters: SecurityEventsFilterState }) {
  const returnTo = securityReportReturnHref(filters, "chains");
  return <section className="sli-ds-panel"><div className="sli-ds-panel__head"><div><h2 className="sli-ds-panel__title">{t("security.events.chains.panel.title")}</h2><p className="sli-ds-panel__subtitle">{t("security.events.chains.panel.subtitle")}</p></div><Badge>{hasMore ? t("security.events.chains.panel.count_more", { count: items.length }) : t("security.events.chains.panel.count", { count: items.length })}</Badge></div><div className="sli-ds-panel__body">
    {loading ? <div className="sli-ds-note" role="status">{t("security.events.chains.panel.loading")}</div> : null}
    {failed ? <div className="sli-ds-note">{t("security.events.chains.panel.failed")}</div> : null}
    {state === "schema_unavailable" ? <div className="sli-ds-note">{t("security.events.chains.panel.schema_unavailable")}</div> : null}
    {state === "not_authorized" ? <div className="sli-ds-note">{t("security.events.chains.panel.not_authorized")}</div> : null}
    {state === "empty" ? <div className="sli-ds-note">{t("security.events.chains.panel.empty")}</div> : null}
    {coverage && coverage.state !== "not_authorized" ? <details className="sli-ds-note"><summary>{t("security.events.chains.coverage.title")}</summary><p>{t("security.events.chains.coverage.matched", { count: coverage.matched_relation_count ?? 0 })}</p>{coverage.supported_rules?.length ? <p>{t("security.events.chains.coverage.supported", { rules: coverage.supported_rules.map((rule) => `${rule.rule_id} v${rule.rule_version} (${rule.lifecycle_status})`).join(", ") })}</p> : null}{coverage.observed_rules?.length ? <p>{t("security.events.chains.coverage.observed", { rules: coverage.observed_rules.map((rule) => `${rule.rule_id} v${rule.rule_version}`).join(", ") })}</p> : null}{coverage.supported_rules_state === "check_unavailable" ? <p>{t("security.events.chains.coverage.unavailable")}</p> : null}{coverage.limitations?.map((limitation, index) => <p key={limitation}>{codedText(`security.events.chains.coverage.limitations.${coverage.limitation_codes?.[index]}`, limitation)}</p>)}</details> : null}
    {items.length ? <div className="sli-ds-list">{items.map((relation) => <article className="sli-ds-list__item" key={relation.candidate_id}><div><div className="sli-ds-list__title">{semanticRelationTitle(relation.relation_kind)}</div><div className="sli-ds-list__copy">{formatDateTime(relation.window_start_utc, filters.timeZone)} — {formatDateTime(relation.window_end_utc, filters.timeZone)}</div>{semanticRelationPresentation(relation) ? <div className="sli-ds-note">{semanticRelationPresentation(relation)}</div> : null}<ol>{[...relation.evidence].sort((a, b) => a.evidence_order - b.evidence_order).map((evidence) => <li key={evidence.event_db_id}>{semanticEvidenceRoleLabel(evidence.evidence_role) ? <strong>{semanticEvidenceRoleLabel(evidence.evidence_role)} · </strong> : null}<span>{getActionByEventId(evidence.event_id) ?? t("security.events.action.default", { id: evidence.event_id })} · {formatDateTime(evidence.time_created_utc, filters.timeZone)} · {evidence.source_host}</span> <Link to="/events/$eventId" params={{ eventId: String(evidence.event_db_id) }} search={{ time_from: filters.timeFrom, time_to: filters.timeTo, timezone: filters.timeZone, return_to: returnTo }}>{t("security.events.chains.evidence.db_link", { id: evidence.event_db_id })}</Link></li>)}</ol><details><summary>{t("security.events.chains.evidence.basis")}</summary><p>{semanticRelationExplanation(relation)}</p>{semanticRelationIdentityBasis(relation.identity_basis) ? <p className="sli-ds-mono">{semanticRelationIdentityBasis(relation.identity_basis)}</p> : null}<p className="sli-ds-mono">{relation.rule_id} · {t("security.events.chains.evidence.version", { version: relation.rule_version })} · {relation.confidence}</p></details></div></article>)}</div> : null}
    {hasMore ? <Button disabled={fetchingMore} onClick={fetchMore}>{fetchingMore ? t("security.events.chains.action.loading") : t("security.events.chains.action.more")}</Button> : null}
  </div></section>;
}

function VpnAccountingEvidencePanel({ domainId, sessionRowId, timeZone }: {
  domainId: number;
  sessionRowId: string;
  timeZone: string;
}) {
  const evidence = useQuery<VpnSessionEvidence>({
    queryKey: ["security-relations", "vpn-accounting-evidence", domainId, sessionRowId],
    queryFn: () => api.vpnSessionEvidence(domainId, sessionRowId),
    retry: false,
  });
  if (evidence.isLoading) return <div className="sli-ds-note" role="status">{t("security.events.vpn.evidence.loading")}</div>;
  if (evidence.isError) return <div className="sli-ds-note">{t("security.events.vpn.evidence.failed")}</div>;
  if (evidence.data?.state === "not_authorized") return <div className="sli-ds-note">{t("security.events.vpn.evidence.not_authorized")}</div>;
  return <ol>{(evidence.data?.observations ?? []).map((observation) => <li key={observation.observation_id}>
    <span>{observation.lifecycle_event === "start" ? t("security.events.vpn.evidence.event.start") : observation.lifecycle_event === "stop" ? t("security.events.vpn.evidence.event.stop") : observation.lifecycle_event === "interim_update" ? t("security.events.vpn.evidence.event.interim") : observation.lifecycle_event} · {observation.observed_at_utc ? formatDateTime(observation.observed_at_utc, timeZone) : t("security.events.vpn.evidence.time_unconfirmed")} · {observation.evidence.source_instance_id}</span>
    <div className="sli-ds-list__copy sli-ds-mono">SHA-256 {observation.evidence.canonical_record_sha256.slice(0, 16)}…</div>
  </li>)}</ol>;
}

export function VpnAccountingSessionsPanel({ report, items, loading, failed, hasMore, fetchingMore, fetchMore, filters }: {
  report?: VpnSessionReport;
  items: VpnSessionReport["items"];
  loading: boolean;
  failed: boolean;
  hasMore: boolean;
  fetchingMore: boolean;
  fetchMore: () => void;
  filters: SecurityEventsFilterState;
}) {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [savedReferences, setSavedReferences] = useState<Set<string>>(() => new Set());
  const referenceKey = (caseId: string, domainId: number, sessionRowId: string) => JSON.stringify([caseId, domainId, sessionRowId]);
  const cases = useQuery({
    queryKey: ["investigation-cases"],
    queryFn: api.investigationCases,
    staleTime: 30_000,
    retry: false,
  });
  useEffect(() => {
    if (!selectedCaseId && cases.data?.items[0]) {
      setSelectedCaseId(String(cases.data.items[0].id));
    }
  }, [cases.data, selectedCaseId]);
  const saveEvidence = useMutation({
    mutationFn: (row: { caseId: string; domain_id: number; session_row_id: string }) => api.addInvestigationEvidenceRef(
      Number(row.caseId),
      {
        evidence_kind: "vpn_accounting_session",
        source_domain_id: row.domain_id,
        reference_id: row.session_row_id,
      },
    ),
    onSuccess: async (_result, row) => {
      setSavedReferences((previous) => new Set(previous).add(referenceKey(row.caseId, row.domain_id, row.session_row_id)));
      await queryClient.invalidateQueries({ queryKey: ["investigation-case", row.caseId] });
    },
  });
  const coverageText = vpnAccountingCoverageText(report);
  const rows = vpnAccountingRows(
    { ...(report ?? { contract_id: "sli.vpn-session-report.v1", report_key: "vpn.audit", source_domain_id: filters.domainId ?? 0, state: "not_collected", branches: {}, coverage: null, page: { limit: 200, offset: 0, has_more: false } }), items },
    (value) => value ? formatDateTime(value, filters.timeZone) : EMPTY_VALUE,
  );
  return <section className="sli-ds-panel"><div className="sli-ds-panel__head"><div><h2 className="sli-ds-panel__title">{t("security.events.vpn.panel.title")}</h2><p className="sli-ds-panel__subtitle">{t("security.events.vpn.panel.subtitle")}</p></div><Badge>{hasMore ? t("security.events.vpn.panel.count_more", { count: rows.length }) : t("security.events.vpn.panel.count", { count: rows.length })}</Badge></div><div className="sli-ds-panel__body">
    {loading ? <div className="sli-ds-note" role="status">{t("security.events.vpn.panel.loading")}</div> : null}
    {failed ? <div className="sli-ds-note">{t("security.events.vpn.panel.failed")}</div> : null}
    {report?.state === "not_authorized" ? <div className="sli-ds-note">{t("security.events.vpn.panel.not_authorized")}</div> : null}
    {coverageText ? <div className="sli-ds-note">{coverageText}</div> : null}
    {rows.length && cases.data?.items.length ? <div className="sli-ds-field"><label>{t("security.events.vpn.panel.investigation.label")}</label><select value={selectedCaseId} onChange={(event) => setSelectedCaseId(event.target.value)}>{cases.data.items.map((item) => <option value={item.id} key={item.id}>#{item.id} · {item.title}</option>)}</select></div> : null}
    {rows.length && cases.data && !cases.data.items.length ? <div className="sli-ds-note">{t("security.events.vpn.panel.investigation.create_note_pre")}<a href="/app/investigations">{t("security.events.vpn.panel.investigation.create_note_link")}</a>{t("security.events.vpn.panel.investigation.create_note_post")}</div> : null}
    {!loading && !failed && report && report.state === "available" && !rows.length ? <div className="sli-ds-note">{t("security.events.vpn.panel.empty")}</div> : null}
    {rows.length ? <div className="sli-ds-list">{rows.map((row) => <article className="sli-ds-list__item" key={row.session_row_id}><div><div className="sli-ds-list__title">{row.lifecycle}</div><div className="sli-ds-list__copy">{t("security.events.vpn.row.entity", { id: row.entity_id })} · {t("security.events.vpn.row.start", { time: row.startedAt })} · {t("security.events.vpn.row.last_observed", { time: row.lastObservedAt })}{row.stoppedAt ? ` · ${t("security.events.vpn.row.stop", { time: row.stoppedAt })}` : ""}</div><div className="sli-ds-list__copy">{row.completion} · {t("security.events.vpn.row.observations", { count: row.observation_count })}</div><div className="sli-ds-list__actions"><a href={securityEntityHref(row.entity_id, filters, "chains") ?? undefined}>{t("security.events.vpn.row.open_entity")}</a><Button onClick={() => setSelected(selected === row.session_row_id ? null : row.session_row_id)}>{selected === row.session_row_id ? t("security.events.vpn.row.hide_evidence") : t("security.events.vpn.row.show_evidence")}</Button>{selectedCaseId && report?.branches.session_evidence?.state === "available" ? <Button disabled={saveEvidence.isPending} onClick={() => saveEvidence.mutate({ ...row, caseId: selectedCaseId })}>{savedReferences.has(referenceKey(selectedCaseId, row.domain_id, row.session_row_id)) ? t("security.events.vpn.row.save_saved") : saveEvidence.isPending && saveEvidence.variables?.caseId === selectedCaseId && saveEvidence.variables?.domain_id === row.domain_id && saveEvidence.variables?.session_row_id === row.session_row_id ? t("security.events.vpn.row.save_saving") : t("security.events.vpn.row.save_action")}</Button> : null}</div>{saveEvidence.isError && saveEvidence.variables?.caseId === selectedCaseId && saveEvidence.variables?.domain_id === row.domain_id && saveEvidence.variables?.session_row_id === row.session_row_id ? <div className="sli-ds-list__copy sli-ds-error">{t("security.events.vpn.row.save_error")}</div> : null}{selected === row.session_row_id ? <VpnAccountingEvidencePanel domainId={row.domain_id} sessionRowId={row.session_row_id} timeZone={filters.timeZone}/> : null}</div></article>)}</div> : null}
    {hasMore ? <Button disabled={fetchingMore} onClick={fetchMore}>{fetchingMore ? t("security.events.chains.action.loading") : t("security.events.vpn.panel.more")}</Button> : null}
  </div></section>;
}

