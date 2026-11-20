import { formatNumber } from "../shared/format";
import { caseNumber } from "./case-number";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useLocation, useNavigate } from "@tanstack/react-router";
import { ApiResponseError, api, type InvestigationCaseSummary as CaseSummary, type InvestigationWorkspaceV1 } from "../api/client";
import { EventCardCompletenessBadge, EventClassificationBadge, RiskBadge } from "../components/badges/Badges";
import { DateTime } from "../components/date-time/DateTime";
import { DataTable, FactList, MetricStrip, PageHeader, StateView, type TableColumn } from "../design-system";
import { t } from "../i18n";
import { fixedText } from "../i18n/fixed-text";
import { eventSemanticText, relationConfidenceText, relationReasonText } from "../i18n/event-metadata";
import { formatDateTime } from "../shared/date-time";
import { stateTone } from "../shared/state-tone";
import { InvestigationMutationGate, bootstrapEffectiveRole, canPerformInvestigationMutation } from "./access-control";
import { useTimeZone } from "./App";
import { eventEvidenceHref, отказЗапроса } from "./event-presentation";
import { investigationApiParameters, investigationContext, investigationDisplayTimeZone, investigationParameters, investigationQueryKey, investigationRouterSearch, safeInvestigationReturnTo, type InvestigationNavigationContext } from "./investigation-context";
import { statusLabel } from "./status-labels";
import { caseStatusLabel } from "./case-status";

type TimelineItem = InvestigationWorkspaceV1["timeline"][number];
type RelationItem = { relation_type: "explicit_event_link" | "computed_correlation"; relation_origin?: "stored" | "computed"; confidence_kind?: "stored_link_value" | "rule_policy_score"; related_event_db_id: number; confidence: number; reason?: string; reason_code?: string; reason_params?: Record<string, string | number>; explanation?: string; relation_strength?: "strong" | "medium"; relation_rule?: string; time_delta_seconds?: number; evidence_fields?: string[]; entity?: string };

const caseStatusOptions = (): Array<{ value: string; label: string }> => [
  { value: "new", label: t("investigations.caseStatus.new") },
  { value: "active", label: t("investigations.caseStatus.active") },
  { value: "review", label: t("investigations.caseStatus.review") },
  { value: "confirmed", label: t("investigations.caseStatus.confirmed") },
  { value: "false_positive", label: t("investigations.caseStatus.false_positive") },
  { value: "closed", label: t("investigations.caseStatus.closed") },
];

function newestFirst<T>(items: readonly T[], timeOf: (item: T) => string | null | undefined, idOf?: (item: T) => number) {
  return [...items].sort((left, right) => {
    const leftMs = Date.parse(timeOf(left) || "");
    const rightMs = Date.parse(timeOf(right) || "");
    const byTime = (Number.isNaN(rightMs) ? -Infinity : rightMs) - (Number.isNaN(leftMs) ? -Infinity : leftMs);
    if (byTime) return byTime;
    return idOf ? idOf(right) - idOf(left) : 0;
  });
}

function Banner({ title, children }: { title: string; children: string }) {
  return <div className="sli-ds-state sli-ds-state--banner" data-tone="neutral" role="status">
    <div className="sli-ds-state__title">{title}</div>
    <div className="sli-ds-state__text">{children}</div>
  </div>;
}

function RelationEvidence({ relations, loading, failed, confidenceContract }: { relations: RelationItem[]; loading: boolean; failed: boolean; confidenceContract?: Record<string, string> }) {
  const location = useLocation();
  const search = new URL(location.href, "http://localhost").search;
  if (loading) return <StateView state="loading"/>;
  if (failed) return <StateView state="unavailable" compact detail={t("investigations.relations.unavailable")}/>;
  if (!relations.length) return <p className="sli-ds-header__subtitle">{t("investigations.relations.empty")}</p>;
  return <ul aria-label={t("investigations.relations.ariaLabel")}>{relations.map((relation) => {
    const explicit = relation.relation_origin === "stored" || relation.relation_type === "explicit_event_link";
    const confidenceNote = relation.confidence_kind ? relationConfidenceText(relation.confidence_kind, confidenceContract?.[relation.confidence_kind] ?? "") : undefined;
    const href = eventEvidenceHref(relation.related_event_db_id, search);
    return <li key={`${relation.relation_type}-${relation.related_event_db_id}`}>
      <strong>{explicit ? t("investigations.relations.explicitLink") : t("investigations.relations.computedCorr")}</strong>
      <p className="sli-ds-header__subtitle">{relationReasonText(relation, t("investigations.relations.reasonMissing"))}</p>
      {relation.relation_rule ? <p className="sli-ds-header__subtitle">{t("investigations.relations.rule", { rule: relation.relation_rule })}</p> : null}
      {!explicit ? <p className="sli-ds-header__subtitle">{t("investigations.relations.corrNote")}</p> : null}
      {relation.entity ? <p className="sli-ds-header__subtitle">{t("investigations.relations.entity", { entity: relation.entity })}</p> : null}
      {relation.evidence_fields?.length ? <p className="sli-ds-header__subtitle">{t("investigations.relations.fields", { fields: relation.evidence_fields.join(", ") })}</p> : null}
      {relation.time_delta_seconds !== undefined ? <p className="sli-ds-header__subtitle">{t("investigations.relations.timeDelta", { delta: relation.time_delta_seconds })}</p> : null}
      <p className="sli-ds-header__subtitle">{t("investigations.relations.confidence", { kind: explicit ? t("investigations.relations.linkValue") : t("investigations.relations.ruleStrength"), pct: Math.round(relation.confidence * 100) })}</p>
      {confidenceNote ? <p className="sli-ds-header__subtitle">{confidenceNote}</p> : null}
      {href ? <a href={href}>{t("investigations.relations.openEvent", { id: relation.related_event_db_id })}</a> : <span className="sli-ds-header__subtitle">{t("investigations.relations.missingId")}</span>}
    </li>;
  })}</ul>;
}

function InvestigationResult({ workspace, timeZone, role }: { workspace: InvestigationWorkspaceV1; timeZone: string; role?: string }) {
  const queryClient = useQueryClient();
  const location = useLocation();
  const timeline = useMemo(() => newestFirst(workspace.timeline, (item) => item.time_utc, (item) => item.event_db_id), [workspace.timeline]);
  const findings = workspace.findings;
  const [pickedEventDbId, setPickedEventDbId] = useState<number | null>(null);
  const activeCase = findings[0] ?? null;
  const [caseStatus, setCaseStatus] = useState(activeCase?.status ?? "new");
  const [caseOwner, setCaseOwner] = useState(activeCase?.assigned_to ?? "");
  const [caseNote, setCaseNote] = useState("");
  const [caseSaved, setCaseSaved] = useState(false);
  useEffect(() => { setCaseStatus(activeCase?.status ?? "new"); setCaseOwner(activeCase?.assigned_to ?? ""); setCaseNote(""); }, [activeCase?.id, activeCase?.status, activeCase?.assigned_to]);
  useEffect(() => { setPickedEventDbId(null); }, [timeline, workspace.anchor_event_db_id]);
  const canMutate = canPerformInvestigationMutation(role, "update_case_status");
  const updateCase = useMutation({
    mutationFn: () => canMutate ? api.updateFinding(activeCase!.id, { status: caseStatus, assigned_to: caseOwner.trim() || null, note: caseNote.trim() || null }) : Promise.reject(new Error("insufficient_permissions")),
    onMutate: () => setCaseSaved(false),
    onSuccess: async () => { setCaseNote(""); await queryClient.invalidateQueries({ queryKey: ["investigation"] }); setCaseSaved(true); },
  });
  const selected = timeline.find((item) => item.event_db_id === pickedEventDbId)
    ?? timeline.find((item) => item.event_db_id === workspace.anchor_event_db_id)
    ?? timeline[0] ?? null;
  const evidenceSearch = new URL(location.href, "http://localhost").search;
  const selectedEvidenceHref = selected ? eventEvidenceHref(selected.event_db_id, evidenceSearch) : null;
  const relations = useQuery({ queryKey: ["event-relations", selected?.event_db_id], queryFn: () => api.eventRelations(selected!.event_db_id), enabled: Boolean(selected) });
  if (workspace.state === "empty") return <StateView state="empty" detail={t("investigations.result.emptyState")}/>;

  const timelineColumns: TableColumn<TimelineItem>[] = [
    { key: "time", label: t("investigations.result.colTime"), render: (row) => (formatDateTime(row.time_utc, timeZone, { seconds: true })) },
    { key: "event", label: t("investigations.result.colEvent"), render: (row) => <>
      <strong>{eventSemanticText(row.title_code, row.title || `Event ID ${row.event_id}`)}</strong><br/>
      <small>{[row.server, row.actor, row.target].filter(Boolean).join(" · ") || t("investigations.result.contextNotExtracted")}</small><br/>
      <small>{row.catalogued ? t("investigations.result.catalogued") : t("investigations.result.notCatalogued")} · DB {row.event_db_id}</small>
    </> },
    { key: "class", label: t("investigations.result.colClass"), render: (row) => <EventClassificationBadge value={row.severity} origin={row.classification_origin}/> },
  ];
  const findingColumns: TableColumn<(typeof findings)[number]>[] = [
    { key: "severity", label: t("investigations.result.colRisk"), render: (row) => <RiskBadge value={row.severity}/> },
    { key: "title", label: t("investigations.result.colFinding"), render: (row) => <><strong>{row.title || t("investigations.result.findingNoTitle")}</strong><br/><small>{row.recommended_action ?? row.target ?? t("investigations.result.findingNoDesc")}</small></> },
  ];
  const submitCase = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (caseNote.trim()) updateCase.mutate(); };

  return <>
    <MetricStrip label={t("investigations.result.summaryAriaLabel")} items={[
      { key: "events", label: t("investigations.result.metricEvents"), value: workspace.summary.events_returned, caption: workspace.summary.has_more ? t("investigations.result.metricEventsMore") : t("investigations.result.metricEventsLimit") },
      { key: "findings", label: t("investigations.result.metricFindings"), value: findings.length },
      { key: "attention", label: t("investigations.result.metricAttention"), value: workspace.summary.attention_level || t("investigations.result.metricAttentionUnknown"), tone: stateTone(workspace.summary.attention_level) },
    ]}/>

    <section className="sli-ds-report__views" aria-label={t("investigations.result.caseAriaLabel")}>
      {activeCase ? <InvestigationMutationGate role={role} action="update_case_status">
        <form className="sli-ds-filters" aria-label={t("investigations.result.caseFormAriaLabel", { id: activeCase.id })} onSubmit={submitCase}>
          <p className="sli-ds-header__subtitle">{t("investigations.result.caseIdLabel", { id: activeCase.id })}</p>
          <div className="sli-ds-filters__fields">
            <div className="sli-ds-field"><label htmlFor="investigation-case-status">{t("investigations.result.caseStatusLabel")}</label>
              <select id="investigation-case-status" value={caseStatus} onChange={(event) => setCaseStatus(event.target.value)}>
                {caseStatusOptions().map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
              </select></div>
            <div className="sli-ds-field"><label htmlFor="investigation-case-owner">{t("investigations.result.caseOwnerLabel")}</label>
              <input id="investigation-case-owner" value={caseOwner} onChange={(event) => setCaseOwner(event.target.value)} placeholder={t("investigations.result.caseOwnerPlaceholder")}/></div>
            <div className="sli-ds-field"><label htmlFor="investigation-case-note">{t("investigations.result.caseNoteLabel")}</label>
              <input id="investigation-case-note" required maxLength={2000} value={caseNote} onChange={(event) => setCaseNote(event.target.value)} placeholder={t("investigations.result.caseNotePlaceholder")}/></div>
          </div>
          <div className="sli-ds-filters__actions"><button className="sli-ds-button" data-variant="primary" type="submit" disabled={updateCase.isPending || !caseNote.trim()}>{updateCase.isPending ? t("investigations.result.caseSaving") : t("investigations.result.caseSave")}</button></div>
          {updateCase.isError ? <p role="alert" className="sli-ds-field__error">{t("investigations.result.caseUpdateError")}</p> : null}
          {caseSaved ? <p role="status" className="sli-ds-header__subtitle">{t("investigations.result.caseSaved")}</p> : null}
        </form>
      </InvestigationMutationGate>
        : <Banner title={t("investigations.result.noCaseBannerTitle")}>{t("investigations.result.noCaseBannerText")}</Banner>}
    </section>

    <section className="sli-ds-report__views" aria-label={t("investigations.result.contextAriaLabel")}>
      <h2>{t("investigations.result.contextHeading")}</h2>
      <FactList facts={[
        { label: t("investigations.result.factQuery"), value: workspace.query },
        { label: t("investigations.result.factScope"), value: workspace.scope === "all" ? t("investigations.result.factScopeAll") : t("investigations.result.factScopeImportant") },
        { label: t("investigations.result.factEvents"), value: formatNumber(workspace.summary.events_returned) },
        ...(activeCase ? [
          { label: t("investigations.result.factCaseOwner"), value: activeCase.assigned_to || t("investigations.result.factCaseOwnerUnassigned") },
          { label: t("investigations.result.factCaseStatus"), value: statusLabel(activeCase.status) },
        ] : []),
        { label: t("investigations.result.factStory"), value: workspace.summary.story ? eventSemanticText(workspace.summary.story_code, fixedText(workspace.summary.story, "investigations.empty.")) : t("investigations.result.factStoryEmpty") },
        { label: t("investigations.result.factWhyMatters"), value: workspace.summary.why_it_matters ? eventSemanticText(workspace.summary.why_it_matters_code, fixedText(workspace.summary.why_it_matters, "investigations.empty.")) : t("investigations.result.factWhyMattersEmpty") },
      ]}/>
      {activeCase?.status_history?.length ? <>
        <h3>{t("investigations.result.caseHistoryHeading")}</h3>
        <ul>{activeCase.status_history.slice(0, 6).map((entry) => <li key={entry.id}>
          <strong>{statusLabel(entry.new_status)}</strong>{" "}
          <span className="sli-ds-header__subtitle">{entry.changed_by}{entry.changed_at ? ` · ${formatDateTime(entry.changed_at, timeZone)}` : ""}</span>
          {entry.note ? <p>{entry.note}</p> : null}
        </li>)}</ul>
      </> : null}
    </section>

    <section className="sli-ds-report__views" aria-label={t("investigations.result.timelineAriaLabel")}>
      <div><h2>{t("investigations.result.timelineHeading")}</h2><p className="sli-ds-header__subtitle">{t("investigations.result.timelineSubtitle")}</p></div>
      {timeline.length
        ? <DataTable columns={timelineColumns} rows={timeline} rowKey={(row) => String(row.event_db_id)} selectedKey={selected ? String(selected.event_db_id) : null} onRowClick={(row) => setPickedEventDbId(row.event_db_id)} caption={t("investigations.result.timelineCaption")}/>
        : <StateView state="empty" detail={t("investigations.result.timelineEmpty")}/>}
    </section>

    <section className="sli-ds-report__views" aria-label={t("investigations.result.selectedAriaLabel")}>
      <h2>{t("investigations.result.selectedHeading")}</h2>
      {selected ? <>
        <h3>{eventSemanticText(selected.title_code, selected.title || `Event ID ${selected.event_id}`)}</h3>
        <FactList facts={[
          { label: t("investigations.result.factEvidence"), value: `DB ${selected.event_db_id} · Event ID ${selected.event_id}` },
          { label: t("investigations.result.factTime"), value: selected.time_utc ? <DateTime value={selected.time_utc} timeZone={timeZone}/> : t("investigations.result.factTimeUnknown") },
          { label: t("investigations.result.factSource"), value: [selected.server, selected.channel].filter(Boolean).join(" · ") || t("investigations.result.factSourceUnknown") },
          { label: t("investigations.result.factActor"), value: selected.actor || t("investigations.result.factActorUnknown") },
          { label: t("investigations.result.factTarget"), value: selected.target || t("investigations.result.factTargetUnknown") },
          { label: t("investigations.result.factEventClass"), value: <EventClassificationBadge value={selected.severity} origin={selected.classification_origin}/> },
          ...(selected.card_completeness === "complete" || selected.card_completeness === "partial"
            ? [{ label: t("investigations.result.factCardCompleteness"), value: <EventCardCompletenessBadge completeness={selected.card_completeness}/> }] : []),
        ]}/>
        <h3>{t("investigations.result.relationsHeading")}</h3>
        <RelationEvidence relations={relations.data?.items ?? []} loading={relations.isLoading} failed={relations.isError} confidenceContract={relations.data?.confidence_contract}/>
        <h3>{t("investigations.result.checksHeading")}</h3>
        {workspace.next_checks.length ? <ol>{workspace.next_checks.map((check, index) => <li key={check}>{eventSemanticText(workspace.next_check_codes?.[index], check)}</li>)}</ol> : <p className="sli-ds-header__subtitle">{t("investigations.result.checksEmpty")}</p>}
        <div className="sli-ds-filters__actions">
          {selectedEvidenceHref ? <a className="sli-ds-button" data-variant="primary" href={selectedEvidenceHref}>{t("investigations.result.openExactCard")}</a> : <span className="sli-ds-header__subtitle">{t("investigations.result.noExactId")}</span>}
        </div>
      </> : <p className="sli-ds-header__subtitle">{t("investigations.result.selectRow")}</p>}
    </section>

    {findings.length ? <section className="sli-ds-report__views" aria-label={t("investigations.result.findingsAriaLabel")}>
      <h2>{t("investigations.result.findingsHeading")}</h2>
      <DataTable columns={findingColumns} rows={findings} rowKey={(row) => String(row.id)} caption={t("investigations.result.findingsCaption")}/>
    </section> : null}
  </>;
}

function InvestigationOutcome({ workspace, timeZone, role }: { workspace: { status: "pending" | "error" | "success"; error: unknown; data?: InvestigationWorkspaceV1; refetch: () => unknown }; timeZone: string; role?: string }) {
  if (workspace.status === "pending") return <StateView state="loading"/>;
  if (workspace.status === "error") {
    const refusal = отказЗапроса(workspace.error as { status?: number; code?: string } | null, t("investigations.result.entityHistoryRefusal"));
    const status = Number((workspace.error as { status?: number } | null)?.status ?? 0);
    if (workspace.data && status !== 401 && status !== 403) return <>
      <StateView state="stale" compact detail={t("investigations.workspace.refreshFailed")}
        actions={<button type="button" className="sli-ds-button" onClick={() => void workspace.refetch()}>{t("state.retry")}</button>}/>
      <InvestigationResult workspace={workspace.data} timeZone={timeZone} role={role}/>
    </>;
    return <StateView
      state={status === 401 || status === 403 ? "denied" : "unavailable"}
      detail={<><strong>{refusal.title}</strong> {refusal.detail} {t("investigations.result.historyRefusalSuffix")}</>}
      onRetry={refusal.retry ? () => void workspace.refetch() : undefined}/>;
  }
  if (!workspace.data) return <StateView state="unavailable" detail={t("investigations.result.emptyResponse")}/>;
  return <InvestigationResult workspace={workspace.data} timeZone={timeZone} role={role}/>;
}

export function InvestigationWorkspacePage() {
  const queryClient = useQueryClient();
  const { timeZone: globalTimeZone } = useTimeZone();
  const location = useLocation();
  const navigate = useNavigate();
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrap, staleTime: 60_000 });
  const parsedContext = useMemo(() => {
    try {
      const parameters = new URL(location.href, "http://localhost").searchParams;
      const context = investigationContext(parameters);
      const returnValues = parameters.getAll("return_to");
      if (returnValues.length > 1) throw new Error("duplicate_return_to");
      const returnTo = returnValues.length
        ? safeInvestigationReturnTo(returnValues[0], "") || null
        : null;
      if (returnValues.length && !returnTo) throw new Error("invalid_return_to");
      return { context, returnTo, error: investigationDisplayTimeZone(context, globalTimeZone).available ? null : "invalid_timezone" as string | null };
    }
    catch (error) { return { context: null, returnTo: null, error: error instanceof Error ? error.message : "invalid_context" }; }
  }, [location.href, globalTimeZone]);
  const context = parsedContext.context;
  const timeZone = investigationDisplayTimeZone(context, globalTimeZone).timeZone;
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState<"important" | "all">("important");
  const [timeFrom, setTimeFrom] = useState("");
  const [timeTo, setTimeTo] = useState("");
  const [timezone, setTimezone] = useState(globalTimeZone);
  const [formError, setFormError] = useState<string | null>(null);
  useEffect(() => {
    if (!context) return;
    setQuery(context.q ?? ""); setScope(context.scope ?? "important");
    setTimeFrom(context.time_from ?? ""); setTimeTo(context.time_to ?? ""); setTimezone(context.timezone ?? globalTimeZone);
    setFormError(null);
  }, [context, globalTimeZone]);
  const active = Boolean(!parsedContext.error && context && (context.q || context.event_db_id || context.entity_id));
  const historyKey = [...(context ? investigationQueryKey(context) : ["investigation", "invalid-context"]), "pages"];
  const history = useInfiniteQuery({
    queryKey: historyKey,
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) => {
      const params = investigationApiParameters(context!);
      if (pageParam) params.set("cursor", pageParam);
      try { return await api.investigationWorkspace(params); }
      catch (error) {
        if (error instanceof ApiResponseError && (error.status === 401 || error.status === 403)) {
          // Erase revoked data from this exact cache entry, including on continuation.
          // A later transient failure must not resurrect it; only a new success can.
          queryClient.getQueryCache().find({ queryKey: historyKey, exact: true })?.setState({ data: undefined });
        }
        throw error;
      }
    },
    getNextPageParam: (lastPage) => lastPage.next_cursor ?? undefined,
    enabled: active,
    retry: false,
  });
  const workspaceData = useMemo(() => {
    if (!history.data) return undefined;
    const pages = history.data.pages;
    const timeline = [...new Map(pages.flatMap((page) => page.timeline).map((item) => [item.event_db_id, item])).values()];
    const last = pages[pages.length - 1];
    return { ...pages[0], timeline, next_cursor: last.next_cursor,
      state: timeline.length ? "ok" as const : pages[0].state,
      summary: { ...pages[0].summary, events_returned: timeline.length, has_more: last.summary.has_more } };
  }, [history.data]);
  const historyDenied = history.isError && [401, 403].includes(Number((history.error as { status?: number } | null)?.status));
  const workspace = { status: workspaceData && history.isFetchNextPageError && !historyDenied ? "success" as const : history.status, data: workspaceData, error: history.error, refetch: history.refetch };
  const cases = useQuery({ queryKey: ["investigation-cases"], queryFn: api.investigationCases, staleTime: 30_000, enabled: !parsedContext.error });
  const anchorEventDbId = context?.event_db_id ?? "";
  const selectedEntityId = context?.entity_id ?? "";
  const presentationSearch = (next: InvestigationNavigationContext): Record<string, string | number> => ({
    ...investigationRouterSearch(next),
    ...(parsedContext.returnTo ? { return_to: parsedContext.returnTo } : {}),
  });
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const next = investigationContext(investigationParameters({ event_db_id: anchorEventDbId || undefined, entity_id: selectedEntityId || undefined, q: query.trim() || undefined, scope, time_from: timeFrom || undefined, time_to: timeTo || undefined, timezone: timezone.trim() || undefined }));
      setFormError(null);
      void navigate({ to: "/investigations", search: presentationSearch(next) });
    } catch (error) { setFormError(error instanceof Error ? error.message : "invalid_context"); }
  };
  const caseColumns: TableColumn<CaseSummary>[] = [
    { key: "id", label: t("investigations.workspace.caseColId"), render: (row) => <Link to="/investigations/$investigationId" params={{ investigationId: String(row.id) }} search={context ? presentationSearch(context) : {}}>{caseNumber(row)}</Link> },
    { key: "title", label: t("investigations.workspace.caseColTitle") },
    { key: "owner", label: t("investigations.workspace.caseColOwner"), render: (row) => row.owner || t("investigations.workspace.caseOwnerUnassigned") },
    { key: "status", label: t("investigations.workspace.caseColStatus"), render: (row) => caseStatusLabel(row.status, row.status_message) },
    { key: "updated_at", label: t("investigations.workspace.caseColUpdated"), render: (row) => <DateTime value={row.updated_at} timeZone={timeZone}/> },
  ];

  return <section className="sli-ds-report">
    <PageHeader
      title={t("investigations.workspace.pageTitle")}
      subtitle={t("investigations.workspace.pageSubtitle")}
      meta={parsedContext.returnTo ? <a className="sli-ds-button" href={parsedContext.returnTo}>{t("investigations.workspace.backToReport")}</a> : null}/>
    {parsedContext.error ? <div className="sli-ds-state" data-tone="danger" role="alert">
      <div className="sli-ds-state__title">{t("investigations.workspace.contextRejectedTitle")}</div>
      <div className="sli-ds-state__text">{t("investigations.workspace.contextRejectedText", { error: parsedContext.error })}</div>
    </div> : null}
    {anchorEventDbId ? <Banner title={t("investigations.workspace.anchorBannerTitle", { id: anchorEventDbId })}>{t("investigations.workspace.anchorBannerText")}</Banner> : null}
    {selectedEntityId && !anchorEventDbId ? <Banner title={t("investigations.workspace.entityBannerTitle", { id: selectedEntityId })}>{t("investigations.workspace.entityBannerText")}</Banner> : null}
    <form className="sli-ds-filters" aria-label={t("investigations.workspace.formAriaLabel")} onSubmit={submit}>
      <div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor="investigation-query">{t("investigations.workspace.queryLabel")}</label>
          <input id="investigation-query" value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("investigations.workspace.queryPlaceholder")}/></div>
        <div className="sli-ds-field"><label htmlFor="investigation-scope">{t("investigations.workspace.scopeLabel")}</label>
          <select id="investigation-scope" value={scope} onChange={(event) => setScope(event.target.value as "important" | "all")}>
            <option value="important">{t("investigations.workspace.scopeImportant")}</option><option value="all">{t("investigations.workspace.scopeAll")}</option>
          </select></div>
        <div className="sli-ds-field"><label htmlFor="investigation-time-from">{t("investigations.workspace.timeFromLabel")}</label>
          <input id="investigation-time-from" type="text" placeholder={t("investigations.workspace.timePlaceholder")} value={timeFrom} onChange={(event) => setTimeFrom(event.target.value)}/></div>
        <div className="sli-ds-field"><label htmlFor="investigation-time-to">{t("investigations.workspace.timeToLabel")}</label>
          <input id="investigation-time-to" type="text" placeholder={t("investigations.workspace.timePlaceholder")} value={timeTo} onChange={(event) => setTimeTo(event.target.value)}/></div>
        <div className="sli-ds-field"><label htmlFor="investigation-timezone">{t("investigations.workspace.timezoneLabel")}</label>
          <input id="investigation-timezone" value={timezone} onChange={(event) => setTimezone(event.target.value)} aria-describedby="investigation-timezone-note"/></div>
      </div>
      <p id="investigation-timezone-note" className="sli-ds-header__subtitle">{t("investigations.workspace.timezoneNote")}</p>
      <div className="sli-ds-filters__actions"><button className="sli-ds-button" data-variant="primary" type="submit" disabled={!query.trim() && !anchorEventDbId && !selectedEntityId}>{t("investigations.workspace.submitButton")}</button></div>
    </form>
    {formError ? <p className="sli-ds-field__error" role="alert">{t("investigations.workspace.formErrorText", { error: formError })}</p> : null}

    {cases.data?.items.length && !(cases.isError && [401, 403].includes(Number((cases.error as { status?: number } | null)?.status))) ? <section className="sli-ds-report__views" aria-label={t("investigations.workspace.casesAriaLabel")}>
      <div><h2>{t("investigations.workspace.casesHeading")}</h2><p className="sli-ds-header__subtitle">{t("investigations.workspace.casesSubtitle")}</p></div>
      <DataTable columns={caseColumns} rows={cases.data.items} rowKey={(row) => String(row.id)} caption={t("investigations.workspace.casesCaption")}/>
    </section> : null}
    {cases.isError ? <StateView state="unavailable" compact detail={t("investigations.workspace.casesUnavailable")}/> : null}

    {!active && !parsedContext.error ? <StateView state="empty" detail={t("investigations.workspace.emptyHint")}/> : null}
    {active ? <InvestigationOutcome workspace={workspace} timeZone={timeZone} role={bootstrapEffectiveRole(bootstrap.data)}/> : null}
    {active && !historyDenied && history.isFetchNextPageError ? <p role="alert">{t("investigations.workspace.continuationError")}</p> : null}
    {active && !historyDenied && history.hasNextPage ? <button type="button" className="sli-ds-button" disabled={history.isFetching} onClick={() => void history.fetchNextPage()}>
      {history.isFetchingNextPage ? t("investigations.workspace.loadingMore") : t("investigations.workspace.showMore")}
    </button> : null}
  </section>;
}
