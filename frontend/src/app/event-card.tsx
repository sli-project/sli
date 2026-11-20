import { EMPTY_VALUE } from "../shared/format";
import { caseNumber } from "./case-number";
import { useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useLocation, useParams } from "@tanstack/react-router";
import { ApiResponseError, api, type EventDetail, type EventEntities, type EventItem, type EventRelations, type SemanticAction } from "../api/client";
import { DataTable, FactList, PageHeader, StateView, type TableColumn } from "../design-system";
import { EventCardCompletenessBadge, EventClassificationBadge, WindowsLevelBadge, eventClassificationLabel } from "../components/badges/Badges";
import { DateTime } from "../components/date-time/DateTime";
import { formatDateTime } from "../shared/date-time";
import { useTimeZone } from "./App";
import { InvestigationMutationGate, bootstrapEffectiveRole, canPerformInvestigationMutation } from "./access-control";
import { auxiliaryCountText, entityEvidenceHref, eventEvidenceHref, eventMachineRisk, eventParticipantFacts, отказЗапроса } from "./event-presentation";
import { investigationContext, investigationDisplayTimeZoneFromSearch, investigationRouterSearch, investigationSearch, navigationHrefWithReturnTo, RELATIVE_NAVIGATION_ORIGIN, safeInvestigationReturnTo, type InvestigationNavigationContext } from "./investigation-context";
import { statusLabel } from "./status-labels";
import { t } from "../i18n";
import { eventFacts, eventSemanticText, relationConfidenceText, relationReasonText } from "../i18n/event-metadata";

type Row = Record<string, unknown>;
type CardView = "overview" | "raw";
type RelationItem = EventRelations["items"][number];
type EntityItem = EventEntities["items"][number];

export function exactEventInvestigationSearch(item: Pick<EventItem, "event_db_id" | "time_created_utc">, query: string, timeZone: string, search = window.location.search): Record<string, string | number> {
  const sourceParameters = new URLSearchParams(search);
  let inherited: InvestigationNavigationContext = {};
  try { inherited = investigationContext(sourceParameters); } catch { /* the destination validates independently */ }
  const context = investigationSearch("", {
    ...inherited,
    q: query || undefined,
    scope: inherited.scope ?? "important",
    event_db_id: String(item.event_db_id),
    time_from: inherited.time_from,
    time_to: inherited.time_to,
    timezone: inherited.timezone ?? timeZone,
  });
  const routed = investigationRouterSearch(investigationContext(new URLSearchParams(context)));
  const returnValues = sourceParameters.getAll("return_to");
  const returnTo = returnValues.length === 1
    ? safeInvestigationReturnTo(returnValues[0], "")
    : "";
  if (returnTo) routed.return_to = returnTo;
  return routed;
}

/** Keep a case connected to a validated report context; never manufacture a broad fallback. */
export function eventCaseNavigationHref(caseId: number, eventDbId: number, returnTo: string | null | undefined): string | null {
  if (!Number.isSafeInteger(caseId) || caseId <= 0 || !Number.isSafeInteger(eventDbId) || eventDbId <= 0) return null;
  const validatedReturnTo = safeInvestigationReturnTo(returnTo, "");
  if (!validatedReturnTo) return null;
  try {
    const original = new URL(validatedReturnTo, RELATIVE_NAVIGATION_ORIGIN);
    const context = investigationContext(original.searchParams);
    const parameters = new URLSearchParams(investigationSearch(original.search, {
      ...context,
      event_db_id: String(eventDbId),
      scope: context.scope ?? "all",
    }));
    parameters.set("return_to", validatedReturnTo);
    return `/app/investigations/${caseId}?${parameters.toString()}`;
  } catch {
    return null;
  }
}

/** Successful case mutations share the same evidence-bound return path in the event UI. */
export function EventCaseMutationOutcome({
  caseId, eventDbId, returnTo, action,
}: {
  caseId: number | null;
  eventDbId: number;
  returnTo: string | null | undefined;
  action: "create" | "add_evidence";
}) {
  if (!caseId || !Number.isSafeInteger(caseId) || caseId <= 0 || !Number.isSafeInteger(eventDbId) || eventDbId <= 0) return null;
  const href = eventCaseNavigationHref(caseId, eventDbId, returnTo) ?? `/app/investigations/${caseId}?event_db_id=${eventDbId}`;
  return <span role="status">
    {action === "create" ? <>{t("events.card.mutationOutcomeCreated", { caseId: caseNumber({ id: caseId }) })}{" "}</> : null}
    <a href={href} data-case-mutation={action}>{t("events.card.mutationOutcomeOpen", { caseId: caseNumber({ id: caseId }) })}</a>
  </span>;
}

/** Evidence membership alone does not establish a directed causal relation. */
type EventSemanticLookupState = "available" | "empty" | "schema_unavailable" | "unavailable" | "error";

export function eventSemanticLookupRequest(eventDbId: number, href: string): { error: string | null; queryKey: string; parameters: string | null } {
  try {
    const context = investigationContext(new URLSearchParams(new URL(href, "http://localhost").search));
    const parameters = new URLSearchParams({ event_db_id: String(eventDbId) });
    for (const key of ["time_from", "time_to", "timezone"] as const) {
      const value = context[key];
      if (value) parameters.set(key, value);
    }
    const serialized = parameters.toString();
    return { error: null, queryKey: serialized, parameters: serialized };
  } catch (error) {
    return {
      error: error instanceof Error ? error.message : "invalid_context",
      queryKey: "invalid-context",
      parameters: null,
    };
  }
}

export function eventSemanticLookupPresentation(states: { actions: EventSemanticLookupState; scenarios: EventSemanticLookupState }): "schema_unavailable" | "unavailable" | "error" | "no_results" | "available" {
  if (states.actions === "schema_unavailable" || states.scenarios === "schema_unavailable") return "schema_unavailable";
  if (states.actions === "unavailable" || states.scenarios === "unavailable") return "unavailable";
  if (states.actions === "error" || states.scenarios === "error") return "error";
  if (states.actions === "empty" && states.scenarios === "empty") return "no_results";
  return "available";
}

function actionStatusLabel(value: SemanticAction["status"]) {
  const labels: Record<SemanticAction["status"], string> = {
    observed: t("events.card.statusObserved"), partially_confirmed: t("events.card.statusPartiallyConfirmed"),
    state_confirmed: t("events.card.statusStateConfirmed"), multi_source_confirmed: t("events.card.statusMultiSourceConfirmed"),
    contradicted: t("events.card.statusContradicted"), superseded: t("events.card.statusSuperseded"), quarantined: t("events.card.statusQuarantined"),
  };
  return labels[value];
}

function investigationCreateError(error: unknown) {
  if (!(error instanceof ApiResponseError)) return t("events.card.errorCreateFailed");
  if (error.status === 401) return t("events.card.errorSessionExpired");
  if (error.status === 403) return t("events.card.errorPermissionDenied");
  if (error.code === "event_not_found") return t("events.card.errorEventDeleted");
  if (error.code === "invalid_title") return t("events.card.errorMissingTitle");
  return t("events.card.errorHttp", { status: String(error.status), code: error.code ? ` (${error.code})` : "" });
}

function Section({ id, title, note, badge, children }: { id?: string; title: string; note?: ReactNode; badge?: ReactNode; children: ReactNode }) {
  return <section id={id} className="sli-ds-report__views" aria-label={title}>
    <div className="sli-ds-header__row"><div><h2>{title}</h2>{note ? <p className="sli-ds-header__subtitle">{note}</p> : null}</div>{badge ? <span className="sli-ds-chip">{badge}</span> : null}</div>
    {children}
  </section>;
}

const getCardViews = (): Array<{ id: CardView; label: string }> => [{ id: "overview", label: t("events.card.tabOverview") }, { id: "raw", label: t("events.card.tabRaw") }];

function CardTabs({ active, onChange }: { active: CardView; onChange: (view: CardView) => void }) {
  const views = getCardViews();
  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let next: number | null = null;
    if (event.key === "ArrowRight") next = (index + 1) % views.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + views.length) % views.length;
    if (next === null) return;
    event.preventDefault();
    const list = event.currentTarget.parentElement;
    onChange(views[next].id);
    requestAnimationFrame(() => list?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next!]?.focus());
  };
  return <div className="sli-ds-header__meta" role="tablist" aria-label={t("events.card.tabsAria")}>
    {views.map((view, index) => <button key={view.id} type="button" role="tab" id={`event-tab-${view.id}`} aria-controls="event-tabpanel" className="sli-ds-chip"
      aria-selected={view.id === active} aria-pressed={view.id === active} tabIndex={view.id === active ? 0 : -1} onClick={() => onChange(view.id)} onKeyDown={(event) => onKeyDown(event, index)}>{view.label}</button>)}
  </div>;
}

function EventSemanticLookup({ eventDbId }: { eventDbId: number }) {
  const location = useLocation();
  const request = useMemo(() => eventSemanticLookupRequest(eventDbId, location.href), [eventDbId, location.href]);
  const parameters = useMemo(() => new URLSearchParams(request.parameters ?? ""), [request.parameters]);
  const actions = useQuery({ queryKey: ["semantic-event-actions", request.queryKey], queryFn: () => api.semanticActions(parameters), enabled: !request.error });
  const scenarios = useQuery({ queryKey: ["semantic-event-scenarios", request.queryKey], queryFn: () => api.semanticScenarios(parameters), enabled: !request.error });
  const title = t("events.card.semanticTitle");
  if (request.error) return <Section title={title}><StateView state="unavailable" detail={t("events.card.semanticContextError", { error: request.error })}/></Section>;
  if (actions.isLoading || scenarios.isLoading) return <Section title={title}><StateView state="loading"/></Section>;
  const presentation = eventSemanticLookupPresentation({
    actions: actions.isError ? "error" : actions.data?.state ?? "error",
    scenarios: scenarios.isError ? "error" : scenarios.data?.state ?? "error",
  });
  if (presentation === "schema_unavailable") return <Section title={title}><StateView state="unavailable" detail={t("events.card.semanticSchemaUnavailable")}/></Section>;
  if (presentation === "unavailable") return <Section title={title}><StateView state="denied" detail={t("events.card.semanticDenied")}/></Section>;
  if (presentation === "error") return <Section title={title}><StateView state="unavailable" detail={t("events.card.semanticError")}/></Section>;
  if (presentation === "no_results") return <Section title={title}><StateView state="empty" detail={t("events.card.semanticEmpty")}/></Section>;
  const rows: Row[] = [
    ...(actions.data?.items ?? []).map((action) => ({ key: `action:${action.canonical_action_id}`, kind: t("events.card.semanticActionKind"), status: actionStatusLabel(action.status), details: JSON.stringify({ canonical_action_id: action.canonical_action_id, action_kind: action.action_kind, semantic_contract_version: action.semantic_contract_version, assembler: `${action.assembler_id}@${action.assembler_version}`, payload_state: action.payload_state }) })),
    ...(scenarios.data?.items ?? []).map((scenario) => ({ key: `scenario:${scenario.scenario_id}`, kind: t("events.card.semanticScenarioKind"), status: statusLabel(scenario.status), details: JSON.stringify({ scenario_id: scenario.scenario_id, scenario_kind: scenario.scenario_kind, result_class: scenario.result_class, payload_state: scenario.payload_state }) })),
  ];
  return <Section title={title} note={t("events.card.semanticNote")} badge={rows.length}>
    <DataTable<Row> caption={title} rows={rows} rowKey={(row) => String(row.key)}
      columns={[{ key: "kind", label: t("events.card.semanticColKind") }, { key: "status", label: t("events.card.semanticColStatus") }, { key: "details", label: t("events.card.semanticColDetails"), render: (row) => <code>{String(row.details)}</code> }]}/>
    <details><summary>{t("events.card.semanticLimits")}</summary><pre className="sli-ds-pre">{JSON.stringify({ actions: actions.data?.limits, scenarios: scenarios.data?.limits })}</pre></details>
  </Section>;
}

function RelationsSection({ eventDbId, query, search, format, refinementSearch }: {
  eventDbId: number; query: { isLoading: boolean; isError: boolean; data?: EventRelations }; search: string; format: (value: string | null | undefined) => string; refinementSearch: Record<string, string | number>;
}) {
  const relations = query.data?.items ?? [];
  const contract = query.data?.confidence_contract;
  const columns: TableColumn<RelationItem>[] = [
    { key: "relation_type", label: t("events.card.relationsColType"), render: (row) => (row.relation_origin === "stored" || row.relation_type === "explicit_event_link" ? t("events.card.relationsExplicitLink") : t("events.card.relationsComputedCorr")) },
    { key: "related_event_db_id", label: t("events.card.relationsColEvent"), render: (row) => { const href = eventEvidenceHref(row.related_event_db_id, search); return href ? <a href={href}>Event {row.related_event_id || EMPTY_VALUE} · DB {row.related_event_db_id}</a> : <span>{t("events.card.relationsMissingId")}</span>; } },
    { key: "related_time_utc", label: t("events.card.relationsColTime"), render: (row) => (format(row.related_time_utc)) },
    { key: "reason", label: t("events.card.relationsColReason"), render: (row) => {
      const explicit = row.relation_origin === "stored" || row.relation_type === "explicit_event_link";
      return <div>
        <div>{relationReasonText(row, t("events.card.relationsMissingReason"))}</div>
        {row.relation_rule ? <div>{t("events.card.relationsRule", { rule: row.relation_rule })}</div> : null}
        {!explicit ? <div>{t("events.card.relationsCorrNote")}</div> : null}
        {row.entity ? <div>{t("events.card.relationsEntity", { entity: row.entity })}</div> : null}
        {row.evidence_fields?.length ? <div>{t("events.card.relationsFields", { fields: row.evidence_fields.join(", ") })}</div> : null}
        {row.time_delta_seconds !== undefined ? <div>{t("events.card.relationsDelta", { delta: String(row.time_delta_seconds) })}</div> : null}
      </div>;
    } },
    { key: "confidence", label: t("events.card.relationsColConfidence"), render: (row) => {
      const explicit = row.relation_origin === "stored" || row.relation_type === "explicit_event_link";
      const note = row.confidence_kind ? relationConfidenceText(row.confidence_kind, contract?.[row.confidence_kind] ?? "") : undefined;
      return <div><div>{explicit ? t("events.card.relationsLinkValue") : t("events.card.relationsRuleStrength")}: {Math.round(row.confidence * 100)}%</div>{note ? <div>{note}</div> : null}</div>;
    } },
  ];
  let body: ReactNode;
  if (query.isLoading) body = <StateView state="loading"/>;
  else if (query.isError) body = <StateView state="unavailable" detail={t("events.card.relationsUnavailable")}/>;
  else if (!relations.length) body = <StateView state="empty" detail={t("events.card.relationsEmpty")}/>;
  else body = <DataTable<RelationItem> caption={t("events.card.relationsCaption")} columns={columns} rows={relations} rowKey={(row) => `${row.relation_type}-${row.related_event_db_id}`}/>;
  return <Section title={t("events.card.relationsTitle")} note={t("events.card.relationsNote", { id: String(eventDbId) })} badge={t("events.card.relationsCount", { count: auxiliaryCountText(query.data?.items, query.isLoading || query.isError) })}>
    {!query.isLoading && !query.isError && query.data?.truncated ? <p role="status" className="sli-ds-header__subtitle">
      {t("events.card.relationsTruncated")} {" "}<Link to="/investigations" search={refinementSearch}>{t("events.card.relationsRefine")}</Link>
    </p> : null}
    {body}
  </Section>;
}

function EntitiesSection({ eventDbId, query }: { eventDbId: number; query: { isLoading: boolean; isError: boolean; data?: EventEntities } }) {
  const entities = query.data?.items ?? [];
  const timedOut = query.data?.evidence_status === "timeout";
  const columns: TableColumn<EntityItem>[] = [
    { key: "display_name", label: t("events.card.entitiesColEntity"), render: (entity) => {
      const baseHref = entityEvidenceHref(entity.id, window.location.search, eventDbId);
      const href = baseHref ? navigationHrefWithReturnTo(baseHref, `${window.location.pathname}${window.location.search}`) : null;
      const name = entity.display_name || entity.natural_key;
      return href ? <a href={href}>{name}</a> : <span>{name}</span>;
    } },
    { key: "type", label: t("events.card.entitiesColType") },
    { key: "link_role", label: t("events.card.entitiesColRole") },
    { key: "confidence", label: t("events.card.entitiesColExtraction"), render: (entity) => (entity.confidence < 1 ? t("events.card.entitiesConfidence", { confidence: String(Math.round(entity.confidence * 100)) }) : t("events.card.entitiesDirectLink")) },
  ];
  let body: ReactNode;
  if (query.isLoading) body = <StateView state="loading"/>;
  else if (query.isError) body = <StateView state="unavailable" detail={t("events.card.entitiesUnavailable")}/>;
  else if (timedOut) body = <StateView state="unavailable" detail={t("events.card.entitiesTimeout")}/>;
  else if (!entities.length) body = <StateView state="empty" detail={t("events.card.entitiesEmpty")}/>;
  else body = <DataTable<EntityItem> caption={t("events.card.entitiesCaption")} columns={columns} rows={entities} rowKey={(entity) => String(entity.id)}/>;
  return <Section id="evidence" title={t("events.card.entitiesTitle")} note={t("events.card.entitiesNote")} badge={auxiliaryCountText(query.data?.items, query.isLoading || query.isError || timedOut)}>{body}</Section>;
}

export function RawSections({ item, timeZone }: { item: EventDetail; timeZone: string }) {
  const semantic = item.semantics;
  const normalized = [
    { label: t("events.card.rawSubject"), value: item.subject ?? t("events.card.notDetermined") },
    { label: t("events.card.rawTarget"), value: item.target ?? t("events.card.notDetermined") },
    { label: t("events.card.rawSource"), value: item.source ?? item.server ?? t("events.card.notDetermined") },
    ...(semantic ? eventFacts(semantic) : []).map(([label, value]) => ({ label, value })),
  ];
  // Archive block absent: the core facts are verified, the source record is not available.
  const archiveUnavailable = item.source_payload_state === "archive_unavailable";
  const expired = item.source_payload_state === "expired";
  const fieldsTitle = expired ? t("events.card.retainedFactsTitle") : "EventData";
  const eventData = Object.entries((expired ? item.retained_facts : item.event_data) ?? {}).map(([key, value]) => ({ key, value: typeof value === "string" ? value : String(value ?? "") }));
  const sourceMissing = t(item.read_representation === "authentication_session" ? "events.card.sessionRepresentation" : expired ? "events.card.sourceExpired" : "events.card.rawSourceMissing");
  return <>
    <Section title={t("events.card.rawNormalizedTitle")}><FactList facts={normalized}/></Section>
    <Section title={t("events.card.rawMessageTitle")}>
      {expired ? <StateView state="partial" detail={sourceMissing}/>
        : item.message_text ? <pre className="sli-ds-pre">{item.message_text}</pre>
        : archiveUnavailable ? <StateView state="unavailable" detail={sourceMissing}/>
        : <StateView state="empty" detail={t("events.card.rawMessageEmpty")}/>}
    </Section>
    <Section title={fieldsTitle} badge={eventData.length}>
      {eventData.length
        ? <DataTable<{ key: string; value: string }> caption={fieldsTitle} rows={eventData} rowKey={(row) => row.key} columns={[{ key: "key", label: t("events.card.rawColField") }, { key: "value", label: t("events.card.rawColValue") }]}/>
        : expired || archiveUnavailable ? <StateView state={expired ? "partial" : "unavailable"} detail={sourceMissing}/>
        : <StateView state="empty" detail={t("events.card.rawEventDataEmpty")}/>}
    </Section>
    <Section title={t("events.card.rawXmlTitle")}>
      <StateView state={expired ? "partial" : "unavailable"} detail={expired ? sourceMissing : t("events.card.rawXmlUnavailable")}/>
    </Section>
    <Section title={t("events.card.rawTechTitle")}>
      <FactList facts={[
        { label: "Provider", value: item.provider_name ?? t("events.card.notDeterminedMasc") },
        { label: "Channel", value: item.channel ?? t("events.card.notDeterminedMasc") },
        { label: "Event Record ID", value: item.event_record_id ?? t("events.card.notDeterminedMasc") },
        { label: t("events.card.rawExactId"), value: item.event_db_id },
        { label: t("events.card.rawTimeUtc"), value: item.time_created_utc ?? t("events.card.unknown") },
        { label: t("events.card.rawTimeLocal"), value: <DateTime value={item.time_created_utc} timeZone={timeZone} showZone/> },
      ]}/>
    </Section>
  </>;
}

export function EventCardPage() {
  const queryClient = useQueryClient();
  const { timeZone: globalTimeZone } = useTimeZone();
  const timeZone = investigationDisplayTimeZoneFromSearch(window.location.search, globalTimeZone).timeZone;
  const { eventId } = useParams({ from: "/events/$eventId" });
  const location = useLocation();
  const routeSearch = new URL(location.href, "http://localhost").search;
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrap, staleTime: 60_000 });
  const role = bootstrapEffectiveRole(bootstrap.data);
  const canCreateCase = canPerformInvestigationMutation(role, "create_case");
  const canAddEvidence = canPerformInvestigationMutation(role, "add_evidence");
  const returnValues = new URLSearchParams(routeSearch).getAll("return_to");
  const rawReturnTo = returnValues.length === 1 ? returnValues[0] : "";
  const returnTo = safeInvestigationReturnTo(rawReturnTo, "/app/events");
  const event = useQuery({ queryKey: ["event", eventId], queryFn: () => api.event(eventId) });
  const relations = useQuery({ queryKey: ["event-relations", eventId], queryFn: () => api.eventRelations(Number(eventId)), enabled: Boolean(event.data?.item?.event_db_id) });
  const entities = useQuery({ queryKey: ["event-entities", eventId], queryFn: () => api.eventEntities(Number(eventId)), enabled: Boolean(event.data?.item?.event_db_id) });
  const [view, setView] = useState<CardView>("overview");
  const [caseTitle, setCaseTitle] = useState("");
  const [caseOwner, setCaseOwner] = useState("");
  const [createdCases, setCreatedCases] = useState<Record<number, number>>({});
  const submittedEvents = useRef(new Set<number>());
  const [existingCaseId, setExistingCaseId] = useState("");
  const createCase = useMutation({
    mutationFn: ({ title, owner, eventDbId }: { title: string; owner: string; eventDbId: number }) => canCreateCase ? api.createInvestigation({ title, owner: owner.trim() || null, event_db_id: eventDbId }) : Promise.reject(new Error("insufficient_permissions")),
    onSuccess: (created, variables) => {
      setCreatedCases((prior) => ({ ...prior, [variables.eventDbId]: created.id }));
      setCaseTitle(""); setCaseOwner("");
      void queryClient.invalidateQueries({ queryKey: ["investigation-cases"] });
    },
    onError: (_error, variables) => { submittedEvents.current.delete(variables.eventDbId); },
  });
  const caseList = useQuery({ queryKey: ["investigation-cases"], queryFn: api.investigationCases, staleTime: 30_000, enabled: canAddEvidence });
  const addToExistingCase = useMutation({ mutationFn: ({ caseId, eventDbId }: { caseId: number; eventDbId: number }) => canAddEvidence ? api.addInvestigationEvent(caseId, { event_db_id: eventDbId }) : Promise.reject(new Error("insufficient_permissions")), onSuccess: () => { setExistingCaseId(""); } });
  const createdCaseId = createdCases[Number(eventId)] ?? (createCase.isSuccess && createCase.variables?.eventDbId === Number(eventId) ? createCase.data?.id ?? null : null);
  const evidenceAddedCaseId = addToExistingCase.isSuccess && addToExistingCase.variables?.eventDbId === Number(eventId) ? addToExistingCase.variables.caseId : null;
  const format = (value: string | null | undefined) => formatDateTime(value, timeZone, { seconds: true });
  const crumbs = (label: string) => [{ label: t("events.card.crumbsEvents"), href: returnTo }, { label }];

  if (event.isLoading) {
    return <section className="sli-ds-report"><PageHeader title={t("events.card.pageTitle")} crumbs={crumbs(`Event ${eventId}`)}/><StateView state="loading"/></section>;
  }
  if (event.isError || !event.data) {
    const failure = отказЗапроса(event.error as { status?: number; code?: string } | null, t("events.presentation.entityRecord"));
    const denied = (event.error as { status?: number } | null)?.status === 403;
    return <section className="sli-ds-report"><PageHeader title={failure.title} crumbs={crumbs(`Event ${eventId}`)}/>
      <StateView state={denied ? "denied" : "unavailable"} detail={failure.detail} onRetry={failure.retry ? () => void event.refetch() : undefined}/>
      <p><a href={returnTo}>{t("events.card.backToEvents")}</a></p></section>;
  }

  const item = event.data.item;
  const semantic = item.semantics;
  const investigationQuery = item.subject || item.target || item.server || String(item.event_id);
  const investigationSearchParams = exactEventInvestigationSearch(item, investigationQuery, timeZone);
  const facts = [...(semantic ? eventFacts(semantic) : [[t("events.presentation.factServer"), item.server ?? t("events.card.notDetermined")]] as Array<[string, string]>), ...eventParticipantFacts(item, semantic?.facts ?? [])]
    .map(([label, value]) => ({ label, value }));
  const checks = semantic?.checks ?? [t("events.card.checksDefault")];

  return <section className="sli-ds-report">
    <PageHeader
      title={eventSemanticText(semantic?.title_code, semantic?.title ?? t("events.card.headerFallback"))}
      crumbs={crumbs(`Event ${item.event_db_id}`)}
      subtitle={`Event ID ${item.event_id} · DB ${item.event_db_id} · ${format(item.time_created_utc)}`}
      meta={<>
        <EventClassificationBadge value={eventMachineRisk(item)} origin={semantic?.classification_origin}/>
        <EventCardCompletenessBadge completeness={semantic?.card_completeness}/>
        <WindowsLevelBadge value={item.level}/>
        <span className="sli-ds-chip" title={`${item.server || t("events.card.sourceNotDetermined")} · Record ${item.event_record_id ?? EMPTY_VALUE}`}>DB {item.event_db_id}</span>
      </>}
      actions={<Link className="sli-ds-button" data-variant="primary" to="/investigations" search={investigationSearchParams}>{t("events.card.actionOpenContext")}</Link>}
    />
    {item.source_payload_state === "archive_unavailable"
      ? <StateView state="partial" compact detail={t("events.card.partialDetail")}/>
      : item.source_payload_state === "expired"
      ? <StateView state="partial" compact detail={t(item.read_representation === "authentication_session" ? "events.card.sessionRepresentation" : "events.card.sourceExpired")}/>
      : null}
    <CardTabs active={view} onChange={setView}/>
    <div id="event-tabpanel" role="tabpanel" aria-labelledby={`event-tab-${view}`} className="sli-ds-report__views">
      {view === "overview" ? <>
        {semantic?.watch_priority?.reason === "watch" && <p>{t("events.card.watchPriority", {
          base: eventClassificationLabel(semantic.watch_priority.base_severity),
          effective: eventClassificationLabel(semantic.watch_priority.effective_severity),
        })}</p>}
        <Section title={t("events.card.overviewTitle")} note={eventSemanticText(semantic?.summary_code, semantic?.summary ?? t("events.card.overviewNote"))}><FactList facts={facts}/></Section>
        <Section title={t("events.card.checksTitle")}>
          <ol>{checks.map((check, index) => <li key={check}><span>{eventSemanticText(semantic?.check_codes?.[index], check)}</span>{" "}{index === 0
            ? <Link to="/investigations" search={investigationSearchParams}>{t("events.card.checksContext")}</Link>
            : <a href={`/app/events?q=${encodeURIComponent(investigationQuery)}`}>{t("events.card.checksSearch")}</a>}</li>)}</ol>
        </Section>
        <RelationsSection eventDbId={item.event_db_id} query={relations} search={routeSearch} format={format} refinementSearch={investigationSearchParams}/>
        <EntitiesSection eventDbId={item.event_db_id} query={entities}/>
        <EventSemanticLookup eventDbId={item.event_db_id}/>
      </> : <RawSections item={item} timeZone={timeZone}/>}
    </div>
    <Section title={t("events.card.investigationTitle")} note={t("events.card.investigationNote")}>
      <InvestigationMutationGate role={role} action="create_case">
        <form className="sli-ds-filters" onSubmit={(formEvent) => { formEvent.preventDefault(); if (createCase.isPending || createdCaseId || submittedEvents.current.has(item.event_db_id)) return; submittedEvents.current.add(item.event_db_id); createCase.mutate({ title: caseTitle.trim() || t("events.card.investigationTitlePlaceholder", { id: String(item.event_db_id) }), owner: caseOwner, eventDbId: item.event_db_id }); }}>
          <strong>{t("events.card.investigationNew")}</strong>
          <div className="sli-ds-filters__fields">
            <div className="sli-ds-field"><label htmlFor="case-title">{t("events.card.investigationTitleLabel")}</label>
              <input id="case-title" value={caseTitle} onChange={(inputEvent) => setCaseTitle(inputEvent.target.value)} placeholder={t("events.card.investigationTitlePlaceholder", { id: String(item.event_db_id) })} maxLength={300}/></div>
            <div className="sli-ds-field"><label htmlFor="case-owner">{t("events.card.investigationOwnerLabel")}</label>
              <input id="case-owner" value={caseOwner} onChange={(inputEvent) => setCaseOwner(inputEvent.target.value)} placeholder={t("events.card.investigationOwnerPlaceholder")} maxLength={200}/></div>
          </div>
          <div className="sli-ds-filters__actions">
            <EventCaseMutationOutcome caseId={createdCaseId} eventDbId={item.event_db_id} returnTo={rawReturnTo} action="create"/>
            {createCase.isError ? <span className="sli-ds-field__error" role="alert">{investigationCreateError(createCase.error)}</span> : null}
            <button type="submit" className="sli-ds-button" data-variant="primary" disabled={createCase.isPending || Boolean(createdCaseId)}>{createCase.isPending ? t("events.card.investigationCreating") : t("events.card.investigationCreateSubmit")}</button>
          </div>
        </form>
      </InvestigationMutationGate>
      <InvestigationMutationGate role={role} action="add_evidence">
        <form className="sli-ds-filters" onSubmit={(formEvent) => { formEvent.preventDefault(); if (existingCaseId) addToExistingCase.mutate({ caseId: Number(existingCaseId), eventDbId: item.event_db_id }); }}>
          <strong>{t("events.card.investigationExisting")}</strong>
          {caseList.isLoading ? <StateView compact state="loading"/> : caseList.data?.items.length ? <div className="sli-ds-filters__fields">
            <div className="sli-ds-field"><label htmlFor="existing-case">{t("events.card.investigationCaseLabel")}</label>
              <select id="existing-case" value={existingCaseId} onChange={(selectEvent) => setExistingCaseId(selectEvent.target.value)}>
                <option value="">{t("events.card.investigationCaseSelect")}</option>
                {caseList.data.items.map((caseItem) => <option key={caseItem.id} value={caseItem.id}>{caseNumber(caseItem)} · {caseItem.title}</option>)}
              </select></div>
          </div> : caseList.isError ? <StateView compact state="unavailable" detail={t("events.card.investigationCasesUnavailable")}/> : <StateView compact state="empty" detail={t("events.card.investigationCasesEmpty")}/>}
          <div className="sli-ds-filters__actions">
            {evidenceAddedCaseId ? <span role="status">{t("events.card.investigationEvidenceAdded")}</span> : null}
            <EventCaseMutationOutcome caseId={evidenceAddedCaseId} eventDbId={item.event_db_id} returnTo={rawReturnTo} action="add_evidence"/>
            {addToExistingCase.isError ? <span className="sli-ds-field__error" role="alert">{t("events.card.investigationEvidenceFailed")}</span> : null}
            {caseList.data?.items.length ? <button type="submit" className="sli-ds-button" disabled={!existingCaseId || addToExistingCase.isPending}>{addToExistingCase.isPending ? t("events.card.investigationAdding") : t("events.card.investigationAddSubmit")}</button> : null}
          </div>
        </form>
      </InvestigationMutationGate>
    </Section>
  </section>;
}
