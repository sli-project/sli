import { EMPTY_VALUE } from "../shared/format";
import { useMemo, useState, type KeyboardEvent, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useLocation, useParams } from "@tanstack/react-router";
import { api, type EventDetail, type EventEntities, type EventItem, type EventRelations, type SemanticAction } from "../api/client";
import { DataTable, FactList, PageHeader, StateView, type TableColumn } from "../design-system";
import { EventClassificationBadge, WindowsLevelBadge, eventClassificationLabel } from "../components/badges/Badges";
import { DateTime } from "../components/date-time/DateTime";
import { formatDateTime } from "../shared/date-time";
import { useTimeZone } from "./App";
import { entityEvidenceHref, eventEvidenceHref, eventMachineRisk, eventParticipantFacts, отказЗапроса } from "./event-presentation";
import { investigationContext, investigationDisplayTimeZoneFromSearch, investigationRouterSearch, investigationSearch, navigationHrefWithReturnTo, safeInvestigationReturnTo, type InvestigationNavigationContext } from "./investigation-context";
import { statusLabel } from "./status-labels";
import { t } from "../i18n";
import { eventFacts, eventSemanticText, relationReasonText } from "../i18n/event-metadata";

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

function Section({ id, title, children }: { id?: string; title: string; children: ReactNode }) {
  return <section id={id} className="sli-ds-report__views" aria-label={title}>
    <h2>{title}</h2>
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
  if (!request.error && (actions.isLoading || scenarios.isLoading)) return <Section title={title}><StateView state="loading"/></Section>;
  const presentation = eventSemanticLookupPresentation({
    actions: actions.isError ? "error" : actions.data?.state ?? "error",
    scenarios: scenarios.isError ? "error" : scenarios.data?.state ?? "error",
  });
  if (request.error || presentation === "schema_unavailable" || presentation === "error") {
    return <Section title={title}><p role="status">{t("events.card.semanticError")}</p></Section>;
  }
  if (presentation === "unavailable") return <Section title={title}><p role="status">{t("events.card.semanticDenied")}</p></Section>;
  if (presentation === "no_results") return null;
  const rows: Row[] = [
    ...(actions.data?.items ?? []).map((action) => ({ key: `action:${action.canonical_action_id}`, kind: t("events.card.semanticActionKind"), status: actionStatusLabel(action.status) })),
    ...(scenarios.data?.items ?? []).map((scenario) => ({ key: `scenario:${scenario.scenario_id}`, kind: t("events.card.semanticScenarioKind"), status: statusLabel(scenario.status) })),
  ];
  return <Section title={title}>
    <DataTable<Row> caption={title} rows={rows} rowKey={(row) => String(row.key)}
      columns={[{ key: "kind", label: t("events.card.semanticColKind") }, { key: "status", label: t("events.card.semanticColStatus") }]}/>
  </Section>;
}

function RelationsSection({ query, search, format }: {
  query: { isLoading: boolean; isError: boolean; data?: EventRelations }; search: string; format: (value: string | null | undefined) => string;
}) {
  const relations = query.data?.items ?? [];
  const columns: TableColumn<RelationItem>[] = [
    { key: "relation_type", label: t("events.card.relationsColType"), render: (row) => (row.relation_origin === "stored" || row.relation_type === "explicit_event_link" ? t("events.card.relationsExplicitLink") : t("events.card.relationsComputedCorr")) },
    { key: "related_event_db_id", label: t("events.card.relationsColEvent"), render: (row) => { const href = eventEvidenceHref(row.related_event_db_id, search); return href ? <a href={href}>Event {row.related_event_id || EMPTY_VALUE} · DB {row.related_event_db_id}</a> : EMPTY_VALUE; } },
    { key: "related_time_utc", label: t("events.card.relationsColTime"), render: (row) => (format(row.related_time_utc)) },
    { key: "reason", label: t("events.card.relationsColReason"), render: (row) => {
      return <div>
        <div>{relationReasonText(row, EMPTY_VALUE)}</div>
        {row.entity ? <div>{t("events.card.relationsEntity", { entity: row.entity })}</div> : null}
        {row.time_delta_seconds !== undefined ? <div>{t("events.card.relationsDelta", { delta: String(row.time_delta_seconds) })}</div> : null}
      </div>;
    } },
    { key: "confidence", label: t("events.card.relationsColConfidence"), render: (row) => {
      const explicit = row.relation_origin === "stored" || row.relation_type === "explicit_event_link";
      return <span>{explicit ? t("events.card.relationsLinkValue") : t("events.card.relationsRuleStrength")}: {Math.round(row.confidence * 100)}%</span>;
    } },
  ];
  let body: ReactNode;
  if (query.isLoading) body = <StateView state="loading"/>;
  else if (query.isError) body = <p role="status">{t("events.card.relationsUnavailable")}</p>;
  else if (!relations.length) body = <p role="status">{t("events.card.relationsEmpty")}</p>;
  else body = <DataTable<RelationItem> caption={t("events.card.relationsCaption")} columns={columns} rows={relations} rowKey={(row) => `${row.relation_type}-${row.related_event_db_id}`}/>;
  return <Section title={t("events.card.relationsTitle")}>{body}</Section>;
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
  else if (query.isError) body = <p role="status">{t("events.card.entitiesUnavailable")}</p>;
  else if (timedOut) body = <p role="status">{t("events.card.entitiesTimeout")}</p>;
  else if (!entities.length) body = <p role="status">{t("events.card.entitiesEmpty")}</p>;
  else body = <DataTable<EntityItem> caption={t("events.card.entitiesCaption")} columns={columns} rows={entities} rowKey={(entity) => String(entity.id)}/>;
  return <Section id="evidence" title={t("events.card.entitiesTitle")}>{body}</Section>;
}

export function RawSections({ item, timeZone }: { item: EventDetail; timeZone: string }) {
  const semantic = item.semantics;
  const normalized = [
    { label: t("events.card.rawSubject"), value: item.subject ?? EMPTY_VALUE },
    { label: t("events.card.rawTarget"), value: item.target ?? EMPTY_VALUE },
    { label: t("events.card.rawSource"), value: item.source ?? item.server ?? EMPTY_VALUE },
    ...(semantic ? eventFacts(semantic) : []).map(([label, value]) => ({ label, value })),
  ];
  const expired = item.source_payload_state === "expired";
  const fieldsTitle = expired ? t("events.card.retainedFactsTitle") : t("events.card.rawFieldsTitle");
  const eventData = Object.entries((expired ? item.retained_facts : item.event_data) ?? {}).map(([key, value]) => ({ key, value: String(value ?? "").trim() ? String(value) : EMPTY_VALUE }));
  return <>
    <Section title={t("events.card.rawNormalizedTitle")}><FactList facts={normalized}/></Section>
    <Section title={t("events.card.rawMessageTitle")}>
      <pre className="sli-ds-pre">{!expired && item.message_text?.trim() ? item.message_text : EMPTY_VALUE}</pre>
    </Section>
    <Section title={fieldsTitle}>
      {eventData.length
        ? <DataTable<{ key: string; value: string }> caption={fieldsTitle} rows={eventData} rowKey={(row) => row.key} columns={[{ key: "key", label: t("events.card.rawColField") }, { key: "value", label: t("events.card.rawColValue") }]}/>
        : <p>{EMPTY_VALUE}</p>}
    </Section>
    <Section title={t("events.card.rawXmlTitle")}><p>{EMPTY_VALUE}</p></Section>
    <Section title={t("events.card.rawTechTitle")}>
      <FactList facts={[
        { label: "Provider", value: item.provider_name ?? EMPTY_VALUE },
        { label: "Channel", value: item.channel ?? EMPTY_VALUE },
        { label: "Event Record ID", value: item.event_record_id ?? EMPTY_VALUE },
        { label: t("events.card.rawExactId"), value: item.event_db_id },
        { label: t("events.card.rawTimeUtc"), value: item.time_created_utc ?? EMPTY_VALUE },
        { label: t("events.card.rawTimeLocal"), value: <DateTime value={item.time_created_utc} timeZone={timeZone} showZone/> },
      ]}/>
    </Section>
  </>;
}

export function EventCardPage() {
  const { timeZone: globalTimeZone } = useTimeZone();
  const timeZone = investigationDisplayTimeZoneFromSearch(window.location.search, globalTimeZone).timeZone;
  const { eventId } = useParams({ from: "/events/$eventId" });
  const location = useLocation();
  const routeSearch = new URL(location.href, "http://localhost").search;
  const returnValues = new URLSearchParams(routeSearch).getAll("return_to");
  const rawReturnTo = returnValues.length === 1 ? returnValues[0] : "";
  const returnTo = safeInvestigationReturnTo(rawReturnTo, "/app/events");
  const event = useQuery({ queryKey: ["event", eventId], queryFn: () => api.event(eventId) });
  const relations = useQuery({ queryKey: ["event-relations", eventId], queryFn: () => api.eventRelations(Number(eventId)), enabled: Boolean(event.data?.item?.event_db_id) });
  const entities = useQuery({ queryKey: ["event-entities", eventId], queryFn: () => api.eventEntities(Number(eventId)), enabled: Boolean(event.data?.item?.event_db_id) });
  const [view, setView] = useState<CardView>("overview");
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
  const sourceFailure = item.source_payload_state === "expired" ? "events.card.recordExpired"
    : item.source_payload_state === "archive_unavailable" ? "events.card.recordUnavailable" : null;
  const investigationQuery = item.subject || item.target || item.server || String(item.event_id);
  const investigationSearchParams = exactEventInvestigationSearch(item, investigationQuery, timeZone);
  const facts = [...(semantic ? eventFacts(semantic) : [[t("events.presentation.factServer"), item.server ?? EMPTY_VALUE]] as Array<[string, string]>), ...eventParticipantFacts(item, semantic?.facts ?? [])]
    .map(([label, value]) => ({ label, value }));
  const watchPriority = semantic?.watch_priority;
  if (watchPriority?.reason === "watch") facts.push({
    label: t("events.card.watchPriority"),
    value: `${eventClassificationLabel(watchPriority.base_severity)} → ${eventClassificationLabel(watchPriority.effective_severity)}`,
  });
  const checks = semantic?.checks ?? [t("events.card.checksDefault")];

  return <section className="sli-ds-report">
    <PageHeader
      title={eventSemanticText(semantic?.title_code, semantic?.title ?? t("events.card.headerFallback"))}
      crumbs={crumbs(`Event ${item.event_db_id}`)}
      subtitle={`Event ID ${item.event_id} · DB ${item.event_db_id} · ${format(item.time_created_utc)}`}
      meta={<>
        <EventClassificationBadge value={eventMachineRisk(item)} origin={semantic?.classification_origin}/>
        <WindowsLevelBadge value={item.level}/>
        <span className="sli-ds-chip" title={`${item.server || EMPTY_VALUE} · Record ${item.event_record_id ?? EMPTY_VALUE}`}>DB {item.event_db_id}</span>
      </>}
      actions={<Link className="sli-ds-button" data-variant="primary" to="/investigations" search={investigationSearchParams}>{t("events.card.actionOpenContext")}</Link>}
    />
    <CardTabs active={view} onChange={setView}/>
    {sourceFailure ? <p role="status">{t(sourceFailure, { id: item.event_id, time: format(item.time_created_utc) })}</p> : null}
    <div id="event-tabpanel" role="tabpanel" aria-labelledby={`event-tab-${view}`} className="sli-ds-report__views">
      {view === "overview" ? <>
        <Section title={t("events.card.overviewTitle")}><FactList facts={facts}/></Section>
        <Section title={t("events.card.checksTitle")}>
          <ol>{checks.map((check, index) => <li key={check}><span>{eventSemanticText(semantic?.check_codes?.[index], check)}</span>{" "}{index === 0
            ? <Link to="/investigations" search={investigationSearchParams}>{t("events.card.checksContext")}</Link>
            : <a href={`/app/events?q=${encodeURIComponent(investigationQuery)}`}>{t("events.card.checksSearch")}</a>}</li>)}</ol>
        </Section>
        <RelationsSection query={relations} search={routeSearch} format={format}/>
        <EntitiesSection eventDbId={item.event_db_id} query={entities}/>
        <EventSemanticLookup eventDbId={item.event_db_id}/>
      </> : <RawSections item={item} timeZone={timeZone}/>}
    </div>
  </section>;
}
