import { EMPTY_VALUE, formatNumber } from "../shared/format";
import { AccountWatch } from "./account-watch";
import { useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation, useNavigate, useParams } from "@tanstack/react-router";
import { api, type EntityCurrentState, type EntityWorkspaceEvent, type EntityWorkspaceDetail, type V4ObjectDetail } from "../api/client";
import { Chart, DataTable, FactList, PageHeader, PeriodPicker, StateView, Tabs, TabList, TabPanel, type PeriodValue, type ResultState, type TableColumn } from "../design-system";
import { formatDateTime } from "../shared/date-time";
import { t } from "../i18n";
import { fixedText } from "../i18n/fixed-text";
import { useTimeZone } from "./App";
import { entityAdContextPresentation } from "./entity-ad-context";
import { entityEventTimeline } from "./entity-timeline";
import { entityVpnApiParameters, entityVpnCompletenessLabel, entityVpnLifecycleLabel } from "./entity-vpn";
import { entityInvestigationHref, eventEvidenceHref, exactNavigationId, отказЗапроса } from "./event-presentation";
import { entityWorkspaceApiParameters, investigationContext, investigationDisplayTimeZoneFromSearch, investigationSearch, navigationHrefWithReturnTo, safeInvestigationReturnTo } from "./investigation-context";
import { securityEventRows, semanticRelationExplanation, semanticRelationIdentityBasis, semanticRelationPresentation, semanticRelationTitle } from "./security-events-report";
import { caseStatusLabel as statusLabel } from "./case-status";
import { groupMembershipRowsView, privilegePathRowsView } from "./entity-ad-relations";
import { shortEntityProfile, entityProfileValue } from "./entity-profile";
import { objectTypeLabel } from "./report-labels";
import { VpnConnectionSessionEvidence } from "./vpn-session-evidence";
import { defaultEntityWindow, ENTITY_WINDOW_MAX_DAYS, entityBoundDay, entityTypeLacksTab, entityWindowDays, recentEntityWindow, type EntityWindow } from "./entity-window";

type Row = Record<string, unknown>;
type TabId = "overview" | "groups" | "privileges" | "states" | "findings" | "events" | "security" | "vpn" | "technical";

const getTabLabels = (): Record<TabId, string> => ({
  overview: t("entities.tab.overview"), groups: t("entities.tab.groups"), privileges: t("entities.tab.privileges"), states: t("entities.tab.states"),
  findings: t("entities.tab.findings"), events: t("entities.tab.events"), security: t("entities.tab.security"), vpn: t("entities.tab.vpn"), technical: t("entities.tab.technical"),
});
const TAB_ORDER: TabId[] = ["overview", "groups", "privileges", "states", "findings", "events", "security", "vpn", "technical"];
const SERVER_TABS: TabId[] = ["groups", "privileges", "states", "findings", "technical"];
/** Tabs of the retired object card that are now served by the events tab. */
const TAB_ALIASES: Record<string, TabId> = { activity: "events", evidence: "events" };

const getStateTypeLabels = (): Record<string, string> => ({
  "account.access": t("entities.stateType.accountAccess"),
  "account.lifecycle": t("entities.stateType.accountLifecycle"),
  "account.credentials": t("entities.stateType.accountCredentials"),
  "group.membership": t("entities.stateType.groupMembership"),
});

/** The retired `/objects/<type>/<id>` address resolves to the same entity card; the object id IS the entity id. */
export function objectRouteRedirect(objectId: string, search: Record<string, unknown>) {
  return { to: "/entities/$entityId" as const, params: { entityId: objectId }, search };
}

/** Evidence links keep the entity, the scope and the selected interval of the card. */
export function entityEvidenceNavigationSearch(entityId: string, href: string): string {
  const search = new URL(href, "http://localhost").search;
  const entity_id = exactNavigationId(entityId, "entity_id");
  const scope = investigationContext(new URLSearchParams(search)).scope ?? "all";
  return entity_id ? new URLSearchParams(investigationSearch(search, { entity_id, scope })).toString() : search;
}

/** The server section state decides which honest message is shown; it is never rendered as zero rows. */
export function sectionResultState(state: string | null | undefined): { state: ResultState; detail: string | null } {
  switch (state) {
    // "empty" / "empty_unverified" are readers' own answers for "queried, nothing found": the section then shows its honest empty text, not an outage.
    case undefined: case null: case "": case "available": case "ok": case "empty": case "empty_unverified": return { state: "ok", detail: null };
    case "not_collected": return { state: "unavailable", detail: t("entities.sectionState.notCollected") };
    case "time_bounds_required": return { state: "partial", detail: t("entities.sectionState.timeBoundsRequired") };
    case "temporarily_unavailable": case "schema_unavailable": return { state: "unavailable", detail: t("entities.sectionState.temporarilyUnavailable") };
    case "forbidden": case "not_authorized": return { state: "denied", detail: t("entities.sectionState.forbidden") };
    default: return { state: "unavailable", detail: t("entities.sectionState.unknown", { state: String(state) }) };
  }
}

const text = (value: unknown) => (value === null || value === undefined || value === "" ? "" : typeof value === "object" ? JSON.stringify(value) : String(value));
const humanInteger = (value: number) => formatNumber(value);

function newestFirst<T>(items: readonly T[], timeOf: (item: T) => string | null | undefined, idOf: (item: T) => number): T[] {
  return [...items].sort((left, right) => {
    const leftMs = Date.parse(timeOf(left) || "");
    const rightMs = Date.parse(timeOf(right) || "");
    const byTime = (Number.isNaN(rightMs) ? -Infinity : rightMs) - (Number.isNaN(leftMs) ? -Infinity : leftMs);
    return byTime || idOf(right) - idOf(left);
  });
}

/** Prefer current versions, then the last observation of each individual attribute. */
export function entityProfileFields(items: readonly Row[]) {
  const observedAt = (item: Row) => text(item.last_observed_at_utc ?? item.observed_at_utc ?? item.valid_from_utc);
  const ordered = newestFirst(items.filter((item) => item.context_kind === "entity"), observedAt, (item) => Number(item.context_evidence_id) || 0)
    .sort((left, right) => Number(right.current === true) - Number(left.current === true));
  const fields = new Map<string, { value: unknown; observation: Row; observedAt: string }>();
  for (const item of ordered) {
    const record = item.attributes;
    if (!record || typeof record !== "object" || Array.isArray(record)) continue;
    const attributes = "attributes" in record && record.attributes && typeof record.attributes === "object" && !Array.isArray(record.attributes)
      ? record.attributes : record;
    for (const [key, value] of Object.entries(attributes)) {
      if (key !== "record_key" && !fields.has(key)) fields.set(key, { value, observation: item, observedAt: observedAt(item) });
    }
  }
  return fields;
}

function Section({ title, note, badge, children }: { title: string; note?: ReactNode; badge?: ReactNode; children: ReactNode }) {
  return <section className="sli-ds-report__views" aria-label={title}>
    <div className="sli-ds-header__row"><div><h2>{title}</h2>{note ? <p className="sli-ds-header__subtitle">{note}</p> : null}</div>{badge ? <span className="sli-ds-chip">{badge}</span> : null}</div>
    {children}
  </section>;
}

/** A section either shows its honest server state or, when the data is fine, its content. */
function Guarded({ state, empty, children }: { state: string | null | undefined; empty?: { rows: number; detail: string }; children: ReactNode }) {
  const result = sectionResultState(state);
  if (result.state !== "ok") return <StateView state={result.state} detail={result.detail}/>;
  if (empty && empty.rows === 0) return <StateView state="empty" detail={empty.detail}/>;
  return <>{children}</>;
}

export function EntityCardPage() {
  const { timeZone: globalTimeZone } = useTimeZone();
  const location = useLocation();
  const navigate = useNavigate();
  const search = new URL(location.href, "http://localhost").search;
  const timeZone = investigationDisplayTimeZoneFromSearch(search, globalTimeZone).timeZone;
  const { entityId } = useParams({ from: "/entities/$entityId" });
  const returnTo = safeInvestigationReturnTo(new URLSearchParams(search).get("return_to"), "/app/objects");
  const requestedTab = new URLSearchParams(search).get("tab") ?? "overview";
  const entityRequest = useMemo(() => {
    try {
      const parameters = entityWorkspaceApiParameters(search, 50);
      return { error: null, parameters, key: parameters.toString() };
    } catch (error) {
      return { error: error instanceof Error ? error.message : "invalid_context", parameters: null, key: "invalid-context" };
    }
  }, [search]);
  const urlVpnParameters = useMemo(() => {
    try { return entityVpnApiParameters(search, 50); } catch { return null; }
  }, [search]);
  const detail = useQuery({ queryKey: ["entity", entityId, entityRequest.key], queryFn: () => api.entityWorkspace(entityId, entityRequest.parameters!), enabled: !entityRequest.error, staleTime: 30_000, refetchOnWindowFocus: false });
  const object = useQuery({ queryKey: ["v4", "object", "entity", entityId], queryFn: () => api.v4Object("entity", entityId), enabled: !entityRequest.error, staleTime: 30_000, refetchOnWindowFocus: false, retry: false });
  const serverTabs = new Set((object.data?.tabs ?? []).filter((tab) => tab.available).map((tab) => tab.id));
  const entityType = object.data?.object.object_type ?? detail.data?.entity.type ?? null;
  const tabs = TAB_ORDER.filter((tab) => (!SERVER_TABS.includes(tab) || serverTabs.has(tab)) && !entityTypeLacksTab(entityType, tab));
  const wanted = (TAB_ALIASES[requestedTab] ?? requestedTab) as TabId;
  const active: TabId = tabs.includes(wanted) || (object.isLoading && SERVER_TABS.includes(wanted)) ? wanted : "overview";
  // Without a period in the address, security actions and VPN sessions are read for a default window
  // (30 days ending at the last observation); the tabs show it and let the user change it.
  const hasUrlWindow = Boolean(urlVpnParameters);
  const lastSeenUtc = detail.data?.entity.last_seen_utc ?? null;
  const defaultWindow = useMemo(() => defaultEntityWindow(lastSeenUtc), [lastSeenUtc]);
  const defaultParameters = useMemo(() => {
    if (hasUrlWindow || !entityRequest.parameters) return null;
    const parameters = new URLSearchParams(entityRequest.parameters);
    parameters.set("time_from", defaultWindow.from);
    parameters.set("time_to", defaultWindow.to);
    return parameters;
  }, [hasUrlWindow, entityRequest.parameters, defaultWindow]);
  const vpnParameters = urlVpnParameters ?? (detail.data ? defaultParameters : null);
  const windowed = useQuery({ queryKey: ["entity", entityId, "default-window", defaultParameters?.toString() ?? "none"], queryFn: () => api.entityWorkspace(entityId, defaultParameters!), enabled: active === "security" && Boolean(defaultParameters) && Boolean(detail.data) && !entityRequest.error, staleTime: 30_000, refetchOnWindowFocus: false, retry: false });
  const vpn = useQuery({ queryKey: ["entity", entityId, "vpn", vpnParameters?.toString() ?? "no-window"], queryFn: () => api.entityVpnSessions(entityId, vpnParameters!), enabled: active === "vpn" && Boolean(vpnParameters) && Boolean(detail.data) && !entityRequest.error, staleTime: 30_000, refetchOnWindowFocus: false, retry: false });
  const format = (value: string | null | undefined) => formatDateTime(value, timeZone, { seconds: true });

  if (entityRequest.error) {
    return <section className="sli-ds-report"><PageHeader title={t("entities.error.invalidContext")} crumbs={[{ label: t("entities.crumbs.back"), href: returnTo }, { label: t("entities.crumbs.entity", { id: entityId }) }]}/>
      <StateView state="unavailable" detail={t("entities.error.invalidContextDetail", { error: String(entityRequest.error) })}/></section>;
  }
  if (detail.isLoading) {
    return <section className="sli-ds-report"><PageHeader title={t("entities.title")} crumbs={[{ label: t("entities.crumbs.back"), href: returnTo }, { label: t("entities.crumbs.entity", { id: entityId }) }]}/><StateView state="loading"/></section>;
  }
  if (detail.isError || !detail.data) {
    const failure = отказЗапроса(detail.error as { status?: number; code?: string } | null, t("entities.entityGenitive"));
    const denied = (detail.error as { status?: number } | null)?.status === 403;
    return <section className="sli-ds-report"><PageHeader title={failure.title} crumbs={[{ label: t("entities.crumbs.back"), href: returnTo }, { label: t("entities.crumbs.entity", { id: entityId }) }]}/>
      <StateView state={denied ? "denied" : "unavailable"} detail={failure.detail} onRetry={failure.retry ? () => void detail.refetch() : undefined}/></section>;
  }

  const data = detail.data;
  const v4 = object.data;
  const selectTab = (tab: TabId) => void navigate({ to: "/entities/$entityId", params: { entityId }, search: ((previous: Record<string, unknown>) => ({ ...previous, tab })) as never, replace: true });

  const effectiveWindow: EntityWindow = hasUrlWindow
    ? { from: entityBoundDay(urlVpnParameters!.get("time_from")), to: entityBoundDay(urlVpnParameters!.get("time_to")) }
    : defaultWindow;
  const applyWindow = (next: EntityWindow) => void navigate({ to: "/entities/$entityId", params: { entityId }, search: ((previous: Record<string, unknown>) => ({ ...previous, time_from: next.from, time_to: next.to })) as never, replace: true });

  const { entity } = data;
  const name = entity.display_name || entity.natural_key || t("entities.unnamedEntity");
  const typeLabel = objectTypeLabel(v4?.object.object_type ?? entity.type ?? "entity");
  const latest = v4?.object.latest_state ?? entity.latest_state ?? null;
  const investigateHref = entityInvestigationHref(entity.id, search);
  const provenance = v4?.provenance ?? [];
  const limitations = v4?.limitations ?? [];

  return <section className="sli-ds-report">
    <PageHeader
      title={name}
      crumbs={[{ label: t("entities.crumbs.back"), href: returnTo }, { label: t("entities.crumbs.entity", { id: entity.id }) }]}
      subtitle={<>{typeLabel}{latest?.status ? ` · ${t("entities.stateLabel")}: ${statusLabel(latest.status)}` : ` · ${t("entities.noConfirmedState")}`}</>}
      meta={provenance.length
        ? provenance.map((item) => <span key={item.source} className="sli-ds-chip">{item.source} · {format(item.observed_at_utc)} · {item.freshness}</span>)
        : <span className="sli-ds-chip">{t("entities.lastSeen")}: {format(entity.last_seen_utc)}</span>}
      actions={<a className="sli-ds-button" data-variant="primary" href={investigateHref}>{t("entities.investigateAction")}</a>}
    />
    {entityType === "ad_user" ? <AccountWatch key={entity.id} entityId={entity.id}/> : null}
    {object.isError ? <StateView compact state="partial" detail={t("entities.error.v4Partial")}/> : null}
    <Tabs items={tabs.map((tab) => ({ key: tab, label: getTabLabels()[tab] }))} active={active} onChange={(key) => selectTab(key as TabId)}>
    <TabList label={t("entities.tabs.aria")}/>
    <TabPanel>
      {active === "overview" ? <OverviewTab data={data} v4={v4} typeLabel={typeLabel} format={format}/> : null}
      {active === "groups" ? <GroupsTab v4={v4} loading={object.isLoading} format={format}/> : null}
      {active === "privileges" ? <PrivilegesTab v4={v4} loading={object.isLoading} format={format}/> : null}
      {active === "states" ? <StatesTab data={data} format={format}/> : null}
      {active === "findings" ? <FindingsTab v4={v4} loading={object.isLoading} evidenceSearch={entityEvidenceNavigationSearch(entityId, location.href)} returnTo={returnTo}/> : null}
      {active === "events" ? <EventsTab data={data} evidenceSearch={entityEvidenceNavigationSearch(entityId, location.href)} returnTo={returnTo} format={format} timeZone={timeZone}/> : null}
      {active === "security" ? <SecurityTab data={hasUrlWindow ? data : windowed.data ?? data} windowPending={!hasUrlWindow && windowed.isLoading} windowFailed={!hasUrlWindow && windowed.isError} period={<EntityPeriod window={effectiveWindow} onApply={applyWindow}/>} evidenceSearch={entityEvidenceNavigationSearch(entityId, location.href)} returnTo={returnTo} format={format}/> : null}
      {active === "vpn" ? <VpnTab data={vpn.data} loading={vpn.isLoading} failed={vpn.isError} hasWindow={Boolean(vpnParameters)} period={<EntityPeriod window={effectiveWindow} onApply={applyWindow}/>} format={format}/> : null}
      {active === "technical" ? <TechnicalTab v4={v4} loading={object.isLoading}/> : null}
    </TabPanel>
    </Tabs>
    {limitations.length ? <StateView compact state="partial" detail={<ul>{limitations.map((item) => <li key={item}>{fixedText(item, "entities.fixed.")}</li>)}</ul>}/> : null}
  </section>;
}

function ServerTabGuard({ v4, loading, children }: { v4: V4ObjectDetail | undefined; loading: boolean; children: (v4: V4ObjectDetail) => ReactNode }) {
  if (loading) return <StateView state="loading"/>;
  if (!v4) return <StateView state="unavailable" detail={t("entities.error.v4Missing")}/>;
  return <>{children(v4)}</>;
}

function OverviewTab({ data, v4, typeLabel, format }: { data: EntityWorkspaceDetail; v4: V4ObjectDetail | undefined; typeLabel: string; format: (value: string | null | undefined) => string }) {
  const { entity } = data;
  const contextItems = v4?.directory_context.items ?? [];
  const profile = entityProfileFields(contextItems);
  const { selected, technical } = shortEntityProfile(v4?.object.object_type ?? entity.type ?? "entity", profile, entity.display_name || entity.natural_key || t("entities.unnamedEntity"));
  const observation = (field: typeof selected[number]) => t("entities.profile.observation", {
    status: field.observation.current === true ? t("entities.adRelations.stateCurrent") : t("entities.adRelations.stateHistorical"),
    date: format(field.observedAt),
    source: [text(field.observation.source_pack_id), text(field.observation.source_section), field.observation.context_evidence_id ? `#${text(field.observation.context_evidence_id)}` : ""].filter(Boolean).join(" · ") || t("entities.unknownCapital"),
  });
  const profileFacts = (fields: typeof selected) => fields.map((field) => ({ label: field.label, value: [entityProfileValue(field.key, field.value, format), field.note].filter(Boolean).join(" · ") }));
  const technicalFacts = [
    { label: t("entities.facts.type"), value: typeLabel },
    { label: t("entities.facts.internalId"), value: String(entity.id) },
    { label: t("entities.facts.key"), value: entity.natural_key },
    { label: t("entities.facts.firstObservation"), value: format(entity.first_seen_utc) },
    { label: t("entities.facts.lastObservation"), value: format(entity.last_seen_utc) },
    ...profileFacts(technical),
    ...[...selected, ...technical].filter((field) => field.observedAt).map((field) => ({ label: t("entities.profile.sourceObservation", { field: field.label }), value: observation(field) })),
  ];
  const context = data.ad_context;
  const contextState = sectionResultState(data.ad_context_state);
  return <>
    <Section title={t("entities.section.profile.title")} note={t("entities.section.profile.note")}><FactList facts={profileFacts(selected)}/><details><summary>{t("entities.profile.technical")}</summary><FactList facts={technicalFacts}/></details></Section>
    <Section title={t("entities.section.states.title")} note={t("entities.section.states.note")} badge={humanInteger(data.current_states.length)}>
      <Guarded state={data.current_states_state} empty={{ rows: data.current_states.length, detail: t("entities.section.states.empty") }}>
        <FactList facts={data.current_states.map((state) => ({ label: getStateTypeLabels()[state.state_type] ?? state.state_type, value: `${statusLabel(state.status)}${state.summary ? ` · ${state.summary}` : ""}` }))}/>
      </Guarded>
    </Section>
    <Section title={t("entities.section.adContext.title")} note={t("entities.section.adContext.note")} badge={humanInteger(context.returned_count)}>
      {contextState.state !== "ok" ? <StateView state={contextState.state} detail={t("entities.section.adContext.unavailable")}/>
        : context.items.length ? <DataTable<Row> caption={t("entities.section.adContext.caption")} rowKey={(row) => String(row.id)}
          columns={[{ key: "title", label: t("entities.section.adContext.colRecord") }, { key: "summary", label: t("entities.section.adContext.colSummary") }, { key: "context", label: t("entities.section.adContext.colContext") }, { key: "source", label: t("entities.section.adContext.colSource") }, { key: "observed", label: t("entities.section.adContext.colObserved") }]}
          rows={context.items.map((item) => { const presentation = entityAdContextPresentation(item); return { id: item.context_evidence_id, title: presentation.title, summary: presentation.summary, context: presentation.context, source: `${item.source_pack_id} · evidence ${item.context_evidence_id ?? EMPTY_VALUE}`, observed: format(item.observed_at_utc) }; })}/>
          : <StateView state="empty" detail={t("entities.section.adContext.empty", { resolution: context.resolution })}/>}
    </Section>
  </>;
}

function GroupsTab({ v4, loading, format }: { v4: V4ObjectDetail | undefined; loading: boolean; format: (value: string | null | undefined) => string }) {
  return <ServerTabGuard v4={v4} loading={loading}>{(object) => {
    const rows = groupMembershipRowsView(object.directory_context.items ?? [], (value) => format(value));
    return <Section title={t("entities.section.groups.title")} note={t("entities.section.groups.note")} badge={humanInteger(rows.length)}>
      {rows.length ? <DataTable<Row> caption={t("entities.section.groups.caption")} rowKey={(row) => JSON.stringify(row)} rows={rows as unknown as Row[]}
        columns={[{ key: "groupName", label: t("entities.section.groups.colGroupObject") }, { key: "membershipType", label: t("entities.section.groups.colMembershipType") }, { key: "source", label: t("entities.section.groups.colSource") }, { key: "status", label: t("entities.section.groups.colStatus") }, { key: "observedAt", label: t("entities.section.groups.colObserved") }]}/>
        : <StateView state="empty" detail={(object.directory_context.items ?? []).length ? t("entities.section.groups.empty") : t("entities.section.groups.emptyNoContext")}/>}
    </Section>;
  }}</ServerTabGuard>;
}

function PrivilegesTab({ v4, loading, format }: { v4: V4ObjectDetail | undefined; loading: boolean; format: (value: string | null | undefined) => string }) {
  return <ServerTabGuard v4={v4} loading={loading}>{(object) => {
    const rows = privilegePathRowsView(object.directory_context.items ?? [], (value) => format(value));
    return <Section title={t("entities.section.privileges.title")} note={t("entities.section.privileges.note")} badge={humanInteger(rows.length)}>
      {rows.length ? <DataTable<Row> caption={t("entities.section.privileges.caption")} rowKey={(row) => JSON.stringify(row)} rows={rows as unknown as Row[]}
        columns={[{ key: "classification", label: t("entities.section.privileges.colClassification") }, { key: "groupName", label: t("entities.section.privileges.colTargetObject") }, { key: "path", label: t("entities.section.privileges.colPath") }, { key: "evidenceId", label: t("entities.section.privileges.colEvidence") }, { key: "observedAt", label: t("entities.section.privileges.colObserved") }]}/>
        : <StateView state="empty" detail={(object.directory_context.items ?? []).length ? t("entities.section.privileges.empty") : t("entities.section.privileges.emptyNoContext")}/>}
    </Section>;
  }}</ServerTabGuard>;
}

function StatesTab({ data, format }: { data: EntityWorkspaceDetail; format: (value: string | null | undefined) => string }) {
  const columns: TableColumn<EntityCurrentState>[] = [
    { key: "state_type", label: t("entities.section.states.colState"), render: (row) => getStateTypeLabels()[row.state_type] ?? row.state_type },
    { key: "status", label: t("entities.section.states.colStatus"), render: (row) => statusLabel(row.projection_status === "conflict" ? "conflict" : row.status) },
    { key: "summary", label: t("entities.section.states.colSummary") },
    { key: "observed_at_utc", label: t("entities.section.states.colObserved"), render: (row) => (format(row.observed_at_utc)) },
    { key: "rule_id", label: t("entities.section.states.colRule"), render: (row) => (row.rule_id ? `${row.rule_id}${row.rule_version ? ` · ${row.rule_version}` : ""}` : EMPTY_VALUE) },
    { key: "evidence_event_db_id", label: t("entities.section.states.colEvidence"), render: (row) => <a href={`/app/events/${row.evidence_event_db_id}`}>{t("entities.section.states.eventLink", { id: row.evidence_event_db_id })}</a> },
  ];
  return <Section title={t("entities.section.states.tableTitle")} note={t("entities.section.states.tableNote")} badge={humanInteger(data.current_states.length)}>
    <Guarded state={data.current_states_state} empty={{ rows: data.current_states.length, detail: t("entities.section.states.tableEmpty") }}>
      <DataTable<EntityCurrentState> caption={t("entities.section.states.tableCaption")} columns={columns} rows={data.current_states} rowKey={(row) => row.state_type}/>
    </Guarded>
  </Section>;
}

function FindingsTab({ v4, loading, evidenceSearch, returnTo }: { v4: V4ObjectDetail | undefined; loading: boolean; evidenceSearch: string; returnTo: string }) {
  return <ServerTabGuard v4={v4} loading={loading}>{(object) => {
    const columns: TableColumn<Row>[] = [
      { key: "title", label: t("entities.section.findings.colTitle") }, { key: "severity", label: t("entities.section.findings.colRisk") }, { key: "status", label: t("entities.section.findings.colStatus"), render: (row) => statusLabel(row.status) }, { key: "summary", label: t("entities.section.findings.colSummary") },
      { key: "evidence_event_id", label: t("entities.section.findings.colEvidence"), render: (row) => { const base = eventEvidenceHref(row.evidence_event_id, evidenceSearch); return base ? <a href={navigationHrefWithReturnTo(base, returnTo)}>{t("entities.dbLink", { id: text(row.evidence_event_id) })}</a> : <span>{t("entities.section.findings.noExactId")}</span>; } },
    ];
    return <Section title={t("entities.section.findings.title")} note={t("entities.section.findings.note")} badge={humanInteger(object.findings.length)}>
      {object.findings.length ? <DataTable<Row> caption={t("entities.section.findings.caption")} columns={columns} rows={object.findings} rowKey={(row) => text(row.id) || JSON.stringify(row)}/>
        : <StateView state="empty" detail={t("entities.section.findings.empty")}/>}
    </Section>;
  }}</ServerTabGuard>;
}

function EventsTab({ data, evidenceSearch, returnTo, format, timeZone }: { data: EntityWorkspaceDetail; evidenceSearch: string; returnTo: string; format: (value: string | null | undefined) => string; timeZone: string | undefined }) {
  const events = useMemo(() => newestFirst(data.events, (item) => item.time_utc, (item) => item.event_db_id), [data.events]);
  const timeline = useMemo(() => entityEventTimeline(data.events, timeZone), [data.events, timeZone]);
  const columns: TableColumn<EntityWorkspaceEvent>[] = [
    { key: "time_utc", label: t("entities.section.events.colTime"), render: (row) => (row.time_utc ? format(row.time_utc) : t("entities.unknownCapital")) },
    { key: "label", label: t("entities.section.events.colEvent"), render: (row) => row.event_id == null ? (row.label || t("entities.timeline.eventFallback")) : `${row.label || t("entities.section.events.fallbackEventLabel", { id: String(row.event_id) })} · Event ID ${row.event_id}` },
    { key: "link_role", label: t("entities.section.events.colRole"), render: (row) => `${row.link_role || t("entities.section.events.notDetermined")} · ${row.confidence == null ? t("entities.unknownCapital") : t("entities.section.events.confidence", { percent: Math.round(row.confidence * 100) })}` },
    { key: "actor", label: t("entities.section.events.colActor"), render: (row) => row.actor || t("entities.section.events.notDetermined") },
    { key: "target", label: t("entities.section.events.colTarget"), render: (row) => row.target || t("entities.section.events.notDetermined") },
    { key: "server", label: t("entities.section.events.colSource"), render: (row) => [row.server, row.channel].filter(Boolean).join(" · ") || row.provider_name || t("entities.section.events.notDeterminedMale") },
    { key: "event_db_id", label: t("entities.section.events.colEvidence"), render: (row) => { const base = eventEvidenceHref(row.event_db_id, evidenceSearch); return base ? <a href={navigationHrefWithReturnTo(base, returnTo)}>{t("entities.dbLink", { id: row.event_db_id })}</a> : <span>{t("entities.section.findings.noExactId")}</span>; } },
  ];
  return <Section title={t("entities.section.events.title")} note={t("entities.section.events.note", { limit: String(data.limits.events ?? events.length) })}
    badge={data.has_more ? t("entities.section.events.badgeMore") : t("entities.section.events.badgeAll")}>
    <Guarded state={data.events_state} empty={{ rows: events.length, detail: t("entities.section.events.empty") }}>
      {timeline ? <Chart title={t("entities.section.events.chartTitle")} spec={timeline} height={220}/> : null}
      <DataTable<EntityWorkspaceEvent> caption={t("entities.section.events.caption")} columns={columns} rows={events} rowKey={(row) => String(row.event_db_id)}/>
    </Guarded>
    {data.has_more ? <StateView compact state="partial" detail={t("entities.section.events.partial")}/> : null}
  </Section>;
}

/** The period the security and VPN tabs read; edits apply once the range is complete and within the server limit. */
function EntityPeriod({ window, onApply }: { window: EntityWindow; onApply: (window: EntityWindow) => void }) {
  const [draft, setDraft] = useState<PeriodValue>({ preset: "custom", from: window.from, to: window.to });
  const days = draft.from && draft.to ? entityWindowDays({ from: draft.from, to: draft.to }) : null;
  const tooWide = days !== null && days > ENTITY_WINDOW_MAX_DAYS;
  const change = (next: PeriodValue) => {
    if (next.preset === "7d" || next.preset === "30d") {
      const recent = recentEntityWindow(next.preset === "7d" ? 7 : 30);
      setDraft({ preset: "custom", from: recent.from, to: recent.to });
      onApply(recent);
      return;
    }
    setDraft({ ...next, preset: "custom" });
    const range = next.from && next.to ? { from: next.from, to: next.to } : null;
    const span = range ? entityWindowDays(range) : null;
    if (range && span !== null && span <= ENTITY_WINDOW_MAX_DAYS) onApply(range);
  };
  return <div>
    <PeriodPicker value={draft} onChange={change} presets={["7d", "30d", "custom"]} label={t("entities.period.label")}/>
    {tooWide ? <p role="alert" className="sli-ds-field__error">{t("entities.period.tooWide", { days: String(ENTITY_WINDOW_MAX_DAYS) })}</p> : null}
  </div>;
}

function SecurityTab({ data, windowPending, windowFailed, period, evidenceSearch, returnTo, format }: { data: EntityWorkspaceDetail; windowPending: boolean; windowFailed: boolean; period: ReactNode; evidenceSearch: string; returnTo: string; format: (value: string | null | undefined) => string }) {
  if (windowPending) return <>{period}<StateView state="loading"/></>;
  const actionsState = windowFailed ? "temporarily_unavailable" : data.security_actions_state ?? "time_bounds_required";
  const relationsState = windowFailed ? "temporarily_unavailable" : data.semantic_relations_state ?? "time_bounds_required";
  const rows = securityEventRows(data.security_actions ?? [], (value) => format(value));
  const relations = data.semantic_relations ?? [];
  const columns: TableColumn<(typeof rows)[number]>[] = [
    { key: "time", label: t("entities.section.security.colTime") }, { key: "action", label: t("entities.section.security.colAction") }, { key: "result", label: t("entities.section.security.colResult") }, { key: "actor", label: t("entities.section.security.colActor") }, { key: "target", label: t("entities.section.security.colTarget") },
    { key: "change", label: t("entities.section.security.colChange"), render: (row) => (row.before && row.after ? `${row.before.текст} → ${row.after.текст}` : EMPTY_VALUE) },
    { key: "key", label: t("entities.section.security.colEvidence"), render: (row) => { const base = eventEvidenceHref(row.key, evidenceSearch); return base ? <a href={navigationHrefWithReturnTo(base, returnTo)}>{t("entities.dbLink", { id: row.key })}</a> : <span>{t("entities.section.findings.noExactId")}</span>; } },
  ];
  return <>
    {period}
    <Section title={t("entities.section.security.actionsTitle")} note={t("entities.section.security.actionsNote")}>
      <Guarded state={actionsState} empty={{ rows: rows.length, detail: t("entities.section.security.actionsEmpty") }}>
        <DataTable caption={t("entities.section.security.actionsCaption")} columns={columns} rows={rows} rowKey={(row) => String(row.key)}/>
      </Guarded>
    </Section>
    <Section title={t("entities.section.security.relationsTitle")} badge={humanInteger(relations.length)}>
      <Guarded state={relationsState} empty={{ rows: relations.length, detail: t("entities.section.security.relationsEmpty") }}>
        <ul>{relations.map((relation) => <li key={relation.candidate_id}><strong>{semanticRelationTitle(relation.relation_kind)}</strong>
          {semanticRelationPresentation(relation) ? <span> · {semanticRelationPresentation(relation)}</span> : null}
          <div>{semanticRelationExplanation(relation)}</div>
          {semanticRelationIdentityBasis(relation.identity_basis) ? <div>{semanticRelationIdentityBasis(relation.identity_basis)}</div> : null}</li>)}</ul>
      </Guarded>
    </Section>
  </>;
}

function VpnTab({ data, loading, failed, hasWindow, period, format }: { data: import("../api/client").EntityVpnSessions | undefined; loading: boolean; failed: boolean; hasWindow: boolean; period: ReactNode; format: (value: string | null | undefined) => string }) {
  type Session = import("../api/client").EntityVpnSessions["items"][number];
  const columns: TableColumn<Session>[] = [
    { key: "lifecycle_state", label: t("entities.section.vpn.colLifecycle"), render: (row) => entityVpnLifecycleLabel(row.lifecycle_state) },
    { key: "started_at_utc", label: t("entities.section.vpn.colStart"), render: (row) => (row.started_at_utc ? format(row.started_at_utc) : t("entities.section.vpn.noStart")) },
    { key: "last_observed_at_utc", label: t("entities.section.vpn.colLastObserved"), render: (row) => (row.last_observed_at_utc ? format(row.last_observed_at_utc) : t("entities.unknownCapital")) },
    { key: "stopped_at_utc", label: t("entities.section.vpn.colStop"), render: (row) => (row.stopped_at_utc ? format(row.stopped_at_utc) : t("entities.section.vpn.noStop")) },
    { key: "completeness", label: t("entities.section.vpn.colCompleteness"), render: (row) => entityVpnCompletenessLabel(row.completeness) },
    { key: "evidence_ref", label: t("entities.section.vpn.colEvidence"), render: (row) => ("kind" in row.evidence_ref
      ? <VpnConnectionSessionEvidence sourceDomainId={row.evidence_ref.source_domain_id} sessionRowId={row.evidence_ref.session_row_id} formatTime={(value) => format(value)}/>
      : <span>{t("entities.section.vpn.evidenceDenied")}</span>) },
  ];
  let body: ReactNode;
  if (!hasWindow) body = <StateView state="partial" detail={t("entities.section.vpn.partial")}/>;
  else if (loading) body = <StateView state="loading"/>;
  else if (failed) body = <StateView state="unavailable" detail={t("entities.section.vpn.unavailable")}/>;
  else if (data?.state === "not_authorized") body = <StateView state="denied" detail={t("entities.section.vpn.denied")}/>;
  else if (data?.items.length) body = <DataTable<Session> caption={t("entities.section.vpn.caption")} columns={columns} rows={data.items} rowKey={(row) => row.session_row_id}/>;
  else body = <StateView state="empty" detail={t("entities.section.vpn.empty")}/>;
  return <>{period}<Section title={t("entities.section.vpn.title")} note={t("entities.section.vpn.note")} badge={data?.has_more ? t("entities.section.vpn.badgeMore") : undefined}>{body}</Section></>;
}

function TechnicalTab({ v4, loading }: { v4: V4ObjectDetail | undefined; loading: boolean }) {
  return <ServerTabGuard v4={v4} loading={loading}>{(object) => {
    const items = object.directory_context.items ?? [];
    return <Section title={t("entities.section.technical.title")} note={t("entities.section.technical.note")} badge={humanInteger(items.length)}>
      {items.length ? <DataTable<Row> caption={t("entities.section.technical.caption")} rowKey={(row) => String(row.id)}
        columns={[{ key: "section", label: t("entities.section.technical.colSection") }, { key: "evidence", label: t("entities.section.technical.colEvidence") }, { key: "attributes", label: t("entities.section.technical.colAttributes"), render: (row) => <pre>{String(row.attributes)}</pre> }]}
        rows={items.map((item, index) => ({ id: `${text(item.context_evidence_id)}:${index}`, section: text(item.source_section ?? item.context_kind), evidence: text(item.context_evidence_id), attributes: JSON.stringify(item.attributes ?? {}, null, 2) }))}/>
        : <StateView state="empty" detail={t("entities.section.technical.empty")}/>}
    </Section>;
  }}</ServerTabGuard>;
}
