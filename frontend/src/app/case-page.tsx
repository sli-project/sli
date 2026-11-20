import { eventSemanticText } from "../i18n/event-metadata";
import { caseNumber } from "./case-number";
import { t } from "../i18n";
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useLocation, useParams } from "@tanstack/react-router";
import { ApiResponseError, api, type InvestigationCase } from "../api/client";
import { EventCardCompletenessBadge, EventClassificationBadge } from "../components/badges/Badges";
import { DateTime } from "../components/date-time/DateTime";
import { DataTable, FactList, PageHeader, StateView, type TableColumn } from "../design-system";
import { formatDateTime } from "../shared/date-time";
import { InvestigationMutationGate, bootstrapEffectiveRole, canPerformInvestigationMutation } from "./access-control";
import { useTimeZone } from "./App";
import { eventEvidenceHref, eventMachineRisk } from "./event-presentation";
import { investigationDisplayTimeZoneFromSearch, safeInvestigationReturnTo } from "./investigation-context";
import { caseStatusLabel as statusLabel } from "./case-status";
import { VpnConnectionSessionEvidence } from "./vpn-session-evidence";

type CaseEvidence = InvestigationCase["events"][number];
type EvidenceRef = NonNullable<InvestigationCase["evidence_refs"]>[number];
type CaseNote = InvestigationCase["notes"][number];
type RelationFilter = "all" | "confirmed" | "excluded";

const RISK_LEVELS = ["info", "low", "medium", "high", "critical"];

function matchesMinimumRisk(risk: string, minimum: string) {
  if (!minimum) return true;
  const rank = RISK_LEVELS.indexOf(["information", "informational"].includes(risk) ? "info" : risk);
  if (minimum === "unknown") return rank < 0;
  return rank >= RISK_LEVELS.indexOf(minimum) && rank >= 0;
}

const STATUS_OPTIONS = ["new", "active", "review", "confirmed", "closed"];

/** Порядок добавления evidence не доказывает причинную связь: рёбра графа без отдельного контракта не строятся. */
export function evidenceGraphRelations(_evidence: readonly { event_db_id: number; relation_status: string }[]): readonly [] {
  return [];
}

function newestFirst<T>(items: readonly T[], timeOf: (item: T) => string | null | undefined, idOf?: (item: T) => number) {
  return [...items].sort((left, right) => {
    const leftMs = Date.parse(timeOf(left) || "");
    const rightMs = Date.parse(timeOf(right) || "");
    const byTime = (Number.isNaN(rightMs) ? -Infinity : rightMs) - (Number.isNaN(leftMs) ? -Infinity : leftMs);
    if (byTime) return byTime;
    return idOf ? idOf(right) - idOf(left) : 0;
  });
}

function VpnEvidence({ refs, state, timeZone }: { refs: InvestigationCase["evidence_refs"]; state: InvestigationCase["evidence_refs_state"]; timeZone: string }) {
  const evidenceRefs = refs ?? [];
  if (!evidenceRefs.length && (state ?? "available") === "available") return null;
  const columns: TableColumn<EvidenceRef>[] = [
    { key: "source", label: t("investigations.case.accounting_session"), render: (row) => t("investigations.case.domain", { id: row.source_domain_id }) },
    { key: "relation_status", label: t("investigations.case.relation"), render: (row) => (row.relation_status === "excluded" ? t("investigations.case.excluded_by_an_analyst") : t("investigations.case.saved_as_related_evidence")) },
    { key: "added_by", label: t("investigations.case.added_by") },
    { key: "session", label: t("investigations.case.session"), render: (row) => <VpnConnectionSessionEvidence sourceDomainId={row.source_domain_id} sessionRowId={row.reference_id} formatTime={(value) => formatDateTime(value, timeZone)}/> },
  ];
  return <section className="sli-ds-report__views" aria-label="VPN Accounting">
    <h2>VPN Accounting</h2>
    <p className="sli-ds-header__subtitle">{t("investigations.case.immutable_session_references_are_stored_separately_from_wind")}</p>
    {state === "partially_authorized" ? <StateView state="partial" compact detail={t("investigations.case.some_saved_vpn_evidence_is_hidden_by_current_permissions_its")}/> : null}
    {evidenceRefs.length ? <DataTable columns={columns} rows={evidenceRefs} rowKey={(row) => `${row.source_domain_id}-${row.reference_id}`} caption={t("investigations.case.case_vpn_evidence")}/> : null}
  </section>;
}

export function InvestigationCasePage() {
  const { timeZone: globalTimeZone } = useTimeZone();
  const location = useLocation();
  const search = new URL(location.href, "http://localhost").search;
  const anchorParameter = new URLSearchParams(search).get("event_db_id") ?? "";
  const anchorEventDbId = /^[1-9]\d*$/.test(anchorParameter) && Number.isSafeInteger(Number(anchorParameter)) ? Number(anchorParameter) : null;
  const reportReturnTo = safeInvestigationReturnTo(new URLSearchParams(search).get("return_to"), "");
  const timeZone = investigationDisplayTimeZoneFromSearch(search, globalTimeZone).timeZone;
  const { investigationId } = useParams({ from: "/investigations/$investigationId" });
  const queryClient = useQueryClient();
  const [noteBody, setNoteBody] = useState("");
  const pageContext = `${investigationId}:${anchorEventDbId}`;
  const [paging, setPaging] = useState<{ context: string; events: number[]; refs: string[] }>({ context: pageContext, events: [], refs: [] });
  const eventPages = paging.context === pageContext ? paging.events : [];
  const refPages = paging.context === pageContext ? paging.refs : [];
  const eventAfter = eventPages.at(-1);
  const referenceAfter = refPages.at(-1);
  const changePage = (events: number[], refs: string[]) => setPaging({ context: pageContext, events, refs });
  const selectionContext = `${pageContext}:${eventAfter ?? "first"}`;
  const [eventSelection, setEventSelection] = useState<{ context: string; id: number | null }>();
  const setSelectedEventDbId = (id: number | null) => setEventSelection({ context: selectionContext, id });
  const [relationFilter, setRelationFilter] = useState<RelationFilter>("all");
  const [riskFilter, setRiskFilter] = useState("");
  const [caseView, setCaseView] = useState<"timeline" | "nodes">("timeline");
  const [evidenceOrder, setEvidenceOrder] = useState<"event_time" | "added_at">("event_time");
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrap, staleTime: 60_000 });
  const role = bootstrapEffectiveRole(bootstrap.data);
  const canMutate = canPerformInvestigationMutation(role, "update_case_status");
  const detail = useQuery({ queryKey: ["investigation-case", investigationId, anchorEventDbId, eventAfter, referenceAfter], queryFn: () => api.investigationCase(Number(investigationId), { eventAfter, referenceAfter, anchorEventId: anchorEventDbId ?? undefined }) });
  const caseEvents = newestFirst(detail.data?.events ?? [], (item) => item.added_at, (item) => item.event_db_id);
  const caseEventIds = useMemo(() => caseEvents.map((evidence) => evidence.event_db_id), [caseEvents]);
  const evidenceBatch = useQuery({ queryKey: ["events-batch", caseEventIds], queryFn: () => api.eventsBatch(caseEventIds), enabled: caseEventIds.length > 0, staleTime: 60_000 });
  const anchorEvidence = detail.data?.anchor_event ?? detail.data?.events.find((evidence) => evidence.event_db_id === anchorEventDbId);
  const anchorOutsidePage = anchorEvidence && !caseEventIds.includes(anchorEvidence.event_db_id) ? anchorEvidence.event_db_id : null;
  const anchorBatch = useQuery({ queryKey: ["events-batch", [anchorOutsidePage]], queryFn: () => api.eventsBatch([anchorOutsidePage!]), enabled: anchorOutsidePage !== null, staleTime: 60_000 });
  const evidenceById = useMemo(() => new Map([...(!evidenceBatch.isError ? evidenceBatch.data?.items ?? [] : []), ...(anchorOutsidePage !== null && !anchorBatch.isError ? anchorBatch.data?.items ?? [] : [])].map((item) => [item.event_db_id, item] as const)), [evidenceBatch.data, evidenceBatch.isError, anchorBatch.data, anchorBatch.isError, anchorOutsidePage]);
  const evidenceAccessDenied = evidenceBatch.error instanceof ApiResponseError && (evidenceBatch.error.status === 401 || evidenceBatch.error.status === 403);
  const evidenceContextFallback = evidenceAccessDenied
    ? t("investigations.case.no_permission_to_view_the_evidence_context")
    : evidenceBatch.isError
      ? t("investigations.case.evidence_context_is_temporarily_unavailable")
      : evidenceBatch.isLoading
        ? t("investigations.case.loading_context")
        : t("investigations.case.evidence_context_is_unavailable_within_the_current_access_sc");
  const initialEventDbId = (eventAfter === undefined ? anchorEvidence?.event_db_id : null) ?? caseEvents[0]?.event_db_id ?? null;
  const selectedEventDbId = eventSelection?.context === selectionContext ? eventSelection.id : initialEventDbId;
  useEffect(() => {
    if (detail.data && eventSelection?.context !== selectionContext) {
      setEventSelection({ context: selectionContext, id: initialEventDbId });
    }
  }, [detail.data, eventSelection?.context, selectionContext, initialEventDbId]);
  const refreshCase = async () => { await queryClient.invalidateQueries({ queryKey: ["investigation-case", investigationId] }); };
  const denied = () => Promise.reject(new Error("insufficient_permissions"));
  const addNote = useMutation({ mutationFn: () => canMutate ? api.addInvestigationNote(Number(investigationId), { body: noteBody.trim() }) : denied(), onSuccess: async () => { setNoteBody(""); await refreshCase(); } });
  const updateStatus = useMutation({ mutationFn: (status: string) => canMutate ? api.updateInvestigationStatus(Number(investigationId), { status }) : denied(), onSuccess: refreshCase });
  const updateRelation = useMutation({ mutationFn: ({ eventDbId, relationStatus }: { eventDbId: number; relationStatus: "confirmed" | "excluded" }) => canMutate ? api.addInvestigationEvent(Number(investigationId), { event_db_id: eventDbId, relation_status: relationStatus }) : denied(), onSuccess: refreshCase });

  const backLink = <Link className="sli-ds-button" to="/investigations" search={(previous) => previous}>{t("investigations.case.investigations")}</Link>;
  if (detail.isLoading) return <section className="sli-ds-report"><PageHeader title={t("investigations.case.loading_case")} actions={backLink}/><StateView state="loading"/></section>;
  if (detail.isError || !detail.data) {
    return <section className="sli-ds-report"><PageHeader title={t("investigations.case.case_unavailable")} actions={<Link className="sli-ds-button" to="/investigations" search={(previous) => previous}>{t("investigations.case.return_to_investigations")}</Link>}/>
      <StateView state={detail.error instanceof ApiResponseError && [401, 403].includes(detail.error.status) ? "denied" : "unavailable"} detail={t("investigations.case.check_that_the_investigation_migration_is_installed_and_you_")}/>
      <button type="button" className="sli-ds-button" onClick={() => void detail.refetch()}>{t("investigations.case.retry_page")}</button>
      <button type="button" className="sli-ds-button" onClick={() => changePage([], [])}>{t("investigations.case.restart_pages")}</button></section>;
  }
  const item = detail.data;
  const selectedEvidence = item.events.find((evidence) => evidence.event_db_id === selectedEventDbId) ?? (anchorEvidence?.event_db_id === selectedEventDbId ? anchorEvidence : undefined);
  const selectedEvidenceHref = selectedEvidence ? eventEvidenceHref(selectedEvidence.event_db_id, search) : null;
  const selectedBatch = selectedEvidence?.event_db_id === anchorOutsidePage ? anchorBatch : evidenceBatch;
  const selectedDenied = selectedBatch.error instanceof ApiResponseError && [401, 403].includes(selectedBatch.error.status);
  const selectedFallback = selectedDenied ? t("investigations.case.no_permission_to_view_the_evidence_context") : selectedBatch.isLoading ? t("investigations.case.loading_context")
    : selectedBatch.isError ? t("investigations.case.evidence_context_is_temporarily_unavailable") : evidenceContextFallback;
  const selectedEvent = selectedEvidence ? evidenceById.get(selectedEvidence.event_db_id) : undefined;
  const orderedEvidence = evidenceOrder === "added_at" ? caseEvents
    : newestFirst(caseEvents, (evidence) => evidenceById.get(evidence.event_db_id)?.time_created_utc, (evidence) => evidence.event_db_id);
  const visibleEvidence = orderedEvidence.filter((evidence) => {
    const risk = eventMachineRisk(evidenceById.get(evidence.event_db_id));
    return (relationFilter === "all" || evidence.relation_status === relationFilter) && matchesMinimumRisk(risk, riskFilter);
  });
  const graphRelations = evidenceGraphRelations(visibleEvidence);
  const graphNotice = graphRelations.length
    ? t("investigations.case.the_graph_shows_only_evidence_links_confirmed_by_the_contrac")
    : t("investigations.case.the_order_of_adding_evidence_does_not_prove_causation_edges_");

  const evidenceColumns: TableColumn<CaseEvidence>[] = [
    { key: "time", label: t("investigations.case.time"), render: (row) => { const event = evidenceById.get(row.event_db_id); return <DateTime value={event?.time_created_utc} timeZone={timeZone}/>; } },
    { key: "event", label: t("investigations.case.event"), render: (row) => {
      const event = evidenceById.get(row.event_db_id);
      return <><strong>{eventSemanticText(event?.semantics?.title_code, event?.semantics?.title ?? event?.label ?? `Event DB ${row.event_db_id}`)}</strong><br/><small>{[event?.subject, event?.target, event?.server].filter(Boolean).join(" · ") || evidenceContextFallback}</small></>;
    } },
    { key: "class", label: t("investigations.case.class"), render: (row) => { const event = evidenceById.get(row.event_db_id); return <><EventClassificationBadge value={eventMachineRisk(event)} origin={event?.semantics?.classification_origin}/> <EventCardCompletenessBadge completeness={event?.semantics?.card_completeness}/></>; } },
    { key: "relation", label: t("investigations.case.relation"), render: (row) => `${row.relation_status === "excluded" ? t("investigations.case.excluded_from_chain") : t("investigations.case.confirmed_evidence")} · DB ${row.event_db_id}` },
  ];
  const noteColumns: TableColumn<CaseNote>[] = [
    { key: "created_by", label: t("investigations.case.author") },
    { key: "created_at", label: t("investigations.case.time"), render: (row) => <DateTime value={row.created_at} timeZone={timeZone}/> },
    { key: "body", label: t("investigations.case.note") },
  ];
  const selectedKey = selectedEvidence ? String(selectedEvidence.event_db_id) : null;
  const submitNote = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); if (noteBody.trim()) addNote.mutate(); };

  return <section className="sli-ds-report">
    <PageHeader
      title={item.title}
      subtitle={<>{t("investigations.case.created")} <DateTime value={item.created_at} timeZone={timeZone} showZone/> {t("investigations.case.author_prefix")} {item.created_by}</>}
      meta={<>{backLink}{reportReturnTo ? <a className="sli-ds-button" href={reportReturnTo}>{t("investigations.case.return_to_source_report")}</a> : null}</>}
      actions={<InvestigationMutationGate role={role} action="update_case_status">
        <div className="sli-ds-field"><label htmlFor="case-status">{t("investigations.case.status")}</label>
          <select id="case-status" value={item.status} disabled={updateStatus.isPending} onChange={(event) => updateStatus.mutate(event.target.value)}>
            {STATUS_OPTIONS.map((status) => <option key={status} value={status}>{statusLabel(status)}</option>)}
          </select></div>
        <button className="sli-ds-button" data-variant="primary" type="button" disabled={item.status === "closed" || updateStatus.isPending} onClick={() => updateStatus.mutate("closed")}>{t("investigations.case.close_investigation")}</button>
      </InvestigationMutationGate>}/>
    {updateStatus.isError ? <p role="alert" className="sli-ds-field__error">{t("investigations.case.status_unchanged_the_api_rejected_the_action")}</p> : null}
    {anchorEventDbId !== null && !anchorEvidence ? <p role="status" className="sli-ds-header__subtitle">{t("investigations.case.anchor_not_saved", { id: anchorEventDbId })}</p> : null}

    <section className="sli-ds-report__views" aria-label={t("investigations.case.case_details")}>
      <h2>{t("investigations.case.context")}</h2>
      <FactList facts={[
        { label: t("investigations.case.number"), value: caseNumber(item) },
        { label: t("investigations.case.status"), value: statusLabel(item.status, item.status_message) },
        { label: t("investigations.case.owner"), value: item.owner },
        { label: t("investigations.case.updated"), value: item.updated_at ? <DateTime value={item.updated_at} timeZone={timeZone} showZone/> : null },
        { label: t("investigations.case.closed"), value: item.closed_at ? <DateTime value={item.closed_at} timeZone={timeZone} showZone/> : null },
        ...(selectedEvent ? [
          { label: t("investigations.case.account"), value: selectedEvent.subject ?? t("investigations.case.unknown") },
          { label: t("investigations.case.host"), value: selectedEvent.server ?? t("investigations.case.unknown_2") },
          { label: t("investigations.case.object"), value: selectedEvent.target ?? t("investigations.case.unknown_2") },
          { label: t("investigations.case.time_interval"), value: <DateTime value={selectedEvent.time_created_utc} timeZone={timeZone} showZone/> },
        ] : []),
      ]}/>
      {selectedEvent || !selectedEvidence ? null : <StateView state={selectedBatch.isLoading ? "loading" : selectedDenied ? "denied" : selectedBatch.isError ? "unavailable" : "empty"} compact detail={selectedFallback}/>}
    </section>

    <section className="sli-ds-report__views" aria-label={t("investigations.case.event_chain")}>
      <div className="sli-ds-header__row">
        <div><h2>{t("investigations.case.event_chain")}</h2><p className="sli-ds-header__subtitle">{t("investigations.case.only_evidence_saved_in_this_investigation_is_shown")}</p></div>
        <div role="group" aria-label={t("investigations.case.investigation_view")}>
          <button type="button" className="sli-ds-chip" aria-pressed={caseView === "timeline"} onClick={() => setCaseView("timeline")}>{t("investigations.case.timeline")}</button>
          <button type="button" className="sli-ds-chip" aria-pressed={caseView === "nodes"} onClick={() => setCaseView("nodes")}>{t("investigations.case.nodes_without_links")}</button>
        </div>
      </div>
      <p role="status">{t("investigations.case.page_scope", { shown: caseEvents.length, total: item.events_total ?? caseEvents.length })}</p>
      <p className="sli-ds-header__subtitle">{t("investigations.case.page_consistency")}</p>
      <div className="sli-ds-filters__actions">
        <button type="button" className="sli-ds-button" disabled={!eventPages.length || detail.isFetching} onClick={() => changePage(eventPages.slice(0, -1), refPages)}>{t("investigations.case.previous_events")}</button>
        <button type="button" className="sli-ds-button" disabled={!item.events_next_cursor || detail.isFetching} onClick={() => changePage([...eventPages, item.events_next_cursor!], refPages)}>{t("investigations.case.next_events")}</button>
      </div>
      {evidenceBatch.isLoading ? <StateView state="loading" compact detail={t("investigations.case.loading_context")}/> : null}
      {evidenceBatch.isError ? <><StateView state={evidenceAccessDenied ? "denied" : "unavailable"} compact detail={evidenceContextFallback}/><button type="button" className="sli-ds-button" onClick={() => void evidenceBatch.refetch()}>{t("investigations.case.retry_page")}</button></> : null}
      <div className="sli-ds-filters"><div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor="case-relation-filter">{t("investigations.case.relation_status")}</label>
          <select id="case-relation-filter" value={relationFilter} onChange={(event) => setRelationFilter(event.target.value as RelationFilter)}>
            <option value="all">{t("investigations.case.all_relations")}</option><option value="confirmed">{t("investigations.case.confirmed_relations")}</option><option value="excluded">{t("investigations.case.excluded_relations")}</option>
          </select></div>
        <div className="sli-ds-field"><label htmlFor="case-risk-filter">{t("investigations.case.minimum_risk")}</label>
          <select id="case-risk-filter" value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
            <option value="">{t("investigations.case.all_levels")}</option><option value="critical">{t("investigations.case.critical")}</option><option value="high">{t("investigations.case.high")}</option><option value="medium">{t("investigations.case.medium")}</option><option value="low">{t("investigations.case.low")}</option>
            <option value="unknown">{t("investigations.case.unknown_class_only")}</option>
          </select></div>
        <div className="sli-ds-field"><label htmlFor="case-evidence-order">{t("investigations.case.evidence_order")}</label>
          <select id="case-evidence-order" value={evidenceOrder} onChange={(event) => setEvidenceOrder(event.target.value as typeof evidenceOrder)}>
            <option value="event_time">{t("investigations.case.order_by_event_time")}</option><option value="added_at">{t("investigations.case.order_by_added_time")}</option>
          </select></div>
      </div></div>
      {!visibleEvidence.length && (evidenceBatch.isLoading || evidenceBatch.isError) ? null : !visibleEvidence.length
        ? <StateView state="empty" detail={t("investigations.case.no_saved_evidence_matches_the_selected_filters")}/>
        : caseView === "timeline"
          ? <DataTable columns={evidenceColumns} rows={visibleEvidence} rowKey={(row) => String(row.event_db_id)} selectedKey={selectedKey} onRowClick={(row) => setSelectedEventDbId(row.event_db_id)} caption={t("investigations.case.case_evidence")}/>
          : <div role="group" aria-label={t("investigations.case.investigation_evidence_without_causal_links")}>
            <p className="sli-ds-header__subtitle">{graphNotice}</p>
            <div className="sli-ds-header__meta">{visibleEvidence.map((evidence) => {
              const graphEvent = evidenceById.get(evidence.event_db_id);
              return <button key={evidence.event_db_id} type="button" className="sli-ds-chip" aria-pressed={evidence.event_db_id === selectedEvidence?.event_db_id} data-relation={evidence.relation_status} onClick={() => setSelectedEventDbId(evidence.event_db_id)}>
                Event {graphEvent?.event_id ?? evidence.event_db_id} · {eventSemanticText(graphEvent?.semantics?.title_code, graphEvent?.semantics?.title ?? graphEvent?.label ?? `DB ${evidence.event_db_id}`)} · {<DateTime value={graphEvent?.time_created_utc} timeZone={timeZone}/>}
              </button>;
            })}</div>
          </div>}
    </section>

    <section className="sli-ds-report__views" aria-label={t("investigations.case.selected_event")}>
      <h2>{t("investigations.case.selected_event")}</h2>
      {selectedEvidence ? <>
        {selectedEvent ? <>
          <h3>{eventSemanticText(selectedEvent.semantics?.title_code, selectedEvent.semantics?.title ?? selectedEvent.label ?? `Event DB ${selectedEvidence.event_db_id}`)}</h3>
          <p>{eventSemanticText(selectedEvent.semantics?.summary_code, selectedEvent.semantics?.summary ?? t("investigations.case.the_catalog_did_not_provide_a_semantic_description"))}</p>
          <div><EventClassificationBadge value={eventMachineRisk(selectedEvent)} origin={selectedEvent?.semantics?.classification_origin}/> <EventCardCompletenessBadge completeness={selectedEvent?.semantics?.card_completeness}/></div>
          <FactList facts={[
            { label: t("investigations.case.evidence"), value: `DB ${selectedEvidence.event_db_id} · Event ID ${selectedEvent.event_id}` },
            { label: t("investigations.case.source"), value: [selectedEvent.server, selectedEvent.channel].filter(Boolean).join(" · ") || t("investigations.case.unknown_2") },
            { label: t("investigations.case.actor"), value: selectedEvent.subject ?? t("investigations.case.could_not_be_determined") },
            { label: t("investigations.case.object"), value: selectedEvent.target ?? t("investigations.case.unknown_2") },
          ]}/>
        </> : <StateView state={selectedBatch.isLoading ? "loading" : selectedDenied ? "denied" : selectedBatch.isError ? "unavailable" : "empty"} compact detail={selectedFallback}/>}
        <div className="sli-ds-filters__actions">
          {selectedEvidenceHref ? <a className="sli-ds-button" data-variant="primary" href={selectedEvidenceHref}>{t("investigations.case.open_full_event")}</a> : <span className="sli-ds-header__subtitle">{t("investigations.case.the_selected_event_s_exact_id_was_not_provided")}</span>}
          <InvestigationMutationGate role={role} action="update_evidence_relation">
            <button className="sli-ds-button" type="button" disabled={updateRelation.isPending} onClick={() => updateRelation.mutate({ eventDbId: selectedEvidence.event_db_id, relationStatus: selectedEvidence.relation_status === "excluded" ? "confirmed" : "excluded" })}>
              {selectedEvidence.relation_status === "excluded" ? t("investigations.case.mark_as_confirmed") : t("investigations.case.exclude_from_chain")}
            </button>
          </InvestigationMutationGate>
          <button type="button" className="sli-ds-button" data-variant="ghost" onClick={() => setSelectedEventDbId(null)} aria-label={t("investigations.case.clear_event_selection")}>{t("investigations.case.clear_selection")}</button>
        </div>
      </> : <p className="sli-ds-header__subtitle">{t("investigations.case.select_evidence_in_the_timeline_or_nodes")}</p>}
      {anchorOutsidePage !== null && anchorBatch.isError ? <button type="button" className="sli-ds-button" onClick={() => void anchorBatch.refetch()}>{t("investigations.case.retry_page")}</button> : null}
      {updateRelation.isError ? <p role="alert" className="sli-ds-field__error">{t("investigations.case.evidence_status_unchanged")}</p> : null}
    </section>

    <VpnEvidence refs={item.evidence_refs} state={item.evidence_refs_state} timeZone={timeZone}/>
    <p role="status">{t("investigations.case.refs_page_scope", { shown: item.evidence_refs?.length ?? 0, total: item.evidence_refs_total ?? item.evidence_refs?.length ?? 0 })}</p>
    <div className="sli-ds-filters__actions">
      <button type="button" className="sli-ds-button" disabled={!refPages.length || detail.isFetching} onClick={() => changePage(eventPages, refPages.slice(0, -1))}>{t("investigations.case.previous_refs")}</button>
      <button type="button" className="sli-ds-button" disabled={!item.evidence_refs_next_cursor || detail.isFetching} onClick={() => changePage(eventPages, [...refPages, item.evidence_refs_next_cursor!])}>{t("investigations.case.next_refs")}</button>
    </div>

    <section className="sli-ds-report__views" aria-label={t("investigations.case.analyst_notes")}>
      <h2>{t("investigations.case.analyst_notes")}</h2>
      <InvestigationMutationGate role={role} action="add_case_note">
        <form className="sli-ds-filters" onSubmit={submitNote}>
          <div className="sli-ds-filters__fields"><div className="sli-ds-field"><label htmlFor="investigation-note">{t("investigations.case.analyst_comment")}</label>
            <textarea id="investigation-note" value={noteBody} onChange={(event) => setNoteBody(event.target.value)} placeholder={t("investigations.case.add_comment")} maxLength={4000}/></div></div>
          <div className="sli-ds-filters__actions"><button className="sli-ds-button" data-variant="primary" type="submit" disabled={!noteBody.trim() || addNote.isPending}>{addNote.isPending ? t("investigations.case.saving") : t("investigations.case.save_note")}</button></div>
        </form>
      </InvestigationMutationGate>
      {addNote.isError ? <p role="alert" className="sli-ds-field__error">{t("investigations.case.note_not_saved_the_api_rejected_the_change")}</p> : null}
      {item.notes.length ? <DataTable columns={noteColumns} rows={item.notes} rowKey={(row) => String(row.id)} caption={t("investigations.case.analyst_notes")}/> : null}
    </section>
  </section>;
}
