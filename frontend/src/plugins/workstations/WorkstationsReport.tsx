import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { useEffectiveAccess, useTimeZone } from "../../app/App";
import { DataTable, DetailDrawer, FactList, FilterBar, MetricStrip, ReportLayout, StateView, Tabs, TabList, type FilterValues, type ResultState } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { countText, lastInteractiveLogin, paging, processDetails, requestParams, selection, stationRows, type Station } from "./model";

const KEY = "workstations.overview";
const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" ? value as Record<string, unknown> : {};
const text = (value: unknown) => typeof value === "string" ? value : t("workstations.overview.unknown");

function ProcessFacts({ finding }: { finding: Record<string, unknown> }) {
  const details = processDetails(finding);
  const { formatDateTime } = useDateFormatters();
  if (!details) return null;
  return <>
    <FactList facts={[
      { label: t("workstations.process.path"), value: details.path ?? t("workstations.overview.unknown") },
      { label: t("workstations.process.pid"), value: details.pid ?? t("workstations.overview.unknown") },
      { label: t("workstations.process.signature"), value: details.measurement ? t(`workstations.process.measurement_${details.measurement.status}`) : details.signature === "not_received" ? t("workstations.process.signature_not_received") : t("workstations.overview.unknown") },
    ]}/>
    {details.measurement && <>
      <FactList facts={[
        { label: t("workstations.process.measurement_at"), value: formatDateTime(details.measurement.at) },
        { label: "SHA-256", value: details.measurement.hash ?? t("workstations.overview.unknown") },
      ]}/>
      <p>{t("workstations.process.measurement_limit")}</p>
    </>}
    <p>{t("workstations.process.current_state_unknown")}</p>
  </>;
}

/** Approved workstation custom view inside the common ReportRenderer. */
export function WorkstationsReport({ definition }: { definition: ReportDefinitionDto }) {
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const { formatDateTime } = useDateFormatters();
  const session = JSON.stringify([access?.subject.type, access?.subject.id, access?.evaluated_at_utc]);
  const previousSession = useRef(session);
  const [search, setSearch] = useState(() => new URLSearchParams(window.location.search));
  const tab = search.get("tab") === "stations" ? "stations" : "checks";
  const selected = selection(search);
  const params = requestParams(search, timeZone);
  const update = (patch: Record<string, string | null>, replace = false) => {
    const next = new URLSearchParams(window.location.search);
    for (const [key, value] of Object.entries(patch)) value === null ? next.delete(key) : next.set(key, value);
    const href = `${window.location.pathname}?${next.toString()}`;
    if (replace) window.history.replaceState(window.history.state, "", href);
    else window.history.pushState(window.history.state, "", href);
    setSearch(next);
  };
  useEffect(() => {
    const pop = () => setSearch(new URLSearchParams(window.location.search));
    window.addEventListener("popstate", pop);
    return () => window.removeEventListener("popstate", pop);
  }, []);
  useEffect(() => {
    if (previousSession.current !== session) {
      previousSession.current = session;
      update({ station: null, finding: null, evidence: null, cursor: null }, true);
    }
  }, [session]);
  const data = useQuery({ queryKey: [KEY, session, "list", params.toString()],
    queryFn: () => api.reportV2Data(KEY, params), retry: false, enabled: definition.access?.allowed !== false });
  const base = new URLSearchParams(params);
  base.delete("cursor"); base.delete("check_id");
  const card = useQuery({ queryKey: [KEY, session, "card", selected.station, base.toString()],
    queryFn: () => api.reportV2Detail(KEY, selected.station!, base),
    enabled: Boolean(selected.station && data.data && !data.error), retry: false });
  const evidenceParams = new URLSearchParams(base);
  if (selected.finding) evidenceParams.set("finding_id", selected.finding);
  if (selected.evidence !== null) evidenceParams.set("evidence_index", String(selected.evidence + 1));
  const evidence = useQuery({ queryKey: [KEY, session, "evidence", selected.station, evidenceParams.toString()],
    queryFn: () => api.reportV2Detail(KEY, selected.station!, evidenceParams),
    enabled: Boolean(selected.station && selected.finding && selected.evidence !== null && card.data && !card.error), retry: false });

  const state: ResultState = definition.access?.allowed === false || data.data?.access?.allowed === false || data.error instanceof ApiResponseError && [401, 403].includes(data.error.status)
    ? "denied" : data.error ? "error" : data.isLoading ? "loading" : data.data?.state ?? "loading";
  let rows: Station[] = [];
  let invalid = false;
  try { rows = !data.error && state !== "denied" ? stationRows(data.data?.items ?? []) : []; } catch { invalid = true; }
  const cardRow = !data.error && state !== "denied" && !card.error && !card.isFetching ? card.data?.items[0] : undefined;
  const cardStation = cardRow ? stationRows([cardRow])[0] : undefined;
  const cardLogin = lastInteractiveLogin(cardStation?.last_interactive_login);
  const checks = !data.error && state !== "denied" ? data.data?.collections?.checks ?? [] : [];
  const findings = cardStation ? card.data?.collections?.findings ?? [] : [];
  const populationStatus = data.data?.coverage.population_status;
  const populationMessage = populationStatus === "inventory_pending" ? t("workstations.overview.inventoryPending")
    : populationStatus === "no_agents" ? t("workstations.overview.noAgents")
    : populationStatus === "awaiting_observations" ? t("workstations.overview.awaitingObservations")
    : t("workstations.overview.partialData");
  const name = (row: Station) => typeof row.metadata.display_name === "string" ? row.metadata.display_name : t("workstations.overview.unnamed");
  const open = (row: Station) => update({ station: row.station_id, finding: null, evidence: null });
  const page = paging(data.data?.collections?.paging);
  const table = <DataTable<Station> caption={t("workstations.overview.stations")} rows={rows} rowKey={(row) => row.station_id}
    columns={[{ key: "station", label: t("workstations.overview.station"), render: (row) => <button type="button" className="sli-ds-button" onClick={() => open(row)}>{name(row)}</button> },
      { key: "os", label: t("workstations.overview.os"), value: (row) => text(row.metadata.operating_system), mobile: false },
      { key: "ou", label: t("workstations.overview.ou"), value: (row) => text(row.metadata.ou_path), mobile: false },
      { key: "lastLogin", label: t("workstations.overview.lastLogin"), render: (row) => {
        const login = lastInteractiveLogin(row.last_interactive_login);
        return login ? <><div>{login.name ?? t("workstations.overview.unknown")}</div><div>{formatDateTime(login.at)}</div><div>{t(`workstations.overview.loginType${login.type}`)}</div></> : t("workstations.overview.unknown");
      } },
      { key: "devices7d", label: t("workstations.overview.devices7d"), mobile: false,
        value: (row) => countText(record(row.devices).devices_7d, t("workstations.overview.unknown")) },
      { key: "checks", label: t("workstations.overview.observed"), value: (row) => row.observed_checks ? `≥ ${row.observed_checks}` : t("workstations.overview.unknown") }]}
    hasMore={data.data?.has_more} total={data.data?.filtered_count} onLoadMore={() => update({ cursor: data.data?.next_cursor ?? null })}
    pagination={{ start: page.start, onPrevious: page.hasPrevious ? () => update({ cursor: page.previousCursor }) : undefined,
      onNext: data.data?.has_more ? () => update({ cursor: data.data?.next_cursor ?? null }) : undefined, busy: data.isFetching }}/>;
  const filters: FilterValues = { search: search.get("search") ?? "", ou: search.get("ou") ?? "" };
  const evidenceRow = !evidence.error && !evidence.isFetching && evidence.data?.access?.allowed !== false ? evidence.data?.items[0] : undefined;
  return <Tabs items={[{ key: "checks", label: t("workstations.overview.checks") }, { key: "stations", label: t("workstations.overview.stations") }]}
    active={tab} onChange={(value) => update({ tab: value, check_id: null, cursor: null, station: null, finding: null, evidence: null })}>
    <ReportLayout title={t("workstations.overview.title")} tabbed state={invalid ? "error" : state} busy={data.isFetching && !data.isLoading}
      metrics={!data.error && state !== "denied" && data.data ? <MetricStrip compact items={data.data.metrics.map((metric) => ({ ...metric, label: t(metric.label as MessageKey),
        value: metric.value === null || metric.quality === "unknown" ? t("workstations.overview.unknown")
          : metric.quality === "observed" ? `≥ ${metric.value}` : metric.value }))}/> : null}
      filters={<FilterBar fields={[{ key: "search", label: t("workstations.overview.search"), kind: "text" },
        { key: "ou", label: t("workstations.overview.ou"), kind: "select", options: data.data?.filter_options.ou ?? [] }]}
        values={filters} onApply={(values) => update({ search: String(values.search ?? ""), ou: String(values.ou ?? ""), cursor: null, station: null, finding: null, evidence: null })}/>}
      tabs={<TabList label={t("workstations.overview.title")}/>}
      stateView={<StateView state={invalid ? "error" : state} message={!invalid && state === "partial" ? populationMessage : undefined} onRetry={() => void data.refetch()}/>}
      drawer={<DetailDrawer open={Boolean(selected.station) && state !== "denied" && !data.error} title={cardStation ? name(cardStation) : t("workstations.overview.station")}
        onClose={() => update({ station: null, finding: null, evidence: null }, true)}>
        {card.isLoading || card.isFetching ? <StateView state="loading"/> : card.error || !cardStation ? <StateView state={card.error instanceof ApiResponseError && card.error.status === 403 ? "denied" : "error"} onRetry={() => void card.refetch()}/> : selected.evidence !== null ? <>
          <button className="sli-ds-button" onClick={() => update({ finding: null, evidence: null }, true)}>{t("workstations.overview.backToStation")}</button>
          <h3>{t("workstations.overview.evidence")}</h3>
          {evidence.isLoading || evidence.isFetching ? <StateView state="loading"/> : evidence.error ? <StateView state="error" onRetry={() => void evidence.refetch()}/> : evidenceRow ? <>
            <pre>{typeof evidenceRow.source_xml === "string" ? evidenceRow.source_xml : JSON.stringify(evidenceRow.state, null, 2)}</pre>
            <FactList facts={[{ label: t("workstations.overview.sourceHash"), value: text(evidenceRow.source_sha256) }]}/>
          </> : <p>{t("workstations.overview.noSource")}</p>}
        </> : <>
          <FactList facts={[{ label: t("workstations.overview.os"), value: text(cardStation.metadata.operating_system) },
            { label: t("workstations.overview.ou"), value: text(cardStation.metadata.ou_path) },
            { label: t("workstations.overview.devices7d"), value: countText(record(cardStation.devices).devices_7d, t("workstations.overview.unknown")) },
            { label: t("workstations.overview.lastLogin"), value: cardLogin?.name ?? t("workstations.overview.unknown") },
            ...(cardLogin ? [{ label: t("workstations.overview.loginAt"), value: formatDateTime(cardLogin.at) },
              { label: t("workstations.overview.loginType"), value: t(`workstations.overview.loginType${cardLogin.type}`) }] : [])]}/>
          {cardLogin ? <p>{t("workstations.overview.loginNotCurrent")}</p> : null}
          <h3>{t("workstations.overview.checks")}</h3>
          {findings.length ? findings.map((finding) => <section key={String(finding.id)}>
            <h4>{t(`workstations.checks.${finding.check_id}.title` as MessageKey)}</h4>
            <p>{t(`workstations.reasons.${finding.reason_code}` as MessageKey, Object.fromEntries(Object.entries(record(finding.reason_params)).filter((entry): entry is [string, string | number] => ["string", "number"].includes(typeof entry[1]))))}</p>
            <ProcessFacts finding={finding}/>
            {(Array.isArray(finding.evidence_refs) ? finding.evidence_refs : []).map((reference: unknown, index: number) => ["workstation_observation", "protection_snapshot"].includes(String(record(reference).kind))
              ? <button className="sli-ds-button" key={index} onClick={() => update({ finding: String(finding.id), evidence: String(index) })}>{t("workstations.overview.evidence")} {index + 1}</button> : null)}
          </section>) : <p>{t("workstations.overview.noFindings")}</p>}
          <details><summary>{t("workstations.overview.details")}</summary><FactList facts={[{ label: "ID", value: cardStation.station_id }, ...(cardLogin?.sid ? [{ label: "SID", value: cardLogin.sid }] : [])]}/></details>
        </>}
      </DetailDrawer>}>
      {tab === "stations" ? table : <>{checks.map((check) => <details key={String(check.check_id)} open={search.get("check_id") === check.check_id}>
        <summary onClick={(event) => { event.preventDefault(); update({ tab: "checks", check_id: search.get("check_id") === check.check_id ? null : String(check.check_id), cursor: null }); }}>
          {t(String(check.title_key) as MessageKey)} · {countText(record(check.counts).stations, t("workstations.overview.unknown"))}
        </summary>
        {record(record(check.counts).stations).relation === "unknown" ? <p>{t("workstations.overview.checkPending")}</p> : null}
        {search.get("check_id") === check.check_id ? table : null}
      </details>)}</>}
    </ReportLayout>
  </Tabs>;
}
