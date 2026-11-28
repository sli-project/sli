import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { useEffectiveAccess, useTimeZone } from "../../app/App";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { DataTable, FilterBar, ReportLayout, StateView, type FilterField, type FilterValues, type ResultState, type TableColumn } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t } from "../../i18n";
import { appliedFilters, closeStation, exactWindow, filterValues, fleetReturnHref, initialSearch, localHref, PAGE_SIZES, pageSize, paging,
  patchedSearch, requestParams, resetEvents, stationRows, WORKSTATIONS_KEY, type Station } from "./model";
import { CollectionIndicator, StationName, WorkstationWorkspace } from "./WorkstationWorkspace";
import "./workstations.css";

export const periodField = (): FilterField => ({ key: "period", label: t("workstations.workspace.event_period"), kind: "period",
  presets: ["24h", "7d", "30d", "custom"], precision: "datetime-local", step: "any" });

export function WorkstationsReport({ definition, initialSearch: providedSearch }: { definition: ReportDefinitionDto; initialSearch?: string }) {
  const [periodTarget, setPeriodTarget] = useState<HTMLDivElement | null>(null);
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const { formatDateTime } = useDateFormatters();
  const session = JSON.stringify([access?.subject.type, access?.subject.id, access?.evaluated_at_utc]);
  const preference = `sli.workstations.page-size:${access?.subject.type ?? "unknown"}:${access?.subject.id ?? "unknown"}`;
  const [search, setSearch] = useState(() => {
    const value = initialSearch(providedSearch ?? window.location.search);
    let stored: string | null = null;
    try { stored = localStorage.getItem(preference); } catch { /* Optional preference. */ }
    value.set("limit", String(pageSize(value.get("limit") ?? stored, definition.limits.max)));
    return value;
  });
  const [routeSearch, setRouteSearch] = useState(providedSearch);
  const previousScope = useRef({ session, timeZone });
  const changedSession = previousScope.current.session !== session;
  const changedScope = changedSession || previousScope.current.timeZone !== timeZone;
  const activeSearch = changedScope ? patchedSearch(search, { ...resetEvents, cursor: null,
    ...(changedSession ? { ...closeStation, selected_station: null } : {}) }) : search;
  const stationId = activeSearch.get("station");
  const list = useRef<HTMLDivElement>(null);
  const scroll = useRef(0);
  const lastStation = useRef<string | null>(stationId);
  const update = (patch: Record<string, string | null>, replace = false) => {
    const next = patchedSearch(activeSearch, patch);
    const href = `${localHref(next)}${window.location.hash}`;
    if (replace) window.history.replaceState(window.history.state, "", href);
    else window.history.pushState(window.history.state, "", href);
    setSearch(next);
  };
  useEffect(() => {
    const pop = () => setSearch(initialSearch(window.location.search));
    window.addEventListener("popstate", pop);
    return () => window.removeEventListener("popstate", pop);
  }, []);
  useEffect(() => {
    if (providedSearch !== routeSearch) { setRouteSearch(providedSearch); if (providedSearch !== undefined) setSearch(initialSearch(providedSearch)); }
  }, [providedSearch, routeSearch]);
  useEffect(() => {
    if (changedScope) {
      previousScope.current = { session, timeZone };
      update({ ...resetEvents, cursor: null, ...(changedSession ? { ...closeStation, selected_station: null } : {}) }, true);
    }
  }, [session, timeZone]);
  useEffect(() => {
    const href = `${localHref(search)}${window.location.hash}`;
    if (href !== `${window.location.pathname}${window.location.search}${window.location.hash}`) window.history.replaceState(window.history.state, "", href);
  }, [search]);

  const allowed = definition.access?.allowed !== false && access?.reports?.find(report => report.report_key === WORKSTATIONS_KEY)?.allowed !== false;
  const params = requestParams(activeSearch, timeZone, definition);
  const query = useQuery({ queryKey: [WORKSTATIONS_KEY, session, "fleet", params?.toString()],
    queryFn: () => api.reportV2Data(WORKSTATIONS_KEY, params!), enabled: allowed && !stationId && Boolean(params),
    retry: false, refetchOnWindowFocus: false, staleTime: 30_000 });
  const denied = !allowed || query.data?.access?.allowed === false || query.data?.state === "denied"
    || query.error instanceof ApiResponseError && [401, 403].includes(query.error.status);
  const result = !denied && !query.error && !query.isFetching ? query.data : undefined;
  let rows: Station[] = [], invalid = false;
  try { rows = result ? stationRows(result.items) : []; } catch { invalid = true; }
  const state: ResultState = denied ? "denied" : query.error || invalid || result?.state === "error" ? "error"
    : !params ? "empty" : query.isPending || query.isFetching ? "loading" : result?.state ?? "loading";
  useEffect(() => {
    if (lastStation.current && !stationId && list.current) {
      const viewport = list.current.querySelector<HTMLElement>(".sli-ds-table__scroll");
      if (viewport) viewport.scrollTop = scroll.current;
    }
    if (!stationId && state !== "loading") lastStation.current = null;
  }, [stationId, state]);

  const values = useMemo(() => filterValues(activeSearch, timeZone), [activeSearch.toString(), timeZone]);
  const windowBounds = exactWindow(activeSearch, timeZone);
  const apply = (draft: FilterValues) => update({ ...appliedFilters(draft, activeSearch, timeZone), cursor: null, ...closeStation, selected_station: null });
  const size = pageSize(activeSearch.get("limit"), definition.limits.max);
  const sizes = PAGE_SIZES.filter(value => value <= definition.limits.max);
  const selectSize = (value: number) => {
    try { localStorage.setItem(preference, String(value)); } catch { /* Optional preference. */ }
    update({ limit: String(value), cursor: null, ...closeStation, selected_station: null });
  };
  const open = (row: Station) => {
    scroll.current = list.current?.querySelector<HTMLElement>(".sli-ds-table__scroll")?.scrollTop ?? 0;
    lastStation.current = row.station_id;
    const back = localHref(patchedSearch(activeSearch, { ...closeStation, selected_station: row.station_id }));
    update({ station: row.station_id, selected_station: row.station_id, station_tab: "important", program: null, station_return: back, ...resetEvents });
  };
  const columns: TableColumn<Station>[] = [
    { key: "station", label: t("workstations.overview.station"), width: "32%", minWidth: "20rem", render: row => <span className="sli-workstations__station-cell">{row.agent_key && <CollectionIndicator station={row}/>}<a className="sli-ds-table__link" title={row.host_name ?? row.display_name ?? undefined}
      href={localHref(patchedSearch(activeSearch, { station: row.station_id, selected_station: row.station_id, station_tab: "important", program: null,
        station_return: localHref(patchedSearch(activeSearch, { ...closeStation, selected_station: row.station_id })), ...resetEvents }))}
      onClick={event => { event.stopPropagation(); if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return; event.preventDefault(); open(row); }}><StationName station={row}/></a></span> },
    { key: "os", label: t("workstations.overview.os"), render: row => <span className="sli-workstations__cell"><span>{row.operating_system ?? "—"}</span>
      {row.operating_system_version ? <small>{row.operating_system_version}</small> : null}</span>, hiddenByDefault: false },
    { key: "last_logon_utc", label: t("reports.v2.ad.computers.v6.columns.last_logon_utc.label"), kind: "datetime",
      render: row => <span>{row.last_logon_utc ? formatDateTime(row.last_logon_utc) : "—"}</span> },
    { key: "agent_version", label: t("workstations.overview.agent"), render: row => <span>{row.agent_version ?? "—"}</span> },
  ];
  const page = paging(result?.collections?.paging);
  const refresh = () => {
    const current = filterValues(activeSearch, timeZone);
    const patch = appliedFilters(current, activeSearch, timeZone);
    const next = patchedSearch(activeSearch, { ...patch, cursor: null });
    if (next.toString() === activeSearch.toString()) void query.refetch();
    else update({ ...patch, cursor: null });
  };
  if (stationId && allowed) return <WorkstationWorkspace key={`${session}:${stationId}`} definition={definition} stationId={stationId}
    search={activeSearch} session={session} timeZone={timeZone} update={update} onBack={() => {
      const href = fleetReturnHref(activeSearch);
      window.history.pushState(window.history.state, "", href);
      setSearch(new URL(href, window.location.origin).searchParams);
    }}/>;

  const emptyMessage = !params ? "workstations.workspace.invalid_period"
    : activeSearch.get("cursor") ? "workstations.workspace.fleet_empty_page"
    : params.has("search") || params.has("domain") || params.has("source_instance_id") || values.collection && values.collection !== "all"
      ? "workstations.workspace.fleet_empty_filtered"
    : "workstations.workspace.fleet_empty";
  return <div className="sli-workstations"><ReportLayout title={t("workstations.overview.title")} state={state} metrics={<></>}
    periodPicker={!denied ? <div ref={setPeriodTarget}/> : undefined}
    meta={windowBounds && !denied ? <span>{t("workstations.workspace.event_period")}: {formatDateTime(windowBounds.from)} — {formatDateTime(windowBounds.to)}</span> : null}
    actions={!denied ? <button type="button" className="sli-ds-button" disabled={query.isFetching} onClick={refresh}>{t("workstations.workspace.refresh")}</button> : null}
    filters={!denied ? <FilterBar periodTarget={periodTarget} align="start" layout="grid" primaryKeys={["search", "collection", "period"]}
      fields={[{ key: "search", label: t("workstations.workspace.search"), kind: "text", placeholder: t("workstations.workspace.search_placeholder") },
        { key: "collection", label: t("workstations.workspace.collection"), kind: "select", options: [
          { value: "all", label: t("filters.any") }, { value: "enabled", label: t("workstations.workspace.collection_enabled") },
          { value: "disabled", label: t("workstations.workspace.collection_disabled") }, { value: "unbound", label: t("workstations.workspace.collection_unbound") },
        ] }, periodField()]} values={values} defaults={{ search: "", collection: "all", period: { preset: "7d" } }} onApply={apply}/> : null}
    stateView={state === "denied" ? <ReportDenied reportKey={WORKSTATIONS_KEY}/>
      : state === "partial" || state === "stale" || state === "processing" ? <></>
      : state === "empty" || state === "not_collected" ? <p className="sli-workstations__local-state" role="status">{t(emptyMessage)}</p>
      : <StateView state={state} onRetry={() => activeSearch.get("cursor") ? update({ cursor: null }) : void query.refetch()}/> }>
    {result && !invalid ? <div ref={list} className="sli-workstations__fleet"><DataTable caption={t("workstations.overview.stations")} columns={columns} rows={rows}
      rowKey={row => row.station_id} compact density="compact" onRowClick={open} selectedKey={activeSearch.get("selected_station")}
      total={result.filtered_count} pageSize={{ value: size, options: sizes, onChange: selectSize }}
      emptyContent={<p>{t(emptyMessage)}</p>}
      pagination={{ start: page.start, busy: query.isFetching,
        onPrevious: page.hasPrevious ? () => update({ cursor: page.previousCursor, selected_station: null }) : undefined,
        onNext: result.has_more && result.next_cursor ? () => update({ cursor: result.next_cursor, selected_station: null }) : undefined }}/></div> : null}
  </ReportLayout></div>;
}
