import { useEffect, useState, useSyncExternalStore } from "react";
import { useInfiniteQuery, useQueries } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { DataTable, Icon, ReportLayout, SeverityBadge, TabList, Tabs, type PeriodPreset, type PeriodValue, type TableColumn } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { formatNumber, EMPTY_VALUE } from "../../shared/format";
import { useTimeZone } from "../../shared/time-zone";
import { preserveNavigationView } from "../navigation";
import { tableColumns } from "./DetailSection";
import { withReturnTo } from "./legacy";
import { ReportDenied } from "./ReportDenied";
import { apiParams, searchFromValues, valuesFromSearch, valuesReady, reportHref } from "./state";

type Row = Record<string, unknown>;
const tabs = ["controls", "parameter_changes", "spn_collisions", "semantic", "changes", "privileged_changes"] as const;
const areas = ["password_policy", "domain_controller", "domain", "replication_link", "domain_trust", "other"] as const;
const results = ["all", "failed", "passed"] as const;
type ParameterFilters = { result: (typeof results)[number]; query: string; area: string };
const copy = (key: string, params?: Record<string, string | number>) => t(`reports.ad.state.${key}` as MessageKey, params);
const id = (row: Row) => String(row.row_id ?? row.id ?? "");
const area = (row: Row) => areas.find((value) => value === row.entity_type) ?? "other";
const observed = (row: Row) => row.qualification === "failed" || row.qualification === "passed"
  || (row.actual_value != null && !["", "—", "unknown", "unavailable", "timeout", "not_collected", "not_evaluated", "partial"].includes(String(row.actual_value).toLowerCase()));
const outcome = (row: Row) => row.qualification === "failed" ? copy("deviation") : row.qualification === "passed" ? copy("passed") : EMPTY_VALUE;
const label = (row: Row) => String(row.label ?? EMPTY_VALUE);
const objectName = (row: Row) => String((area(row) === "password_policy" ? row.domain_name : row.entity_name) ?? EMPTY_VALUE).slice(0, 512);
const source = (row: Row) => row.authority === "collector_diagnostic" && area(row) === "domain_controller" ? copy("diagnostics")
  : row.source_section === "domain_health" && area(row) === "replication_link" ? copy("replication")
  : row.source_section === "domain_posture" || row.source_section === "domain_health" ? "AD" : EMPTY_VALUE;
const inApp = (path: string) => withReturnTo(path, `${window.location.pathname}${window.location.search}`);

function entityLink(name: string, entity: unknown) {
  return /^[1-9]\d*$/.test(String(entity)) ? <a href={inApp(`/app/entities/${encodeURIComponent(String(entity))}`)} onClick={(event) => event.stopPropagation()}>{name}</a> : name;
}

function objectLink(row: Row) {
  return entityLink(objectName(row), area(row) === "password_policy" ? row.domain_entity_id : row.entity_id);
}

function problemLink(row: Row) {
  return /^[1-9]\d*$/.test(String(row.finding_id))
    ? <a href={reportHref("security.problems", { id: String(row.finding_id), domain: String(row.domain_id ?? "") })}>{copy("open_problem")}</a> : null;
}

function Failure({ subject, retry }: { subject: string; retry: () => void }) {
  return <div role="alert">{copy("load_failed", { subject })}{" "}<button type="button" className="sli-ds-button" onClick={retry}>{t("state.retry")}</button></div>;
}

function ParameterHistory({ row, reportKey, params }: { row: Row; reportKey: string; params: string }) {
  const history = useInfiniteQuery({ queryKey: ["report-v2", reportKey, "history", id(row), params, row.observed_at_utc],
    initialPageParam: null as string | null,
    getNextPageParam: (last: ReportResultDto) => last.has_more ? last.next_cursor : null,
    queryFn: ({ pageParam }) => {
      const query = new URLSearchParams(params);
      if (pageParam) query.set("cursor", pageParam);
      return api.reportV2Detail(reportKey, id(row), query);
    }, retry: false, staleTime: 60_000, refetchOnWindowFocus: false });
  const items = history.data?.pages.flatMap((page) => page.items) ?? [];
  const title = copy("history_title", { parameter: label(row), object: objectName(row) });
  const columns: TableColumn<Row>[] = [
    { key: "observed_at_utc", label: copy("since"), kind: "datetime", width: "var(--sli-field-min-width)" },
    { key: "actual_text", label: copy("value"), width: "var(--sli-field-max-width)", render: (item) => item === items[0] ? <strong>{valueText(item, row)}</strong> : valueText(item, row) },
    { key: "source", label: copy("source"), render: () => source(row) },
  ];
  const host = area(row) === "domain_controller" && typeof row.object_context === "object" && row.object_context !== null
    ? (row.object_context as Row).dns_host_name : undefined;
  return <section className="sli-ds-table__detail">
    <h3>{title}</h3>
    {history.isError && !items.length || ["error", "denied"].includes(history.data?.pages[0]?.state ?? "") ? <Failure subject={copy("history")} retry={() => void history.refetch()}/> :
      <div aria-busy={history.isLoading || undefined}><DataTable caption={title} columns={columns} rows={items}
        rowKey={(item) => String(item.row_id ?? item.observed_at_utc)} stickyHeader={false} showFooter={Boolean(history.hasNextPage)} hasMore={history.hasNextPage}
        loadingMore={history.isFetchingNextPage} onLoadMore={() => void history.fetchNextPage()} emptyContent={EMPTY_VALUE}/></div>}
    {typeof host === "string" && host ? <a href={inApp(reportHref("events.journal", { server: host.slice(0, 256), domain: String(row.domain_id ?? "") }))}>{copy("object_events")}</a> : null}
  </section>;
}

function valueText(item: Row, parameter = item): string {
  const value = item.actual_value;
  const number = typeof value === "number" ? value : typeof value === "string" && /^\d+$/.test(value) ? Number(value) : null;
  switch (parameter.control_id) {
    case "dc.advertising": if (value === "passed") return copy("advertised"); break;
    case "dc.connectivity": if (value === "passed") return copy("responding"); break;
    case "dc.services": if (value === "passed" || value === "failed") return copy(value === "passed" ? "running" : "service_check_failed"); break;
    case "dc.sysvol": case "dc.netlogon": if (value === "passed" || value === "failed") return copy(value === "passed" ? "accessible" : "share_check_failed"); break;
    case "password.minimum_length": return number === null ? EMPTY_VALUE : copy("characters", { count: formatNumber(number) });
    case "password.history_length": return number === null ? EMPTY_VALUE : copy("passwords", { count: formatNumber(number) });
    case "password.lockout_threshold": return number === 0 ? copy("disabled") : number === null ? EMPTY_VALUE : copy("attempts", { count: formatNumber(number) });
    case "password.minimum_age": case "password.maximum_age": case "password.lockout_duration": case "password.lockout_observation_window": {
      const duration = /^(?:(\d+)\.)?(\d{2}):(\d{2}):(\d{2})$/.exec(String(value));
      if (!duration) break;
      const minutes = Number(duration[1] ?? 0) * 1440 + Number(duration[2]) * 60 + Number(duration[3]) + Number(duration[4]) / 60;
      if (minutes === 0 && parameter.control_id === "password.maximum_age") return copy("never_expires");
      if (minutes === 0 && parameter.control_id === "password.lockout_duration") return copy("manual_unlock");
      return minutes % 1440 === 0 && parameter.control_id.toString().endsWith("age") ? copy("days", { count: formatNumber(minutes / 1440) }) : copy("minutes", { count: formatNumber(minutes) });
    }
    case "password.properties": return number === null ? EMPTY_VALUE : copy(number % 2 === 1 ? "enabled" : "disabled");
    case "domain.functional_level": case "forest.functional_level": {
      const versions: Record<string, string> = { "0": "2000", "1": "2003", "2": "2003", "3": "2008", "4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016", "10": "2025" };
      if (Object.hasOwn(versions, String(value))) return `Windows Server ${versions[String(value)]}`;
    }
  }
  if (value === "passed" || value === "failed") return copy(value === "passed" ? "check_passed" : "check_failed");
  return observed(item) || parameter !== item ? String(item.actual_text ?? EMPTY_VALUE).slice(0, 512) : EMPTY_VALUE;
}

const wideQuery = "(min-width: 2200px)";
function subscribeWide(listener: () => void) {
  const media = window.matchMedia?.(wideQuery);
  media?.addEventListener("change", listener);
  return () => media?.removeEventListener("change", listener);
}

function Parameters({ rows, reportKey, params, initialOpen, filters, setFilters, wide }: { rows: Row[]; reportKey: string; params: string; initialOpen?: string; wide: boolean;
  filters: ParameterFilters; setFilters: (filters: ParameterFilters) => void }) {
  const { result, query, area: filterArea } = filters;
  const [collapsed, setCollapsed] = useState<string[]>([]);
  const [expanded, setExpanded] = useState<string[]>(initialOpen ? [initialOpen] : []);
  const search = query.trim().toLocaleLowerCase();
  const toggle = (key: string, update: (fn: (current: string[]) => string[]) => void) => update((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key]);
  const groupRows = (key: string) => rows.filter((row) => area(row) === key);
  const count = (items: Row[], status: string) => status === "all" ? items.length : items.filter((row) => row.qualification === status).length;
  const filtered = areas.flatMap((key) => groupRows(key).sort((a, b) => Number(b.qualification === "failed") - Number(a.qualification === "failed")))
    .filter((row) => (!filterArea || area(row) === filterArea) && (result === "all" || row.qualification === result)
      && (!search || [label(row), objectName(row), valueText(row)].some((value) => value.toLocaleLowerCase().includes(search))));
  const columns: TableColumn<Row>[] = [
    { key: "label", label: copy("parameter"), render: (row) => <button type="button" className="sli-ds-table__disclosure" aria-expanded={expanded.includes(id(row))}
      onClick={(event) => { event.stopPropagation(); toggle(id(row), setExpanded); }}><Icon name="chevron"/>{label(row)}</button> },
    { key: "object", label: copy("object"), render: objectLink },
    { key: "actual", label: copy("actual"), render: (row) => row.qualification === "failed" ? <strong>{valueText(row)}</strong> : valueText(row) },
    { key: "expected", label: copy("expected"), render: (row) => row.authority === "not_defined" ? EMPTY_VALUE : String(row.expected_condition ?? EMPTY_VALUE) },
    { key: "result", label: copy("result"), render: (row) => row.qualification === "failed" ? <strong>{outcome(row)}</strong> : outcome(row) },
    { key: "observed_at_utc", label: copy("observed"), kind: "datetime" },
  ];
  if (wide) columns.push({ key: "previous", label: copy("previous"), render: (row) => row.previous_value == null ? EMPTY_VALUE : valueText({ actual_value: row.previous_value, actual_text: row.previous_text }, row) },
    { key: "source", label: copy("source"), render: source });
  return <>
    <div className="sli-ds-table__toolbar" role="group" aria-label={copy("result")}>
      {results.map((status) => <button key={status} type="button" className="sli-ds-chip" aria-pressed={status === result} onClick={() => setFilters({ ...filters, result: status })}>{copy(`filter.${status}`)} <strong>{formatNumber(count(rows, status))}</strong></button>)}
      <label className="sli-ds-field"><input type="search" maxLength={256} aria-label={copy("search")} placeholder={copy("search")} value={query} onChange={(event) => setFilters({ ...filters, query: event.target.value })}/></label>
      <label className="sli-ds-table__toolbar-choice">{copy("area")} <span className="sli-ds-field"><select value={filterArea} onChange={(event) => setFilters({ ...filters, area: event.target.value })}>
        <option value="">{copy("filter.all")}</option>{areas.filter((key) => groupRows(key).length).map((key) => <option key={key} value={key}>{copy(`area.${key}`)}</option>)}
      </select></span></label>
    </div>
    <DataTable caption={copy("tab.controls")} columns={columns} rows={filtered} rowKey={id} showFooter={false} emptyContent={EMPTY_VALUE}
      onRowClick={(row) => toggle(id(row), setExpanded)} rowGroup={(row) => {
        const key = area(row);
        const items = groupRows(key);
        const closed = collapsed.includes(key);
        return { key, collapsed: closed, heading: <>
          <button type="button" className="sli-ds-table__disclosure" aria-expanded={!closed} onClick={() => toggle(key, setCollapsed)}><Icon name="chevron"/><strong>{copy(`area.${key}`)}</strong></button>
          <span className="sli-ds-table__group-count">{copy("group_count", { failed: formatNumber(count(items, "failed")), total: formatNumber(items.length) })}</span>
        </> };
      }} rowDetail={(row) => expanded.includes(id(row)) ? <ParameterHistory row={row} reportKey={reportKey} params={params}/> : null}/>
  </>;
}

function collisions(result?: ReportResultDto) {
  const grouped = new Map<string, Row[]>();
  for (const row of result?.collections?.spn_collisions ?? []) {
    if (Number(row.owner_count) < 2) continue;
    const key = JSON.stringify([row.domain_id, row.run_id, row.normalized_spn ?? row.spn]);
    grouped.set(key, [...(grouped.get(key) ?? []), row]);
  }
  return [...grouped].map(([row_id, owners]) => ({ ...owners[0], row_id, owners }));
}

export function AdStateReport({ definition, initialSearch }: { definition: ReportDefinitionDto; initialSearch?: string }) {
  const { timeZone } = useTimeZone();
  const wide = useSyncExternalStore(subscribeWide, () => window.matchMedia?.(wideQuery)?.matches ?? false, () => false);
  const [values, setValues] = useState(() => valuesFromSearch(definition, new URLSearchParams(initialSearch ?? window.location.search)));
  const [filters, setFilters] = useState<ParameterFilters>(() => ({
    result: values.qualification === "failed" || values.qualification === "passed" ? values.qualification : values.view === "risks" ? "failed" : "all",
    query: typeof values.q === "string" ? values.q : "",
    area: areas.find((area) => area === values.entity_type) ?? "",
  }));
  const views = tabs.flatMap((key) => definition.views.filter((view) => view.key === key));
  const [selected, select] = useState(() => new URLSearchParams(initialSearch ?? window.location.search).get("tab") ?? "controls");
  const active = views.find((view) => view.key === selected) ?? views[0];
  const ready = valuesReady(definition, values, active.key);
  const queryParams = (tab: string) => {
    const params = apiParams(definition, values, { timeZone, view: tab });
    params.set("tab", tab);
    if (tab === "controls") {
      if (wide) params.set("include_previous", "true");
      if (["passed", "failed"].includes(String(values.qualification))) params.delete("qualification");
      if (areas.some((area) => area === values.entity_type)) params.delete("entity_type");
      params.delete("q");
      if (values.view === "risks") params.delete("view");
    } else for (const name of ["row_id", "view", "qualification", "entity_type", "q"]) params.delete(name);
    return params;
  };
  const simpleViews = views.filter((view) => view.key !== "parameter_changes");
  const queries = useQueries({ queries: simpleViews.map((view) => {
    const params = queryParams(view.key).toString();
    return { queryKey: ["report-v2", "data", definition.key, params], queryFn: () => api.reportV2Data(definition.key, new URLSearchParams(params)),
      enabled: ready && view.access?.allowed !== false && (!["changes", "privileged_changes"].includes(view.key) || active.key === view.key), retry: false, staleTime: 60_000, refetchOnWindowFocus: false };
  }) });
  const changesParams = queryParams("parameter_changes").toString();
  const changesView = views.find((view) => view.key === "parameter_changes");
  const changes = useInfiniteQuery({ queryKey: ["report-v2", "data", definition.key, changesParams],
    enabled: ready && Boolean(changesView) && changesView?.access?.allowed !== false,
    initialPageParam: null as { cursor: string; from: string; to: string } | null,
    getNextPageParam: (last: ReportResultDto) => last.has_more && last.next_cursor && last.window.from_utc && last.window.to_utc_exclusive
      ? { cursor: last.next_cursor, from: last.window.from_utc, to: last.window.to_utc_exclusive } : null,
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams(changesParams);
      if (pageParam) {
        params.set("cursor", pageParam.cursor);
        params.set("period", "custom");
        params.set("from", pageParam.from);
        params.set("to", pageParam.to);
      }
      return api.reportV2Data(definition.key, params);
    }, retry: false, staleTime: 60_000, refetchOnWindowFocus: false,
  });
  const byTab: Record<string, Pick<(typeof queries)[number], "data" | "isError" | "isLoading" | "isFetching" | "error" | "dataUpdatedAt"> & { refetch: () => Promise<unknown> }> =
    Object.fromEntries(simpleViews.map((view, i) => [view.key, queries[i]]));
  byTab.parameter_changes = { ...changes, data: changes.data?.pages[0] };
  const current = byTab[active.key];
  const controls = byTab.controls?.data?.items.filter(observed) ?? [];
  const spns = collisions(byTab.spn_collisions?.data);
  const countFor = (key: string) => {
    const data = byTab[key]?.data;
    if (!data || ["error", "denied", "unavailable", "not_collected", "processing"].includes(data.state)) return undefined;
    if (key === "spn_collisions" && spns.length === 0 && data.state !== "ok" && data.state !== "empty") return undefined;
    if (key === "controls") return controls.length;
    if (key === "spn_collisions") return spns.length;
    if (key === "parameter_changes") return data.filtered_count ?? data.collections?.[key]?.length;
    return data.collections?.[key]?.length;
  };
  const displayKey = ["privileged_changes", "changes"].includes(active.key) ? "parameter_changes" : active.key;
  const displayViews = views.filter((view) => !["changes", "privileged_changes"].includes(view.key) && view.access?.allowed !== false);
  const title = copy(`tab.${displayKey}`);
  const denied = active.access?.allowed === false || current.data?.state === "denied" || current.error instanceof ApiResponseError && [401, 403].includes(current.error.status);
  const failed = current.isError || current.data?.state === "error";
  const period = definition.params.find((item) => item.kind === "period");
  const changeWindow = byTab.parameter_changes?.data?.window;
  const end = changeWindow?.to_utc_exclusive ?? changeWindow?.to_utc;
  const params = queryParams(active.key);
  const detailParams = queryParams("controls");
  for (const key of ["row_id", "view", "qualification", "entity_type", "q", "tab", "period", "from", "to", "include_previous"]) detailParams.delete(key);
  const domain = String(values.domain ?? values.domain_id ?? "") || undefined;
  const exportParams = new URLSearchParams(params);
  exportParams.delete("limit");
  exportParams.delete("include_previous");
  if (active.key === "controls") {
    if (filters.result !== "all") exportParams.set("qualification", filters.result);
    if (filters.query.trim()) exportParams.set("q", filters.query.trim());
    if (filters.area && filters.area !== "other") exportParams.set("entity_type", filters.area);
  }
  useEffect(() => {
    const search = searchFromValues(definition, { ...values,
      view: values.view === "risks" ? undefined : values.view,
      qualification: filters.result === "all" ? undefined : filters.result,
      q: filters.query.trim() || undefined, entity_type: filters.area || undefined,
    });
    if (active.key !== "controls") search.set("tab", active.key);
    preserveNavigationView(search, window.location.search);
    const query = search.toString();
    window.history.replaceState(window.history.state, "", `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`);
  }, [active.key, definition, filters, values]);

  let rows = current.data?.collections?.[active.source ?? active.key] ?? current.data?.items ?? [];
  let columns = tableColumns(active.columns ?? [], timeZone);
  if (active.key === "spn_collisions") {
    rows = spns;
    columns = [
      { key: "spn", label: "SPN" },
      { key: "owners", label: copy("owners"), render: (row) => (row.owners as Row[]).map((owner, index) => <span key={String(owner.entity_id)}>{index > 0 ? ", " : ""}{entityLink(String(owner.entity_name ?? EMPTY_VALUE), owner.entity_id)}</span>) },
      { key: "observed_at_utc", label: copy("detected"), kind: "datetime" },
    ];
  } else if (active.key === "semantic") {
    columns = [
      { key: "severity", label: copy("severity"), render: (row) => <SeverityBadge severity={row.severity}/> },
      { key: "object", label: copy("object"), render: objectLink },
      { key: "title", label: copy("finding") },
      { key: "last_seen_utc", label: copy("time"), kind: "datetime" },
      { key: "action", label: copy("action"), render: problemLink },
    ];
  } else if (active.key === "parameter_changes") {
    rows = changes.data?.pages.flatMap((page) => page.collections?.parameter_changes ?? []) ?? [];
    const domainEntities = new Map(controls.filter((row) => row.entity_type === "domain").map((row) => [row.domain_id, row.entity_id]));
    rows = rows.map((row) => area(row) === "password_policy" ? { ...row, domain_entity_id: domainEntities.get(row.domain_id) } : row);
    columns = [
      { key: "observed_at_utc", label: copy("time"), kind: "datetime" },
      { key: "object", label: copy("object"), render: objectLink },
      { key: "label", label: copy("parameter") },
      { key: "change", label: copy("change"), render: (row) => <>{valueText({ actual_value: row.previous_value, actual_text: row.previous_text }, row)} → <strong>{valueText(row)}</strong></> },
      { key: "actor", label: copy("initiator"), render: () => copy("snapshot_comparison") },
    ];
  }
  return <Tabs items={displayViews.map((view) => {
    const count = countFor(view.key);
    return { key: view.key, label: <>{copy(`tab.${view.key}`)}{typeof count === "number" ? <> <strong>{formatNumber(count)}</strong></> : null}</> };
  })} active={displayKey} onChange={select}>
    <ReportLayout title={copy("title")} domain={domain} tabs={<TabList label={t("reports.views.tabs_aria")}/>} tabbed panel
      state={denied ? "denied" : failed ? "error" : current.isLoading ? "loading" : "ok"}
      stateView={denied ? <ReportDenied reportKey={definition.key} title={copy("title")}/> : failed ? <Failure subject={title} retry={() => void current.refetch()}/> : undefined}
      controls={denied ? undefined : { period: period ? { value: values.period as PeriodValue, presets: period.presets as PeriodPreset[],
        bounds: changeWindow?.from_utc && end ? { from: changeWindow.from_utc, to: end } : undefined,
        showBounds: true, showPrevious: false,
        onChange: (value) => setValues((current) => ({ ...current, period: value })) } : undefined,
        onRefresh: ready ? () => {
          for (const query of queries) if (query.isEnabled) void query.refetch({ cancelRefetch: false });
          if (changes.isEnabled) void changes.refetch({ cancelRefetch: false });
        } : undefined,
        refreshing: current.isFetching, updatedAt: current.data && !failed ? current.data.window.generated_at_utc ?? current.dataUpdatedAt : undefined }}
      actions={definition.export && ready && !denied && !failed ? <a className="sli-ds-button" href={`/api/v2/reports/${definition.key}/export.csv?${exportParams}`} download><Icon name="download"/>{t("reports.renderer.export_csv")}</a> : null}>
      {active.key === "controls" ? <Parameters key={detailParams.toString()} rows={controls} reportKey={definition.key} params={detailParams.toString()}
        filters={filters} setFilters={setFilters} wide={wide}
        initialOpen={typeof values.row_id === "string" ? values.row_id : undefined}/> : <>
        {["changes", "privileged_changes"].includes(active.key) ? <label className="sli-ds-field">{copy("tab.parameter_changes")}<select value={active.key} onChange={(event) => select(event.target.value)}>
          {views.filter((view) => ["parameter_changes", "changes", "privileged_changes"].includes(view.key) && view.access?.allowed !== false).map((view) => <option key={view.key} value={view.key}>{view.key === "parameter_changes" ? copy("tab.parameter_changes") : view.title}</option>)}
        </select></label> : null}
        <DataTable caption={title} columns={columns} rows={rows} rowKey={(row) => String(row.row_id ?? row.finding_id ?? row.id ?? JSON.stringify(row))}
          showFooter={active.key === "parameter_changes" && Boolean(changes.hasNextPage)} hasMore={active.key === "parameter_changes" && changes.hasNextPage}
          loadingMore={changes.isFetchingNextPage} onLoadMore={() => void changes.fetchNextPage()} total={active.key === "parameter_changes" ? countFor(active.key) : undefined}
          emptyContent={active.key === "spn_collisions" && countFor(active.key) === 0 ? copy("no_collisions") : EMPTY_VALUE}/>
      </>}
    </ReportLayout>
  </Tabs>;
}
