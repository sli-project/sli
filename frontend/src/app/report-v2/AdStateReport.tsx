import { Select } from "../../design-system/Select";
import { useEffect, useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { useInfiniteQuery, useQueries } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { DataTable, FactList, Icon, ReportLayout, SeverityBadge, StateView, TabList, Tabs, useDateFormatters, type TableColumn } from "../../design-system";
import { plural, t, type MessageKey } from "../../i18n";
import { formatNumber, EMPTY_VALUE } from "../../shared/format";
import { useTimeZone } from "../../shared/time-zone";
import { safeInvestigationReturnTo } from "../investigation-context";
import { preserveNavigationView } from "../navigation";
import { tableColumns } from "./DetailSection";
import { withReturnTo } from "./legacy";
import { ReportDenied } from "./ReportDenied";
import { apiParams, searchFromValues, valuesFromSearch, valuesReady, reportHref } from "./state";

type Row = Record<string, unknown>;
const tabs = ["controls", "spn_collisions", "semantic"] as const;
const areas = ["password_policy", "domain_controller", "domain", "replication_link", "domain_trust", "other"] as const;
const results = ["all", "failed", "passed", "unassessed"] as const;
type ParameterFilters = { result: (typeof results)[number]; query: string; area: string };
const copy = (key: string, params?: Record<string, string | number>) => t(`reports.ad.state.${key}` as MessageKey, params);
const id = (row: Row) => String(row.row_id ?? row.id ?? "");
const area = (row: Row) => areas.find((value) => value === row.entity_type) ?? "other";
const observed = (row: Row) => row.qualification === "failed" || row.qualification === "passed"
  || (row.actual_value != null && !["", "—", "unknown", "unavailable", "timeout", "not_collected", "not_evaluated", "partial"].includes(String(row.actual_value).toLowerCase()));
const group = (row: Row) => row.qualification === "failed" || row.qualification === "passed" ? row.qualification : "unassessed";
const outcome = (row: Row) => row.qualification === "failed" ? copy("deviation") : row.qualification === "passed" ? copy("passed") : copy("filter.unassessed");
const label = (row: Row) => String(row.label ?? EMPTY_VALUE);
const objectName = (row: Row) => String((area(row) === "password_policy" ? row.domain_name : row.entity_name) ?? EMPTY_VALUE).slice(0, 512);
const expected = (row: Row) => row.authority === "not_defined" ? EMPTY_VALUE : String(row.expected_condition ?? EMPTY_VALUE);
const entityId = (entity: unknown) => /^[1-9]\d*$/.test(String(entity)) ? String(entity) : null;
const source = (row: Row) => row.authority === "collector_diagnostic" && area(row) === "domain_controller" ? copy("diagnostics")
  : row.source_section === "domain_health" && area(row) === "replication_link" ? copy("replication")
  : row.source_section === "domain_posture" || row.source_section === "domain_health" ? copy("directory_source") : EMPTY_VALUE;
const inApp = (path: string) => withReturnTo(path, `${window.location.pathname}${window.location.search}`);

function entityLink(name: string, entity: unknown) {
  return entityId(entity) ? <a href={inApp(`/app/entities/${encodeURIComponent(String(entity))}`)} onClick={(event) => event.stopPropagation()}>{name}</a> : name;
}

function objectLink(row: Row) {
  return entityLink(objectName(row), area(row) === "password_policy" ? row.domain_entity_id : row.entity_id);
}

function controllerEvents(row: Row) {
  const host = area(row) === "domain_controller" && typeof row.object_context === "object" && row.object_context !== null
    ? (row.object_context as Row).dns_host_name : undefined;
  return typeof host === "string" && host ? <a href={inApp(reportHref("events.journal", { server: host.slice(0, 256), domain: String(row.domain_id ?? "") }))}>{copy("object_events")}</a> : null;
}

function problemLink(row: Row) {
  return /^[1-9]\d*$/.test(String(row.finding_id))
    ? <a href={reportHref("security.problems", { id: String(row.finding_id), domain: String(row.domain_id ?? "") })}>{copy("open_problem")}</a> : null;
}

function Failure({ subject, retry }: { subject: string; retry: () => void }) {
  return <div role="alert">{copy("load_failed", { subject })}{" "}<button type="button" className="sli-ds-button" onClick={retry}>{t("state.retry")}</button></div>;
}

const historyUnavailable = ["error", "denied", "unavailable", "not_collected", "processing"];

function ParameterHistory({ row, reportKey, params }: { row: Row; reportKey: string; params: string }) {
  const history = useInfiniteQuery({ queryKey: ["report-v2", reportKey, "history", id(row), params, row.observed_at_utc],
    initialPageParam: null as string | null,
    getNextPageParam: (last: ReportResultDto, _pages, _cursor, cursors) => last.items.length > 0 && last.has_more
      && last.next_cursor && !cursors.includes(last.next_cursor) ? last.next_cursor : null,
    queryFn: async ({ pageParam }) => {
      const query = new URLSearchParams(params);
      if (pageParam) query.set("cursor", pageParam);
      const page = await api.reportV2Detail(reportKey, id(row), query);
      if (historyUnavailable.includes(page.state) || page.state === "partial" && page.items.length === 0) throw new Error(page.state);
      return page;
    }, retry: false, staleTime: 60_000, refetchOnWindowFocus: false });
  const items = history.data?.pages.flatMap((page) => page.items) ?? [];
  const title = copy("history_title", { parameter: label(row), object: objectName(row) });
  const columns: TableColumn<Row>[] = [
    { key: "observed_at_utc", label: copy("since"), kind: "datetime", width: "var(--sli-field-min-width)" },
    { key: "actual_text", label: copy("value"), width: "var(--sli-field-max-width)", render: (item) => item === items[0] ? <strong>{valueText(item, row)}</strong> : valueText(item, row) },
  ];
  if (!history.isPending && !history.isError && !items.length) return null;
  return <section className="sli-ds-table__detail">
    <h3>{title}</h3>
    {history.isPending ? <StateView state="loading" compact skeleton="table"/>
      : history.isError && !items.length ? <Failure subject={copy("history")} retry={() => void history.refetch()}/>
      : <DataTable caption={title} columns={columns} rows={items}
        rowKey={(item) => String(item.row_id ?? item.observed_at_utc)} stickyHeader={false} showFooter={Boolean(history.hasNextPage) && !history.isFetchNextPageError}
        hasMore={history.hasNextPage && !history.isFetchNextPageError} loadingMore={history.isFetchingNextPage}
        onLoadMore={() => void history.fetchNextPage()} emptyContent={EMPTY_VALUE}/>}
    {history.isFetchNextPageError ? <Failure subject={copy("history")} retry={() => void history.fetchNextPage()}/> : null}
  </section>;
}

function quantity(unit: "characters" | "passwords" | "attempts" | "days" | "minutes", count: number) {
  const form = plural(count, { one: "one", few: "few", many: "many", other: "many" });
  return copy(`${unit}.${form}`, { count: formatNumber(count) });
}

function valueText(item: Row, parameter = item): string {
  const value = item.actual_value;
  const number = typeof value === "number" ? value : typeof value === "string" && /^\d+$/.test(value) ? Number(value) : null;
  switch (parameter.control_id) {
    case "dc.advertising": if (value === "passed") return copy("advertised"); break;
    case "dc.connectivity": if (value === "passed") return copy("responding"); break;
    case "dc.services": if (value === "passed" || value === "failed") return copy(value === "passed" ? "running" : "service_check_failed"); break;
    case "dc.sysvol": case "dc.netlogon": if (value === "passed" || value === "failed") return copy(value === "passed" ? "accessible" : "share_check_failed"); break;
    case "password.minimum_length": return number === null ? EMPTY_VALUE : quantity("characters", number);
    case "password.history_length": return number === null ? EMPTY_VALUE : quantity("passwords", number);
    case "password.lockout_threshold": return number === 0 ? copy("disabled") : number === null ? EMPTY_VALUE : quantity("attempts", number);
    case "password.minimum_age": case "password.maximum_age": case "password.lockout_duration": case "password.lockout_observation_window": {
      const duration = /^(?:(\d+)\.)?(\d{2}):(\d{2}):(\d{2})$/.exec(String(value));
      if (!duration) break;
      const minutes = Number(duration[1] ?? 0) * 1440 + Number(duration[2]) * 60 + Number(duration[3]) + Number(duration[4]) / 60;
      if (minutes === 0 && parameter.control_id === "password.maximum_age") return copy("never_expires");
      if (minutes === 0 && parameter.control_id === "password.lockout_duration") return copy("manual_unlock");
      return minutes % 1440 === 0 && parameter.control_id.toString().endsWith("age") ? quantity("days", minutes / 1440) : quantity("minutes", minutes);
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

function CheckFacts({ row }: { row: Row }) {
  const { formatCell } = useDateFormatters();
  const objectContext = row.object_context as Row | undefined;
  const context = Array.isArray(row.context) ? row.context.flatMap((item: Row) =>
    typeof item.label === "string" && typeof item.value === "string" && item.value !== EMPTY_VALUE
      ? [{ label: item.label, value: item.code === "last_replication_attempt_utc"
          ? formatCell(objectContext?.last_replication_attempt_utc, "datetime") : item.value }] : []) : [];
  return <>
    <FactList facts={[
      { label: copy("object"), value: objectLink(row) },
      { label: copy("actual"), value: valueText(row) },
      ...(expected(row) !== EMPTY_VALUE ? [{ label: copy("expected"), value: expected(row) }] : []),
      ...context,
    ]}/>
    {controllerEvents(row)}
  </>;
}

const wideQuery = "(min-width: 2200px)";
function subscribeWide(listener: () => void) {
  const media = window.matchMedia?.(wideQuery);
  media?.addEventListener("change", listener);
  return () => media?.removeEventListener("change", listener);
}

function parameterRows(rows: Row[], { query, area: filterArea }: ParameterFilters) {
  const search = query.trim().toLocaleLowerCase();
  return rows.filter((row) => (!filterArea || area(row) === filterArea)
    && (!search || [label(row), objectName(row), valueText(row)].some((value) => value.toLocaleLowerCase().includes(search))));
}

function Parameters({ rows, reportKey, params, initialOpen, filters, setFilters, wide, spn }: {
  rows: Row[]; reportKey: string; params: string; initialOpen?: string; wide: boolean;
  filters: ParameterFilters; setFilters: (filters: ParameterFilters) => void; spn?: ReactNode;
}) {
  const { result, query, area: filterArea } = filters;
  const [collapsed, setCollapsed] = useState(() => ["passed", "unassessed"].filter((key) =>
    !rows.some((row) => id(row) === initialOpen && group(row) === key)));
  const [expanded, setExpanded] = useState<string | undefined>(initialOpen);
  const open = (row: Row) => setExpanded((current) => current === id(row) ? undefined : id(row));
  const matching = parameterRows(rows, filters);
  const count = (status: string) => status === "all" ? matching.length : matching.filter((row) => group(row) === status).length;
  const visible = (["failed", "unassessed", "passed"] as const)
    .filter((status) => result === "all" || status === result)
    .flatMap((status) => matching.filter((row) => group(row) === status));

  const columns: TableColumn<Row>[] = [
    { key: "label", label: copy("parameter"), render: (row) => <button type="button" className="sli-ds-table__disclosure" aria-expanded={expanded === id(row)}
      onClick={(event) => { event.stopPropagation(); open(row); }}><Icon name="chevron"/>{label(row)}</button> },
    { key: "object", label: copy("object"), render: objectLink },
    { key: "actual", label: copy("actual"), render: (row) => valueText(row) },
    { key: "expected", label: copy("expected"), render: expected },
    { key: "result", label: copy("result"), render: (row) => row.qualification === "failed"
      ? <span style={{ color: "var(--sli-danger)" }}><span aria-hidden="true">✕ </span>{outcome(row)}</span>
      : outcome(row) },
    { key: "observed_at_utc", label: copy("observed"), kind: "datetime" },
  ];
  if (wide) columns.push({ key: "previous", label: copy("previous"), render: (row) => row.previous_value == null ? EMPTY_VALUE : valueText({ actual_value: row.previous_value, actual_text: row.previous_text }, row) },
    { key: "source", label: copy("source"), render: source });
  return <>
    <div className="sli-ds-table__toolbar" role="group" aria-label={copy("result")}>
      {results.filter((status) => status !== "unassessed" || count(status) > 0 || status === result).map((status) => <button key={status} type="button" className="sli-ds-chip" aria-pressed={status === result} onClick={() => setFilters({ ...filters, result: status })}>{copy(`filter.${status}`)} <strong>{formatNumber(count(status))}</strong></button>)}
      <label className="sli-ds-field"><input type="search" maxLength={256} aria-label={copy("search")} placeholder={copy("search")} value={query} onChange={(event) => setFilters({ ...filters, query: event.target.value })}/></label>
      <div className="sli-ds-table__toolbar-choice"><span style={{ whiteSpace: "nowrap" }}>{copy("area")}</span> <span className="sli-ds-field" style={{ minWidth: "var(--sli-field-min-width)" }}><Select label={String(copy("area")) + String("")} value={filterArea} onChange={(selectedValue) => setFilters({ ...filters, area: selectedValue })}
        options={[{ value: "", label: copy("filter.all") }, ...(areas.filter((key) => rows.some((row) => area(row) === key)).map((key) => ({ value: key, label: copy(`area.${key}`) })) ?? [])]}/></span></div>
      {spn}
    </div>
    <DataTable caption={copy("tab.controls")} columns={columns} rows={visible} rowKey={id} showFooter={false} emptyContent={EMPTY_VALUE} pageScroll wrapCells="all"
      selectedKey={expanded} onRowClick={open} rowGroup={result === "all" ? (row) => {
        const key = group(row);
        const closed = collapsed.includes(key);
        return { key, collapsed: closed, heading: <>
          <button type="button" className="sli-ds-table__disclosure" aria-expanded={!closed} onClick={() => setCollapsed((current) => current.includes(key) ? current.filter((item) => item !== key) : [...current, key])}><Icon name="chevron"/><strong>{copy(`filter.${key}`)}</strong></button>
          <span className="sli-ds-table__group-count">{formatNumber(count(key))}</span>
        </> };
      } : undefined} rowDetail={(row) => expanded === id(row) ? <div className="sli-ds-table__detail"><CheckFacts row={row}/>
        <ParameterHistory row={row} reportKey={reportKey} params={params}/></div> : null}/>
  </>;
}

function collisions(result?: ReportResultDto): Array<Row & { row_id: string; owners: Row[] }> {
  const grouped = new Map<string, Map<string, Row>>();
  for (const row of result?.collections?.spn_collisions ?? []) {
    const entity = entityId(row.entity_id);
    const spn = row.normalized_spn ?? row.spn;
    const ownerCount = Number(row.owner_count);
    if (!entity || !entityId(row.domain_id) || !row.run_id || !spn || !Number.isInteger(ownerCount) || ownerCount < 2) continue;
    const key = JSON.stringify([String(row.domain_id), row.run_id, spn]);
    const owners = grouped.get(key) ?? new Map<string, Row>();
    owners.set(entity, row);
    grouped.set(key, owners);
  }
  return [...grouped].map(([row_id, group]) => {
    const owners = [...group.values()];
    return { ...owners[0], row_id, owners };
  });
}

export function AdStateReport({ definition: sourceDefinition, initialSearch }: { definition: ReportDefinitionDto; initialSearch?: string }) {
  const { timeZone } = useTimeZone();
  const definition = useMemo(() => ({ ...sourceDefinition,
    params: sourceDefinition.params.filter((param) => param.kind !== "period"),
  }), [sourceDefinition]);
  const wide = useSyncExternalStore(subscribeWide, () => window.matchMedia?.(wideQuery)?.matches ?? false, () => false);
  const [values] = useState(() => {
    const initial = valuesFromSearch(definition, new URLSearchParams(initialSearch ?? window.location.search));
    if (initial.view === "all") initial.view = "overview";
    return initial;
  });
  const [filters, setFilters] = useState<ParameterFilters>(() => ({
    result: values.qualification === "failed" || values.qualification === "passed" ? values.qualification : values.view === "risks" ? "failed" : "all",
    query: typeof values.q === "string" ? values.q : "",
    area: areas.find((area) => area === values.entity_type) ?? "",
  }));
  const views = tabs.flatMap((key) => definition.views.filter((view) => view.key === key));
  const [selected, select] = useState(() => new URLSearchParams(initialSearch ?? window.location.search).get("tab") ?? "controls");
  const active = views.find((view) => view.key === selected) ?? views[0];
  const initialOpen = typeof values.row_id === "string" ? values.row_id : undefined;
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
  const queries = useQueries({ queries: views.map((view) => {
    const params = queryParams(view.key).toString();
    return { queryKey: ["report-v2", "data", definition.key, params], queryFn: () => api.reportV2Data(definition.key, new URLSearchParams(params)),
      enabled: ready && view.access?.allowed !== false, retry: false, staleTime: 60_000, refetchOnWindowFocus: false };
  }) });
  const byTab = Object.fromEntries(views.map((view, i) => [view.key, queries[i]]));
  const current = byTab[active.key];
  const controls = byTab.controls?.data?.items.filter((row) => observed(row) && row.control_id !== "dc.operating_system_version") ?? [];
  const spns = collisions(byTab.spn_collisions?.data);
  const countFor = (key: string) => {
    const data = byTab[key]?.data;
    if (!data || ["error", "denied", "unavailable", "not_collected", "processing"].includes(data.state)) return undefined;
    if (key === "controls") return controls.length;
    if (key === "spn_collisions") return spns.length || (data.state === "ok" || data.state === "empty" ? 0 : undefined);
    return data.collections?.[key]?.length;
  };
  const displayKey = active.key === "spn_collisions" ? "controls" : active.key;
  const displayViews = views.filter((view) => view.key !== "spn_collisions" && view.access?.allowed !== false);
  const title = copy(`tab.${active.key}`);
  const denied = active.access?.allowed === false || current.data?.state === "denied" || current.error instanceof ApiResponseError && [401, 403].includes(current.error.status);
  const failed = current.isError || current.data?.state === "error";
  const exportParams = queryParams(active.key);
  const detailParams = queryParams("controls");
  for (const key of ["row_id", "view", "qualification", "entity_type", "q", "tab", "include_previous"]) detailParams.delete(key);
  const domain = String(values.domain ?? values.domain_id ?? "") || undefined;
  exportParams.delete("limit");
  exportParams.delete("include_previous");
  if (active.key === "controls") {
    if (filters.result === "passed" || filters.result === "failed") exportParams.set("qualification", filters.result);
    if (filters.query.trim()) exportParams.set("q", filters.query.trim());
    if (filters.area && filters.area !== "other") exportParams.set("entity_type", filters.area);
  }
  useEffect(() => {
    const search = searchFromValues(definition, { ...values,
      view: values.view === "risks" ? undefined : values.view,
      qualification: filters.result === "passed" || filters.result === "failed" ? filters.result : undefined,
      q: filters.query.trim() || undefined, entity_type: filters.area || undefined,
    });
    if (active.key !== "controls") search.set("tab", active.key);
    const currentSearch = window.location.search;
    preserveNavigationView(search, currentSearch);
    const returnTo = safeInvestigationReturnTo(new URLSearchParams(currentSearch).get("return_to"), "");
    if (returnTo) search.set("return_to", returnTo);
    const query = search.toString();
    window.history.replaceState(window.history.state, "", `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`);
  }, [active.key, definition, filters, values]);

  let rows = current.data?.collections?.[active.source ?? active.key] ?? current.data?.items ?? [];
  let columns = tableColumns(active.columns ?? [], timeZone);
  if (active.key === "spn_collisions") {
    rows = spns;
    columns = [
      { key: "spn", label: "SPN", render: (row) => String(row.spn ?? EMPTY_VALUE) },
      { key: "owners", label: copy("owners"), render: (row) => (row.owners as Row[]).map((owner, index) => <span key={String(owner.entity_id)}>{index > 0 ? ", " : ""}{entityLink(String(owner.entity_name ?? EMPTY_VALUE), owner.entity_id)}</span>) },
      { key: "observed_at_utc", label: copy("detected"), kind: "datetime" },
    ];
  } else if (active.key === "semantic") {
    rows = current.data?.collections?.semantic ?? [];
    columns = [
      { key: "severity", label: copy("severity"), render: (row) => <SeverityBadge severity={row.severity}/> },
      { key: "object", label: copy("object"), render: objectLink },
      { key: "title", label: copy("finding") },
      { key: "last_seen_utc", label: copy("time"), kind: "datetime" },
      { key: "action", label: copy("action"), render: problemLink },
    ];
  }
  const resultState = current.data?.state;
  const confirmed = resultState === "ok" || resultState === "empty";
  const collectionTab = active.key === "spn_collisions" || active.key === "semantic";
  const hasCollection = confirmed || (resultState === "partial" || resultState === "stale") &&
    Array.isArray(current.data?.collections?.[active.key]);
  const emptyLine = collectionTab && rows.length === 0 && (hasCollection
    ? copy(active.key === "spn_collisions" ? "no_collisions" : "no_linked_findings") : EMPTY_VALUE);

  return <Tabs items={displayViews.map((view) => {
    const count = countFor(view.key);
    return { key: view.key, label: <>{copy(`tab.${view.key}`)}{typeof count === "number" ? <> <strong>{formatNumber(count)}</strong></> : null}</> };
  })} active={displayKey} onChange={select}>
    <ReportLayout title={copy("title")} domain={domain} tabs={<TabList label={t("reports.views.tabs_aria")}/>} tabbed panel
      state={denied ? "denied" : failed ? "error" : current.isLoading ? "loading" : "ok"}
      stateView={denied ? <ReportDenied reportKey={definition.key} title={copy("title")}/> : failed ? <Failure subject={title} retry={() => void current.refetch()}/> : undefined}
      controls={denied ? undefined : {
        onRefresh: ready ? () => {
          for (const query of queries) if (query.isEnabled) void query.refetch({ cancelRefetch: false });
        } : undefined,
        refreshing: current.isFetching,
        dataAsOf: !failed && typeof current.data?.coverage.observed_at_utc === "string" ? current.data.coverage.observed_at_utc : undefined,
      }}
      actions={definition.export && ready && !denied && !failed && (active.key !== "controls" || filters.result !== "unassessed") ? <a className="sli-ds-button" href={`/api/v2/reports/${definition.key}/export.csv?${exportParams}`} download><Icon name="download"/>{t("reports.renderer.export_csv")}</a> : null}>
      {active.key === "controls" ? <Parameters key={detailParams.toString()} rows={controls} reportKey={definition.key} params={detailParams.toString()}
        filters={filters} setFilters={setFilters} wide={wide} initialOpen={initialOpen}
        spn={(countFor("spn_collisions") ?? 0) > 0 ? <button type="button" className="sli-ds-chip" onClick={() => select("spn_collisions")}>
          {copy("tab.spn_collisions")} <strong>{formatNumber(spns.length)}</strong>
        </button> : null}/> : <>
        {active.key === "spn_collisions" ? <button type="button" className="sli-ds-button" onClick={() => select("controls")}>{copy("tab.controls")}</button> : null}
        {emptyLine ? <p role="status">{emptyLine}</p> : <DataTable caption={title} columns={columns} rows={rows} rowKey={(row) => String(row.row_id ?? row.finding_id ?? row.id ?? JSON.stringify(row))}
          showFooter={false} emptyContent={EMPTY_VALUE} pageScroll wrapCells="all"/>}
      </>}
    </ReportLayout>
  </Tabs>;
}
