import { useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportColumnDto } from "../../api/report-v2-types";
import { Button, Chart, DataTable, DetailDrawer, FactList, SeverityBadge, TabList, TabPanel, Tabs, type TableColumn } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t, type MessageKey } from "../../i18n";
import { formatDateTime as formatZonedDateTime } from "../../shared/date-time";
import { formatNumber } from "../../shared/format";
import { useEffectiveAccess } from "../App";
import { tableColumns } from "./DetailSection";
import { withReturnTo } from "./legacy";
import { ReportState } from "./ReportState";
import { computerRole } from "../../plugins/ad/ComputerChecks";

type Row = Record<string, unknown>;
type ObservationRow = Row & { observationKey: string };
type StoredLogonRow = {
  row_id: string;
  observed_at_utc: string | undefined;
  user_name: string | undefined;
  logon_type: string | undefined;
  source: string | undefined;
  repeat_count: number;
  source_event_id: string | undefined;
};
const text = (value: unknown) => typeof value === "string" && value.trim() ? value : undefined;
const id = (value: unknown) => /^[1-9][0-9]*$/.test(String(value)) ? String(value) : undefined;
const record = (value: unknown) => (value && typeof value === "object" ? value : {}) as Row;
const dash = () => t("table.noValue");
const severities = ["critical", "high", "medium", "low", "info"] as const;
const path = (report: string, filters: Record<string, string>) => `/app/report/${report}?${new URLSearchParams(filters)}`;
const domainOf = (row: Row) => {
  const domain = id(row.domain_id);
  return domain ? { domain } : {} as Record<string, string>;
};

export function computerEmpty() {
  return <p role="status">{dash()}</p>;
}

export function ComputerLogonsEmpty({ state }: { state: unknown }) {
  switch (state) {
    case "not_collected": return <p role="status">{t("reports.computers.logons_not_collected")}</p>;
    case "partial": return <p role="status">{t("reports.computers.logons_partial")}</p>;
    case "available": case "empty_unverified": case "empty": case "ok":
      return <p role="status">{t("reports.computers.logons_empty")}</p>;
    default: return null;
  }
}

export function computerLogonsLink(row: Row) {
  const domain = id(row.domain_id);
  return path("ad.computer-logons", { ...(domain ? { domain_id: domain } : {}), q: text(row.dns_host_name) ?? text(row.display_name) ?? "" });
}

function eventHref(value: unknown) {
  const event = id(value);
  return event ? withReturnTo(`/app/events/${event}`, `${window.location.pathname}${window.location.search}`) : null;
}

function eventLink(row: Row) {
  const href = eventHref(row.source_event_id);
  return href ? <a href={href} onClick={(event) => event.stopPropagation()}>#{String(row.source_event_id)}</a> : dash();
}

export function computerInventoryColumns(columns: ReportColumnDto[], timeZone: string, select: (row: Row) => void): TableColumn<Row>[] {
  const displayed = ["display_name", "computer_type", "operating_system", "ou_path", "last_logon_utc", "ip_addresses", "laps_state", "sli_agent"];
  return tableColumns(columns, timeZone).filter((column) => displayed.includes(column.key)).sort((a, b) => displayed.indexOf(a.key) - displayed.indexOf(b.key))
    .map((column) => {
      const overrides: Record<string, Partial<TableColumn<Row>>> = {
        display_name: { render: (row) => <button type="button" className="sli-ds-table__link" onClick={(event) => {
          event.stopPropagation(); select(row);
        }}>{typeof row.enabled === "boolean" ? <span role="img"
          aria-label={t(row.enabled ? "reports.computers.enabled" : "reports.computers.disabled")}>{row.enabled ? "✓" : "−"} </span> : null}{text(row.display_name) ?? dash()}</button> },
        computer_type: { label: t("reports.ad.computers.role"), render: (row) => computerRole(row.computer_type) },
        operating_system: { render: (row) => computerOs(row) ?? dash() },
        last_logon_utc: { label: t("reports.computers.ad_activity"), value: adActivity, render: undefined, sortable: false },
        ip_addresses: { label: t("reports.computers.dns"), render: (row) => addressText(row) ?? dash() },
        laps_state: { label: t("reports.computers.laps"), kind: "datetime", value: (row) => record(row.laps).expiration_utc, render: undefined },
        sli_agent: { label: t("reports.computers.agent"), render: (row) => <AgentSignal row={row}/> },
      };
      return { ...column, ...overrides[column.key], hiddenByDefault: column.key === "display_name" ? undefined : false };
    });
}

const computerOs = (row: Row) => typeof row.operating_system === "string" && !/^(unknown|none|null|неизвестно)$/i.test(row.operating_system)
  ? text(row.operating_system) : undefined;
const adActivity = (row: Row) => text(Object.hasOwn(row, "ad_last_logon_utc") ? row.ad_last_logon_utc : row.last_logon_utc);

function addressText(row: Row) {
  const values = record(row.dns_ip).addresses;
  return Array.isArray(values) ? values.filter((value): value is string => typeof value === "string").join(", ") || undefined : undefined;
}

function AgentSignal({ row }: { row: Row }) {
  const { formatDateTime } = useDateFormatters();
  const agent = record(row.sli_agent);
  return agent.state === "absent" ? t("reports.computers.no_registration")
    : text(agent.last_seen_utc) ? formatDateTime(String(agent.last_seen_utc)) : dash();
}

function ComputerFacts({ row }: { row: Row }) {
  const { formatDateTime } = useDateFormatters();
  const access = useEffectiveAccess();
  const entity = id(row.entity_id);
  const domain = id(row.domain_id);
  const allowed = access?.reports.some((report) => report.allowed && ["security.problems", "security.queue"].includes(report.report_key));
  const filters = { domain: domain ?? "", entity_id: entity ?? "", population: "open" };
  const problems = useQuery({
    queryKey: ["report-v2", "computer-problems", filters],
    queryFn: () => api.reportV2Data("security.problems", new URLSearchParams({ ...filters, queue_view: "all", limit: "1" })),
    enabled: Boolean(allowed && entity && domain),
    retry: false,
  });
  const counts = problems.data?.coverage.open_by_severity;
  const usable = counts && Boolean(allowed) && !problems.isError;
  const dns = record(row.dns_ip);
  const laps = record(row.laps);
  const agent = record(row.sli_agent);
  const address = addressText(row);
  const activity = adActivity(row);
  return <>
    <section>
      <h3 className="sli-ds-section-title">{t("reports.computers.ad_object")}</h3>
      <FactList facts={[
        { label: t("reports.computers.account"), value: typeof row.enabled === "boolean" ? t(row.enabled ? "reports.computers.enabled" : "reports.computers.disabled") : null },
        { label: t("reports.computers.ou"), value: text(row.ou_path) },
        { label: t("reports.ad.computers.role"), value: computerRole(row.computer_type) },
        { label: t("reports.computers.os"), value: computerOs(row) },
        { label: t("reports.computers.ad_activity"), value: activity ? formatDateTime(activity) : null },
        ...(row.ad_last_logon_utc ? [{ label: t("reports.computers.activity_source"), value: "lastLogonTimestamp" }] : []),
        ...(usable ? [{ label: t("reports.computers.open_problems"), value: <a href={path("security.problems", filters)}>
          {severities.some((level) => counts[level]) ? severities.filter((level) => counts[level]).map((level, index) => <span key={level}>
            {index ? " · " : ""}<SeverityBadge severity={level} label={`${level === "info" ? `● ${t("reports.computers.info")}`
              : level === "critical" ? t("reports.computers.critical") : t(`shell.severity.${level}`)} ${formatNumber(counts[level] ?? 0)}`}/>
          </span>) : "0"}
        </a> }] : []),
      ]}/>
    </section>
    {address ? <section>
      <h3 className="sli-ds-section-title">{t("reports.computers.addresses")}</h3>
      <FactList facts={[{ label: t("reports.computers.dns"), value: address },
        { label: t("reports.computers.observed"), value: formatDateTime(text(dns.observed_at_utc)) }]}/>
    </section> : null}
    {text(laps.expiration_utc) ? <section>
      <h3 className="sli-ds-section-title">{t("reports.computers.laps")}</h3>
      <FactList facts={[{ label: t("reports.computers.attribute"), value: text(laps.source_attribute) },
        { label: t("reports.computers.expiration"), value: <>{formatDateTime(text(laps.expiration_utc))}
          {laps.state === "expired" ? ` · ${t("reports.v2.ad.computers.v6.columns.laps_state.labels.expired")}` : null}</> }]}/>
    </section> : null}
    {["installed", "silent", "absent"].includes(String(agent.state)) ? <section>
      <h3 className="sli-ds-section-title">{t("reports.computers.agent")}</h3>
      <FactList facts={[
        { label: t("reports.computers.registration"), value: t(agent.state === "absent" ? "reports.computers.no_registration" : "reports.computers.registered") },
        ...(agent.last_seen_utc ? [{ label: t("reports.computers.signal"), value: formatDateTime(text(agent.last_seen_utc)) }] : []),
        ...(agent.version ? [{ label: t("reports.computers.agent_version"), value: text(agent.version) }] : []),
      ]}/>
    </section> : null}
  </>;
}

function ComputerChanges({ row, columns, timeZone }: { row: Row; columns: ReportColumnDto[]; timeZone: string }) {
  const guid = text(row.object_guid);
  const params = new URLSearchParams({ ...domainOf(row), tab: "changes", object_guid: guid ?? "", limit: "50", tz: timeZone });
  const query = useInfiniteQuery({
    queryKey: ["report-v2", "computer-changes", params.toString()],
    queryFn: ({ pageParam }) => {
      const page = new URLSearchParams(params);
      if (pageParam) page.set("cursor", pageParam);
      return api.reportV2Data("ad.computers.v6", page);
    },
    enabled: Boolean(guid),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.has_more ? page.next_cursor : null,
    retry: false,
  });
  const rows = query.data?.pages.flatMap((page) => page.items) ?? [];
  const state = query.data?.pages[0]?.state;
  if (query.isLoading) return <ReportState state="loading"/>;
  if (state === "denied" || query.error instanceof ApiResponseError && query.error.status === 403) return <ReportState state="denied"/>;
  if (query.isError || state === "error") return <ReportState state="error" subject={t("reports.computers.changes")} onRetry={() => void query.refetch()}/>;
  const changeColumns = tableColumns(columns.filter((column) =>
    (column.path === "observed_at_utc" || ["change_type", "before", "after", "actor"].includes(column.key))
    && (column.key !== "actor" || rows.some((change) => change.actor))), timeZone).map((column) => column.key === "change_type" ? {
      ...column, render: (row: Row) => row.change_type === "membership_added" || row.change_type === "membership_removed"
        ? <>{t(`reports.computers.${row.change_type}`)}{row.group_name ? ` · ${String(row.group_name)}` : null}</>
        : column.render ? column.render(row) : column.value?.(row) as string ?? dash(),
    } : column.key === "actor" ? { ...column, label: t("reports.computers.initiator") } : column);
  if (rows.some((change) => change.source_event_id)) changeColumns.push({ key: "source_event_id", label: t("reports.computers.source_event"), render: eventLink });
  return rows.length ? <DataTable caption={t("reports.computers.changes")} columns={changeColumns}
    rows={rows} rowKey={(change) => String(change.row_id)} hasMore={query.hasNextPage} loadingMore={query.isFetchingNextPage} onLoadMore={() => void query.fetchNextPage()}/> : computerEmpty();
}

function Observations({ row, params, strip }: { row: Row; params: string; strip: boolean }) {
  const entity = id(row.entity_id);
  const { formatDateTime } = useDateFormatters();
  const [selectedKey, selectObservation] = useState<string>();
  const query = useInfiniteQuery({
    queryKey: ["report-v2", "computer-observations", entity, params],
    queryFn: ({ pageParam }) => {
      const url = new URLSearchParams(params);
      url.delete("sort");
      url.delete("direction");
      url.set("limit", "50");
      if (pageParam) url.set("cursor", pageParam);
      return api.reportV2Detail("ad.computer-logons", entity!, url);
    },
    enabled: Boolean(entity),
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.has_more ? page.next_cursor : null,
    retry: false,
  });
  const result = query.data?.pages[0];
  const rows = query.data?.pages.flatMap((page) => page.items) ?? [];
  const summary = result?.computer_logon_activity;
  // Older responses can omit row_id. Distinguish their duplicate observations
  // only within the current result, without using the evidence link as identity.
  const legacyCounts = new Map<string, number>();
  const observations = rows.map((observation): ObservationRow => {
    const rowId = id(observation.row_id);
    if (rowId) return { ...observation, observationKey: rowId };
    const fields = JSON.stringify([observation.observed_at_utc, observation.user_name, observation.source_event_id]);
    const occurrence = (legacyCounts.get(fields) ?? 0) + 1;
    legacyCounts.set(fields, occurrence);
    return { ...observation, observationKey: `legacy:${fields}:${occurrence}` };
  });
  const opened = observations.find((observation) => observation.observationKey === selectedKey) ?? observations[0];
  const href = eventHref(opened?.source_event_id);
  const columns: TableColumn<ObservationRow>[] = [
    { key: "observed_at_utc", label: t("reports.computers.time"), kind: "datetime" },
    ...(rows.some((observation) => observation.user_display_name) ? [{ key: "user_display_name", label: t("reports.computers.user") }] : []),
    { key: "user_name", label: t("reports.computers.account") },
    { key: "source_event_id", label: t("reports.computers.source_event"), render: eventLink },
  ];
  if (query.isLoading) return <ReportState state="loading"/>;
  if (result?.state === "denied" || query.error instanceof ApiResponseError && query.error.status === 403) return <ReportState state="denied"/>;
  if (query.isError || result?.state === "error") return <ReportState state="error" subject={t("reports.computers.logons")} onRetry={() => void query.refetch()}/>;
  return <>
    {strip && summary?.days.length ? <>
      <FactList facts={[
        { label: t("reports.computers.period_total"), value: summary.total == null ? null : formatNumber(summary.total) },
        { label: t("reports.computers.typical"), value: summary.typical == null ? null : formatNumber(summary.typical) },
      ]}/>
      <Chart title={t("reports.computers.by_day")} spec={{ kind: "bar", series: [{
        name: t("reports.computers.logons"), points: summary.days.map(({ day, count }) => ({ x: day, y: count })),
      }] }}/>
    </> : null}
    {summary?.top ? <FactList facts={[{ label: t("reports.computers.top_account"),
      value: t("reports.computers.account_count", { account: summary.top.account, count: formatNumber(summary.top.count) }) }]}/> : null}
    {observations.length ? <DataTable caption={t("reports.computers.observations")} columns={columns} rows={observations}
      rowKey={(observation) => observation.observationKey} compact
      onRowClick={(observation) => selectObservation(observation.observationKey)} selectedKey={opened?.observationKey}
      hasMore={query.hasNextPage} loadingMore={query.isFetchingNextPage}
      onLoadMore={() => void query.fetchNextPage()} showFooter={query.hasNextPage}/>
      : <ComputerLogonsEmpty state={result?.coverage.observation_state ?? result?.state}/>}
    {href && opened ? <div className="sli-ds-header__row">
      <span>{formatDateTime(text(opened.observed_at_utc))} · {text(opened.user_name) ?? dash()} · #{String(opened.source_event_id)}</span>
      <div className="sli-ds-header__actions"><a className="sli-ds-button" data-variant="primary" href={href}>{t("reports.computers.open_event")}</a></div>
    </div> : null}
  </>;
}

function StoredLogons({ computer, params, timeZone }: { computer: string; params: string; timeZone: string }) {
  const [pageSize, setPageSize] = useState(50);
  const [index, setIndex] = useState(0);
  const query = useInfiniteQuery({
    queryKey: ["report-v2", "computer-stored-logons", computer, params, pageSize],
    queryFn: ({ pageParam }) => {
      const url = new URLSearchParams(params);
      url.set("limit", String(pageSize));
      if (pageParam) url.set("cursor", pageParam);
      return api.reportV2Detail("ad.computer-logons", computer, url);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.has_more ? page.next_cursor : null,
    retry: false,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
  const page = query.data?.pages[index];
  const subject = t("reports.v2.ad.computer-logons.detail.title");
  if (query.isLoading) return <ReportState state="loading"/>;
  if (page?.state === "denied" || query.error instanceof ApiResponseError && query.error.status === 403) return <ReportState state="denied"/>;
  if (query.isError || page?.state === "error") return <ReportState state="error" subject={subject} onRetry={() => void query.refetch()}/>;
  const rows: StoredLogonRow[] = (page?.items ?? []).map((row) => ({
    row_id: String(row.row_id), observed_at_utc: text(row.observed_at_utc), user_name: text(row.user_name),
    logon_type: text(row.logon_type), source: text(row.source),
    repeat_count: Number(row.repeat_count), source_event_id: id(row.source_event_id),
  }));
  const columns: TableColumn<StoredLogonRow>[] = [
    { key: "observed_at_utc", label: t("reports.v2.ad.computer-logons.detail.columns.time.label"),
      render: (row) => formatZonedDateTime(row.observed_at_utc, timeZone, { seconds: true }) },
    { key: "user_name", label: t("reports.v2.ad.computer-logons.detail.columns.user.label"), render: (row) => {
      return <>{row.user_name ?? dash()}{row.repeat_count > 1 ? ` ×${formatNumber(row.repeat_count)}` : null}</>;
    } },
    { key: "logon_type", label: t("reports.v2.ad.computer-logons.detail.columns.type.label"), render: (row) => {
      if (!row.logon_type) return dash();
      const key = `reports.v2.ad.computer-logons.detail.types.${row.logon_type}` as MessageKey;
      const label = t(key);
      return label === key ? row.logon_type : label;
    } },
    { key: "source", label: t("reports.v2.ad.computer-logons.detail.columns.source.label") },
    { key: "source_event_id", label: t("reports.v2.ad.computer-logons.detail.columns.event.label"), render: eventLink },
  ];
  return <DataTable caption={subject} columns={columns} rows={rows} rowKey={(row) => row.row_id} compact wrapCells="all"
    emptyContent={dash()} showFooter={rows.length > 0}
    pageSize={{ value: pageSize, options: [25, 50, 100, 200], onChange: (size) => { setIndex(0); setPageSize(size); } }}
    total={page?.filtered_count}
    pagination={{ start: index * pageSize + 1, busy: query.isFetchingNextPage,
      onPrevious: index > 0 ? () => setIndex(index - 1) : undefined,
      onNext: page?.has_more ? async () => {
        if (!query.data?.pages[index + 1] && (await query.fetchNextPage()).isError) return;
        setIndex(index + 1);
      } : undefined }}/>
}

export function ComputerPanel({ row, logons, logonParams, changes, canCompare, onClose, timeZone }: {
  row: Row; logons: boolean; logonParams: string; changes: ReportColumnDto[]; canCompare: boolean; onClose: () => void; timeZone: string;
}) {
  const [tab, setTab] = useState(canCompare && row.object_guid && row.change_type ? "changes" : "facts");
  const [expanded, setExpanded] = useState(false);
  const access = useEffectiveAccess();
  const canSee = (key: string) => access?.reports.some((report) => report.allowed && report.report_key === key);
  const logonsAllowed = row.computer_type === "workstation" && Boolean(id(row.entity_id)) && canSee("ad.computer-logons");
  const entity = id(row.entity_id);
  const name = text(row.display_name) ?? text(row.name) ?? dash();
  const computer = logons ? text(row.computer_key) : undefined;
  if (computer) return <DetailDrawer open inline inlineKeyboard={false} title={name} onClose={onClose}>
    <StoredLogons key={JSON.stringify([computer, logonParams])} computer={computer} params={logonParams} timeZone={timeZone}/>
  </DetailDrawer>;
  const observations = <Observations key={JSON.stringify([entity, logonParams])} row={row} params={logonParams} strip={!logons}/>;
  const tabs = [
    { key: "facts", label: "reports.computers.details" },
    ...(canCompare && row.object_guid ? [{ key: "changes", label: "reports.computers.changes" }] : []),
    ...(logonsAllowed ? [{ key: "logons", label: "reports.computers.logons_tab" }] : []),
  ];
  const footer = !logons && tab === "facts" ? <>
    {logonsAllowed ? <a href={computerLogonsLink(row)} className="sli-ds-button">{t("reports.computers.logons_link")}</a> : null}
    {entity && access?.capabilities.includes("objects.computers") ? <a href={`/app/entities/${entity}`} className="sli-ds-button">{t("reports.computers.open_ad")}</a> : null}
    {entity && canSee("events.explorer") ? <a href={path("events.journal", { q: text(row.dns_host_name) ?? name })} className="sli-ds-button">{t("reports.computers.journal")}</a> : null}
    {tabs.some((item) => item.key === "changes") ? <Button variant="primary" onClick={() => setTab("changes")}>{t("reports.computers.compare")}</Button> : null}
  </> : undefined;
  return <DetailDrawer open inline={!expanded} title={name} subtitle={logons ? t("reports.computers.observations") : text(row.dns_host_name)}
    onClose={expanded ? () => setExpanded(false) : onClose} footer={footer}
    inlineKeyboard={false} headerActions={!expanded ? <Button variant="ghost" aria-label={t("reports.computers.expand")} onClick={() => setExpanded(true)}>↗</Button> : undefined}>
    {logons ? observations : <Tabs items={tabs.map((item) => ({ ...item, label: t(item.label as MessageKey) }))} active={tab} onChange={setTab}>
      <TabList label={t("reports.computers.details")}/>
      <TabPanel>{tab === "changes" ? <ComputerChanges row={row} columns={changes} timeZone={timeZone}/>
        : tab === "logons" ? observations
        : <ComputerFacts row={row}/>}</TabPanel>
    </Tabs>}
  </DetailDrawer>;
}
