import { useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportColumnDto } from "../../api/report-v2-types";
import { Button, Chart, DataTable, DetailDrawer, FactList, Icon, SeverityBadge, TabList, TabPanel, Tabs, type TableColumn } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t, type MessageKey } from "../../i18n";
import { formatDateTime as formatZonedDateTime } from "../../shared/date-time";
import { formatNumber } from "../../shared/format";
import { useEffectiveAccess } from "../App";
import { tableColumns } from "./DetailSection";
import { withReturnTo } from "./legacy";
import { ReportState } from "./ReportState";
import { computerRole } from "../../plugins/ad/ComputerChecks";
import { AgentStatus, formatAgentStatus } from "../../plugins/ad/ReportAdditions";

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
export function LogonComputerName({ row }: { row: Row }) {
  const name = text(row.display_name) ?? dash();
  const type = row.computer_type;
  const icon = type === "domain_controller" ? "shield" : type === "server" ? "database" : type === "workstation" ? "computer" : undefined;
  if (!icon) return name;
  const role = computerRole(type);
  return <span className="sli-ds-cell-with-icon">
    <span role="img" aria-label={role} title={role}><Icon name={icon}/></span>{name}
  </span>;
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

export function computerLogonsLink(row: Row, period?: URLSearchParams) {
  const domain = id(row.domain_id);
  return path("ad.computer-logons", { ...Object.fromEntries(period ?? []), ...(domain ? { domain } : {}), q: text(row.dns_host_name) ?? text(row.display_name) ?? "" });
}

function eventHref(value: unknown) {
  const event = id(value);
  return event ? withReturnTo(`/app/events/${event}`, `${window.location.pathname}${window.location.search}`) : null;
}

function matchText(value: string, query: string) {
  const match = query ? value.toLocaleLowerCase().indexOf(query.toLocaleLowerCase()) : -1;
  if (match < 0) return value;
  return <>{value.slice(0, match)}<mark>{value.slice(match, match + query.length)}</mark>{value.slice(match + query.length)}</>;
}

export function computerInventoryColumns(columns: ReportColumnDto[], timeZone: string, select: (row: Row) => void, query = ""): TableColumn<Row>[] {
  const displayed = ["display_name", "computer_type", "operating_system", "enabled", "ou_path", "last_logon_utc", "ip_addresses", "laps_state", "sli_agent"];
  const q = query.trim();
  return tableColumns(columns, timeZone)
    .filter(({ key }) => displayed.includes(key))
    .sort((a, b) => displayed.indexOf(a.key) - displayed.indexOf(b.key))
    .map((column) => {
      const overrides: Record<string, Partial<TableColumn<Row>>> = {
        display_name: { render: (row) => {
          const name = text(row.display_name) ?? dash();
          const dns = text(row.dns_host_name);
          const matchesDns = dns && q && dns.toLocaleLowerCase().includes(q.toLocaleLowerCase()) && !name.toLocaleLowerCase().includes(q.toLocaleLowerCase());
          return <><button type="button" className="sli-ds-table__link" onClick={(event) => {
            event.stopPropagation(); select(row);
          }}>{typeof row.enabled === "boolean" ? <span role="img"
            aria-label={t(row.enabled ? "reports.computers.enabled" : "reports.computers.disabled")}>{row.enabled ? "✓" : "−"} </span> : null}{matchText(name, q)}</button>
            {matchesDns && dns ? <small className="sli-ds-muted">{matchText(dns, q)}</small> : null}</>;
        } },
        computer_type: { label: t("reports.ad.computers.role"), render: (row) => computerRole(row.computer_type) },
        operating_system: { render: (row) => computerOs(row) ?? dash() },
        last_logon_utc: { label: t("reports.computers.last_logon"),
          render: (row) => computerLastLogon(row, (stamp) => formatZonedDateTime(stamp, timeZone)), sortable: false },
        ip_addresses: { label: t("reports.computers.dns"), render: (row) => matchText(addressText(row) ?? dash(), q) },
        laps_state: { label: t("reports.computers.laps"), kind: "datetime", value: (row) => record(row.laps).expiration_utc, render: undefined },
        sli_agent: { label: t("reports.computers.agent"), render: (row) => formatAgentStatus(row, timeZone) },
      };
      return { ...column, ...overrides[column.key], hiddenByDefault: column.key === "display_name" ? undefined : false };
    });
}

const computerOs = (row: Row) => typeof row.operating_system === "string" && !/^(unknown|none|null|неизвестно)$/i.test(row.operating_system)
  ? text(row.operating_system) : undefined;
function computerLastLogon(row: Row, formatDateTime: (stamp: string) => string, withSource = false) {
  const stamp = text(row.last_logon_utc) ?? text(row.ad_last_logon_utc);
  if (stamp) {
    const source = row.last_logon_source;
    const date = formatDateTime(stamp);
    return withSource && (source === "windows_event" || source === "domain_controllers" || source === "active_directory")
      ? `${date} · ${t(`reports.computers.last_logon_source.${source}`)}` : date;
  }
  return row.last_logon_state === "never" ? t("reports.v2.ad.computers.v6.params.activity.options.never") : dash();
}

function addressText(row: Row) {
  const values = record(row.dns_ip).addresses;
  return Array.isArray(values) ? values.filter((value): value is string => typeof value === "string").join(", ") || undefined : undefined;
}

function ComputerImportant({ row }: { row: Row }) {
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
  const reasons = (Array.isArray(row.reasons) ? row.reasons : []).map(record)
    .filter((reason) => !reason.code || ["unsupported_os", "unconstrained_delegation", "laps_expired", "stale_activity"].includes(String(reason.code)))
    .flatMap((reason) => text(reason.label) ?? []);
  return <>
    {reasons.length ? <ul>{reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul> : null}
    {counts && allowed ? <FactList facts={[{ label: t("reports.computers.open_problems"), value: <a href={path("security.problems", filters)}>
          {severities.some((level) => counts[level]) ? severities.filter((level) => counts[level]).map((level, index) => <span key={level}>
            {index ? " · " : ""}<SeverityBadge severity={level} label={`${level === "info" ? `● ${t("reports.computers.info")}`
              : level === "critical" ? t("reports.computers.critical") : t(`shell.severity.${level}`)} ${formatNumber(counts[level] ?? 0)}`}/>
          </span>) : "0"}
        </a> }]}/> : null}
    {problems.isError ? <ReportState state="error" subject={t("reports.computers.open_problems")} onRetry={() => void problems.refetch()}/>
      : !counts && problems.isFetching ? <ReportState state="loading"/>
      : !reasons.length && !counts ? <p>{t("reports.computers.no_review_reasons")}</p> : null}
  </>;
}

function ComputerFacts({ row }: { row: Row }) {
  const { formatDateTime } = useDateFormatters();
  const dns = record(row.dns_ip);
  const laps = record(row.laps);
  const agent = record(row.sli_agent);
  const address = addressText(row);
  return <>
    <section>
      <h3 className="sli-ds-section-title">{t("reports.computers.ad_object")}</h3>
      <FactList facts={[
        { label: t("reports.computers.account"), value: typeof row.enabled === "boolean" ? t(row.enabled ? "reports.computers.enabled" : "reports.computers.disabled") : null },
        { label: t("reports.computers.ou"), value: text(row.ou_path) },
        { label: t("reports.ad.computers.role"), value: computerRole(row.computer_type) },
        { label: t("reports.computers.os"), value: computerOs(row) },
        { label: t("reports.computers.last_logon"), value: computerLastLogon(row, formatDateTime, true) },
      ]}/>
    </section>
    {address ? <section>
      <h3 className="sli-ds-section-title">{t("reports.computers.addresses")}</h3>
      <FactList facts={[{ label: t("reports.computers.dns"), value: address },
        { label: t("reports.computers.observed"), value: formatDateTime(text(dns.observed_at_utc)) }]}/>
    </section> : null}
    {text(laps.expiration_utc) ? <section>
      <h3 className="sli-ds-section-title">{t("reports.computers.laps")}</h3>
      <FactList facts={[{ label: t("reports.computers.expiration"), value: <>{formatDateTime(text(laps.expiration_utc))}
          {laps.state === "expired" ? ` · ${t("reports.v2.ad.computers.v6.columns.laps_state.labels.expired")}` : null}</> }]}/>
    </section> : null}
    {["installed", "silent", "absent"].includes(String(agent.state)) ? <section>
      <h3 className="sli-ds-section-title">{t("reports.computers.agent")}</h3>
      <FactList facts={[
        { label: t("reports.computers.registration"), value: <AgentStatus row={row}/> },
      ]}/>
    </section> : null}
  </>;
}

function ComputerChangesLink({ entity, domain, period, timeZone }: { entity: string; domain: string; period: URLSearchParams; timeZone: string }) {
  const report = "security.events.chains";
  const filters = { ...Object.fromEntries(period), domain, entity_id: entity, changes_view: "all", repeat_mode: "collapsed" };
  const { data } = useQuery({
    queryKey: ["report-v2", "computer-domain-changes", filters, timeZone],
    queryFn: () => api.reportV2Data(report, new URLSearchParams({ ...filters, tz: timeZone, limit: "1" })),
    retry: false,
  });
  const total = data?.state === "ok" || data?.state === "empty" ? data.filtered_count : null;
  return <a className="sli-ds-button" href={path(report, filters)}>
    {total == null ? t("reports.computers.domain_changes") : t("reports.computers.domain_changes_count", { count: formatNumber(total) })} →
  </a>;
}

function Observations({ row, params, strip }: { row: Row; params: string; strip: boolean }) {
  const entity = id(row.entity_id);
  const domain = id(row.domain_id);
  const { formatDateTime } = useDateFormatters();
  const [selectedKey, selectObservation] = useState<string>();
  const query = useInfiniteQuery({
    queryKey: ["report-v2", "computer-observations", entity, domain, params],
    queryFn: ({ pageParam }) => {
      const url = new URLSearchParams(params);
      url.delete("sort");
      url.delete("direction");
      if (domain && !url.has("domain") && !url.has("domain_id")) url.set("domain", domain);
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
      <span>{formatDateTime(text(opened.observed_at_utc))} · {text(opened.user_name) ?? dash()}</span>
      <div className="sli-ds-header__actions"><a className="sli-ds-button" data-variant="primary" href={href}>{t("reports.computers.open_event")}</a></div>
    </div> : null}
  </>;
}

function StoredLogons({ computer, destination, params, timeZone }: { computer: string; destination: string; params: string; timeZone: string }) {
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
  const host = (value: string) => value.trim().replace(/\.$/, "").toLowerCase();
  const sourceOf = (row: Row) => {
    const source = text(row.source);
    const name = text(row.workstation_name) ?? source?.split(" / ")[0];
    if (name && host(name) === host(destination)) return text(row.ip_address) ?? source?.split(" / ")[1];
    return source;
  };
  const rows: StoredLogonRow[] = (page?.items ?? []).map((row) => ({
    row_id: String(row.row_id), observed_at_utc: text(row.observed_at_utc), user_name: text(row.user_name),
    logon_type: text(row.logon_type), source: sourceOf(row),
    repeat_count: Number(row.repeat_count), source_event_id: id(row.source_event_id),
  }));
  const columns: TableColumn<StoredLogonRow>[] = [
    { key: "observed_at_utc", label: t("reports.v2.ad.computer-logons.detail.columns.time.label"), render: (row) => {
      const time = formatZonedDateTime(row.observed_at_utc, timeZone, { seconds: true });
      const href = eventHref(row.source_event_id);
      return href ? <a href={href} aria-label={`${t("reports.computers.open_event")} · ${time}`}>{time}</a> : time;
    } },
    { key: "user_name", label: t("reports.v2.ad.computer-logons.detail.columns.user.label"), render: (row) => {
      return <>{row.user_name ?? dash()}{row.repeat_count > 1 ? ` ×${formatNumber(row.repeat_count)}` : null}</>;
    } },
    { key: "logon_type", label: t("reports.v2.ad.computer-logons.detail.columns.type.label"), render: (row) => {
      if (!row.logon_type) return dash();
      const key = `reports.v2.ad.computer-logons.detail.types.${row.logon_type}` as MessageKey;
      const label = t(key);
      return label === key ? row.logon_type : label;
    } },
    ...(rows.some((row) => row.source) ? [{ key: "source", label: t("reports.v2.ad.computer-logons.detail.columns.source.label") }] : []),
  ];
  return <DataTable caption={subject} columns={columns} rows={rows} rowKey={(row) => row.row_id} compact wrapCells="all"
    emptyContent={t("reports.states.empty.text")} showFooter={rows.length > 0}
    pageSize={{ value: pageSize, options: [25, 50, 100, 200], onChange: (size) => { setIndex(0); setPageSize(size); } }}
    total={page?.filtered_count}
    pagination={{ start: index * pageSize + 1, busy: query.isFetchingNextPage,
      onPrevious: index > 0 ? () => setIndex(index - 1) : undefined,
      onNext: page?.has_more ? async () => {
        if (!query.data?.pages[index + 1] && (await query.fetchNextPage()).isError) return;
        setIndex(index + 1);
      } : undefined }}/>
}

export function ComputerPanel({ row, logons, logonParams, period, onClose, timeZone }: {
  row: Row; logons: boolean; logonParams: string; period?: URLSearchParams; onClose: () => void; timeZone: string;
}) {
  const [tab, setTab] = useState("important");
  const [expanded, setExpanded] = useState(false);
  const access = useEffectiveAccess();
  const canSee = (key: string) => access?.reports.some((report) => report.allowed && report.report_key === key);
  const logonsAllowed = row.computer_type === "workstation" && Boolean(id(row.entity_id)) && canSee("ad.computer-logons");
  const entity = id(row.entity_id);
  const domain = id(row.domain_id);
  const name = text(row.display_name) ?? text(row.name) ?? dash();
  const computer = logons ? text(row.computer_key) : undefined;
  if (computer) return <DetailDrawer open inline inlineKeyboard={false} title={name} onClose={onClose}>
    <StoredLogons key={JSON.stringify([computer, logonParams])} computer={computer} destination={name} params={logonParams} timeZone={timeZone}/>
  </DetailDrawer>;
  const observations = <Observations key={JSON.stringify([entity, logonParams])} row={row} params={logonParams} strip={!logons}/>;
  const tabs = [
    { key: "important", label: "reports.computers.important" },
    { key: "facts", label: "reports.computers.details" },
    ...(logonsAllowed ? [{ key: "logons", label: "reports.computers.logons_tab" }] : []),
  ];
  const changesPeriod = new URLSearchParams(logonParams);
  changesPeriod.delete("tz");
  const footer = !logons ? <>
    {logonsAllowed ? <a href={computerLogonsLink(row, period)} className="sli-ds-button">{t("reports.computers.logons_link")}</a> : null}
    {entity && access?.capabilities.includes("objects.computers") ? <a href={`/app/entities/${entity}`} className="sli-ds-button">{t("reports.computers.open_ad")}</a> : null}
    {entity && canSee("events.explorer") ? <a href={path("events.journal", { q: text(row.dns_host_name) ?? name })} className="sli-ds-button">{t("reports.computers.journal")}</a> : null}
    {entity && domain && canSee("security.events.chains") ?
      <ComputerChangesLink entity={entity} domain={domain} period={changesPeriod} timeZone={timeZone}/> : null}
  </> : undefined;
  return <DetailDrawer open inline={!expanded} title={name} subtitle={logons ? t("reports.computers.observations") : text(row.dns_host_name)}
    onClose={expanded ? () => setExpanded(false) : onClose} footer={footer}
    inlineKeyboard={false} headerActions={!expanded ? <Button variant="ghost" aria-label={t("reports.computers.expand")} onClick={() => setExpanded(true)}>↗</Button> : undefined}>
    {logons ? observations : <Tabs items={tabs.map((item) => ({ ...item, label: t(item.label as MessageKey) }))} active={tab} onChange={setTab}>
      <TabList label={t("reports.computers.details")}/>
      <TabPanel>{tab === "important" ? <ComputerImportant row={row}/>
        : tab === "logons" ? observations
        : <ComputerFacts row={row}/>}</TabPanel>
    </Tabs>}
  </DetailDrawer>;
}
