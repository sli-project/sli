import { useEffect, useRef, useState, type ReactNode } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import {
  Button, DataTable, DetailDrawer, FactList, FilterBar, Icon, ReportLayout,
  SeverityBadge, TabList, TabPanel, Tabs, type FilterValues, type PeriodValue, type TableColumn,
} from "../../design-system";
import { t } from "../../i18n";
import { dayKey, formatClockWithOffset, formatDateTime, isValidTimeZone } from "../../shared/date-time";
import { EMPTY_VALUE, formatNumber } from "../../shared/format";
import { useTimeZone } from "../../shared/time-zone";
import { preserveNavigationView } from "../navigation";
import { CopyFactsButton } from "./DetailSection";
import { withReturnTo } from "./legacy";
import { ReportDenied } from "./ReportDenied";
import { apiParams, defaultValues, filterFields, searchFromValues, valuesFromSearch, valuesReady } from "./state";

const categories = ["all", "authentication", "accounts", "groups", "audit"] as const;
const sizes = [25, 50, 100, 200];
type JournalTextKey<T> = T extends `reports.v2.events.journal.${infer Key}` ? Key : never;
const journalText = (key: JournalTextKey<Parameters<typeof t>[0]>, params?: Record<string, string | number>) =>
  t(`reports.v2.events.journal.${key}`, params);
type Pivot = "account" | "address" | "computer";
type JournalRow = {
  key: string;
  id?: string;
  code: string;
  title: string;
  time: string;
  first: string;
  last: string;
  count: number;
  expandable: boolean;
  account: string;
  initiator: string;
  computer: string;
  address: string;
  result: string;
  channel: string;
  logonType: string;
  findingId: string;
  severity: string;
};

function decode(row: Record<string, unknown>): JournalRow {
  const value = (key: string) => ["string", "number"].includes(typeof row[key]) && !["-", "—"].includes(String(row[key]).trim()) ? String(row[key]).trim() : "";
  const id = value("id");
  const messages = row.presentation_messages as Record<string, { code?: string }> | undefined;
  const account = value("target") || value("actor") ||
    (messages?.participant?.code === "events.participant_unknown" ? "" : value("participant"));
  return {
    key: id || `${value("day")}:${value("summary_key") || [value("time_created_utc"), value("event_id"), account, value("journal_computer")].join(":")}`,
    id: /^[1-9][0-9]*$/.test(id) ? id : undefined,
    code: value("event_id"), title: messages?.title_text?.code === "events.unknown_type" ? "" : value("title_text"),
    time: value("time_created_utc"),
    first: value("first_seen_utc"), last: value("last_seen_utc"),
    count: typeof row.event_count === "number" ? row.event_count : 1,
    expandable: row.journal_expandable === true,
    account, initiator: value("on_behalf"),
    computer: value("journal_computer"), address: value("ip_address"), result: value("journal_result"),
    channel: value("channel"), logonType: value("logon_type"),
    findingId: /^[1-9][0-9]*$/.test(value("journal_finding_id")) ? value("journal_finding_id") : "",
    severity: value("journal_severity"),
  };
}

function pageWindow(result?: ReportResultDto) {
  const from = result?.window.from_utc;
  const to = result?.window.to_utc_exclusive;
  return from && to ? { from, to } : undefined;
}

function followup(params: URLSearchParams, window?: { from: string; to: string }, cursor?: string | null) {
  const next = new URLSearchParams(params);
  if (window) {
    next.set("period", "custom");
    next.set("from", window.from);
    next.set("to", window.to);
  }
  if (cursor) next.set("cursor", cursor);
  return next;
}

function Result({ value }: { value: string }) {
  return value === "success" || value === "failure"
    ? <span className="sli-ds-result" data-result={value}>{journalText(`result.${value}`)}</span>
    : <>{EMPTY_VALUE}</>;
}

function eventTitle(row: JournalRow) {
  return row.count > 1 ? <>{row.title || EMPTY_VALUE} <strong>×{formatNumber(row.count)}</strong></> : row.title || EMPTY_VALUE;
}

function eventTime(row: JournalRow, zone: string, details = false) {
  const format = (value: string, dates: boolean) => {
    if (!value || !Number.isFinite(Date.parse(value))) return EMPTY_VALUE;
    if (dates || (zone !== "browser" && !isValidTimeZone(zone))) return formatDateTime(value, zone, { seconds: true, withYear: details });
    return formatClockWithOffset(new Date(value), zone, true).time;
  };
  if (row.count > 1 && row.first && row.last && row.first !== row.last) {
    const dates = details || dayKey(row.first, zone) !== dayKey(row.last, zone);
    return `${format(row.first, dates)} – ${format(row.last, dates)}`;
  }
  return format(row.last || row.time, details);
}

function pivotLink(value: string, type: Pivot, href: (type: Pivot, value: string) => string, onPivot: (type: Pivot, value: string) => void, label = value) {
  return value ? <a href={href(type, value)} onClick={(event) => {
    event.stopPropagation();
    if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    onPivot(type, value);
  }}>{label}</a> : EMPTY_VALUE;
}

function RepeatRows({ params, row, columns, onSelect, member }: {
  params: URLSearchParams; row: JournalRow; columns: TableColumn<JournalRow>[]; onSelect: (row: JournalRow) => void; member?: string;
}) {
  const [active, setActive] = useState<string>();
  const [page, setPage] = useState(0);
  const input = new URLSearchParams(params);
  input.set("expand", row.id!);
  if (member) input.set("member", member);
  input.set("limit", "25");
  const repeats = useInfiniteQuery({
    queryKey: ["journal", "repeats", input.toString()],
    initialPageParam: null as string | null,
    queryFn: ({ pageParam }) => api.reportV2Data("events.journal", followup(input, undefined, pageParam)),
    getNextPageParam: (last) => last.next_cursor || undefined,
    retry: false,
  });
  const rows = repeats.data?.pages[page]?.items.map(decode) ?? [];
  const toggle = (item: JournalRow) => setActive((current) => current === item.id ? undefined : item.id);
  const pickPage = (index: number) => { setActive(undefined); setPage(index); };
  const memberColumns = columns.map((column) => column.key === "title" ? {
    ...column, render: (item: JournalRow) => <span className="sli-ds-table__cell-line">
      {item.expandable && item.id ? <Button variant="ghost" icon={active === item.id ? "chevron-down" : "chevron"}
        aria-label={journalText(active === item.id ? "fold" : "expand")} aria-expanded={active === item.id}
        onClick={(event) => { event.stopPropagation(); toggle(item); }}/> : null}
      <span>{eventTitle(item)}</span>
    </span>,
  } : column);
  if (repeats.isLoading) return <span role="status">{t("state.loading")}</span>;
  return <>
    {rows.length ? <DataTable compact caption={journalText("expand")} rows={rows} rowKey={(item) => item.key} columns={memberColumns}
      onRowClick={(item) => { if (item.expandable) toggle(item); else onSelect(item); }} stickyHeader={false}
      expanded={(item) => !member && active && item.id === active
        ? <RepeatRows params={params} row={row} member={active} columns={columns} onSelect={onSelect}/> : null}
      showFooter={page > 0 || repeats.hasNextPage}
      total={repeats.data?.pages[0]?.filtered_count}
      pagination={{
        start: page * 25 + 1, busy: repeats.isFetchingNextPage,
        onPrevious: page > 0 ? () => pickPage(page - 1) : undefined,
        onNext: (repeats.data?.pages.length ?? 0) > page + 1 ? () => pickPage(page + 1) : repeats.hasNextPage ? () => {
          void repeats.fetchNextPage().then((next) => { if ((next.data?.pages.length ?? 0) > page + 1) pickPage(page + 1); });
        } : undefined,
      }}/> : null}
    {repeats.isError ? <div role="alert">{journalText("repeats_failed")}{" "}<Button onClick={() => void repeats.refetch()}>{t("state.retry")}</Button></div> : null}
  </>;
}

function JournalDetail({ row, params, zone, onClose, onSelect, onExpand, inline, link, pivot }: {
  row: JournalRow; params: URLSearchParams; zone: string; onClose: () => void;
  onSelect: (row: JournalRow) => void; onExpand?: () => void; inline: boolean;
  link: (type: Pivot, value: string) => string; pivot: (type: Pivot, value: string) => void;
}) {
  const [tabChoice, setTabChoice] = useState<{ row: string; tab: string }>();
  const tab = tabChoice?.row === row.key ? tabChoice.tab : "details";
  const context = new URLSearchParams(params);
  for (const key of ["q", "pivot", "server", "view", "result"]) context.delete(key);
  context.set("before", row.id || "");
  context.set("limit", "5");
  const earlier = useQuery({
    queryKey: ["journal", "before", context.toString()],
    queryFn: () => api.reportV2Data("events.journal", context),
    enabled: Boolean(row.id && !row.expandable && params.has("from") && params.has("to")),
    retry: false,
  });
  const source = useQuery({
    queryKey: ["event", row.id],
    queryFn: () => api.event(row.id!),
    enabled: Boolean(row.id && !row.expandable),
    retry: false,
  });
  const event = source.data?.item;
  const raw = event && !event.source_payload_state
    ? [event.message_text?.trim(), event.event_data && Object.keys(event.event_data).length ? JSON.stringify(event.event_data, null, 2) : ""].filter(Boolean).join("\n\n")
    : "";
  const related = earlier.data?.items.map(decode) ?? [];
  const facts = [
    { label: journalText("account"), text: row.account, value: pivotLink(row.account, "account", link, pivot) },
    { label: journalText("initiator"), text: row.initiator },
    { label: journalText("address"), text: row.address, value: pivotLink(row.address, "address", link, pivot) },
    { label: journalText("computer"), text: row.computer, value: pivotLink(row.computer, "computer", link, pivot) },
    { label: journalText("logon_type"), text: row.logonType },
    { label: journalText("authentication"), text: typeof event?.event_data?.AuthenticationPackageName === "string" ? event.event_data.AuthenticationPackageName : "" },
    { label: journalText("occurrences"), text: row.count > 1 ? formatNumber(row.count) : "" },
    { label: journalText("columns.channel.label"), text: row.channel },
    { label: journalText("record"), text: event?.event_record_id ? String(event.event_record_id) : "" },
  ].filter((fact) => fact.text);
  const title = `${row.title || EMPTY_VALUE}${row.count > 1 ? ` ×${formatNumber(row.count)}` : ""}`;
  const stamp = new Date(row.last || row.time);
  const offset = Number.isFinite(stamp.getTime()) && (zone === "browser" || isValidTimeZone(zone)) ? formatClockWithOffset(stamp, zone).zone : "";
  const when = eventTime(row, zone, true);
  return <DetailDrawer open inline={inline} title={title} onClose={onClose}
    subtitle={[row.code, when, offset].filter(Boolean).join(" · ")}
    footer={<>
      {row.findingId ? <a className="sli-ds-button" href={`/app/report/security.problems?id=${row.findingId}`}>{journalText("open_problem")}</a> : null}
      {event && row.id ? <a className="sli-ds-button" href={withReturnTo(`/app/events/${row.id}`, window.location.pathname + window.location.search)}>{journalText("original")}</a> : null}
      <CopyFactsButton text={[title, when, ...facts.map((fact) => `${fact.label} · ${fact.text}`)].join("\n")}/>
    </>}>
    {row.severity || row.result ? <div className="sli-ds-header__meta">
      <Result value={row.result}/>{row.severity ? <SeverityBadge severity={row.severity}/> : null}
    </div> : null}
    {raw ? <Tabs items={[
      { key: "details", label: journalText("details") },
      { key: "source", label: journalText("original") },
    ]} active={tab} onChange={(next) => setTabChoice({ row: row.key, tab: next })}>
      <TabList label={title}/>
      <TabPanel>{tab === "source" ? <pre className="sli-ds-pre">{raw}</pre>
        : <FactList facts={facts.map((fact) => ({ label: fact.label, value: fact.value ?? fact.text }))}/>}</TabPanel>
    </Tabs> : <FactList facts={facts.map((fact) => ({ label: fact.label, value: fact.value ?? fact.text }))}/>}
    {related.length ? <section>
      <h3>{journalText("before")}</h3>
      <DataTable compact caption={journalText("before")} rows={related} rowKey={(item) => item.key} onRowClick={onSelect}
        stickyHeader={false} showFooter={false} columns={[
          { key: "time", label: journalText("columns.time.label"), kind: "datetime", render: (item) => eventTime(item, zone) },
          { key: "title", label: journalText("columns.event.label"), render: (item) => <button type="button" className="sli-ds-link" onClick={(event) => { event.stopPropagation(); onSelect(item); }}>{eventTitle(item)}</button> },
          { key: "result", label: journalText("result"), render: (item) => <Result value={item.result}/> },
        ]}/>
    </section> : null}
    {earlier.isError ? <div role="alert">{journalText("before_failed")}{" "}<Button onClick={() => void earlier.refetch()}>{t("state.retry")}</Button></div> : null}
    {onExpand ? <Button onClick={onExpand}>{journalText("source_count", { count: formatNumber(row.count) })}</Button> : null}
    <div className="sli-ds-header__meta">
      {(["account", "address", "computer"] as const).map((type) => row[type] ? <span key={type}>{pivotLink(row[type], type, link, pivot, journalText(`pivot.${type}`))}</span> : null)}
    </div>
  </DetailDrawer>;
}

export function EventJournal({ definition, initialSearch }: { definition: ReportDefinitionDto; initialSearch?: string }) {
  const { timeZone } = useTimeZone();
  const [values, setValues] = useState(() => {
    const search = new URLSearchParams(initialSearch ?? window.location.search);
    const legacyDomain = search.get("domain_id");
    if (legacyDomain && !search.has("domain")) search.set("domain", legacyDomain);
    return valuesFromSearch(definition, search);
  });
  const [size, setSize] = useState(50);
  const [page, setPage] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [selection, setSelection] = useState<JournalRow | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [wide, setWide] = useState(false);
  useEffect(() => {
    const media = window.matchMedia?.("(min-width: 1376px)");
    if (!media) return;
    const update = () => setWide(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);
  useEffect(() => {
    const search = searchFromValues(definition, values);
    preserveNavigationView(search, window.location.search);
    const query = search.toString();
    window.history.replaceState(window.history.state, "", `${window.location.pathname}${query ? `?${query}` : ""}${window.location.hash}`);
  }, [definition, values]);

  const collapse = values.collapse !== "off";
  const requestedView = values.view;
  const active = requestedView === "attention" || requestedView === "tasks" ? requestedView
    : categories.find((category) => category === requestedView) ?? "all";
  const valid = valuesReady(definition, values);
  const params = apiParams(definition, { ...values, view: active, collapse: collapse ? "on" : "off" }, { timeZone, limit: size });
  const requestKey = `${params}:${refresh}`;
  const currentRequest = useRef(requestKey);
  currentRequest.current = requestKey;
  const data = useInfiniteQuery({
    queryKey: ["journal", definition.key, params.toString(), refresh],
    initialPageParam: {} as { cursor?: string; window?: { from: string; to: string } },
    queryFn: ({ pageParam }) => api.reportV2Data(definition.key, followup(params, pageParam.window, pageParam.cursor)),
    getNextPageParam: (last, all) => last.next_cursor ? { cursor: last.next_cursor, window: pageWindow(all[0]) } : undefined,
    enabled: valid,
    retry: false,
  });
  const first = data.data?.pages[0];
  const result = data.data?.pages[page];
  const rows = result?.items.map(decode) ?? [];
  const windowBounds = pageWindow(first);
  const fixedParams = followup(params, windowBounds);
  const auto = wide && typeof window.matchMedia === "function" && window.matchMedia("(min-width: 2200px)").matches;
  const selected = selection ?? (auto && !dismissed ? rows[0] : undefined);
  const change = (next: FilterValues) => {
    setPage(0); setExpanded(null); setSelection(null); setValues(next);
  };
  const select = (row: JournalRow) => { setSelection(row); setDismissed(false); };
  const pivotValues = (type: Pivot, value: string) => ({ ...values, q: value, pivot: type, view: "all", server: undefined, result: undefined });
  const link = (type: Pivot, value: string) => `?${searchFromValues(definition, pivotValues(type, value))}`;
  const pivot = (type: Pivot, value: string) => change(pivotValues(type, value));
  const pickPage = (index: number) => { setPage(index); setExpanded(null); setSelection(null); };
  const viewKeys = active === "attention" || active === "tasks" ? [...categories, active] as const : categories;
  const counts = first?.journal_counts;
  const tabs = viewKeys.map((key) => ({
    key, label: <>{journalText(`view.${key}`)}{typeof counts?.[key] === "number" ? <> <strong>{formatNumber(counts[key])}</strong></> : null}</>,
  }));
  const defaults = defaultValues(definition);
  const filterDefinitions = filterFields(definition).filter((field) => ["q", "result"].includes(field.key)).map((field) => (
    field.key === "q" && field.kind === "text" ? { ...field, immediate: true, placeholder: journalText("search") }
      : field.key === "result" && field.kind === "select" ? { ...field, label: journalText("result"), immediate: true, hideLabel: true, options: [
          { value: "", label: journalText("result.any") },
          { value: "success", label: journalText("result.success") },
          { value: "failure", label: journalText("result.failure") },
        ] } : field
  ));
  const columns: TableColumn<JournalRow>[] = [
    { key: "severity", label: journalText("severity"), render: (row) => <SeverityBadge severity={row.severity}/> },
    { key: "time", label: journalText("columns.time.label"), kind: "datetime", render: (row) => eventTime(row, timeZone) },
    { key: "title", label: journalText("columns.event.label"), render: (row) => <span className="sli-ds-table__cell-line">
        {row.expandable && row.id ? <Button variant="ghost" icon={expanded === row.key ? "chevron-down" : "chevron"}
          aria-label={journalText(expanded === row.key ? "fold" : "expand")} aria-expanded={expanded === row.key}
          onClick={(event) => { event.stopPropagation(); setExpanded(expanded === row.key ? null : row.key); }}/> : null}
        <span>{eventTitle(row)}</span>
      </span> },
    { key: "computer", label: journalText("computer"), render: (row) => pivotLink(row.computer, "computer", link, pivot) },
    { key: "account", label: journalText("account"), render: (row) => pivotLink(row.account, "account", link, pivot) },
    { key: "address", label: journalText("address"), mobile: false, render: (row) => pivotLink(row.address, "address", link, pivot) },
    { key: "result", label: journalText("result"), render: (row) => <Result value={row.result}/> },
    { key: "code", label: journalText("code"), kind: "code", mobile: false },
  ];
  const denied = first?.state === "denied" || data.error instanceof ApiResponseError && data.error.status === 403;
  if (denied) return <ReportDenied reportKey={definition.key} page/>;
  const drawer = selected ? <JournalDetail row={selected} params={fixedParams} zone={timeZone}
    inline={wide} onClose={() => { setSelection(null); setDismissed(true); }} onSelect={select}
    link={link} pivot={pivot} onExpand={selected.expandable ? () => setExpanded(selected.key) : undefined}/> : undefined;
  const total = first?.filtered_count;
  const footer = <><div className="sli-ds-header__meta" role="group" aria-label={journalText("page_size")}>
    {journalText("page_size")}{sizes.map((value) => <button type="button" className="sli-ds-chip" key={value} aria-pressed={size === value}
      onClick={() => { pickPage(0); setSize(value); }}>{value}</button>)}
    </div>
    {typeof first?.journal_event_count === "number" ? <span>{journalText("event_count", { count: formatNumber(first.journal_event_count) })}</span> : null}</>;
  let content: ReactNode;
  if (!rows.length) content = <p role="status">{journalText(first?.state === "not_collected" ? "not_loaded" : "empty")}</p>;
  else content = <DataTable compact caption={definition.title} rows={rows} rowKey={(row) => row.key} columns={columns}
    sort={{ field: "time", direction: "desc" }} selectedKey={selected?.key} onRowClick={select} total={total} footerControls={footer}
    expanded={(row) => expanded === row.key && row.id ? <RepeatRows params={fixedParams} row={row} columns={columns} onSelect={select}/> : null}
    pagination={{ start: page * size + 1, busy: data.isFetchingNextPage,
      label: typeof total === "number" ? journalText("page", { page: page + 1, total: Math.max(1, Math.ceil(total / size)) }) : journalText("page_number", { page: page + 1 }),
      onPrevious: page > 0 ? () => pickPage(page - 1) : undefined,
      onNext: data.data && page < data.data.pages.length - 1 ? () => pickPage(page + 1) : data.hasNextPage ? () => {
        void data.fetchNextPage().then((next) => {
          if (currentRequest.current === requestKey && next.data && next.data.pages.length > page + 1) pickPage(page + 1);
        });
      } : undefined,
    }}/>;
  const failed = data.isError && !data.isFetchNextPageError || first?.state === "error";
  return <Tabs items={tabs} active={active} onChange={(key) => change({ ...values, view: key })}>
    <ReportLayout title={definition.title} domain={typeof values.domain === "string" ? values.domain : undefined}
      controls={{
        period: {
          value: values.period as PeriodValue,
          presets: definition.params.find((param) => param.key === "period")?.presets,
          bounds: windowBounds,
          showBounds: true,
          onChange: (period) => change({ ...values, period }),
        },
        updatedAt: first?.window.generated_at_utc ?? (first ? data.dataUpdatedAt : undefined),
        refreshing: data.isFetching,
        onRefresh: valid ? () => { pickPage(0); setRefresh((value) => value + 1); } : undefined,
      }}
      actions={definition.export && valid ? <a className="sli-ds-button" aria-label={t("reports.renderer.export_csv")}
        title={t("reports.renderer.export_csv")} href={`/api/v2/reports/events.journal/export.csv?${fixedParams}`} download><Icon name="download"/></a> : null}
      filters={<FilterBar layout="inline" fields={filterDefinitions} primaryKeys={["q", "result"]} values={values}
        defaults={{ ...defaults, domain: values.domain, period: values.period }}
        onApply={(next) => change({ ...next, pivot: next.q === values.q ? values.pivot : undefined })}
        leadingControls={<TabList label={journalText("params.view.label")}/>}
        quickFilters={<label className="sli-ds-field"><input type="checkbox" checked={collapse} onChange={(event) => change({ ...values, collapse: event.target.checked ? "on" : "off" })}/>{journalText("collapse")}</label>}/>}
      state={data.isLoading ? "loading" : failed ? "error" : "ok"}
      stateView={failed ? <div role="alert">{journalText("load_failed")} <Button onClick={() => void data.refetch()}>{t("state.retry")}</Button></div> : undefined}
      busy={data.isFetching && !data.isLoading} drawer={!wide ? drawer : undefined} inlineDrawer={wide ? drawer : undefined}>
      <TabPanel>{content}{data.isFetchNextPageError ? <div role="alert">{journalText("load_failed")}</div> : null}</TabPanel>
    </ReportLayout>
  </Tabs>;
}
