import { useEffect, useRef, useState, type ReactNode } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import {
  Button, DataTable, DetailDrawer, FactList, FilterBar, Icon, ReportLayout,
  TabList, TabPanel, Tabs, type FilterField, type FilterValues, type PeriodValue, type TableColumn,
} from "../../design-system";
import { t } from "../../i18n";
import { dayKey, formatClockWithOffset, formatDateTime, isValidTimeZone } from "../../shared/date-time";
import { EMPTY_VALUE, formatNumber } from "../../shared/format";
import { useTimeZone } from "../../shared/time-zone";
import { preserveNavigationView } from "../navigation";
import { safeInvestigationReturnTo } from "../investigation-context";
import { CopyFactsButton } from "./DetailSection";
import { withReturnTo } from "./legacy";
import { ReportDenied } from "./ReportDenied";
import { FirstAdSource, isEmptyFirstAdReportResult, useFirstAdSource } from "../first-ad-source";
import { apiParams, defaultValues, filterFields, searchFromValues, valuesFromSearch, valuesReady } from "./state";

const categories = ["all", "authentication", "failures", "service"] as const;
const sizes = [25, 50, 100, 200];
const kerberosCodes = ["4768", "4769", "4770", "4771", "4772", "4773"] as const;
const logonTypeCodes = ["2", "3", "4", "5", "7", "8", "9", "10", "11", "12", "13"] as const;
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
  sourceCount: number;
  expandable: boolean;
  account: string;
  reportedAccount: string;
  initiator: string;
  computer: string;
  address: string;
  workstation: string;
  result: string;
  channel: string;
  logonType: string;
  findingId: string;
  changeDomain: string;
};

function decode(row: Record<string, unknown>): JournalRow {
  const value = (key: string) => ["string", "number"].includes(typeof row[key]) && !["-", "—"].includes(String(row[key]).trim()) ? String(row[key]).trim() : "";
  const id = value("id");
  const messages = row.presentation_messages as Record<string, { code?: string }> | undefined;
  const account = value("journal_account");
  const code = value("event_id");
  const action = value("journal_action");
  const kerberos = kerberosCodes.find((eventCode) => eventCode === code);
  const rawLogonType = value("logon_type");
  const logonType = logonTypeCodes.find((type) => type === rawLogonType);
  const count = typeof row.event_count === "number" ? row.event_count : 1;
  let title = messages?.title_text?.code === "events.unknown_type" ? "" : value("title_text");
  if (action === "failed_logon" || action === "privileged_logon") title = journalText(`action.${action}`);
  else if (kerberos && title) title = journalText(`event.${kerberos}`);
  return {
    key: id || `${value("day")}:${value("summary_key") || [value("time_created_utc"), value("event_id"), account, value("journal_computer")].join(":")}`,
    id: /^[1-9][0-9]*$/.test(id) ? id : undefined,
    code, title,
    time: value("time_created_utc"),
    first: value("first_seen_utc"), last: value("last_seen_utc"),
    count, sourceCount: typeof row.journal_source_count === "number" ? row.journal_source_count : count,
    expandable: row.journal_expandable === true,
    account, reportedAccount: value("journal_reported_account"), initiator: value("journal_initiator"),
    computer: value("journal_computer"), address: value("journal_address"), result: value("journal_result"),
    workstation: value("journal_workstation"), channel: value("channel"),
    logonType: logonType ? journalText(`logon_type.${logonType}`) : "",
    findingId: /^[1-9][0-9]*$/.test(value("journal_finding_id")) ? value("journal_finding_id") : "",
    changeDomain: /^[1-9][0-9]*$/.test(value("journal_change_domain")) ? value("journal_change_domain") : "",
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
  return value === "success" || value === "failure" ? journalText(`result.${value}`) : EMPTY_VALUE;
}

function eventTitle(row: JournalRow) {
  return row.count > 1 ? <>{row.title || EMPTY_VALUE} ×{formatNumber(row.count)}</> : row.title || EMPTY_VALUE;
}

function eventTime(row: JournalRow, zone: string, details = false) {
  const format = (value: string, dates: boolean) => {
    if (!value || !Number.isFinite(Date.parse(value))) return EMPTY_VALUE;
    if (dates || (zone !== "browser" && !isValidTimeZone(zone))) return formatDateTime(value, zone, { seconds: true, withYear: details });
    return formatClockWithOffset(new Date(value), zone, true).time;
  };
  if (row.count > 1 && row.first && row.last) {
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

function RepeatRows({ params, row, columns, onSelect }: {
  params: URLSearchParams; row: JournalRow; columns: TableColumn<JournalRow>[]; onSelect: (row: JournalRow) => void;
}) {
  const [page, setPage] = useState(0);
  const input = new URLSearchParams(params);
  input.set("expand", row.id!);
  input.set("limit", "25");
  const repeats = useInfiniteQuery({
    queryKey: ["journal", "repeats", input.toString()],
    initialPageParam: null as string | null,
    queryFn: ({ pageParam, signal }) => api.reportV2Data("events.journal", followup(input, undefined, pageParam), signal),
    getNextPageParam: (last) => last.next_cursor || undefined,
    retry: false,
  });
  const rows = repeats.data?.pages[page]?.items.map((item) => {
    const member = decode(item);
    return { ...member, account: member.reportedAccount || member.account };
  }) ?? [];
  const visibleColumns = columns.filter(({ key }) => key === "account" || key === "time" || key === "code" || distinguishes(rows, key));
  if (repeats.isLoading) return <span role="status">{t("state.loading")}</span>;
  return <>
    {rows.length ? <DataTable compact caption={journalText("expand")} rows={rows} rowKey={(item) => item.key} columns={visibleColumns}
      onRowClick={onSelect} stickyHeader={false}
      showFooter={page > 0 || repeats.hasNextPage}
      total={repeats.data?.pages[0]?.filtered_count}
      pagination={{
        start: page * 25 + 1, busy: repeats.isFetchingNextPage,
        onPrevious: page > 0 ? () => setPage(page - 1) : undefined,
        onNext: (repeats.data?.pages.length ?? 0) > page + 1 ? () => setPage(page + 1) : repeats.hasNextPage ? () => {
          void repeats.fetchNextPage().then((next) => { if ((next.data?.pages.length ?? 0) > page + 1) setPage(page + 1); });
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
    queryFn: ({ signal }) => api.reportV2Data("events.journal", context, signal),
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
    { label: journalText("reported_account"), text: row.reportedAccount !== row.account ? row.reportedAccount : "" },
    { label: journalText("initiator"), text: row.initiator },
    { label: journalText("address"), text: row.address || row.workstation,
      value: row.address ? pivotLink(row.address, "address", link, pivot) : row.workstation },
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
    {row.result ? <div className="sli-ds-header__meta"><Result value={row.result}/></div> : null}
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
    {onExpand ? <Button onClick={onExpand}>{journalText("source_count", { count: formatNumber(row.sourceCount) })}</Button> : null}
    <div className="sli-ds-header__meta">
      {(["account", "address", "computer"] as const).map((type) => row[type] ? <span key={type}>{pivotLink(row[type], type, link, pivot, journalText(`pivot.${type}`))}</span> : null)}
    </div>
  </DetailDrawer>;
}

function distinguishes(rows: JournalRow[], key: string) {
  if (key === "title") return true;
  if (key === "problem") return rows.some((row) => row.findingId);
  const value = (row: JournalRow) => key === "address" ? row.address || row.workstation
    : key === "time" ? [row.last || row.time, row.count > 1 ? row.first : ""].join("|")
    : row[key as keyof JournalRow];
  return rows.some((row) => value(row) !== value(rows[0]));
}

function journalRouteValues(definition: ReportDefinitionDto, routeSearch: string): FilterValues {
  const search = new URLSearchParams(routeSearch);
  const legacyDomain = search.get("domain_id");
  if (legacyDomain && !search.has("domain")) search.set("domain", legacyDomain);
  if (!categories.some((category) => category === search.get("view"))) search.delete("view");
  return { collapse: "on", hide_open_problem_evidence: "on", ...valuesFromSearch(definition, search) };
}

export function EventJournal({ definition, initialSearch }: { definition: ReportDefinitionDto; initialSearch?: string }) {
  const { timeZone } = useTimeZone();
  const [values, setValues] = useState(() => journalRouteValues(definition, initialSearch ?? window.location.search));
  const [routeSearch, setRouteSearch] = useState(initialSearch);
  const [entrySearch] = useState(() => new URLSearchParams(initialSearch ?? window.location.search));
  const returnValues = new URLSearchParams(initialSearch ?? window.location.search).getAll("return_to");
  const returnTo = returnValues.length === 1 ? safeInvestigationReturnTo(returnValues[0], "") : "";
  const [size, setSize] = useState(50);
  const [page, setPage] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [selection, setSelection] = useState<JournalRow | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [wide, setWide] = useState(false);
  if (initialSearch !== routeSearch) {
    setRouteSearch(initialSearch);
    if (initialSearch !== undefined) {
      const next = journalRouteValues(definition, initialSearch);
      // The router also sees the journal's own URL normalization.
      if (searchFromValues(definition, next).toString() !== searchFromValues(definition, values).toString()) {
        setValues(next);
        setPage(0);
        setExpanded(null);
        setSelection(null);
        setDismissed(false);
      }
    }
  }
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
    if (returnTo) search.set("return_to", returnTo);
    const query = search.toString();
    const next = query ? `?${query}` : "";
    if (next !== window.location.search)
      window.history.replaceState(window.history.state, "", `${window.location.pathname}${next}${window.location.hash}`);
  }, [definition, values, returnTo]);

  const collapse = values.collapse !== "off";
  const active = categories.find((category) => category === values.view) ?? "all";
  const valid = valuesReady(definition, values);
  const params = apiParams(definition, { ...values, view: active, collapse: collapse ? "on" : "off" }, { timeZone, limit: size });
  const requestKey = `${params}:${refresh}`;
  const currentRequest = useRef(requestKey);
  currentRequest.current = requestKey;
  const data = useInfiniteQuery({
    queryKey: ["journal", definition.key, params.toString(), refresh],
    initialPageParam: {} as { cursor?: string; window?: { from: string; to: string } },
    queryFn: ({ pageParam, signal }) => api.reportV2Data(definition.key, followup(params, pageParam.window, pageParam.cursor), signal),
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
  const counts = first?.journal_counts;
  const tabs = categories.map((key) => ({
    key, label: <>{journalText(`view.${key}`)}{typeof counts?.[key] === "number" ? ` ${formatNumber(counts[key])}` : null}</>,
  }));
  const defaults = { ...defaultValues(definition), collapse: "on", hide_open_problem_evidence: "on" };
  const currentSearch = new URLSearchParams(initialSearch ?? window.location.search);
  const hasExplicitScope = ["domain", "domain_id", "scope"].some(key => entrySearch.has(key) || currentSearch.has(key));
  const firstAdSource = useFirstAdSource(currentSearch, !hasExplicitScope && page === 0 && active === "all"
    && searchFromValues(definition, values).toString() === searchFromValues(definition, defaults).toString()
    && definition.access?.allowed !== false && data.isSuccess && !data.isFetching && isEmptyFirstAdReportResult(first));
  const filterDefinitions: FilterField[] = filterFields(definition).filter((field) => ["q", "result"].includes(field.key)).map((field) => (
    field.key === "q" && field.kind === "text" ? { ...field, immediate: true, placeholder: journalText("search") }
      : field.key === "result" && field.kind === "select" ? { ...field, label: journalText("result"), immediate: true, hideLabel: true, options: [
          { value: "", label: journalText("result.any") },
          { value: "success", label: journalText("result.success") },
          { value: "failure", label: journalText("result.failure") },
        ] } : field
  ));
  filterDefinitions.push(
    { key: "collapse", kind: "checkbox", label: journalText("collapse"), onValue: "on", offValue: "off" },
    { key: "hide_open_problem_evidence", kind: "checkbox", label: journalText("hide_open_problem_evidence"), onValue: "on", offValue: "off" },
  );
  const columns: TableColumn<JournalRow>[] = [
    { key: "time", label: journalText("columns.time.label"), kind: "datetime", render: (row) => eventTime(row, timeZone) },
    { key: "title", label: journalText("columns.event.label"), render: (row) => <span className="sli-ds-table__cell-line">
        {row.expandable && row.id ? <Button variant="ghost" icon={expanded === row.key ? "chevron-down" : "chevron"}
          aria-label={journalText(expanded === row.key ? "fold" : "expand")} aria-expanded={expanded === row.key}
          onClick={(event) => { event.stopPropagation(); setExpanded(expanded === row.key ? null : row.key); }}/> : null}
        <span title={row.title || undefined}>{row.title || EMPTY_VALUE}</span>
        {row.count > 1 ? `×${formatNumber(row.count)}` : null}
        {row.id && row.changeDomain && windowBounds ? <a className="sli-ds-button" data-variant="ghost" href={`/app/report/security.events.chains?${new URLSearchParams({
          domain: row.changeDomain, period: "custom", from: windowBounds.from, to: windowBounds.to,
          event_db_id: row.id, repeat_mode: "individual",
        })}`} onClick={(event) => event.stopPropagation()}>{journalText("open_change")}</a> : null}
      </span> },
    { key: "account", label: journalText("account"), render: (row) => pivotLink(row.account, "account", link, pivot) },
    { key: "initiator", label: journalText("initiator"), mobile: false, render: (row) => pivotLink(row.initiator, "account", link, pivot) },
    { key: "address", label: journalText("address"), mobile: false,
      render: (row) => row.address ? pivotLink(row.address, "address", link, pivot) : row.workstation || EMPTY_VALUE },
    { key: "logonType", label: journalText("logon_type"), mobile: false, render: (row) => row.logonType || EMPTY_VALUE },
    { key: "computer", label: journalText("computer"), render: (row) => pivotLink(row.computer, "computer", link, pivot) },
    { key: "result", label: journalText("result"), render: (row) => <Result value={row.result}/> },
    { key: "code", label: journalText("code"), kind: "code", mobile: false },
    { key: "problem", label: journalText("problem"), render: (row) => row.findingId ? <a
      href={`/app/report/security.problems?id=${row.findingId}`} onClick={(event) => event.stopPropagation()}>
      {journalText("problem_number", { id: row.findingId })}</a> : null },
  ];
  const varying = first && "journal_varying_columns" in first && Array.isArray(first.journal_varying_columns) ? first.journal_varying_columns : undefined;
  const visibleColumns = columns.filter(({ key }) => key === "title" || key === "problem" || !varying
    ? distinguishes(rows, key)
    : varying.includes(key));
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
  if (!rows.length) content = firstAdSource ? <FirstAdSource/>
    : <p role="status">{journalText(first?.state === "not_collected" ? "not_loaded" : "empty")}</p>;
  else content = <DataTable compact caption={definition.title} rows={rows} rowKey={(row) => row.key} columns={visibleColumns}
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
      actions={<>
        {returnTo ? <a className="sli-ds-button" href={returnTo}>{t("investigations.case.return_to_source_report")}</a> : null}
        {definition.export && valid ? <a className="sli-ds-button" aria-label={t("reports.renderer.export_csv")}
          title={t("reports.renderer.export_csv")} href={`/api/v2/reports/events.journal/export.csv?${fixedParams}`} download><Icon name="download"/></a> : null}
      </>}
      filters={<FilterBar layout="inline" fields={filterDefinitions} primaryKeys={["q", "result", "collapse", "hide_open_problem_evidence"]} values={values} applyInline
        defaults={{ ...defaults, domain: values.domain, period: values.period }}
        onApply={(next) => change({ ...next, pivot: next.q === values.q ? values.pivot : undefined })}
        leadingControls={<TabList label={journalText("params.view.label")}/>}/>}
      state={data.isLoading ? "loading" : failed ? "error" : "ok"}
      stateView={failed ? <div role="alert">{journalText("load_failed")} <Button onClick={() => void data.refetch()}>{t("state.retry")}</Button></div> : undefined}
      busy={data.isFetching && !data.isLoading} drawer={!wide ? drawer : undefined} inlineDrawer={wide ? drawer : undefined}>
      <TabPanel>{content}{data.isFetchNextPageError ? <div role="alert">{journalText("load_failed")}</div> : null}</TabPanel>
    </ReportLayout>
  </Tabs>;
}
