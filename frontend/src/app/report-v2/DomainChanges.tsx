import { useEffect, useState, type FormEvent, type MouseEvent } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import {
  Badge, Button, DataTable, DetailDrawer, FactList, PeriodPicker, ReportLayout, TabList, TabPanel, Tabs,
  periodBounds, type FilterValues, type PeriodPreset, type PeriodValue, type TableColumn,
} from "../../design-system";
import { periodLabel } from "../../design-system/PeriodPicker";
import { PageHeaderContext } from "../../design-system/PageHeader";
import { t, type MessageKey } from "../../i18n";
import { dayKey, formatClockWithOffset, formatDateTime, isValidTimeZone, localDateTimeToUtc, utcToLocalDateTimeInput } from "../../shared/date-time";
import { formatNumber } from "../../shared/format";
import { useTimeZone } from "../../shared/time-zone";
import { preserveNavigationView } from "../navigation";
import { CopyFactsButton } from "./DetailSection";
import { ReportDenied } from "./ReportDenied";
import { apiParams, paramOptions, searchFromValues, valuesFromSearch } from "./state";

const prefix = "reports.domain_changes." as const;
const labels = (key: string) => t(`${prefix}${key}` as MessageKey);
const views = ["all", "accounts", "groups", "passwords", "audit"] as const;
type Row = Record<string, unknown>;
type Change = {
  id: string;
  domain: string;
  event: string;
  time: string;
  first: string;
  count: number;
  title: string;
  sign: string;
  object: string;
  target: string;
  member: string;
  group: string;
  actor: string;
  actorFilter: string;
  targetFilter: string;
  groupFilter: string;
  fields: { label: string; value: string; previousAt?: string }[];
  host: string;
  result: string;
  record: string;
  channel: string;
};

const text = (value: unknown) => typeof value === "string" && !["", "-", "—"].includes(value.trim())
  ? value.trim() : typeof value === "number" && Number.isFinite(value) ? String(value) : "";
const object = (value: unknown): Row => value && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
const name = (value: Row) => text(value.name) || text(value.sid);
const identity = (value: Row) => text(value.sid) || text(value.name);
const pageSizes = [25, 50, 100, 200];
const dash = () => t("table.noValue");
const show = (value: string) => value || dash();
const lifecycleLabels: Record<string, string> = {
  created: "created", deleted: "deleted", enabled: "enabled", disabled: "disabled", locked: "locked", unlocked: "unlocked",
  group_created: "created", group_deleted: "deleted",
};

function toChange(row: Row): Change {
  const event = text(row.event_id);
  const change = object(row.change);
  const actor = object(row.actor), group = object(row.group), member = object(row.member), target = object(row.affected_account);
  const host = text(object(row.source_host).hostname);
  const kind = text(change.kind);
  const added = ["created", "group_created", "member_added"].includes(kind);
  const removed = ["deleted", "group_deleted", "member_removed"].includes(kind);
  const attributes = object(change.attributes);
  const previous = object(change.previous_attributes);
  const fields: Change["fields"] = Object.entries(attributes).flatMap(([key, value]) => {
    const code = `${prefix}attribute.${key}`;
    const label = labels(`attribute.${key}`);
    const after = text(value);
    const before = text(object(previous[key]).value);
    return label !== code && after ? [{
      label, value: before ? `${before} → ${after}` : after, previousAt: text(object(previous[key]).observed_at_utc),
    }] : [];
  });
  const compare = (before: unknown, after: unknown) => text(after)
    ? [text(before), text(after)].filter(Boolean).join(" → ") : "";
  const transition = object(object(row.account_change).observed_transition);
  const rename = event === "4781" ? compare(object(transition.before).value, object(transition.after).value) : "";
  const groupType = compare(change.old_group_type, change.new_group_type);
  if (rename) fields.push({ label: t(`${prefix}name`), value: rename });
  if (groupType) fields.push({ label: t(`${prefix}group_type`), value: groupType });
  if (text(change.attribute)) fields.push({ label: text(change.attribute), value: text(change.observed_value) });
  else if (text(change.observed_value)) fields.push({ label: t(`${prefix}audit`), value: text(change.observed_value) });
  const accountFlags = compare(attributes.old_user_account_control, attributes.new_user_account_control);
  if (accountFlags && !fields.some(({ label }) => label === labels("attribute.user_account_control")))
    fields.push({ label: labels("attribute.user_account_control"), value: accountFlags });
  if (name(member) && name(group) && (added || removed)) fields.push({ label: name(group), value: `${added ? "+" : "−"} ${name(member)}` });
  if (!fields.length && Object.hasOwn(lifecycleLabels, kind)) {
    const field = kind.startsWith("group_") ? "group" : ["created", "deleted"].includes(kind) ? "account" : "account_state";
    fields.push({ label: labels(field), value: labels(lifecycleLabels[kind]) });
  }
  if (!fields.length && kind.startsWith("password_")) fields.push({ label: labels("password"), value: "" });
  return {
    id: text(row.event_db_id), domain: text(row.domain_id), event,
    time: text(row.time_created_utc), first: text(row.first_seen_utc),
    count: typeof row.repeat_count === "number" ? row.repeat_count : 1,
    title: text(row.change_text) || t(`${prefix}change`),
    sign: added ? "+" : removed ? "−" : "↻",
    object: name(member) || name(target) || name(group) || (text(row.event_family) === "audit_configuration" ? host : ""),
    target: name(target), member: name(member), group: name(group), actor: name(actor),
    actorFilter: identity(actor), targetFilter: identity(member) || identity(target), groupFilter: identity(group),
    fields, host, result: text(row.outcome_code), record: text(row.event_record_id), channel: text(row.channel),
  };
}

function ErrorLine({ onRetry }: { onRetry: () => void }) {
  return <div role="alert">{t("reports.domain_events.load_failed")}{" "}<Button onClick={onRetry}>{t("state.retry")}</Button></div>;
}

function Result({ value }: { value: string }) {
  return value === "failure" ? <span className="sli-ds-error"><span aria-hidden="true">✗ </span>{t(`${prefix}failure`)}</span>
    : value === "success" ? <span aria-label={t(`${prefix}success`)} title={t(`${prefix}success`)}>✓</span> : dash();
}

function shortTime(time: string, timeZone: string) {
  if (!time || dayKey(time, timeZone) !== dayKey(new Date(), timeZone)) return formatDateTime(time, timeZone, { seconds: true });
  return new Intl.DateTimeFormat("en-GB", {
    timeZone: timeZone === "browser" ? undefined : timeZone, hour: "2-digit", minute: "2-digit", second: "2-digit",
  }).format(new Date(time));
}

function PeriodControl({ period, timeZone, presets, apply }: {
  period: PeriodValue; timeZone: string; presets?: PeriodPreset[]; apply: (period: PeriodValue) => void;
}) {
  const [draft, setDraft] = useState<PeriodValue>();
  const toInput = (value?: string) => value && /(?:Z|[+-]\d\d:\d\d)$/i.test(value)
    ? utcToLocalDateTimeInput(value, timeZone) : value?.length === 10 ? `${value}T00:00` : value;
  const current = period.preset === "custom" ? { ...period, from: toInput(period.from), to: toInput(period.to) } : period;
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!draft || draft.preset === "custom" && (!draft.from || !draft.to || draft.from >= draft.to)) return;
    apply(draft);
    const details = event.currentTarget.closest("details");
    if (details) details.open = false;
  };
  return <details className="sli-ds-header__period" onToggle={(event) => { if (!event.currentTarget.open) setDraft(undefined); }}>
    <summary className="sli-ds-button">{period.preset === "custom" && current.from && current.to
      ? `${current.from.replace("T", " ")} → ${current.to.replace("T", " ")}` : periodLabel(period.preset)}</summary>
    <form className="sli-ds-header__period-menu" onSubmit={submit}>
      <PeriodPicker value={draft ?? current} precision="datetime-local" presets={presets} onChange={setDraft}/>
      <Button type="submit" disabled={!draft || draft.preset === "custom" && (!draft.from || !draft.to || draft.from >= draft.to)}>{t("filters.apply")}</Button>
    </form>
  </details>;
}

function ChangeDetails({ change, query, timeZone, close, pivot }: {
  change: Change; query: string; timeZone: string; close: () => void;
  pivot: (key: "target" | "actor" | "group", value: string, domain: string) => void;
}) {
  const [tab, setTab] = useState("change");
  const [wide, setWide] = useState(false);
  const tabs = ["change", "participants", "event"];
  const participants = [
    { label: labels(change.member ? "member" : "object"), value: change.target || change.member || change.object },
    ...(change.group ? [{ label: labels("group"), value: change.group }] : []),
    { label: labels("initiator"), value: change.actor },
  ];
  const eventFacts = [
    { label: labels("time"), value: formatDateTime(change.time, timeZone, { seconds: true }) },
    { label: labels("dc"), value: change.host },
    { label: labels("event_id"), value: change.event },
    ...(change.record ? [{ label: labels("record"), value: change.record }] : []),
    ...(change.channel ? [{ label: labels("channel"), value: change.channel }] : []),
  ];
  const facts = [
    { label: labels("operation"), value: `${change.sign} ${change.title}` },
    ...(change.member ? [] : change.fields.map(({ label, value, previousAt }) => ({
      label, value: previousAt ? `${value} · ${labels("previous_observation")} ${formatDateTime(previousAt, timeZone, { seconds: true })}` : value,
    }))),
    ...participants,
    ...eventFacts,
    { label: labels("result"), value: change.result === "success" || change.result === "failure" ? labels(change.result) : "" },
  ];
  const pivots = [
    { key: "target", value: change.targetFilter, label: t(`${prefix}by_target`, { name: change.target || change.member }) },
    { key: "actor", value: change.actorFilter, label: t(`${prefix}by_actor`, { name: change.actor }) },
    { key: "group", value: change.groupFilter, label: t(`${prefix}by_group`, { name: change.group }) },
  ] as const;
  const search = new URLSearchParams(query);
  const eventSearch = new URLSearchParams({ return_to: `${window.location.pathname}?${search}`, timezone: timeZone });
  for (const [from, to] of [["from", "time_from"], ["to", "time_to"]]) {
    const value = search.get(from);
    if (value) eventSearch.set(to, value);
  }
  return <DetailDrawer open inline={!wide} title={change.title} subtitle={change.group || change.object} onClose={close}
    headerActions={<Button variant="ghost" aria-label={labels(wide ? "dock_details" : "expand_details")} onClick={() => setWide(!wide)}>{wide ? "↙" : "↗"}</Button>}
    footer={<>
      {change.id ? <a className="sli-ds-button" data-variant="primary" href={`/app/events/${encodeURIComponent(change.id)}?${eventSearch}`}>{labels("open_event")}</a> : null}
      <CopyFactsButton text={facts.filter(({ value }) => value).map(({ label, value }) => `${label}: ${value}`).join("\n")}/>
    </>}>
    <Tabs items={tabs.map((key) => ({ key, label: labels(key) }))} active={tab} onChange={setTab}>
      <TabList label={labels("details")}/>
      <TabPanel><FactList facts={tab === "participants" ? participants : tab === "event" ? eventFacts : facts}/></TabPanel>
    </Tabs>
    <div className="sli-ds-list">
      {pivots.filter(({ value }) => value).map(({ key, value, label }) =>
        <Button key={key} variant="ghost" icon="search" onClick={() => pivot(key, value, change.domain)}>{label} →</Button>)}
    </div>
  </DetailDrawer>;
}

function BatchRows({ id, domain, params, report, columns, colSpan, select }: {
  id: string; domain: string; params: string; report: string; columns: TableColumn<Change>[]; colSpan: number; select: (row: Change) => void;
}) {
  const data = useInfiniteQuery({
    queryKey: ["report-v2", "domain-changes-batch", report, params, domain, id],
    queryFn: ({ pageParam }) => {
      const request = new URLSearchParams(params);
      if (domain) request.set("domain", domain);
      request.set("batch", id);
      if (pageParam) request.set("cursor", pageParam);
      return api.reportV2Data(report, request);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page: ReportResultDto) => page.has_more ? page.next_cursor : null,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const first = data.data?.pages[0];
  return <tr><td colSpan={colSpan}>
    {data.error || first?.state === "denied" || first?.state === "error"
      ? <ErrorLine onRetry={() => void data.refetch()}/>
      : data.isPending ? <span role="status">{t("state.loading")}</span>
        : <DataTable caption={t(`${prefix}batch`)} columns={columns.map((column) => ({ ...column, hiddenByDefault: undefined }))}
            rows={data.data?.pages.flatMap((page) => page.items.map((row) => toChange({ ...row, repeat_count: 1 }))) ?? []}
            rowKey={(row) => row.id} onRowClick={select} stickyHeader={false} wrapCells
            showFooter={data.hasNextPage} hasMore={data.hasNextPage} loadingMore={data.isFetchingNextPage} onLoadMore={() => void data.fetchNextPage()}/>}
  </td></tr>;
}

export function DomainChanges({ definition, initialSearch }: { definition: ReportDefinitionDto; initialSearch?: string }) {
  const { timeZone: preferredZone } = useTimeZone();
  const timeZone = preferredZone === "browser" || isValidTimeZone(preferredZone) ? preferredZone : "UTC";
  const [filters, setFilters] = useState(() => valuesFromSearch(definition, new URLSearchParams(initialSearch ?? window.location.search)));
  const [search, setSearch] = useState(text(filters.q));
  const [anchor, setAnchor] = useState(() => new Date());
  const [limit, setLimit] = useState(50);
  const [position, setPosition] = useState({ query: "", page: 0 });
  const [selection, setSelection] = useState<Change | null>(null);
  const [details, setDetails] = useState(true);
  const [expanded, setExpanded] = useState("");
  const [density, setDensity] = useState<"compact" | "comfortable">("compact");
  const active = views.find((key) => key === filters.changes_view) ?? "all";
  const collapse = filters.repeat_mode !== "individual";
  const period = (filters.period ?? { preset: "7d" }) as PeriodValue;
  const bounds = period.preset === "custom" ? null : periodBounds(period, anchor);
  const values: FilterValues = { ...filters, changes_view: active, repeat_mode: collapse ? "collapsed" : "individual", batch: undefined };
  const uiQuery = searchFromValues(definition, values);
  const params = apiParams(definition, values, { limit, timeZone, view: "events" });
  if (bounds) {
    params.set("period", "custom");
    params.set("from", bounds.from);
    params.set("to", bounds.to);
  }
  for (const key of ["from", "to"]) {
    const value = params.get(key);
    if (!bounds && value?.includes("T") && !/(?:Z|[+-]\d\d:?\d\d)$/i.test(value)) {
      const utc = localDateTimeToUtc(value, timeZone);
      if (utc) params.set(key, utc);
    }
  }
  if (timeZone === "browser") params.set("tz", Intl.DateTimeFormat().resolvedOptions().timeZone ?? "UTC");
  const query = params.toString();
  const pageIndex = position.query === query ? position.page : 0;
  const data = useInfiniteQuery({
    queryKey: ["report-v2", "domain-changes", definition.key, query],
    queryFn: ({ pageParam }) => {
      const request = new URLSearchParams(query);
      if (pageParam) request.set("cursor", pageParam);
      return api.reportV2Data(definition.key, request);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page: ReportResultDto) => page.has_more ? page.next_cursor : null,
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  });
  preserveNavigationView(uiQuery, window.location.search);
  const url = `${window.location.pathname}?${uiQuery}`;
  useEffect(() => {
    window.history.replaceState(window.history.state, "", url);
  }, [url]);
  const set = (next: FilterValues) => {
    setSelection(null);
    setExpanded("");
    setPosition({ query: "", page: 0 });
    setFilters(next);
  };
  const page = data.data?.pages[pageIndex];
  const rows = page?.items.map(toChange) ?? [];
  const counts = page?.change_counts;
  const title = t("reports.v2.security.events.chains.title");
  const refresh = () => {
    setSelection(null);
    setExpanded("");
    setPosition({ query: "", page: 0 });
    if (period.preset === "custom") void data.refetch();
    else setAnchor(new Date());
  };
  const select = (row: Change) => { setSelection(row); setDetails(true); };
  const pivot = (key: "target" | "actor" | "group", value: string, domain: string) => {
    setSearch("");
    set({ ...values, category: undefined, event_id: undefined, event_db_id: undefined, actor: undefined,
      target: undefined, group: undefined, entity_id: undefined, q: undefined, domain, changes_view: "all", [key]: value });
  };
  const toggleBatch = (event: MouseEvent, id: string) => {
    event.stopPropagation();
    setExpanded(expanded === id ? "" : id);
  };
  const columns: TableColumn<Change>[] = [
    { key: "time", label: labels("time"), minWidth: "calc(5 * var(--sli-space-8))", sortable: true, render: (row) => row.count > 1 && row.first !== row.time
      ? `${shortTime(row.first, timeZone)}–${shortTime(row.time, timeZone)}` : shortTime(row.time, timeZone) },
    { key: "change", label: labels("change_id"), render: (row) => row.count > 1
      ? <button type="button" className="sli-ds-button" data-variant="ghost" data-size="compact" aria-expanded={expanded === row.id}
          onClick={(event) => toggleBatch(event, row.id)}>{row.sign} {row.title} · {row.event} ×{formatNumber(row.count)}</button>
      : `${row.sign} ${row.title} · ${row.event}` },
    { key: "object", label: labels("object"), render: (row) => row.count > 1 ? dash() : show(row.object) },
    { key: "field", label: labels("field"), hiddenByDefault: false, render: (row) => row.count > 1 ? dash() : row.fields.map(({ label }) => label).join(" · ") || dash() },
    { key: "value", label: labels("value"), hiddenByDefault: false, render: (row) => row.count > 1 ? dash() : row.fields.map(({ value }) => show(value)).join(" · ") || dash() },
    { key: "initiator", label: labels("initiator"), hiddenByDefault: false, render: (row) => show(row.actor) },
    { key: "dc", label: labels("dc"), minWidth: "calc(4.5 * var(--sli-space-8))", hiddenByDefault: false, render: (row) => show(row.host) },
    { key: "result", label: labels("result"), minWidth: "calc(2.5 * var(--sli-space-8))", hiddenByDefault: false, render: (row) => <Result value={row.result}/> },
  ];
  const operations = paramOptions(definition, "event_id", page?.filter_options);
  const count = page?.filtered_count;
  const blocked = page?.state === "denied" || (data.error instanceof ApiResponseError && [401, 403].includes(data.error.status));
  if (blocked) return <ReportDenied reportKey={definition.key} page/>;
  const failed = !page && Boolean(data.error) || page?.state === "error";
  const state = data.isPending ? "loading" : failed ? "error" : page?.state === "not_collected" ? "partial" : page?.state ?? "ok";
  const exportHref = `/api/v2/reports/${encodeURIComponent(definition.key)}/export.csv?${query}`;
  const when = page?.window.to_utc_exclusive ?? bounds?.to;
  const zone = formatClockWithOffset(when && Number.isFinite(Date.parse(when)) ? new Date(when) : anchor, timeZone).zone;
  const detailParams = new URLSearchParams(query);
  if (page?.window.from_utc) detailParams.set("from", page.window.from_utc);
  if (page?.window.to_utc_exclusive) detailParams.set("to", page.window.to_utc_exclusive);
  const chosen = details && selection ? <ChangeDetails key={selection.id} change={selection} query={detailParams.toString()} timeZone={timeZone} close={() => setSelection(null)} pivot={pivot}/> : null;
  const submitSearch = (event: FormEvent) => {
    event.preventDefault();
    set({ ...values, q: search.trim(), actor: undefined, target: undefined, group: undefined });
  };
  const go = async (to: number) => {
    if (data.data && to >= data.data.pages.length) {
      const result = await data.fetchNextPage();
      if (!result.data?.pages[to]) return;
    }
    setSelection(null);
    setExpanded("");
    setPosition({ query, page: to });
  };
  return <PageHeaderContext.Provider value={{}}><Tabs items={views.map((key) => ({ key, label: counts && typeof counts[key] === "number" ? `${labels(key)} ${formatNumber(counts[key])}` : labels(key) }))}
    active={active} onChange={(key) => set({ ...values, changes_view: key })}>
    <ReportLayout title={title} controls={{}} tabbed state={state}
      stateView={failed ? <ErrorLine onRetry={() => void data.refetch()}/> : state === "empty"
        ? <p role="status">{t("reports.domain_events.empty")}</p> : <></>} busy={data.isFetching && !data.isPending}
      actions={<>
        <Button icon="refresh" disabled={data.isFetching} onClick={refresh}>{t("shell.header.refresh")}</Button>
        {definition.export ? <a className="sli-ds-button" href={exportHref} download>{t("reports.renderer.export_csv")}</a> : null}
      </>}
      filters={<div className="sli-ds-filters" data-layout="inline"><div className="sli-ds-filters__fields">
        <PeriodControl period={period} timeZone={timeZone} presets={definition.params.find(({ key }) => key === "period")?.presets as PeriodPreset[] | undefined}
          apply={(next) => {
            if (next.preset === "custom" && (!localDateTimeToUtc(next.from!, timeZone) || !localDateTimeToUtc(next.to!, timeZone))) return;
            setAnchor(new Date());
            set({ ...values, period: next });
          }}/>
        <Badge>{zone}</Badge>
        <label className="sli-ds-field"><span>{labels("domain")}</span>
          <select value={text(filters.domain)} onChange={(event) => set({ ...values, domain: event.target.value, scope: event.target.value ? undefined : "all" })}>
            <option value="">{t("reports.filters.all_domains")}</option>
            {paramOptions(definition, "domain", page?.filter_options).map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </label>
        <form className="sli-ds-field" onSubmit={submitSearch}>
          <label className="sli-ds-sr-only" htmlFor="domain-changes-search">{labels("search")}</label>
          <input id="domain-changes-search" type="search" maxLength={256} value={search} placeholder={labels("search")} onChange={(event) => {
            setSearch(event.target.value);
            if (!event.target.value && values.q) set({ ...values, q: undefined });
          }}/>
          <button className="sli-ds-sr-only" type="submit">{labels("submit_search")}</button>
        </form>
        <label className="sli-ds-field"><span>{labels("operation")}</span>
          <select value={text(filters.event_id)} onChange={(event) => set({ ...values, event_id: event.target.value, category: undefined, changes_view: "all" })}>
            <option value="">{labels("any_operation")}</option>
            {operations.map(({ value }) => <option key={value} value={value}>{t(`reports.v2.security.events.chains.actions.${value}` as MessageKey)} · {value}</option>)}
          </select>
        </label>
      </div></div>}
      tabs={<div className="sli-ds-header__meta">
        <TabList label={labels("views")}/>
        <label><input type="checkbox" checked={collapse} onChange={(event) => set({ ...values, repeat_mode: event.target.checked ? "collapsed" : "individual" })}/>{labels("collapse")}</label>
        {["actor", "target", "group"].some((key) => values[key]) ? <Button variant="ghost"
          onClick={() => set({ ...values, actor: undefined, target: undefined, group: undefined })}>
          {labels("clear_pivot")} · {text(values.actor || values.target || values.group)}
        </Button> : null}
      </div>}
      side={chosen}>
      <div className="sli-ds-report__views">
        {data.error && page ? <ErrorLine onRetry={() => void data.fetchNextPage()}/> : null}
        <DataTable caption={title} columns={columns} rows={rows} rowKey={(row) => row.id} wrapCells density={density}
          sort={{ field: "time", direction: values.changes_order === "asc" ? "asc" : "desc" }}
          onSort={() => set({ ...values, changes_order: values.changes_order === "asc" ? "desc" : "asc" })}
          onRowClick={(row) => { if (row.count > 1) setExpanded(expanded === row.id ? "" : row.id); else select(row); }}
          selectedKey={details ? selection?.id : null} total={count}
          toolbar={<div className="sli-ds-field">
            <select aria-label={labels("density")} value={density} onChange={(event) => setDensity(event.target.value === "compact" ? "compact" : "comfortable")}>
              <option value="compact">{labels("compact")}</option><option value="comfortable">{labels("comfortable")}</option>
            </select>
          </div>}
          toolbarEnd={<Button aria-pressed={details} onClick={() => setDetails(!details)}>{labels("details")}</Button>}
          footerControls={<div className="sli-ds-header__actions" role="group" aria-label={labels("rows_per_page")}>
            <span>{labels("rows_per_page")}</span>{pageSizes.map((size) =>
              <button className="sli-ds-chip" type="button" key={size} aria-pressed={size === limit} onClick={() => {
                setLimit(size); setSelection(null); setExpanded(""); setPosition({ query: "", page: 0 });
              }}>{size}</button>)}
          </div>}
          pagination={{ start: pageIndex * limit + 1, busy: data.isFetchingNextPage,
            pageLabel: typeof count === "number" && count > 0 ? t(`${prefix}page`, { page: pageIndex + 1, total: Math.ceil(count / limit) }) : undefined,
            onPrevious: pageIndex ? () => void go(pageIndex - 1) : undefined,
            onNext: page?.has_more ? () => void go(pageIndex + 1) : undefined }}
          renderExpanded={(row, colSpan) => expanded === row.id && row.count > 1
            ? <BatchRows id={row.id} domain={row.domain} params={query} report={definition.key} columns={columns} colSpan={colSpan} select={select}/> : null}/>
        {page?.state === "ok" && !rows.length ? <p role="status">{t("reports.domain_events.empty")}</p> : null}
      </div>
    </ReportLayout>
  </Tabs></PageHeaderContext.Provider>;
}
