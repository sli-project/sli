import { useEffect, useMemo, useState } from "react";
import { useMutation, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { Badge, Button, DataTable, DetailDrawer, FactList, LoadingRegion, PeriodPicker, ReportLayout, TableSkeleton, Tabs, periodBounds, type PeriodValue, type TableColumn } from "../../design-system";
import { FilterToolbar } from "../../design-system/FilterBar";
import { TabList } from "../../design-system/Tabs";
import { t } from "../../i18n";
import { localDateTimeToUtc, utcToLocalDateTimeInput } from "../../shared/date-time";
import { EMPTY_VALUE, formatNumber } from "../../shared/format";
import { useTimeZone } from "../../shared/time-zone";
import { useEffectiveAccess } from "../App";
import { isClosed, problemFacts, problemJournalHref, problemObject, problemSource, problemStatement, problemSteps, problemTime, recorded, type Breakdown, type Problem, type Severity } from "./problems-model";

const REPORT = "security.problems";
const PAGE_SIZE = 50;
const SHOWN_BREAKDOWN = 10;
const SEVERITY_TONE = { critical: "danger", high: "danger", medium: "warning", low: "neutral" } as const;
const FILTERS = ["domain", "cohort", "rule_code", "created_from", "created_to", "entity_id"] as const;
type Tab = "open" | "closed";
type QueueRow = { problem: Problem; key: string; observation?: Breakdown; more?: number; breakdownState?: "loading" | "error" };

function readProblemId() {
  const query = new URLSearchParams(window.location.search);
  const id = Number(query.get("id") ?? window.location.hash.slice(1));
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function updateProblemId(id: number | null) {
  const url = new URL(window.location.href);
  url.searchParams.delete("id");
  url.hash = id ? String(id) : "";
  window.history.replaceState(window.history.state, "", url);
}

function ListError({ message, retry }: { message: string; retry: () => void }) {
  return <div role="alert">{message} <Button onClick={retry}>{t("problems.retry")}</Button></div>;
}

const tabItems = (counts?: Record<Tab, number>) => (["open", "closed"] as const).map((key) => ({
  key, label: t(`problems.${key}`, { count: counts ? formatNumber(counts[key]) : EMPTY_VALUE }),
}));

export function ProblemsUnavailable({ retry }: { retry: () => void }) {
  const [tab, setTab] = useState("open");
  const title = t("problems.title");
  return <Tabs items={tabItems()} active={tab} onChange={setTab}>
    <ReportLayout title={title} tabbed state="error" filters={<FilterToolbar showActions={false}><TabList label={title}/></FilterToolbar>}
      stateView={<ListError message={t("problems.load_failed")} retry={retry}/>}/>
  </Tabs>;
}

function QueueSeverity({ severity }: { severity?: Severity }) {
  return severity && Object.hasOwn(SEVERITY_TONE, severity)
    ? <Badge tone={SEVERITY_TONE[severity]}>{t(`home.queue.${severity}`)}</Badge> : EMPTY_VALUE;
}

export function ProblemsWorkplace({ definition }: { definition: ReportDefinitionDto }) {
  const title = t("problems.title");
  const { timeZone } = useTimeZone();
  const access = useEffectiveAccess();
  const canManage = Boolean(access?.capabilities.includes("investigations.manage"));
  const canJournal = Boolean(access?.capabilities.includes("evidence.exact") && access?.reports?.some((report) => report.report_key === "events.explorer" && report.allowed));
  const canSearch = definition.params.some((param) => param.key === "q");
  const queryClient = useQueryClient();
  const [initial] = useState(() => new URLSearchParams(window.location.search));
  const [tab, setTab] = useState<Tab>(() => initial.get("tab") === "closed" || initial.get("status") === "closed" ? "closed" : "open");
  const [search, setSearch] = useState(() => canSearch ? initial.get("q") ?? "" : "");
  const [appliedSearch, setAppliedSearch] = useState(search);
  const [severity, setSeverity] = useState(() => initial.get("severity") === "high" ? "high" : initial.get("severity") === "critical" ? "critical" : "");
  const [period, setPeriod] = useState<PeriodValue>(() => {
    if (initial.has("time_from") && initial.has("time_to")) return { preset: "custom",
      from: utcToLocalDateTimeInput(initial.get("time_from"), timeZone), to: utcToLocalDateTimeInput(initial.get("time_to"), timeZone) };
    return { preset: "24h" };
  });
  const [now, setNow] = useState(() => new Date());
  const [positions, setPositions] = useState<Array<string | null>>([null]);
  const [selected, setSelected] = useState<number[]>([]);
  const [expanded, setExpanded] = useState<Record<number, "preview" | "all">>({});
  const [hidden, setHidden] = useState<string[]>([]);
  const [cardId, setCardId] = useState(readProblemId);
  const [copyState, setCopyState] = useState<"copied" | "failed" | null>(null);

  const base = useMemo(() => {
    const params = new URLSearchParams({ tz: timeZone });
    for (const key of FILTERS) {
      const value = initial.get(key);
      if (value && definition.params.some((param) => param.key === key)) params.set(key, value);
    }
    return params;
  }, [definition, initial, timeZone]);
  const bounds = useMemo(() => {
    if (period.preset !== "custom") return periodBounds(period, now);
    const from = period.from && localDateTimeToUtc(period.from, timeZone);
    const to = period.to && localDateTimeToUtc(period.to, timeZone);
    return from && to && from < to ? { from, to } : null;
  }, [now, period, timeZone]);
  const params = new URLSearchParams(base);
  params.set("queue_tab", tab);
  params.set("limit", String(PAGE_SIZE));
  for (const [key, value] of Object.entries({ q: appliedSearch.trim(), severity, time_from: bounds?.from, time_to: bounds?.to, cursor: positions.at(-1) })) {
    if (value) params.set(key, value);
  }
  const query = useQuery({ queryKey: ["problems-workplace", "list", params.toString()], queryFn: () => api.reportV2Data(REPORT, params), enabled: Boolean(bounds), retry: false });
  const problems = (query.data?.items ?? []) as Problem[];
  const listFailed = query.isError || ["denied", "error", "unavailable"].includes(query.data?.state ?? "");

  const detailIds = [...new Set([...Object.keys(expanded).map(Number), ...(cardId ? [cardId] : [])])];
  const detailQueries = useQueries({ queries: detailIds.map((id) => {
    const params = new URLSearchParams({ tz: timeZone, queue_tab: "open", id: String(id), limit: "1" });
    const domain = base.get("domain");
    if (domain) params.set("domain", domain);
    return { queryKey: ["problems-workplace", "detail", params.toString()], queryFn: () => api.reportV2Data(REPORT, params), retry: false };
  }) });
  const details = new Map(detailIds.map((id, index) => [id, detailQueries[index]]));
  const cardQuery = cardId ? details.get(cardId) : undefined;
  const card = cardQuery?.data?.items[0] as Problem | undefined;
  const cardPreview = card ?? problems.find((problem) => problem.id === cardId);

  function clearPage() {
    setSelected([]);
    setExpanded({});
  }
  function resetList() {
    clearPage();
    setPositions([null]);
  }
  function openCard(id: number | null) {
    setCopyState(null);
    setCardId(id);
    updateProblemId(id);
  }
  const mutation = useMutation({
    mutationFn: ({ ids, status }: { ids: number[]; status: "closed" | "active" }) => api.updateProblems(ids, status),
    onSuccess: async (_, { ids }) => {
      if (cardId && ids.includes(cardId)) openCard(null);
      resetList();
      await queryClient.invalidateQueries({ queryKey: ["problems-workplace"] });
    },
  });

  useEffect(() => {
    const timer = window.setTimeout(() => setAppliedSearch(search), 180);
    return () => window.clearTimeout(timer);
  }, [search]);
  useEffect(() => {
    const read = () => { setCardId(readProblemId()); setCopyState(null); };
    window.addEventListener("hashchange", read);
    window.addEventListener("popstate", read);
    return () => {
      window.removeEventListener("hashchange", read);
      window.removeEventListener("popstate", read);
    };
  }, []);

  const selectedSet = new Set(selected);
  const allSelected = problems.length > 0 && problems.every(({ id }) => selectedSet.has(id));
  const selectionDisabled = mutation.isPending || search !== appliedSearch || query.isFetching || listFailed;
  const toggle = (id: number, checked: boolean) => setSelected((previous) => checked ? [...previous, id] : previous.filter((value) => value !== id));
  const expand = (id: number) => setExpanded((previous) => {
    if (!previous[id]) return { ...previous, [id]: "preview" };
    const next = { ...previous };
    delete next[id];
    return next;
  });
  const columns: TableColumn<QueueRow>[] = [
    { key: "select", label: "", width: "var(--sli-space-10)", renderHeader: () => canManage && <span className="sli-ds-table__cell-actions">
      <input type="checkbox" aria-label={t("problems.select_all")} disabled={!problems.length || selectionDisabled} checked={allSelected}
        ref={(input) => { if (input) input.indeterminate = selected.length > 0 && !allSelected; }}
        onChange={(event) => setSelected(event.currentTarget.checked ? problems.map(({ id }) => id) : [])}/>
    </span>, render: ({ problem, observation, more, breakdownState }) => !observation && !more && !breakdownState && <span className="sli-ds-table__cell-actions" onClick={(event) => event.stopPropagation()}>
      {(problem.kind === "brute" && (problem.address_count ?? 0) > 1 || problem.kind === "spray" && (problem.accounts ?? 0) > 1)
        && <Button variant="ghost" aria-expanded={Boolean(expanded[problem.id])}
          aria-label={t(expanded[problem.id] ? "problems.collapse" : "problems.expand", { object: problemObject(problem) })}
          onClick={() => expand(problem.id)}>{expanded[problem.id] ? "▾" : "▸"}</Button>}
      {canManage && <input type="checkbox" checked={selectedSet.has(problem.id)} disabled={selectionDisabled}
        aria-label={t("problems.select", { object: problemObject(problem) })}
        onChange={(event) => toggle(problem.id, event.currentTarget.checked)}/>}
    </span> },
    { key: "severity", label: t("problems.severity"), width: "13%", render: ({ problem, observation, more, breakdownState }) => !observation && !more && !breakdownState && <QueueSeverity severity={problem.severity}/> },
    { key: "object", label: t("problems.object"), width: "19%", render: ({ problem, observation, more, breakdownState }) =>
      breakdownState ? null : more ? <Button variant="ghost" onClick={() => setExpanded((value) => ({ ...value, [problem.id]: "all" }))}>{t("problems.more", { count: formatNumber(more) })}</Button>
        : observation ? observation.object || (observation.accounts ? t("problems.accounts_value", { count: formatNumber(observation.accounts) }) : EMPTY_VALUE) : problemObject(problem) },
    { key: "recorded", label: t("problems.recorded"), render: ({ problem, observation, more, breakdownState }) => breakdownState === "error"
      ? <Button variant="ghost" onClick={() => void details.get(problem.id)?.refetch()}>{t("problems.breakdown_failed")}</Button>
      : breakdownState === "loading" ? t("state.loading") : !more &&
      (observation ? t("problems.attempts_value", { count: formatNumber(observation.attempts) }) : recorded(problem)) },
    { key: "source", label: t("problems.source"), width: "16%", render: ({ problem, observation, more, breakdownState }) => !more && !breakdownState && (observation ? observation.source || EMPTY_VALUE : problemSource(problem)) },
    { key: "time", label: t("problems.time"), width: "11%", render: ({ problem, observation, more, breakdownState }) => !more && !breakdownState && problemTime(observation?.at ?? problem.last_seen_utc, timeZone, now) },
    { key: "action", label: t(tab === "closed" ? "problems.closed_column" : "problems.action"), width: "18%",
      render: ({ problem, observation, more, breakdownState }) => !observation && !more && !breakdownState && (tab === "closed"
        ? problem.closed_at ? t("problems.closed_at", { time: problemTime(problem.closed_at, timeZone, now, true) }) : EMPTY_VALUE
        : problem.kind === "other" ? problem.next || EMPTY_VALUE : t(`problems.action.${problem.kind}`)) },
  ];
  const rows = listFailed ? [] : problems.flatMap<QueueRow>((problem) => {
    const key = String(problem.id);
    const row = { problem, key };
    if (!expanded[problem.id]) return [row];
    const result = details.get(problem.id);
    if (result?.isPending || result?.isError) return [row, { problem, key: `${key}-state`, breakdownState: result.isError ? "error" : "loading" }];
    const breakdown = (result?.data?.items[0] as Problem | undefined)?.breakdown ?? [];
    const limit = expanded[problem.id] === "all" ? breakdown.length : SHOWN_BREAKDOWN;
    return [
      row,
      ...breakdown.slice(0, limit).map((observation, index) => ({ problem, key: `${key}-${index}`, observation })),
      ...(breakdown.length > limit ? [{ problem, key: `${key}-more`, more: breakdown.length - limit }] : []),
    ];
  });

  const counts = !listFailed ? query.data?.queue_counts : undefined;
  const tabs = tabItems(counts);
  const journal = card && canJournal ? problemJournalHref(card, timeZone) : null;
  const steps = card && !isClosed(card) ? problemSteps(card) : [];
  const facts = card ? problemFacts(card, timeZone) : [];
  const onTab = (key: string) => {
    if (key === tab) return;
    setTab(key === "closed" ? "closed" : "open");
    resetList();
    openCard(null);
  };
  const onCopy = async () => {
    if (!card?.addresses?.length) return;
    try {
      await navigator.clipboard.writeText(card.addresses.join("\n"));
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };
  const loading = bounds && query.isPending;
  const resultState = !bounds || loading ? "ok" : listFailed ? "error" : problems.length ? "ok" : "empty";

  return <Tabs items={tabs} active={tab} onChange={onTab}>
    <ReportLayout title={title} tabbed dockDrawer state={resultState}
      actions={<Button onClick={() => { resetList(); setNow(new Date()); if (period.preset === "custom" && positions.length === 1) void query.refetch(); }}>{t("problems.refresh")}</Button>}
      filters={<FilterToolbar showActions={selected.length > 0} actions={canManage && <>
        <Button variant="primary" disabled={selectionDisabled} onClick={() => mutation.mutate({ ids: selected, status: tab === "closed" ? "active" : "closed" })}>
          {t(tab === "closed" ? "problems.bulk_reopen" : "problems.bulk_close", { count: formatNumber(selected.length) })}
        </Button>
        <Button disabled={mutation.isPending} onClick={() => setSelected([])}>{t("problems.clear")}</Button>
      </>}>
        <TabList label={title}/>
        {canSearch && <label className="sli-ds-field" data-kind="text">
          <input type="search" value={search} maxLength={256} aria-label={t("problems.search")} placeholder={t("problems.search")}
            onChange={(event) => { setSearch(event.currentTarget.value); resetList(); }}/>
        </label>}
        <label className="sli-ds-field" data-kind="select">
          <select aria-label={t("problems.severity")} value={severity} onChange={(event) => { setSeverity(event.currentTarget.value); resetList(); }}>
            <option value="">{t("problems.any")}</option>
            <option value="high">{t("problems.high")}</option>
            <option value="critical">{t("problems.critical")}</option>
          </select>
        </label>
        <details className="sli-ds-table__columns">
          <summary className="sli-ds-button">{t(`period.${period.preset}`)}</summary>
          <div><PeriodPicker label={t("problems.period")} value={period} precision="datetime-local"
            onChange={(value) => { setPeriod(value); setNow(new Date()); resetList(); }}/></div>
        </details>
        <details className="sli-ds-table__columns">
          <summary className="sli-ds-button">{t("table.columns")}</summary>
          <div role="group" aria-label={t("table.columns")}>{columns.slice(1).map(({ key, label }) => <label key={key}>
            <input type="checkbox" checked={!hidden.includes(key)} disabled={!hidden.includes(key) && hidden.length >= columns.length - 2}
              onChange={(event) => setHidden(event.currentTarget.checked ? hidden.filter((value) => value !== key) : [...hidden, key])}/> {label}
          </label>)}</div>
        </details>
      </FilterToolbar>}
      stateView={listFailed ? <ListError message={t("problems.load_failed")} retry={() => void query.refetch()}/> : <div role="status">{t("problems.empty")}</div>}
      drawer={<DetailDrawer dock open={cardId !== null} title={cardPreview ? problemObject(cardPreview) === EMPTY_VALUE ? recorded(cardPreview) : problemObject(cardPreview) : title}
        subtitle={cardPreview && <QueueSeverity severity={cardPreview.severity}/>} onClose={() => openCard(null)}
        footer={card && <>
          {Boolean(card.addresses?.length) && <Button onClick={() => void onCopy()}>{t("problems.copy", { count: formatNumber(card.addresses!.length) })}</Button>}
          {canManage && <Button variant="primary" disabled={mutation.isPending} onClick={() => mutation.mutate({ ids: [card.id], status: isClosed(card) ? "active" : "closed" })}>{t(isClosed(card) ? "problems.reopen" : "problems.close")}</Button>}
          {journal && <a className="sli-ds-button" href={journal}>{t("problems.journal")}</a>}
        </>}>
        {cardQuery?.isPending ? <span aria-busy="true">{t("state.loading")}</span> : cardQuery?.isError || !card
          ? <ListError message={t("problems.detail_failed")} retry={() => void cardQuery?.refetch()}/>
          : <>
            <section><h3>{t("problems.detail")}</h3>
              <p>{problemStatement(card, timeZone, now)}</p></section>
            {facts.length > 0 && <section><h3>{t("problems.facts")}</h3><FactList facts={facts}/></section>}
            {steps.length > 0 && <section><h3>{t("problems.action")}</h3><ol>{steps.map((step) => <li key={step}>{step}</li>)}</ol></section>}
            {copyState && <span role={copyState === "failed" ? "alert" : "status"}>{t(copyState === "failed" ? "problems.copy_failed" : "problems.copied")}</span>}
            {mutation.isError && <div role="alert">{t("problems.change_failed")}</div>}
          </>}
      </DetailDrawer>}>
      {mutation.isError && !cardId && <div role="alert">{t("problems.change_failed")}</div>}
      {loading ? <LoadingRegion><TableSkeleton/></LoadingRegion> : bounds && <DataTable compact columns={columns.filter(({ key }) => !hidden.includes(key))} rows={rows} rowKey={(row) => row.key}
        isSubRow={(row) => Boolean(row.observation || row.more || row.breakdownState)} selectedKey={cardId ? String(cardId) : null}
        caption={title} onRowClick={({ problem }) => openCard(problem.id)}
        total={query.data?.filtered_count} pagination={{
          start: (positions.length - 1) * PAGE_SIZE + 1,
          end: (positions.length - 1) * PAGE_SIZE + problems.length,
          busy: selectionDisabled,
          onPrevious: positions.length > 1 ? () => { clearPage(); setPositions(positions.slice(0, -1)); } : undefined,
          onNext: query.data?.next_cursor ? () => { clearPage(); setPositions([...positions, query.data!.next_cursor]); } : undefined,
        }}/>}
    </ReportLayout>
  </Tabs>;
}
