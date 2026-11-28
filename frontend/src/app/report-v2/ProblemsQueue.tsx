import { DateInput } from "../../design-system/PeriodPicker";
import { useMemo, useState, type FormEvent } from "react";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto, ReportResultDto } from "../../api/report-v2-types";
import { Button, Checkbox, DataTable, DetailDrawer, FactList, FilterChips, Pager, ReportLayout, Select, SeverityBadge, StateView,
  periodBounds, type PeriodValue, type TableColumn, useOverlays } from "../../design-system";
import { getLocale, t } from "../../i18n";
import { eventSemanticText } from "../../i18n/event-metadata";
import { browserTimeZone, formatClockWithOffset, formatDateTime, formatTableTime, localDateTimeToUtc } from "../../shared/date-time";
import { EMPTY_VALUE, formatNumber } from "../../shared/format";
import { useEffectiveAccess, useTimeZone } from "../App";
import { ReportDenied } from "./ReportDenied";
import { FirstAdSource, isEmptyFirstAdReportResult, useFirstAdSource } from "../first-ad-source";
import { statusLabel } from "../problem-lifecycle";
import "./ProblemsQueue.css";

const views = ["all", "open", "active", "deferred", "resolved"] as const;
const states = ["new", "active", "deferred", "closed", "false_positive"] as const;
type View = typeof views[number];
type State = typeof states[number];
type Decision = Parameters<typeof api.decideProblems>[0];
type RecordRow = Record<string, unknown>;
type Problem = ReturnType<typeof problemRow>;

const asText = (value: unknown) => typeof value === "string" && value.trim() && value !== "-" ? value.trim() : "";
const text = (value: unknown) => asText(value) || EMPTY_VALUE;
const record = (value: unknown): RecordRow => value && typeof value === "object" && !Array.isArray(value) ? value as RecordRow : {};
const asCount = (value: unknown) => value == null || !Number.isSafeInteger(Number(value)) || Number(value) < 0 ? null : Number(value);
const stateOf = (raw: string): State => raw === "review" ? "active" : raw === "confirmed" || raw === "repeated" ? "new" : states.find((state) => state === raw) ?? "new";
const stateName = (state: State) => t(`problems.queue.state.${state}`);
const severityOptions = ["critical", "high", "medium", "low"] as const;
const hostText = (value: unknown) => asText(value).slice(0, 256);

function distinctNames(value: unknown) {
  const names = new Map<string, string>();
  if (Array.isArray(value)) {
    for (const item of value) {
      const name = hostText(item);
      const key = name.toLowerCase();
      if (name && name !== EMPTY_VALUE && !names.has(key)) names.set(key, name);
    }
  }
  return [...names.values()];
}

function readableName(value: string) {
  // Common UTF-8 decoding errors in Windows-1251 and Windows-1252, plus invalid/control characters.
  return !/[\p{Cc}\p{Cf}\p{Cs}\uFFFD]|(?:[РС][\u0400-\u045f\u2010-\u203f]){2}|(?:[ÐÑ][\u0080-\u00bf\u2010-\u203f]){2}|[ÃÂ][\u0080-\u00bf]/u.test(value);
}

function eventQuantity(count: number) {
  const plural = new Intl.PluralRules(getLocale()).select(count);
  return t(`problems.queue.eventCount.${plural === "zero" || plural === "two" ? "other" : plural}`, { count: formatNumber(count) });
}

function queueValues(values: string[], total: number | null) {
  if (!values.length) return EMPTY_VALUE;
  const count = Math.max(values.length, total ?? 0) - Math.min(values.length, 2);
  const full = values.join(", ");
  return <span data-problems-queue-values ref={(node) => {
    const cell = node?.closest("td");
    if (!cell) return;
    cell.title = full;
    return () => cell.removeAttribute("title");
  }}>
    <span>{values.slice(0, 2).join(", ")}</span>
    {count > 0 ? <span>{t("problems.queue.moreValues", { count: formatNumber(count) })}</span> : null}
  </span>;
}

function problemRow(row: RecordRow) {
  const attack = record(row.queue_attack);
  const isAttack = Object.keys(attack).length > 0;
  const rawAccounts = distinctNames(attack.accounts);
  const accounts = rawAccounts.filter(readableName);
  const sources = distinctNames(attack.addresses);
  const addresses = sources.join(", ") || hostText(row.actor_text);
  const accountCount = asCount(attack.account_count);
  const rule = asText(row.rule_code);
  const messages = record(row.presentation_messages);
  const displayText = (value: unknown, code: unknown) => {
    const label = asText(value);
    return label === EMPTY_VALUE || label === rule || label === code || /^semantic\.[\w.-]+$/u.test(label) ? "" : label;
  };
  const rawTitle = displayText(row.title_text, record(messages.title_text).code) || t("problems.queue.title");
  const brute = rule === "semantic.qw.password-brute-force";
  const title = brute && !readableName(rawTitle) ? t("security.problems.presentation.brute_title") : rawTitle;
  const titleContainsAccount = accounts.some((name) => rawTitle.toLowerCase().includes(name.toLowerCase()));
  const baseTitle = brute && accounts.length > 1 && titleContainsAccount ? t("security.problems.presentation.brute_title") : title;
  const accountList = accounts.slice(0, 3).join(", ");
  const readableCount = Math.max(accounts.length, (accountCount ?? 0) - (rawAccounts.length - accounts.length));
  const more = readableCount - Math.min(accounts.length, 3);
  const accountSummary = accountList && more ? t("problems.queue.moreAccounts", { names: accountList, count: formatNumber(more) }) : accountList;
  const titleAccounts = brute && baseTitle === rawTitle && accounts.length === 1 && titleContainsAccount ? "" : accountSummary;
  const cardTitle = [baseTitle, titleAccounts].filter(Boolean).join(" · ");
  const participant = hostText(row.queue_participant);
  const group = hostText(row.queue_group);
  const entity = hostText(row.entity_text);
  const entities = distinctNames(Array.isArray(row.entity_messages)
    ? row.entity_messages.map((value) => typeof value === "string" ? value : record(value).text) : []);
  const what = record(messages.what_happened);
  const parameters = record(what.params);
  const nextCode = record(messages.next_text).code;
  const next = nextCode === "security.problems.presentation.default_next" ? "" :
    nextCode === "security.problems.presentation.password_next" && rule === "semantic.qw.password-spray" && sources.length === 1
      ? t("problems.queue.sprayAction", { source: sources[0] }) : displayText(row.next_text, nextCode);
  return {
    id: Number(row.id), state: stateOf(asText(row.status)), severity: row.severity, title, cardTitle,
    objects: accounts.length ? accounts : entities.length ? entities : [entity].filter(Boolean),
    actors: sources.length ? sources : [addresses].filter(Boolean),
    objectCount: accounts.length ? readableCount : null, addressCount: asCount(attack.address_count),
    assignee: asText(row.assigned_to), cohort: asText(row.problem_cohort), isAttack, fileEpisode: rule === "semantic.qw.file-ransom",
    evidence: asCount(isAttack ? attack.event_count : row.evidence_total), occurrences: asCount(row.occurrence_count) ?? 1,
    first: asText(row.first_seen_utc), last: asText(row.last_seen_utc), until: asText(row.deferred_until),
    object: accounts.join(", ") || [entities.length > 1 ? entities.join(", ") : participant || entity, group].filter(Boolean).join(", "),
    source: (isAttack ? addresses : "") || hostText(parameters.source) || hostText(parameters.computer),
    description: displayText(row.what_happened, what.code), whatCode: asText(what.code), next,
    history: Array.isArray(row.status_history) ? row.status_history.map(record).filter((entry) =>
      !(entry.changed_by === "semantic-worker" && entry.note === "created from enabled semantic scenario")) : [],
  };
}

function timeLabel(value: string, zone: string, short = false) {
  if (!value || !Number.isFinite(Date.parse(value))) return EMPTY_VALUE;
  if (short) return formatTableTime(value, zone);
  return formatDateTime(value, zone, { withTime: true, seconds: true });
}

function historyAction(entry: RecordRow, zone: string) {
  const rawNote = asText(entry.note);
  let note = rawNote;
  let decision: RecordRow = {};
  if (rawNote.startsWith("sli.queue:")) {
    try { decision = record(JSON.parse(rawNote.slice("sli.queue:".length))); note = asText(decision.comment); } catch { /* Preserve the original note. */ }
  }
  const classification = asText(decision.classification);
  const reason = classification === "fixed" || classification === "expected" || classification === "false_positive" ? t(`problems.queue.reason.${classification}`) : "";
  const statuses = [entry.old_status, entry.new_status].flatMap((value) => typeof value === "string" ? [value === "deferred" ? stateName("deferred") : statusLabel(value)] : []);
  const until = asText(decision.until);
  const assignment = decision.assignment_changed ? t("problems.queue.assignment", { from: text(decision.old_assignee), to: text(decision.new_assignee) }) : "";
  if (entry.changed_by === "system" && note === "created from event") note = t("reports.problemLifecycle.createdFromEvent");
  if (entry.changed_by === "system" && note === "repeat evidence added") note = t("reports.problemLifecycle.repeatEvidence");
  if (note === "risk_acceptance_expired") note = t("reports.risk.expired");
  if (note === "risk_acceptance_revoked") note = t("reports.risk.revoked");
  return [statuses[0] === statuses[1] && assignment ? "" : [...new Set(statuses)].join(" → "), reason, assignment, until && timeLabel(until, zone), note].filter(Boolean).join(" · ");
}

function setOpenEntityScope(params: URLSearchParams, entity: string | null) {
  if (entity) {
    params.set("entity_id", entity);
    params.set("population", "open");
  }
}

export function ProblemsQueue({ definition, initialSearch }: { definition: ReportDefinitionDto; initialSearch?: string }) {
  const { timeZone: preference } = useTimeZone();
  const timeZone = preference === "browser" ? browserTimeZone() : preference;
  const access = useEffectiveAccess();
  const canManage = Boolean(access?.capabilities.includes("investigations.manage"));
  const ownerAllowed = definition.params.some(({ key }) => key === "queue_assignee");
  const [initial] = useState(() => new URLSearchParams(initialSearch ?? window.location.search));
  const openEntity = initial.get("population") === "open" ? initial.get("entity_id") : null;
  const [view, setView] = useState<View>(() => {
    const chosen = views.find((item) => item === initial.get("queue_view"));
    if (chosen) return chosen;
    const status = initial.get("status");
    if (initial.get("risk") === "accepted") return "deferred";
    if (status === "active") return "active";
    if (status === "closed" || status === "false_positive") return "resolved";
    if (initial.get("population") === "attention" || status === "new") return "open";
    return ["id", "entity_id", "cohort", "created_from", "created_to"].some((key) => initial.has(key)) ? "all" : "open";
  });
  const [domain, setDomain] = useState(initial.get("domain") ?? String(definition.default_domain_id ?? ""));
  const [severity, setSeverity] = useState(initial.get("severity") ?? "");
  const [owner, setOwner] = useState(initial.get("queue_assignee") ?? "");
  const [search, setSearch] = useState(initial.get("q") ?? "");
  const [draft, setDraft] = useState(search);
  const [period, setPeriod] = useState<PeriodValue>(initial.has("time_from") ? { preset: "custom" } : { preset: "7d" });
  const [bounds, setBounds] = useState(() => {
    const from = initial.get("time_from"), to = initial.get("time_to");
    return from && to ? { from, to } : (["id", "entity_id", "created_from", "created_to", "cohort", "time_from", "time_to"].some((key) => initial.has(key)) ? null : periodBounds(period));
  });
  const [compact, setCompact] = useState(true);
  const [fold, setFold] = useState(initial.get("fold") !== "false");
  const [hidden, setHidden] = useState<string[]>([]);
  const [size, setSize] = useState(50);
  const [direction, setDirection] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState<{ key: string; cursors: string[] }>({ key: "", cursors: [] });
  const [expanded, setExpanded] = useState<number | null>(null);
  const [selected, setSelected] = useState<number | null>(() => {
    const id = Number(initial.get("id"));
    return Number.isSafeInteger(id) && id > 0 ? id : null;
  });
  const [checked, setChecked] = useState<number[]>([]);
  const clearRows = () => { setPage({ key: "", cursors: [] }); setExpanded(null); setSelected(null); setChecked([]); };
  const changeView = (next: string) => {
    const chosen = views.find((item) => item === next);
    if (!chosen || chosen === view) return;
    const url = new URL(window.location.href);
    url.searchParams.set("queue_view", chosen);
    window.history.replaceState(window.history.state, "", url);
    setView(chosen);
    clearRows();
  };
  const select = setSelected;
  const refresh = () => {
    if (period.preset !== "custom" && bounds) {
      setBounds(periodBounds(period));
      setPage({ key: "", cursors: [] });
    } else void list.refetch();
  };

  const base = useMemo(() => {
    const params = new URLSearchParams({ queue_view: view, tz: timeZone, limit: String(size), direction, sort: "last_seen_utc" });
    if (domain) params.set("domain", domain);
    if (severity) params.set("severity", severity);
    if (owner && ownerAllowed) params.set("queue_assignee", owner);
    if (search && definition.params.some(({ key }) => key === "q")) params.set("q", search);
    if (!fold) params.set("fold", "false");
    for (const key of ["id", "entity_id", "cohort", "rule_code", "created_from", "created_to", "show_suppressed", "risk", "time_from", "time_to"]) {
      const value = initial.get(key);
      if (value && value !== "accepted" && definition.params.some((param) => param.key === key)) params.set(key, value);
    }
    setOpenEntityScope(params, openEntity);
    if (bounds) { params.set("time_from", bounds.from); params.set("time_to", bounds.to); }
    return params.toString();
  }, [view, timeZone, size, direction, domain, severity, owner, ownerAllowed, search, definition.params, fold, initial, openEntity, bounds]);
  const cursors = page.key === base ? page.cursors : [];
  const cursor = cursors.at(-1);
  const list = useQuery({ queryKey: ["report-v2", "data", definition.key, base, cursor], retry: false, queryFn: () => {
    const params = new URLSearchParams(base);
    if (cursor) params.set("cursor", cursor);
    return api.reportV2Data(definition.key, params);
  } });
  const result = list.data;
  const users = useQuery({ queryKey: ["findings", "responsibles"], queryFn: api.riskResponsibles, enabled: canManage && ownerAllowed, retry: false });
  const rows = (result?.items ?? []).map(problemRow);
  const representative = rows.find((row) => row.id === expanded);
  const members = useInfiniteQuery({ queryKey: ["report-v2", "data", definition.key, "members", base, representative?.cohort, representative?.state, representative?.assignee], retry: false,
    enabled: Boolean(representative?.cohort), queryFn: ({ pageParam }) => {
      const params = new URLSearchParams(base);
      params.set("cohort", representative!.cohort);
      params.set("limit", "200");
      if (pageParam) params.set("cursor", pageParam);
      const state = representative!.state;
      params.set("queue_view", state === "new" ? "open" : state === "closed" || state === "false_positive" ? "resolved" : state);
      if (state === "closed" || state === "false_positive") params.set("status", state);
      if (ownerAllowed) params.set("queue_assignee", representative!.assignee || "-");
      return api.reportV2Data(definition.key, params);
    }, initialPageParam: null as string | null, getNextPageParam: (page) => page.has_more ? page.next_cursor : null });
  const details = useQuery({ queryKey: ["report-v2", "data", definition.key, "finding", selected, domain, timeZone, openEntity], retry: false, enabled: selected !== null,
    queryFn: async () => {
      const params = new URLSearchParams({ queue_view: "all", id: String(selected), limit: "1", tz: timeZone });
      if (domain) params.set("domain", domain);
      setOpenEntityScope(params, openEntity);
      return (await api.reportV2Data(definition.key, params)).items[0];
    } });
  const detailRow = details.data ? problemRow(details.data) : null;
  const expandedRows = members.data?.pages.flatMap((page) => page.items.map(problemRow)).filter((member) => member.id !== expanded && member.state === representative?.state) ?? [];
  const visibleRows = rows.flatMap((row) => row.id !== expanded ? [row] : [row, ...expandedRows]);
  const active = detailRow ?? visibleRows.find((row) => row.id === selected);
  const position = visibleRows.findIndex((row) => row.id === selected);
  const denied = list.error instanceof ApiResponseError && [401, 403].includes(list.error.status) || result?.state === "denied";
  const error = list.isError || result?.state === "error";
  const firstAdSource = useFirstAdSource(initial, initial.size === 0 && !cursor && !domain
    && view === "open" && !severity && !owner && !search && period.preset === "7d"
    && definition.access?.allowed !== false && list.isSuccess && !list.isFetching && isEmptyFirstAdReportResult(result));
  const incomplete = (result?.state === "not_collected" || result?.state === "partial" || result?.state === "stale" || result?.state === "processing") && rows.length === 0;
  const counts = incomplete ? {} : record(result?.series?.queue_counts);
  const names = new Set([...(result?.filter_options?.queue_assignee?.map(({ value }) => value) ?? []), ...(users.data?.items.map(({ username }) => username) ?? []), ...rows.map((row) => row.assignee), owner]);
  const client = useQueryClient();
  const { openModal, closeModal } = useOverlays();
  const update = useMutation({ mutationFn: (payload: Decision) => api.decideProblems(payload), onSuccess: async () => {
    closeModal(); setChecked([]);
    await Promise.all([client.invalidateQueries({ queryKey: ["report-v2", "data", definition.key] }), client.invalidateQueries({ queryKey: ["home", "summary"] })]);
  } });
  const decide = (kind: "state" | "assign" | "defer", ids: number[], choose?: State) => {
    if (!canManage || !ids.length) return;
    update.reset();
    const save = (decision: Decision) => update.mutateAsync(decision).then(() => true, () => false);
    openModal({ title: t(`problems.queue.action.${kind}`), bodyOwnsForm: true, body: <DecisionForm kind={kind} choose={choose} ids={ids}
      current={ids.length === 1 && ids[0] === active?.id ? active?.assignee : undefined} zone={timeZone} onSave={save}/> });
  };
  const columns: TableColumn<Problem>[] = [
    ...(canManage ? [{ key: "select", label: "", width: "var(--sli-space-10)", render: (row: Problem) => <Checkbox aria-label={t("problems.queue.selectNumber", { id: row.id })} checked={checked.includes(row.id)} disabled={checked.length >= 200 && !checked.includes(row.id)} onClick={(event) => event.stopPropagation()} onChange={(event) => setChecked((old) => event.target.checked ? [...old, row.id] : old.filter((id) => id !== row.id))}/> }] : []),
    { key: "severity", label: t("problems.queue.severity"), width: "calc(var(--sli-space-10) * 2 + var(--sli-space-6))", render: (row) => <SeverityBadge severity={row.severity}/> },
    { key: "title", label: t("problems.queue.title"), render: (row) => <div data-problems-queue-title>
      {fold && row.cohort && row.occurrences > 1 ? <Button variant="ghost" aria-expanded={expanded === row.id} aria-label={t(expanded === row.id ? "problems.queue.collapse" : "problems.queue.expand", { id: row.id })} onClick={(event) => { event.stopPropagation(); setExpanded(expanded === row.id ? null : row.id); }}>{expanded === row.id ? "⌄" : "›"}</Button> : null}
      <a title={row.title} href={`/app/report/security.problems?${new URLSearchParams({ id: String(row.id), ...(domain ? { domain } : {}) })}`} onClick={(event) => {
        event.stopPropagation();
        if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault(); select(row.id);
      }}>{row.title}</a>
      {fold && row.cohort && row.occurrences > 1 && (!row.isAttack || row.occurrences !== row.evidence) ? <span>×{formatNumber(row.occurrences)}</span> : null}
    </div> },
    { key: "entities", label: t("problems.queue.object"), width: "11.5%", render: (row) => queueValues(row.objects, row.objectCount) },
    { key: "actor", label: t("problems.queue.actor"), width: "11%", render: (row) => queueValues(row.actors, row.addressCount) },
    { key: "last_seen_utc", label: t("problems.queue.latest"), width: "9.5%", sortable: true, render: (row) => timeLabel(row.last, timeZone, true) },
    { key: "evidence", align: "end", label: t("problems.queue.evidence"), width: "8.2%", render: (row) => {
      if (!row.evidence) return EMPTY_VALUE;
      const label = eventQuantity(row.evidence);
      return <button className="sli-ds-link" type="button" aria-label={label} title={label}
        onClick={(event) => { event.stopPropagation(); select(row.id); }}>{formatNumber(row.evidence)}</button>;
    } },
    { key: "state", label: t("problems.queue.status"), width: "8%", render: (row) => stateName(row.state) },
    { key: "owner", label: t("problems.queue.owner"), width: "10.5%", value: (row) => row.assignee },
  ];
  const availableColumns = columns.filter(({ key }) => key !== "owner" || ownerAllowed);
  const count = incomplete ? null : result?.filtered_count;
  const totalPages = typeof count === "number" ? Math.max(1, Math.ceil(count / size)) : null;
  const controls = !denied ? <>
    <form className="sli-ds-list-filters" onSubmit={(event) => { event.preventDefault(); setSearch(draft.trim()); clearRows(); }}>
      <span className="sli-ds-chip">{formatClockWithOffset(new Date(), timeZone).zone}</span>
      {definition.params.some(({ key }) => key === "q") ? <input aria-label={t("problems.queue.search")} type="search" maxLength={256} placeholder={t("problems.queue.search")} value={draft} onChange={(event) => { setDraft(event.target.value); if (!event.target.value) { setSearch(""); clearRows(); } }}/> : null}
      <div className="sli-ds-control-field"><span>{t("problems.queue.severity")}</span>
        <Select label={t("problems.queue.severity")} value={severity} onChange={(value) => { setSeverity(value); clearRows(); }}
          options={[{ value: "", label: t("filters.any") }, ...severityOptions.map((value) => ({ value, label: t(`shell.severity.${value}`) }))]}/>
      </div>
      {ownerAllowed ? <div className="sli-ds-control-field"><span>{t("problems.queue.owner")}</span>
        <Select label={t("problems.queue.owner")} value={owner} onChange={(value) => { setOwner(value); clearRows(); }}
          options={[{ value: "", label: t("filters.any") }, { value: "-", label: t("security.problems.assignee.unassigned") },
            ...[...names].filter((name) => name && name !== "-").sort().map((name) => ({ value: name, label: name }))]}/>
      </div> : null}
    </form>
    <div className="sli-ds-list-toolbar">
      <FilterChips label={t("problems.queue.views")} value={view}
        items={views.map((item) => ({ key: item, label: t(`problems.queue.view.${item}`),
          count: asCount(counts[item]) === null ? undefined : formatNumber(Number(counts[item])) }))}
        onChange={changeView}/>
      <div className="sli-ds-header__actions">
      <Checkbox checked={fold} onChange={(event) => { setFold(event.target.checked); clearRows(); }}>{t("problems.queue.fold")}</Checkbox>
      <Select label={t("problems.queue.density")} value={compact ? "compact" : "standard"} onChange={(value) => setCompact(value === "compact")}
        options={[{ value: "compact", label: t("problems.queue.compact") }, { value: "standard", label: t("problems.queue.standard") }]}/>
      <details className="sli-ds-table__columns"><summary className="sli-ds-button">{t("table.columns")}</summary>
        <div role="group" aria-label={t("table.columns")}>{availableColumns.filter(({ key }) => !["select", "title"].includes(key)).map(({ key, label }) =>
          <Checkbox key={key} checked={!hidden.includes(key)} onChange={(event) => setHidden((old) => event.target.checked ? old.filter((item) => item !== key) : [...old, key])}>{label}</Checkbox>)}</div>
      </details>
      <Button aria-pressed={selected !== null} disabled={selected === null && !rows.length} onClick={() => select(selected === null ? rows[0].id : null)}>{t("problems.queue.details")}</Button>
    </div></div>
    {checked.length ? <div className="sli-ds-list-toolbar" role="group" aria-label={t("problems.queue.bulk")}>
      <span>{t("problems.queue.selected", { count: checked.length })}</span><div className="sli-ds-header__actions">
        <Button onClick={() => decide("state", checked)}>{t("problems.queue.action.state")}</Button>
        {ownerAllowed ? <Button onClick={() => decide("assign", checked)}>{t("problems.queue.action.assign")}</Button> : null}
        <Button onClick={() => decide("defer", checked)}>{t("problems.queue.action.defer")}</Button>
      </div>
    </div> : null}
  </> : null;
  const footer = <Pager pageSize={{ value: size, options: [25, 50, 100, 200], onChange: (value) => { setSize(value); clearRows(); } }}
    label={t("table.page", { page: cursors.length + 1, total: totalPages ?? EMPTY_VALUE })} busy={list.isFetching}
    onPrevious={cursors.length ? () => { setExpanded(null); setChecked([]); select(null); setPage({ key: base, cursors: cursors.slice(0, -1) }); } : undefined}
    onNext={result?.next_cursor ? () => { setExpanded(null); setChecked([]); select(null); setPage({ key: base, cursors: [...cursors, result.next_cursor!] }); } : undefined}/>;

  const domainPicker = !denied ? <Select label={t("problems.queue.domain")} value={domain}
    onChange={(value) => { setDomain(value); clearRows(); }}
    options={[{ value: "", label: t("reports.filters.all_domains") }, ...(definition.filter_options.domain ?? [])]}/> : undefined;

  return <ReportLayout title={definition.title} split showDomain={false} domainPicker={domainPicker}
      controls={denied ? {} : { refreshing: list.isFetching, onRefresh: refresh, period: {
        value: period.preset === "custom" && !period.from && bounds ? { preset: "custom", ...bounds } : period,
        precision: "datetime-local", showPrevious: false, onChange: (value) => {
          const window = value.preset === "custom" && value.from && value.to ? {
            from: localDateTimeToUtc(value.from, timeZone), to: localDateTimeToUtc(value.to, timeZone),
          } : periodBounds(value);
          if (window?.from && window.to) { setPeriod(value); setBounds({ from: window.from, to: window.to }); clearRows(); }
        },
      }}}
      state={denied ? "denied" : list.isLoading ? "loading" : error ? "error" : "ok"}
      busy={list.isFetching && !list.isLoading} stateView={denied ? <ReportDenied reportKey={definition.key}/> : error ? <StateView state="error" detail={t("problems.queue.loadFailed")} onRetry={() => void list.refetch()}/> : undefined}
      tabs={controls} drawer={active && selected !== null ? <div data-problems-queue-drawer>
        <ProblemPanel key={active.id} publicRow={active} detail={details.data ? detailRow : null} detailError={details.isError}
          retryDetails={() => void details.refetch()} domain={domain} zone={timeZone} openEntity={openEntity} canManage={canManage}
          canAssign={ownerAllowed} canEvidence={!active.fileEpisode && typeof definition.detail === "object" && definition.detail.query_available !== false}
          onClose={() => select(null)} previous={position > 0 ? () => select(visibleRows[position - 1].id) : undefined}
          next={position >= 0 && position < visibleRows.length - 1 ? () => select(visibleRows[position + 1].id) : undefined}
          onChange={(kind, choose) => decide(kind, [active.id], choose)}/>
      </div> : undefined}>
      <div data-problems-queue-table><DataTable caption={definition.title} columns={availableColumns.filter(({ key }) => !hidden.includes(key))} rows={visibleRows} rowKey={(row) => String(row.id)}
        onRowClick={(row) => select(row.id)} selectedKey={selected === null ? null : String(selected)} density={compact ? "compact" : "standard"} showFooter={false}
        sort={{ field: "last_seen_utc", direction }} onSort={() => { setDirection((current) => current === "asc" ? "desc" : "asc"); clearRows(); }}
        afterRow={representative ? (row) => {
          if (row.id === representative.id && !expandedRows.length && !members.hasNextPage)
            return <ExpandedEvidence id={row.id} domain={domain} zone={timeZone} openEntity={openEntity} members={members.data?.pages[0]} failed={members.isError} retry={() => void members.refetch()}/>;
          if (row.id === (expandedRows.at(-1)?.id ?? representative.id) && members.hasNextPage)
            return <Button disabled={members.isFetchingNextPage} onClick={() => void members.fetchNextPage()}>{t(members.isFetchNextPageError ? "state.retry" : "table.loadMore")}</Button>;
          return null;
        } : undefined}/></div>
      {firstAdSource ? <FirstAdSource/>
        : rows.length === 0 ? <p role="status">{incomplete ? EMPTY_VALUE : t("problems.queue.empty")}</p> : null}
      {footer}
    </ReportLayout>;
}

function DecisionForm({ kind, choose, ids, current, zone, onSave }: {
  kind: "state" | "assign" | "defer"; choose?: State; ids: number[]; current?: string;
  zone: string; onSave: (input: Decision) => Promise<boolean>;
}) {
  const [state, setState] = useState<State>(kind === "defer" ? "deferred" : choose ?? "active");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const responsibles = useQuery({ queryKey: ["findings", "responsibles"], queryFn: api.riskResponsibles, enabled: kind === "assign", retry: false });
  const users = responsibles.data?.items ?? [];
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const values = new FormData(event.currentTarget);
    const payload: Decision = { ids };
    const comment = String(values.get("comment") ?? "").trim();
    if (comment) payload.comment = comment;
    if (kind === "assign") payload.assignee_id = values.get("assignee") ? Number(values.get("assignee")) : null;
    else {
      payload.state = state;
      if (state === "closed" || state === "false_positive") {
        const classification = state === "false_positive" ? "false_positive" : String(values.get("classification"));
        if (classification !== "fixed" && classification !== "expected" && classification !== "false_positive") return;
        payload.classification = classification;
        if (classification === "false_positive") payload.state = "false_positive";
      }
      if (state === "deferred") {
        const until = localDateTimeToUtc(String(values.get("until") ?? ""), zone);
        if (!until || Date.parse(until) <= Date.now()) { setError(t("problems.queue.future")); return; }
        payload.until = until;
      }
    }
    setError(""); setSaving(true);
    if (!await onSave(payload)) { setError(t("problems.queue.saveFailed")); setSaving(false); }
  };
  return <form className="sli-ds-report__views" onSubmit={(event) => void submit(event)}>
    {kind === "state" ? <div className="sli-ds-field">{t("problems.queue.status")}<Select label={t("problems.queue.status")} value={state} onChange={(selectedValue) => setState(stateOf(selectedValue))}
      options={states.map((item) => ({ value: item, label: stateName(item) }))}/></div> : null}
    {kind === "assign" ? responsibles.isError ? <StateView state="error" detail={t("problems.queue.usersFailed")} onRetry={() => void responsibles.refetch()}/>
      : responsibles.isPending ? <StateView state="loading"/> : <div className="sli-ds-field">{t("problems.queue.owner")}<Select label={t("problems.queue.owner")} name="assignee" defaultValue={users.find(({ username }) => username === current)?.id ?? ""}
        options={[{ value: "", label: t("security.problems.assignee.unassigned") }, ...(users.map(({ id, username }) => ({ value: id, label: username })) ?? [])]}/></div> : null}
    {kind !== "assign" && state === "closed" ? <div className="sli-ds-field">{t("problems.queue.classification")}<Select label={t("problems.queue.classification")} name="classification" required defaultValue=""
      options={[{ value: "", label: EMPTY_VALUE, disabled: true }, ...((["fixed", "expected", "false_positive"] as const).map((reason) => ({ value: reason, label: t(`problems.queue.reason.${reason}`) })) ?? [])]}/></div> : null}
    {kind !== "assign" && state === "deferred" ? <div className="sli-ds-field"><label htmlFor="problem-until">{t("problems.queue.until")}</label>
      <DateInput id="problem-until" name="until" label={t("problems.queue.until")} required/></div> : null}
    <label className="sli-ds-field">{t("reports.problemLifecycle.optionalComment")}<textarea name="comment" maxLength={2000}/></label>
    {error ? <span role="alert" className="sli-ds-field__error">{error}</span> : null}
    <Button type="submit" variant="primary" disabled={saving || kind === "assign" && !responsibles.data}>{t(error ? "state.retry" : "reports.problemLifecycle.save")}</Button>
  </form>;
}

function useProblemEvidence(id: number, domain: string, zone: string, enabled = true, openEntity: string | null = null) {
  return useInfiniteQuery({ queryKey: ["report-v2", "data", "security.problems", "evidence", id, domain, zone, openEntity], enabled, retry: false,
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ queue_view: "all", tz: zone });
      if (domain) params.set("domain", domain);
      setOpenEntityScope(params, openEntity);
      if (pageParam) params.set("cursor", pageParam);
      return api.reportV2Detail("security.problems", String(id), params);
    }, initialPageParam: null as string | null, getNextPageParam: (page) => page.has_more ? page.next_cursor : null });
}

function eventHref(value: unknown) {
  const id = asCount(value);
  return id && id > 0 ? `/app/events/${id}` : undefined;
}

function EvidenceTable({ evidence, zone, card = false }: { evidence: ReturnType<typeof useProblemEvidence>; zone: string; card?: boolean }) {
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null);
  const key = (row: RecordRow) => `${row.evidence_id ?? row.evidence_key ?? row.event_db_id}:${row.time_created_utc ?? ""}:${row.evidence_role ?? ""}`;
  const rows = evidence.data?.pages.flatMap((page) => page.items) ?? [];
  const timeColumn: TableColumn<RecordRow> = { key: "time", label: t("problems.queue.time"), width: card ? "16%" : undefined, wrap: card,
    render: (row) => timeLabel(asText(row.time_created_utc ?? row.observed_at_utc), zone, true) };
  const columns: TableColumn<RecordRow>[] = card ? [
    timeColumn,
    { key: "event", label: t("problems.queue.event"), width: "44%", render: (row) => {
      if (row.storage_kind === "file_audit_snapshot") return t("evidence.acl.snapshot");
      if (row.event_id == null) return EMPTY_VALUE;
      const code = String(row.event_id);
      const title = eventSemanticText(asText(row.event_title_code), "");
      const label = title ? `${title} · ${code}` : code;
      if (row.event_record_id == null && !eventHref(row.event_db_id)) return label;
      const id = key(row);
      return <Button variant="ghost" aria-expanded={id === expandedEvent}
        onClick={() => setExpandedEvent(id === expandedEvent ? null : id)}>{label}</Button>;
    } },
    { key: "account", label: t("problems.queue.account"), width: "20%", wrap: true, value: (row) => typeof row.account === "string" ? row.account.slice(0, 256) : "" },
    { key: "from", label: t("problems.queue.from"), width: "20%", wrap: true, value: (row) => hostText(row.source) || hostText(row.hostname) },
  ] : [
    timeColumn,
    { key: "code", label: t("problems.queue.code"), render: (row) => row.event_id == null ? EMPTY_VALUE : eventHref(row.event_db_id)
      ? <a href={eventHref(row.event_db_id)}>{String(row.event_id)}</a> : String(row.event_id) },
    { key: "source", label: t("problems.queue.source"), value: (row) => asText(row.hostname) || asText(row.channel) },
  ];
  const loadFailed = t(card ? "problems.queue.eventsFailed" : "problems.queue.evidenceFailed");
  if (evidence.isError && !rows.length) return <StateView state="error" detail={loadFailed} onRetry={() => void evidence.refetch()}/>;
  if (evidence.isPending) return <StateView state="loading"/>;
  if (!rows.length) return card ? <p role="status">{t("security.problems.evidence.empty")}</p> : <span>{EMPTY_VALUE}</span>;
  return <><DataTable caption={t(card ? "problems.queue.events" : "problems.queue.proof")} rows={rows} columns={columns} density="compact" stickyHeader={false} wrapCells={card ? "all" : false}
    rowKey={key} expandedContent={card ? (row) => expandedEvent === key(row) ? <>
      {row.event_record_id != null ? <FactList facts={[{ label: t("problems.queue.windowsRecord"), value: String(row.event_record_id) }]}/> : null}
      {eventHref(row.event_db_id) ? <a href={eventHref(row.event_db_id)}>{t("problems.queue.original")}</a> : null}
    </> : null : undefined}
    hasMore={Boolean(evidence.hasNextPage)} showFooter={Boolean(evidence.hasNextPage)} loadingMore={evidence.isFetchingNextPage} onLoadMore={() => void evidence.fetchNextPage()}/>
    {evidence.isFetchNextPageError ? <StateView state="error" detail={loadFailed} onRetry={() => void evidence.fetchNextPage()}/> : null}</>;
}

function ExpandedEvidence({ id, domain, zone, openEntity, members, failed, retry }: { id: number; domain: string; zone: string; openEntity: string | null; members?: ReportResultDto; failed: boolean; retry: () => void }) {
  const showEvidence = members?.items.length === 1;
  const evidence = useProblemEvidence(id, domain, zone, showEvidence, openEntity);
  if (failed) return <StateView state="error" detail={t("problems.queue.repeatsFailed")} onRetry={retry}/>;
  if (!members) return <StateView state="loading"/>;
  return showEvidence ? <EvidenceTable evidence={evidence} zone={zone}/> : null;
}

export function ProblemJournal({ definition, finding, domain }: { definition: ReportDefinitionDto; finding: number; domain: string }) {
  const { timeZone: preference } = useTimeZone();
  const timeZone = preference === "browser" ? browserTimeZone() : preference;
  const evidence = useProblemEvidence(finding, domain, timeZone, definition.access?.allowed !== false);
  const query = new URLSearchParams({ id: String(finding), ...(domain ? { domain } : {}) });
  if (definition.access?.allowed === false) return <ReportDenied reportKey={definition.key} page/>;
  return <ReportLayout title={definition.title} actions={<a className="sli-ds-button" href={`/app/report/security.problems?${query}`}>{t("problems.queue.problemNumber", { id: finding })}</a>}>
    <EvidenceTable evidence={evidence} zone={timeZone}/>
  </ReportLayout>;
}

function ProblemPanel({ publicRow, detail, detailError, retryDetails, domain, zone, openEntity, canManage, canAssign, canEvidence, onClose, previous, next, onChange }: {
  publicRow: Problem; detail: Problem | null; detailError: boolean; retryDetails: () => void; domain: string; zone: string; openEntity: string | null;
  canManage: boolean; canAssign: boolean; canEvidence: boolean; onClose: () => void;
  previous?: () => void; next?: () => void; onChange: (kind: "state" | "assign" | "defer", state?: State) => void;
}) {
  const row = detail ?? publicRow;
  const evidence = useProblemEvidence(row.id, domain, zone, canEvidence, openEntity);
  const options = new URLSearchParams({ finding: String(row.id), ...(domain ? { domain } : {}), hide_open_problem_evidence: "off" });
  const event = evidence.data?.pages.flatMap((page) => page.items).find((item) => eventHref(item.event_db_id));
  const first = timeLabel(row.first, zone);
  const last = timeLabel(row.last, zone);
  const time = last !== EMPTY_VALUE ? last : first;
  const observedTime = first !== EMPTY_VALUE && last !== EMPTY_VALUE && first !== last
    ? t("problems.queue.observedRange", { first, last })
    : time !== EMPTY_VALUE ? t("problems.queue.observedTime", { time }) : "";
  const facts = [
    row.object && t("problems.queue.observedObject", { object: row.object }),
    row.source && t("problems.queue.observedSource", { source: row.source }),
    observedTime,
  ].filter(Boolean).join(" ");
  const description = row.description && (facts
    ? new Intl.Segmenter(getLocale(), { granularity: "sentence" }).segment(row.description).containing(0)?.segment.trim()
    : row.description);
  const spray = row.whatCode === "security.problems.presentation.spray_threshold_what" ||
    row.whatCode === "security.problems.presentation.spray_what";
  const summary = spray && facts ? t("problems.queue.sprayObservation", { facts })
    : [description, facts && t("problems.queue.observation", { facts })].filter(Boolean).join(" ");
  return <DetailDrawer responsive open title={row.cardTitle} onClose={onClose}
    headerActions={<><Button variant="ghost" aria-label={t("problems.queue.previous")} disabled={!previous} onClick={previous}>↑</Button>
      <Button variant="ghost" aria-label={t("problems.queue.next")} disabled={!next} onClick={next}>↓</Button></>}
    footer={<>
      {event ? <a className="sli-ds-button" data-variant="primary" href={`/app/report/events.journal?${options}`}>{t("problems.queue.investigate")}</a> : null}
      {canManage ? <><Button onClick={() => onChange("state", row.state)}>{t("problems.queue.action.state")}</Button>
        <Button onClick={() => onChange("defer")}>{t("problems.queue.action.defer")}</Button></> : null}
    </>}>
    <div className="sli-ds-header__actions"><SeverityBadge severity={row.severity}/>
      <span aria-hidden="true">·</span>
      {canManage ? <div className="sli-ds-field"><span className="sli-ds-sr-only">{t("problems.queue.status")}</span><Select label={t("problems.queue.status")} value={row.state} onChange={(selectedValue) => onChange("state", stateOf(selectedValue))}
        options={states.map((state) => ({ value: state, label: stateName(state) }))}/></div> : stateName(row.state)}
      {row.until ? <time>{timeLabel(row.until, zone)}</time> : null}
    </div>
    {canAssign ? <div className="sli-ds-header__actions"><span>{t("problems.queue.owner")}</span><span>{row.assignee || EMPTY_VALUE}</span>
      {canManage ? <Button variant="ghost" onClick={() => onChange("assign")}>{t("problems.queue.action.assign")}</Button> : null}</div> : null}
    {detailError ? <StateView state="error" detail={t("problems.queue.detailsFailed")} onRetry={retryDetails}/> : null}
    {summary ? <section>
      <h3>{t("reports.v2.security.problems.columns.what.label")}</h3>
      <p>{summary}</p>
    </section> : null}
    {row.next && row.next !== EMPTY_VALUE ? <section>
      <h3>{t("reports.v2.security.problems.columns.next.label")}</h3>
      <p>{row.next}</p>
    </section> : null}
    {canEvidence ? <section><h3>{t("problems.queue.events")}</h3><EvidenceTable evidence={evidence} zone={zone} card/></section> : null}
    {row.history.length ? <section>
      <h3>{t("problems.queue.history")}</h3>
      <ul className="sli-ds-decision-list">{row.history.map((entry) => <li key={String(entry.id)}>
        <time>{timeLabel(asText(entry.changed_at), zone, true)}</time>
        <span>{entry.changed_by === "semantic-worker" || entry.changed_by === "system" ? t("reports.problemLifecycle.system") : text(entry.changed_by)}</span>
        <span>{historyAction(entry, zone)}</span>
      </li>)}</ul>
    </section> : null}
  </DetailDrawer>;
}
