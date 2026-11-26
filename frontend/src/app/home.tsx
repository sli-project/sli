import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { api } from "../api/client";
import type { HomeChange, HomePeriod, HomeProblem, HomeQueueFilter, HomeQueuePage, HomeWeakSpot } from "../api/home-period";
import { Button, DataTable, PageHeader, Panel, Select, SeverityBadge, StateView, Tabs, TabList, TabPanel, type TableColumn } from "../design-system";
import { en } from "../i18n/en";
import { getLocale, t, type MessageKey } from "../i18n";
import { browserTimeZone, formatDateTime } from "../shared/date-time";
import { EMPTY_VALUE, formatNumber } from "../shared/format";
import { useAccessStatus, useEffectiveAccess, useTimeZone } from "./App";
import { FirstAdSource, useFirstAdSource } from "./first-ad-source";
import "./home.css";


function clock(value: string | null, zone: string) {
  return formatDateTime(value, zone, { timeOnly: true });
}

function link(href: string | null | undefined, label: ReactNode) {
  return href ? <a href={href} onClick={(event) => event.stopPropagation()}>{label}</a> : label;
}

function LoadError({ message, retry, fetching }: { message: string; retry: () => void; fetching: boolean }) {
  return <div>
    <p className="sli-ds-home-load-error" role="alert">{message}</p>
    <Button disabled={fetching} onClick={retry}>{t("state.retry")}</Button>
  </div>;
}

function eventFact(id: number) {
  switch (id) {
    case 4624: return t("home.event.4624");
    case 4625: return t("home.event.4625");
    default: {
      const key = `reports.v2.security.events.chains.actions.${id}` as MessageKey;
      return Object.hasOwn(en, key) ? t(key) : t("home.event.source", { id });
    }
  }
}

const queueFilters = ["all", "unassigned", "in_work"] as const;
const pageSizes = [25, 50, 100, 200];
const initialQueue: HomeQueuePage = { filter: "all", page: 1, limit: 25 };

function savedQueue(key: string): HomeQueuePage {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) ?? "null") as HomeQueuePage | null;
    if (value && queueFilters.includes(value.filter) && pageSizes.includes(value.limit)
      && Number.isSafeInteger(value.page) && value.page > 0) return value;
  } catch { /* Storage may be unavailable. */ }
  return initialQueue;
}

function Problems({ data, zone, queue, setQueue, pending, showAssignment }: {
  data: NonNullable<HomePeriod["problems"]>;
  zone: string;
  queue: HomeQueuePage;
  setQueue: (queue: HomeQueuePage) => void;
  pending: boolean;
  showAssignment: boolean;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const title = t("home.problems");
  const counts = { all: data.open_count, unassigned: showAssignment ? data.unassigned_count : null, in_work: data.in_work_count };
  const active = counts[queue.filter] !== null ? queue.filter : "all";
  const total = counts[active];
  const page = active !== queue.filter ? 1 : pending ? queue.page : data.page ?? queue.page;
  const select = (next: HomeQueuePage) => { setExpanded(null); setQueue(next); };
  const columns: TableColumn<HomeProblem>[] = [
    { key: "severity", label: t("home.severity"), width: "9rem", render: ({ severity }) =>
      <SeverityBadge severity={severity} label={t(`home.severity.${severity}`)}/> },
    { key: "name", label: t("home.object"), width: "16%", wrap: true,
      render: (row) => row.name ? link(row.object_href ?? row.href, row.name) : EMPTY_VALUE },
    { key: "fact", label: t("home.fact"), wrap: true, render: (row) => <>
      {[row.fact, row.source].filter(Boolean).join(" · ") || EMPTY_VALUE}
      {row.occurrence_count > 1 && <span className="sli-ds-home-inline-source"> {link(row.repeats_href, `×${formatNumber(row.occurrence_count)}`)}</span>}
    </> },
    { key: "at", label: t("home.lastSeen"), width: "10rem",
      render: ({ at }) => at ? <time dateTime={at} title={`${formatDateTime(at, zone, { seconds: true })} (${zone})`}>
        {formatDateTime(at, zone, { withYear: false })}
      </time> : EMPTY_VALUE },
    { key: "review", label: t("home.review"), width: "7rem", wrap: true,
      render: (row) => link(row.href, t(`home.status.${row.status}`)) },
  ];
  if (showAssignment && data.unassigned_count !== null) columns.push({
    key: "assignee", label: t("home.assignee"), width: "9rem", wrap: true,
    render: (row) => row.assignee_state === "mixed" ? t("home.assignee.mixed") : row.assignee ?? EMPTY_VALUE,
  });
  const items = queueFilters.filter((key) => counts[key] !== null).map((key) => ({
    key, label: t(`home.filter.${key}`, { count: formatNumber(counts[key]) }),
  }));
  if (!data.href) return <div data-home-block="problems"><Panel title={title}>
    <p className="sli-ds-home-load-error" role="status">{t("state.denied.title")}</p>
  </Panel></div>;
  return <div data-home-block="problems">
    <Tabs items={items} active={active} onChange={(key) => select({ ...queue, filter: key as HomeQueueFilter, page: 1 })}>
      <Panel title={title} action={<>
        <TabList label={title}/>
        <span data-home-panel-action>{link(data.href, t("home.openQueue"))}</span>
      </>}>
        <TabPanel>
          <DataTable caption={title} columns={columns} rows={pending ? [] : data.items} rowKey={(row) => String(row.id)}
            density="compact" total={total} selectedKey={expanded}
            emptyContent={pending ? t("state.loading") : t("home.queue.empty")}
            onRowClick={(row) => setExpanded((current) => current === String(row.id) ? null : String(row.id))}
            pageSize={{ value: queue.limit, options: pageSizes, onChange: (limit) => select({ ...queue, filter: active, limit, page: 1 }) }}
            pagination={{
              start: (page - 1) * queue.limit + 1, busy: pending,
              onPrevious: page > 1 ? () => select({ ...queue, filter: active, page: page - 1 }) : undefined,
              onNext: total !== null && page * queue.limit < total ? () => select({ ...queue, filter: active, page: page + 1 }) : undefined,
            }}
            renderExpandedRow={(row) => <div className="sli-ds-home-observations">
              {row.observations.length > 0 && <DataTable caption={t("home.observations")} columns={[
                { key: "at", label: t("home.time"), render: (item) => formatDateTime(item.at, zone, { withYear: false }) },
                { key: "event_id", label: t("home.fact"), wrap: true, render: (item) => link(item.href, eventFact(item.event_id)) },
                { key: "source", label: t("home.source"), wrap: true },
              ]} rows={row.observations} rowKey={(item) => `${item.at}:${item.event_id}:${item.href ?? item.source}`}
                stickyHeader={false} showFooter={false}/>}
              <div className="sli-ds-home-links">
                {row.object_href && link(row.object_href, t("home.openObject"))}
                {link(row.href, t("home.openProblem"))}
              </div>
            </div>}/>
        </TabPanel>
      </Panel>
    </Tabs>
  </div>;
}

function WeakSpots({ data, fetching, retry }: {
  data: NonNullable<HomePeriod["weak_spots"]>; fetching: boolean; retry: () => void;
}) {
  if (!data.items.length && !data.failed.length) return null;
  const title = t("home.weakSpots");
  const columns: TableColumn<HomeWeakSpot>[] = [
    { key: "label", label: t("home.check"), wrap: true,
      render: ({ label, label_key }) => label_key ? t(label_key) : label },
    { key: "count", label: t("home.affectedObjects"), render: ({ count }) => formatNumber(count) },
    { key: "report", label: t("home.checkScreen"), wrap: true,
      render: ({ href, report }) => link(href, t(`home.checkScreen.${report}`)) },
  ];
  return <div data-home-block="weakSpots"><Panel title={title}>
    {data.items.length > 0 && <DataTable caption={title} columns={columns} rows={data.items} rowKey={({ id }) => id}
      density="compact" stickyHeader={false} showFooter={false}/>}
    {data.failed.length > 0 && <LoadError message={t("home.loadFailed.checkScreens", {
      screens: data.failed.map((report) => t(`home.checkScreen.${report}`)).join(", "),
    })} fetching={fetching} retry={retry}/>}
  </Panel></div>;
}

const passwordLabels: Record<string, MessageKey> = {
  password_min_length: "home.password.length", password_history_length: "home.password.history",
  password_min_age: "home.password.minAge", password_max_age: "home.password.maxAge",
  lockout_threshold: "home.password.lockout", lockout_duration: "home.password.lockoutDuration",
  lockout_observation_window: "home.password.lockoutWindow",
};

function changeFact(row: HomeChange) {
  if ("event_id" in row) {
    const values = row.before && row.after ? `${row.before} → ${row.after}` : row.value ?? row.after ?? row.before;
    return [eventFact(row.event_id), values].filter(Boolean).join(" · ");
  }
  if (row.kind === "password") {
    const label = passwordLabels[row.field] ? t(passwordLabels[row.field]) : null;
    return [label, `${row.before ?? EMPTY_VALUE} → ${row.after ?? EMPTY_VALUE}`].filter(Boolean).join(" · ");
  }
  const operation = row.operation === "object_added" ? t("home.gpo.added") : row.operation === "object_removed" ? t("home.gpo.removed") : t("home.gpo.changed");
  return [row.label, row.before !== null || row.after !== null ? `${row.before ?? EMPTY_VALUE} → ${row.after ?? EMPTY_VALUE}` : operation].filter(Boolean).join(" · ");
}

function Changes({ data, zone }: { data: NonNullable<HomePeriod["changes"]>; zone: string }) {
  if (!data.href && !data.items.length) return null;
  const title = t("home.changes");
  return <div data-home-block="changes"><Panel title={title}
    action={data.href ? <span data-home-panel-action>{link(data.href, t("home.domainChanges"))}</span> : null}>
    <DataTable caption={title} rows={data.items} rowKey={(row) => String(data.items.indexOf(row))}
      density="compact" stickyHeader={false} showFooter={false} emptyContent={t("home.changes.empty")} columns={[
        { key: "at", label: t("home.time"), width: "9rem", render: (row) => formatDateTime(row.at, zone, { withYear: false }) },
        { key: "change", label: t("home.change"), wrap: true, render: (row) => {
          const name = row.name ?? ("kind" in row && row.kind === "password" ? t("home.password") : null);
          return <>{name && <>{link(row.href, name)} · </>}{changeFact(row)}</>;
        } },
        { key: "initiator", label: t("home.initiator"), width: "14rem", wrap: true, render: (row) => "event_id" in row
          ? row.initiator ?? EMPTY_VALUE
          : row.before_at ? `${formatDateTime(row.before_at, zone, { withYear: false })} → ${formatDateTime(row.at, zone, { withYear: false })}`
          : t("home.snapshotComparison") },
      ]}/>
  </Panel></div>;
}

function HomeComposition({ data, zone, fetching, retry, queue, setQueue, pending }: {
  data: HomePeriod; zone: string; fetching: boolean; retry: () => void;
  queue: HomeQueuePage; setQueue: (queue: HomeQueuePage) => void; pending: boolean;
}) {
  const failure = (block: "problems" | "weakSpots" | "changes") => <div data-home-block={block}>
    <Panel title={t(`home.${block}`)}>
      <LoadError message={t(`home.loadFailed.${block}`)} fetching={fetching} retry={retry}/>
    </Panel>
  </div>;
  return <div className="sli-ds-report__views sli-ds-home-main" aria-busy={fetching}>
    {data.problems ? <Problems data={data.problems} zone={zone} queue={queue} setQueue={setQueue} pending={pending}
      showAssignment={(data.active_operator_count ?? 0) >= 2}/> : failure("problems")}
    {data.weak_spots ? <WeakSpots data={data.weak_spots} fetching={fetching} retry={retry}/> : failure("weakSpots")}
    {data.changes ? <Changes data={data.changes} zone={zone}/> : failure("changes")}
  </div>;
}

export function HomePage() {
  const { timeZone } = useTimeZone();
  const access = useEffectiveAccess();
  const accessStatus = useAccessStatus();
  const { searchStr } = useLocation();
  const navigate = useNavigate();
  const [period, setPeriod] = useState("24h");
  const [previous, setPrevious] = useState<{ from: string; to: string } | null>(null);
  const params = new URLSearchParams();
  const search = new URLSearchParams(searchStr);
  const domain = search.get("domain_id") ?? search.get("domain");
  const queueKey = `sli.home.queue:${domain ?? ""}`;
  const [queue, setQueue] = useState(() => savedQueue(queueKey));
  const selectQueue = (next: HomeQueuePage) => {
    setQueue(next);
    try { sessionStorage.setItem(queueKey, JSON.stringify(next)); }
    catch { /* Storage may be unavailable. */ }
  };
  if (domain) params.set("domain_id", domain);
  const actualZone = timeZone === "browser" ? browserTimeZone() : timeZone;
  params.set("tz", actualZone);
  params.set("queue", queue.filter);
  params.set("page", String(queue.page));
  params.set("limit", String(queue.limit));
  params.set("period", previous ? "custom" : period);
  if (previous) { params.set("from", previous.from); params.set("to", previous.to); }
  const scope = ["home", "v5", domain, previous?.from ?? period, getLocale(), actualZone, access];
  const summary = useQuery({
    queryKey: [...scope, params.toString()],
    queryFn: () => api.homePeriod(params),
    placeholderData: (prior, query) => query?.queryKey.slice(0, -1).every((key, index) =>
      Object.is(key, scope[index])) ? prior : undefined,
    staleTime: 30_000, retry: false, enabled: accessStatus === "получены",
  });
  const data = summary.data;
  const firstAdSource = useFirstAdSource(search, summary.isSuccess && data?.domains.length === 0);
  const retry = () => void summary.refetch();
  const togglePrevious = () => {
    if (previous) setPrevious(null);
    else if (data) {
      const start = Date.parse(data.from);
      setPrevious({ from: new Date(start - (Date.parse(data.to) - start)).toISOString(), to: new Date(start).toISOString() });
    }
  };
  const actions = <>
    {data?.domains.length ? <Select label={t("home.domain")} value={data.domain_id ?? undefined}
      options={data.domains.map(({ id, name }) => ({ value: id, label: name }))} onChange={(value) => {
        if (!value) return;
        void navigate({ search: ((old: Record<string, unknown>) => ({ ...old, domain: Number(value), domain_id: undefined, scope: undefined })) as never });
      }}/> : null}
    <Select label={t("home.period")} value={period}
      options={[{ value: "24h", label: t("home.period.24h") }, { value: "7d", label: t("home.period.7d") }]}
      onChange={(value) => { if (value) { setPeriod(value); setPrevious(null); } }}/>
    <Button aria-pressed={previous !== null} disabled={!data && !previous} onClick={togglePrevious}>{t("home.period.previous")}</Button>
    {data ? <span>{formatDateTime(data.from, actualZone, { withYear: false })} → {formatDateTime(data.to, actualZone, { withYear: false })}</span> : null}
    {data ? <span data-home-updated>{t("home.updated", { time: clock(data.updated_at, actualZone) })}</span> : null}
    <Button disabled={accessStatus !== "получены" || summary.isFetching} onClick={retry}>{t("home.refresh")}</Button>
  </>;
  if (firstAdSource) return <section className="sli-ds-report sli-ds-home">
    <PageHeader title={t("home.title")}/>
    <FirstAdSource/>
  </section>;
  const delta = data?.since_previous_login;
  return <section className="sli-ds-report sli-ds-home">
    <PageHeader title={t("home.title")} actions={actions} meta={delta && <>
      {t("home.sincePreviousLogin")} {link(delta.new_href, t("home.sincePreviousLogin.new", { count: formatNumber(delta.new_count) }))}
      {" · "}{t("home.sincePreviousLogin.closed", { count: formatNumber(delta.closed_count) })}
    </>}/>
    {accessStatus === "загружается" || summary.isLoading || firstAdSource === undefined ? <StateView state="loading" compact skeleton="table"/> : null}
    {accessStatus === "отказ" ? <p role="alert">{t("home.loadFailed")}</p> : null}
    {accessStatus === "получены" && <>
      {summary.isError ? <LoadError message={t("home.loadFailed")} fetching={summary.isFetching} retry={retry}/> : null}
      {data && firstAdSource !== undefined ? <HomeComposition data={data} zone={actualZone} fetching={summary.isFetching} retry={retry}
        queue={queue} setQueue={selectQueue} pending={summary.isPlaceholderData}/> : null}
    </>}
  </section>;
}
