import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { api } from "../api/client";
import type { HomeChange, HomeController, HomePeriod, HomeProblem } from "../api/home-period";
import { Button, Chart, DataTable, PageHeader, Panel, SeverityBadge, StateView, type TableColumn } from "../design-system";
import { getLocale, plural, t, type MessageKey } from "../i18n";
import { browserTimeZone, formatDateTime } from "../shared/date-time";
import { EMPTY_VALUE, formatNumber } from "../shared/format";
import { useAccessStatus, useEffectiveAccess, useTimeZone } from "./App";
import "./home.css";


function clock(value: string | null, zone: string) {
  return formatDateTime(value, zone, { timeOnly: true });
}

function link(href: string | null | undefined, label: ReactNode) {
  return href ? <a href={href} onClick={(event) => event.stopPropagation()}>{label}</a> : label;
}

function EmptyRow() {
  return <div className="sli-ds-home-empty">{EMPTY_VALUE}</div>;
}

function LoadError({ message, retry, fetching }: { message: string; retry: () => void; fetching: boolean }) {
  return <div>
    <p role="alert">{message}</p>
    <Button disabled={fetching} onClick={retry}>{t("state.retry")}</Button>
  </div>;
}

function eventFact(id: number) {
  switch (id) {
    case 4624: return t("home.event.4624");
    case 4625: return t("home.event.4625");
    case 1102: return t("home.event.1102");
    case 4719: return t("home.event.4719");
    case 4720: return t("home.event.4720");
    case 4725: return t("home.event.4725");
    case 4726: return t("home.event.4726");
    case 4728: case 4732: case 4756: return t("home.event.memberAdded");
    case 4729: case 4733: case 4757: return t("home.event.memberRemoved");
    case 4738: return t("home.event.4738");
    default: return t("home.event.source", { id });
  }
}

function Problems({ data, zone }: { data: NonNullable<HomePeriod["problems"]>; zone: string }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const title = t("home.problems");
  const counters = [
    ["home.count.new", data.new_count], ["home.count.closed", data.closed_count], ["home.count.open", data.open_count],
  ] as const;
  const columns: TableColumn<HomeProblem>[] = [
    { key: "severity", label: t("home.severity"), width: "8rem", render: ({ id, severity }) => <>
      <span aria-hidden="true" className="sli-ds-home-chevron">{expanded === String(id) ? "▾" : "▸"}</span>
      <SeverityBadge severity={severity} label={t(`home.severity.${severity}`)}/>
    </> },
    { key: "name", label: t("home.object"), width: "12%", wrap: true, render: (row) => link(row.href, row.name ?? EMPTY_VALUE) },
    { key: "fact", label: t("home.fact"), wrap: true, render: (row) => <>
      {row.fact || EMPTY_VALUE}
      {row.source ? <span className="sli-ds-home-inline-source"> · {row.source}</span> : null}
    </> },
    { key: "source", label: t("home.source"), width: "8rem", wrap: true },
    { key: "at", label: t("home.time"), width: "5rem", render: (row) => clock(row.at, zone) },
  ];
  return <div data-home-block="problems"><Panel title={title}
    subtitle={counters.map(([key, count]) => t(key, { count: formatNumber(count) })).join(" · ")}>
    {data.items.length ? <DataTable caption={title} columns={columns} rows={data.items} rowKey={(row) => String(row.id)}
      selectedKey={expanded} onRowClick={(row) => setExpanded((current) => current === String(row.id) ? null : String(row.id))}
      stickyHeader={false} showFooter={false}
      renderExpandedRow={(row) => <div className="sli-ds-home-observations">
        <strong>{t("home.observations")}</strong>
        {row.observations.length ? <DataTable caption={t("home.observations")} columns={[
          { key: "at", label: t("home.time"), render: (item) => clock(item.at, zone) },
          { key: "event_id", label: t("home.fact"), wrap: true, render: (item) => link(item.href, eventFact(item.event_id)) },
          { key: "source", label: t("home.source"), wrap: true, render: (item) => <>{item.source ?? EMPTY_VALUE} · {t("home.event.source", { id: item.event_id })}</> },
        ]} rows={row.observations} rowKey={(item) => `${item.at}:${item.event_id}:${item.href ?? item.source}`} stickyHeader={false} showFooter={false}/> : <EmptyRow/>}
        <div className="sli-ds-home-links">
          {row.object_href ? link(row.object_href, t("home.openObject")) : null}
          {row.events_href ? link(row.events_href, t("home.objectEvents")) : null}
          {link(row.href, t("home.openProblem"))}
        </div>
      </div>}/> : <EmptyRow/>}
    {data.href ? <div className="sli-ds-home-links" data-align="end">
      {link(data.href, t("home.openQueue", { count: formatNumber(data.open_count) }))}
    </div> : null}
  </Panel></div>;
}

function RowLimit({ limit, setLimit }: { limit: number; setLimit: (limit: number) => void }) {
  return <div className="sli-ds-home-links" data-align="start" role="group" aria-label={t("home.rows")}>
    <span>{t("home.rows")}</span>
    {[25, 50, 100, 200].map((size) => <Button key={size} variant={size === limit ? "primary" : "ghost"}
      aria-pressed={size === limit} onClick={() => setLimit(size)}>{size}</Button>)}
  </div>;
}

type ControllerRow = { controller: HomeController; check?: HomeController["failures"][number] };

function Controllers({ data, zone }: { data: NonNullable<HomePeriod["controllers"]>; zone: string }) {
  const [limit, setLimit] = useState(50);
  const title = t("home.controllers");
  const name = (row: ControllerRow) => link(row.controller.href, row.controller.name ?? EMPTY_VALUE);
  const rows: ControllerRow[] = [
    ...data.items.flatMap((controller) => controller.failures.map((check) => ({ controller, check }))),
    ...data.items.filter((controller) => controller.passed > 0 || controller.failures.length === 0).map((controller) => ({ controller })),
  ];
  const columns: TableColumn<ControllerRow>[] = [
    { key: "name", label: t("home.controller"), wrap: true, render: name },
    { key: "check", label: t("home.check"), wrap: true, render: ({ controller, check }) => {
      if (check) return t(`home.check.${check.key}`);
      if (!controller.passed) return EMPTY_VALUE;
      return plural(controller.passed, {
        one: t(controller.failures.length ? "home.passed.other.one" : "home.passed.one", { count: controller.passed }),
        few: t(controller.failures.length ? "home.passed.other.few" : "home.passed.few", { count: controller.passed }),
        many: t(controller.failures.length ? "home.passed.other.many" : "home.passed.many", { count: controller.passed }),
        other: t(controller.failures.length ? "home.passed.other.many" : "home.passed.many", { count: controller.passed }),
      });
    } },
    { key: "expected", label: t("home.expected"), wrap: true, render: ({ check }) => check
      ? t(check.key === "os" ? "home.supported" : check.key === "time" ? "home.running" : "home.passedState") : EMPTY_VALUE },
    { key: "observed", label: t("home.observed"), wrap: true, render: ({ controller, check }) => {
      const actual = check?.actual === "failed" ? t("home.failedState") : check?.actual === "stopped" ? t("home.stopped") : check?.actual;
      return [actual, clock(controller.at, zone)].filter(Boolean).join(" · ");
    } },
  ];
  return <div data-home-block="controllers"><Panel title={title}
    action={data.href ? <span data-home-panel-action>{link(data.href, t("home.adStatus"))}</span> : null}>
    {rows.length ? <DataTable caption={title} columns={columns} rows={rows.slice(0, limit)}
      rowKey={({ controller, check }) => `${controller.id}:${check?.key ?? "summary"}`} stickyHeader={false} showFooter={false}/> : <EmptyRow/>}
    {rows.length > 0 ? <RowLimit limit={limit} setLimit={setLimit}/> : null}
  </Panel></div>;
}

const passwordLabels: Record<string, MessageKey> = {
  password_min_length: "home.password.length", password_history_length: "home.password.history",
  password_min_age: "home.password.minAge", password_max_age: "home.password.maxAge",
  lockout_threshold: "home.password.lockout", lockout_duration: "home.password.lockoutDuration",
  lockout_observation_window: "home.password.lockoutWindow",
};

function changeFact(row: HomeChange) {
  if ("event_id" in row) return [eventFact(row.event_id), row.value].filter(Boolean).join(" · ");
  if (row.kind === "password") {
    const label = passwordLabels[row.field] ? t(passwordLabels[row.field]) : null;
    return [label, `${row.before ?? EMPTY_VALUE} → ${row.after ?? EMPTY_VALUE}`].filter(Boolean).join(" · ");
  }
  const operation = row.operation === "object_added" ? t("home.gpo.added") : row.operation === "object_removed" ? t("home.gpo.removed") : t("home.gpo.changed");
  return [row.label, row.before !== null || row.after !== null ? `${row.before ?? EMPTY_VALUE} → ${row.after ?? EMPTY_VALUE}` : operation].filter(Boolean).join(" · ");
}

function Changes({ data, zone }: { data: NonNullable<HomePeriod["changes"]>; zone: string }) {
  const [limit, setLimit] = useState(50);
  const title = t("home.changes");
  return <div data-home-block="changes"><Panel title={title}
    action={data.href ? <span data-home-panel-action>{link(data.href, t("home.domainChanges"))}</span> : null}>
    {data.items.length ? <DataTable caption={title} rows={data.items.slice(0, limit)} rowKey={(row) => String(data.items.indexOf(row))}
      stickyHeader={false} showFooter={false} columns={[
        { key: "at", label: t("home.time"), render: (row) => clock(row.at, zone) },
        { key: "name", label: t("home.object"), wrap: true, render: (row) => link(row.href, row.name ?? ("kind" in row && row.kind === "password" ? t("home.password") : EMPTY_VALUE)) },
        { key: "change", label: t("home.change"), wrap: true, render: changeFact },
        { key: "initiator", label: t("home.initiator"), wrap: true, render: (row) => "event_id" in row
          ? `${row.initiator ?? EMPTY_VALUE} · ${row.event_id}` : t("home.snapshotComparison") },
      ]}/> : <EmptyRow/>}
    {data.items.length > 0 ? <RowLimit limit={limit} setLimit={setLimit}/> : null}
  </Panel></div>;
}

function HomeComposition({ data, zone, fetching, retry }: { data: HomePeriod; zone: string; fetching: boolean; retry: () => void }) {
  const activity = data.activity;
  const failure = (block: "problems" | "controllers" | "changes" | "activity") => <div data-home-block={block}>
    <Panel title={t(`home.${block}`)}>
      <LoadError message={t(`home.loadFailed.${block}`)} fetching={fetching} retry={retry}/>
    </Panel>
  </div>;
  const series = [
    { key: "failed", style: "bar", name: t("home.activity.failed") },
    { key: "succeeded", style: "line", name: t("home.activity.succeeded") },
    { key: "typical", style: "dashed", name: t("home.activity.typical") },
  ] as const;
  return <div className="sli-ds-report__views sli-ds-home-main">
    {data.problems ? <Problems key={`${data.domain_id}:${data.from}`} data={data.problems} zone={zone}/> : failure("problems")}
    {data.controllers ? <Controllers data={data.controllers} zone={zone}/> : failure("controllers")}
    {data.changes ? <Changes data={data.changes} zone={zone}/> : failure("changes")}
    {activity ? <div data-home-block="activity"><Chart title={t("home.activity")} height="100%" emptyValue={EMPTY_VALUE} spec={{
      kind: "timeseries", range: [data.from, data.to],
      series: series.map(({ key, style, name }) => ({ name, style, points: activity.hours.map((hour) => ({ x: hour.at, y: hour[key] })) })),
      markers: activity.markers.map((marker) => ({ ...marker, label: [clock(marker.at, zone), t(`home.severity.${marker.severity}`), marker.name, marker.fact].filter(Boolean).join(" · ") })),
    }}/></div> : failure("activity")}
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
  if (domain) params.set("domain_id", domain);
  const actualZone = timeZone === "browser" ? browserTimeZone() : timeZone;
  params.set("tz", actualZone);
  params.set("period", previous ? "custom" : period);
  if (previous) { params.set("from", previous.from); params.set("to", previous.to); }
  const summary = useQuery({
    queryKey: ["home", "v4", params.toString(), getLocale(), access],
    queryFn: () => api.homePeriod(params), staleTime: 30_000, retry: false, enabled: accessStatus === "получены",
  });
  const data = summary.data;
  const retry = () => void summary.refetch();
  const togglePrevious = () => {
    if (previous) setPrevious(null);
    else if (data) {
      const start = Date.parse(data.from);
      setPrevious({ from: new Date(start - (Date.parse(data.to) - start)).toISOString(), to: new Date(start).toISOString() });
    }
  };
  const actions = <>
    {data?.domains.length ? <label className="sli-ds-field"><select aria-label={t("home.domain")} value={data.domain_id ?? ""} onChange={(event) => {
      const id = Number(event.target.value);
      void navigate({ search: ((old: Record<string, unknown>) => ({ ...old, domain: id, domain_id: undefined, scope: undefined })) as never });
    }}>
      {data.domains.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
    </select></label> : null}
    <label className="sli-ds-field"><select aria-label={t("home.period")} value={period} onChange={(event) => { setPeriod(event.target.value); setPrevious(null); }}>
      <option value="24h">{t("home.period.24h")}</option><option value="7d">{t("home.period.7d")}</option>
    </select></label>
    <Button aria-pressed={previous !== null} disabled={!data && !previous} onClick={togglePrevious}>{t("home.period.previous")}</Button>
    {data ? <span>{formatDateTime(data.from, actualZone, { withYear: false })} → {formatDateTime(data.to, actualZone, { withYear: false })}</span> : null}
    {data ? <span data-home-updated>{t("home.updated", { time: clock(data.updated_at, actualZone) })}</span> : null}
    <Button disabled={accessStatus !== "получены" || summary.isFetching} onClick={retry}>{t("home.refresh")}</Button>
  </>;
  return <section className="sli-ds-report sli-ds-home">
    <PageHeader title={t("home.title")} actions={actions}/>
    {accessStatus === "загружается" || summary.isLoading ? <StateView state="loading" compact skeleton="table"/> : null}
    {accessStatus === "отказ" ? <p role="alert">{t("home.loadFailed")}</p> : null}
    {accessStatus === "получены" && <>
      {summary.isError ? <LoadError message={t("home.loadFailed")} fetching={summary.isFetching} retry={retry}/> : null}
      {data ? <HomeComposition data={data} zone={actualZone} fetching={summary.isFetching} retry={retry}/> : null}
    </>}
  </section>;
}
