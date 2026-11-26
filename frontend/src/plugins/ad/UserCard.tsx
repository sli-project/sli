import { useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { ReportColumnDto } from "../../api/report-v2-types";
import { Chart, DataTable, DetailDrawer, FactList, SeverityBadge, Tabs, TabList, TabPanel } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { eventEvidenceHref, exactNavigationId } from "../../app/event-presentation";
import { CopyFactsButton, rowFactsText } from "../../app/report-v2/DetailSection";
import { withReturnTo } from "../../app/report-v2/legacy";
import { t } from "../../i18n";
import { formatNumber } from "../../shared/format";
import { userDeviations, UserStateMark, userObject as object, userObjects as objects, userText as text } from "./UserChecks";

type Row = Record<string, unknown>;
type UserLabel<Section extends "card" | "event"> =
  Extract<Parameters<typeof t>[0], `reports.ad.users.${Section}.${string}`> extends `reports.ad.users.${Section}.${infer Label}` ? Label : never;
const missing = () => t("table.noValue");
const cardText = (key: UserLabel<"card">) => t(`reports.ad.users.card.${key}`);
const groupId = (value: unknown) => exactNavigationId(text(value)?.replace(/^group:/, ""), "entity_id");
const tabs = ["account", "rights", "activity"] as const;

function GroupLink({ group }: { group: Row }) {
  const id = groupId(group.id);
  const name = text(group.name);
  return name && id ? <a href={withReturnTo(`/app/entities/${id}`, window.location.pathname + window.location.search)}>{name}</a> : name ?? missing();
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return <section className="sli-ds-fact-section"><h3>{title}</h3>{children}</section>;
}

function Privileges({ row }: { row: Row }) {
  const paths = objects(row.privilege_paths).filter((path) => path.relation === "nested" && objects(path.nodes).length > 2);
  const groups = objects(row.direct_memberships);
  return <>
    {paths.length ? <Section title={cardText("privilege_path")}>
      {paths.map((path) => <ol className="sli-ds-path" key={String(path.groupId)}>
        <li>{text(row.sam) ?? text(row.display_name) ?? missing()}</li>
        {objects(path.nodes).slice(1).map((group, index) => <li key={String(group.id)}>
          <GroupLink group={group}/> · {cardText(index > 0 ? "nested" : path.first_relation === "primary" || path.relation === "primary" ? "primary" : "direct")}
        </li>)}
      </ol>)}
    </Section> : null}
    {groups.length ? <Section title={cardText("direct_membership")}>
      <DataTable caption={cardText("direct_membership")} rows={groups} rowKey={(group) => String(group.id)}
        columns={[{ key: "group", label: cardText("group"), render: (group) => <GroupLink group={group}/> },
          { key: "relation", label: cardText("membership"), render: () => cardText("direct") }]}
        wrapCells="all" stickyHeader={false} showFooter={false}/>
    </Section> : null}
  </>;
}

function Timeline({ rows, returnTo }: { rows: Row[]; returnTo: string }) {
  const [collapse, setCollapse] = useState(true);
  const { formatDateTime } = useDateFormatters();
  const label = (row: Row) => [
    t(Number(row.event_id) === 4624 ? "reports.ad.users.event.success" : "reports.ad.users.event.failure"),
    ...new Set([row.target, row.actor, row.source].map(text).filter((value) => value && value !== "-" && value !== "S-1-0-0")),
  ].join(" · ");
  const groups: Row[][] = [];
  for (const row of rows) {
    const last = groups.at(-1);
    if (collapse && last && label(last[0]) === label(row)) last.push(row);
    else groups.push([row]);
  }
  const entry = (row: Row, index: number) => {
    const href = eventEvidenceHref(row.id);
    const time = formatDateTime(text(row.at_utc));
    const repeats = typeof row.event_count === "number" && row.event_count > 1 ? row.event_count : null;
    return <li key={`${row.id ?? row.summary_key}:${index}`}>
      {label(row)}{repeats ? ` ×${repeats}` : ""} · {repeats && row.first_seen_utc !== row.at_utc ? `${formatDateTime(text(row.first_seen_utc))}–` : ""}
      {href ? <a href={withReturnTo(href, returnTo)}>{time}</a> : time}
    </li>;
  };
  if (!rows.length) return null;
  return <>
    <label><input type="checkbox" checked={collapse} onChange={(event) => setCollapse(event.target.checked)}/> {cardText("collapse")}</label>
    <ul className="sli-ds-path">{groups.map((group, index) => {
      const count = group.reduce((sum, row) => sum + (typeof row.event_count === "number" ? row.event_count : 1), 0);
      return group.length === 1 ? entry(group[0], index) : <li key={index}><details>
        <summary>{label(group[0])} ×{count} · {formatDateTime(text(group.at(-1)?.first_seen_utc))}–{formatDateTime(text(group[0].at_utc))}</summary>
        <ul className="sli-ds-path">{group.map(entry)}</ul>
      </details></li>;
    })}</ul>
  </>;
}

function LogonStrip({ row }: { row: Row }) {
  const days = objects(row.logon_days);
  const totals = object(row.logon_totals);
  if (!days.length) return null;
  const points = (key: string) => days.map((day) => ({ x: String(day.day), y: typeof day[key] === "number" ? day[key] : null }));
  return <Section title={cardText("period")}>
    <FactList facts={[
      { label: cardText("successes"), value: text(String(totals.successes ?? "")) },
      { label: cardText("failures"), value: text(String(totals.failures ?? "")) },
      { label: cardText("typical"), value: text(String(totals.typical ?? "")) },
    ]}/>
    <Chart height={160} title={cardText("daily_logons")} spec={{ kind: "timeseries", series: [
      { name: cardText("failures"), style: "bar", points: points("failures") },
      { name: cardText("successes"), style: "line", points: points("successes") },
      { name: cardText("typical"), style: "dashed", points: days.map((day) => ({ x: String(day.day), y: typeof totals.typical === "number" ? totals.typical : null })) },
    ] }}/>
  </Section>;
}

export function UserCard({ selected, columns, timeZone, initialTab, historical, allowJournal, allowProblems, allowChanges, onClose }: {
  selected: Row; columns: ReportColumnDto[]; timeZone: string; initialTab: string; historical: boolean;
  allowJournal: boolean; allowProblems: boolean; allowChanges: boolean; onClose: () => void;
}) {
  const { formatDateTime, formatCell } = useDateFormatters();
  const [tab, setTab] = useState(initialTab);
  const id = exactNavigationId(selected.entity_id, "entity_id");
  const domain = exactNavigationId(selected.domain_id, "entity_id");
  const query = useQuery({ queryKey: ["ad-user-card", domain, id, timeZone], enabled: !!id && !historical,
    queryFn: async () => {
      const params = new URLSearchParams({ tab: "all", tz: timeZone });
      if (domain) params.set("domain", domain);
      return (await api.reportV2Detail("ad.users.v2", id!, params)).items[0] ?? null;
    }, retry: false, staleTime: 60_000, refetchOnWindowFocus: false });
  const row = { ...selected, ...query.data };
  const sam = text(row.sam);
  const account = sam && text(row.domain_name) && !sam.includes("\\") ? `${row.domain_name}\\${sam}` : sam;
  const name = text(row.display_name) ?? account ?? missing();
  const returnTo = window.location.pathname + window.location.search;
  const journalParams = new URLSearchParams({ q: text(row.sid) ?? sam ?? "", period: "30d" });
  if (domain) journalParams.set("domain", domain);
  const scope = id && domain ? { entity_id: id, domain } : null;
  const problemsParams = new URLSearchParams({ ...scope, population: "open" });
  const problems = useQuery({
    queryKey: ["report-v2", "user-open-problems", domain, id],
    enabled: allowProblems && scope !== null,
    queryFn: () => api.reportV2Data("security.problems", new URLSearchParams({ ...scope, population: "open", queue_view: "all", limit: "1" })),
    retry: false,
  });
  const counts = problems.data?.coverage.open_by_severity;
  const openCount = counts && !problems.isError ? Object.values(counts).reduce((total, count) => total + count, 0) : null;
  const canSee = (key: string) => columns.some((column) => column.key === key);
  const events = objects(row.timeline).filter((event) => [4624, 4625].includes(Number(event.event_id)));
  const computers = objects(row.computers);
  const deviations = userDeviations(row);
  const values = [
    { key: "state", label: cardText("ad_state"), value: typeof row.enabled === "boolean"
      ? <><UserStateMark enabled={row.enabled}/> {cardText(row.enabled ? "enabled" : "disabled")}</> : null },
    { key: "department", label: cardText("department"), value: text(row.department) },
    { key: "ou", label: "OU", value: text(row.ou) },
    { key: "password_last_set", label: cardText("password_last_set"), value: formatCell(row.password_last_set, "date") },
    { key: "activity", label: cardText("last_activity"), value: formatDateTime(text(row.activity_at)) },
    { key: "activity_source", label: cardText("activity_source"), value: text(row.activity_source)?.includes("lastLogon across all")
      ? cardText("source_dc") : text(row.activity_source) ? cardText("source_ad") : null },
  ].filter((fact) => canSee(fact.key) && (fact.key !== "department" || fact.value !== null));
  return <DetailDrawer open responsive title={name} subtitle={account !== name ? account : undefined} onClose={onClose} footer={<>
    {allowJournal && sam ? <a className="sli-ds-button" data-variant="primary" href={withReturnTo(`/app/report/events.journal?${journalParams}`, returnTo)}>{cardText("journal")}</a> : null}
    <CopyFactsButton text={rowFactsText(name, columns, row, timeZone)}/>
  </>}>
    <Tabs items={tabs.map((key) => ({ key, label: cardText(key) }))} active={tab} onChange={setTab}>
      <TabList label={cardText("tabs")}/>
      <TabPanel>
        {query.isError ? <div role="alert">{cardText("load_error")} <button type="button" className="sli-ds-button" onClick={() => void query.refetch()}>{t("state.retry")}</button></div> : null}
        {tab === "account" ? <>
          <FactList facts={values}/>
          {scope && (allowProblems || allowChanges) ? <ul className="sli-ds-path">
            {allowProblems ? <li><a href={withReturnTo(`/app/report/security.problems?${problemsParams}`, returnTo)}>
              {openCount === null ? cardText("problems") : t("reports.ad.users.card.open_problems", { count: formatNumber(openCount) })} →
            </a></li> : null}
            {allowChanges ? <li><a href={withReturnTo(`/app/report/security.events.chains?${new URLSearchParams(scope)}`, returnTo)}>
              {cardText("object_changes")} →
            </a></li> : null}
          </ul> : null}
          {deviations.length ? <Section title={t("reports.ad.users.list.deviation")}>
            <ul className="sli-ds-path">{deviations.map((reason) => <li key={reason.key}>
              {reason.severity ? <><SeverityBadge severity={reason.severity}/> </> : null}{reason.label}
            </li>)}</ul>
          </Section> : null}
          {computers.length ? <Section title={cardText("computers")}>
            <DataTable caption={cardText("computers")} rows={computers} rowKey={(computer) => String(computer.computer)} columns={[
              { key: "computer", label: cardText("computer") },
              { key: "at_utc", label: cardText("last_logon"), render: (computer) => {
                const href = eventEvidenceHref(computer.id);
                const date = formatDateTime(text(computer.at_utc));
                return href ? <a href={withReturnTo(href, returnTo)}>{date}</a> : date;
              } },
            ]} wrapCells="all" stickyHeader={false} showFooter={false}/>
          </Section> : null}
        </> : tab === "rights" ? <Privileges row={row}/>
          : <>
            <LogonStrip row={row}/>
            <Timeline rows={events} returnTo={returnTo}/>
            {!query.isFetching && !query.isError && !events.length ? <p>{missing()}</p> : null}
          </>}
      </TabPanel>
    </Tabs>
  </DetailDrawer>;
}
