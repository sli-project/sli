import { useState } from "react";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { api, type EntityWorkspaceDetail, type EntityWorkspaceEvent, type V4ObjectDetail } from "../api/client";
import { Button, DataTable, FactList, PageHeader, SeverityBadge, StateView, Tabs, TabList, TabPanel, periodBounds, type TableColumn } from "../design-system";
import { t } from "../i18n";
import { eventSemanticText } from "../i18n/event-metadata";
import { browserTimeZone, formatDateTime } from "../shared/date-time";
import { EMPTY_VALUE, formatNumber } from "../shared/format";
import { AccountWatch } from "./account-watch";
import { entityProfileValue, shortEntityProfile } from "./entity-profile";
import { groupMembershipRowsView } from "./entity-ad-relations";
import { eventEvidenceHref, exactNavigationId } from "./event-presentation";
import { withReturnTo } from "./report-v2/legacy";
import { objectTypeLabel } from "./report-labels";
import { computerRole } from "../plugins/ad/ComputerChecks";
import { EntityChangesLink, useEntityOpenProblems, useEntityReportAccess } from "../plugins/ad/EntityCardReports";
import { UserLogonActivity, useUserCardDetail, userActivitySource } from "../plugins/ad/UserCard";
import { userObjects, userText } from "../plugins/ad/UserChecks";

type Row = Record<string, unknown>;
type AttentionRow = { id: string; title: string; severity: unknown; time: string | null; href?: string };
const ranks = ["critical", "high", "medium", "low"];
const rank = (value: unknown) => typeof value === "string" && ranks.includes(value) ? ranks.indexOf(value) : ranks.length;
const stamp = (value: unknown) => Date.parse(userText(value) ?? "") || 0;
const windowsCode = (row: EntityWorkspaceEvent) => row.event_id === 4624 ? t("reports.ad.users.event.success")
  : row.event_id === 4625 ? t("reports.ad.users.event.failure")
    : row.label && !row.label.startsWith("Event ID ") ? eventSemanticText(row.title_code ?? undefined, row.label) : t("entities.timeline.eventFallback");

function AttentionTable({ rows, format }: { rows: AttentionRow[]; format: (value: string | null) => string }) {
  const ordered = [...rows].sort((left, right) => rank(left.severity) - rank(right.severity) || stamp(right.time) - stamp(left.time));
  return <DataTable caption={t("entities.card.important")} rows={ordered} rowKey={(row) => row.id} showFooter={false} columns={[
    { key: "severity", label: t("entities.card.severity"), render: (row) => <SeverityBadge severity={row.severity}/> },
    { key: "title", label: t("entities.card.attentionItem"), render: (row) => row.href ? <a href={row.href}>{row.title}</a> : row.title },
    { key: "time", label: t("entities.section.events.colTime"), render: (row) => format(row.time) },
  ]}/>;
}

function EntityEvents({ data, bounds, zone, returnTo }: {
  data: EntityWorkspaceDetail; bounds: { from: string; to: string }; zone: string; returnTo: string;
}) {
  const id = String(data.entity.id);
  const query = useInfiniteQuery({
    queryKey: ["entity-card-events", id, bounds, zone],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ time_from: bounds.from, time_to: bounds.to, timezone: zone, limit: "50" });
      if (pageParam?.time_utc) {
        params.set("before_time_utc", pageParam.time_utc);
        params.set("before_event_db_id", String(pageParam.event_db_id));
        if (pageParam.summary_key) params.set("before_summary_key", pageParam.summary_key);
      }
      return api.entityWorkspace(id, params);
    },
    initialPageParam: null as EntityWorkspaceDetail["next_cursor"],
    getNextPageParam: (page) => page.next_cursor?.time_utc ? page.next_cursor : undefined,
    retry: false,
  });
  const pages = query.data?.pages ?? [];
  const renderTime = (value: string | null | undefined) => formatDateTime(value, zone, { seconds: true });
  if (query.isLoading) return <StateView state="loading"/>;
  if (pages[0]?.events_state === "forbidden") return <StateView state="denied"/>;
  if (query.isError && !pages.length || pages[0]?.events_state === "temporarily_unavailable")
    return <StateView state="error" detail={t("entities.card.eventsError")} onRetry={() => void query.refetch()}/>;
  const events = pages.flatMap((page) => page.events);
  if (!events.length) return <p>{t("entities.card.periodEmpty")}</p>;
  const columns: TableColumn<EntityWorkspaceEvent>[] = [
    { key: "severity", label: t("entities.card.severity"), render: (event) => <SeverityBadge severity={event.severity}
      label={rank(event.severity) < ranks.length ? undefined : t(event.severity === "info" ? "reports.computers.info" : "reports.metadata.not_assessed")}/> },
    { key: "label", label: t("entities.section.events.colEvent"), render: (event) => {
      const href = eventEvidenceHref(event.event_db_id);
      return href ? <a href={withReturnTo(href, returnTo)}>{windowsCode(event)}</a> : windowsCode(event);
    } },
    { key: "time_utc", label: t("entities.section.events.colTime"), render: (event) => renderTime(event.time_utc) },
  ];
  if (events.some((row) => row.server !== events[0].server))
    columns.push({ key: "server", label: t("entities.section.events.colSource") });
  return <DataTable caption={t("entities.tab.events")} columns={columns} rows={events}
    rowKey={(event) => String(event.event_db_id || event.summary_key)} hasMore={query.hasNextPage}
    loadingMore={query.isFetchingNextPage} onLoadMore={() => void query.fetchNextPage()}/>;
}

function ComputerLogons({ scope, bounds, zone }: {
  scope: { entity_id: string; domain: string }; bounds: { from: string; to: string }; zone: string;
}) {
  const query = useInfiniteQuery({
    queryKey: ["entity-card-computer-logons", scope, bounds, zone],
    queryFn: ({ pageParam }) => {
      const params = new URLSearchParams({ domain: scope.domain, ...bounds, period: "custom", tz: zone });
      if (pageParam) params.set("cursor", pageParam);
      return api.reportV2Detail("ad.computer-logons", scope.entity_id, params);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.has_more ? page.next_cursor : null,
    retry: false,
  });
  if (query.isLoading) return <StateView state="loading"/>;
  const pages = query.data?.pages ?? [];
  if (pages[0]?.state === "denied") return <StateView state="denied"/>;
  if (query.isError && !pages.length || pages[0]?.state === "error")
    return <StateView state="error" detail={t("entities.card.activityError")} onRetry={() => void query.refetch()}/>;
  const rows = pages.flatMap((page) => page.items);
  if (!rows.length) return <p>{pages[0]?.state === "empty" ? t("entities.card.periodEmpty") : EMPTY_VALUE}</p>;
  return <DataTable caption={t("entities.card.logons")} rows={rows} rowKey={(row) => String(row.row_id)} columns={[
    { key: "user_name", label: t("reports.computers.account") },
    { key: "observed_at_utc", label: t("reports.computers.time"), render: (row) => formatDateTime(userText(row.observed_at_utc), zone) },
  ]} hasMore={query.hasNextPage} loadingMore={query.isFetchingNextPage} onLoadMore={() => void query.fetchNextPage()}/>;
}

export function AdEntityCard({ data, object, fields, requestedTab, selectTab, returnTo, location, timeZone }: {
  data: EntityWorkspaceDetail; object?: V4ObjectDetail; fields: Parameters<typeof shortEntityProfile>[1];
  requestedTab: string; selectTab: (tab: string) => void; returnTo: string; location: string; timeZone: string;
}) {
  const { entity } = data;
  const user = entity.type === "ad_user";
  const id = exactNavigationId(entity.id, "entity_id");
  const domain = exactNavigationId(entity.domain_id, "entity_id");
  const scope = id && domain ? { entity_id: id, domain } : null;
  const zone = timeZone === "browser" ? browserTimeZone() : timeZone;
  const [defaultBounds] = useState(() => periodBounds({ preset: "30d" })!);
  const context = data.context;
  const bounds = context?.time_from_utc && context.time_to_utc_exclusive
    ? { from: context.time_from_utc, to: context.time_to_utc_exclusive } : defaultBounds;
  const format = (value: string | null | undefined) => formatDateTime(value, zone, { seconds: true });
  const report = user ? "ad.users.v2" : "ad.computers.v6";
  const allowInventory = useEntityReportAccess(report);
  const allowProblems = useEntityReportAccess("security.problems");
  const allowChanges = useEntityReportAccess("security.events.chains");
  const allowComputerLogons = useEntityReportAccess("ad.computer-logons");
  const card = useUserCardDetail(id, domain, zone, user && allowInventory && Boolean(scope), bounds);
  const computer = useQuery({
    queryKey: ["report-v2", "computer-entity-properties", scope],
    enabled: !user && allowInventory && scope !== null,
    queryFn: ({ signal }) => api.reportV2Data(report, new URLSearchParams({ ...scope, tab: "computers", limit: "1" }), signal),
    retry: false,
  });
  const checks = useQuery({
    queryKey: ["report-v2", "entity-checks", report, scope],
    enabled: allowInventory && scope !== null,
    queryFn: ({ signal }) => api.reportV2Data(report, new URLSearchParams({
      ...scope, tab: "checks", limit: "25", ...(user ? { account_rows: "yes" } : {}),
    }), signal),
    retry: false,
  });
  const open = useEntityOpenProblems(scope, allowProblems, 50);
  const facts = allowInventory ? computer.data?.items[0] : undefined;
  const agent = facts?.sli_agent as Row | undefined;
  const activityTab = user ? "activity" : "logons";
  const items = [
    { key: "important", label: t("entities.card.important") },
    { key: "properties", label: t("entities.card.properties") },
    ...(scope && (user ? allowInventory : allowComputerLogons && facts?.computer_type === "workstation")
      ? [{ key: activityTab, label: user ? t("reports.ad.users.card.activity") : t("entities.card.logons") }] : []),
    ...(object?.tabs.some((tab) => tab.id === "groups" && tab.available)
      ? [{ key: "groups", label: t("entities.card.groups") }] : []),
    { key: "events", label: t("entities.tab.events") },
  ];
  const showChecks = requestedTab === "checks";
  const wanted = requestedTab === "overview" ? "properties"
    : requestedTab === "findings" || showChecks ? "important" : requestedTab;
  const active = items.some((item) => item.key === wanted) ? wanted : "important";
  const name = entity.display_name || entity.natural_key || t("entities.unnamedEntity");
  const problemsHref = withReturnTo(`/app/report/security.problems?${open.params}`, location);
  const problemRows = (allowProblems ? open.query.data?.items ?? [] : []).flatMap((row): AttentionRow[] => {
    const rowId = exactNavigationId(row.id, "entity_id");
    const title = userText(row.title_text);
    if (!rowId || !title) return [];
    const params = new URLSearchParams(open.params);
    params.set("id", rowId);
    return [{ id: `problem:${rowId}`, title, severity: row.severity, time: userText(row.last_seen_utc),
      href: withReturnTo(`/app/report/security.problems?${params}`, location) }];
  });
  const checkRows = (allowInventory ? checks.data?.items ?? [] : []).flatMap((row) => {
    const rows = user ? userObjects(row.review_reasons) : [row];
    return rows.flatMap((check): AttentionRow[] => {
      const title = userText(user ? check.label : check.title);
      return title ? [{ id: `check:${check.key}`, title, severity: check.severity,
        time: userText(user ? row.observed_at_utc : check.last_seen_utc) }] : [];
    });
  });
  const checksAvailable = allowInventory && !!checks.data && ["ok", "empty", "partial", "stale"].includes(checks.data.state);
  const hasCheckResult = checkRows.length > 0 || Number(checks.data?.coverage.population) > 0;
  const checksCount = checksAvailable && hasCheckResult && !checks.isError ? checkRows.length : null;
  const attention = showChecks ? checkRows : [...problemRows, ...checkRows];
  const profile = shortEntityProfile(entity.type, fields, name).selected
    .filter((field) => !((user || facts?.last_logon_utc) && field.key === "last_logon"))
    .map((field) => ({ label: field.label, value: entityProfileValue(field.key, field.value, format) }));
  const lastActivity = userText(card.data?.activity_at);
  const groups = groupMembershipRowsView((object?.directory_context.items ?? []).filter((row) => row.current !== false), format);

  return <section className="sli-ds-report">
    <PageHeader title={name} subtitle={objectTypeLabel(entity.type)}
      actions={<a className="sli-ds-button" href={returnTo}>{t("entities.crumbs.back")}</a>}/>
    {scope ? <div className="sli-ds-list__actions">
      {allowProblems ? <a href={problemsHref}>{open.count === null ? t("reports.ad.users.card.problems")
        : t("reports.ad.users.card.open_problems", { count: formatNumber(open.count) })} →</a> : null}
      {checksCount !== null ? <Button aria-pressed={showChecks} onClick={() => selectTab(showChecks ? "important" : "checks")}>
        {t("entities.card.failedChecksCount", { count: formatNumber(checksCount) })}</Button> : null}
      {allowChanges ? <EntityChangesLink scope={scope} bounds={bounds} timeZone={zone} returnTo={location}/> : null}
    </div> : null}
    <Tabs items={items} active={active} onChange={selectTab}><TabList label={t("entities.tabs.aria")}/><TabPanel>
      {active === "important" ? <>
        {(!showChecks && open.query.isLoading) || checks.isLoading ? <StateView state="loading"/> : null}
        {!showChecks && (open.query.isError || open.query.data?.state === "error") ? <StateView state="error" detail={t("entities.card.problemsError")}
          onRetry={() => void open.query.refetch()}/> : null}
        {checks.isError || checks.data?.state === "error" ? <StateView state="error" detail={t("entities.card.checksError")}
          onRetry={() => void checks.refetch()}/> : null}
        {attention.length ? <AttentionTable rows={attention} format={format}/>
          : checksCount === 0 && (showChecks || open.count === 0)
            ? <p>{t(showChecks ? "entities.card.checksEmpty" : "entities.card.importantEmpty")}</p>
            : !open.query.isFetching && !checks.isFetching && !open.query.isError && !checks.isError
              && open.query.data?.state !== "error" && checks.data?.state !== "error" ? <p>{EMPTY_VALUE}</p> : null}
      </> : null}
      {active === "properties" ? <>
        {user && card.isError || !user && computer.isError ? <StateView state="error" detail={t("entities.card.propertiesError")}
          onRetry={() => void (user ? card : computer).refetch()}/> : null}
        <FactList facts={[
          ...profile,
          ...(user ? [{ label: t("reports.ad.users.card.last_activity"), value: lastActivity
            ? [format(lastActivity), userActivitySource(card.data?.activity_source)].filter(Boolean).join(" · ") : null }] : [
            { label: t("reports.ad.computers.role"), value: computerRole(facts?.computer_type) },
            ...(facts?.last_logon_utc ? [{ label: t("reports.computers.last_logon"), value: format(userText(facts.last_logon_utc)) }] : []),
            { label: t("reports.computers.agent"), value: agent?.state === "installed" || agent?.state === "silent"
              ? [userText(agent.version), agent.last_seen_utc ? t(agent.state === "silent" ? "reports.computers.agent_silent"
                : "reports.computers.agent_connected", { time: format(userText(agent.last_seen_utc)) }) : null].filter(Boolean).join(" · ") : null },
          ]),
        ]}/>
        {user ? <AccountWatch key={entity.id} entityId={entity.id}/> : null}
      </> : null}
      {active === "groups" ? groups.length ? <DataTable caption={t("entities.card.groups")} rows={groups} showFooter={false}
        rowKey={(row) => `${row.groupName}:${row.membershipType}`} columns={[
          { key: "groupName", label: t("entities.section.groups.colGroupObject") },
          { key: "membershipType", label: t("entities.section.groups.colMembershipType") },
          { key: "observedAt", label: t("entities.section.groups.colObserved") },
        ]}/> : <p>{EMPTY_VALUE}</p> : null}
      {active === "activity" ? card.isLoading ? <StateView state="loading"/>
        : card.isError ? <StateView state="error" detail={t("entities.card.activityError")} onRetry={() => void card.refetch()}/>
          : card.data?.timeline ? <UserLogonActivity row={card.data} returnTo={location}/> : <p>{EMPTY_VALUE}</p> : null}
      {active === "logons" && scope ? <ComputerLogons scope={scope} bounds={bounds} zone={zone}/> : null}
      {active === "events" ? <EntityEvents data={data} bounds={bounds} zone={zone} returnTo={location}/> : null}
    </TabPanel></Tabs>
  </section>;
}
