import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { api, type HomeDecisionSummary } from "../api/client";
import { Badge, PageHeader, StateView } from "../design-system";
import { counted, getLocale, t, type MessageKey } from "../i18n";
import { resolveMessage } from "../i18n/messages";
import { useAccessStatus, useEffectiveAccess, useTimeZone } from "./App";
import { homeAssignee, homeDay, homeObjects, homeOccurrences, homeParams, homeTime } from "./home-view";
import { errorState } from "./report-v2/ReportRenderer";
import { ReportState } from "./report-v2/ReportState";

const severityKeys: Record<string, MessageKey> = {
  critical: "home.queue.critical", high: "home.queue.high", medium: "home.queue.medium", low: "home.queue.low",
};

function HomeDenied() {
  return <div className="sli-ds-state" data-state="denied" role="alert">
    <div className="sli-ds-state__title">{t("home.queue.denied.title")}</div>
    <p>{t("home.queue.denied.text")}</p>
    <div className="sli-ds-state__actions"><a className="sli-ds-button" data-variant="primary" href="/app/reports">{t("home.queue.request_access")}</a></div>
  </div>;
}

export function HomeComposition({ data, onRetry, actions }: { data: HomeDecisionSummary; onRetry: () => void; actions?: ReactNode }) {
  const denied = data.state === "denied";
  const unconfirmed = data.state === "partial" || data.state === "stale";
  const showAssignee = data.groups.some((group) => group.assigned_to?.trim());
  const remainingProblems = data.remaining_problems;
  return <>
    <PageHeader title={t("home.title")} actions={actions}/>
    {denied ? <HomeDenied/> : <>
      {data.groups.length ? <>
        <div className="sli-ds-report__views"><div className="sli-ds-table sli-ds-home-queue"><div className="sli-ds-table__scroll"><table aria-label={t("home.title")}>
          <thead><tr>
            <th scope="col">{t("home.queue.severity")}</th><th scope="col">{t("home.queue.problem")}</th>
            <th scope="col" data-home-detail data-align="end">{t("home.queue.new")}</th>
            <th scope="col" data-home-detail>{t("home.queue.latest")}</th>
            {showAssignee ? <th scope="col" data-home-detail>{t("home.queue.assignee")}</th> : null}
            <th scope="col" data-align="end">{t("home.queue.total")}</th><th data-home-detail aria-hidden="true"/>
          </tr></thead>
          <tbody>{data.groups.map((group) => <tr key={group.key}>
            <td><Badge tone={["critical", "high"].includes(group.severity) ? "danger" : group.severity === "medium" ? "warning" : "neutral"}>
              {t(severityKeys[group.severity] ?? "home.queue.no_data")}
            </Badge></td>
            <td><a className="sli-ds-home-queue__link" href={group.href}>{resolveMessage(group.title_message, group.title)}</a>
              {group.objects.length ? <> <span className="sli-ds-home-queue__objects">{homeObjects(group)}</span></> : null}
              {group.day ? <> <span>{t("home.queue.day", { day: homeDay(group.day) })}</span></> : null}</td>
            <td data-home-detail data-align="end">{group.new_count !== null && group.new_count > 0 ? <b>{group.new_count}</b> : t("home.queue.no_data")}</td>
            <td data-home-detail className="sli-ds-home-queue__time">{homeTime(group.last_seen_utc, data.time_zone)}</td>
            {showAssignee ? <td data-home-detail>{homeAssignee(group)}</td> : null}
            <td data-align="end">{group.day ? homeOccurrences(group.total) : group.total}</td><td data-home-detail aria-hidden="true">›</td>
          </tr>)}</tbody>
        </table></div></div></div>
        {remainingProblems === null || remainingProblems > 0 ? <p><a href={data.href}>{remainingProblems === null ? t("home.queue.more_unknown") : t("home.queue.more", {
          count: counted(remainingProblems, "problems"),
        })}</a></p> : null}
      </> : data.state === "empty" && data.total === 0 ? <div className="sli-ds-state" data-state="empty" role="status">
        <div className="sli-ds-state__title">{t("home.queue.empty")}</div>
      </div> : unconfirmed ? null : <ReportState state="error" detail={t("home.queue.load_failed")} onRetry={onRetry}/>}
    </>}
  </>;
}

export function HomePage() {
  const { timeZone } = useTimeZone();
  const access = useEffectiveAccess();
  const accessStatus = useAccessStatus();
  const canManageAgents = accessStatus === "получены" && Boolean(access?.platform_owner || access?.capabilities.includes("access.manage"));
  const inventory = useQuery({ queryKey: ["admin-agents"], queryFn: () => api.agents(), retry: false, enabled: canManageAgents });
  const canConfigureNotifications = access?.platform_owner || (access?.subject.coarse_role === "admin"
    && ["notifications.channels", "notifications.deliveries"].every((key) => access.reports.some((report) => report.report_key === key && report.allowed)));
  const actions = canManageAgents && inventory.isSuccess && inventory.data.items.length === 0 ? <>
    <a className="sli-ds-button" data-variant="primary" href="/app/agents?register=1">{t("home.addAgent")}</a>
    {canConfigureNotifications ? <a className="sli-ds-button" href="/app/notifications?tab=channels">{t("home.connectNotifications")}</a> : null}
  </> : null;
  const params = homeParams(window.location.search, timeZone);
  const summary = useQuery({ queryKey: ["home", "summary", "v3", params.toString(), getLocale(), access],
    queryFn: () => api.homeDecisions(params), staleTime: 30_000, retry: false, enabled: accessStatus === "получены" });
  const failure = summary.error ? errorState(summary.error) : null;
  return <section className="sli-ds-report sli-ds-home">
    {actions && !summary.data?.groups.length ? <PageHeader title={t("home.title")} actions={actions}/>
      : accessStatus === "загружается" || summary.isLoading || inventory.isLoading && !summary.data?.groups.length ? <><PageHeader title={t("home.title")}/><StateView state="loading" compact skeleton="table"/></>
      : accessStatus === "отказ" ? <><PageHeader title={t("home.title")}/><p role="alert">{t("home.queue.access_failed")}</p></>
      : failure ? <><PageHeader title={t("home.title")}/>{failure.state === "denied" ? <HomeDenied/> : <ReportState state="error" detail={failure.detail ?? t("home.queue.load_failed")} onRetry={() => void summary.refetch()}/>}</>
      : summary.data ? <HomeComposition data={summary.data} actions={actions} onRetry={() => void summary.refetch()}/> : null}
  </section>;
}

