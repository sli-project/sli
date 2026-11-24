import { useQuery } from "@tanstack/react-query";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { api } from "../api/client";
import { StateView, Tabs, TabList, TabPanel } from "../design-system";
import { t, type MessageKey } from "../i18n";
import { PluginReportPage } from "../plugins/routes";
import { useAccessStatus, useEffectiveAccess } from "./App";
import { reportWorkspace } from "./navigation";
import { ReportRenderer } from "./report-v2/ReportRenderer";

/** Groups existing renderers without changing report keys or their server authorization. */
export function ReportWorkspacePage({ reportKey, journalSearch }: { reportKey: string; journalSearch?: string }) {
  const workspace = reportWorkspace(reportKey);
  const catalog = useQuery({ queryKey: ["report-v2", "catalog"], queryFn: api.reportsV2Catalog,
    staleTime: 30_000, retry: false, enabled: !!workspace });
  const access = useEffectiveAccess();
  const accessStatus = useAccessStatus();
  const location = useLocation();
  const navigate = useNavigate();
  if (reportKey === "events.journal" && journalSearch !== undefined) return <ReportRenderer reportKey={reportKey} initialSearch={journalSearch}/>;
  if (reportKey === "ad.gpo.v2") return <ReportRenderer reportKey={reportKey} initialSearch={location.searchStr}/>;
  if (!workspace || reportKey.startsWith("file-audit.")) return <PluginReportPage reportKey={reportKey}/>;
  if (accessStatus === "отказ" || catalog.isError) return <StateView state="unavailable"/>;
  if (catalog.isLoading || !access) return <StateView state="loading"/>;
  const entry = catalog.data?.navigation?.sections.flatMap((section) => section.groups.flatMap((group) => group.entries))
    .find((item) => item.id === workspace.id) ?? workspace;
  const grants = new Set(access.reports.filter((report) => report.allowed).map((report) => report.report_key));
  const views = entry?.views?.filter((view) => view.reports.some((key) => grants.has(key))) ?? [];
  const requested = new URLSearchParams(new URL(location.href, "http://localhost").search).get("nav_view");
  const active = requested ? views.find((view) => view.id === requested) : views[0];
  if (!active || !entry) return <StateView state="denied"/>;
  if (reportKey === "vpn.connections") return <PluginReportPage reportKey={active.report_key}/>;
  const select = (id: string) => {
    // A different report has its own filters and internal tabs. Keep the domain scope.
    const current = location.search as Record<string, unknown>;
    const computerTab = active.report_key === "ad.computer-logons" && ["checks", "changes", "computers"].includes(id);
    const search = { ...(current.domain_id !== undefined ? { domain_id: current.domain_id }
      : current.domain !== undefined ? { domain: current.domain } : {}), nav_view: computerTab ? "computers" : id,
      ...(computerTab ? { tab: id } : {}) };
    void navigate({ to: entry.path, search: search as never });
  };
  if (active.report_key === "ad.computers.v6") return <ReportRenderer reportKey={active.report_key}
    additionalTabs={views.filter((view) => view.id !== active.id).map((view) => ({ key: view.id, label: t(view.label as MessageKey) }))}
    onAdditionalTab={select}/>;
  if (active.report_key === "ad.computer-logons") return <ReportRenderer reportKey={active.report_key}
    additionalTabs={views.some((view) => view.id === "computers") ? [
      { key: "checks", label: t("reports.computers.review") },
      { key: "changes", label: t("reports.computers.changes") },
      { key: "computers", label: t("reports.computers.all") },
    ] : []} onAdditionalTab={select}/>;
  return <Tabs items={views.map((view) => ({ key: view.id, label: t(view.label as MessageKey) }))} active={active.id} onChange={select}>
    <TabList label={t(entry.label as MessageKey)}/>
    <TabPanel><PluginReportPage key={active.report_key} reportKey={active.report_key}/></TabPanel>
  </Tabs>;
}
