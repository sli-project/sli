import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError, type PluginState } from "../../api/client";
import { Badge, PageHeader, Tabs, TabList, TabPanel, StateView } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { useEffectiveAccess, useTimeZone } from "../App";
import { formatDateTime } from "../../shared/date-time";
import { navigationRedirect } from "../navigation";
import { PluginSettingsForm } from "./plugin-settings-form";
import { PluginReadState, PluginSources } from "./plugin-sources";
import { PluginRadiusSources } from "./plugin-radius-sources";
import { fileAuditAgentParameter } from "./plugin-file-audit-controls";

const tabIds = ["overview", "connection", "settings", "rules", "reports"] as const;

/** Mounted only after the existing administration access gate has allowed this route. */
export function PluginPage({ pluginId, title }: { pluginId: string; title: string }) {
  const access = useEffectiveAccess();
  const [tab, setTab] = useState<string>(() => pluginId === "sli.file-audit"
    && new URLSearchParams(window.location.search).has(fileAuditAgentParameter) ? "connection" : "overview");
  const client = useQueryClient();
  const { timeZone } = useTimeZone();
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: api.plugins });
  const settings = useQuery({ queryKey: ["plugin-settings", pluginId], queryFn: () => api.pluginSettings(pluginId), enabled: tab === "settings" || tab === "rules" });
  const reports = useQuery({ queryKey: ["reports-v2-catalog"], queryFn: api.reportsV2Catalog, enabled: tab === "reports" });
  const sigma = useQuery({ queryKey: ["sigma-rules"], queryFn: () => api.sigmaRules(), enabled: tab === "rules" && pluginId === "sli.sigma" });
  const item = plugins.data?.items.find((plugin) => plugin.plugin_id === pluginId);
  const canEdit = !!access && (access.platform_owner === true || access.subject.coarse_role === "admin");
  const canManageAgents = canEdit && (access.platform_owner === true || access.capabilities.includes("access.manage"));
  const change = useMutation({
    mutationFn: ({ item, enabled }: { item: PluginState; enabled: boolean }) => api.setPluginEnabled(item, enabled),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["plugins"] });
      void client.invalidateQueries({ queryKey: ["report-v2"] });
      void client.invalidateQueries({ queryKey: ["reports-v2-catalog"] });
      void client.invalidateQueries({ queryKey: ["setup-status"] });
      void client.invalidateQueries({ queryKey: ["radius-plugin-sources"] });
    },
    onError: () => void client.invalidateQueries({ queryKey: ["plugins"] }),
  });
  const receipt = item?.data_receipts;
  const latest = receipt ? receipt.last_received_at : item?.last_data_at_utc;
  const pluginReports = reports.data?.items.filter((report) => report.owner_id === pluginId
    && (!["sli.file-audit", "sli.remote-access"].includes(pluginId) || !navigationRedirect(`/report/${report.key}`, {}))) ?? [];
  return <section className="sli-ds-report">
    <PageHeader title={title} subtitle={item ? <Badge tone={item.enabled ? "success" : "neutral"}>{t(!item.enabled ? "plugins.disabled" : item.component_runtime === "running" ? "plugins.runtime.running" : item.component_runtime === "draining" ? "plugins.runtime.draining" : item.component_runtime === "stopped" ? "plugins.runtime.stopped" : "plugins.runtime.unknown")}</Badge> : undefined}
      actions={item && plugins.data?.can_manage && canEdit ? <label><input type="checkbox" role="switch" checked={item.enabled}
        disabled={change.isPending || !item.installed || (!item.enabled && (!item.configured || item.component_runtime !== "stopped"))}
        onChange={(event) => change.mutate({ item, enabled: event.target.checked })}/>{t("plugins.enabled")}</label> : undefined}/>
    <PluginReadState loading={plugins.isLoading} error={plugins.error} retry={() => void plugins.refetch()}/>
    {plugins.data && !item ? <StateView state="empty" detail={t("plugins.error.notFound")}/> : null}
    {!canEdit ? <p role="note">{t("pluginPage.readOnly")}</p> : null}
    {change.error ? <p role="alert">{t(change.error instanceof ApiResponseError && change.error.code === "plugin_not_configured" ? "plugins.error.notConfigured"
      : change.error instanceof ApiResponseError && change.error.code === "plugin_revision_conflict" ? "plugins.error.revisionConflict" : "plugins.changeFailed")}</p> : null}
    <Tabs active={tab} onChange={setTab} items={tabIds.map((key) => ({ key, label: t(`pluginPage.tab.${key}`) }))}>
      <TabList label={title}/><TabPanel>
        {tab === "overview" || tab === "connection" ? <>
          {tab === "overview" && item ? <p>{receipt?.state === "unavailable" ? t("plugins.receiptUnavailable") : receipt?.state === "not_supported" ? t("plugins.receiptUnsupported") : latest ? t("pluginPage.latest", { time: formatDateTime(latest, timeZone) }) : t("pluginPage.noData")}</p> : null}
          {pluginId === "sli.remote-access" ? <PluginRadiusSources connection={tab === "connection"}/>
            : <PluginSources key={pluginId} pluginId={pluginId} connection={tab === "connection"} canEdit={canManageAgents}/>}
        </> : null}
        {tab === "settings" || tab === "rules" ? <PluginReadState loading={settings.isLoading} error={settings.error} retry={() => void settings.refetch()}/> : null}
        {settings.data ? <div hidden={tab !== "settings"}><PluginSettingsForm key={pluginId} data={settings.data} canEdit={canEdit}/></div> : null}
        {tab === "rules" ? <>
          {settings.data?.rules?.length ? <ul className="sli-ds-link-list">{settings.data.rules.map((rule) => <li key={rule.rule_id}>
            {t(rule.name as MessageKey)}{rule.settings.length ? <p><button type="button" className="sli-ds-button" onClick={() => setTab("settings")}>{t("pluginPage.ruleSettings")}</button></p> : null}
          </li>)}</ul> : settings.data ? <p>{t("pluginPage.noRules")}</p> : null}
          {pluginId === "sli.sigma" ? <>
            <PluginReadState loading={sigma.isLoading} error={sigma.error} retry={() => void sigma.refetch()}/>
            {sigma.data?.state === "unavailable" ? <StateView state="unavailable" compact/> : sigma.data?.rules.length ? <ul>{sigma.data.rules.map((rule) => <li key={rule.rule_id}>{rule.title || t("pluginPage.unnamedRule")}</li>)}</ul> : sigma.data ? <p>{t("pluginPage.noRules")}</p> : null}
          </> : null}
          <p>{t("pluginPage.rulesReadOnly")}</p><a href="/app/platform-settings">{t("pluginPage.policyControls")}</a>
        </> : null}
        {tab === "reports" ? <>
          <PluginReadState loading={reports.isLoading} error={reports.error} retry={() => void reports.refetch()}/>
          {pluginReports.length ? <ul className="sli-ds-link-list">{pluginReports.map((report) => <li key={report.key}><a href={`/app/report/${encodeURIComponent(report.key)}`}>{report.title}</a><p>{report.description}</p></li>)}</ul> : reports.data ? <p>{t("pluginPage.noReports")}</p> : null}
        </> : null}
      </TabPanel>
    </Tabs>
  </section>;
}
