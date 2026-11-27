import { Checkbox } from "../../design-system/Checkbox";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError, type PluginState } from "../../api/client";
import { Button, PageHeader, Tabs, TabList, TabPanel } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { useEffectiveAccess, useTimeZone } from "../App";
import { navigationRedirect } from "../navigation";
import { SigmaLiveRules } from "../sigma-live-rules";
import { PluginSettingsForm } from "./plugin-settings-form";
import { PluginReadState, PluginSources } from "./plugin-sources";
import { PluginRadiusSources } from "./plugin-radius-sources";
import { fileAuditAgentParameter } from "./plugin-file-audit-controls";
import { moduleStatusText, pluginNextAction } from "./plugin-status";

const tabIds = ["overview", "connection", "settings", "rules", "reports"] as const;

/** Mounted only after the existing administration access gate has allowed this route. */
export function PluginPage({ pluginId, title }: { pluginId: string; title: string }) {
  const access = useEffectiveAccess();
  const sigmaPlugin = pluginId === "sli.sigma";
  const [tab, setTab] = useState<string>(() => {
    if (sigmaPlugin) return "rules";
    return pluginId === "sli.file-audit" && new URLSearchParams(window.location.search).has(fileAuditAgentParameter)
      ? "connection" : "overview";
  });
  const client = useQueryClient();
  const { timeZone } = useTimeZone();
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: api.plugins, refetchInterval: 5_000 });
  const settings = useQuery({ queryKey: ["plugin-settings", pluginId], queryFn: () => api.pluginSettings(pluginId), enabled: tab === "settings" || tab === "rules" && !sigmaPlugin });
  const reports = useQuery({ queryKey: ["reports-v2-catalog"], queryFn: api.reportsV2Catalog, enabled: tab === "reports" });
  const item = plugins.isError ? undefined : plugins.data?.items.find((plugin) => plugin.plugin_id === pluginId);
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
  const pluginReports = reports.data?.items.filter((report) => report.owner_id === pluginId
    && (!["sli.file-audit", "sli.remote-access"].includes(pluginId) || !navigationRedirect(`/report/${report.key}`, {}))) ?? [];
  const domainPlugin = pluginId === "sli.ad" || pluginId === "sli.gpo";
  const radiusPlugin = pluginId === "sli.remote-access";
  const nextAction = pluginNextAction(item?.status);
  const connectionAction = t("pluginPage.openConnection");
  const connectionButton = <Button onClick={() => setTab("connection")}>{connectionAction}</Button>;
  const rulesButton = <Button onClick={() => setTab("rules")}>{t("pluginPage.openSigmaRules")}</Button>;
  return <section className="sli-ds-report">
    <PageHeader title={title} subtitle={item ? moduleStatusText(item, timeZone) : undefined}
      actions={item && plugins.data?.can_manage && canEdit ? <Checkbox role="switch" aria-label={t("plugins.toggle")} checked={item.enabled} disabled={change.isPending || !item.installed || (!item.enabled && (!item.configured || item.component_runtime !== "stopped"))} onChange={(event) => change.mutate({ item, enabled: event.target.checked })}/> : undefined}/>
    <PluginReadState loading={plugins.isLoading} error={plugins.error} retry={() => void plugins.refetch()}/>
    {plugins.data && !plugins.isError && !item ? <p role="status">{t("plugins.error.notFound")}</p> : null}
    {change.error ? <p role="alert">{t(change.error instanceof ApiResponseError && change.error.code === "plugin_not_configured" ? "plugins.error.notConfigured"
      : change.error instanceof ApiResponseError && change.error.code === "plugin_revision_conflict" ? "plugins.error.revisionConflict" : "plugins.changeFailed")}</p> : null}
    <Tabs active={tab} onChange={setTab} items={tabIds.map((key) => ({ key, label: t(`pluginPage.tab.${key}`) }))}>
      <TabList label={title}/><TabPanel>
        {tab === "connection" || tab === "overview" && (domainPlugin || radiusPlugin) ? radiusPlugin ? <PluginRadiusSources/>
          : <PluginSources key={pluginId} pluginId={pluginId} connection={tab === "connection"} canEdit={canManageAgents} nextAction={nextAction}/> : null}
        {tab === "overview" && !domainPlugin && !radiusPlugin && item ? item.source_names?.length
          ? <ul>{item.source_names.map((name, index) => <li key={`${name}:${index}`}>{name}</li>)}</ul>
          : <p>{nextAction ?? (sigmaPlugin ? rulesButton : connectionButton)}</p> : null}
        {tab === "settings" || tab === "rules" && !sigmaPlugin ? <PluginReadState loading={settings.isLoading} error={settings.error}
          message={t(tab === "settings" ? "pluginPage.settingsFailed" : "pluginPage.rulesFailed")} retry={() => void settings.refetch()}/> : null}
        {settings.data ? <div hidden={tab !== "settings" || settings.isError}><PluginSettingsForm key={pluginId} data={settings.data} canEdit={canEdit}
          emptyAction={sigmaPlugin ? rulesButton : connectionButton}/></div> : null}
        {tab === "rules" ? sigmaPlugin ? <SigmaLiveRules sourceAction={item?.status?.reason === "no_sources" ? nextAction : undefined}/>
          : settings.data && !settings.isError ? settings.data.rules?.length ? <ul className="sli-ds-link-list">{settings.data.rules.map((rule) => <li key={rule.rule_id}>
            {t(rule.name as MessageKey)}{rule.settings.length ? <p><Button onClick={() => setTab("settings")}>{t("pluginPage.ruleSettings")}</Button></p> : null}
          </li>)}</ul> : <p>{t("pluginPage.noRules")} {connectionButton}</p> : null : null}
        {tab === "reports" ? <>
          <PluginReadState loading={reports.isLoading} error={reports.error} message={t("pluginPage.reportsFailed")} retry={() => void reports.refetch()}/>
          {!reports.isError && reports.data ? pluginReports.length ? <ul className="sli-ds-link-list">{pluginReports.map((report) => <li key={report.key}><a href={`/app/report/${encodeURIComponent(report.key)}`}>{report.title}</a><p>{report.description}</p></li>)}</ul>
            : <p>{t("pluginPage.noReports")} {nextAction ?? (sigmaPlugin ? rulesButton : connectionButton)}</p> : null}
        </> : null}
      </TabPanel>
    </Tabs>
  </section>;
}
