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
import { moduleStatusText, pluginNextAction, pluginSilentAgents, useFileAuditResourceCounts } from "./plugin-status";
import { useAgentSetup } from "./agent-state";
import { withDomain } from "../domain-navigation";

const tabIds = ["overview", "connection", "settings", "rules", "reports"] as const;

/** Mounted only after the existing administration access gate has allowed this route. */
export function PluginPage({ pluginId, title }: { pluginId: string; title: string }) {
  const access = useEffectiveAccess();
  const sigmaPlugin = pluginId === "sli.sigma";
  const workstationPlugin = pluginId === "sli.workstations";
  const fileAudit = pluginId === "sli.file-audit";
  const [tab, setTab] = useState<string>(sigmaPlugin ? "rules" : fileAudit ? "settings" : "overview");
  const client = useQueryClient();
  const { timeZone } = useTimeZone();
  const plugins = useQuery({ queryKey: ["plugins"], queryFn: api.plugins, refetchInterval: 5_000 });
  const item = plugins.isError ? undefined : plugins.data?.items.find((plugin) => plugin.plugin_id === pluginId);
  const settings = useQuery({ queryKey: ["plugin-settings", pluginId], queryFn: () => api.pluginSettings(pluginId), enabled: !!item });
  const reports = useQuery({ queryKey: ["reports-v2-catalog"], queryFn: api.reportsV2Catalog, enabled: !!item });
  const counts = useFileAuditResourceCounts(!!item && fileAudit, access?.evaluated_at_utc, timeZone);
  const setup = useAgentSetup(Boolean(item && (access?.platform_owner || access?.capabilities.includes("access.manage"))));
  const canEdit = !!access && (access.platform_owner === true || access.subject.coarse_role === "admin");
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
  const pluginRules = settings.data?.rules ?? [];
  const hasSettings = !!settings.data && (Object.keys(settings.data.schema.properties ?? {}).length > 0
    || !!settings.data.schema["x-core-settings"]?.length);
  const availableTabs = tabIds.filter((key) => {
    switch (key) {
      case "connection": return !fileAudit && !workstationPlugin;
      case "overview": return !fileAudit;
      case "settings": return hasSettings || settings.isError;
      case "rules": return sigmaPlugin || pluginRules.length > 0 || settings.isError;
      case "reports": return pluginReports.length > 0 || reports.isError;
      default: return true;
    }
  });
  const activeTab = availableTabs.some((key) => key === tab) ? tab : availableTabs[0];
  const connection = activeTab === "connection";
  const overview = activeTab === "overview";
  const domainPlugin = pluginId === "sli.ad" || pluginId === "sli.gpo";
  const radiusPlugin = pluginId === "sli.remote-access";
  const pluginStatus = item ? t(item.enabled ? "plugins.enabled" : "plugins.status.disabled") : undefined;
  const silent = item && !setup.isError ? pluginSilentAgents(item, setup.data?.agent_collection) : 0;
  const fileSummary = pluginStatus && counts ? t("file-audit.resources.summary", { status: pluginStatus, ...counts }) : pluginStatus;
  const statusText = fileAudit ? [fileSummary, silent ? t("plugins.silentAgents", { count: silent }) : null].filter(Boolean).join(" · ")
    : item ? moduleStatusText(item, timeZone, undefined, silent) : undefined;
  const resourcesHref = withDomain("/app/report/file-audit.overview?tab=overview", window.location.search);
  const nextAction = pluginNextAction(item?.status);
  const openAgents = item?.status?.next_action === "connect_file_server" || item?.status?.next_action === "install_workstation_agent"
    || item?.status?.next_action === "connect_sigma_events";
  const connectionButton = <Button onClick={() => setTab("connection")}>{t("pluginPage.tab.connection")}</Button>;
  const rulesButton = <Button onClick={() => setTab("rules")}>{t("pluginPage.openSigmaRules")}</Button>;
  return <section className="sli-ds-report">
    <PageHeader title={title} subtitle={fileAudit && statusText ? <>{statusText} · <a href={resourcesHref}>{t("file-audit.screen.overview")}</a></> : statusText}
      actions={item && plugins.data?.can_manage && canEdit ? <Checkbox role="switch" aria-label={t("plugins.toggle")} checked={item.enabled} disabled={change.isPending || !item.installed || (!item.enabled && (!item.configured || item.component_runtime !== "stopped"))} onChange={(event) => change.mutate({ item, enabled: event.target.checked })}/> : undefined}/>
    <PluginReadState loading={plugins.isLoading} error={plugins.error} retry={() => void plugins.refetch()}/>
    {plugins.data && !plugins.isError && !item ? <p role="status">{t("plugins.error.notFound")}</p> : null}
    {change.error ? <p role="alert">{t(change.error instanceof ApiResponseError && change.error.code === "plugin_not_configured" ? "plugins.error.notConfigured"
      : change.error instanceof ApiResponseError && change.error.code === "plugin_revision_conflict" ? "plugins.error.revisionConflict" : "plugins.changeFailed")}</p> : null}
    {activeTab ? <Tabs active={activeTab} onChange={setTab} items={availableTabs.map((key) => ({ key, label: t(`pluginPage.tab.${key}`) }))}>
      <TabList label={title}/><TabPanel>
        {connection && statusText && openAgents
          ? <p><a href="/app/agents">{statusText}</a></p> : null}
        {connection || overview && (domainPlugin || radiusPlugin) ? radiusPlugin ? <PluginRadiusSources/>
          : <PluginSources key={pluginId} pluginId={pluginId} connection={connection}
            sourceCount={item?.source_count ?? item?.source_names?.length}/> : null}
        {overview && !fileAudit && !domainPlugin && !radiusPlugin && item ? item.source_names?.length
          ? <ul>{item.source_names.map((name, index) => <li key={`${name}:${index}`}>{name}</li>)}</ul>
          : workstationPlugin
            ? item.status?.next_action === "install_workstation_agent" && nextAction ? <p><a href="/app/agents">{nextAction}</a></p> : null
            : <p>{sigmaPlugin ? rulesButton : connectionButton}</p> : null}
        {activeTab === "settings" || activeTab === "rules" && !sigmaPlugin ? <PluginReadState loading={settings.isLoading} error={settings.error}
          message={t(activeTab === "settings" ? "pluginPage.settingsFailed" : "pluginPage.rulesFailed")} retry={() => void settings.refetch()}/> : null}
        {hasSettings && settings.data ? <div hidden={activeTab !== "settings" || settings.isError}><PluginSettingsForm key={pluginId} data={settings.data}
          canEdit={canEdit}/></div> : null}
        {activeTab === "rules" ? sigmaPlugin ? <SigmaLiveRules sourceAction={item?.status?.reason === "no_sources" ? nextAction : undefined}/>
          : !settings.isError && pluginRules.length > 0 ? <ul className="sli-ds-link-list">{pluginRules.map((rule) => <li key={rule.rule_id}>
            {t(rule.name as MessageKey)}{hasSettings && rule.settings.length ? <p><Button onClick={() => setTab("settings")}>{t("pluginPage.ruleSettings")}</Button></p> : null}
          </li>)}</ul> : null : null}
        {activeTab === "reports" ? <>
          <PluginReadState loading={reports.isLoading} error={reports.error} message={t("pluginPage.reportsFailed")} retry={() => void reports.refetch()}/>
          {!reports.isError && pluginReports.length > 0 ? <ul className="sli-ds-link-list">{pluginReports.map((report) => <li key={report.key}>
            <a href={`/app/report/${encodeURIComponent(report.key)}`}>{report.title}</a>
            {report.key !== "workstations.protection" && report.description ? <p>{report.description}</p> : null}
          </li>)}</ul> : null}
        </> : null}
      </TabPanel>
    </Tabs> : null}
  </section>;
}
