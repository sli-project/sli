import { Select } from "../../design-system/Select";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError, type AgentCollectionHealth, type SetupStatus } from "../../api/client";
import { Button, StateView } from "../../design-system";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { useTimeZone } from "../App";
import { setupSourceName } from "./setup-source-labels";
import { agentHostName } from "./agent-actions";
import { PluginFileAuditControls } from "./plugin-file-audit-controls";

const packs: Record<string, string[]> = {
  "sli.ad": ["sli.windows.ad-context", "sli.windows.ad-dc"], "sli.gpo": ["sli.windows.ad-context"],
  "sli.sigma": ["sli.windows.ad-context", "sli.windows.ad-dc"],
};
const modules: Record<string, string[]> = {
  "sli.ad": ["sli.windows.ad-dc", "sli.windows.ad-dc-history", "sli.ad-snapshot"], "sli.gpo": ["sli.gpo-snapshot"],
  "sli.workstations": ["sli.workstations"], "sli.file-audit": ["sli.file-audit"],
  "sli.sigma": ["sli.windows.ad-dc"],
};

export function PluginReadState({ loading, error, retry, message = t("plugins.unavailable") }: {
  loading: boolean; error: Error | null; retry: () => void; message?: string;
}) {
  if (loading) return <StateView state="loading" compact/>;
  if (error instanceof ApiResponseError && [401, 403].includes(error.status)) return <p role="status">{t("state.denied.title")}</p>;
  if (error) return <p role="alert">{message} <Button onClick={retry}>{t("state.retry")}</Button></p>;
  return null;
}

const lastImport = (agent: AgentCollectionHealth["items"][number], pluginId: string) => agent.modules
  .filter((module) => modules[pluginId]?.includes(module.module_id)).flatMap((module) => module.channels)
  .map((channel) => channel.last_import_at).filter((stamp): stamp is string => !!stamp && Number.isFinite(Date.parse(stamp)))
  .sort((left, right) => Date.parse(right) - Date.parse(left))[0];

export function PluginSources({ pluginId, connection, canEdit, sourceCount }: {
  pluginId: string; connection: boolean; canEdit: boolean; sourceCount?: number;
}) {
  const showSources = Object.hasOwn(packs, pluginId) || (sourceCount ?? 0) > 0;
  const status = useQuery({ queryKey: ["setup-status"], queryFn: api.setupStatus, enabled: showSources });
  const manageFiles = pluginId === "sli.file-audit" && canEdit && connection;
  const agents = useQuery({ queryKey: ["admin-agents"], queryFn: () => api.agents(), enabled: manageFiles });
  const fileServers = agents.data?.items.filter((agent) => agent.assigned_modules.some((module) =>
    typeof module === "string" ? module === "sli.file-audit" : module.module_id === "sli.file-audit")) ?? [];
  return <>
    {connection && (pluginId === "sli.ad" || pluginId === "sli.gpo") ? <p><a href="/app/setup#setup-domains">{t("pluginPage.manageDomains")}</a></p> : null}
    {showSources ? <>
      <PluginReadState loading={status.isLoading} error={status.error} message={t("pluginPage.sourcesFailed")} retry={() => void status.refetch()}/>
      {status.data && !status.isError ? <SourceObjects pluginId={pluginId} data={status.data}/> : null}
    </> : null}
    {manageFiles ? <>
      <PluginReadState loading={agents.isLoading} error={agents.error} message={t("pluginPage.sourcesFailed")} retry={() => void agents.refetch()}/>
      {agents.data?.items.some((agent) => agent.status === "active") && !agents.isError ? <PluginFileAuditControls agents={agents.data.items}/> : null}
      {fileServers.length > 0 && !agents.isError ? <><h2>{t("pluginPage.serversFolders")}</h2>{fileServers.map((agent) => {
        const module = agent.assigned_modules.find((item) => typeof item !== "string" && item.module_id === "sli.file-audit");
        const roots: unknown[] = module && typeof module !== "string" && Array.isArray(module.config.roots) ? module.config.roots : [];
        return <details key={agent.id} className="sli-ds-filters__additional"><summary>{agentHostName(agent)}</summary>
          <a href={`/app/agents?agent_id=${encodeURIComponent(agent.id)}`}>{t("pluginPage.openComputer")}</a>
          {roots.length ? <ul>{roots.map((root, index) => <li key={index}>{root && typeof root === "object" && typeof (root as { path?: unknown }).path === "string" ? (root as { path: string }).path : t("pluginPage.notSet")}</li>)}</ul> : <p>{t("pluginPage.noFolders")}</p>}
        </details>;
      })}</> : null}
    </> : null}
  </>;
}

function SourceObjects({ pluginId, data }: { pluginId: string; data: SetupStatus }) {
  const { timeZone } = useTimeZone();
  const [selected, setSelected] = useState("");
  const domainPlugin = pluginId === "sli.ad" || pluginId === "sli.gpo";
  const sources = data.sources.filter((source) => packs[pluginId]?.includes(source.pack_id));
  const health = data.agent_collection;
  const agents = health?.items.filter((agent) => agent.modules.some((module) => modules[pluginId]?.includes(module.module_id))) ?? [];
  const domains = domainPlugin ? [...new Set([...data.domains.filter((domain) => !domain.is_archived).map((domain) => domain.fqdn),
    ...data.domain_controllers.flatMap((controller) => controller.domain ? [controller.domain] : []), ...agents.flatMap((agent) => agent.domains)])] : [];
  const last = (stamp: string) => t("pluginPage.latest", { time: formatDateTime(stamp, timeZone) });
  const agentRow = (agent: AgentCollectionHealth["items"][number]) => {
    const stamp = lastImport(agent, pluginId);
    return <li key={agent.id}>
      <a href={`/app/agents?agent_id=${encodeURIComponent(agent.id)}`}>{agent.name}</a>{stamp ? ` · ${last(stamp)}` : null}
    </li>;
  };
  const sourcesUnavailable = health?.state === "unavailable" || health?.diagnostics?.state === "unavailable";
  return <>
    {sourcesUnavailable ? <p role="status">{t("pluginPage.sourcesFailed")}</p> : null}
    {domainPlugin ? <>
      {domains.length ? <div className="sli-ds-field"><label htmlFor="plugin-domain">{t("pluginPage.object")}</label><Select label={t("pluginPage.object")} id="plugin-domain" value={selected} onChange={(selectedValue) => setSelected(selectedValue)}
        options={[{ value: "", label: t("pluginPage.allDomains") }, ...(domains.map((domain) => ({ value: domain, label: domain })) ?? [])]}/></div> : <p>{t("pluginPage.noDomains")}</p>}
      {domains.filter((domain) => !selected || selected === domain).map((domain) => {
        const controllers = data.domain_controllers.filter((controller) => controller.domain?.toLowerCase() === domain.toLowerCase());
        const domainAgents = agents.filter((agent) => agent.domains.some((name) => name.toLowerCase() === domain.toLowerCase()));
        const stamp = data.domains.find((item) => item.fqdn === domain)?.observed_at_utc;
        return <details key={domain} open className="sli-ds-filters__additional"><summary>{domain}</summary>
          {pluginId === "sli.ad" && stamp ? <p>{last(stamp)}</p> : null}
          <h2>{t("pluginPage.controllers")}</h2>
          {!controllers.length && !domainAgents.length ? <p>{t("pluginPage.noControllers")}</p> : <ul>{controllers.map((controller) => {
            const agent = domainAgents.find((item) => item.name.toLowerCase() === controller.hostname.toLowerCase());
            const stamp = agent ? lastImport(agent, pluginId) : undefined;
            return <li key={controller.hostname}>{controller.hostname}
              {!controller.enabled ? ` · ${t("plugins.status.disabled")}` : stamp ? ` · ${last(stamp)}` : null}
            </li>;
          })}{domainAgents.filter((agent) => !controllers.some((controller) => controller.hostname.toLowerCase() === agent.name.toLowerCase())).map(agentRow)}</ul>}
        </details>;
      })}
      {data.domain_controllers.some((controller) => !controller.domain) ? <><h2>{t("pluginPage.unknownDomain")}</h2><ul>{data.domain_controllers.filter((controller) => !controller.domain).map((controller) => <li key={controller.hostname}>{controller.hostname}</li>)}</ul></> : null}
    </> : agents.length > 0 ? <ul>{agents.map(agentRow)}</ul> : null}
    {sources.map((source) => <details key={source.pack_id} open className="sli-ds-filters__additional"><summary>{setupSourceName(source)}</summary>
      {!source.enabled ? <p>{t("plugins.status.disabled")}</p> : null}
      {source.instances?.length ? <ul>{source.instances.map((instance) => <li key={instance.source_instance_id}>
        {instance.source_instance_id}{instance.last_data_utc ? ` · ${last(instance.last_data_utc)}` : null}
      </li>)}</ul> : null}
    </details>)}
  </>;
}
