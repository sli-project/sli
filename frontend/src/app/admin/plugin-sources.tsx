import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError, type AgentCollectionHealth, type SetupStatus } from "../../api/client";
import { StateView } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { useTimeZone } from "../App";
import { setupSourceName } from "./setup-source-labels";
import { agentHostName } from "./agent-actions";

const packs: Record<string, string[]> = {
  "sli.ad": ["sli.windows.ad-context", "sli.windows.ad-dc"], "sli.gpo": ["sli.windows.ad-context"],
  "sli.workstations": ["sli.windows.workstations"], "sli.file-audit": ["sli.windows.file-audit"],
  "sli.remote-access": ["sli.windows.vpn-radius"], "sli.sigma": [],
};
const modules: Record<string, string[]> = {
  "sli.ad": ["sli.windows.ad-dc", "sli.windows.ad-dc-history", "sli.ad-snapshot"], "sli.gpo": ["sli.gpo-snapshot"],
  "sli.workstations": ["sli.workstations"], "sli.file-audit": ["sli.file-audit"],
  "sli.remote-access": ["sli.windows.vpn-radius"], "sli.sigma": [],
};

export function PluginReadState({ loading, error, retry }: { loading: boolean; error: Error | null; retry: () => void }) {
  if (loading) return <StateView state="loading" compact/>;
  if (error) return <StateView state={error instanceof ApiResponseError && error.status === 403 ? "denied" : "unavailable"} compact onRetry={retry}/>;
  return null;
}

const lastImport = (agent: AgentCollectionHealth["items"][number], pluginId: string) => agent.modules
  .filter((module) => modules[pluginId]?.includes(module.module_id)).flatMap((module) => module.channels)
  .map((channel) => channel.last_import_at).filter((stamp): stamp is string => !!stamp && Number.isFinite(Date.parse(stamp)))
  .sort((left, right) => Date.parse(right) - Date.parse(left))[0];

export function PluginSources({ pluginId, connection }: { pluginId: string; connection: boolean }) {
  const status = useQuery({ queryKey: ["setup-status"], queryFn: api.setupStatus });
  const agents = useQuery({ queryKey: ["agents"], queryFn: () => api.agents(), enabled: pluginId === "sli.file-audit" });
  return <>
    {connection ? <><p>{t(({
      "sli.ad": "pluginPage.needAd", "sli.gpo": "pluginPage.needAd", "sli.file-audit": "pluginPage.needFiles",
      "sli.remote-access": "pluginPage.needVpn", "sli.workstations": "pluginPage.needAgents", "sli.sigma": "pluginPage.needSigma",
    } as Record<string, MessageKey>)[pluginId])}</p><a href="/app/agents">{t("pluginPage.computers")}</a>
      {pluginId === "sli.ad" || pluginId === "sli.gpo" ? <p><a href="/app/setup#setup-domains">{t("pluginPage.manageDomains")}</a></p> : null}
    </> : null}
    <PluginReadState loading={status.isLoading} error={status.error} retry={() => void status.refetch()}/>
    {status.data ? <SourceObjects pluginId={pluginId} data={status.data}/> : null}
    {pluginId === "sli.file-audit" ? <>
      <PluginReadState loading={agents.isLoading} error={agents.error} retry={() => void agents.refetch()}/>
      {agents.data ? <><h2>{t("pluginPage.serversFolders")}</h2>{agents.data.items.filter((agent) => agent.assigned_modules.some((module) => typeof module === "string" ? module === "sli.file-audit" : module.module_id === "sli.file-audit")).map((agent) => {
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
  const last = (stamp: string | null | undefined) => t(stamp === undefined ? "pluginPage.coverageUnavailable" : stamp ? "pluginPage.latest" : "pluginPage.noData", { time: formatDateTime(stamp, timeZone) });
  const agentRow = (agent: AgentCollectionHealth["items"][number]) => <li key={agent.id}>
    <a href={`/app/agents?agent_id=${encodeURIComponent(agent.id)}`}>{agent.name}</a> · {last(lastImport(agent, pluginId))}
  </li>;
  return <>
    {health?.state === "unavailable" || health?.diagnostics?.state === "unavailable" ? <StateView state="unavailable" compact detail={t("pluginPage.coverageUnavailable")}/> : null}
    {domainPlugin ? <>
      {domains.length ? <div className="sli-ds-field"><label htmlFor="plugin-domain">{t("pluginPage.object")}</label><select id="plugin-domain" value={selected} onChange={(event) => setSelected(event.target.value)}>
        <option value="">{t("pluginPage.allDomains")}</option>{domains.map((domain) => <option key={domain} value={domain}>{domain}</option>)}
      </select></div> : <p>{t("pluginPage.noDomains")}</p>}
      {domains.filter((domain) => !selected || selected === domain).map((domain) => {
        const controllers = data.domain_controllers.filter((controller) => controller.domain?.toLowerCase() === domain.toLowerCase());
        const domainAgents = agents.filter((agent) => agent.domains.some((name) => name.toLowerCase() === domain.toLowerCase()));
        return <details key={domain} open className="sli-ds-filters__additional"><summary>{domain}</summary>
          {pluginId === "sli.ad" ? <p>{last(data.domains.find((item) => item.fqdn === domain)?.observed_at_utc)}</p> : null}
          <h2>{t("pluginPage.controllers")}</h2>
          {!controllers.length && !domainAgents.length ? <p>{t("pluginPage.noControllers")}</p> : <ul>{controllers.map((controller) => {
            const agent = domainAgents.find((item) => item.name.toLowerCase() === controller.hostname.toLowerCase());
            return <li key={controller.hostname}>{controller.hostname} · {controller.enabled ? last(agent ? lastImport(agent, pluginId) : undefined) : t("plugins.disabled")}</li>;
          })}{domainAgents.filter((agent) => !controllers.some((controller) => controller.hostname.toLowerCase() === agent.name.toLowerCase())).map(agentRow)}</ul>}
        </details>;
      })}
      {data.domain_controllers.some((controller) => !controller.domain) ? <><h2>{t("pluginPage.unknownDomain")}</h2><ul>{data.domain_controllers.filter((controller) => !controller.domain).map((controller) => <li key={controller.hostname}>{controller.hostname} · {t("pluginPage.coverageUnavailable")}</li>)}</ul></> : null}
    </> : <>
      {agents.length ? <ul>{agents.map(agentRow)}</ul> : null}
      {!agents.length && !sources.some((source) => source.instances?.length) ? <p>{t(pluginId === "sli.remote-access" ? "pluginPage.noVpn" : pluginId === "sli.sigma" ? "pluginPage.sigmaSources" : "pluginPage.noSources")}</p> : null}
    </>}
    {sources.map((source) => <details key={source.pack_id} open className="sli-ds-filters__additional"><summary>{setupSourceName(source)}</summary>
      {!source.enabled ? <p>{t("plugins.disabled")}</p> : null}
      {source.instances?.length ? <ul>{source.instances.map((instance) => <li key={instance.source_instance_id}>
        {instance.source_instance_id} · {instance.data_state === "unavailable" ? t("pluginPage.coverageUnavailable") : last(instance.last_data_utc)}
      </li>)}</ul> : <p>{t(source.data_state === "unavailable" ? "pluginPage.coverageUnavailable" : "pluginPage.noData")}</p>}
    </details>)}
  </>;
}
