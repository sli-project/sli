import { Select } from "../../design-system/Select";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError, type AgentCollectionHealth, type SetupStatus } from "../../api/client";
import { Button, DataTable, StateView, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { useTimeZone } from "../App";
import { setupSourceName } from "./setup-source-labels";

const packs: Record<string, string[]> = {
  "sli.ad": ["sli.windows.ad-context", "sli.windows.ad-dc"], "sli.gpo": ["sli.windows.ad-context"],
  "sli.sigma": ["sli.windows.ad-context", "sli.windows.ad-dc"],
};
const modules: Record<string, string[]> = {
  "sli.ad": ["sli.windows.ad-dc", "sli.windows.ad-dc-history", "sli.ad-snapshot"], "sli.gpo": ["sli.gpo-snapshot"],
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

export function PluginSources({ pluginId, connection, sourceCount }: {
  pluginId: string; connection: boolean; sourceCount?: number;
}) {
  const showSources = Object.hasOwn(packs, pluginId) || (sourceCount ?? 0) > 0;
  const status = useQuery({ queryKey: ["setup-status"], queryFn: api.setupStatus, enabled: showSources });
  return <>
    {connection && (pluginId === "sli.ad" || pluginId === "sli.gpo") ? <p><a href="/app/setup#setup-domains">{t("pluginPage.manageDomains")}</a></p> : null}
    {showSources ? <>
      <PluginReadState loading={status.isLoading} error={status.error} message={t("pluginPage.sourcesFailed")} retry={() => void status.refetch()}/>
      {status.data && !status.isError ? pluginId === "sli.sigma"
        ? <SigmaSources data={status.data}/>
        : <SourceObjects pluginId={pluginId} data={status.data}/> : null}
    </> : null}
  </>;
}

function SigmaSources({ data }: { data: SetupStatus }) {
  const { timeZone } = useTimeZone();
  const rows = data.sources.filter(source => packs["sli.sigma"].includes(source.pack_id))
    .flatMap(source => (source.instances ?? []).filter(instance => isDomainSource(instance.source_instance_id))
      .map(instance => ({ ...instance, packId: source.pack_id })));
  const columns: TableColumn<(typeof rows)[number]>[] = [
    { key: "source", label: t("pluginPage.source"), render: row => row.source_instance_id },
    { key: "data", label: t("pluginPage.sourceData"), render: row => t(row.packId === "sli.windows.ad-dc"
      ? "pluginPage.sourceEvents" : "setup.source.name.adContext") },
    { key: "latest", label: t("pluginPage.sourceLatest"), render: row => row.last_data_utc
      ? formatDateTime(row.last_data_utc, timeZone)
      : t(row.data_state === "unavailable" ? "pluginPage.sourceDataUnavailable" : "pluginPage.sourceNotCollected") },
  ];
  if (!rows.length) return <p role="status">{t(data.agent_collection?.state === "unavailable" || data.agent_collection?.diagnostics
    ? "pluginPage.sourcesFailed" : "pluginPage.noSigmaSources")}</p>;
  return <DataTable columns={columns} rows={rows} rowKey={row => JSON.stringify([row.packId, row.source_instance_id])}
    caption={t("pluginPage.tab.connection")}/>;
}

const isDomainSource = (name: string) => name.trim().toLowerCase() !== "workstations.invalid";

function SourceObjects({ pluginId, data }: { pluginId: string; data: SetupStatus }) {
  const { timeZone } = useTimeZone();
  const [selected, setSelected] = useState("");
  const domainPlugin = pluginId === "sli.ad" || pluginId === "sli.gpo";
  const sources = data.sources.filter((source) => packs[pluginId]?.includes(source.pack_id));
  const health = data.agent_collection;
  const agents = health?.items.filter((agent) => agent.modules.some((module) => modules[pluginId]?.includes(module.module_id))) ?? [];
  const domains = domainPlugin ? [...new Set([...data.domains.filter((domain) => !domain.is_archived).map((domain) => domain.fqdn),
    ...data.domain_controllers.flatMap((controller) => controller.domain ? [controller.domain] : []), ...agents.flatMap((agent) => agent.domains)].filter(isDomainSource))] : [];
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
      {source.instances?.some(instance => isDomainSource(instance.source_instance_id)) ? <ul>{source.instances.filter(instance => isDomainSource(instance.source_instance_id)).map((instance) => <li key={instance.source_instance_id}>
        {instance.source_instance_id}{instance.last_data_utc ? ` · ${last(instance.last_data_utc)}` : null}
      </li>)}</ul> : null}
    </details>)}
  </>;
}
