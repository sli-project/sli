import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { t, type MessageKey } from "../../i18n";
import { PluginReadState } from "./plugin-sources";

const sourceStates: Record<string, MessageKey> = {
  disabled: "pluginPage.radius.sourceDisabled",
  subscription_disabled: "pluginPage.radius.subscriptionDisabled",
  manual_enabled: "pluginPage.radius.sourceEnabled",
};
export function PluginRadiusSources() {
  const query = useQuery({ queryKey: ["radius-plugin-sources"], queryFn: api.radiusPluginSources, refetchInterval: 15_000 });
  const retry = () => void query.refetch();
  const readError = t("pluginPage.radius.failed");
  if (query.isLoading || query.error) return <PluginReadState loading={query.isLoading} error={query.error} message={readError} retry={retry}/>;
  const observed = query.data?.item.observed;
  if (observed?.status !== "ok") return <PluginReadState loading={false} error={new Error(readError)} message={readError} retry={retry}/>;
  if (!observed.sources.length) return <p>{t("pluginPage.radius.missing")}</p>;
  const sources = new Map<string, Set<string>>();
  for (const source of observed.sources) {
    const states = sources.get(source.source_instance_id) ?? new Set<string>();
    states.add(source.source_state);
    sources.set(source.source_instance_id, states);
  }
  return <div className="sli-ds-table"><div className="sli-ds-table__scroll"><table>
    <thead><tr>
      <th scope="col">{t("pluginPage.radius.source")}</th>
      <th scope="col">{t("pluginPage.radius.collection")}</th>
    </tr></thead>
    <tbody>{Array.from(sources, ([id, states]) => <tr key={id}>
      <td>{id}</td>
      <td>{Array.from(states, (state) => t(Object.hasOwn(sourceStates, state) ? sourceStates[state] : "pluginPage.radius.stateUnavailable")).join(" · ")}</td>
    </tr>)}</tbody>
  </table></div></div>;
}
