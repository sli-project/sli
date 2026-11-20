import type { AgentCollectionHealth } from "../api/client";
import { Button, useOverlays } from "../design-system";
import { t } from "../i18n";
import { agentCollectionDetail, agentCollectionHeader, agentCollectionName, agentCollectionSummary } from "./agent-collection-view";

/** Keep the shell compact; evidence and navigation belong in the drawer. */
export function CollectionStatus({ data, timeZone, canManageAgents }: {
  data?: AgentCollectionHealth | null;
  timeZone: string;
  canManageAgents: boolean;
}) {
  const { openDrawer } = useOverlays();
  const model = agentCollectionHeader(data, timeZone);
  const silent = data?.items.filter((agent) => !["current", "paused", "disabled"].includes(agent.state)) ?? [];
  if (!silent.length) return null;
  const summary = silent.length === 1 ? t("shell.collection.silent_one", { name: agentCollectionName(silent[0]) })
    : t("shell.collection.silent_many", { count: silent.length });
  const showDetails = () => openDrawer({ title: t("shell.collection.missing"), body: <>
    <h3>{model.title}</h3>
    <p>{model.detail}</p>
    {silent.map((agent) => <section key={agent.id}>
      <h3>{agentCollectionName(agent)}</h3>
      <p>{agentCollectionSummary(agent, data?.diagnostics)}</p>
      <p>{agentCollectionDetail(agent, timeZone)}</p>
      {canManageAgents ? <a href={agent.href} title={model.tooltip}>{t("operations.agent_collection.open")}</a> : null}
    </section>)}
    {canManageAgents ? <a href={model.href}>{t("agents.title")}</a> : null}
  </> });
  return <div className="sli-ds-shell__freshness" data-state={model.state} role="status" aria-live="polite">
    <span className="sli-ds-shell__light" aria-hidden="true"/>
    <span className="sli-ds-shell__label">
      <Button variant="ghost" className="sli-ds-shell__collection-link" onClick={showDetails}>{summary}</Button>
    </span>
  </div>;
}
