import type { AgentItem } from "../../api/client";
import { t } from "../../i18n";
import { useId, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import { api } from "../../api/client";
import { DataTable } from "../../design-system";

type OldAgent = { id: string; name: string; agent_version?: string | null; replacement_version?: string | null; certificate_reissue_required?: boolean };

export function OldAgentsTable({ agents, canRemove }: { agents: OldAgent[]; canRemove: boolean }) {
  const [selected, setSelected] = useState<OldAgent | null>(null);
  const description = useId();
  const heading = useId();
  const client = useQueryClient();
  const removal = useMutation({ mutationFn: (agent: OldAgent) => api.agentAction("remove", { operation_id: crypto.randomUUID(), agent_ids: [agent.id] }),
    onSuccess: () => { setSelected(null); void client.invalidateQueries({ queryKey: ["admin-agents"] }); void client.invalidateQueries({ queryKey: ["setup-status"] }); } });
  if (!agents.length) return null;
  return <>
    <h2 id={heading} className="sli-ds-section-title">{t("agents.oldAgents")}</h2>
    <DataTable columns={[
      { key: "name", label: t("agents.hostName") },
      { key: "agent_version", label: t("agents.version"), render: (agent) => agent.agent_version || "—" },
      { key: "status", label: t("agents.status"), render: (agent) => <span className="sli-ds-shell__freshness" data-state="neutral"><span className="sli-ds-shell__light" aria-hidden="true"/>{agent.certificate_reissue_required ? t("agents.certificateReissueRequired", { name: agent.name }) : agent.replacement_version ? t("agents.replacedByVersion", { version: agent.replacement_version }) : t("agents.replaced")}</span> },
      { key: "action", label: t("systemStatus.action"), render: (agent) => agent.certificate_reissue_required ? canRemove ? <a className="sli-ds-button" href="/app/agents?register=1">{t("agents.registerAgain")}</a> : "—" : canRemove ? <button type="button" className="sli-ds-button" disabled={removal.isPending} onClick={() => { removal.reset(); setSelected(agent); }}>{t("agents.removeOld")}</button> : t("agents.removeOldOnComputer", { name: agent.name }) },
    ]} rows={agents} rowKey={(agent) => agent.id} labelledBy={heading} showFooter={false}/>
    <ModalOverlay className="sli-ds-modal" isOpen={Boolean(selected)} isDismissable={!removal.isPending} onOpenChange={(open) => { if (!open && !removal.isPending) setSelected(null); }}>
      <Modal className="sli-ds-modal__panel"><Dialog aria-describedby={description}>
        <Heading slot="title" level={2}>{t("agents.confirmTitle", { action: t("agents.removeOld"), host: selected?.name ?? "—" })}</Heading>
        <p id={description}>{t("agents.confirmRemove")}</p>
        {removal.isError ? <p role="alert">{t("agents.oldRemoveError")}</p> : null}
        <button type="button" className="sli-ds-button" disabled={removal.isPending} onClick={() => setSelected(null)}>{t("agents.cancel")}</button>
        <button type="button" className="sli-ds-button" disabled={removal.isPending} onClick={() => { if (selected) removal.mutate(selected); }}>{t("agents.removeOld")}</button>
      </Dialog></Modal>
    </ModalOverlay>
  </>;
}

export function AgentRemovalStatus({ removal }: { removal: AgentItem["removal"] }) {
  if (!removal) return null;
  return <div role="status">
    <p>{t(`agents.removal.${removal.state}`)}</p>
    <p>{t(`agents.removal.${removal.connection}`)}</p>
    {removal.reason ? <p>{t(`agents.removal.${removal.reason}`)}</p> : null}
    <p>{t("agents.removal.historyRetained")}</p>
  </div>;
}
