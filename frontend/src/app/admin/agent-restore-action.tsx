import { useId, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import { api } from "../../api/client";
import { t } from "../../i18n";
import { EMPTY_VALUE } from "../../shared/format";

export function RestoreAgentAction({ agentId, currentAgentId, name, canRestore }: { agentId: string; currentAgentId: string; name: string; canRestore: boolean }) {
  const [open, setOpen] = useState(false);
  const description = useId();
  const client = useQueryClient();
  const restore = useMutation({ mutationFn: () => api.agentAction("restore", { agent_id: agentId, current_agent_id: currentAgentId }),
    onSuccess: () => { setOpen(false); void client.invalidateQueries({ queryKey: ["admin-agents"] }); void client.invalidateQueries({ queryKey: ["setup-status"] }); } });
  if (!canRestore) return EMPTY_VALUE;
  return <>
    <button type="button" className="sli-ds-button" onClick={() => { restore.reset(); setOpen(true); }}>{t("agents.restoreOld")}</button>
    <ModalOverlay className="sli-ds-modal" isOpen={open} isDismissable={!restore.isPending} onOpenChange={(value) => { if (!restore.isPending) setOpen(value); }}>
      <Modal className="sli-ds-modal__panel"><Dialog aria-describedby={description}>
        <Heading slot="title" level={2}>{t("agents.confirmTitle", { action: t("agents.restoreOld"), host: name })}</Heading>
        <p id={description}>{t("agents.confirmRestore")}</p>
        {restore.isError ? <p role="alert">{t("agents.restoreError")}</p> : null}
        <button type="button" className="sli-ds-button" disabled={restore.isPending} onClick={() => setOpen(false)}>{t("agents.cancel")}</button>
        <button type="button" className="sli-ds-button" disabled={restore.isPending} onClick={() => restore.mutate()}>{t("agents.restoreOld")}</button>
      </Dialog></Modal>
    </ModalOverlay>
  </>;
}
