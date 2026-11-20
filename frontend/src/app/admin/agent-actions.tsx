import { useId, useRef, useState } from "react";
import { Button, Dialog, Header, Heading, Menu, MenuItem, MenuSection, MenuTrigger, Modal, ModalOverlay, Popover, Separator } from "react-aria-components";
import type { AgentItem } from "../../api/client";
import { t, type MessageKey } from "../../i18n";
import "./agent-actions.css";

type ActionKind = "modules" | "policy" | "disable" | "revoke" | "rights-probe" | "remove";
type Confirmation = { title: string; message: MessageKey; kind: ActionKind; body: Record<string, unknown>; serial?: string; auditEnable?: boolean };

export const agentHostName = (agent: AgentItem) => [agent.host_name, agent.hostname]
  .map((name) => name?.trim())
  .find((name) => name && !/^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$/i.test(name)
    && !["localhost", "unknown"].includes(name.toLowerCase())) || t("agents.unknownHost");
export const agentModuleName = (module: string) => module === "sli.workstations" ? t("agents.moduleWorkstations") : module === "sli.windows.ad-dc" ? t("agents.moduleDc")
  : module === "sli.windows.ad-dc-history" ? t("agents.moduleDcHistory")
  : module === "sli.ad-snapshot" ? t("agents.moduleAdSnapshot") : module === "sli.gpo-snapshot" ? t("agents.moduleGpoSnapshot") : module;

export function AgentActions({ agent, busy, change, canRemove = false }: { agent: AgentItem; busy: boolean; canRemove?: boolean; change: (kind: ActionKind, body: Record<string, unknown>) => void }) {
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [commandLine, setCommandLine] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const descriptionId = useId();
  const host = agentHostName(agent);
  const active = agent.status === "active";
  const collecting = (agent.collection_policy?.state ?? "active") === "active";
  const modules = agent.assigned_modules.filter((module) => typeof module !== "string");
  const workstation = modules.find((module) => module.module_id === "sli.workstations");
  const dc = modules.find((module) => module.module_id === "sli.windows.ad-dc");
  const closeConfirmation = () => {
    setConfirmation(null);
    requestAnimationFrame(() => trigger.current?.focus());
  };
  const confirmPolicy = (state: "active" | "paused" | "drain") => setConfirmation({
    title: t(state === "active" ? "agents.resume" : state === "drain" ? "agents.drain" : "agents.pause"),
    message: state === "active" ? "agents.confirmResume" : state === "drain" ? "agents.confirmDrain" : "agents.confirmPause",
    kind: "policy", body: { agent_id: agent.id, expected_revision: agent.policy_revision, collection_policy: { state } },
  });
  return <>
    <MenuTrigger>
      <Button ref={trigger} className="sli-ds-button" aria-label={t("agents.actionsFor", { host })}>{t("agents.actions")}</Button>
      <Popover className="agent-actions-popover" placement="bottom end">
        <Menu className="agent-actions-menu" aria-label={t("agents.actionsFor", { host })}>
          <MenuSection>
            <Header>{t("agents.collection")}</Header>
            <MenuItem id="collection" isDisabled={!active || busy} onAction={() => confirmPolicy(collecting ? "paused" : "active")}>{t(collecting ? "agents.pause" : "agents.resume")}</MenuItem>
            {collecting ? <MenuItem id="drain" isDisabled={!active || busy} onAction={() => confirmPolicy("drain")}>{t("agents.drain")}</MenuItem> : null}
            <MenuItem id="probe" isDisabled={!active || busy || Boolean(agent.rights_probe.pending)} onAction={() => change("rights-probe", { agent_id: agent.id })}>{t("agents.checkAccess")}</MenuItem>
            <MenuItem id="windows-audit" isDisabled={!active || busy} onAction={() => {
              const enable = !agent.collection_policy?.manage_windows_audit;
              setCommandLine(Boolean(agent.collection_policy?.audit_process_command_line));
              setConfirmation({ title: t(enable ? "agents.auditEnable" : "agents.auditDisable"),
                message: enable ? "agents.auditConfirmEnable" : "agents.auditConfirmDisable", kind: "policy", auditEnable: enable,
                body: { agent_id: agent.id, expected_revision: agent.policy_revision,
                  collection_policy: { manage_windows_audit: enable } } });
            }}>{t(agent.collection_policy?.manage_windows_audit ? "agents.auditDisable" : "agents.auditEnable")}</MenuItem>
          </MenuSection>
          {!workstation || !dc ? <MenuSection>
            <Header>{t("agents.modules")}</Header>
            {!workstation ? <MenuItem id="assign-workstations" isDisabled={!active || busy || Boolean(dc?.enabled)} onAction={() => change("modules", { agent_id: agent.id, module_id: "sli.workstations", enabled: true, config: {}, expected_revision: agent.policy_revision })}>{t("agents.assignWorkstations")}</MenuItem> : null}
            {!dc ? <MenuItem id="assign-dc" isDisabled={!active || busy || Boolean(workstation?.enabled)} onAction={() => change("modules", { agent_id: agent.id, module_id: "sli.windows.ad-dc", enabled: true, config: { source_name: agent.host_id, connect_address: "localhost" }, expected_revision: agent.policy_revision })}>{t("agents.assignDc")}</MenuItem> : null}
          </MenuSection> : null}
          <Separator/>
          <MenuSection>
            <Header>{t("agents.destructiveActions")}</Header>
            {agent.certificates.filter((cert) => !cert.revoked_at).map((cert) => <MenuItem key={cert.serial} id={`revoke:${cert.serial}`} className="agent-actions-danger" isDisabled={busy} onAction={() => setConfirmation({ title: t("agents.revoke"), message: "agents.confirmRevoke", kind: "revoke", body: { agent_id: agent.id, serial: cert.serial }, serial: cert.serial })}>{t("agents.revokeSerial", { serial: cert.serial })}</MenuItem>)}
            <MenuItem id="disable" className="agent-actions-danger" isDisabled={!active || busy} onAction={() => setConfirmation({ title: t("agents.disable"), message: "agents.confirmDisable", kind: "disable", body: { agent_id: agent.id } })}>{t("agents.disable")}</MenuItem>
            {canRemove ? <MenuItem id="remove" className="agent-actions-danger" isDisabled={busy || Boolean(agent.removal)} onAction={() => setConfirmation({ title: t("agents.remove"), message: "agents.confirmRemove", kind: "remove", body: { operation_id: crypto.randomUUID(), agent_ids: [agent.id] } })}>{t("agents.remove")}</MenuItem> : null}
          </MenuSection>
        </Menu>
      </Popover>
    </MenuTrigger>
    <ModalOverlay className="sli-ds-modal" isOpen={Boolean(confirmation)} isDismissable onOpenChange={(open) => { if (!open) closeConfirmation(); }}>
      <Modal className="sli-ds-modal__panel">
        <Dialog className="agent-confirmation" aria-describedby={descriptionId}>
          {confirmation ? <>
            <Heading slot="title" level={2}>{t("agents.confirmTitle", { action: confirmation.title, host })}</Heading>
            <p>{t("agents.confirmTarget", { agent: agent.instance_name ? `${agent.instance_name} (${agent.id})` : agent.id, host: agent.host_id })}</p>
            {confirmation.serial ? <p>{t("agents.certificateSerial", { serial: confirmation.serial })}</p> : null}
            <p id={descriptionId}>{t(confirmation.message)}</p>
            {confirmation.auditEnable ? <label><input type="checkbox" checked={commandLine} disabled={busy} onChange={(event) => setCommandLine(event.target.checked)}/>{t("agents.auditCommandLineConsent")}</label> : null}
            <div className="agent-confirmation-actions">
              <Button className="sli-ds-button" autoFocus onPress={closeConfirmation}>{t("agents.cancel")}</Button>
              <Button className="sli-ds-button" data-danger={confirmation.kind === "disable" || confirmation.kind === "revoke" || confirmation.kind === "remove" || undefined} isDisabled={busy} onPress={() => {
                if (busy) return;
                const body = confirmation.auditEnable === undefined ? confirmation.body : { ...confirmation.body,
                  collection_policy: { manage_windows_audit: confirmation.auditEnable,
                    audit_process_command_line: confirmation.auditEnable && commandLine } };
                change(confirmation.kind, body);
                closeConfirmation();
              }}>{confirmation.title}</Button>
            </div>
          </> : null}
        </Dialog>
      </Modal>
    </ModalOverlay>
  </>;
}
