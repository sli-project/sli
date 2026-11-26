import { Checkbox } from "../../design-system/Checkbox";
import { useState } from "react";
import { Button, Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import type { AgentItem, AgentWindowsAudit } from "../../api/client";
import { DataTable, type TableColumn } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { isValidTimeZone, zonedParts } from "../../shared/date-time";
import { agentHasDcAudit } from "./agent-actions";

const subcategoryKeys: Record<string, MessageKey> = {
  logon: "agents.auditSubcategory.logon", logoff: "agents.auditSubcategory.logoff",
  process_creation: "agents.auditSubcategory.process_creation",
  security_group_management: "agents.auditSubcategory.security_group_management",
  security_system_extension: "agents.auditSubcategory.security_system_extension",
  other_object_access: "agents.auditSubcategory.other_object_access",
  audit_policy_change: "agents.auditSubcategory.audit_policy_change", pnp_activity: "agents.auditSubcategory.pnp_activity",
  kerberos_authentication_service: "agents.auditSubcategory.kerberos_authentication_service",
  kerberos_service_ticket_operations: "agents.auditSubcategory.kerberos_service_ticket_operations",
  credential_validation: "agents.auditSubcategory.credential_validation",
  user_account_management: "agents.auditSubcategory.user_account_management",
  computer_account_management: "agents.auditSubcategory.computer_account_management",
  directory_service_changes: "agents.auditSubcategory.directory_service_changes",
  directory_service_access: "agents.auditSubcategory.directory_service_access",
  other_account_management: "agents.auditSubcategory.other_account_management",
  authentication_policy_change: "agents.auditSubcategory.authentication_policy_change",
  authorization_policy_change: "agents.auditSubcategory.authorization_policy_change",
  domain_root_sacl: "agents.auditSubcategory.domain_root_sacl",
};
type AuditRow = NonNullable<AgentWindowsAudit["families"]["domain_controller"]>["required"][number];
const detectionKeys: Record<number, MessageKey> = {
  1: "security.problems.presentation.qw.password-brute-force.title",
  2: "security.problems.presentation.qw.password-spray.title",
  3: "security.problems.presentation.qw.password-success.title",
  4: "security.problems.presentation.kerberoasting_title",
  5: "security.problems.presentation.asrep_title",
  6: "security.problems.presentation.privilege_title",
  8: "security.problems.presentation.t109.audit-disabled.title",
  10: "agents.auditDetection10",
};
export function auditDetectionName(number: number) {
  return detectionKeys[number] ? `${number}. ${t(detectionKeys[number])}` : "—";
}
export function auditPurpose(row: AuditRow) {
  return [row.detections?.map(auditDetectionName).join("; ") ?? "",
    ["directory_service_access", "other_account_management", "authentication_policy_change", "authorization_policy_change"].includes(row.subcategory) ? t("shell.nav.events") : "",
    row.domain_changes ? t("agents.auditDomainChanges") : ""].filter(Boolean).join(" · ") || "—";
}
export function auditMaskLabel(success: boolean | null, failure: boolean | null) {
  return t(success === null || failure === null ? "agents.auditMask.unknown" : success && failure ? "agents.auditMask.both"
    : success ? "agents.auditMask.success" : failure ? "agents.auditMask.failure" : "agents.auditMask.none");
}

export function AgentWindowsAuditStatus({ agent, change, busy = false, timeZone = "browser", savedAt }: {
  agent: AgentItem; change?: (kind: "policy", body: Record<string, unknown>) => void; busy?: boolean; timeZone?: string; savedAt?: string;
}) {
  const [confirmRestore, setConfirmRestore] = useState(false);
  const [confirmDomain, setConfirmDomain] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const report = agent.windows_audit?.policy_revision === agent.policy_revision ? agent.windows_audit as AgentWindowsAudit : null;
  const dc = agentHasDcAudit(agent);
  const managed = agent.collection_policy?.manage_windows_audit === true;
  const [auditEnabled, setAuditEnabled] = useState(managed);
  const rows = [...new Map(Object.values(report?.families ?? {}).flatMap((family) => family?.required ?? []).map((row) => [row.guid, row])).values()];
  const hasDomainRoot = rows.some((row) => row.subcategory === "domain_root_sacl");
  const hasDomainConsent = agent.collection_policy?.manage_domain_root_sacl === true;
  const send = (enable: boolean, domainConsent = false) => change?.("policy", { agent_id: agent.id, expected_revision: agent.policy_revision,
    collection_policy: { manage_windows_audit: enable,
      ...(domainConsent || dc || hasDomainConsent ? { manage_domain_root_sacl: domainConsent } : {}),
      ...(!domainConsent && (dc || !enable) ? { audit_process_command_line: false } : {}) } });
  const name = (row: AuditRow) => subcategoryKeys[row.subcategory] ? t(subcategoryKeys[row.subcategory]) : "—";
  const auditTime = (value: string) => {
    if (!Number.isFinite(Date.parse(value)) || !(timeZone === "browser" || isValidTimeZone(timeZone))) return "—";
    const parts = zonedParts(new Date(value), timeZone);
    return `${parts.hour}:${parts.minute}`;
  };
  const columns: TableColumn<AuditRow>[] = [
    { key: "subcategory", label: t("agents.auditWhat"), render: (row) => <>{name(row)}{row.subcategory === "domain_root_sacl" ? <><br/>{t("agents.auditAdChange")}</> : null}</> },
    { key: "why", label: t("agents.auditWhy"), render: auditPurpose },
    { key: "actual", label: t("agents.auditNow"), render: (row) => {
      if (row.subcategory === "domain_root_sacl") return <>{t(row.state === "ok" ? "agents.auditRoot.ok" : row.state === "restored" ? "agents.auditRoot.restored"
        : row.state === "missing" ? "agents.auditRoot.missing" : "agents.auditMask.unknown")}
        {row.enabled_at ? <><br/>{t("agents.auditEnabledAt", { time: auditTime(row.enabled_at) })}</> : null}</>;
      const managed = row.state === "managed_by_gpo" || !row.state && report?.families && Object.values(report.families).some((family) => family?.state === "managed_by_gpo");
      const command = `auditpol /set /subcategory:"${name(row)}"${row.success ? " /success:enable" : ""}${row.failure ? " /failure:enable" : ""}`;
      return <>{auditMaskLabel(row.actual_success, row.actual_failure)}
        {managed ? <><br/><span>{t(row.policy_name ? "agents.auditPolicyNamed" : "agents.auditPolicyOwner", row.policy_name ? { name: row.policy_name } : {})}</span>
          <br/><code>{command}</code> <button type="button" className="sli-ds-button" onClick={() => {
            void (async () => {
              try { await navigator.clipboard.writeText(command); setCopyError(false); }
              catch { setCopyError(true); }
            })();
          }}>{t("agents.copy")}</button></> : row.enabled_at ? <><br/><span>{t("agents.auditEnabledAt", { time: auditTime(row.enabled_at) })}</span></> : null}
      </>;
    } },
    { key: "required", label: t("agents.auditNeeded"), render: (row) => auditMaskLabel(row.success, row.failure) },
  ];
  const disabled = busy || agent.status !== "active" || !change;
  return <>
    {dc ? <form className="sli-ds-header__actions" onSubmit={(event) => {
      event.preventDefault();
      if (disabled || auditEnabled === managed) return;
      if (auditEnabled) send(true); else setConfirmRestore(true);
    }}>
      <Checkbox checked={auditEnabled} disabled={disabled} onChange={(event) => setAuditEnabled(event.target.checked)}>{t("agents.manageWindowsAudit")}</Checkbox>
      <button className="sli-ds-button" type="submit" disabled={disabled || auditEnabled === managed}>{t("agents.saveAudit")}</button>
      {hasDomainRoot && managed && !hasDomainConsent ? <button className="sli-ds-button" type="button" disabled={disabled}
        onClick={() => setConfirmDomain(true)}>{t("agents.auditSubcategory.domain_root_sacl")}</button> : null}
    </form> : <div className="sli-ds-header__actions">
      <button className="sli-ds-button" type="button" disabled={disabled} onClick={() => hasDomainConsent ? setConfirmDomain(true) : send(true)}>{t("agents.auditApply")}</button>
      <button className="sli-ds-button" type="button" disabled={disabled} onClick={() => setConfirmRestore(true)}>{t("agents.auditRestore")}</button>
    </div>}
    {dc && savedAt && !busy ? <p role="status">{t("agents.auditSavedAt", { time: auditTime(savedAt) })}</p> : null}
    {rows.length ? <DataTable columns={columns} rows={rows} rowKey={(row) => row.subcategory} caption={t("agents.windowsAudit")} showFooter={false} stickyHeader={false}/> : null}
    {report?.management_state === "restored" ? <p role="status">{t("agents.auditManagement.restored")}</p> : null}
    {copyError ? <p role="alert">{t("agents.auditCopyError")}</p> : null}
    {report?.powershell_logging ? <section>
      <p>{t("agents.auditPowerShellChannel")}: {t(report.powershell_logging.channel_enabled === true ? "agents.on" : report.powershell_logging.channel_enabled === false ? "agents.off" : "agents.auditMask.unknown")}</p>
      <p>{t("agents.auditPowerShellScriptBlock")}: {t(report.powershell_logging.script_block_logging_enabled === true ? "agents.on" : report.powershell_logging.script_block_logging_enabled === false ? "agents.off" : "agents.auditMask.unknown")}</p>
      {report.powershell_logging.channel_enabled !== true || report.powershell_logging.script_block_logging_enabled !== true ? <p>{t("agents.auditPowerShellAction")}</p> : null}
    </section> : null}
    <ModalOverlay className="sli-ds-modal" isOpen={confirmRestore} isDismissable onOpenChange={setConfirmRestore}>
      <Modal className="sli-ds-modal__panel"><Dialog>
        <Heading slot="title">{t(hasDomainConsent ? "agents.auditRootRestoreTarget" : "agents.auditRestoreTarget", { name: agent.host_name || agent.hostname || "—" })}</Heading>
        <Button className="sli-ds-button" onPress={() => setConfirmRestore(false)}>{t("agents.cancel")}</Button>
        <Button className="sli-ds-button" isDisabled={disabled} onPress={() => { send(false); setConfirmRestore(false); }}>{t("agents.auditRestore")}</Button>
      </Dialog></Modal>
    </ModalOverlay>
    <ModalOverlay className="sli-ds-modal" isOpen={confirmDomain} isDismissable onOpenChange={setConfirmDomain}>
      <Modal className="sli-ds-modal__panel"><Dialog>
        <Heading slot="title">{t("agents.auditRootApplyTarget", { name: agent.host_name || agent.hostname || "—" })}</Heading>
        <Button className="sli-ds-button" onPress={() => setConfirmDomain(false)}>{t("agents.cancel")}</Button>
        <Button className="sli-ds-button" isDisabled={disabled} onPress={() => { send(true, true); setConfirmDomain(false); }}>{t("agents.auditApply")}</Button>
      </Dialog></Modal>
    </ModalOverlay>
  </>;
}
