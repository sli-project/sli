import { AccessRequestStateView, useAccessRequest } from "../access-request-state";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError, PASSWORD_DETECTION_DOMAIN_UNAVAILABLE, type AgentItem, type AgentEnrollmentToken } from "../../api/client";
import { DataTable, DetailDrawer, FactList, PageHeader, StateView, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { EMPTY_VALUE } from "../../shared/format";
import { useEffectiveAccess, useTimeZone } from "../App";
import { Note } from "./gate";
import { AgentCollectionControls, AgentModuleControls } from "./agent-policy-controls";
import { AgentActions, agentHasDcAudit, agentHostName, agentModuleName } from "./agent-actions";
import { AgentWindowsAuditStatus, auditGroupPolicyStatus } from "./agent-windows-audit";
import { AgentRemovalStatus, OldAgentsTable } from "./agent-removal-status";
import { AgentDeploymentPanel } from "./agent-deployment";
import { AgentDeliveryDiagnostics } from "./agent-delivery-diagnostics";
import { AgentEventlogDiagnostics } from "./agent-eventlog-diagnostics";
import { AgentSequenceRecovery } from "./agent-sequence-recovery";
import { AgentFileServerCard } from "./agent-file-audit";
import { AgentConsoleEnrollment } from "./agent-console-enrollment";
import { collectionDiagnosis, missingAuditSetting } from "./collection-diagnosis";
import { statusSources } from "./status-view";

export function AgentsPage() {
  const access = useEffectiveAccess();
  const accessRequest = useAccessRequest();
  if (!access || accessRequest?.error) return <section className="sli-ds-report"><PageHeader title={t("agents.title")}/><AccessRequestStateView/></section>;
  if (!access.platform_owner && !access.capabilities.includes("access.manage")) {
    return <section className="sli-ds-report"><PageHeader title={t("agents.title")}/><StateView state="denied"/></section>;
  }
  return <AgentsContent/>;
}

type AgentFilter = "all" | "silent" | "auditOff" | "disabled";
const certificateRejectionActions = {
  untrusted_root: "agents.certificateRejection.untrustedRoot",
  unexpected_chain_length: "agents.certificateRejection.chainLength",
  wrong_eku: "agents.certificateRejection.wrongUsage",
  expired: "agents.certificateRejection.expired",
  not_yet_valid: "agents.certificateRejection.notYetValid",
  revoked: "agents.certificateRejection.revoked",
  invalid_chain: "agents.certificateRejection.invalidChain",
} as const satisfies Record<NonNullable<AgentItem["certificate_rejection_reason"]>, string>;
const silent = (agent: AgentItem) => agent.status === "active" && (!agent.last_seen
  || Date.now() - Date.parse(agent.last_seen) > Math.max(300, (agent.collection_policy?.interval_seconds ?? 60) * 3) * 1000);

function agentCollectionState(agent: AgentItem, timeZone: string, source?: ReturnType<typeof statusSources>[number]) {
  if (agent.status !== "active") return { state: t("agents.disabled"), action: EMPTY_VALUE };
  if (silent(agent)) {
    const state = agent.last_seen ? t("agents.silentSince", { date: formatDateTime(agent.last_seen, timeZone, { withYear: false }) }) : t("agents.notConnected");
    return { state, action: t("systemStatus.action.agent") };
  }
  if (agent.collection_policy && agent.collection_policy.state !== "active") {
    return { state: t("collectionDiagnosis.paused"), action: t("collectionDiagnosis.resume") };
  }
  const issue = collectionDiagnosis(agent, timeZone, agent.collection_policy?.interval_seconds);
  if (issue) return issue;
  if (source?.href) return source;
  const count = auditDisabled(agent);
  if (count && !dcAuditFailure(agent)) return { state: t("agents.auditOffStatus", { count }), action: t("collectionDiagnosis.auditAction") };
  return { state: t("agents.working"), action: EMPTY_VALUE };
}
function auditDisabled(agent: AgentItem): number | null {
  const report = agent.windows_audit;
  if (report?.policy_revision !== agent.policy_revision) return null;
  const families = agentHasDcAudit(agent) ? [report.families?.domain_controller] : Object.values(report.families ?? {});
  const rows = [...new Map(families.flatMap((family) => family?.required ?? []).filter((row) =>
    row.subcategory !== "domain_root_sacl").map((row) => [row.guid, row])).values()];
  const count = rows.filter(missingAuditSetting).length;
  return count || (rows.length && rows.every((row) => row.actual_success !== null && row.actual_failure !== null) ? 0 : null);
}
function dcAuditFailure(agent: AgentItem) {
  if (agent.status !== "active" || !agent.collection_policy?.manage_windows_audit) return null;
  const report = agent.windows_audit;
  if (report?.policy_revision !== agent.policy_revision) return null;
  const policy = auditGroupPolicyStatus(report);
  if (policy || !agentHasDcAudit(agent)) return policy;
  const rows = report.families?.domain_controller?.required.filter((row) => row.subcategory !== "domain_root_sacl");
  if (!rows?.length) return null;
  const missing = rows.filter(missingAuditSetting);
  if (report.management_state === "blocked" || missing.length ||
      rows.some((row) => row.actual_success === null || row.actual_failure === null)) return t("agents.auditApplyFailed");
  return null;
}
const moduleId = (module: AgentItem["assigned_modules"][number]) => typeof module === "string" ? module : module.module_id;
function computers(items: AgentItem[]) {
  const hosts = new Map<string, AgentItem>();
  for (const item of items) {
    const previous = hosts.get(item.host_id);
    if (!previous || item.status === "active" && previous.status !== "active" || item.status === previous.status &&
      Date.parse(item.last_seen ?? item.created_at ?? "1970-01-01") > Date.parse(previous.last_seen ?? previous.created_at ?? "1970-01-01")) hosts.set(item.host_id, item);
  }
  return [...hosts.values()];
}

function AgentsContent() {
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const client = useQueryClient();
  const params = new URLSearchParams(window.location.search);
  const agentId = params.get("agent_id") ?? undefined;
  const openPasswordDomain = params.get("configure") === "password-domain";
  const inventory = useQuery({ queryKey: agentId ? ["admin-agents", agentId] : ["admin-agents"], queryFn: () => api.agents(agentId), refetchInterval: 15_000 });
  const setup = useQuery({ queryKey: ["setup-status"], queryFn: api.setupStatus, retry: false, refetchInterval: 30_000 });
  const health = !setup.isError && !setup.data?.agent_collection?.diagnostics ? setup.data?.agent_collection : null;
  const sources = new Map(statusSources(health, setup.data?.domains ?? [], timeZone).map((row) => [row.id, row]));
  const collectionState = (agent: AgentItem) => agentCollectionState(agent, timeZone, sources.get(agent.id));
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const linkedAgentFocused = useRef(false);
  useEffect(() => {
    const id = agentId ?? (window.location.hash.startsWith("#agent-") ? window.location.hash.slice(7) : undefined);
    if (id && inventory.data?.items.some((item) => item.id === id) && !linkedAgentFocused.current) {
      linkedAgentFocused.current = true;
      setSelectedId(id);
    }
  }, [agentId, inventory.data]);
  const [adding, setAdding] = useState(false);
  const [enrollment, setEnrollment] = useState<"group" | "manual">(() => access?.platform_owner ? "group" : "manual");
  const sessionKey = JSON.stringify([access?.subject.type, access?.subject.id, access?.subject.username, access?.evaluated_at_utc]);
  const [consoleSession, setConsoleSession] = useState(() =>
    new URLSearchParams(window.location.search).get("register") === "1" ? sessionKey : undefined);
  const [keysSession, setKeysSession] = useState<string>();
  const [auditSaved, setAuditSaved] = useState<{ id: string; at: string }>();
  const [filter, setFilter] = useState<AgentFilter>(() => {
    const value = new URLSearchParams(window.location.search).get("filter");
    return value === "silent" || value === "auditOff" || value === "disabled" ? value : "all";
  });
  const setQuickFilter = (value: AgentFilter) => {
    setFilter(value);
    const url = new URL(window.location.href);
    if (value === "all") url.searchParams.delete("filter"); else url.searchParams.set("filter", value);
    window.history.replaceState(window.history.state, "", url);
  };
  const action = useMutation({ mutationFn: ({ kind, body }: { kind: "modules" | "disable" | "revoke" | "rights-probe" | "policy" | "remove"; body: Record<string, unknown> }) => api.agentAction(kind, body),
    onSuccess: (_, { kind, body }) => {
      const policy = body.collection_policy;
      if (kind === "policy" && typeof body.agent_id === "string" && policy && typeof policy === "object" && "manage_windows_audit" in policy) {
        setAuditSaved({ id: body.agent_id, at: new Date().toISOString() });
      }
      void client.invalidateQueries({ queryKey: ["admin-agents"] });
    } });
  const changePolicy = (kind: "modules" | "policy", body: Record<string, unknown>) => action.mutate({ kind, body });
  const actionError = action.error;
  const actionErrorMessage = actionError instanceof Error ? actionError.message : "";
  const workstationProfileError = actionError instanceof ApiResponseError && actionError.code === "workstation_journal_profile_unsupported";
  const allowedIds = workstationProfileError ? actionError.payload?.allowed_event_ids : undefined;
  const allowedIdsText = Array.isArray(allowedIds) ? allowedIds.filter(Number.isSafeInteger).join(", ") : "";
  const actionErrorKey = workstationProfileError ? "agents.invalidPolicy"
    : actionErrorMessage === PASSWORD_DETECTION_DOMAIN_UNAVAILABLE ? "agents.passwordDomain.unavailable" : "agents.actionError";
  const date = (value?: string | null) => formatDateTime(value, timeZone);
  const items = computers((inventory.data?.items ?? []).filter((agent) => agent.status !== "replaced"));
  const oldAgents = (inventory.data?.items ?? []).filter((agent) => agent.status === "replaced" && !agent.removal).map((agent) => ({ ...agent, name: agentHostName(agent) }));
  const selected = inventory.data?.items.find((item) => item.id === selectedId);
  const groups = {
    all: items.filter((item) => item.status === "active"),
    silent: items.filter(silent),
    auditOff: items.filter((item) => item.status === "active" && (auditDisabled(item) ?? 0) > 0),
    disabled: items.filter((item) => item.status !== "active"),
  };
  const columns: TableColumn<AgentItem>[] = [
    { key: "host_name", label: t("agents.hostName"), render: agentHostName },
    { key: "agent_version", label: t("agents.version"), render: (agent) => agent.agent_version || "—" },
    { key: "role", label: t("agents.computerRole"), render: (agent) => agent.assigned_modules.some((module) => ["sli.windows.ad-dc", "sli.windows.ad-dc-history"].includes(moduleId(module)))
      ? t("agents.roleDc") : agent.assigned_modules.some((module) => moduleId(module) === "sli.workstations") ? t("agents.roleWorkstation") : "—" },
    { key: "status", label: t("agents.status"), render: (agent) => collectionState(agent).state },
    { key: "action", label: t("systemStatus.action"), render: (agent) => {
      const reason = agent.certificate_rejection_reason;
      return reason && Object.hasOwn(certificateRejectionActions, reason)
        ? t(certificateRejectionActions[reason]) : collectionState(agent).action;
    } },
    { key: "last_seen", label: t("agents.lastData"), kind: "datetime", render: (agent) =>
      <span title={date(agent.last_seen)}>{formatDateTime(agent.last_seen, timeZone, { withYear: false })}</span> },
    { key: "windows_audit", label: t("agents.windowsAudit"), render: (agent) => {
      const count = auditDisabled(agent);
      return dcAuditFailure(agent) ?? (count === null ? "—" : count ? t("agents.auditDisabledCount", { count }) : t("agents.auditConfigured"));
    } },
  ];
  const addButton = <button className="sli-ds-button" type="button" onClick={() => setConsoleSession(sessionKey)}>{t("agents.addComputer")}</button>;
  const modules = selected?.assigned_modules.filter((module) => ["sli.windows.ad-dc", "sli.windows.ad-dc-history", "sli.ad-snapshot", "sli.gpo-snapshot", "sli.workstations"].includes(moduleId(module))) ?? [];
  const selectedState = selected && collectionState(selected);
  return <section className="sli-ds-report">
    <PageHeader title={t("agents.title")} actions={addButton}/>
    <div className="sli-ds-filters" role="group" aria-label={t("agents.title")}>
      {(["all", "silent", "auditOff", "disabled"] as const).map((key) => <button key={key} type="button" className="sli-ds-button" aria-pressed={filter === key} onClick={() => setQuickFilter(key)}>{t(`agents.quick.${key}`)} · {groups[key].length}</button>)}
    </div>
    {inventory.isLoading ? <StateView state="loading"/> : inventory.isError ? <div><p role="alert">{t("agents.loadError")}</p><button className="sli-ds-button" onClick={() => void inventory.refetch()}>{t("state.retry")}</button></div>
      : groups[filter].length ? <div className="sli-ds-report__views"><DataTable columns={columns} rows={groups[filter]} rowKey={(agent) => agent.id} onRowClick={(agent) => setSelectedId(agent.id)} selectedKey={selectedId} caption={t("agents.title")}/></div>
      : items.length ? <p>{t("agents.noMatches")}</p>
      : <div><p>{t("agents.emptyComputers")}</p>{addButton}</div>}
    <OldAgentsTable agents={oldAgents} canRemove={Boolean(access?.platform_owner)}/>
    <div className="sli-ds-filters__actions">
      <button className="sli-ds-button" type="button" onClick={() => setKeysSession(sessionKey)}>{t("agents.console.keys")}</button>
      <button className="sli-ds-button" type="button" onClick={() => {
        setEnrollment(access?.platform_owner ? "group" : "manual");
        setAdding(true);
      }}>{t("agents.registrationSettings")}</button>
    </div>
    {consoleSession === sessionKey && <AgentConsoleEnrollment onClose={() => setConsoleSession(undefined)}/>}
    {keysSession === sessionKey && <AgentConsoleKeys sessionKey={sessionKey} timeZone={timeZone} onClose={() => setKeysSession(undefined)}/>}
    {selected ? <DetailDrawer open title={agentHostName(selected)} onClose={() => setSelectedId(null)}>
      {selectedState ? <p>{selectedState.state}{selectedState.action === EMPTY_VALUE ? "" : `. ${selectedState.action}`}</p> : null}
      <AgentFileServerCard key={selected.id} agent={selected} busy={action.isPending} timeZone={timeZone}
        canManage={Boolean(access?.platform_owner || access?.subject.coarse_role === "admin" && access.capabilities.includes("access.manage"))}/>
      {selected.collection_policy || modules.length || selected.eventlog_diagnostics?.items.length || selected.delivery_diagnostics ? <section>
        <h3>{t("agents.collection")}</h3>
        {selected.collection_policy ? <AgentCollectionControls key={`${selected.id}:${selected.policy_revision}`} agent={selected} busy={action.isPending} change={changePolicy}/> : null}
        {modules.map((module) => typeof module === "string" ? null : <section key={module.module_id}>
          <label><input type="checkbox" checked={module.enabled} disabled={selected.status !== "active" || action.isPending || !["sli.workstations", "sli.windows.ad-dc", "sli.windows.ad-dc-history"].includes(module.module_id)}
            onChange={() => action.mutate({ kind: "modules", body: { agent_id: selected.id, module_id: module.module_id, enabled: !module.enabled, config: module.module_id === "sli.workstations" && !module.enabled ? {} : module.config, expected_revision: selected.policy_revision } })}/>{agentModuleName(module.module_id)}</label>
          <AgentModuleControls key={`${selected.id}:${module.module_id}:${selected.policy_revision}`} agent={selected}
            module={module} busy={action.isPending} change={changePolicy} openPasswordDomain={selected.id === agentId && openPasswordDomain}/>
        </section>)}
        {selected.eventlog_diagnostics?.items.length ? <AgentEventlogDiagnostics agent={selected} timeZone={timeZone}/> : null}
        {selected.delivery_diagnostics ? <AgentDeliveryDiagnostics agent={selected} timeZone={timeZone} recoveryAvailable={Boolean(access?.platform_owner)}/> : null}
        {access?.platform_owner && selected.delivery_diagnostics?.items.some((item) => !item.resolved_at_utc && ["agent_sequence_gap", "agent_cursor_mismatch"].includes(item.error_code)) ? <AgentSequenceRecovery agentId={selected.id} hostName={agentHostName(selected)} canRecover active={selected.status === "active"} timeZone={timeZone}/> : null}
      </section> : null}
      {agentHasDcAudit(selected) || selected.windows_audit?.policy_revision !== undefined ? <section>
        <h3>{t("agents.windowsAudit")}</h3>
        <AgentWindowsAuditStatus key={`${selected.id}:${selected.policy_revision}`} agent={selected} change={changePolicy}
          busy={action.isPending} timeZone={timeZone} savedAt={auditSaved?.id === selected.id && !action.isError ? auditSaved.at : undefined}/>
      </section> : null}
      {selected.certificates.length ? <section><h3>{t("agents.certificate")}</h3><ul>{selected.certificates.map((cert) => <li key={cert.serial}>{date(cert.not_after)} · {t("agents.certificateSerial", { serial: cert.serial })}{cert.revoked_at ? ` · ${t("agents.revoked")}` : ""}</li>)}</ul></section> : null}
      {selected.policy_audit?.length ? <section><h3>{t("agents.audit")}</h3><ul>{selected.policy_audit.map((entry) => <li key={entry.id}>
        {t(entry.action === "module_assign" ? "agents.auditModule" : entry.action === "policy_ack" ? "agents.auditAck" : "agents.auditPolicy")} · {entry.actor} · {date(entry.occurred_at)}
        <PolicyAuditDetails details={entry.details}/>
      </li>)}</ul></section> : null}
      <section><h3>{t("agents.actions")}</h3><AgentActions key={selected.id} agent={selected} busy={action.isPending} canRemove={Boolean(access?.platform_owner)} change={(kind, body) => action.mutate({ kind, body })}/>
        <AgentRemovalStatus removal={selected.removal}/>
        {selected.rights_probe.pending ? <p role="status">{t("agents.probePending")}</p> : null}
        {selected.rights_probe.last_result ? <p>{t(selected.rights_probe.last_result.status === "allowed" ? "agents.probeAllowed" : selected.rights_probe.last_result.status === "denied" ? "agents.probeDenied" : "agents.probeUnavailable")} · {date(selected.rights_probe.last_result.reported_at)}</p> : null}
        {action.isError ? <p role="alert">
          {t(actionErrorKey)}
          {allowedIdsText ? <> {t("agents.allowIds")}: {allowedIdsText}.</> : null}
        </p> : null}
      </section>
      <FactList facts={[{ label: t("agents.host"), value: selected.host_id }, { label: t("agents.agentId"), value: selected.id }]}/>
    </DetailDrawer> : null}
    {adding ? <DetailDrawer open title={t("agents.addComputer")} onClose={() => setAdding(false)}>
      <div role="tablist" aria-label={t("agents.addComputer")}>
        {([...(access?.platform_owner ? ["group" as const] : []), "manual" as const]).map((key) => <button key={key} type="button" className="sli-ds-button" role="tab" id={`enrollment-${key}`} aria-controls={`enrollment-panel-${key}`} aria-selected={enrollment === key} onClick={() => setEnrollment(key)}>{t(key === "group" ? "agents.deployment.title" : "agents.manualEnrollment")}</button>)}
      </div>
      <div role="tabpanel" id={`enrollment-panel-${enrollment}`} aria-labelledby={`enrollment-${enrollment}`}>
        {enrollment === "group" ? access?.platform_owner ? <AgentDeploymentPanel key={sessionKey} expanded agents={items}/> : null : <ManualEnrollment key={sessionKey} timeZone={timeZone}/>}
      </div>
    </DetailDrawer> : null}
  </section>;
}

function AgentConsoleKeys({ sessionKey, timeZone, onClose }: { sessionKey: string; timeZone: string; onClose: () => void }) {
  const tokens = useQuery({ queryKey: ["agent-console-tokens", sessionKey], queryFn: api.agentConsoleTokens,
    refetchInterval: 15_000, meta: { persist: false } });
  const revoke = useMutation({ mutationFn: api.revokeAgentConsoleToken,
    onSuccess: async () => { await tokens.refetch(); } });
  const date = (value: string) => formatDateTime(value, timeZone);
  return <DetailDrawer open title={t("agents.console.keys")} onClose={onClose}>
    {tokens.isLoading ? <StateView state="loading"/> : tokens.isError ? <p role="alert">{t("agents.console.listError")}</p>
      : tokens.data?.items.length ? <ul>{tokens.data.items.map((token) => <li key={token.id}>
        {date(token.created_at)} · {t("agents.console.remaining", { count: token.remaining })}{" "}
        <button className="sli-ds-button" type="button" disabled={revoke.isPending} onClick={() => {
          if (window.confirm(t("agents.console.confirmRevoke", { date: date(token.created_at) }))) revoke.mutate(token.id);
        }}>{t("agents.console.revoke")}</button>
      </li>)}</ul> : <p>{t("agents.console.noKeys")}</p>}
    {revoke.isError && <p role="alert">{t("agents.console.revokeError")}</p>}
  </DetailDrawer>;
}

function ManualEnrollment({ timeZone }: { timeZone: string }) {
  const [host, setHost] = useState("");
  const [replacementName, setReplacementName] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [ttl, setTtl] = useState(900);
  // Secrets live only in this mounted page, never in the query/mutation cache.
  const [token, setToken] = useState<AgentEnrollmentToken | null>(null);
  const [creating, setCreating] = useState(false);
  const [tokenError, setTokenError] = useState(false);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const date = (value?: string | null) => formatDateTime(value, timeZone);
  const createToken = async (event: FormEvent) => {
    event.preventDefault();
    setToken(null); setTokenError(false); setCopied(false); setCopyError(false); setCreating(true);
    try { setToken(await api.createAgentToken({ host_id: host.trim(), key_fingerprint: fingerprint.trim(), ttl_seconds: ttl,
      ...(replacementName.trim() ? { registration_host_name: replacementName.trim() } : {}) })); }
    catch { setTokenError(true); }
    finally { setCreating(false); }
  };
  const copyToken = async () => {
    if (!token) return;
    try { await navigator.clipboard.writeText(token.token); setCopied(true); setCopyError(false); }
    catch { setCopied(false); setCopyError(true); }
  };
  return <>
    <form className="sli-ds-filters" onSubmit={(event) => { void createToken(event); }}>
      <h2 className="sli-ds-section-title">{t("agents.enrollmentTitle")}</h2>
      <div className="sli-ds-filters__fields" data-align="start">
        <div className="sli-ds-field"><label htmlFor="agent-host">{t("agents.host")}</label><input id="agent-host" aria-describedby="agent-host-help" required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" value={host} onChange={(event) => setHost(event.target.value)}/><small id="agent-host-help">{t("agents.hostHelp")}</small></div>
        <div className="sli-ds-field"><label htmlFor="agent-replacement-name">{t("agents.replacementName")}</label><input id="agent-replacement-name" maxLength={253} value={replacementName} onChange={(event) => setReplacementName(event.target.value)}/></div>
        <div className="sli-ds-field"><label htmlFor="agent-key">{t("agents.fingerprint")}</label><input id="agent-key" aria-describedby="agent-key-help" required pattern="[0-9a-f]{64}" value={fingerprint} onChange={(event) => setFingerprint(event.target.value)}/><small className="sli-ds-field__help" id="agent-key-help">{t("agents.fingerprintHelp")}</small></div>
        <div className="sli-ds-field"><label htmlFor="agent-ttl">{t("agents.ttl")}</label><input id="agent-ttl" type="number" required min={60} max={3600} value={ttl} onChange={(event) => setTtl(Number(event.target.value))}/></div>
      </div>
      <button className="sli-ds-button" type="submit" disabled={creating}>{t("agents.createToken")}</button>
      {tokenError ? <p role="alert">{t("agents.actionError")}</p> : null}
    </form>
    {token ? <Note title={t("agents.tokenOnce")}><p>{t("agents.expires", { date: date(token.expires_at) })}</p><pre className="sli-ds-pre">{token.token}</pre>
      <button className="sli-ds-button" onClick={() => { void copyToken(); }}>{t("agents.copy")}</button>
      <button className="sli-ds-button" onClick={() => { setToken(null); setCopied(false); setCopyError(false); }}>{t("agents.dismiss")}</button>
      {copied ? <p role="status">{t("agents.copied")}</p> : null}{copyError ? <p role="alert">{t("agents.copyError")}</p> : null}
    </Note> : null}
  </>;
}

function PolicyAuditDetails({ details }: { details: Record<string, unknown> }) {
  const families = ["logons", "processes", "usb", "local_admins", "protection"] as const;
  const fields = { state: "agents.collection", interval_seconds: "agents.interval", batch_size: "agents.batch",
    rate_limit_per_minute: "agents.rate", spool_max_bytes: "agents.spool", families: "agents.familySettings",
    channels: "agents.channelSettings", family_filters: "agents.filters", allow_event_ids: "agents.allowIds",
    deny_event_ids: "agents.denyIds", allow_process_paths: "agents.allowPaths", deny_process_paths: "agents.denyPaths",
    rate_limits: "agents.eventRates", rate_window_seconds: "agents.rateWindow", channel_generations: "agents.channelSettings",
    manage_windows_audit: "agents.auditEnable", audit_process_command_line: "agents.auditCommandLine" } as const;
  return <>
    {details.module_id === "sli.workstations" || details.module_id === "sli.windows.ad-dc" ? <p>{agentModuleName(details.module_id)} · {t(details.enabled === true ? "agents.on" : "agents.off")}</p> : null}
    {details.state === "active" || details.state === "paused" || details.state === "drain" ? <p>{t(details.state === "active" ? "agents.active" : details.state === "paused" ? "agents.paused" : "agents.draining")}</p> : null}
    {details.families && typeof details.families === "object" ? <ul>{families.map((family) => {
      const enabled = (details.families as Record<string, unknown>)[family];
      return typeof enabled === "boolean" ? <li key={family}>{t(`agents.family.${family}`)}: {t(enabled ? "agents.on" : "agents.off")}</li> : null;
    })}</ul> : null}
    {details.channels && typeof details.channels === "object" ? <ul>{["Security", "System", "Directory Service"].map((channel) => {
      const enabled = (details.channels as Record<string, unknown>)[channel];
      return typeof enabled === "boolean" ? <li key={channel}>{channel}: {t(enabled ? "agents.on" : "agents.off")}</li> : null;
    })}</ul> : null}
    {Array.isArray(details.changed_fields) ? <ul>{details.changed_fields.filter((key): key is keyof typeof fields => typeof key === "string" && Object.hasOwn(fields, key)).map((key) => <li key={key}>{t(fields[key])}{typeof details[key] === "number" ? `: ${details[key]}` : typeof details[key] === "boolean" ? `: ${t(details[key] ? "agents.on" : "agents.off")}` : ""}</li>)}</ul> : null}
  </>;
}
