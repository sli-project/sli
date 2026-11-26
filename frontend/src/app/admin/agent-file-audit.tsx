import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { acceptedAgentFileAuditCommand, api, ApiResponseError, type AgentFileAuditCatalog, type AgentFileAuditCommand, type AgentFileAuditStatus, type AgentItem } from "../../api/client";
import { Button, Checkbox, Select } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { withDomain } from "../domain-navigation";
import { agentHostName } from "./agent-actions";

type Root = { collection_scope_id: string; share_name: string; path: string; important: boolean;
  sacl: { trustee_sids: string[]; inherit_files: boolean; inherit_directories: boolean } };
type AuditDraft = Partial<{ paths: string; shares: string; scopes: string; exclusions: string; enabled: boolean; important: boolean; catalogScope: string; manualServer: boolean }>;
type ServerCatalog = {
  agentId: string | null;
  result?: AgentFileAuditCatalog;
  loading: boolean;
  error: boolean;
  denied: boolean;
  selectAgent: (id: string | null) => void;
  refresh: () => void;
};
type Change = (kind: "file-audit", body: Record<string, unknown>) => void;
const lines = (text: string) => text.split("\n").map((line) => line.trim()).filter(Boolean);
const fileConfig = (agent: AgentItem) => {
  const module = agent.assigned_modules.find((item) => typeof item !== "string" && item.module_id === "sli.file-audit");
  return module && typeof module !== "string" ? module : undefined;
};
const kindOf = (agent: AgentItem) => {
  const module = fileConfig(agent);
  return module ? module.config.source_kind ?? "server" : undefined;
};
const workstation = (agent: AgentItem) => agent.assigned_modules.some(
  (module) => typeof module !== "string" && module.module_id === "sli.workstations" && module.enabled);

const folderFailures: Readonly<Record<string, MessageKey>> = {
  sacl_missing: "agents.fileServer.saclMissing",
  policy_missing: "agents.fileServer.auditIncomplete",
  managed_by_gpo: "agents.fileServer.groupPolicy",
};

export function AgentFileServerCard({ agent, busy, canManage, timeZone }: {
  agent: AgentItem; busy: boolean; canManage: boolean; timeZone?: string;
}) {
  const client = useQueryClient();
  const assignment = fileConfig(agent);
  const config = assignment?.config ?? {};
  const root = Array.isArray(config.roots) && config.roots.length === 1 ? config.roots[0] as Root : undefined;
  const assigned = Boolean(assignment?.enabled);
  const [choosing, setChoosing] = useState(false);
  const [scope, setScope] = useState("");
  const statusKey = ["admin-file-server-status", agent.id] as const;
  const catalogKey = ["admin-file-audit-catalog", agent.id] as const;
  const status = useQuery({
    queryKey: statusKey,
    queryFn: async () => {
      try { return await api.agentFileAuditStatus(agent.id); }
      catch (error) {
        if (error instanceof ApiResponseError && error.status === 404) return null;
        throw error;
      }
    },
    enabled: agent.status === "active" && (assigned || canManage) && kindOf(agent) !== "workstation",
    retry: false,
    refetchInterval: (query) => query.state.data?.state === "pending" || query.state.data?.state === "partial" ? 5_000 : assigned ? 15_000 : false,
  });
  const mayEdit = canManage && status.isSuccess && agent.status === "active" && kindOf(agent) !== "workstation";
  const catalog = useQuery({ queryKey: catalogKey, enabled: choosing && mayEdit, retry: false,
    queryFn: ({ signal }) => api.agentFileAuditCatalog(agent.id, signal),
    refetchInterval: (query) => query.state.data?.state === "pending" ? 5_000 : false,
  });
  const refresh = useMutation({ mutationFn: api.requestAgentFileAuditCatalog,
    onMutate: () => client.cancelQueries({ queryKey: catalogKey }),
    onSuccess: (data) => client.setQueryData(catalogKey, data),
  });
  const requestedCatalog = useRef(false);
  const requestCatalog = refresh.mutate;
  const catalogState = catalog.data?.state;
  useEffect(() => {
    if (!choosing) requestedCatalog.current = false;
    if (choosing && mayEdit && !requestedCatalog.current && !catalog.isFetching && (catalogState === "idle" || catalogState === "expired")) {
      requestedCatalog.current = true;
      requestCatalog(agent.id);
    }
  }, [agent.id, catalog.isFetching, catalogState, choosing, mayEdit, requestCatalog]);
  const change = useMutation({
    mutationFn: async ({ selected, remove }: { selected: Root; remove: boolean }) => {
      const body = { agent_id: agent.id, expected_revision: agent.policy_revision,
        command: { contract_id: "sli.file-audit.audit-command.v1", command_id: crypto.randomUUID(),
          action: remove ? "restore" : "apply", policy_revision: String(agent.policy_revision + 1),
          collection_scope_ids: [selected.collection_scope_id] },
        config: { ...config, source_kind: "server", roots: [selected] },
        ...(remove ? { remove_assignment: true } : { enabled: true, activate_collection: true }) };
      const accepted = acceptedAgentFileAuditCommand(body, await api.agentAction("file-audit", body));
      if (!accepted) throw new Error("file_audit_receipt_unrecognized");
      return accepted;
    },
    onSuccess: () => { setChoosing(false); setScope(""); },
    onSettled: async () => {
      await Promise.all([client.invalidateQueries({ queryKey: ["admin-agents"] }), client.invalidateQueries({ queryKey: statusKey })]);
    },
  });
  if (kindOf(agent) === "workstation" || agent.status !== "active") return null;

  const observed = status.data;
  const accepted = change.data;
  const enabled = accepted && Number(accepted.policy_revision) > agent.policy_revision ? accepted.action === "apply" : assigned;
  const matches = !accepted || (observed?.command.command_id === accepted.command_id
    && observed.command.policy_revision === accepted.policy_revision);
  const folder = root ?? change.variables?.selected;
  const observedScope = observed?.command.collection_scope_ids.length === 1 ? observed.command.collection_scope_ids[0] : undefined;
  const folderScope = folder?.collection_scope_id ?? (observed?.command.action === "restore" ? observedScope : undefined);
  const path = folder?.path ?? (folderScope ? observed?.folders?.[folderScope] : undefined);
  const lastEvent = observed?.last_event?.collection_scope_id === folderScope ? observed?.last_event : undefined;
  const receipt = folderScope && matches && observed && observed.command.action !== "check"
    && observed.command.collection_scope_ids.includes(folderScope) ? observed.scopes[folderScope] : undefined;
  const selected = catalog.data?.items.find((item) => item.collection_scope_id === scope);
  const restoring = observed?.command.action === "restore" && observed.may_own_audit;
  const disabled = busy || change.isPending || !mayEdit || restoring || (enabled && !root);
  const toggle = (checked: boolean) => {
    change.reset();
    if (checked || !enabled) { setChoosing(checked); return; }
    if (root && window.confirm(t("agents.fileServer.confirmDisable", { path: root.path }))) change.mutate({ selected: root, remove: true });
  };
  const save = () => {
    if (!selected) return;
    change.mutate({ remove: false, selected: { ...selected, important: false,
      sacl: { trustee_sids: ["S-1-1-0"], inherit_files: true, inherit_directories: true } } });
  };
  return <section className="sli-ds-filters__fields" data-align="start">
    <Checkbox label={t("agents.fileServer.role")} checked={enabled || choosing} disabled={disabled}
      onChange={(event) => toggle(event.target.checked)}/>
    {choosing && mayEdit ? <>
      <Select label={t("agents.fileServer.folder")} value={scope} onChange={(event) => setScope(event.target.value)} disabled={disabled}>
        <option value="">{t("agents.deployment.choose")}</option>
        {(catalog.data?.items ?? []).map((share) => <option key={share.collection_scope_id} value={share.collection_scope_id}>
          {share.share_name} · {share.path}
        </option>)}
      </Select>
      {catalog.data?.state !== "ready" || !catalog.data.items.length ? <Button
        disabled={disabled || catalog.isFetching || catalog.data?.state === "pending" || refresh.isPending}
        onClick={() => refresh.mutate(agent.id)}>{t("agents.fileAudit.catalog.refresh")}</Button> : null}
      {catalog.isError || refresh.isError ? <p role="alert">{t("agents.fileAudit.catalog.unavailable")}</p> : null}
      <Button variant="primary" disabled={disabled || !selected || !agent.collection_policy?.manage_windows_audit}
        onClick={save}>{t("agents.saveAudit")}</Button>
      {!agent.collection_policy?.manage_windows_audit ? <p>{t("agents.fileServer.managementOff")}</p> : null}
    </> : null}
    {!choosing && path ? <p role="status">{path} · {receipt && observed?.reported_at ? <>{formatDateTime(observed.reported_at, timeZone)} · {
      receipt.state === "verified" ? t(observed.command.action === "restore" ? "agents.fileServer.restored" : "agents.fileServer.applied")
        : t(Object.hasOwn(folderFailures, receipt.reason_code) ? folderFailures[receipt.reason_code] : "agents.fileServer.auditFailed")}</>
      : t(status.isError ? "agents.fileServer.readFailed"
        : status.isPending || observed?.state === "pending" || !matches ? "agents.fileAudit.result.pending" : "agents.fileServer.noResult")}
      {lastEvent ? <> · {t("agents.fileServer.lastEvent", { time: formatDateTime(lastEvent.observed_at, timeZone) })}</> : null}
    </p> : null}
    {change.isError ? <p role="alert">{t("agents.fileServer.changeFailed")}</p> : null}
  </section>;
}

export function AgentFileAuditControls({ agents, busy, change, accepted, serverCatalog }: {
  agents: AgentItem[]; busy: boolean; change: Change; accepted?: AgentFileAuditCommand; serverCatalog?: ServerCatalog;
}) {
  const [sourceKind, setSourceKind] = useState<"workstation" | "server">(serverCatalog?.agentId ? "server" : "workstation");
  const eligible = agents.filter((agent) => agent.status === "active" && (sourceKind === "server"
    ? kindOf(agent) === undefined || kindOf(agent) === "server"
    : (workstation(agent) || kindOf(agent) === "workstation") && (kindOf(agent) === undefined || kindOf(agent) === "workstation")));
  const [selected, setSelected] = useState<string[]>(() => serverCatalog?.agentId ? [serverCatalog.agentId] : []);
  const [draft, setDraft] = useState<AuditDraft>({});
  const [dismissedCommand, setDismissedCommand] = useState<string | null>(null);
  const [error, setError] = useState<MessageKey | null>(null);
  const chosen = eligible.filter((agent) => selected.includes(agent.id));
  const primary = eligible.find((agent) => agent.id === selected[0]);
  const assignment = primary ? fileConfig(primary) : undefined;
  const originalConfig = assignment?.config ?? {};
  const original = Array.isArray(originalConfig.roots) ? originalConfig.roots as Root[] : [];
  const catalog = sourceKind === "server" && primary && primary.id === serverCatalog?.agentId && original.length <= 1 ? serverCatalog : undefined;
  const catalogEnabled = Boolean(catalog && catalog.result?.state !== "unsupported");
  const saved = catalog?.result?.saved_selection;
  const state = catalog?.result?.state;
  const canEnterManually = catalogEnabled && !catalog?.denied && !saved
    && (catalog?.error || state === "unavailable" || state === "incomplete");
  const manualServer = catalogEnabled && !catalog?.denied && Boolean(draft.manualServer);
  const useCatalog = catalogEnabled && !manualServer;
  const options = catalog?.result?.state === "ready" ? catalog.result.items : [];
  const choices = saved ? [saved, ...options.filter((item) => item.collection_scope_id !== saved.collection_scope_id)] : options;
  const selectedShare = choices.find((item) => item.collection_scope_id === (draft.catalogScope ?? saved?.collection_scope_id));
  const paths = useCatalog ? selectedShare?.path ?? "" : draft.paths ?? (original.length ? original.map((root) => root.path).join("\n") : saved?.path ?? "");
  const shares = useCatalog ? selectedShare?.share_name ?? "" : draft.shares ?? (original.length ? original.map((root) => root.share_name).join("\n") : saved?.share_name ?? "");
  const scopes = useCatalog ? selectedShare?.collection_scope_id ?? "" : draft.scopes ?? (original.length ? original.map((root) => root.collection_scope_id).join("\n") : saved?.collection_scope_id ?? "");
  const shareNames = lines(shares);
  const formScopeIds = lines(scopes);
  const savedCommand = catalog?.result?.saved_command;
  const restored = primary && saved && savedCommand && (savedCommand.action === "check" || savedCommand.action === "apply")
    && savedCommand.collection_scope_ids.length === 1 && savedCommand.collection_scope_ids[0] === saved.collection_scope_id
    && paths === saved.path && shares === saved.share_name && scopes === saved.collection_scope_id
    ? { ...savedCommand, agent_id: primary.id } : undefined;
  const current = primary && accepted?.agent_id === primary.id
    && (!useCatalog || accepted.action === "restore" || accepted.collection_scope_ids.includes(scopes)) ? accepted : restored;
  const reportShare = catalog?.result?.saved_report_share_key;
  const permissionReportHref = saved && reportShare && restored?.action === "apply" && current?.action === "apply"
    && current.command_id === restored.command_id && current.policy_revision === restored.policy_revision
    ? withDomain(`/app/report/file-audit.permission-changes?${new URLSearchParams({
      period: "24h", source_kind: "server", share: reportShare, path: saved.path,
      include_nested: "true", operation: "permissions",
    })}`, window.location.search)
    : undefined;
  const dismissResult = () => setDismissedCommand(current?.command_id ?? null);
  const exclusions = draft.exclusions ?? (Array.isArray(originalConfig.service_account_exclusions) ? originalConfig.service_account_exclusions.join("\n") : "");
  const enabled = draft.enabled ?? Boolean(assignment?.enabled);
  const important = draft.important ?? (original.length > 0 && original.every((root) => root.important));
  const edit = (field: AuditDraft) => {
    dismissResult();
    setDraft((previous) => ({ ...previous, ...field }));
  };
  // A shared workstation edit must never clone or overwrite a different bound identity.
  const compatible = chosen.every((agent) => Boolean(fileConfig(agent)) === Boolean(primary && fileConfig(primary))
    && (!fileConfig(agent) || JSON.stringify(fileConfig(agent)?.config) === JSON.stringify(originalConfig)));
  const mayWrite = chosen.length > 0 && chosen.every((agent) => agent.collection_policy?.manage_windows_audit);
  const mayCollect = chosen.length > 0 && compatible && (sourceKind === "server" || chosen.every(workstation));
  const canSubmit = mayCollect && (!useCatalog || Boolean(selectedShare && !catalog?.loading && !catalog?.error));
  const choose = (agent: AgentItem) => {
    const next = selected.includes(agent.id) ? selected.filter((id) => id !== agent.id)
      : sourceKind === "server" ? [agent.id] : [...selected, agent.id];
    setSelected(next);
    if (sourceKind === "server") serverCatalog?.selectAgent(next[0] ?? null);
  };
  useEffect(() => {
    setDraft({});
    setError(null);
  }, [primary?.id, sourceKind]);
  const submit = (action: "check" | "apply" | "restore") => {
    if (!useCatalog && !manualServer) dismissResult();
    if (useCatalog && action !== "restore" && !canSubmit) return;
    const restoreAssigned = (useCatalog || manualServer) && action === "restore";
    const entries = restoreAssigned ? original.map((root) => root.path) : lines(paths);
    const shareEntries = restoreAssigned ? original.map((root) => root.share_name) : lines(shares);
    const scopeEntries = restoreAssigned ? original.map((root) => root.collection_scope_id) : lines(scopes);
    const excluded = restoreAssigned ? [] : lines(exclusions);
    if (!chosen.length || chosen.length > 64 || !compatible || (sourceKind === "server" && chosen.length !== 1)
        || !entries.length || entries.length > 100 || (manualServer && action !== "restore" && entries.length !== 1)
        || excluded.length > 100
        || new Set(entries.map((path) => path.toLowerCase())).size !== entries.length
        || entries.some((path) => !/^[A-Za-z]:[\\/]/.test(path))
        || excluded.some((sid) => !/^S-1-(?:\d+-)*\d+$/.test(sid))
        || (sourceKind === "server" && (shareEntries.length !== entries.length || scopeEntries.length !== entries.length
          || new Set(scopeEntries).size !== scopeEntries.length))) { setError("agents.invalidPolicy"); return; }
    // Existing identities cannot be migrated by this editor. Never silently discard an edit.
    if (action !== "restore" && sourceKind === "server" && entries.some((path, index) => {
      const prior = original.find((root) => root.path.toLowerCase() === path.toLowerCase());
      const shareMatches = useCatalog ? prior?.share_name.toLowerCase() === shareEntries[index].toLowerCase() : prior?.share_name === shareEntries[index];
      return prior && (!shareMatches || prior.collection_scope_id !== scopeEntries[index]);
    })) { setError("agents.fileAudit.identityImmutable"); return; }
    const roots: Root[] = action === "restore" ? original : entries.map((path, index) => {
      const prior = original.find((root) => root.path.toLowerCase() === path.toLowerCase());
      return prior ? { ...prior, important: draft.important ?? prior.important } : {
        collection_scope_id: sourceKind === "server" ? scopeEntries[index] : `wsfile:${index}`,
        share_name: sourceKind === "server" ? shareEntries[index] : "", path, important,
        sacl: { trustee_sids: ["S-1-1-0"], inherit_files: true, inherit_directories: true },
      };
    });
    if (new Set(roots.map((root) => root.collection_scope_id)).size !== roots.length) { setError("agents.invalidPolicy"); return; }
    if (action === "apply" && (useCatalog || manualServer) && !window.confirm(t("agents.fileAudit.catalog.confirmApply", { share: shares }))) return;
    if (useCatalog || manualServer) dismissResult();
    setError(null);
    const targets = chosen.map((agent) => ({ agent_id: agent.id, expected_revision: agent.policy_revision }));
    change("file-audit", { ...(sourceKind === "server" ? targets[0] : { agents: targets }),
      ...(sourceKind === "workstation" || action === "apply" ? { enabled: action === "restore" ? false : enabled } : {}),
      ...(sourceKind === "server" ? { command: { contract_id: "sli.file-audit.audit-command.v1",
        command_id: crypto.randomUUID(), action, policy_revision: String(targets[0].expected_revision + 1),
        collection_scope_ids: roots.map((root) => root.collection_scope_id) } } : { action }),
      ...(action === "apply" && enabled ? { activate_collection: true } : {}),
      config: action === "restore" ? { ...originalConfig, roots } : {
        ...originalConfig, source_kind: sourceKind, roots, service_account_exclusions: [...new Set(excluded)] } });
  };
  if (!agents.some((agent) => agent.status === "active")) return null;
  return <details className="sli-ds-filters__additional" open={serverCatalog?.agentId ? true : undefined}><summary>{t("agents.fileAudit.title")}</summary>
    <fieldset disabled={busy} className="sli-ds-filters">
      <legend>{t("agents.fileAudit.select")}</legend>
      <label className="sli-ds-field">{t("agents.fileAudit.sourceKind")}<select value={sourceKind} onChange={(event) => {
        setSelected([]); serverCatalog?.selectAgent(null); setSourceKind(event.target.value as "workstation" | "server");
      }}><option value="workstation">{t("agents.fileAudit.workstation")}</option><option value="server">{t("agents.fileAudit.server")}</option></select></label>
      {eligible.map((agent) => <div key={agent.id}><label><input id={`file-audit-agent-${agent.id}`} aria-describedby={`file-audit-identity-${agent.id}`} type={sourceKind === "server" ? "radio" : "checkbox"} name="file-audit-agent" value={agent.id} checked={selected.includes(agent.id)} onChange={() => choose(agent)}/>{t("agents.fileAudit.agent", { host: agentHostName(agent) })}</label>
        <details id={`file-audit-identity-${agent.id}`}><summary>{t("agents.technicalDetails")}</summary><dl>
          <dt>{t("agents.agentId")}</dt><dd>{agent.id}</dd><dt>{t("agents.host")}</dt><dd>{agent.host_id}</dd>
        </dl></details></div>)}
      {!compatible ? <p role="alert">{t("agents.fileAudit.incompatible")}</p> : null}
      {chosen.length > 0 && !mayWrite ? <p>{t("agents.fileAudit.managementHint")}</p> : null}
      <label><input type="checkbox" checked={enabled} disabled={!mayCollect} onChange={(event) => edit({ enabled: event.target.checked })}/>{t("agents.fileAudit.enabled")}</label>
      {useCatalog && catalog ? <div className="sli-ds-filters__fields" data-layout="grid" data-align="start">
        <label className="sli-ds-field">{t("agents.fileAudit.catalog.share")}<select value={selectedShare?.collection_scope_id ?? ""}
          onChange={(event) => edit({ catalogScope: event.target.value })}>
          <option value="">{t("agents.deployment.choose")}</option>
          {choices.map((item) => <option key={item.collection_scope_id} value={item.collection_scope_id}>{item.share_name}</option>)}
        </select></label>
        <label className="sli-ds-field">{t("agents.fileAudit.catalog.path")}<input value={selectedShare?.path ?? ""} readOnly/></label>
        <button className="sli-ds-button" type="button" disabled={catalog.loading || catalog.result?.state === "pending"}
          onClick={catalog.refresh}>{t("agents.fileAudit.catalog.refresh")}</button>
        {catalog.loading || catalog.result?.state === "pending" ? <p role="status">{t("agents.fileAudit.catalog.pending")}</p> :
          catalog.error || catalog.result?.state === "unavailable" || catalog.result?.state === "incomplete" || catalog.result?.state === "expired"
            ? <p role="status">{t("agents.fileAudit.catalog.unavailable")}</p>
            : catalog.result?.state === "ready" && !choices.length ? <p role="status">{t("agents.fileAudit.catalog.empty")}</p> : null}
        {catalog.result?.native_status ? <p>{t("agents.fileAudit.readError.code", { code: catalog.result.native_status })}</p> : null}
      </div> : <div className="sli-ds-filters__fields" data-layout="grid" data-align="start">
        <label className="sli-ds-field">{t("agents.fileAudit.paths")}<textarea value={paths} onChange={(event) => edit({ paths: event.target.value })}/></label>
        {sourceKind === "server" ? <>
          <label className="sli-ds-field">{t("agents.fileAudit.shares")}<textarea value={shares} onChange={(event) => edit({ shares: event.target.value })}/></label>
          <label className="sli-ds-field">{t("agents.fileAudit.scopes")}<textarea value={scopes} onChange={(event) => edit({ scopes: event.target.value })}/></label>
        </> : null}
      </div>}
      {manualServer || canEnterManually ? <button className="sli-ds-button" type="button"
        onClick={() => edit({ manualServer: !manualServer })}>{t(manualServer
          ? "agents.fileAudit.catalog.backToShares" : "agents.fileAudit.catalog.manualEntry")}</button> : null}
      <label><input type="checkbox" checked={important} onChange={(event) => edit({ important: event.target.checked })}/>{t("agents.fileAudit.important")}</label>
      <label className="sli-ds-field">{t("agents.fileAudit.exclusions")}<textarea value={exclusions} onChange={(event) => edit({ exclusions: event.target.value })}/></label>
      <div className="sli-ds-filters__actions">
        <button className="sli-ds-button" type="button" disabled={!canSubmit} onClick={() => submit("check")}>{t("agents.fileAudit.check")}</button>
        <button className="sli-ds-button" type="button" disabled={!mayWrite || !canSubmit || !enabled} onClick={() => submit("apply")}>{t("agents.fileAudit.apply")}</button>
        <button className="sli-ds-button" type="button" disabled={!mayWrite || !compatible || !original.length} onClick={() => submit("restore")}>{t("agents.fileAudit.restore")}</button>
      </div>
    </fieldset>
    {!busy && sourceKind === "server" && current && current.command_id !== dismissedCommand ? <>
      {serverCatalog && current.action !== "restore" ? <h3>{t(`agents.fileAudit.catalog.${current.action}Result`)}</h3> : null}
      <AgentFileAuditReadback key={`${current.agent_id}:${current.command_id}:${current.policy_revision}:${current.action}`}
        accepted={current} permissionReportHref={permissionReportHref}
        shareName={shareNames.length === 1 && formScopeIds.length === 1 && current.collection_scope_ids.length === 1
          && current.collection_scope_ids[0] === formScopeIds[0] ? shareNames[0] : undefined}/>
    </> : null}
    {error ? <p role="alert">{t(error)}</p> : null}
  </details>;
}



type ReadbackState = "loading" | "pending" | "delayed" | "unavailable" | "verified" | "partial" | "blocked" | "failed" | "denied" | "stale" | "unknown";
export function AgentFileAuditReadback({ accepted, permissionReportHref, shareName }: {
  accepted: AgentFileAuditCommand; permissionReportHref?: string; shareName?: string;
}) {
  const [result, setResult] = useState<{ state: ReadbackState; receipt?: AgentFileAuditStatus }>({ state: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false;
    let poll: ReturnType<typeof setTimeout> | undefined;
    const deadline = setTimeout(() => {
      cancelled = true;
      clearTimeout(poll);
      setResult({ state: "delayed" });
    }, 120_000);
    const read = async () => {
      try {
        const receipt = await api.agentFileAuditStatus(accepted.agent_id);
        if (cancelled) return;
        let state: ReadbackState = "unknown";
        if (receipt?.command) {
          const command = receipt.command;
          if (command.command_id !== accepted.command_id || command.policy_revision !== accepted.policy_revision
              || command.action !== accepted.action || !Array.isArray(command.collection_scope_ids)
              || command.collection_scope_ids.length !== accepted.collection_scope_ids.length
              || !accepted.collection_scope_ids.every((scope) => command.collection_scope_ids.includes(scope))) state = "stale";
          else if (receipt.state === "pending" || receipt.state === "partial") state = receipt.state;
          else if (receipt.state === "verified" && receipt.reported_at && accepted.collection_scope_ids.every(
            (scope) => receipt.scopes?.[scope]?.state === "verified")) state = "verified";
          else if ((receipt.state === "blocked" || receipt.state === "failed") && receipt.reported_at
            && accepted.collection_scope_ids.some((scope) => receipt.scopes?.[scope]?.state === receipt.state
              && receipt.scopes[scope].reason_code)) state = receipt.state;
        }
        // Do not retain foreign/malformed receipt details under the requested command.
        setResult({ state, ...(["verified", "partial", "pending", "blocked", "failed"].includes(state) ? { receipt } : {}) });
        if (state === "pending") poll = setTimeout(() => { void read(); }, 5_000);
        else clearTimeout(deadline);
      } catch (error) {
        if (cancelled) return;
        clearTimeout(deadline);
        const status = error instanceof ApiResponseError ? error.status : undefined;
        let state: ReadbackState = "unknown";
        if (status === 401 || status === 403) state = "denied";
        else if (status !== undefined && status >= 500) state = "unavailable";
        setResult({ state });
      }
    };
    void read();
    return () => {
      cancelled = true;
      clearTimeout(poll);
      clearTimeout(deadline);
    };
  }, [accepted.agent_id, accepted.command_id, accepted.policy_revision, accepted.action, attempt]);
  const terminalFailure = result.state === "failed" || result.state === "blocked";
  const scopeReceipt = accepted.collection_scope_ids.length === 1
    ? result.receipt?.scopes?.[accepted.collection_scope_ids[0]] : undefined;
  const reason = shareName && result.receipt?.reported_at && scopeReceipt?.state === result.state ? scopeReceipt.reason_code : undefined;
  const explanation = accepted.action === "check" && result.state === "partial" && reason === "coverage_incomplete"
    ? "agents.fileAudit.result.checkCoverageIncomplete"
    : accepted.action === "apply" && result.state === "blocked" && reason === "global_sacl_unknown"
      ? "agents.fileAudit.result.applyGlobalSaclUnknown" : undefined;
  return <div>
    <p role="status">{explanation && shareName ? t(explanation, { share: shareName }) : t(`agents.fileAudit.result.${result.state}`)}</p>
    {result.state === "verified" && permissionReportHref
      ? <p><a href={permissionReportHref}>{t("file-audit.tabs.permission-changes")}</a></p> : null}
    {terminalFailure && !explanation ? <dl>{accepted.collection_scope_ids.map((scope) => {
      const row = result.receipt?.scopes?.[scope];
      if (row?.state !== result.state) return null;
      const detail = row.read_error;
      const code = detail?.code_kind === "hresult" && detail.code
        ? "0x" + detail.code.toString(16).toUpperCase().padStart(8, "0") : detail?.code;
      return <div key={scope}><dt>{scope}</dt><dd>
        {detail ? <>
          <p>{t(`agents.fileAudit.readError.${detail.stage}`)}</p>
          {code ? <p>{t("agents.fileAudit.readError.code", { code })}</p> : null}
        </> : row.reason_code}
      </dd></div>;
    })}</dl> : null}
    <button className="sli-ds-button" type="button" disabled={result.state === "loading"} onClick={() => {
      setResult({ state: "loading" }); setAttempt((value) => value + 1);
    }}>{t("agents.fileAudit.result.refresh")}</button>
    <details><summary>{t("agents.technicalDetails")}</summary><dl>
      <dt>{t("agents.agentId")}</dt><dd>{accepted.agent_id}</dd>
      <dt>{t("file-audit.receipt.command_id")}</dt><dd>{accepted.command_id}</dd>
      <dt>{t("file-audit.receipt.policy_revision")}</dt><dd>{accepted.policy_revision}</dd>
      <dt>{t("file-audit.receipt.action")}</dt><dd>{t(`agents.fileAudit.${accepted.action}`)}</dd>
      {result.receipt?.reported_at ? <><dt>{t("agents.fileAudit.result.receivedAt")}</dt><dd>{result.receipt.reported_at}</dd></> : null}
    </dl>
      {result.receipt && (!terminalFailure || explanation) ? <dl>{accepted.collection_scope_ids.map((scope) => <div key={scope}>
        <dt>{scope}</dt><dd>{result.receipt?.scopes?.[scope]?.reason_code ?? t("agents.fileAudit.result.noScopeReceipt")}</dd>
      </div>)}</dl> : null}
    </details>
  </div>;
}
