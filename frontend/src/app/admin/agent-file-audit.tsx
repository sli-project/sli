import { useEffect, useState } from "react";
import { api, ApiResponseError, type AgentFileAuditCommand, type AgentFileAuditStatus, type AgentItem } from "../../api/client";
import { t, type MessageKey } from "../../i18n";
import { agentHostName } from "./agent-actions";

type Root = { collection_scope_id: string; share_name: string; path: string; important: boolean;
  sacl: { trustee_sids: string[]; inherit_files: boolean; inherit_directories: boolean } };
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

export function AgentFileAuditControls({ agents, busy, change, accepted }: { agents: AgentItem[]; busy: boolean; change: Change; accepted?: AgentFileAuditCommand }) {
  const [sourceKind, setSourceKind] = useState<"workstation" | "server">("workstation");
  const eligible = agents.filter((agent) => agent.status === "active" && (sourceKind === "server"
    ? kindOf(agent) === undefined || kindOf(agent) === "server"
    : (workstation(agent) || kindOf(agent) === "workstation") && (kindOf(agent) === undefined || kindOf(agent) === "workstation")));
  const [selected, setSelected] = useState<string[]>([]);
  const [enabled, setEnabled] = useState(false);
  const [paths, setPaths] = useState("");
  const [shares, setShares] = useState("");
  const [scopes, setScopes] = useState("");
  const [exclusions, setExclusions] = useState("");
  const [important, setImportant] = useState(false);
  const [importantChanged, setImportantChanged] = useState(false);
  const [original, setOriginal] = useState<Root[]>([]);
  const [originalConfig, setOriginalConfig] = useState<Record<string, unknown>>({});
  const [dismissedCommand, setDismissedCommand] = useState<string | null>(null);
  const dismissResult = () => setDismissedCommand(accepted?.command_id ?? null);
  const [error, setError] = useState<MessageKey | null>(null);
  const chosen = eligible.filter((agent) => selected.includes(agent.id));
  const primary = eligible.find((agent) => agent.id === selected[0]);
  // A shared workstation edit must never clone or overwrite a different bound identity.
  const compatible = chosen.every((agent) => Boolean(fileConfig(agent)) === Boolean(primary && fileConfig(primary))
    && (!fileConfig(agent) || JSON.stringify(fileConfig(agent)?.config) === JSON.stringify(originalConfig)));
  const mayWrite = chosen.length > 0 && chosen.every((agent) => agent.collection_policy?.manage_windows_audit);
  const mayCollect = chosen.length > 0 && compatible && (sourceKind === "server" || chosen.every(workstation));
  const choose = (agent: AgentItem) => {
    setSelected(selected.includes(agent.id) ? selected.filter((id) => id !== agent.id)
      : sourceKind === "server" ? [agent.id] : [...selected, agent.id]);
  };
  useEffect(() => {
    const module = primary ? fileConfig(primary) : undefined;
    const config = module?.config ?? {};
    const roots = Array.isArray(config.roots) ? config.roots as Root[] : [];
    setOriginalConfig(config); setOriginal(roots); setPaths(roots.map((root) => root.path).join("\n"));
    setShares(roots.map((root) => root.share_name).join("\n"));
    setScopes(roots.map((root) => root.collection_scope_id).join("\n"));
    setExclusions(Array.isArray(config.service_account_exclusions) ? config.service_account_exclusions.join("\n") : "");
    setEnabled(Boolean(module?.enabled));
    setImportant(roots.length > 0 && roots.every((root) => root.important));
    setImportantChanged(false); setError(null);
  }, [primary?.id, primary?.policy_revision, sourceKind]);
  const submit = (action: "check" | "apply" | "restore") => {
    dismissResult();
    const entries = lines(paths), excluded = lines(exclusions), shareEntries = lines(shares), scopeEntries = lines(scopes);
    if (!chosen.length || chosen.length > 64 || !compatible || (sourceKind === "server" && chosen.length !== 1)
        || !entries.length || entries.length > 100 || excluded.length > 100
        || new Set(entries.map((path) => path.toLowerCase())).size !== entries.length
        || entries.some((path) => !/^[A-Za-z]:[\\/]/.test(path))
        || excluded.some((sid) => !/^S-1-(?:\d+-)*\d+$/.test(sid))
        || (sourceKind === "server" && (shareEntries.length !== entries.length || scopeEntries.length !== entries.length
          || new Set(scopeEntries).size !== scopeEntries.length))) { setError("agents.invalidPolicy"); return; }
    // Existing identities cannot be migrated by this editor. Never silently discard an edit.
    if (action !== "restore" && sourceKind === "server" && entries.some((path, index) => {
      const prior = original.find((root) => root.path.toLowerCase() === path.toLowerCase());
      return prior && (prior.share_name !== shareEntries[index] || prior.collection_scope_id !== scopeEntries[index]);
    })) { setError("agents.fileAudit.identityImmutable"); return; }
    const roots: Root[] = action === "restore" ? original : entries.map((path, index) => {
      const prior = original.find((root) => root.path.toLowerCase() === path.toLowerCase());
      return prior ? { ...prior, important: !importantChanged ? prior.important : important } : {
        collection_scope_id: sourceKind === "server" ? scopeEntries[index] : `wsfile:${index}`,
        share_name: sourceKind === "server" ? shareEntries[index] : "", path, important,
        sacl: { trustee_sids: ["S-1-1-0"], inherit_files: true, inherit_directories: true },
      };
    });
    if (new Set(roots.map((root) => root.collection_scope_id)).size !== roots.length) { setError("agents.invalidPolicy"); return; }
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
  return <details><summary>{t("agents.fileAudit.title")}</summary>
    <p>{t("agents.fileAudit.hint")}</p>
    <fieldset disabled={busy}>
      <legend>{t("agents.fileAudit.select")}</legend>
      <label>{t("agents.fileAudit.sourceKind")}<select value={sourceKind} onChange={(event) => {
        setSelected([]); setSourceKind(event.target.value as "workstation" | "server");
      }}><option value="workstation">{t("agents.fileAudit.workstation")}</option><option value="server">{t("agents.fileAudit.server")}</option></select></label>
      {eligible.map((agent) => <div key={agent.id}><label><input id={`file-audit-agent-${agent.id}`} aria-describedby={`file-audit-identity-${agent.id}`} type={sourceKind === "server" ? "radio" : "checkbox"} name="file-audit-agent" value={agent.id} checked={selected.includes(agent.id)} onChange={() => choose(agent)}/>{t("agents.fileAudit.agent", { host: agentHostName(agent) })}</label>
        <details id={`file-audit-identity-${agent.id}`}><summary>{t("agents.technicalDetails")}</summary><dl>
          <dt>{t("agents.agentId")}</dt><dd>{agent.id}</dd><dt>{t("agents.host")}</dt><dd>{agent.host_id}</dd>
        </dl></details></div>)}
      {!compatible ? <p role="alert">{t("agents.fileAudit.incompatible")}</p> : null}
      {chosen.length > 0 && !mayWrite ? <p>{t("agents.fileAudit.managementHint")}</p> : null}
      <label><input type="checkbox" checked={enabled} disabled={!mayCollect} onChange={(event) => { dismissResult(); setEnabled(event.target.checked); }}/>{t("agents.fileAudit.enabled")}</label>
      <label>{t("agents.fileAudit.paths")}<textarea value={paths} onChange={(event) => { dismissResult(); setPaths(event.target.value); }}/></label>
      {sourceKind === "server" ? <>
        <label>{t("agents.fileAudit.shares")}<textarea value={shares} onChange={(event) => { dismissResult(); setShares(event.target.value); }}/></label>
        <label>{t("agents.fileAudit.scopes")}<textarea value={scopes} onChange={(event) => { dismissResult(); setScopes(event.target.value); }}/></label>
      </> : null}
      <label><input type="checkbox" checked={important} onChange={(event) => { dismissResult(); setImportant(event.target.checked); setImportantChanged(true); }}/>{t("agents.fileAudit.important")}</label>
      <label>{t("agents.fileAudit.exclusions")}<textarea value={exclusions} onChange={(event) => { dismissResult(); setExclusions(event.target.value); }}/></label>
      <button className="sli-ds-button" type="button" disabled={!mayCollect} onClick={() => submit("check")}>{t("agents.fileAudit.check")}</button>
      <button className="sli-ds-button" type="button" disabled={!mayWrite || !mayCollect || !enabled} onClick={() => submit("apply")}>{t("agents.fileAudit.apply")}</button>
      <button className="sli-ds-button" type="button" disabled={!mayWrite || !compatible || !original.length} onClick={() => submit("restore")}>{t("agents.fileAudit.restore")}</button>
    </fieldset>
    {!busy && sourceKind === "server" && primary && accepted?.agent_id === primary.id && accepted.command_id !== dismissedCommand ?
      <AgentFileAuditReadback key={`${accepted.agent_id}:${accepted.command_id}:${accepted.policy_revision}:${accepted.action}`}
        accepted={accepted}/> : null}
    {error ? <p role="alert">{t(error)}</p> : null}
  </details>;
}



type ReadbackState = "loading" | "pending" | "verified" | "partial" | "denied" | "stale" | "unknown";
function AgentFileAuditReadback({ accepted }: { accepted: AgentFileAuditCommand }) {
  const [result, setResult] = useState<{ state: ReadbackState; receipt?: AgentFileAuditStatus }>({ state: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const read = async () => {
      try {
        const receipt = await api.agentFileAuditStatus(accepted.agent_id);
        if (cancelled) return;
        let state: ReadbackState = "unknown";
        if (receipt?.command) {
          const command = receipt.command;
          if (command.command_id !== accepted.command_id || command.policy_revision !== accepted.policy_revision
              || command.action !== accepted.action) state = "stale";
          else if (receipt.state === "pending" || receipt.state === "partial") state = receipt.state;
          else if (receipt.state === "verified" && receipt.reported_at && accepted.collection_scope_ids.every(
            (scope) => receipt.scopes?.[scope]?.state === "verified")) state = "verified";
        }
        // Do not retain foreign/malformed receipt details under the requested command.
        setResult({ state, ...(["verified", "partial", "pending"].includes(state) ? { receipt } : {}) });
        if (state === "pending") timer = setTimeout(() => { void read(); }, 5_000);
      } catch (error) {
        if (!cancelled) setResult({ state: error instanceof ApiResponseError && [401, 403].includes(error.status) ? "denied" : "unknown" });
      }
    };
    void read();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [accepted.agent_id, accepted.command_id, accepted.policy_revision, accepted.action, attempt]);
  return <div>
    <p role="status">{t(`agents.fileAudit.result.${result.state}`)}</p>
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
      {result.receipt ? <dl>{accepted.collection_scope_ids.map((scope) => <div key={scope}>
        <dt>{scope}</dt><dd>{result.receipt?.scopes?.[scope]?.reason_code ?? "unknown"}</dd>
      </div>)}</dl> : null}
    </details>
  </div>;
}
