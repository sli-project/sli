import { Checkbox } from "../../design-system/Checkbox";
import { Select } from "../../design-system/Select";
import { agentHostName } from "./agent-actions";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type AgentDeploymentBinding, type AgentItem } from "../../api/client";
import { StateView } from "../../design-system";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { downloadRegistration, registrationConfiguration, registrationFile } from "./registration-file";

export function AgentDeploymentPanel({ agents, sessionKey, expanded = false }: { agents: AgentItem[]; sessionKey?: string; expanded?: boolean }) {
  const [open, setOpen] = useState(false);
  if (expanded) return <DeploymentControls key={sessionKey} agents={agents}/>;
  return <details onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary>{t("agents.deployment.title")}</summary>
    {open ? <DeploymentControls key={sessionKey} agents={agents}/> : null}
  </details>;
}

function DeploymentControls({ agents }: { agents: AgentItem[] }) {
  const client = useQueryClient();
  const [domain, setDomain] = useState<number>();
  const [ou, setOu] = useState<number>();
  const [selected, setSelected] = useState<number[]>([]);
  const [all, setAll] = useState(true);
  const [templateId, setTemplateId] = useState("");
  const [sourceId, setSourceId] = useState("");
  const [automatic, setAutomatic] = useState(false);
  const [bindings, setBindings] = useState<AgentDeploymentBinding[]>([]);
  const [maximum, setMaximum] = useState(100);
  const [ttl, setTtl] = useState(3600);
  // Credentials never enter the query or mutation cache.
  const [secret, setSecret] = useState<string>();
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const [registration, setRegistration] = useState<{ id: string; expires_at: string; computers: Array<{ id: number; name: string }>; scope: string }>();
  const [origin, setOrigin] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const epoch = useRef(0), active = useRef(true);
  const clearSecrets = useCallback(() => { ++epoch.current; setSecret(undefined); setRegistration(undefined); setCopied(false); setCopyError(false); }, []);
  useEffect(() => { active.current = true; return () => { active.current = false; ++epoch.current; }; }, []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const domains = useQuery({ queryKey: ["agent-deployment-domains"], queryFn: () => api.agentDeploymentDirectory({}) });
  const directory = useQuery({ queryKey: ["agent-deployment-directory", domain, ou], enabled: domain !== undefined,
    queryFn: () => api.agentDeploymentDirectory({ domain_id: domain, ou_entity_ids: ou ? [ou] : [] }) });
  const templates = useQuery({ queryKey: ["agent-templates"], queryFn: api.agentTemplates });
  const tokens = useQuery({ queryKey: ["agent-group-tokens"], queryFn: api.agentGroupTokens });
  const waves = useQuery({ queryKey: ["agent-update-waves"], queryFn: api.agentUpdateWaves });
  const template = templates.data?.items.find((item) => item.id === templateId);
  const computers = all ? [] : (directory.data?.computers ?? []).filter((item) => selected.includes(item.id));
  const scope = JSON.stringify([domain, ou, all, selected, templateId, template?.version, maximum, ttl, automatic, bindings, origin, fingerprint,
    directory.data?.computers?.map((item) => item.id)]);
  const currentScope = useRef(scope); currentScope.current = scope;
  useLayoutEffect(() => { clearSecrets(); }, [scope, clearSecrets]);
  useEffect(() => client.getQueryCache().subscribe((event) => {
    if (event.type === "removed" && (event.query.queryKey[0] === "bootstrap" || event.query.queryKey.join("/") === "v4/access/shell")) clearSecrets();
  }), [client, clearSecrets]);
  useEffect(() => {
    if (!registration) return;
    const remaining = Date.parse(registration.expires_at) - Date.now();
    const timer = window.setTimeout(clearSecrets, Math.min(Math.max(remaining, 0), 2147483647));
    return () => window.clearTimeout(timer);
  }, [registration, clearSecrets]);
  useEffect(() => {
    const item = tokens.data?.items.find((row) => row.id === registration?.id);
    if (item && (item.revoked_at || Date.parse(item.expires_at) <= Date.now())) clearSecrets();
  }, [tokens.data, registration?.id, clearSecrets]);
  const execute = async (operation: (generation: number) => Promise<void>) => {
    setError(false); setBusy(true); clearSecrets(); const generation = epoch.current;
    try { await operation(generation); }
    catch { if (active.current && generation === epoch.current) setError(true); }
    finally { if (active.current) setBusy(false); }
  };
  const upload = async (file?: File) => {
    setBindings([]);
    if (!file) return;
    await execute(async () => {
      if (file.size > 512 * 1024) throw new Error();
      const value: unknown = JSON.parse(await file.text());
      if (!Array.isArray(value) || !value.length || value.length > 1000 || !value.every((item: unknown) => {
        if (!item || typeof item !== "object") return false;
        const row = item as Record<string, unknown>;
        return Object.keys(row).sort().join(",") === "computer_entity_id,host_id,instance_name,key_fingerprint" &&
          typeof row.host_id === "string" && /^[0-9a-f-]{36}$/i.test(row.host_id) &&
          typeof row.key_fingerprint === "string" && /^[0-9a-f]{64}$/.test(row.key_fingerprint) &&
          (row.instance_name === null || typeof row.instance_name === "string") &&
          Number.isSafeInteger(row.computer_entity_id) && Number(row.computer_entity_id) > 0;
      })) throw new Error();
      setBindings(value as AgentDeploymentBinding[]);
    });
  };
  const create = () => execute(async (generation) => {
    if (!template || domain === undefined || !all && !selected.length) return;
    const result = await api.createAgentGroupToken({ domain_id: domain, ou_entity_ids: ou ? [ou] : [],
      computer_entity_ids: all ? [] : selected, max_uses: maximum, ttl_seconds: ttl,
      template_id: template.id, template_version: template.version, auto_approve: automatic,
      trusted_bindings: automatic ? bindings : [] });
    if (!active.current || generation !== epoch.current || currentScope.current !== scope) return;
    setSecret(result.token); setRegistration({ id: result.id, expires_at: result.expires_at, computers, scope });
    void client.invalidateQueries({ queryKey: ["agent-group-tokens"] });
  });
  const saveTemplate = () => execute(async () => {
    const source = agents.find((item) => item.id === sourceId);
    if (!source) return;
    const result = await api.saveAgentTemplate({ expected_version: 0,
      assigned_modules: source.assigned_modules.filter((item) => typeof item !== "string" && item.module_id === "sli.workstations"),
      collection_policy: source.collection_policy ?? {} });
    await client.invalidateQueries({ queryKey: ["agent-templates"] });
    setTemplateId(result.id);
  });
  const approve = (groupId: string, tokenId: string) => execute(async (generation) => {
    const filter = { group_id: groupId, token_id: tokenId };
    const requests = await api.agentGroupRequests(filter);
    const evidence = requests.items.flatMap((row) => {
      const match = bindings.find((binding) => binding.host_id === row.host_id && binding.instance_name === row.instance_name &&
        binding.key_fingerprint === row.key_fingerprint && binding.computer_entity_id === row.computer_entity_id);
      return match ? [{ ...match, request_id: row.id }] : [];
    });
    if (!evidence.length) throw new Error();
    const result = await api.approveAgentGroupRequests({ filter, evidence });
    const credentials = result.items.filter((item) => item.token);
    if (result.items.some((item) => item.status === "rejected")) setError(true);
    if (credentials.length && active.current && generation === epoch.current) setSecret(JSON.stringify(credentials, null, 2));
  });
  let validConfiguration = false;
  try { registrationConfiguration(origin, fingerprint); validConfiguration = true; } catch { /* Fixed translated copy below. */ }
  const download = (computerId: number) => {
    try {
      if (!secret || !registration || registration.scope !== scope || !registration.computers.some((item) => item.id === computerId)) return;
      downloadRegistration(registrationFile(origin, fingerprint, { token: secret, expires_at: registration.expires_at }, computerId), computerId);
    } catch { clearSecrets(); setError(true); }
  };
  const copy = async () => {
    if (!secret) return;
    const generation = epoch.current;
    try {
      await navigator.clipboard.writeText(secret);
      if (active.current && generation === epoch.current) { setCopied(true); setCopyError(false); }
    } catch {
      if (active.current && generation === epoch.current) { setCopied(false); setCopyError(true); }
    }
  };
  const unavailable = domains.isError || directory.isError || templates.isError || tokens.isError || waves.isError;
  return <section className="sli-ds-panel__body">
    {unavailable ? <StateView state="unavailable"/> : null}
    <div className="sli-ds-filters__fields" data-align="start">
      <div className="sli-ds-field">{t("agents.deployment.domain")}<Select label={t("agents.deployment.domain")} disabled={busy} value={domain ?? ""} onChange={(selectedValue) => {
        setDomain(selectedValue ? Number(selectedValue) : undefined); setOu(undefined); setSelected([]); setBindings([]); setSecret(undefined);
      }}
        options={[{ value: "", label: t("agents.deployment.choose") }, ...(domains.data?.domains?.map((item) => ({ value: item.id, label: item.name })) ?? [])]}/></div>
      <div className="sli-ds-field">{t("agents.deployment.ou")}<Select label={t("agents.deployment.ou")} disabled={busy || directory.isFetching} value={ou ?? ""} onChange={(selectedValue) => {
        setOu(selectedValue ? Number(selectedValue) : undefined); setSelected([]); setBindings([]); setSecret(undefined);
      }}
        options={[{ value: "", label: t("agents.deployment.wholeDomain") }, ...(directory.data?.ous?.map((item) => ({ value: item.id, label: item.name })) ?? [])]}/></div>
      <div className="sli-ds-field">{t("agents.deployment.template")}<Select label={t("agents.deployment.template")} value={templateId} disabled={busy} onChange={(selectedValue) => setTemplateId(selectedValue)}
        options={[{ value: "", label: t("agents.deployment.choose") }, ...(templates.data?.items.map((item) => ({ value: item.id, label: String(item.id) + String(" · ") + String(item.version) })) ?? [])]}/></div>
      <div className="sli-ds-field">{t("agents.deployment.templateSource")}<Select label={t("agents.deployment.templateSource")} value={sourceId} aria-describedby={sourceId ? "agent-template-source-identity" : undefined} disabled={busy} onChange={(selectedValue) => setSourceId(selectedValue)}
        options={[{ value: "", label: t("agents.deployment.choose") }, ...(agents.filter((item) => item.status === "active").map((item) => ({ value: item.id, label: agentHostName(item) })) ?? [])]}/></div>
      {sourceId ? <details id="agent-template-source-identity"><summary>{t("agents.technicalDetails")}</summary>
        <dl><dt>{t("agents.agentId")}</dt><dd>{sourceId}</dd><dt>{t("agents.host")}</dt><dd>{agents.find((item) => item.id === sourceId)?.host_id}</dd></dl>
      </details> : null}
      <button type="button" className="sli-ds-button" disabled={busy || !sourceId} onClick={() => void saveTemplate()}>{t("agents.deployment.saveTemplate")}</button>
    </div>
    <Checkbox disabled={busy} checked={all} onChange={(event) => { setAll(event.target.checked); setSelected([]); }}>{t("agents.deployment.allComputers")}</Checkbox>
    {directory.isFetching ? <StateView state="loading"/> : domain !== undefined && !directory.isError && !directory.data?.computers?.length ? <StateView state="empty"/> : null}
    {directory.data?.has_more ? <p role="status">{t("agents.deployment.more")}</p> : null}
    {!all ? <ul>{directory.data?.computers?.map((item) => <li key={item.id}><Checkbox disabled={busy} checked={selected.includes(item.id)} onChange={(event) => setSelected(event.target.checked ? [...selected, item.id] : selected.filter((id) => id !== item.id))}>{item.name}</Checkbox></li>)}</ul> : null}
    <p>{t("agents.deployment.personal")}</p>
    <Checkbox checked={automatic} disabled={busy} onChange={(event) => setAutomatic(event.target.checked)}>{t("agents.deployment.auto")}</Checkbox>
    <p>{t("agents.deployment.trustedHelp")}</p>
    <label className="sli-ds-field">{t("agents.deployment.trustedReport")}<input type="file" accept="application/json,.json" disabled={busy} onChange={(event) => void upload(event.target.files?.[0])}/></label>
    <label className="sli-ds-field">{t("agents.deployment.limit")}<input type="number" min={1} max={10000} value={maximum} disabled={busy} onChange={(event) => setMaximum(Number(event.target.value))}/></label>
    <label className="sli-ds-field">{t("agents.ttl")}<input type="number" min={60} max={604800} value={ttl} disabled={busy} onChange={(event) => setTtl(Number(event.target.value))}/></label>
    <p>{t("agents.deployment.registrationHelp")}</p>
    <div className="sli-ds-filters__fields" data-align="start">
      <label className="sli-ds-field">{t("agents.deployment.registrationOrigin")}<input required autoComplete="off" disabled={busy} value={origin} onChange={(event) => setOrigin(event.target.value)}/></label>
      <label className="sli-ds-field">{t("agents.deployment.registrationPin")}<input required autoComplete="off" disabled={busy} value={fingerprint} onChange={(event) => setFingerprint(event.target.value)}/></label>
    </div>
    <p>{t("agents.deployment.registrationTrust")}</p>
    {!validConfiguration ? <p>{t("agents.deployment.registrationRequired")}</p> : null}
    <button type="button" className="sli-ds-button" disabled={busy || unavailable || directory.isFetching || !template || domain === undefined ||
      !directory.data?.computers?.length || !all && !selected.length || automatic && !bindings.length ||
      !Number.isInteger(maximum) || maximum < 1 || maximum > 10000 || !Number.isInteger(ttl) || ttl < 60 || ttl > 604800}
      onClick={() => void create()}>{t("agents.deployment.create")}</button>
    {secret ? <div><p>{t("agents.tokenOnce")}</p><pre className="sli-ds-pre">{secret}</pre>
      {registration ? <p>{t("agents.expires", { date: formatDateTime(registration.expires_at) })}</p> : null}
      <button type="button" className="sli-ds-button" onClick={() => void copy()}>{t("agents.copy")}</button>
      {copied ? <p role="status">{t("agents.copied")}</p> : null}
      {copyError ? <p role="alert">{t("agents.copyError")}</p> : null}
      {registration?.scope === scope && registration.computers.length ? <div>
        <p>{t("agents.deployment.registrationSecret")}</p>
        {registration.computers.map((computer) => <button key={computer.id} type="button" className="sli-ds-button" disabled={busy || !validConfiguration}
          onClick={() => download(computer.id)}>{t("agents.deployment.registrationDownload", { computer: computer.name })}</button>)}
      </div> : null}
      <button type="button" className="sli-ds-button" onClick={clearSecrets}>{t("agents.dismiss")}</button></div> : null}
    {error ? <p role="alert">{t("agents.actionError")}</p> : null}
    <h3>{t("agents.deployment.batches")}</h3>
    <ul>{tokens.data?.items.map((item) => <li key={item.id}>{item.id} · {item.uses_count}/{item.max_uses}
      <button type="button" className="sli-ds-button" disabled={busy || Boolean(item.revoked_at) || Date.parse(item.expires_at) <= Date.now() || !bindings.length}
        onClick={() => void approve(item.group_id, item.id)}>{t("agents.deployment.approve")}</button>
      <button type="button" className="sli-ds-button" disabled={busy || Boolean(item.revoked_at)} onClick={() => void execute(async () => {
        await api.revokeAgentGroupToken(item.id); void client.invalidateQueries({ queryKey: ["agent-group-tokens"] });
      })}>{t("agents.deployment.stopBatch")}</button>
    </li>)}</ul>
    <h3>{t("agents.deployment.waves")}</h3>
    <ul>{waves.data?.items.map((item) => <li key={item.id}>{item.id} · {item.version} · {t(`agents.deployment.wave.${item.status}`)}
      <button type="button" className="sli-ds-button" disabled={busy || item.status !== "running"} onClick={() => void execute(async () => {
        await api.stopAgentUpdateWave(item.id); void client.invalidateQueries({ queryKey: ["agent-update-waves"] });
      })}>{t("agents.deployment.stopWave")}</button>
    </li>)}</ul>
  </section>;
}
