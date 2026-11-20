import { useMemo, useState, useSyncExternalStore } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiResponseError, api } from "../api/client";
import type { SigmaRuleListRow, SigmaRulePolicy, SigmaRuleScope } from "../api/sigma-types";
import { Badge, Button, DataTable, FactList, Panel, StateView, type TableColumn } from "../design-system";
import { t } from "../i18n";
import { sigmaReasonLabel, sigmaStateLabel } from "./sigma-validation-view";
import { ExecutionDetails, SigmaValidationPanel } from "./sigma-validation";
import { useEffectiveAccess } from "./App";
import type { QueryClient } from "@tanstack/react-query";

const unknown = () => t("security.sigma.unmeasured");
const failure = (error: unknown) => error instanceof ApiResponseError && [401, 403].includes(error.status) ? "denied" : "unavailable";
const policyKey = (policy: SigmaRulePolicy) => JSON.stringify([policy.policy_id, policy.policy_version]);
type AdmissionOperation = { token: number; scope: SigmaRuleScope; phase: "pending" | "uncertain" | "reconciling" };
type SubmitAdmission = (policy: SigmaRulePolicy, reason: string, scope: SigmaRuleScope) => void;
type AdmissionLedger = { actor: string; epoch: number; nextToken: number; revision: number;
  operations: Map<string, AdmissionOperation>; listeners: Set<() => void> };
const ledgerKey = ["sigma-admission-session"];
let nextEpoch = 0;
function sessionLedger(client: QueryClient, actor: string): AdmissionLedger {
  const retained = client.getQueryData<AdmissionLedger>(ledgerKey);
  if (retained?.actor === actor) return retained;
  const created = { actor, epoch: ++nextEpoch, nextToken: 0, revision: 0,
    operations: new Map<string, AdmissionOperation>(), listeners: new Set<() => void>() };
  // Memory only. AppShell's existing logout clears QueryClient; a new actor
  // replaces this identity. No reasons, auth tokens or credentials are retained.
  client.setQueryDefaults(ledgerKey, { gcTime: Infinity });
  client.setQueryData(ledgerKey, created);
  // Structural sharing may replace the top-level object; use cache identity.
  return client.getQueryData<AdmissionLedger>(ledgerKey)!;
}

function PolicyControl({ policy, scope, busy, operation, submit }: { policy: SigmaRulePolicy; scope: SigmaRuleScope;
  busy: boolean; operation?: AdmissionOperation; submit: SubmitAdmission }) {
  const [reason, setReason] = useState("");
  const ready = policy.admitted || ["shadow", "enabled"].includes(policy.lifecycle_status);
  const valid = reason.trim().length > 0 && reason.trim().length <= 2000;
  const id = `sigma-policy-${policy.policy_id}-${policy.policy_version}`;
  return <section>
    <FactList facts={[
      { label: t("security.sigma.list.policy_title"), value: policy.policy_title?.trim() || unknown() },
      { label: t("security.sigma.list.policy"), value: <code>{policy.policy_id} · {policy.policy_version}</code> },
      { label: t("security.sigma.list.lifecycle"), value: policy.lifecycle_status },
      { label: t("security.sigma.list.effective_mode"), value: policy.effective_mode ?? unknown() },
    ]}/>
    <details><summary>{t("security.sigma.list.pin")}</summary><pre>{JSON.stringify(policy.execution, null, 2)}</pre></details>
    <form onSubmit={(event) => {
      event.preventDefault();
      if (operation || busy || !ready || !valid) return;
      submit(policy, reason.trim(), scope);
      setReason("");
    }}>
      <div className="sli-ds-field"><label htmlFor={id}>{t("semanticControls.decisionReason")}</label>
        <input id={id} value={reason} maxLength={2000} required disabled={Boolean(operation) || busy}
          onChange={(event) => setReason(event.target.value)}/></div>
      <Button type="submit" disabled={!valid || !ready || Boolean(operation) || busy}>
        {t(policy.admitted ? "security.sigma.list.revoke" : "security.sigma.list.admit")}</Button>
      {!ready ? <p>{t("security.sigma.list.not_ready")}</p> : null}
      {operation?.phase === "uncertain" ? <StateView state="unavailable" compact detail={t("security.sigma.list.save_failed")}/> : null}
    </form>
  </section>;
}

function RuleDetails({ row, scope, busy, operations, submit }: { row: SigmaRuleListRow; scope: SigmaRuleScope;
  busy: boolean; operations: Map<string, AdmissionOperation>; submit: SubmitAdmission }) {
  return <details><summary>{t("security.sigma.details")}</summary>
    {row.metadata_state === "unavailable" ? <p>{t("security.sigma.list.metadata_unavailable")}</p> : null}
    <FactList facts={[
      { label: t("security.sigma.rule"), value: <code>{row.rule_id}</code> },
      { label: t("security.sigma.version.rule"), value: <code>{row.raw_sha256}</code> },
      { label: t("security.sigma.version.upstream"), value: <code>{row.upstream_commit}</code> },
      { label: t("security.sigma.list.scope"), value: <code>{JSON.stringify(scope)}</code> },
      { label: t("security.sigma.list.shadow"), value: row.runtime.shadow ?? unknown() },
      { label: t("security.sigma.list.test_inputs"), value: row.runtime.test ?? unknown() },
    ]}/>
    {row.executions.map((execution, index) => <ExecutionDetails key={index} row={{ rule: row, execution, state: execution.state }}/>) }
    {row.admission.state === "unavailable" ? <p>{t("security.sigma.list.owner_required")}</p>
      : row.admission.policies.map((policy) => <PolicyControl key={policyKey(policy)}
        policy={policy} scope={scope} busy={busy} operation={operations.get(policyKey(policy))} submit={submit}/>)}
  </details>;
}

/** Existing Sigma tab: metadata and TEST/live/admission are independent facts. */
export function SigmaRulesPanel() {
  const client = useQueryClient();
  const access = useEffectiveAccess();
  const actor = access ? JSON.stringify([access.subject.type, access.subject.id, access.subject.username]) : "unavailable";
  const ledger = useMemo(() => sessionLedger(client, actor), [client, actor]);
  useSyncExternalStore((listener) => { ledger.listeners.add(listener); return () => { ledger.listeners.delete(listener); }; }, () => ledger.revision);
  const live = () => client.getQueryData(ledgerKey) === ledger;
  const operations = { current: ledger.operations };
  const changed = () => { if (live()) { ledger.revision++; ledger.listeners.forEach((listener) => listener()); } };
  const [selected, setSelected] = useState("");
  const [technical, setTechnical] = useState(false);
  const sources = useQuery({ queryKey: ["sigma-sources", ledger.epoch], queryFn: () => api.sigmaRules(), retry: false, refetchOnWindowFocus: false });
  const visible = !sources.isError && sources.data?.state === "available" ? sources.data.sources : [];
  const scope = visible.find((item) => JSON.stringify(item) === selected);
  const query = useQuery({ queryKey: ["sigma-rules", ledger.epoch, scope], queryFn: () => api.sigmaRules(scope!),
    enabled: Boolean(scope), retry: false, refetchOnWindowFocus: false });
  const data = scope && !query.isError && query.data?.state === "available" ? query.data : undefined;
  const refreshScope = async (target: SigmaRuleScope) => {
    if (!live()) return;
    const eligible = [...operations.current].filter(([, operation]) => operation.phase !== "pending"
      && JSON.stringify(operation.scope) === JSON.stringify(target));
    for (const [key, operation] of eligible) operations.current.set(key, { ...operation, phase: "reconciling" });
    changed();
    try {
      const queryKey = ["sigma-rules", ledger.epoch, target];
      // Cancel/detach older GETs rather than deduplicating against a pre-write read.
      await client.cancelQueries({ queryKey, exact: true });
      if (!live()) return;
      const result = await client.fetchQuery({ queryKey, queryFn: () => api.sigmaRules(target), staleTime: 0, retry: false });
      if (!live()) return;
      if (result.state !== "available") throw new Error("sigma_read_unavailable");
      for (const [key, operation] of eligible) {
        if (operations.current.get(key)?.token === operation.token) operations.current.delete(key);
      }
    } catch {
      if (!live()) return;
      for (const [key, operation] of eligible) {
        if (operations.current.get(key)?.token === operation.token) operations.current.set(key, { ...operation, phase: "uncertain" });
      }
    }
    changed();
  };
  const submit: SubmitAdmission = (policy, reason, target) => {
    const key = policyKey(policy);
    if (!access || !live() || operations.current.has(key)) return;
    const operation: AdmissionOperation = { token: ++ledger.nextToken, scope: target, phase: "pending" };
    operations.current.set(key, operation); // Synchronous repeated-click guard.
    changed();
    void (async () => {
      try {
        await api.updateSemanticControl({ action: "policy_admission", policy_id: policy.policy_id,
          policy_version: policy.policy_version, enabled: !policy.admitted, reason });
        if (!live()) return;
        operations.current.set(key, { ...operation, phase: "reconciling" });
        changed();
        await refreshScope(target);
      } catch {
        if (!live()) return;
        operations.current.set(key, { ...operation, phase: "uncertain" });
        changed();
      }
    })();
  };
  const columns: TableColumn<SigmaRuleListRow>[] = [
    { key: "name", label: t("security.sigma.list.name"), render: (row) => <>
      <span>{row.title?.trim() || t("security.sigma.list.title_unknown")}</span>
      <p>{row.description?.trim() || t("security.sigma.list.purpose_unknown")}</p></> },
    { key: "admission", label: t("security.sigma.list.admission"), render: (row) => row.admission.state === "unavailable" ? unknown()
      : row.admission.policies.length ? row.admission.policies.map((policy) => <p key={`${policy.policy_id}:${policy.policy_version}`}>
        {t("security.sigma.list.version", { version: policy.policy_version })} · <Badge tone="neutral">
          {t(policy.admitted ? "security.sigma.list.admitted" : "security.sigma.list.not_admitted")}</Badge></p>)
        : t("security.sigma.list.unbound") },
    { key: "data", label: t("security.sigma.list.data"), render: (row) => row.executions.length ? row.executions.map((execution, index) =>
      <p key={index}>{sigmaStateLabel(execution.state)} · {t("security.sigma.count.scanned")}: {execution.counts.scanned}</p>) : unknown() },
    { key: "test", label: t("security.sigma.list.test"), render: (row) => row.executions.length ? row.executions.map((execution, index) =>
      <p key={index}>TEST · {execution.counts.matched}</p>) : unknown() },
    { key: "runtime", label: t("security.sigma.list.runtime"), render: (row) => row.runtime.enabled ?? unknown() },
    { key: "details", label: t("security.sigma.details"), render: (row) => <RuleDetails row={row} scope={scope!}
      busy={!access || query.isFetching || sources.isFetching} operations={operations.current} submit={submit}/> },
  ];
  const readError = sources.error || (scope && query.error);
  const unavailable = sources.data?.state === "unavailable" ? sources.data : scope && query.data?.state === "unavailable" ? query.data : null;
  return <Panel title={t("security.sigma.list.title")} subtitle={t("security.sigma.list.description")}>
    {sources.isPending ? <StateView state="loading"/> : null}
    {readError ? <StateView state={failure(readError)} detail={t("security.sigma.reason.unavailable")}
      onRetry={() => void (sources.isError ? sources.refetch() : refreshScope(scope!))}/> : null}
    {unavailable ? <StateView state="unavailable" detail={sigmaReasonLabel(unavailable.reason ?? "projection_unavailable")}
      onRetry={() => void (sources.data?.state === "unavailable" ? sources.refetch() : refreshScope(scope!))}/> : null}
    {visible.length ? <div className="sli-ds-field"><label htmlFor="sigma-list-source">{t("security.sigma.list.source")}</label>
      <select id="sigma-list-source" value={scope ? selected : ""} onChange={(event) => setSelected(event.target.value)}>
        <option value="">{t("security.sigma.list.choose")}</option>{visible.map((item, index) =>
          <option key={JSON.stringify(item)} value={JSON.stringify(item)}>{t("security.sigma.list.source_number", { number: index + 1 })}</option>)}
      </select></div> : null}
    {scope && query.isPending ? <StateView state="loading"/> : null}
    {data ? <>
      <p>{data.since && data.until ? `${t("security.sigma.list.interval")}: ${data.since} — ${data.until}` : t("security.sigma.list.no_interval")}</p>
      <p>{t("security.sigma.list.evidence_boundary")}</p>
      <Button disabled={query.isFetching} onClick={() => void refreshScope(scope!)}>{t("security.sigma.list.refresh")}</Button>
      {query.isFetching ? <StateView state="stale" compact/> : null}
      {data.rules.length ? <DataTable columns={columns} rows={data.rules} rowKey={(row) => JSON.stringify([row.rule_id, row.raw_sha256])}
        caption={t("security.sigma.list.title")}/> : <StateView state="empty" detail={t("security.sigma.no_rules")}/>}
    </> : null}
    <details onToggle={(event) => setTechnical(event.currentTarget.open)}><summary>{t("security.sigma.list.technical")}</summary>
      {technical ? <SigmaValidationPanel/> : null}</details>
  </Panel>;
}
