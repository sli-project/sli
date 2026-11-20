import { useDateFormatters } from "../../design-system/useDateFormatters";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type SemanticControlChange } from "../../api/client";
import { StateView } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { FieldError } from "./gate";

const buckets: Record<string, MessageKey> = {
  machine_account: "semanticControls.bucket.machine_account",
  system_account: "semanticControls.bucket.system_account",
  known_gpo_refresh: "semanticControls.bucket.known_gpo_refresh",
  interactive_admin: "semanticControls.bucket.interactive_admin",
  unknown: "semanticControls.bucket.unknown",
};
const states: Record<string, MessageKey> = {
  active: "semanticControls.state.active", expired: "semanticControls.state.expired", revoked: "semanticControls.state.revoked",
};

// Only the exact bundled version/title is translated; custom metadata remains literal.
const builtinPolicyTitles = [
  { id: "l1-eventlog-cleared", version: 2, title: "Security event log was cleared", message: "security.problems.presentation.eventlog_cleared_title" },
  { id: "l1-audit-policy-changed", version: 2, title: "Audit policy was changed", message: "security.problems.presentation.audit_title" },
  { id: "l1-privileged-group-member-added", version: 2, title: "Member was added to a privileged group", message: "security.problems.presentation.privileged_group_title" },
  { id: "l1-scheduled-task-created", version: 2, title: "Scheduled task was registered", message: "security.problems.presentation.scheduled_task_title" },
] as const;

// Default QW IDs contain a source-specific digest. Translate only exact
// producer rule/title pairs, preserving custom policy metadata verbatim.
const defaultPolicyTitles = [
  { rule: "account-decoy", title: "Registered decoy account used", name: "account_decoy" },
  { rule: "file-decoy", title: "Registered decoy file touched", name: "file_decoy" },
  { rule: "file-ransom", title: "Suspected ransomware: mass file changes", name: "file_ransom" },
  { rule: "file-acl-broad-write", title: "Write permissions granted to a broad group", name: "file_acl" },
  { rule: "disabled-account-logon", title: "Sign-in attempted with a disabled account", name: "disabled_logon" },
  { rule: "password-spray", title: "Passwords tried across several accounts", name: "password_spray" },
  { rule: "password-brute-force", title: "Repeated password attempts against one account", name: "password_brute" },
] as const;

function policyTitle(policy: { policy_id: string; policy_version: number; title?: string | null }): string {
  const builtin = builtinPolicyTitles.find((item) => item.id === policy.policy_id
    && item.version === policy.policy_version && item.title === policy.title);
  if (builtin) return t(builtin.message);
  const rule = /^default:qw\.([a-z-]+):[a-f0-9]{32}$/.exec(policy.policy_id)?.[1];
  const bundled = defaultPolicyTitles.find((item) => item.rule === rule && item.title === policy.title);
  return bundled ? t(`reports.v2.security.rule-quality.names.${bundled.name}`)
    : policy.title?.trim() || t("semanticControls.policyTitleUnknown");
}

/** Сервер повторно проверяет владельца платформы для чтения и каждого изменения. */
export function SemanticControlsPanel() {
  const { formatDateTime } = useDateFormatters();
  const client = useQueryClient();
  const controls = useQuery({ queryKey: ["semantic-controls"], queryFn: api.semanticControls });
  const [semanticType, setSemanticType] = useState("");
  const [domain, setDomain] = useState("");
  const [scopeKind, setScopeKind] = useState<"subject_sid" | "bucket">("subject_sid");
  const [scope, setScope] = useState("");
  const [reason, setReason] = useState("");
  const [decisionReason, setDecisionReason] = useState("");
  const [expiry, setExpiry] = useState("");
  const save = useMutation({
    mutationFn: (change: SemanticControlChange) => api.updateSemanticControl(change),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["semantic-controls"] });
      void client.invalidateQueries({ queryKey: ["report-v2"] });
    },
  });
  const expires = new Date(expiry).getTime();
  const validDecisionReason = Boolean(decisionReason.trim()) && decisionReason.trim().length <= 2000;
  const valid = /^[a-z][a-z0-9_.-]{1,159}$/.test(semanticType.trim())
    && /^[1-9]\d*$/.test(domain) && Number.isSafeInteger(Number(domain))
    && Boolean(reason.trim()) && reason.trim().length <= 2000
    && (scopeKind === "bucket" ? scope in buckets : /^S-1-(?:\d+-)+\d+$/.test(scope.trim()) && scope.trim().length <= 184)
    && expires > Date.now() && expires <= Date.now() + 90 * 86400000;

  return <div className="sli-ds-filters">
    <h2 className="sli-ds-section-title">{t("semanticControls.title")}</h2>
    <p className="sli-ds-header__subtitle">{t("semanticControls.description")}</p>
    {controls.isLoading ? <StateView state="loading"/> : controls.error ? <StateView state="unavailable" compact detail={controls.error.message} onRetry={() => void controls.refetch()}/> : null}
    {controls.data ? <>
      <h3>{t("semanticControls.policies")}</h3>
      <div className="sli-ds-field"><label htmlFor="semantic-decision-reason">{t("semanticControls.decisionReason")}</label><input id="semantic-decision-reason" required maxLength={2000} value={decisionReason} onChange={(event) => setDecisionReason(event.target.value)}/></div>
      {controls.data.policies.map((policy) => {
        const registeredAt = policy.version_created_at?.trim();
        const versionDate = registeredAt && Number.isFinite(Date.parse(registeredAt))
          ? t("semanticControls.versionRegistered", { date: formatDateTime(registeredAt) })
          : t("semanticControls.versionDateUnknown");
        return <div className="sli-ds-field" key={`${policy.policy_id}:${policy.policy_version}`}>
          <label>
            <input type="checkbox" checked={Boolean(policy.enabled)} disabled={save.isPending || !validDecisionReason || !["shadow", "enabled"].includes(policy.lifecycle_status)}
              onChange={(event) => save.mutate({ action: "policy_admission", policy_id: policy.policy_id, policy_version: policy.policy_version, enabled: event.target.checked, reason: decisionReason.trim() })}/>
            {policyTitle(policy)} · {versionDate}
          </label>
          <details><summary>{t("semanticControls.policyDetails")}</summary><p>{policy.policy_id} · {policy.policy_version}</p></details>
        </div>;
      })}
      <form onSubmit={(event) => {
        event.preventDefault();
        if (valid && !save.isPending) save.mutate({ action: "create_suppression", semantic_type: semanticType.trim(), domain_id: Number(domain), scope_kind: scopeKind,
          scope_value: scope.trim(), reason: reason.trim(), expires_at: new Date(expiry).toISOString() });
      }}>
        <h3>{t("semanticControls.suppressions")}</h3>
        <div className="sli-ds-field"><label htmlFor="semantic-type">{t("semanticControls.type")}</label><input id="semantic-type" required value={semanticType} onChange={(event) => setSemanticType(event.target.value)}/></div>
        <div className="sli-ds-field"><label htmlFor="semantic-domain">{t("semanticControls.domain")}</label><input id="semantic-domain" required type="number" min="1" step="1" value={domain} onChange={(event) => setDomain(event.target.value)}/></div>
        <div className="sli-ds-field"><label htmlFor="semantic-scope-kind">{t("semanticControls.scope")}</label>
          <select id="semantic-scope-kind" value={scopeKind} onChange={(event) => { setScopeKind(event.target.value as typeof scopeKind); setScope(""); }}>
            <option value="subject_sid">{t("semanticControls.sid")}</option><option value="bucket">{t("semanticControls.bucket")}</option>
          </select></div>
        <div className="sli-ds-field"><label htmlFor="semantic-scope">{t(scopeKind === "subject_sid" ? "semanticControls.sid" : "semanticControls.bucket")}</label>
          {scopeKind === "subject_sid" ? <input id="semantic-scope" required value={scope} onChange={(event) => setScope(event.target.value)}/> : <select id="semantic-scope" required value={scope} onChange={(event) => setScope(event.target.value)}>
            <option value="">{t("semanticControls.choose")}</option>{Object.entries(buckets).map(([value, key]) => <option key={value} value={value}>{t(key)}</option>)}
          </select>}</div>
        <div className="sli-ds-field"><label htmlFor="semantic-reason">{t("semanticControls.reason")}</label><input id="semantic-reason" required maxLength={2000} value={reason} onChange={(event) => setReason(event.target.value)}/></div>
        <div className="sli-ds-field"><label htmlFor="semantic-expiry">{t("semanticControls.expiry")}</label><input id="semantic-expiry" required type="datetime-local" value={expiry} onChange={(event) => setExpiry(event.target.value)}/></div>
        <button className="sli-ds-button" type="submit" disabled={!valid || save.isPending}>{t("semanticControls.create")}</button>
      </form>
      {controls.data.suppressions.map((rule) => <div className="sli-ds-field" key={rule.id}>
        <p>{rule.semantic_type} · {rule.domain_id} · {rule.scope_kind === "bucket" && buckets[rule.scope_value] ? t(buckets[rule.scope_value]) : rule.scope_value}</p>
        <p>{rule.reason} · {formatDateTime(rule.expires_at)} · {rule.created_by} · {t(states[rule.state] ?? "semanticControls.bucket.unknown")}</p>
        {rule.state === "active" ? <button type="button" className="sli-ds-button" disabled={save.isPending || !validDecisionReason} onClick={() => save.mutate({ action: "revoke_suppression", id: rule.id, reason: decisionReason.trim() })}>{t("semanticControls.revoke")}</button> : null}
      </div>)}
      <p className="sli-ds-header__subtitle">{t("semanticControls.limits")}</p>
    </> : null}
    <FieldError error={save.error}/>
    {save.isSuccess ? <p role="status">{t("platformSettings.saved")}</p> : null}
  </div>;
}
