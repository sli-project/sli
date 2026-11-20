import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError, type FindingRiskAcceptance, type FindingRiskAudit, type FindingRiskRequest } from "../api/client";
import { Badge, useOverlays } from "../design-system";
import { t, type MessageKey } from "../i18n";
import { useEffectiveAccess } from "./App";
import { ProblemCaseActions } from "./problem-case-actions";

type Row = Record<string, unknown>;
type FormatTime = (value: string | null | undefined) => string;
const REPORT_KEY = ["report-v2", "data"];

function useRiskState(risk: FindingRiskAcceptance | null | undefined) {
  const client = useQueryClient();
  const [tick, setTick] = useState(0);
  const expires = Date.parse(risk?.expires_at ?? "");
  useEffect(() => {
    if (risk?.state !== "active" || !Number.isFinite(expires)) return;
    const delay = expires - Date.now();
    if (delay <= 0) return;
    const timer = window.setTimeout(() => {
      setTick((value) => value + 1);
      if (Date.now() >= expires) void client.invalidateQueries({ queryKey: REPORT_KEY });
    }, Math.min(delay + 1, 2147483647));
    return () => window.clearTimeout(timer);
  }, [risk?.state, expires, tick, client]);
  return risk?.state === "active" && expires <= Date.now() ? "expired" : risk?.state;
}

export function RiskBadge({ row, formatTime }: { row: Row; formatTime: FormatTime }) {
  const risk = row.risk_acceptance as FindingRiskAcceptance | null | undefined;
  const state = useRiskState(risk);
  if (!risk) return null;
  return <Badge tone={state === "expired" ? "warning" : "neutral"}>
    {t(`reports.risk.${state}` as MessageKey)} · {formatTime(risk.expires_at)}
  </Badge>;
}

function errorText(error: unknown) {
  if (error instanceof ApiResponseError) {
    const key = `reports.risk.err.${error.code}` as MessageKey;
    const text = t(key);
    if (text !== key) return text;
  }
  return t("reports.risk.err.generic");
}

/** Export only the already-authorized finding shown in the detail. */
export function exportFinding(row: Row) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(row, null, 2)], { type: "application/json" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `finding-${Number(row.id)}.json`;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function RiskAcceptanceDialog({ row, onChanged }: { row: Row; onChanged: (risk: FindingRiskAcceptance, audit: FindingRiskAudit[]) => void }) {
  const access = useEffectiveAccess();
  const client = useQueryClient();
  const { closeModal } = useOverlays();
  const canManage = Boolean(access?.capabilities.includes("investigations.manage"));
  const [reason, setReason] = useState("");
  const [responsible, setResponsible] = useState("");
  const [expiry, setExpiry] = useState("");
  const [validation, setValidation] = useState(false);
  const users = useQuery({ queryKey: ["findings", "risk-responsibles"], queryFn: api.riskResponsibles, enabled: canManage, retry: false });
  const save = useMutation({
    mutationFn: (body: FindingRiskRequest) => canManage ? api.changeFindingRisk(Number(row.id), body) : Promise.reject(new Error("denied")),
    onSuccess: async (result) => {
      onChanged({ ...result.acceptance, responsible_username: users.data?.items.find((user) => user.id === result.acceptance.responsible_user_id)?.username }, result.risk_audit);
      closeModal();
      await client.invalidateQueries({ queryKey: REPORT_KEY });
    },
  });
  const submit = () => {
    const date = new Date(expiry);
    const now = Date.now();
    if (!reason.trim() || reason.trim().length > 2000 || !users.data?.items.some((user) => user.id === Number(responsible))
      || !Number.isFinite(date.getTime()) || date.getTime() <= now || date.getTime() > now + 90 * 86400000) {
      setValidation(true);
      return;
    }
    setValidation(false);
    save.mutate({ action: "create", reason: reason.trim(), responsible_user_id: Number(responsible), expires_at: date.toISOString() });
  };
  return <div className="sli-ds-report__views">
    <p>{t("reports.risk.limit")}</p>
    <div className="sli-ds-field"><label htmlFor="risk-reason">{t("reports.risk.reason")}</label>
      <textarea id="risk-reason" required maxLength={2000} value={reason} onChange={(event) => setReason(event.target.value)}/></div>
    <div className="sli-ds-field"><label htmlFor="risk-responsible">{t("reports.risk.responsible")}</label>
      <select id="risk-responsible" required value={responsible} disabled={users.isPending || Boolean(users.error)} onChange={(event) => setResponsible(event.target.value)}>
        <option value="">{t("reports.risk.chooseUser")}</option>
        {users.data?.items.map((user) => <option key={user.id} value={user.id}>{user.username}</option>)}
      </select></div>
    {users.error ? <p role="alert">{t("reports.risk.usersFailed")}</p> : null}
    <div className="sli-ds-field"><label htmlFor="risk-expiry">{t("reports.risk.expiry")}</label>
      <input id="risk-expiry" type="datetime-local" required value={expiry} onChange={(event) => setExpiry(event.target.value)}/></div>
    <p className="sli-ds-header__subtitle">{t("reports.risk.expiryHint")}</p>
    {validation || save.error ? <p role="alert">{validation ? t("reports.risk.validation") : errorText(save.error)}</p> : null}
    <div className="sli-ds-filters__actions">
      <button type="submit" className="sli-ds-button" data-variant="primary" disabled={!canManage || save.isPending || !users.data || Boolean(users.error)} onClick={(event) => { event.preventDefault(); submit(); }}>
        {save.isPending ? t("reports.risk.saving") : t("reports.risk.accept")}</button>
      <button type="button" className="sli-ds-button" onClick={closeModal}>{t("reports.risk.cancel")}</button>
      <button type="button" className="sli-ds-button" onClick={() => exportFinding(row)}>{t("reports.risk.export")}</button>
    </div>
    <ProblemCaseActions row={row} onOpen={closeModal}/>
  </div>;
}

/** Risk is an expiring analyst decision, separate from the finding's lifecycle. */
export function ProblemRiskAcceptance({ row, formatTime }: { row: Row; formatTime: FormatTime }) {
  const access = useEffectiveAccess();
  const client = useQueryClient();
  const { openModal } = useOverlays();
  const [changedRisk, setChangedRisk] = useState<FindingRiskAcceptance>();
  const [changedAudit, setChangedAudit] = useState<FindingRiskAudit[]>();
  const [olderAudit, setOlderAudit] = useState<FindingRiskAudit[]>([]);
  const [hasMoreAudit, setHasMoreAudit] = useState<boolean>();
  useEffect(() => { setChangedRisk(undefined); setChangedAudit(undefined); setOlderAudit([]); setHasMoreAudit(undefined); }, [row.id, row.risk_acceptance, row.risk_audit]);
  const risk = changedRisk ?? row.risk_acceptance as FindingRiskAcceptance | null | undefined;
  const state = useRiskState(risk);
  const canManage = Boolean(access?.capabilities.includes("investigations.manage"));
  const audit = [...(changedAudit ?? (row.risk_audit ?? []) as FindingRiskAudit[]), ...olderAudit];
  const onChanged = (next: FindingRiskAcceptance, history: FindingRiskAudit[]) => {
    setChangedRisk(next); setChangedAudit(history); setOlderAudit([]); setHasMoreAudit(undefined);
  };
  const moreAudit = useMutation({
    mutationFn: () => api.findingRiskAudit(Number(row.id), audit[audit.length - 1].id),
    onSuccess: (result) => { setOlderAudit((items) => [...items, ...result.items]); setHasMoreAudit(result.has_more); },
  });
  const revoke = useMutation({
    mutationFn: () => canManage && risk ? api.changeFindingRisk(Number(row.id), { action: "revoke", id: risk.id }) : Promise.reject(new Error("denied")),
    onSuccess: async (result) => { onChanged({ ...result.acceptance, responsible_username: risk?.responsible_username }, result.risk_audit); await client.invalidateQueries({ queryKey: REPORT_KEY }); },
  });
  return <section aria-label={t("reports.risk.heading")} className="sli-ds-report__views">
    <h3 style={{ margin: 0 }}>{t("reports.risk.heading")}</h3>
    <RiskBadge row={{ ...row, risk_acceptance: risk }} formatTime={formatTime}/>
    {risk ? <p>{risk.reason} · {t("reports.risk.responsible")}: {risk.responsible_username ?? risk.responsible_user_id} · {t("reports.risk.author")}: {risk.created_by} · {formatTime(risk.created_at)}</p> : null}
    {canManage ? state === "active"
      ? <button type="button" className="sli-ds-button" disabled={revoke.isPending} onClick={() => revoke.mutate()}>{t("reports.risk.revoke")}</button>
      : <button type="button" className="sli-ds-button" onClick={() => openModal({ title: t("reports.risk.accept"), onSubmit: (event) => event.preventDefault(),
        body: <RiskAcceptanceDialog row={{ ...row, risk_acceptance: risk, risk_audit: audit }} onChanged={onChanged}/> })}>{t("reports.risk.accept")}</button> : null}
    {revoke.error ? <p role="alert">{errorText(revoke.error)}</p> : null}
    {audit.length ? <details><summary>{t("reports.risk.audit")}</summary><ul>{audit.map((entry) => <li key={entry.id}>
      {formatTime(entry.occurred_at)} · {t(`reports.risk.audit.${entry.action}` as MessageKey)} · {entry.actor} · {entry.details.rule.reason}
      {` · ${t("reports.risk.responsible")}: ${entry.details.rule.responsible_user_id} · ${formatTime(entry.details.rule.expires_at)}`}
    </li>)}</ul>
      {(hasMoreAudit ?? audit.length === 50) ? <button type="button" className="sli-ds-button" disabled={moreAudit.isPending} onClick={() => moreAudit.mutate()}>{t("reports.risk.moreAudit")}</button> : null}
      {moreAudit.error ? <p role="alert">{t("reports.risk.auditFailed")}</p> : null}
    </details> : null}
  </section>;
}
