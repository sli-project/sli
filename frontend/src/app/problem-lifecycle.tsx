import { useMutation, useQueryClient } from "@tanstack/react-query";
import type { FormEvent } from "react";

import { t, type MessageKey } from "../i18n";
import { api } from "../api/client";
import { useEffectiveAccess } from "./App";
import { useOverlays } from "../design-system";
import { ProblemCaseActions } from "./problem-case-actions";
import { ProblemRiskAcceptance } from "./problem-risk-acceptance";
import { ProblemNotification } from "./problem-notification";

type Row = Record<string, unknown>;
type HistoryEntry = { id: number; changed_at?: string | null; new_status?: string | null; changed_by?: string | null; note?: string | null };

const STATUS_LABELS: Record<string, MessageKey> = {
  new: "reports.problemLifecycle.new", active: "reports.problemLifecycle.active", review: "reports.problemLifecycle.review", confirmed: "reports.problemLifecycle.confirmed",
  false_positive: "reports.problemLifecycle.false_positive", closed: "reports.problemLifecycle.closed", repeated: "reports.problemLifecycle.repeated",
};

export function statusLabel(status: unknown): string {
  return t(STATUS_LABELS[String(status ?? "").toLowerCase()] ?? "reports.problemLifecycle.unknown");
}

function historyActor(value: unknown): string {
  if (value === "semantic-worker") return t("reports.problemLifecycle.semanticWorker");
  return value === "system" ? t("reports.problemLifecycle.system") : String(value ?? "").trim() || t("reports.problemLifecycle.system");
}

function historyNote(entry: HistoryEntry): string {
  if (entry.note === "risk_acceptance_expired") return t("reports.risk.expired");
  if (entry.note === "risk_acceptance_revoked") return t("reports.risk.revoked");
  if (entry.changed_by === "system" && entry.note === "created from event") return t("reports.problemLifecycle.createdFromEvent");
  if (entry.changed_by === "system" && entry.note === "repeat evidence added") return t("reports.problemLifecycle.repeatEvidence");
  return entry.changed_by === "semantic-worker" && entry.note === "created from enabled semantic scenario"
    ? t("reports.problemLifecycle.created") : String(entry.note ?? "").trim();
}

/** Status, owner and hand-off to an investigation for one problem (Detail.actions). */
export function ProblemLifecycle({ row, formatTime }: { row: Row; formatTime: (value: string | null | undefined) => string }) {
  const access = useEffectiveAccess();
  const client = useQueryClient();
  const { toast } = useOverlays();
  const id = Number(row.id);
  const status = String(row.status ?? "new");
  const statuses = Array.isArray(row.allowed_statuses) ? (row.allowed_statuses as string[]) : [status];
  const history = Array.isArray(row.status_history) ? (row.status_history as HistoryEntry[]) : [];
  const canManage = Boolean(access?.capabilities.includes("investigations.manage"));
  const refresh = () => client.invalidateQueries({ queryKey: ["report-v2", "data"] });

  const update = useMutation({
    mutationFn: (payload: { status: string; assigned_to?: string | null; note: string | null }) => api.updateFinding(id, payload),
    onSuccess: async () => { await refresh(); toast(t("reports.problemLifecycle.saved"), t("reports.problemLifecycle.savedDetail")); },
    onError: (error) => toast(t("reports.problemLifecycle.failed"), error.message),
  });

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const assignedTo = String(data.get("assigned_to") || "").trim();
    const reason = String(data.get("note") || "").trim();
    if (!reason) return;
    update.mutate({
      status: String(data.get("status") || status),
      ...(assignedTo !== String(row.assigned_to ?? "").trim() ? { assigned_to: assignedTo || null } : {}),
      note: reason,
    });
  };

  return <section aria-label={t("reports.problemLifecycle.aria")} className="sli-ds-report__views">
    <ProblemNotification findingId={id}/>
    <h3 style={{ margin: 0 }}>{t("reports.problemLifecycle.history")}</h3>
    {history.length
      ? <ul className="sli-ds-state__text">{history.map((entry) => <li key={entry.id}>{formatTime(entry.changed_at)} · {statusLabel(entry.new_status)} · {historyActor(entry.changed_by)}{historyNote(entry) ? ` · ${historyNote(entry)}` : ""}</li>)}</ul>
      : <p className="sli-ds-header__subtitle">{t("reports.problemLifecycle.noHistory")}</p>}
    <h3 style={{ margin: 0 }}>{t("reports.problemLifecycle.change")}</h3>
    {canManage ? <form className="sli-ds-filters" onSubmit={submit} key={`${id}:${status}`}>
      <div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor={`problem-status-${id}`}>{t("reports.problemLifecycle.status")}</label>
          <select id={`problem-status-${id}`} name="status" defaultValue={status}>{statuses.map((value) => <option key={value} value={value}>{statusLabel(value)}</option>)}</select></div>
        <div className="sli-ds-field"><label htmlFor={`problem-owner-${id}`}>{t("reports.problemLifecycle.owner")}</label>
          <input id={`problem-owner-${id}`} name="assigned_to" defaultValue={String(row.assigned_to ?? "")} placeholder={t("reports.problemLifecycle.ownerPlaceholder")}/></div>
        <div className="sli-ds-field"><label htmlFor={`problem-note-${id}`}>{t("reports.problemLifecycle.comment")}</label>
          <input id={`problem-note-${id}`} name="note" required maxLength={2000} placeholder={t("reports.problemLifecycle.commentPlaceholder")}/></div>
      </div>
      <div className="sli-ds-filters__actions">
        <button type="submit" className="sli-ds-button" data-variant="primary" disabled={update.isPending}>{update.isPending ? t("reports.problemLifecycle.saving") : t("reports.problemLifecycle.save")}</button>
      </div>
    </form> : <p className="sli-ds-header__subtitle">{t("reports.problemLifecycle.denied")}</p>}
    <ProblemRiskAcceptance row={row} formatTime={formatTime}/>
    <ProblemCaseActions row={row}/>
  </section>;
}
