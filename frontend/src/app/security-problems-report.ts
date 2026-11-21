import { t } from "../i18n";
import { EMPTY_VALUE } from "../shared/format";
import { resolveMessage } from "../i18n/messages";
import type { SecurityProblemFinding } from "../api/client";

export function statusLabel(status: string | null | undefined): string {
  const map: Record<string, import("../i18n").MessageKey> = {
    new: "security.problems.status.new",
    active: "security.problems.status.active",
    review: "security.problems.status.review",
    confirmed: "security.problems.status.confirmed",
    false_positive: "security.problems.status.false_positive",
    closed: "security.problems.status.closed",
    repeated: "security.problems.status.repeated",
  };
  const key = map[String(status ?? "").toLowerCase()];
  return key ? t(key) : t("security.problems.status.unknown");
}

export function entityLabel(entity: { display_name?: string | null; entity_role?: string | null }): string {
  const value = String(entity.display_name ?? "").trim();
  const system = /^sid:([^:]+):S-1-5-18$/i.exec(value);
  if (system) return t("security.problems.entity.system", { name: system[1].toUpperCase() });
  if (entity.entity_role === "source_host" && /^\d+$/.test(value)) return t("security.problems.entity.source_host");
  return value || t("security.problems.entity.unknown");
}

export function entityRoleLabel(value: string | null | undefined): string {
  const roleMap: Record<string, import("../i18n").MessageKey> = {
    actor: "security.problems.role.actor",
    source_host: "security.problems.role.source_host",
  };
  const key = roleMap[String(value ?? "")];
  return key ? t(key) : t("security.problems.role.linked");
}

export function historyActorLabel(value: string | null | undefined): string {
  if (value === "semantic-worker") return t("security.problems.history.semantic_worker");
  return String(value ?? "").trim() || t("security.problems.history.system");
}

export function historyNoteLabel(value: string | null | undefined): string {
  if (value === "created from enabled semantic scenario") {
    return t("security.problems.history.semantic_scenario");
  }
  return String(value ?? "").trim();
}

function actorLabel(value: string | null | undefined): string {
  const actor = String(value ?? "").trim();
  const system = /^sid:([^:]+):S-1-5-18$/i.exec(actor);
  if (system) return t("security.problems.actor.system", { name: system[1].toUpperCase() });
  return actor || EMPTY_VALUE;
}

export function problemPresentation(finding: SecurityProblemFinding) {
  const auditPolicyChanged = finding.presentation_code === "audit_policy_changed" || finding.title === "Audit policy was changed";
  const text = (field: string, fallback: string) => resolveMessage(finding.presentation_messages?.[field], fallback);
  return {
    title: text("title_text", auditPolicyChanged ? t("security.problems.presentation.audit_title") : finding.title || t("security.problems.presentation.default_title", { id: finding.id })),
    whatHappened: text("what_happened", auditPolicyChanged
      ? t("security.problems.presentation.audit_what")
      : finding.summary || t("security.problems.presentation.default_what")),
    whyItMatters: text("why_text", auditPolicyChanged
      ? t("security.problems.presentation.audit_why")
      : finding.why_it_matters || t("security.problems.presentation.default_why")),
    nextAction: finding.presentation_messages?.next_text?.code === "security.problems.presentation.default_next" ? EMPTY_VALUE : text("next_text", auditPolicyChanged
      ? t("security.problems.presentation.audit_next")
      : finding.recommended_action?.trim() || EMPTY_VALUE).trim() || EMPTY_VALUE,
    actor: text("actor_text", actorLabel(finding.actor)),
  };
}

export function problemMetrics(summary: Array<{ severity: string; status: string; count: number }>) {
  const count = (statuses: Set<string>) => summary
    .filter((row) => statuses.has(row.status))
    .reduce((total, row) => total + Number(row.count || 0), 0);
  const total = summary.reduce((sum, row) => sum + Number(row.count || 0), 0);
  const attention = count(new Set(["new", "confirmed", "repeated"]));
  const inProgress = count(new Set(["active", "review"]));
  const closed = count(new Set(["false_positive", "closed"]));
  return { open: attention + inProgress, attention, inProgress, closed, total };
}
