import { t } from "../i18n";

export function statusLabel(value: unknown) {
  const status = String(value ?? "").toLowerCase();
  if (status === "locked") return t("events.status.locked");
  if (status === "unlocked") return t("events.status.unlocked");
  if (status === "open") return t("events.status.open");
  if (status === "under_review") return t("events.status.under_review");
  if (status === "resolved") return t("events.status.resolved");
  if (status === "dismissed") return t("events.status.dismissed");
  if (status === "enabled") return t("events.status.enabled");
  if (status === "disabled") return t("events.status.disabled");
  if (status === "observed") return t("events.status.observed");
  if (status === "conflict") return t("events.status.conflict");
  if (status === "unknown") return t("events.status.unknown");
  if (status === "ok" || status === "completed" || status === "ready") return t("events.status.ok");
  if (status === "running") return t("events.status.running");
  if (status === "idle") return t("events.status.idle");
  if (status === "partial") return t("events.status.partial");
  if (status === "bounded") return t("events.status.bounded");
  if (status === "skipped") return t("events.status.skipped");
  if (status === "not_registered") return t("events.status.not_registered");
  if (status === "not_observed") return t("events.status.not_observed");
  if (status === "active") return t("events.status.active");
  if (status === "stale") return t("events.status.stale");
  if (status === "warn" || status === "warning") return t("events.status.warning");
  if (status === "failed" || status === "critical" || status === "blocked") return t("events.status.failed");
  return value ? String(value) : t("events.status.unknown");
}

export function statusTone(value: unknown) {
  const status = String(value ?? "").toLowerCase();
  if (["warn", "warning", "stale", "partial", "blocked"].includes(status)) return "bad";
  if (["failed", "error", "critical", "unavailable"].includes(status)) return "bad";
  return ["ok", "completed", "ready", "running", "active", "healthy", "success"].includes(status) ? "good" : undefined;
}
