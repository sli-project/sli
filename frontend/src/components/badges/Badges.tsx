import type { ReactNode } from "react";
import { SeverityBadge, type Tone } from "../../design-system";
import { t } from "../../i18n";

type KnownTone = "critical" | "high" | "medium" | "low" | "unknown";
type OperationalTone = "ok" | "running" | "warning" | "failed" | "unknown";

const normalized = (value: unknown) => String(value ?? "").trim().toLowerCase();

export function riskTone(value: unknown): KnownTone {
  const risk = normalized(value);
  if (["critical", "критический", "критичная"].includes(risk)) return "critical";
  if (["high", "высокий", "high_risk"].includes(risk)) return "high";
  if (["medium", "средний", "moderate"].includes(risk)) return "medium";
  if (["low", "низкий", "informational", "information", "info"].includes(risk)) return "low";
  return "unknown";
}

export function confidenceTone(value: unknown): Exclude<KnownTone, "critical"> {
  const confidence = normalized(value);
  if (["high", "высокая", "высокий"].includes(confidence)) return "high";
  if (["medium", "средняя", "средний"].includes(confidence)) return "medium";
  if (["low", "низкая", "низкий"].includes(confidence)) return "low";
  return "unknown";
}

export function operationalTone(value: unknown): OperationalTone {
  const status = normalized(value);
  if (["ok", "completed", "ready", "healthy", "success"].includes(status)) return "ok";
  if (["running", "active", "in_progress"].includes(status)) return "running";
  if (["warn", "warning", "stale", "partial", "degraded", "blocked"].includes(status)) return "warning";
  if (["failed", "error", "critical", "unavailable"].includes(status)) return "failed";
  return "unknown";
}

const CONFIDENCE_TONE: Record<KnownTone, Tone> = { critical: "neutral", high: "success", medium: "warning", low: "neutral", unknown: "neutral" };
const OPERATIONAL_TONE: Record<OperationalTone, Tone> = { ok: "success", running: "accent", warning: "warning", failed: "danger", unknown: "neutral" };

function Badge({ tone, children, label }: { tone: Tone; children: ReactNode; label?: string }) {
  return <span className="sli-ds-badge" data-tone={tone === "neutral" ? undefined : tone} aria-label={label}>{children}</span>;
}

export function RiskBadge({ value }: { value: unknown }) {
  const severity = riskTone(value);
  return <SeverityBadge severity={severity} label={severity === "unknown" ? undefined : t("events.badges.riskPrefix", { value: t(`shell.severity.${severity}`) })}/>;
}

export function ConfidenceBadge({ value }: { value: unknown }) {
  const val = String(value ?? t("events.badges.unknownFeminine"));
  const text = t("events.badges.confidencePrefix", { value: val });
  return <Badge tone={CONFIDENCE_TONE[confidenceTone(value)]} label={text}>{text}</Badge>;
}

type EventClassificationOrigin = "catalog_base" | "contextual_rule" | "unavailable" | undefined;
type EventCardCompleteness = "complete" | "partial" | "not_applicable" | undefined;

export function eventClassificationLabel(value: unknown): string {
  const classification = normalized(value);
  if (["critical", "критический", "критичная"].includes(classification)) return t("events.badges.classCritical");
  if (["high", "высокий"].includes(classification)) return t("events.badges.classHigh");
  if (["medium", "средний", "moderate"].includes(classification)) return t("events.badges.classMedium");
  if (["low", "низкий"].includes(classification)) return t("events.badges.classLow");
  if (["info", "informational", "information"].includes(classification)) return t("events.badges.classInfo");
  return t("events.badges.classUnknown");
}

export function EventClassificationBadge({ value, origin }: { value: unknown; origin?: EventClassificationOrigin }) {
  const prefix = origin === "contextual_rule"
    ? t("events.badges.classContextual")
    : origin === "catalog_base"
      ? t("events.badges.classCatalog")
      : t("events.badges.classEvent");
  const classification = eventClassificationLabel(value);
  const label = t("events.badges.classificationLabel", { prefix, classification });
  return <SeverityBadge severity={riskTone(value)} label={label}/>;
}

export function EventCardCompletenessBadge({ completeness }: { completeness?: EventCardCompleteness }) {
  if (completeness !== "complete" && completeness !== "partial") return null;
  const label = completeness === "complete" ? t("events.badges.completenessComplete") : t("events.badges.completenessPartial");
  const text = t("events.badges.completenessPrefix", { value: label });
  return <Badge tone={completeness === "complete" ? "success" : "warning"} label={text}>{text}</Badge>;
}

export function WindowsLevelBadge({ value }: { value: unknown }) {
  const val = String(value ?? t("events.badges.unknown"));
  return <Badge tone="accent" label={t("events.badges.windowsLevelPrefix", { value: val })}>{t("events.badges.windowsPrefix", { value: val })}</Badge>;
}

export function OperationalStatusBadge({ value, children }: { value: unknown; children?: ReactNode }) {
  return <Badge tone={OPERATIONAL_TONE[operationalTone(value)]}>{children ?? String(value ?? t("events.status.unknown"))}</Badge>;
}
