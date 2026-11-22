import { t } from "../i18n";
import { EMPTY_VALUE } from "../shared/format";

const SHAPES = {
  critical: "■",
  high: "◆",
  medium: "▲",
  low: "●",
} as const;

export type Severity = keyof typeof SHAPES;

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && Object.hasOwn(SHAPES, value);
}

export function SeverityBadge({ severity, label }: { severity: unknown; label?: string }) {
  if (!isSeverity(severity)) return <>{label ?? EMPTY_VALUE}</>;
  return <span className="sli-ds-severity" data-severity={severity}>
    <span className="sli-ds-severity__shape" aria-hidden="true">{SHAPES[severity]}</span>
    {label ?? t(`shell.severity.${severity}`)}
  </span>;
}
