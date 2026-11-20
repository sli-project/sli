import type { ReactNode } from "react";
import { t } from "../i18n";
import { resolveMessage, type ApiMessage } from "../i18n/messages";
import { CardSkeleton, LoadingRegion, MetricStripSkeleton, TableSkeleton } from "./Skeleton";

/** Truthful result states (REPORTING_PRODUCT_CONTRACT): never rendered as a zero. */
export type ResultState = "ok" | "loading" | "empty" | "partial" | "stale" | "unavailable" | "denied" | "not_collected" | "processing" | "error";

const COPY: Record<Exclude<ResultState, "ok" | "loading">, { title: Parameters<typeof t>[0]; text: Parameters<typeof t>[0]; tone: string }> = {
  empty: { title: "state.empty.title", text: "state.empty.text", tone: "neutral" },
  partial: { title: "state.partial.title", text: "state.partial.text", tone: "warning" },
  stale: { title: "state.stale.title", text: "state.stale.text", tone: "warning" },
  unavailable: { title: "state.unavailable.title", text: "state.unavailable.text", tone: "danger" },
  denied: { title: "state.denied.title", text: "state.denied.text", tone: "danger" },
  not_collected: { title: "reports.states.not_collected.title", text: "reports.states.not_collected.text", tone: "warning" },
  processing: { title: "reports.states.processing.title", text: "reports.states.processing.text", tone: "warning" },
  error: { title: "reports.states.error.title", text: "reports.states.error.text", tone: "danger" },
};

export function StateView({ state, message, titleMessage, detail, actions, age, onRetry, compact = false, skeleton = "card" }: {
  state: ResultState;
  /** A coded title or context-specific meaning and recovery text. */
  message?: ApiMessage | ReactNode;
  /** A coded title supplied alongside context-specific message text. */
  titleMessage?: ApiMessage;
  /** Explanation; shown under the standard text. For "empty" it replaces the generic "change filters" line, which is wrong where no filters exist. */
  detail?: ReactNode;
  /** Context-specific recovery actions, supplied only when supported by evidence. */
  actions?: ReactNode;
  /** Human-readable age for the stale state. */
  age?: string;
  onRetry?: () => void;
  /** Inline banner above data (partial/stale) instead of a full block. */
  compact?: boolean;
  /** Shape of the loading placeholder: approximates the content that will replace it. */
  skeleton?: "card" | "table" | "metrics";
}) {
  if (state === "ok") return null;
  if (state === "loading") {
    return <LoadingRegion>{skeleton === "table" ? <TableSkeleton rows={compact ? 3 : 8}/> : skeleton === "metrics" ? <MetricStripSkeleton count={compact ? 3 : 4}/> : <CardSkeleton lines={compact ? 2 : 4}/>}</LoadingRegion>;
  }
  const copy = COPY[state];
  const codedMessage = message && typeof message === "object" && "code" in message ? message : undefined;
  const text = codedMessage ? undefined : message as ReactNode;
  const role = state === "unavailable" || state === "error" || state === "denied" ? "alert" : "status";
  return <div className={compact ? "sli-ds-state sli-ds-state--banner" : "sli-ds-state"} data-tone={copy.tone} data-state={state} role={role}>
    <div className="sli-ds-state__title">{resolveMessage(codedMessage ?? titleMessage, t(copy.title))}</div>
    {text ? <div className="sli-ds-state__text">{text}</div> : state === "empty" && detail ? null
      : <div className="sli-ds-state__text">{state === "stale" && !age ? t("state.stale.textUnknownAge") : t(copy.text, { age: age ?? "" })}</div>}
    {detail ? <div className="sli-ds-state__detail">{detail}</div> : null}
    {actions ? <div className="sli-ds-state__actions">{actions}</div> : null}
    {onRetry && (state === "unavailable" || state === "error") ? <button type="button" className="sli-ds-button" onClick={onRetry}>{t("state.retry")}</button> : null}
  </div>;
}
