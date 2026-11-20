import { formatNumber } from "../shared/format";
import { useState, type ReactNode } from "react";
import { t } from "../i18n";
import { Badge, type Tone } from "./Primitives";

export type ReviewItem = {
  key: string;
  title: string;
  severity: string;
  tone: Tone;
  objects?: ReactNode;
  status: string;
  newCount: number | null;
  total: number | null;
  detail: ReactNode;
};

/** A compact, expandable list of checks; counts always retain unknown values. */
export function ReviewList({ items, compact = false, summaryOnly = false }: { items: ReviewItem[]; compact?: boolean; summaryOnly?: boolean }) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const count = (value: number | null) => value === null ? t(compact ? "table.noValue" : "reports.ad.checks.status.not_evaluated") : formatNumber(value);
  return <div className="sli-ds-review-list" data-compact={compact || undefined}>
    <div className="sli-ds-review-list__heading" aria-hidden="true">
      <span>{t("reports.ad.checks.column.severity")}</span><span>{t("reports.ad.checks.column.title")}</span>
      <span>{t("reports.ad.checks.column.status_text")}</span><span>{t("reports.ad.checks.column.new_count")}</span><span>{t("reports.ad.checks.column.total")}</span>
    </div>
    {items.map((item) => <details key={item.key} className="sli-ds-review-list__item" onToggle={summaryOnly ? (event) => {
      const open = event.currentTarget.open;
      setExpanded((current) => ({ ...current, [item.key]: open }));
    } : undefined}>
      <summary className="sli-ds-review-list__summary">
        <span><Badge tone={item.tone}>{item.severity}</Badge></span>
        <span><strong>{item.title}</strong>{!compact && item.objects ? <span className="sli-ds-review-list__objects">{item.objects}</span> : null}</span>
        <span className="sli-ds-review-list__status">{item.status}</span>
        <span className="sli-ds-review-list__new" aria-label={t("reports.ad.checks.column.new_count")}>{count(item.newCount)}</span>
        <span className="sli-ds-review-list__total" aria-label={t("reports.ad.checks.column.total")}>{count(item.total)}
          {item.newCount !== null && item.newCount > 0 ? <span className="sli-ds-review-list__plus">+{item.newCount}</span> : null}
        </span>
        <span className="sli-ds-review-list__chevron" aria-hidden="true">›</span>
      </summary>
      <div className="sli-ds-review-list__body">{!summaryOnly || expanded[item.key] ? item.detail : null}</div>
    </details>)}
  </div>;
}
