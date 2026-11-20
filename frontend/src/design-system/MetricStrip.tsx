import { formatNumber } from "../shared/format";
import type { ReactNode } from "react";
import { t } from "../i18n";

export type MetricItem = {
  key: string;
  label: string;
  /** null means the value is unknown/unavailable, never zero. */
  value: number | string | null;
  /** Exact counted population; unknown measurements have no value link. */
  valueHref?: string;
  caption?: ReactNode;
  tone?: "neutral" | "accent" | "success" | "warning" | "danger";
  /** When set, the tile is a filter toggle. */
  onSelect?: () => void;
  active?: boolean;
};

export function MetricStrip({ items, label = t("reports.summaryAria"), compact = false }: { items: MetricItem[]; label?: string; compact?: boolean }) {
  if (!items.length) return null;
  return <section className="sli-ds-metrics" aria-label={label} data-compact={compact || undefined}>
    {items.map((item) => {
      const value = item.value === null ? t("table.noValue") : typeof item.value === "number" ? formatNumber(item.value) : item.value;
      const body = <>
        <span className="sli-ds-metric__label">{item.label}</span>
        <span className="sli-ds-metric__value" data-unknown={item.value === null || undefined}>{item.valueHref && item.value !== null && !item.onSelect
          ? <a href={item.valueHref} aria-label={`${item.label}: ${value}`}>{value}</a> : value}</span>
        {item.caption ? <span className="sli-ds-metric__caption">{item.caption}</span> : null}
      </>;
      return item.onSelect
        ? <button key={item.key} type="button" className="sli-ds-metric" data-tone={item.tone ?? "neutral"} aria-pressed={!!item.active} onClick={item.onSelect}>{body}</button>
        : <div key={item.key} className="sli-ds-metric" data-tone={item.tone ?? "neutral"}>{body}</div>;
    })}
  </section>;
}
