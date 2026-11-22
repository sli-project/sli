import { createContext, useContext, useRef, useState, type ReactNode } from "react";
import { t } from "../i18n";
import { dayKey, formatClockWithOffset, formatDateTime as formatDateRange, isValidTimeZone } from "../shared/date-time";
import { useTimeZone } from "../shared/time-zone";
import { formatDateTime } from "./format";
import { Icon } from "./Icon";
import { PeriodPicker, periodLabel, previousPeriod, type PeriodPreset, type PeriodValue } from "./PeriodPicker";
import { Button } from "./Primitives";

export type Crumb = { label: string; href?: string };

export type PageHeaderControls = {
  period?: {
    value?: PeriodValue;
    presets?: PeriodPreset[];
    bounds?: { from: string; to: string };
    showBounds?: boolean;
    showPrevious?: boolean;
    onChange: (value: PeriodValue) => void;
    onClear?: () => void;
  };
  updatedAt?: string | number | null;
  refreshing?: boolean;
  onRefresh?: () => void;
};

export const PageHeaderContext = createContext<{ domain?: (id?: string) => ReactNode; controls?: PageHeaderControls }>({});

function HeaderPeriod({ value, presets, bounds, showBounds, showPrevious = true, onChange, onClear }: NonNullable<PageHeaderControls["period"]>) {
  const picker = useRef<HTMLDetailsElement>(null);
  const [draft, setDraft] = useState<PeriodValue>();
  const { timeZone } = useTimeZone();
  const activeCustom = value?.preset === "custom" ? value : undefined;
  const inputValue = activeCustom?.from?.includes("T") && activeCustom.to && (timeZone === "browser" || isValidTimeZone(timeZone))
    ? { preset: "custom" as const, from: dayKey(activeCustom.from, timeZone) ?? undefined, to: dayKey(new Date(Date.parse(activeCustom.to) - 1), timeZone) ?? undefined }
    : value;
  const previous = value && (presets?.includes("custom") ?? true) ? previousPeriod(value, bounds) : null;
  const close = () => {
    if (!picker.current?.open) return;
    picker.current.open = false;
    picker.current.querySelector("summary")?.focus();
  };
  return <>
    <details className="sli-ds-header__period" ref={picker} onToggle={(event) => {
      if (!event.currentTarget.open) setDraft(undefined);
    }} onKeyDown={(event) => {
      if (event.key === "Escape" && event.currentTarget.open) { event.stopPropagation(); close(); }
    }}>
      <summary className="sli-ds-button">
        <Icon name="calendar"/><span>{value ? periodLabel(value.preset) : t("shell.header.allTime")}</span><Icon name="chevron-down"/>
      </summary>
      <div className="sli-ds-header__period-menu">
        {onClear ? <Button onClick={() => { onClear(); close(); }}>{t("shell.header.allTime")}</Button> : null}
        <PeriodPicker value={draft ?? inputValue} presets={presets} onChange={(next) => {
          if (next.preset !== "custom") { onChange(next); close(); return; }
          setDraft(next);
          if (next.from && next.to && next.from <= next.to && (next.from !== inputValue?.from || next.to !== inputValue?.to)) onChange(next);
        }}/>
      </div>
    </details>
    {showBounds && bounds ? <span className="sli-ds-header__updated">{formatDateRange(bounds.from, timeZone, { withYear: false })} → {formatDateRange(bounds.to, timeZone, { withYear: false })}</span> : null}
    {showPrevious && (presets?.includes("custom") ?? true) ? <Button icon="chevron-left" disabled={!previous} onClick={() => { if (previous) onChange(previous); }}>
      {t("shell.header.previousPeriod")}
    </Button> : null}
  </>;
}

function UpdatedTime({ value }: { value: string | number }) {
  const { timeZone } = useTimeZone();
  const instant = new Date(value);
  if (!Number.isFinite(instant.getTime()) || (timeZone !== "browser" && !isValidTimeZone(timeZone))) return null;
  const clock = formatClockWithOffset(instant, timeZone);
  return <time className="sli-ds-header__updated" dateTime={instant.toISOString()}>{t("shell.header.updated", { ...clock, date: formatDateTime(instant, false, timeZone) })}</time>;
}

export function PageHeader({ title, subtitle, crumbs, actions, meta, controls, domain, showDomain = true }: {
  title: string;
  subtitle?: ReactNode;
  crumbs?: Crumb[];
  actions?: ReactNode;
  /** Scope/coverage line under the title (domain, observed time). */
  meta?: ReactNode;
  controls?: PageHeaderControls;
  domain?: string;
  showDomain?: boolean;
}) {
  const scope = useContext(PageHeaderContext);
  const { period, updatedAt, refreshing, onRefresh } = controls ?? scope.controls ?? {};
  const domainControl = showDomain ? scope.domain?.(domain) : null;
  return <header className="sli-ds-header">
    {crumbs?.length ? <nav className="sli-ds-crumbs" aria-label={t("reports.breadcrumbs_aria")}>
      <ol>{crumbs.map((crumb, index) => <li key={`${crumb.label}-${index}`}>{crumb.href && index < crumbs.length - 1 ? <a href={crumb.href}>{crumb.label}</a> : <span aria-current={index === crumbs.length - 1 ? "page" : undefined}>{crumb.label}</span>}</li>)}</ol>
    </nav> : null}
    <div className="sli-ds-header__row">
      <h1 className="sli-ds-header__title" data-page-heading tabIndex={-1}>{title}</h1>
      {domainControl}
      {period ? <HeaderPeriod {...period}/> : null}
      {updatedAt || onRefresh || actions ? <div className="sli-ds-header__actions">
        {updatedAt ? <UpdatedTime value={updatedAt}/> : null}
        {onRefresh ? <Button icon="refresh" aria-label={t("shell.header.refresh")} title={t("shell.header.refresh")} disabled={refreshing} onClick={onRefresh}/> : null}
        {actions}
      </div> : null}
    </div>
    {subtitle ? <p className="sli-ds-header__subtitle">{subtitle}</p> : null}
    {meta ? <div className="sli-ds-header__meta">{meta}</div> : null}
  </header>;
}
