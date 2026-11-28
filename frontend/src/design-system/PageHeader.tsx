import { createContext, useContext, useRef, useState, type ReactNode } from "react";
import { t } from "../i18n";
import { dayKey, formatClockWithOffset, formatDateTime as formatDateRange, isValidTimeZone, utcToLocalDateTimeInput } from "../shared/date-time";
import { useTimeZone } from "../shared/time-zone";
import { formatDateTime } from "./format";
import { PeriodPopover } from "./PeriodPopover";
import { PeriodPicker, isPeriodBoundary, periodLabel, previousPeriod, type PeriodPreset, type PeriodValue } from "./PeriodPicker";
import { Button } from "./Primitives";

export type Crumb = { label: string; href?: string };

export type PageHeaderControls = {
  period?: {
    value?: PeriodValue;
    presets?: PeriodPreset[];
    bounds?: { from: string; to: string };
    showBounds?: boolean;
    showPrevious?: boolean;
    precision?: "date" | "datetime-local";
    applyPresets?: boolean;
    showSelection?: boolean;
    strictRange?: boolean;
    onChange: (value: PeriodValue) => void;
    onClear?: () => void;
  };
  scope?: ReactNode;
  showBreadcrumbs?: boolean;
  updatedAt?: string | number | null;
  dataAsOf?: string | null;
  refreshing?: boolean;
  onRefresh?: () => void;
  showRefreshLabel?: boolean;
};

export const PageHeaderContext = createContext<{ domain?: (id?: string) => ReactNode; controls?: PageHeaderControls }>({});

function HeaderPeriod({ value, presets, bounds, showBounds, showPrevious = !showBounds, onChange, onClear,
  precision = "date", applyPresets = true, showSelection, strictRange }: NonNullable<PageHeaderControls["period"]>) {
  const picker = useRef<HTMLDetailsElement>(null);
  const [draft, setDraft] = useState<PeriodValue>();
  const { timeZone } = useTimeZone();
  const activeCustom = value?.preset === "custom" ? value : undefined;
  const toLocal = (end?: string, inclusiveEnd = false) => {
    if (!end) return end;
    if (precision === "datetime-local") {
      if (end.length === 10) return end + "T00:00";
      return /(?:Z|[+-]\d\d:\d\d)$/i.test(end) ? utcToLocalDateTimeInput(end, timeZone) : end;
    }
    if (!/(?:Z|[+-]\d\d:\d\d)$/i.test(end)) return end.slice(0, 10);
    return dayKey(new Date(Date.parse(end) - (inclusiveEnd ? 1 : 0)), timeZone) ?? undefined;
  };
  const inputValue = activeCustom && (timeZone === "browser" || isValidTimeZone(timeZone))
    ? { preset: "custom" as const, from: toLocal(activeCustom.from), to: toLocal(activeCustom.to, true) } : value;
  const previous = value && (presets?.includes("custom") ?? true) ? previousPeriod(value, bounds) : null;
  const valid = draft && (draft.preset !== "custom" ||
    isPeriodBoundary(draft.from, precision) && isPeriodBoundary(draft.to, precision) &&
    (strictRange ? draft.from < draft.to : draft.from <= draft.to));
  const close = () => {
    if (!picker.current?.open) return;
    setDraft(undefined);
    picker.current.open = false;
    picker.current.querySelector("summary")?.focus();
  };
  const selection = showSelection && inputValue?.preset === "custom" && inputValue.from && inputValue.to
    ? inputValue.from.replace("T", " ") + " – " + inputValue.to.replace("T", " ") : null;
  return <>
    <PeriodPopover label={selection ?? (value ? periodLabel(value.preset) : t("shell.header.allTime"))}
      pickerRef={picker} onDismiss={() => setDraft(undefined)}>
      {onClear ? <Button onClick={() => { onClear(); close(); }}>{t("shell.header.allTime")}</Button> : null}
      <PeriodPicker value={draft ?? inputValue} presets={presets} precision={precision} onChange={(next) => {
        if (next.preset !== "custom" && applyPresets) { onChange(next); close(); return; }
        setDraft(next);
      }}/>
      {draft?.preset === "custom" || inputValue?.preset === "custom" || !applyPresets ? <Button disabled={!valid}
        onClick={() => { if (valid) { onChange(draft); close(); } }}>{t("filters.apply")}</Button> : null}
    </PeriodPopover>
    {showBounds && bounds ? <span className="sli-ds-header__updated">{formatDateRange(bounds.from, timeZone, { withYear: false })} → {formatDateRange(bounds.to, timeZone, { withYear: false })}</span> : null}
    {showPrevious && (presets?.includes("custom") ?? true) ? <Button icon="chevron-left" disabled={!previous} onClick={() => { if (previous) onChange(previous); }}>
      {t("shell.header.previousPeriod")}
    </Button> : null}
  </>;
}

function UpdatedTime({ value, snapshot }: { value: string | number; snapshot?: boolean }) {
  const { timeZone } = useTimeZone();
  const instant = new Date(value);
  if (!Number.isFinite(instant.getTime()) || (timeZone !== "browser" && !isValidTimeZone(timeZone))) return null;
  const clock = formatClockWithOffset(instant, timeZone);
  if (snapshot) return <time className="sli-ds-header__updated" dateTime={instant.toISOString()}>{t("shell.header.dataAsOf", {
    time: formatDateRange(instant, timeZone), zone: clock.zone,
  })}</time>;
  return <time className="sli-ds-header__updated" dateTime={instant.toISOString()}>{t("shell.header.updated", { ...clock, date: formatDateTime(instant, false, timeZone) })}</time>;
}

export function PageHeader({ title, titleId, subtitle, crumbs, actions, meta, controls, domain, domainPicker, periodPicker, showDomain = true }: {
  title: string;
  titleId?: string;
  subtitle?: ReactNode;
  crumbs?: Crumb[];
  actions?: ReactNode;
  /** Scope/coverage line under the title (domain, observed time). */
  meta?: ReactNode;
  controls?: PageHeaderControls;
  domain?: string;
  domainPicker?: ReactNode;
  periodPicker?: ReactNode;
  showDomain?: boolean;
}) {
  const scope = useContext(PageHeaderContext);
  const { period, scope: scopeControl, updatedAt, dataAsOf, refreshing, onRefresh, showRefreshLabel, showBreadcrumbs } = controls ?? scope.controls ?? {};
  const domainControl = domainPicker ?? (showDomain ? scope.domain?.(domain) : null);
  return <header className="sli-ds-header">
    {showBreadcrumbs && crumbs?.length ? <nav className="sli-ds-crumbs" aria-label={t("reports.breadcrumbs_aria")}>
      <ol>{crumbs.map((crumb, index) => <li key={`${crumb.label}-${index}`}>{crumb.href && index < crumbs.length - 1 ? <a href={crumb.href}>{crumb.label}</a> : <span aria-current={index === crumbs.length - 1 ? "page" : undefined}>{crumb.label}</span>}</li>)}</ol>
    </nav> : null}
    <div className="sli-ds-header__row">
      <h1 id={titleId} className="sli-ds-header__title" data-page-heading tabIndex={-1}>{title}</h1>
      {domainControl}
      {scopeControl}
      {periodPicker ?? (period ? <HeaderPeriod {...period}/> : null)}
      {dataAsOf || updatedAt || onRefresh || actions ? <div className="sli-ds-header__actions">
        {dataAsOf ? <UpdatedTime value={dataAsOf} snapshot/> : updatedAt ? <UpdatedTime value={updatedAt}/> : null}
        {onRefresh ? <Button icon="refresh" aria-label={t("shell.header.refresh")} title={t("shell.header.refresh")} disabled={refreshing} onClick={onRefresh}>
          {showRefreshLabel ? t("shell.header.refresh") : null}
        </Button> : null}
        {actions}
      </div> : null}
    </div>
    {subtitle ? <p className="sli-ds-header__subtitle">{subtitle}</p> : null}
    {meta ? <div className="sli-ds-header__meta">{meta}</div> : null}
  </header>;
}
