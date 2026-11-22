import { formatNumber } from "../shared/format";
import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { t } from "../i18n";
import { PeriodPicker, type PeriodValue } from "./PeriodPicker";
import { Button } from "./Primitives";
import { SearchMultiSelect, type SearchOption } from "./SearchMultiSelect";

export type FilterOption = { value: string; label: string; count?: number };

export type FilterField =
  | { key: string; label: string; kind: "text"; placeholder?: string; wide?: boolean; nested?: { key: string; label: string }; immediate?: boolean }
  | { key: string; label: string; kind: "select"; options: FilterOption[]; immediate?: boolean; hideLabel?: boolean }
  | { key: string; label: string; kind: "checkbox"; onValue: string; offValue: string }
  | { key: string; label: string; kind: "multiselect"; options: FilterOption[] }
  | { key: string; label: string; kind: "search-multiselect"; options: SearchOption[] }
  | { key: string; label: string; kind: "period"; presets?: PeriodValue["preset"][]; precision?: "date" | "datetime-local" };

export type FilterValue = string | string[] | PeriodValue | undefined;
export type FilterValues = Record<string, FilterValue>;

function isActive(value: FilterValue): boolean {
  if (value === undefined || value === "") return false;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

/**
 * Declarative filter bar (ADR 0010 `params`). Edits stay in a draft until
 * the user applies them, so a report query runs once per decision.
 */
export function FilterBar({ fields, values, onApply, defaults = {}, primaryKeys, additionalContent, align, layout, quickFilters, leadingControls, applyInline }: {
  fields: FilterField[];
  values: FilterValues;
  onApply: (values: FilterValues) => void;
  /** Values restored by "reset"; period fields usually keep a default. */
  defaults?: FilterValues;
  /** When supplied, remaining fields share a collapsible section of this form. */
  primaryKeys?: string[];
  additionalContent?: ReactNode;
  align?: "start" | "end";
  /** A three-column form with wide object fields; stacks on narrow screens. */
  layout?: "grid" | "inline";
  quickFilters?: ReactNode;
  leadingControls?: ReactNode;
  applyInline?: boolean;
}) {
  const [draft, setDraft] = useState<FilterValues>(values);
  // On a phone a long form hides the result; it starts folded behind one toggle.
  const [collapsed, setCollapsed] = useState(() => !primaryKeys && typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia("(max-width: 900px)").matches);
  const formId = useId();
  const searchTimer = useRef<number | undefined>(undefined);
  useEffect(() => {
    setDraft(values);
    return () => window.clearTimeout(searchTimer.current);
  }, [values]);
  const activeCount = fields.filter((field) => field.kind !== "period" && isActive(values[field.key]) && JSON.stringify(values[field.key]) !== JSON.stringify(defaults[field.key])).length;
  const additional = primaryKeys ? fields.filter((field) => !primaryKeys.includes(field.key)) : [];
  const additionalActive = additional.filter((field) => isActive(draft[field.key]) && JSON.stringify(draft[field.key]) !== JSON.stringify(defaults[field.key])).length;
  const [additionalOpen, setAdditionalOpen] = useState(() => !quickFilters && additionalActive > 0);
  useEffect(() => { if (!quickFilters && additionalActive > 0) setAdditionalOpen(true); }, [additionalActive, quickFilters]);
  const set = (key: string, value: FilterValue) => setDraft((current) => ({ ...current, [key]: value }));
  const apply = (next: FilterValues) => { window.clearTimeout(searchTimer.current); onApply(next); };
  const submit = (event: FormEvent) => { event.preventDefault(); apply(draft); };

  const renderFields = (items: FilterField[]) => items.map((field) => {
    const id = `${formId}-${field.key}`;
    if (field.kind === "period") {
      return <PeriodPicker key={field.key} label={field.label} presets={field.presets}
        precision={field.precision}
        value={(draft[field.key] as PeriodValue | undefined) ?? { preset: "30d" }}
        onChange={(value) => {
          set(field.key, value);
          if (applyInline && (value.preset !== "custom" || value.from && value.to && value.from <= value.to))
            apply({ ...draft, [field.key]: value });
        }}/>;
    }
    if (field.kind === "checkbox") return <label key={field.key} className="sli-ds-button">
      <input type="checkbox" checked={draft[field.key] === field.onValue} onChange={(event) => {
        const value = event.target.checked ? field.onValue : field.offValue;
        set(field.key, value);
        if (applyInline) apply({ ...draft, [field.key]: value });
      }}/>{field.label}
    </label>;
    if (field.kind === "search-multiselect") return <SearchMultiSelect key={field.key} label={field.label} options={field.options}
      values={(draft[field.key] as string[] | undefined) ?? []} onChange={(value) => set(field.key, value)}/>;
    return <div key={field.key} className="sli-ds-field" data-kind={field.kind} data-wide={field.kind === "text" && field.wide || undefined}>
      <label htmlFor={id} className={layout === "inline" && (field.kind === "text" || field.kind === "select" && field.hideLabel) ? "sli-ds-sr-only" : undefined}>{field.label}</label>
      {field.kind === "text"
        ? <><input id={id} type="search" value={(draft[field.key] as string | undefined) ?? ""} placeholder={field.placeholder ?? t("filters.search")}
          onBlur={() => { if (applyInline && draft[field.key] !== values[field.key]) apply(draft); }} onChange={(event) => {
            set(field.key, event.target.value);
            const next = { ...draft, [field.key]: event.target.value };
            if (field.immediate && event.target.value) {
              window.clearTimeout(searchTimer.current);
              searchTimer.current = window.setTimeout(() => onApply(next), 250);
            } else if (field.immediate || layout === "inline" && !event.target.value) apply(next);
          }}/>
          {field.nested ? <label className="sli-ds-field__help"><input type="checkbox" checked={draft[field.nested.key] === "true"}
            onChange={(event) => set(field.nested!.key, String(event.target.checked))}/>{field.nested.label}</label> : null}</>
        : field.kind === "select"
          ? <select id={id} value={(draft[field.key] as string | undefined) ?? ""} onChange={(event) => {
              const value = event.target.value || undefined;
              set(field.key, value);
              if (field.immediate || applyInline) apply({ ...draft, [field.key]: value });
            }}>
              {!field.options.some((option) => option.value === "") ? <option value="">{t("filters.any")}</option> : null}
              {field.options.map((option) => <option key={option.value} value={option.value}>{option.label}{typeof option.count === "number" ? ` (${formatNumber(option.count)})` : ""}</option>)}
            </select>
          : <select id={id} multiple size={Math.min(6, Math.max(3, field.options.length))} value={(draft[field.key] as string[] | undefined) ?? []}
              onChange={(event) => set(field.key, [...event.target.selectedOptions].map((option) => option.value))}>
              {field.options.map((option) => <option key={option.value} value={option.value}>{option.label}{typeof option.count === "number" ? ` (${formatNumber(option.count)})` : ""}</option>)}
            </select>}
    </div>;
  });

  const actions = <div className="sli-ds-filters__actions">
    {activeCount && layout !== "inline" ? <span className="sli-ds-badge" data-tone="accent">{t("filters.active", { count: activeCount })}</span> : null}
    <Button variant="ghost" onClick={() => { setDraft(defaults); apply(defaults); }}>{t("filters.reset")}</Button>
    <Button type="submit" variant="primary">{t("filters.apply")}</Button>
  </div>;

  return <form className="sli-ds-filters" onSubmit={submit} aria-label={t("filters.title")} data-layout={layout} data-collapsed={collapsed} data-grouped={primaryKeys ? true : undefined} data-quick-filters={quickFilters ? true : undefined}>
    {!primaryKeys ? <Button className="sli-ds-filters__toggle" aria-expanded={!collapsed} aria-controls={`${formId}-fields`} onClick={() => setCollapsed((value) => !value)}>
      {t("filters.title")}{activeCount ? ` · ${t("filters.active", { count: activeCount })}` : ""}
    </Button> : null}
    {leadingControls}
    <div className="sli-ds-filters__fields" id={`${formId}-fields`} data-align={align} data-layout={layout}>
      {renderFields(primaryKeys ? fields.filter((field) => primaryKeys.includes(field.key)) : fields)}
    </div>
    {quickFilters}
    {additional.length || additionalContent ? <details className="sli-ds-filters__additional" open={additionalOpen} onToggle={(event) => setAdditionalOpen(event.currentTarget.open)}>
      <summary>{t("reports.filters.more")}{additionalActive ? ` · ${t("filters.active", { count: additionalActive })}` : ""}</summary>
      {additionalContent}
      {layout === "inline" ? <div className="sli-ds-filters__popover"><div className="sli-ds-filters__fields">{renderFields(additional)}</div>{actions}</div>
        : <div className="sli-ds-filters__fields">{renderFields(additional)}</div>}
    </details> : null}
    {layout !== "inline" ? actions : null}
  </form>;
}
