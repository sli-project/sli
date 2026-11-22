import { useId } from "react";
import { t } from "../i18n";

export type PeriodPreset = "2h" | "24h" | "7d" | "30d" | "90d" | "custom";
/** `from`/`to` are local dates or local date-times, according to the picker precision. */
export type PeriodValue = { preset: PeriodPreset; from?: string; to?: string };

const PRESET_LABEL: Record<PeriodPreset, Parameters<typeof t>[0]> = {
  "2h": "reports.v2.events.journal.period.2h", "24h": "period.24h", "7d": "period.7d", "30d": "period.30d", "90d": "period.90d", custom: "period.custom",
};
export const periodLabel = (preset: PeriodPreset) => Object.hasOwn(PRESET_LABEL, preset) ? t(PRESET_LABEL[preset]) : t("period.label");

const PRESET_HOURS: Record<Exclude<PeriodPreset, "custom">, number> = { "2h": 2, "24h": 24, "7d": 168, "30d": 720, "90d": 2160 };

/** Resolves a period to an absolute UTC window for a report query. */
export function periodBounds(value: PeriodValue, now = new Date()): { from: string; to: string } | null {
  if (value.preset === "custom") {
    if (!value.from || !value.to) return null;
    const from = new Date(value.from.includes("T") ? value.from : `${value.from}T00:00:00`);
    const to = new Date(value.to.includes("T") ? value.to : `${value.to}T23:59:59.999`);
    if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || from > to) return null;
    return { from: from.toISOString(), to: to.toISOString() };
  }
  if (!Object.hasOwn(PRESET_HOURS, value.preset)) return null;
  return { from: new Date(now.getTime() - PRESET_HOURS[value.preset] * 3_600_000).toISOString(), to: now.toISOString() };
}

export function previousPeriod(value: PeriodValue, window?: { from: string; to: string }): PeriodValue | null {
  if (value.preset === "custom" && value.from && value.to && !value.from.includes("T") && !value.to.includes("T")) {
    const from = Date.parse(value.from);
    const to = Date.parse(value.to);
    if (!Number.isFinite(from) || !Number.isFinite(to) || to < from) return null;
    const day = 86_400_000;
    return { preset: "custom", from: new Date(from - (to - from) - day).toISOString().slice(0, 10), to: new Date(from - day).toISOString().slice(0, 10) };
  }
  const bounds = window ?? periodBounds(value);
  if (!bounds) return null;
  const from = Date.parse(bounds.from);
  const to = Date.parse(bounds.to);
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) return null;
  return { preset: "custom", from: new Date(from - (to - from)).toISOString(), to: bounds.from };
}

function openPicker(input: HTMLInputElement) {
  try { input.showPicker?.(); } catch { /* not user-activated or unsupported: plain input still works */ }
}

export function PeriodPicker({ value, onChange, label = t("period.label"), presets = ["24h", "7d", "30d", "90d", "custom"], precision = "date" }: {
  value: PeriodValue | undefined;
  onChange: (value: PeriodValue) => void;
  label?: string;
  presets?: PeriodPreset[];
  precision?: "date" | "datetime-local";
}) {
  const id = useId();
  const invalid = value?.preset === "custom" && value.from && value.to && value.from > value.to;
  return <fieldset className="sli-ds-period">
    <legend>{label}</legend>
    <div className="sli-ds-period__presets" role="radiogroup" aria-label={label}>
      {presets.map((preset) => <button key={preset} type="button" role="radio" aria-checked={value?.preset === preset}
        className="sli-ds-chip" onClick={() => onChange(preset === "custom" ? { preset, from: value?.from, to: value?.to } : { preset })}>{periodLabel(preset)}</button>)}
    </div>
    {value?.preset === "custom" ? <div className="sli-ds-period__custom">
      <label htmlFor={`${id}-from`}>{t("period.from")}</label>
      <input id={`${id}-from`} type={precision} required={precision === "datetime-local"} value={value.from ?? ""} max={value.to} onClick={(event) => openPicker(event.currentTarget)} onChange={(event) => onChange({ ...value, from: event.target.value })}/>
      <label htmlFor={`${id}-to`}>{t("period.to")}</label>
      <input id={`${id}-to`} type={precision} required={precision === "datetime-local"} value={value.to ?? ""} min={value.from} onClick={(event) => openPicker(event.currentTarget)} onChange={(event) => onChange({ ...value, to: event.target.value })}/>
      {invalid ? <span role="alert" className="sli-ds-field__error">{t("period.invalid")}</span> : null}
    </div> : null}
  </fieldset>;
}
