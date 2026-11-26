import { useEffect, useId, useRef, useState } from "react";
import { parseDate } from "@internationalized/date";
import { Button, Calendar, CalendarCell, CalendarGrid, Dialog, DialogTrigger, Heading, I18nProvider, Popover } from "react-aria-components";
import { getLocale, t } from "../i18n";
import { Icon } from "./Icon";

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

export function isPeriodBoundary(value: string | undefined, precision: "date" | "datetime-local"): value is string {
  if (!value) return false;
  const pattern = precision === "date" ? /^\d{4}-\d{2}-\d{2}$/ : /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,3})?)?$/;
  if (!pattern.test(value)) return false;
  const date = new Date(value + (precision === "date" ? "T00:00:00Z" : "Z"));
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 16) === (precision === "date" ? value + "T00:00" : value.slice(0, 16));
}

export function DateInput({ id, label, value, defaultValue = "", precision = "datetime-local", required,
  name, "aria-describedby": describedBy, "aria-invalid": invalid, onChange }: {
  id?: string;
  label: string;
  value?: string;
  defaultValue?: string;
  precision?: "date" | "datetime-local";
  required?: boolean;
  name?: string;
  "aria-describedby"?: string;
  "aria-invalid"?: boolean;
  onChange?: (value: string) => void;
}) {
  const [draft, setDraft] = useState(defaultValue);
  const current = value ?? draft;
  const input = useRef<HTMLInputElement>(null);
  const malformed = Boolean(current) && !isPeriodBoundary(current, precision);
  useEffect(() => {
    input.current?.setCustomValidity(malformed ? t("period.invalidBoundary") : "");
  }, [malformed]);
  const change = (next: string) => {
    if (value === undefined) setDraft(next);
    onChange?.(next);
  };
  const withTime = precision === "datetime-local";
  const date = current.slice(0, 10);
  const time = current.split("T")[1];
  return <div className="sli-ds-field__control sli-ds-date-input">
      <input id={id} ref={input} aria-label={label} aria-describedby={describedBy} aria-invalid={invalid || malformed || undefined} type="text" placeholder={t(withTime ? "period.dateTimeFormat" : "period.dateFormat")}
        pattern={withTime ? "[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}(:[0-9]{2}([.][0-9]{1,3})?)?" : "[0-9]{4}-[0-9]{2}-[0-9]{2}"}
        autoComplete="off" required={required} value={current.replace("T", " ")}
        onChange={(event) => change(event.target.value.replace(" ", "T"))}/>
      {name ? <input type="hidden" name={name} value={current}/> : null}
      <I18nProvider locale={getLocale()}>
        <DialogTrigger>
          <Button className="sli-ds-button" aria-label={t("period.chooseDate", { label })}><Icon name="calendar"/></Button>
          <Popover className="sli-ds-calendar">
            <Dialog aria-label={t("period.chooseDate", { label })}>{({ close }) =>
              <Calendar aria-label={label} value={isPeriodBoundary(date, "date") ? parseDate(date) : null} onChange={(day) => {
                change(day.toString() + (withTime ? "T" + (time || "00:00") : ""));
                close();
              }}>
                <header className="sli-ds-calendar__header">
                  <Button slot="previous" className="sli-ds-button" aria-label={t("table.previous")}><Icon name="chevron-left"/></Button>
                  <Heading/>
                  <Button slot="next" className="sli-ds-button" aria-label={t("table.next")}><Icon name="chevron-right"/></Button>
                </header>
                <CalendarGrid>{(day) => <CalendarCell date={day} className="sli-ds-calendar__day"/>}</CalendarGrid>
              </Calendar>}
            </Dialog>
          </Popover>
        </DialogTrigger>
      </I18nProvider>
    </div>;
}

export function PeriodPicker({ value, onChange, label = t("period.label"), presets = ["24h", "7d", "30d", "90d", "custom"], precision = "date" }: {
  value: PeriodValue | undefined;
  onChange: (value: PeriodValue) => void;
  label?: string;
  presets?: PeriodPreset[];
  precision?: "date" | "datetime-local";
  step?: number | "any";
}) {
  const id = useId();
  const invalid = value?.preset === "custom" && (
    Boolean(value.from && !isPeriodBoundary(value.from, precision)) ||
    Boolean(value.to && !isPeriodBoundary(value.to, precision)) ||
    Boolean(value.from && value.to && value.from > value.to));
  return <fieldset className="sli-ds-period">
    <legend>{label}</legend>
    <div className="sli-ds-period__presets" role="radiogroup" aria-label={label}>
      {presets.map((preset) => <button key={preset} type="button" role="radio" aria-checked={value?.preset === preset}
        className="sli-ds-chip" onClick={() => onChange(preset === "custom" ? { preset, from: value?.from, to: value?.to } : { preset })}>{periodLabel(preset)}</button>)}
    </div>
    {value?.preset === "custom" ? <div className="sli-ds-period__custom">
      <label htmlFor={id + "-from"}>{t("period.from")}</label>
      <DateInput id={id + "-from"} required={precision === "datetime-local"} label={t("period.from")} value={value.from ?? ""} precision={precision}
        onChange={(from) => onChange({ ...value, from })}/>
      <label htmlFor={id + "-to"}>{t("period.to")}</label>
      <DateInput id={id + "-to"} required={precision === "datetime-local"} label={t("period.to")} value={value.to ?? ""} precision={precision}
        onChange={(to) => onChange({ ...value, to })}/>
      {invalid ? <span role="alert" className="sli-ds-field__error">{t("period.invalid")}</span> : null}
    </div> : null}
  </fieldset>;
}
