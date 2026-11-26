import { Checkbox } from "../../design-system/Checkbox";
import { Select } from "../../design-system/Select";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type PlatformSetting } from "../../api/client";
import { PageHeader, StateView } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { useTimeZone } from "../../shared/time-zone";
import { zonedParts } from "../../shared/date-time";
import { useEffectiveAccess } from "../App";
import { AccountWatch } from "../account-watch";
import { BackupSettingsSection } from "./backup-settings";
import { DecoyRegistry } from "./decoys";

const fields = [
  { key: "reports.domain_fqdn", group: "domain", text: "report_domain" },
  { key: "ad.password_max_age_days", group: "accounts", text: "ad.password", defaultValue: "365", min: 1, max: 3650, unit: "days" },
  { key: "ad.inactivity_days", group: "accounts", text: "ad.inactivity", defaultValue: "90", min: 1, max: 3650, unit: "days" },
  { key: "ad.service_account_exceptions", group: "accounts", text: "service_exceptions", defaultValue: "0" },
  { key: "windows_auth.distributed_window_hours", group: "spray", text: "spray.distributed_window_hours", defaultValue: "24", min: 1, max: 744, unit: "hours" },
  { key: "windows_auth.distributed_min_accounts", group: "spray", text: "spray.distributed_min_accounts", defaultValue: "10", min: 1, max: 744 },
  { key: "windows_auth.distributed_min_sources", group: "spray", text: "spray.distributed_min_sources", defaultValue: "5", min: 1, max: 744 },
  { key: "windows_auth.distributed_max_failures_per_account", group: "spray", text: "spray.distributed_max_failures_per_account", defaultValue: "3", min: 1, max: 744 },
  { key: "security.working_time", group: "time", text: "working_time" },
] as const;
type Field = typeof fields[number];
type Calendar = { timezone: string; weekdays: number[]; start: string; end: string; excluded_dates: string[]; exceptions: unknown[] };
const weekdays = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"] as const;
const message = (field: Field, suffix: "title" | "description") => t(`platformSettings.${field.text}.${suffix}` as MessageKey);

function calendar(value: string): Calendar {
  return value ? JSON.parse(value) as Calendar : { timezone: "", weekdays: [], start: "", end: "", excluded_dates: [], exceptions: [] };
}
function editorValue(setting: PlatformSetting): string {
  if (setting.key !== "ad.service_account_exceptions") return setting.value;
  return (JSON.parse(setting.value) as (string | { sid: string })[]).map((entry) => typeof entry === "string" ? entry : entry.sid).join("\n");
}
function storedValue(field: Field, value: string): string {
  if (field.key === "ad.service_account_exceptions") return JSON.stringify(value.split(/\r?\n/).map((sid) => sid.trim().toUpperCase()).filter(Boolean));
  return value.trim();
}

function ServiceAccountsField({ id, value, onChange }: { id: string; value: string; onChange: (value: string) => void }) {
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const selected = value.split(/\r?\n/).filter(Boolean);
  const accounts = useQuery({ queryKey: ["settings-accounts", search], queryFn: () => api.reportV2Data("ad.users.v2", new URLSearchParams({ tab: "all", q: search, limit: "50" })) });
  const names = useQuery({
    queryKey: ["settings-account-names", selected],
    queryFn: async () => {
      const result: Record<string, string> = {};
      // Resolve only the saved selections; never download the whole directory.
      for (const sid of selected) {
        const data = await client.fetchQuery({ queryKey: ["settings-account", sid], staleTime: 60_000,
          queryFn: () => api.reportV2Data("ad.users.v2", new URLSearchParams({ tab: "all", q: sid, limit: "50" })) });
        const row = data.items.find((item) => item.sid === sid);
        if (row) result[sid] = String(row.sam || row.display_name || "—");
      }
      return result;
    },
  });
  return <div className="sli-ds-form__accounts">
    <input id={id} type="search" value={search} maxLength={256} aria-describedby={`${id}-help`} onChange={(event) => setSearch(event.target.value)} autoComplete="off"/>
    {search && accounts.data?.items.some((item) => typeof item.sid === "string" && !selected.includes(item.sid)) ? <Select label={t("platformSettings.service_exceptions.choose")} value="" onChange={(selectedValue) => { if (selectedValue) { onChange([...selected, selectedValue].join("\n")); setSearch(""); } }}
      options={[{ value: "", label: "—" }, ...(accounts.data.items.filter((item) => typeof item.sid === "string" && !selected.includes(item.sid)).map((item) => ({ value: String(item.sid), label: String(item.sam || item.display_name || "—") })) ?? [])]}/> : null}
    {selected.map((sid) => {
      const row = accounts.data?.items.find((item) => item.sid === sid);
      const name = names.data?.[sid] || (row ? String(row.sam || row.display_name || "—") : "—");
      return <div className="sli-ds-form__account" key={sid}><span>{name}</span><button type="button" className="sli-ds-button" disabled={name === "—"} aria-label={t("platformSettings.service_exceptions.remove", { name })} onClick={() => {
        if (window.confirm(t("platformSettings.service_exceptions.confirm", { name }))) onChange(selected.filter((item) => item !== sid).join("\n"));
      }}>×</button></div>;
    })}
    {accounts.isError || names.isError ? <p role="alert">{t("platformSettings.service_exceptions.loadFailed")}</p> : null}
  </div>;
}

export function PlatformSettingsPage() {
  const access = useEffectiveAccess();
  const decoyAccess = access?.reports?.some((report) => report.report_key === "decoys.registry" && report.allowed);
  const watchAccess = access?.reports?.some((report) => report.report_key === "watch.registry" && report.allowed);
  const decoyOnly = (decoyAccess || watchAccess) && !access?.platform_owner && !access?.capabilities?.includes("access.manage");
  const settings = useQuery({ queryKey: ["platform-settings"], queryFn: api.platformSettings, enabled: Boolean(access) && !decoyOnly });
  return <section className="sli-ds-report">
    <PageHeader title={t("platformSettings.page.title")}/>
    {!decoyOnly && (settings.isLoading ? <StateView state="loading"/> : settings.error ? <StateView state="unavailable" compact detail={t("platformSettings.loadFailed")} onRetry={() => void settings.refetch()}/> : null)}
    {!decoyOnly && settings.data ? <SettingsForm items={settings.data.items}/> : null}
    {access?.platform_owner === true && !access.preview ? <BackupSettingsSection/> : null}
    {decoyOnly && decoyAccess ? <DecoyRegistry/> : null}
    {decoyOnly && watchAccess ? <AccountWatch/> : null}
  </section>;
}

function SettingsForm({ items }: { items: PlatformSetting[] }) {
  const client = useQueryClient();
  const { timeZone } = useTimeZone();
  const visible = fields.filter((field) => items.some((item) => item.key === field.key));
  const [values, setValues] = useState<Record<string, string>>(() => Object.fromEntries(items.map((item) => [item.key, editorValue(item)])));
  const [baseline, setBaseline] = useState(values);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [savedAt, setSavedAt] = useState("");
  const domains = useQuery({ queryKey: ["setup-domains"], queryFn: api.setupDomains, enabled: visible.some((field) => field.key === "reports.domain_fqdn") });
  const changed = visible.filter((field) => storedValue(field, values[field.key]) !== storedValue(field, baseline[field.key]));
  const edit = (key: string, value: string) => {
    setValues((current) => ({ ...current, [key]: value }));
    setErrors((current) => ({ ...current, [key]: "" })); setSavedAt("");
  };
  const validation = (field: Field): string => {
    const value = values[field.key];
    if ("min" in field && (!/^[0-9]+$/.test(value.trim()) || Number(value) < field.min || Number(value) > field.max))
      return t("platformSettings.range", { min: field.min, max: field.max });
    if (field.key === "ad.service_account_exceptions") {
      const sids = JSON.parse(storedValue(field, value)) as string[];
      if (sids.length > 1000 || new Set(sids).size !== sids.length || sids.some((sid) => !/^S-1-5-21-\d+-\d+-\d+-\d+$/.test(sid))) return t("platformSettings.service_exceptions.validation");
    }
    if (field.key === "reports.domain_fqdn" && (!domains.isSuccess || !domains.data.items.some((domain) => !domain.is_archived && domain.fqdn.toLowerCase() === value.trim().toLowerCase()))) return t("platformSettings.report_domain.validation");
    if (field.key === "security.working_time") {
      const c = calendar(value);
      if (!c.timezone || !c.weekdays.length || !c.start || !c.end || c.start === c.end) return t("platformSettings.working_time.validation");
    }
    return "";
  };
  return <form className="sli-ds-form" noValidate onSubmit={async (event) => {
    event.preventDefault();
    if (busy || !changed.length) return;
    const invalid = Object.fromEntries(changed.map((field) => [field.key, validation(field)]).filter(([, error]) => error));
    setErrors(invalid); setSavedAt("");
    if (Object.keys(invalid).length) return;
    setBusy(true);
    let failed = false;
    try {
      for (const field of changed) {
        try {
          const result = await api.updatePlatformSetting(field.key, storedValue(field, values[field.key]));
          const confirmed = editorValue(result.item);
          setValues((current) => ({ ...current, [field.key]: confirmed }));
          setBaseline((current) => ({ ...current, [field.key]: confirmed }));
          client.setQueryData<{ items: PlatformSetting[] }>(["platform-settings"], (current) => current ? { items: current.items.map((item) => item.key === field.key ? result.item : item) } : current);
        } catch {
          failed = true;
          setErrors((current) => ({ ...current, [field.key]: t("platformSettings.saveFailed", { name: message(field, "title") }) }));
        }
      }
      if (!failed) { const now = zonedParts(new Date(), timeZone); setSavedAt(`${now.hour}:${now.minute}`); }
    } finally { setBusy(false); }
  }}>
    <fieldset className="sli-ds-form__fields" disabled={busy}>
      {(["domain", "accounts", "spray", "time"] as const).map((group) => {
        const groupFields = visible.filter((field) => field.group === group);
        return groupFields.length ? <section className="sli-ds-form__group" key={group} aria-labelledby={`settings-${group}`}>
          <h2 className="sli-ds-section-title" id={`settings-${group}`}>{t(`platformSettings.group.${group}`)}</h2>
          {groupFields.map((field) => {
            const id = `platform-setting-${field.key}`;
            const value = values[field.key];
            const error = errors[field.key] || (changed.includes(field) ? validation(field) : "");
            const c = field.key === "security.working_time" ? calendar(value) : null;
            const zones = c ? [...new Set(["UTC", ...Intl.supportedValuesOf("timeZone"), ...(c.timezone ? [c.timezone] : [])])] : [];
            return <div className="sli-ds-form__row" key={field.key}>
              <div className="sli-ds-form__label">
                {c ? <span id={`${id}-label`}>{message(field, "title")}</span> : <label htmlFor={id}>{message(field, "title")}</label>}
                <p id={`${id}-help`}>{message(field, "description")}</p>
              </div>
              <div className="sli-ds-form__value sli-ds-field">
                {c ? <div className="sli-ds-form__calendar" role="group" aria-labelledby={`${id}-label`} aria-describedby={`${id}-help`}>
                  <div className="sli-ds-form__weekdays">{weekdays.map((day, index) => <Checkbox key={day} checked={c.weekdays.includes(index)} onChange={(event) => edit(field.key, JSON.stringify({ ...c, weekdays: event.target.checked ? [...c.weekdays, index].sort() : c.weekdays.filter((n) => n !== index) }))}>{t(`platformSettings.day.${day}`)}</Checkbox>)}</div>
                  <div className="sli-ds-form__hours">
                    <label>{t("platformSettings.time.start")}<input type="time" value={c.start} aria-invalid={Boolean(error)} onChange={(event) => edit(field.key, JSON.stringify({ ...c, start: event.target.value }))}/></label>
                    <label>{t("platformSettings.time.end")}<input type="time" value={c.end} aria-invalid={Boolean(error)} onChange={(event) => edit(field.key, JSON.stringify({ ...c, end: event.target.value }))}/></label>
                    <div className="sli-ds-control-field">{t("platformSettings.time.zone")}<Select label={t("platformSettings.time.zone")} value={c.timezone} aria-invalid={Boolean(error)} onChange={(selectedValue) => edit(field.key, JSON.stringify({ ...c, timezone: selectedValue }))}
                      options={[{ value: "", label: "—" }, ...(zones.map((zone) => ({ value: zone, label: zone })) ?? [])]}/></div>
                  </div>
                </div> : field.key === "reports.domain_fqdn" ? <Select label={message(field, "title")} id={id} value={value} aria-describedby={`${id}-help`} aria-invalid={Boolean(error)} disabled={!domains.isSuccess} onChange={(selectedValue) => edit(field.key, selectedValue)}
                  options={[{ value: "", label: "—" }, ...(value && !domains.data?.items.some((domain) => domain.fqdn === value && !domain.is_archived) ? [{ value: value, label: value, disabled: true }] : []), ...(domains.data?.items.filter((domain) => !domain.is_archived).map((domain) => ({ value: domain.fqdn, label: domain.fqdn })) ?? [])]}/> : field.key === "ad.service_account_exceptions" ? <ServiceAccountsField id={id} value={value} onChange={(next) => edit(field.key, next)}/> : <input id={id} type="number" min={"min" in field ? field.min : undefined} max={"max" in field ? field.max : undefined} step={1} value={value} aria-describedby={`${id}-help`} aria-invalid={Boolean(error)} onChange={(event) => edit(field.key, event.target.value)}/>}
                {error ? <p className="sli-ds-field__error" role="alert">{error}</p> : null}
                {field.key === "reports.domain_fqdn" && domains.isError ? <p role="alert">{t("platformSettings.domainsFailed")}</p> : null}
              </div>
              <span className="sli-ds-form__default">{"unit" in field ? `${t(`platformSettings.unit.${field.unit}`)} · ` : ""}{"defaultValue" in field ? t("platformSettings.default", { value: field.defaultValue }) : "—"}</span>
            </div>;
          })}
        </section> : null;
      })}
    </fieldset>
    <div className="sli-ds-filters__actions">
      <button className="sli-ds-button" data-variant="primary" type="submit" disabled={busy || !changed.length || changed.some((field) => Boolean(validation(field)))}>{t(busy ? "platformSettings.saving" : "platformSettings.save")}</button>
      <button className="sli-ds-button" type="button" disabled={busy || !changed.length} onClick={() => { setValues({ ...baseline }); setErrors({}); setSavedAt(""); }}>{t("platformSettings.cancel")}</button>
      {savedAt ? <span role="status">{t("platformSettings.savedAt", { time: savedAt })}</span> : null}
    </div>
  </form>;
}
