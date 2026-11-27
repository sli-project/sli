import { Select } from "../../design-system/Select";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Button, ComboBox, Input, Label, ListBox, ListBoxItem, Popover } from "react-aria-components";
import { api } from "../../api/client";
import { PageHeader, StateView } from "../../design-system";
import { useTimeZone } from "../../shared/time-zone";
import { roleLabel } from "../report-labels";
import { getLocale, setLocale, t, type Locale } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";

const serverTimeZoneKey = "server.timezone";

export function SettingsPage() {
  const { timeZone, setTimeZone } = useTimeZone();
  const [language, setLanguage] = useState(getLocale);
  const [zone, setZone] = useState(timeZone);
  const [serverZone, setServerZone] = useState<string>();
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState<Date | undefined>(() => {
    try {
      const value = sessionStorage.getItem("sli.profile.savedAt");
      const instant = value ? Date.parse(value) : NaN;
      return Number.isFinite(instant) ? new Date(instant) : undefined;
    } catch { return undefined; }
  });
  const [saveError, setSaveError] = useState(false);
  const zones = useMemo(() => [...new Set([...Intl.supportedValuesOf("timeZone"), "UTC", ...(timeZone === "browser" ? [] : [timeZone])])], [timeZone]);
  const options = [{ id: "browser", label: t("operations.settings.tz_browser") }, ...zones.map((id) => ({ id, label: id }))];
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrap, staleTime: 60_000 });
  const principal = bootstrap.data?.principal;
  const canSetServerZone = principal?.role === "admin" && bootstrap.data?.capabilities?.includes("access.manage") === true;
  const settings = useQuery({ queryKey: ["platform-settings"], queryFn: api.platformSettings, enabled: canSetServerZone });
  const storedServerZone = canSetServerZone ? settings.data?.items.find(item => item.key === serverTimeZoneKey)?.value : undefined;
  const serverZones = [...new Set([...zones, ...(storedServerZone && storedServerZone !== "host" ? [storedServerZone] : [])])];
  const serverZoneChanged = storedServerZone !== undefined && serverZone !== undefined && serverZone !== storedServerZone;
  const queryClient = useQueryClient();
  const logout = useMutation({ mutationFn: api.logout, onSuccess: () => window.location.assign("/login") });
  const changed = language !== getLocale() || zone !== timeZone || serverZoneChanged;

  return <section className="sli-ds-report">
    <PageHeader title={t("shell.adminNav.locale")}
      actions={<button type="button" className="sli-ds-button" onClick={() => logout.mutate()} disabled={logout.isPending}>{logout.isPending ? t("operations.settings.logging_out") : t("operations.settings.logout")}</button>}/>
    {principal ? <p className="sli-ds-header__subtitle">{principal.username ?? "—"} · {principal.role ? roleLabel(principal.role) : "—"}</p> : null}
    {bootstrap.isLoading ? <StateView state="loading" compact/> : bootstrap.error ? <p role="alert">{t("operations.settings.load_error")} <button type="button" className="sli-ds-button" onClick={() => void bootstrap.refetch()}>{t("state.retry")}</button></p> : null}
    {logout.isError ? <p role="alert">{t("shell.profile.logoutFailed")}</p> : null}
    <form className="sli-ds-report__views" onSubmit={async (event) => {
      event.preventDefault();
      if (!changed || saving) return;
      setSaveError(false);
      setSaving(true);
      try {
        if (serverZoneChanged) {
          const { item } = await api.updatePlatformSetting(serverTimeZoneKey, serverZone);
          queryClient.setQueryData<Awaited<ReturnType<typeof api.platformSettings>>>(["platform-settings"], current =>
            current && { items: current.items.map(setting => setting.key === item.key ? item : setting) });
          setServerZone(undefined);
        }
        setTimeZone(zone);
        const saved = new Date();
        // Keep the result visible after changing the interface language reloads the page.
        try { sessionStorage.setItem("sli.profile.savedAt", saved.toISOString()); } catch { /* The result remains visible until reload. */ }
        setSavedAt(saved);
        if (language !== getLocale()) setLocale(language);
      } catch {
        setSaveError(true);
        setSavedAt(undefined);
      } finally {
        setSaving(false);
      }
    }}>
      <div className="sli-ds-field" data-layout="row"><label htmlFor="settings-language">{t("shell.profile.language.title")}</label>
        <Select label={t("shell.profile.language.title")} id="settings-language" value={language} aria-describedby={saveError ? "settings-save-error" : undefined} onChange={(selectedValue) => setLanguage(selectedValue as Locale)}
          options={(["ru", "en"] as const).map((locale) => ({ value: locale, label: t(`shell.profile.language.${locale}`) }))}/></div>
      <ComboBox className="sli-ds-field" data-layout="row" selectedKey={zone} defaultItems={options} menuTrigger="focus"
        defaultFilter={(text, input) => text.toLocaleLowerCase().includes(input.trim().toLocaleLowerCase())}
        onSelectionChange={(key) => { if (key !== null) setZone(String(key)); }}>
        <Label>{t("operations.settings.tz_title")}</Label>
        <div className="sli-ds-field__control"><Input aria-describedby={saveError ? "settings-save-error" : undefined}/>
          <Button className="sli-ds-button" aria-label={t("operations.settings.tz_title")}>▾</Button></div>
        <Popover className="sli-ds-suggestions" isNonModal>
          <ListBox className="sli-ds-suggestions__list" renderEmptyState={() => t("filters.no_matches")}>
            {(option: { id: string; label: string }) => <ListBoxItem id={option.id} textValue={option.label} className="sli-ds-suggestions__item">{option.label}</ListBoxItem>}
          </ListBox>
        </Popover>
      </ComboBox>
      {storedServerZone !== undefined ? <div className="sli-ds-field" data-layout="row">
        <label htmlFor="settings-server-time-zone">{t("operations.settings.server_tz_title")}</label>
        <Select label={t("operations.settings.server_tz_title")} id="settings-server-time-zone" value={serverZone ?? storedServerZone} disabled={saving} aria-describedby={saveError ? "settings-save-error" : undefined} onChange={(selectedValue) => setServerZone(selectedValue)}
          options={[{ value: "host", label: t("operations.settings.server_tz_host") }, ...(serverZones.map(id => ({ value: id, label: id })) ?? [])]}/>
      </div> : null}
      {canSetServerZone && settings.isError ? <p role="alert">{t("operations.settings.server_tz_load_error")}</p> : null}
      {saveError ? <p id="settings-save-error" className="sli-ds-field__error" role="alert">{t("operations.settings.save_error")}</p> : null}
      <div className="sli-ds-state__actions">
        <button type="submit" className="sli-ds-button" data-variant="primary" disabled={!changed || saving}>{t("operations.settings.save")}</button>
        {savedAt && !changed ? <span role="status">{t("operations.settings.saved", { time: formatDateTime(savedAt, timeZone) })}</span> : null}
      </div>
    </form>
  </section>;
}
