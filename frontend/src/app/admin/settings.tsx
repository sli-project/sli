import { useMutation, useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Button, ComboBox, Input, Label, ListBox, ListBoxItem, Popover } from "react-aria-components";
import { api } from "../../api/client";
import { PageHeader, StateView } from "../../design-system";
import { useTimeZone } from "../../shared/time-zone";
import { roleLabel } from "../report-labels";
import { getLocale, setLocale, t, type Locale } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";

/** Язык и отображение времени для текущего пользователя. */
export function SettingsPage() {
  const { timeZone, setTimeZone } = useTimeZone();
  const [language, setLanguage] = useState(getLocale);
  const [zone, setZone] = useState(timeZone);
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
  const logout = useMutation({ mutationFn: api.logout, onSuccess: () => window.location.assign("/login") });
  const changed = language !== getLocale() || zone !== timeZone;

  return <section className="sli-ds-report">
    <PageHeader title={t("operations.settings.title")}
      actions={<button type="button" className="sli-ds-button" onClick={() => logout.mutate()} disabled={logout.isPending}>{logout.isPending ? t("operations.settings.logging_out") : t("operations.settings.logout")}</button>}/>
    {principal ? <p className="sli-ds-header__subtitle">{principal.username ?? "—"} · {principal.role ? roleLabel(principal.role) : "—"}</p> : null}
    {bootstrap.isLoading ? <StateView state="loading" compact/> : bootstrap.error ? <p role="alert">{t("operations.settings.load_error")} <button type="button" className="sli-ds-button" onClick={() => void bootstrap.refetch()}>{t("state.retry")}</button></p> : null}
    {logout.isError ? <p role="alert">{t("shell.profile.logoutFailed")}</p> : null}
    <form className="sli-ds-report__views" onSubmit={(event) => {
      event.preventDefault();
      if (!changed) return;
      setSaveError(false);
      try {
        setTimeZone(zone);
        const saved = new Date();
        // Keep the result visible after changing the interface language reloads the page.
        try { sessionStorage.setItem("sli.profile.savedAt", saved.toISOString()); } catch { /* The result remains visible until reload. */ }
        setSavedAt(saved);
        if (language !== getLocale()) setLocale(language);
      } catch {
        setSaveError(true);
        setSavedAt(undefined);
      }
    }}>
      <div className="sli-ds-field" data-layout="row"><label htmlFor="settings-language">{t("shell.profile.language.title")}</label>
        <select id="settings-language" value={language} aria-describedby={saveError ? "settings-save-error" : undefined} onChange={(event) => setLanguage(event.target.value as Locale)}>
          {(["ru", "en"] as const).map((locale) => <option key={locale} value={locale}>{t(`shell.profile.language.${locale}`)}</option>)}
        </select></div>
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
      {saveError ? <p id="settings-save-error" className="sli-ds-field__error" role="alert">{t("operations.settings.save_error")}</p> : null}
      <div className="sli-ds-state__actions">
        <button type="submit" className="sli-ds-button" data-variant="primary" disabled={!changed}>{t("operations.settings.save")}</button>
        {savedAt && !changed ? <span role="status">{t("operations.settings.saved", { time: formatDateTime(savedAt, timeZone) })}</span> : null}
      </div>
    </form>
  </section>;
}
