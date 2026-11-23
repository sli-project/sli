import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiResponseError } from "../../api/client";
import { StateView } from "../../design-system";
import { t, type MessageKey } from "../../i18n";

const queryKey = ["backup-settings"] as const;
const pathErrors = new Map<string, MessageKey>([
  ["backup_settings_invalid", "backupSettings.pathInvalid"],
  ["native_backup_root_invalid", "backupSettings.pathMissing"],
  ["native_backup_root_untrusted", "backupSettings.pathUntrusted"],
  ["native_backup_root_same_device", "backupSettings.pathSameDisk"],
  ["native_backup_root_insufficient_space", "backupSettings.pathSpace"],
  ["native_backup_root_mount_mismatch", "backupSettings.pathMount"],
]);

function validDirectory(value: string): boolean {
  return /^(\/[A-Za-z0-9_.-]+)+$/.test(value)
    && !value.split("/").some((segment) => segment === "." || segment === "..");
}

export function BackupSettingsSection() {
  const client = useQueryClient();
  const query = useQuery({
    queryKey, queryFn: ({ signal }) => api.backupSettings(signal),
    refetchOnWindowFocus: false, refetchOnReconnect: false,
  });
  const [draft, setDraft] = useState<{ enabled: boolean; path: string } | null>(null);
  const [saved, setSaved] = useState(false);
  const save = useMutation({
    mutationFn: api.updateBackupSettings,
    onSuccess: (confirmed) => {
      client.setQueryData(queryKey, confirmed);
      setDraft(null);
      setSaved(true);
    },
  });
  const edit = (next: { enabled: boolean; path: string }) => {
    setDraft(next);
    setSaved(false);
    save.reset();
  };
  const reload = async () => {
    const refreshed = await query.refetch();
    if (refreshed.isSuccess && refreshed.data.revision !== null) {
      setDraft(null);
      setSaved(false);
      save.reset();
    }
  };
  const settings = query.data;
  let content;
  if (query.isPending) {
    content = <StateView state="loading" compact/>;
  } else if (query.isError || !settings?.revision) {
    const denied = query.error instanceof ApiResponseError && query.error.status === 403;
    content = denied ? <StateView state="denied" compact/> : <StateView state="unavailable" compact
      message={t("backupSettings.loadError")} onRetry={() => void reload()}/>;
  } else {
    const enabled = draft?.enabled ?? settings.enabled;
    const path = enabled ? draft?.path ?? settings.path ?? "" : settings.path ?? "";
    const nextPath = enabled ? path.trim() : settings.path;
    const changed = enabled !== settings.enabled || nextPath !== settings.path;
    const valid = !enabled || validDirectory(path.trim());
    const failure = save.error instanceof ApiResponseError ? save.error : null;
    const conflict = failure?.code === "backup_settings_revision_conflict" || failure?.status === 409;
    const pathError = !valid ? "backupSettings.pathInvalid" : pathErrors.get(failure?.code ?? "");
    const locked = query.isFetching || save.isPending || conflict;
    const storageText = settings.storage_status === "ready" ? "backupSettings.storageReady"
      : settings.storage_status === "unavailable" ? "backupSettings.storageUnavailable" : "backupSettings.storageUnconfigured";
    content = <form className="sli-ds-form" noValidate aria-busy={save.isPending} onSubmit={(event) => {
      event.preventDefault();
      if (!locked && valid && changed) {
        setSaved(false);
        save.mutate({ enabled, path: nextPath, revision: settings.revision });
      }
    }}>
      <div className="sli-ds-form__fields">
        <label><input type="checkbox" checked={enabled} disabled={locked}
          onChange={(event) => edit({ enabled: event.target.checked, path })}/>{" "}
          {t("backupSettings.enabled")}</label>
        <div className="sli-ds-form__row">
          <div className="sli-ds-form__label">
            <label htmlFor="backup-settings-path">{t("backupSettings.path")}</label>
            <p id="backup-settings-path-help">{t("backupSettings.pathHelp")}</p>
          </div>
          <div className="sli-ds-form__value sli-ds-field">
            <input id="backup-settings-path" type="text" autoComplete="off" spellCheck={false} value={path}
              disabled={locked || !enabled} aria-invalid={Boolean(pathError)}
              aria-describedby={pathError ? "backup-settings-path-help backup-settings-path-error" : "backup-settings-path-help"}
              onChange={(event) => edit({ enabled, path: event.target.value })}/>
            {pathError ? <p className="sli-ds-field__error" id="backup-settings-path-error" role="alert">{t(pathError)}</p> : null}
          </div>
        </div>
        <p>{t(settings.enabled ? "backupSettings.savedEnabled" : "backupSettings.savedDisabled")}{" "}
          <span>{t(storageText)}</span></p>
      </div>
      {conflict ? <p role="alert">{t("backupSettings.conflict")}</p> : save.isError && !pathError ?
        <p role="alert">{t(failure?.code === "backup_settings_unavailable" ? "backupSettings.saveUnavailable" : "backupSettings.saveError")}</p> : null}
      <div className="sli-ds-filters__actions">
        <button className="sli-ds-button" data-variant="primary" type="submit" disabled={locked || !changed || !valid}>
          {t(save.isPending ? "platformSettings.saving" : "backupSettings.save")}
        </button>
        {conflict ? <button className="sli-ds-button" type="button" disabled={query.isFetching}
          onClick={() => void reload()}>{t("backupSettings.reload")}</button> : null}
        {saved ? <span role="status">{t("backupSettings.saved")}</span> : null}
      </div>
    </form>;
  }
  return <section id="backup" className="sli-ds-home-section" aria-labelledby="backup-settings-title">
    <h2 id="backup-settings-title" className="sli-ds-section-title">{t("backupSettings.title")}</h2>
    {content}
  </section>;
}
