import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Dialog, Heading, Modal, ModalOverlay } from "react-aria-components";
import { api, type PlatformSetting, type StorageOverview } from "../../api/client";
import { Button, DataTable, PageHeader, StateView, type TableColumn } from "../../design-system";
import { plural, t } from "../../i18n";
import { formatNumber } from "../../shared/format";
import { formatByteSize, localizeByteSize } from "../../shared/byte-size";
import { formatDateTime } from "../../shared/date-time";
import { useEffectiveAccess, useTimeZone } from "../App";
import { bootstrapEffectiveRole } from "../access-control";

const retentionKey = "ad.snapshot_history_days";
const settingsKey = ["platform-settings"] as const;
const validRetention = (value: string) => /^[0-9]+$/.test(value) && Number(value) >= 7 && Number(value) <= 3650;

function daysLabel(days: number) {
  const count = formatNumber(days, { maximumFractionDigits: 1 });
  return plural(days, {
    one: t("operations.days.one", { count }), few: t("operations.days.few", { count }),
    many: t("operations.days.many", { count }), other: t("operations.days.other", { count }),
  });
}

function DiskTable({ data }: { data: StorageOverview }) {
  const volume = data.storage.postgres_volume;
  // Older responses only report the application disk.
  const legacyDisk = volume === undefined ? data.storage.disk_pressure?.disk : undefined;
  const used = formatByteSize(volume?.used_bytes ?? legacyDisk?.used_bytes) ?? localizeByteSize(legacyDisk?.used_human);
  const free = formatByteSize(volume?.free_bytes ?? legacyDisk?.free_bytes) ?? localizeByteSize(legacyDisk?.free_human);
  const days = volume ? data.storage.postgres_volume_forecast_days : undefined;
  if (volume === undefined && used == null && free == null) return null;
  const columns: TableColumn<{ used: string | null; free: string | null }>[] = [
    ...(used != null ? [{ key: "used", label: t("operations.disk.used"), align: "end" as const }] : []),
    ...(free != null ? [{ key: "free", label: t("operations.disk.free"), align: "end" as const }] : []),
  ];
  return <section id="storage-diagnostics" className="sli-ds-home-section">
    <h2 id="storage-disk-title" className="sli-ds-section-title">{t("operations.disk.title")}</h2>
    {columns.length ? <DataTable columns={columns} rows={[{ used: used ?? null, free: free ?? null }]}
      rowKey={() => "disk"} labelledBy="storage-disk-title" showFooter={false} stickyHeader={false}/>
      : <p>{t("operations.disk.unmeasured")}</p>}
    {typeof days === "number" && Number.isFinite(days) && days >= 0
      ? <p>{t("operations.disk.forecast", { days: daysLabel(Number(days.toFixed(1))) })}</p> : null}
  </section>;
}

function HistoryRetention({ canEdit }: { canEdit: boolean }) {
  const client = useQueryClient();
  const { timeZone } = useTimeZone();
  const [draft, setDraft] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<number>();
  const [saved, setSaved] = useState<Date>();
  const settings = useQuery({ queryKey: settingsKey, queryFn: api.platformSettings });
  const value = settings.data?.items.find((item) => item.key === retentionKey)?.value;
  const change = useMutation({
    mutationFn: (days: string) => api.updatePlatformSetting(retentionKey, days),
    onSuccess: ({ item }) => {
      client.setQueryData<{ items: PlatformSetting[] }>(settingsKey, (current) => current && {
        items: current.items.map((setting) => setting.key === item.key ? item : setting),
      });
      setDraft(null);
      setSaved(new Date());
    },
  });
  if (settings.isError) return <p role="alert">{t("operations.history.loadError")} <Button onClick={() => void settings.refetch()}>{t("state.retry")}</Button></p>;
  if (value === undefined) return null;
  const invalid = draft !== null && !validRetention(draft);
  return <section className="sli-ds-home-section" aria-labelledby="storage-history">
    <h2 id="storage-history" className="sli-ds-section-title">{t("operations.history.title")}</h2>
    {validRetention(value) ? <p>{t("operations.history.retained", { days: daysLabel(Number(value)) })}</p>
      : <p>{t("operations.history.loadError")}</p>}
    {canEdit && draft === null ? <div className="sli-ds-state__actions">
      <Button onClick={() => { setDraft(value); setSaved(undefined); }}>{t("operations.history.edit")}</Button>
    </div> : null}
    {canEdit && draft !== null ? <form className="sli-ds-form" onSubmit={(event) => {
      event.preventDefault();
      const days = Number(draft);
      if (invalid || change.isPending || days === Number(value)) return;
      if (validRetention(value) && days < Number(value)) setConfirming(days);
      else change.mutate(String(days));
    }} noValidate>
      <div className="sli-ds-field" data-layout="row">
        <label htmlFor="storage-history-days">{t("operations.history.days")}</label>
        <input id="storage-history-days" type="number" value={draft} min={7} max={3650} step={1}
          aria-invalid={invalid || change.isError} aria-describedby={invalid || change.isError ? "storage-history-error" : undefined}
          disabled={change.isPending} onChange={(event) => { change.reset(); setDraft(event.target.value); }}/>
      </div>
      {invalid || change.isError ? <p id="storage-history-error" className="sli-ds-field__error" role="alert">
        {t(invalid ? "operations.history.range" : "operations.history.saveError")}
      </p> : null}
      <div className="sli-ds-state__actions">
        <Button type="submit" variant="primary" disabled={invalid || change.isPending || Number(draft) === Number(value)}>{t("operations.settings.save")}</Button>
        <Button disabled={change.isPending} onClick={() => { change.reset(); setDraft(null); }}>{t("platformSettings.cancel")}</Button>
      </div>
    </form> : null}
    <ModalOverlay className="sli-ds-modal" isOpen={canEdit && confirming !== undefined} isDismissable
      onOpenChange={(open) => { if (!open) setConfirming(undefined); }}>
      <Modal className="sli-ds-modal__panel"><Dialog aria-describedby="storage-history-impact">
        <Heading slot="title" level={2}>{t("operations.history.confirmShorten", { days: daysLabel(confirming ?? 0) })}</Heading>
        <p id="storage-history-impact">{t("operations.history.shortenImpact")}</p>
        <Button autoFocus onClick={() => setConfirming(undefined)}>{t("platformSettings.cancel")}</Button>{" "}
        <Button data-danger onClick={() => {
          if (confirming !== undefined) change.mutate(String(confirming));
          setConfirming(undefined);
        }}>{t("operations.history.shorten")}</Button>
      </Dialog></Modal>
    </ModalOverlay>
    {saved ? <p role="status">{t("operations.settings.saved", { time: formatDateTime(saved, timeZone) })}</p> : null}
  </section>;
}

function OperationsContent({ role }: { role: string }) {
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const canReadSettings = !!access?.platform_owner || !!access?.capabilities?.includes("access.manage");
  const canEdit = canReadSettings && role === "admin";
  const storage = useQuery({ queryKey: ["operations-storage"], queryFn: api.storageOverview });
  const backup = storage.data?.storage.footprint?.backups?.last_backup_at_utc;

  return <section className="sli-ds-report">
    <PageHeader title={t("operations.page.title")}/>
    {storage.isLoading ? <StateView state="loading" skeleton="table"/> : storage.isError ? <p role="alert">
      {t("operations.page.unavailable")} <button className="sli-ds-button" onClick={() => void storage.refetch()}>{t("state.retry")}</button>
    </p> : storage.data ? <DiskTable data={storage.data}/> : null}
    {canReadSettings ? <HistoryRetention canEdit={canEdit}/> : null}
    {backup && Number.isFinite(Date.parse(backup)) ? <section className="sli-ds-home-section">
      <h2 id="storage-backup-title" className="sli-ds-section-title">{t("operations.backup.title")}</h2>
      <DataTable columns={[{ key: "last", label: t("operations.backup.last"), render: () => formatDateTime(backup, timeZone) }]}
        rows={[{ key: "backup" }]} rowKey={(row) => row.key} labelledBy="storage-backup-title" showFooter={false} stickyHeader={false}/>
    </section> : null}
    {canEdit && storage.data?.storage.retired_clickhouse_data ? <p>{t("operations.clickhouse.cleanup")} <code>sudo rm -rf -- /srv/sli-db/clickhouse</code></p> : null}
  </section>;
}

/** The server checks operations.view on every request. */
export function OperationsPage() {
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrap, staleTime: 60_000 });
  if (bootstrap.isLoading) return <section className="sli-ds-report"><PageHeader title={t("operations.page.title")}/><StateView state="loading"/></section>;
  const role = bootstrapEffectiveRole(bootstrap.data) ?? "";
  if (!["admin", "operator"].includes(role)) return <section className="sli-ds-report"><PageHeader title={t("operations.page.title")}/><StateView state="denied" detail={t("operations.auth.denied")}/></section>;
  return <OperationsContent role={role}/>;
}
