import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type PlatformSetting, type StorageOverview, type StorageGrowth } from "../../api/client";
import { DataTable, PageHeader, StateView, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { EMPTY_VALUE, formatNumber } from "../../shared/format";
import { localizeByteSize } from "../../shared/byte-size";
import { formatDateTime, isValidTimeZone, zonedParts } from "../../shared/date-time";
import { useEffectiveAccess, useTimeZone } from "../App";
import { bootstrapEffectiveRole } from "../access-control";

type DiskRow = { key: string; label: string; used?: string | null; free?: string | null; growth?: string | null; days?: number | null };
const hasSize = (value: string | null | undefined) => typeof value === "string" && value.trim().length > 0;

function DiskTable({ data, growth }: { data: StorageOverview; growth?: StorageGrowth }) {
  const components = data.storage.footprint?.components ?? [];
  const database = components.find((item) => item.key === "postgres_database");
  const disk = data.storage.disk_pressure?.disk;
  const measured = growth?.measured_growth?.components;
  const daily = (key: "database_bytes" | "disk_used_bytes") => {
    const value = measured?.[key];
    return value && Number.isFinite(value.bytes_per_day) && hasSize(value.per_day_human)
      ? `${value.bytes_per_day < 0 ? "−" : ""}${localizeByteSize(value.per_day_human)}` : null;
  };
  const rows: DiskRow[] = [
    { key: "database", label: t("operations.disk.database"), used: database?.human, growth: daily("database_bytes") },
    { key: "disk", label: t("operations.disk.partition"), used: disk?.used_human, free: disk?.free_human, growth: daily("disk_used_bytes"), days: growth?.forecast?.estimated_days },
  ];
  const used = rows.some((row) => hasSize(row.used));
  const free = rows.some((row) => hasSize(row.free));
  const hasGrowth = rows.some((row) => hasSize(row.growth));
  const hasDays = rows.some((row) => typeof row.days === "number" && Number.isFinite(row.days));
  if (!used && !free && !hasGrowth && !hasDays) return null;
  const columns: TableColumn<DiskRow>[] = [
    { key: "label", label: t("operations.disk.what") },
    ...(used ? [{ key: "used", label: t("operations.disk.used"), align: "end" as const,
      render: (row: DiskRow) => hasSize(row.used) ? localizeByteSize(row.used) : EMPTY_VALUE }] : []),
    ...(free ? [{ key: "free", label: t("operations.disk.free"), align: "end" as const,
      render: (row: DiskRow) => hasSize(row.free) ? localizeByteSize(row.free) : EMPTY_VALUE }] : []),
    ...(hasGrowth ? [{ key: "growth", label: t("operations.disk.growth"), align: "end" as const,
      render: (row: DiskRow) => hasSize(row.growth) ? localizeByteSize(row.growth) : EMPTY_VALUE }] : []),
    ...(hasDays ? [{ key: "days", label: t("operations.disk.days"), align: "end" as const,
      render: (row: DiskRow) => formatNumber(row.days) }] : []),
  ];
  return <section id="storage-diagnostics" className="sli-ds-home-section">
    <h2 className="sli-ds-section-title">{t("operations.disk.title")}</h2>
    <DataTable columns={columns} rows={rows} rowKey={(row) => row.key} caption={t("operations.disk.title")} showFooter={false} stickyHeader={false}/>
  </section>;
}

function OperationsContent({ role }: { role: string }) {
  const client = useQueryClient();
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const canReadSettings = !!access?.platform_owner || !!access?.capabilities?.includes("access.manage");
  const storage = useQuery({ queryKey: ["operations-storage"], queryFn: api.storageOverview });
  const growth = useQuery({ queryKey: ["operations-storage-growth"], queryFn: api.storageGrowth });
  const health = useQuery({ queryKey: ["operations-health"], queryFn: api.systemHealth, refetchInterval: 10_000 });
  const catchup = health.data?.password_catchup;
  const settings = useQuery({ queryKey: ["platform-settings"], queryFn: api.platformSettings, enabled: canReadSettings });
  const retention = settings.data?.items.find((item) => item.key === "ad.snapshot_history_days");
  const backup = storage.data?.storage.footprint?.backups?.last_backup_at_utc;
  const canEdit = canReadSettings && role === "admin";
  const [edited, setEdited] = useState<string | null>(null);
  const [savedAt, setSavedAt] = useState<Date | null>(null);
  const value = edited ?? retention?.value ?? "";
  const valid = /^\d+$/.test(value) && Number(value) >= 7 && Number(value) <= 3650;
  const changed = !!retention && value !== retention.value;
  const save = useMutation({
    mutationFn: () => api.updatePlatformSetting("ad.snapshot_history_days", value),
    onSuccess: ({ item }) => {
      client.setQueryData<{ items: PlatformSetting[] }>(["platform-settings"], (previous) => previous
        ? { items: previous.items.map((old) => old.key === "ad.snapshot_history_days" ? item : old) } : previous);
      setEdited(null); setSavedAt(new Date());
    },
  });
  const field = "storage-retention-days";
  const error = !valid ? t("platformSettings.ad_history.validation") : save.isError ? t("operations.retention.saveError") : null;
  const time = savedAt && (timeZone === "browser" || isValidTimeZone(timeZone))
    ? `${zonedParts(savedAt, timeZone).hour}:${zonedParts(savedAt, timeZone).minute}` : EMPTY_VALUE;

  return <section className="sli-ds-report">
    <PageHeader title={t("operations.page.title")} actions={canEdit && retention ? <button form="storage-retention" type="submit" className="sli-ds-button" data-variant="primary" disabled={!changed || !valid || save.isPending}>{t("platformSettings.save")}</button> : null}/>
    {catchup ? <p role="status">{t("operations.passwordCatchup", { from: formatDateTime(catchup.from, timeZone), to: formatDateTime(catchup.to, timeZone), cursor: formatDateTime(catchup.cursor, timeZone) })}</p> : null}
    {health.isError ? <p role="alert">{t("operations.passwordCatchupError")} <button className="sli-ds-button" onClick={() => void health.refetch()}>{t("state.retry")}</button></p> : null}
    {storage.isLoading ? <StateView state="loading" skeleton="table"/> : storage.isError ? <p role="alert">
      {t("operations.page.unavailable")} <button className="sli-ds-button" onClick={() => void storage.refetch()}>{t("state.retry")}</button>
    </p> : storage.data ? <DiskTable data={storage.data} growth={growth.data}/> : null}
    {retention ? <section className="sli-ds-home-section">
    <h2 className="sli-ds-section-title">{t("operations.retention.title")}</h2>
    <form id="storage-retention" onSubmit={(event) => { event.preventDefault(); if (canEdit && changed && valid && !save.isPending) save.mutate(); }}>
      <DataTable columns={[
        { key: "what", label: t("operations.retention.what"), render: () => <label htmlFor={field}>{t("operations.retention.adHistory")}</label> },
        { key: "days", label: t("operations.retention.days"), render: () => <div className="sli-ds-field" style={{ gridTemplateColumns: "6rem auto", alignItems: "center" }}>
          {canEdit ? <input id={field} type="number" min={7} max={3650} step={1} value={value} disabled={save.isPending}
            aria-invalid={!!error} aria-describedby={error ? `${field}-error` : undefined}
            onChange={(event) => { setEdited(event.target.value); setSavedAt(null); save.reset(); }}/>
            : <span>{retention.value}</span>}
          <span>{t("operations.retention.default", { days: 365 })}</span>
          {error ? <span id={`${field}-error`} role="alert" className="sli-ds-field__error" style={{ gridColumn: "1 / -1" }}>{error}</span> : null}
        </div> },
      ]} rows={[retention]} rowKey={(row) => row.key} caption={t("operations.retention.title")} showFooter={false} stickyHeader={false}/>
      {savedAt ? <p role="status">{t("operations.retention.saved", { time })}</p> : null}
    </form>
    </section> : null}
    {canReadSettings && settings.isError ? <p role="alert">{t("operations.retention.loadError")} <button className="sli-ds-button" onClick={() => void settings.refetch()}>{t("state.retry")}</button></p> : null}
    {backup && Number.isFinite(Date.parse(backup)) ? <section className="sli-ds-home-section">
      <h2 className="sli-ds-section-title">{t("operations.backup.title")}</h2>
      <DataTable columns={[{ key: "last", label: t("operations.backup.last"), render: () => formatDateTime(backup, timeZone) }]}
        rows={[{ key: "backup" }]} rowKey={(row) => row.key} caption={t("operations.backup.title")} showFooter={false} stickyHeader={false}/>
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
