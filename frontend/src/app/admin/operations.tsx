import { useQuery } from "@tanstack/react-query";
import { api, type StorageOverview, type StorageGrowth } from "../../api/client";
import { DataTable, PageHeader, StateView, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { EMPTY_VALUE, formatNumber } from "../../shared/format";
import { formatByteSize, localizeByteSize } from "../../shared/byte-size";
import { formatDateTime } from "../../shared/date-time";
import { useEffectiveAccess, useTimeZone } from "../App";
import { bootstrapEffectiveRole } from "../access-control";

type DiskRow = { key: string; label: string; used?: string | null; free?: string | null; growth?: string | null; days?: number | null };
const hasSize = (value: string | null | undefined) => typeof value === "string" && value.trim().length > 0;

function DiskTable({ data, growth }: { data: StorageOverview; growth?: StorageGrowth }) {
  const components = data.storage.footprint?.components ?? [];
  const database = components.find((item) => item.key === "postgres_database");
  const volume = data.storage.postgres_volume;
  const volumeFree = formatByteSize(volume?.free_bytes);
  // Older responses without a PostgreSQL volume field describe only the application disk.
  const disk = volume === undefined ? data.storage.disk_pressure?.disk : undefined;
  const measured = growth?.measured_growth?.components;
  const daily = (key: "database_bytes" | "disk_used_bytes") => {
    const value = measured?.[key];
    return value && Number.isFinite(value.bytes_per_day) && hasSize(value.per_day_human)
      ? `${value.bytes_per_day < 0 ? "−" : ""}${localizeByteSize(value.per_day_human)}` : null;
  };
  const rows: DiskRow[] = [
    { key: "database", label: t("operations.disk.database"), used: formatByteSize(database?.bytes) ?? localizeByteSize(database?.human),
      free: volumeFree, growth: daily("database_bytes") },
    { key: "disk", label: volume ? t("operations.disk.postgresVolume", { mount: volume.mount_point }) : t("operations.disk.partition"),
      used: volume ? formatByteSize(volume.used_bytes) : formatByteSize(disk?.used_bytes) ?? localizeByteSize(disk?.used_human),
      free: volume ? volumeFree : formatByteSize(disk?.free_bytes) ?? localizeByteSize(disk?.free_human),
      growth: disk ? daily("disk_used_bytes") : null, days: disk ? growth?.forecast?.estimated_days : null },
  ];
  const used = rows.some((row) => hasSize(row.used));
  const free = rows.some((row) => hasSize(row.free));
  const hasGrowth = rows.some((row) => hasSize(row.growth));
  const hasDays = rows.some((row) => typeof row.days === "number" && Number.isFinite(row.days));
  if (!used && !free && !hasGrowth && !hasDays) return null;
  const columns: TableColumn<DiskRow>[] = [
    { key: "label", label: t("operations.disk.what") },
    ...(used ? [{ key: "used", label: t("operations.disk.used"), align: "end" as const,
      render: (row: DiskRow) => hasSize(row.used) ? row.used : EMPTY_VALUE }] : []),
    ...(free ? [{ key: "free", label: t("operations.disk.free"), align: "end" as const,
      render: (row: DiskRow) => hasSize(row.free) ? row.free : EMPTY_VALUE }] : []),
    ...(hasGrowth ? [{ key: "growth", label: t("operations.disk.growth"), align: "end" as const,
      render: (row: DiskRow) => hasSize(row.growth) ? row.growth : EMPTY_VALUE }] : []),
    ...(hasDays ? [{ key: "days", label: t("operations.disk.days"), align: "end" as const,
      render: (row: DiskRow) => formatNumber(row.days) }] : []),
  ];
  return <section id="storage-diagnostics" className="sli-ds-home-section">
    <h2 id="storage-disk-title" className="sli-ds-section-title">{t("operations.disk.title")}</h2>
    <DataTable columns={columns} rows={rows} rowKey={(row) => row.key} labelledBy="storage-disk-title" showFooter={false} stickyHeader={false}/>
  </section>;
}

function OperationsContent({ role }: { role: string }) {
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const canReadSettings = !!access?.platform_owner || !!access?.capabilities?.includes("access.manage");
  const canEdit = canReadSettings && role === "admin";
  const storage = useQuery({ queryKey: ["operations-storage"], queryFn: api.storageOverview });
  const growth = useQuery({ queryKey: ["operations-storage-growth"], queryFn: api.storageGrowth });
  const backup = storage.data?.storage.footprint?.backups?.last_backup_at_utc;

  return <section className="sli-ds-report">
    <PageHeader title={t("operations.page.title")}/>
    {storage.isLoading ? <StateView state="loading" skeleton="table"/> : storage.isError ? <p role="alert">
      {t("operations.page.unavailable")} <button className="sli-ds-button" onClick={() => void storage.refetch()}>{t("state.retry")}</button>
    </p> : storage.data ? <DiskTable data={storage.data} growth={growth.data}/> : null}
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
