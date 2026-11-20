import { EMPTY_VALUE } from "../../shared/format";
import { collectionCheckLabel } from "../operations-actions";
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { api, type SourceDetail } from "../../api/client";
import { Badge, DataTable, MetricStrip, PageHeader, StateView, type MetricItem, type TableColumn } from "../../design-system";
import { formatDateTime } from "../../shared/date-time";
import { stateTone } from "../../shared/state-tone";
import { useTimeZone } from "../App";
import { Note } from "./gate";
import { t } from "../../i18n";
import { fixedText } from "../../i18n/fixed-text";

type Disk = SourceDetail["source"]["disks"][number];
type Channel = SourceDetail["channels"][number];

const roleLabel = (value?: string | null) => {
  if (!value) return t("operations.source.role_missing");
  const labels: Record<string, string> = {
    domain_controller: t("operations.source.role_domain_controller"),
    member_server: t("operations.source.role_member_server"),
    standalone_server: t("operations.source.role_standalone_server"),
    workstation: t("operations.source.role_workstation"),
  };
  return labels[value] ?? value.replaceAll("_", " ");
};

/** Неизвестный размер остаётся прочерком, а не «0 Б». */
function formatBytes(value?: number) {
  if (value === undefined || value === null || !Number.isFinite(value) || value < 0) return EMPTY_VALUE;
  const units = [t("operations.source.unit_b"), t("operations.source.unit_kb"), t("operations.source.unit_mb"), t("operations.source.unit_gb"), t("operations.source.unit_tb")];
  let current = value;
  let unit = 0;
  while (current >= 1024 && unit < units.length - 1) { current /= 1024; unit += 1; }
  return `${current >= 10 || unit === 0 ? current.toFixed(0) : current.toFixed(1)} ${units[unit]}`;
}

function diskStateLabel(value: string | null | undefined, count: number) {
  if (value === "ok") return t("operations.source.disk_state_ok", { count });
  if (value === "warning") return t("operations.source.disk_state_warning", { count });
  if (value === "timeout") return t("operations.source.disk_state_timeout");
  if (value === "failed") return t("operations.source.disk_state_failed");
  return t("operations.source.disk_state_pending");
}

export function SourceDetailPage() {
  const { hostname = "" } = useParams({ strict: false }) as { hostname?: string };
  const { timeZone } = useTimeZone();
  const query = useQuery({ queryKey: ["operations", "source", hostname], queryFn: () => api.sourceDetail(hostname), enabled: Boolean(hostname), staleTime: 30_000, retry: false });
  const data = query.data;
  const freshness = data?.collection_freshness;
  const freshnessTone = stateTone(freshness?.state);

  const diskColumns: TableColumn<Disk>[] = [
    { key: "name", label: t("operations.source.col_volume"), render: (disk) => disk.name ?? EMPTY_VALUE },
    { key: "total", label: t("operations.source.col_total"), align: "end", render: (disk) => formatBytes(disk.total_bytes) },
    { key: "free", label: t("operations.source.col_free"), align: "end", render: (disk) => formatBytes(disk.free_bytes) },
    { key: "percent", label: t("operations.source.col_free_percent"), align: "end", render: (disk) => (disk.free_percent === undefined || disk.free_percent === null ? EMPTY_VALUE : `${disk.free_percent}%`) },
  ];
  const channelColumns: TableColumn<Channel>[] = [
    { key: "channel", label: t("operations.source.col_channel"), render: (channel) => channel.channel ?? EMPTY_VALUE },
    { key: "check", label: t("operations.source.col_last_check"), render: (channel) => (formatDateTime(channel.last_successful_collection_utc, timeZone)) },
    { key: "event", label: t("operations.source.col_last_event"), render: (channel) => (formatDateTime(channel.last_event_time_utc, timeZone)) },
    { key: "state", label: t("operations.source.col_state"), render: (channel) => <Badge tone={stateTone(channel.collection_state ?? channel.last_status)}>{collectionCheckLabel(channel)}</Badge> },
  ];

  const metrics: MetricItem[] = data ? [
    { key: "role", label: t("operations.source.fact_role"), value: roleLabel(data.source.role), caption: data.source.fqdn || t("operations.source.fqdn_missing") },
    {
      key: "os", label: t("operations.source.fact_os"), tone: stateTone(data.source.os_name?.trim() ? "ok" : "unknown"),
      value: [data.source.os_name, data.source.os_version].filter(Boolean).join(" ") || t("operations.source.os_missing"),
      caption: data.source.inventory_observed_at_utc ? t("operations.source.ad_snapshot", { time: formatDateTime(data.source.inventory_observed_at_utc, timeZone) }) : data.source.site || t("operations.source.site_missing"),
    },
    { key: "ip", label: t("operations.source.fact_ips"), tone: stateTone(data.source.ip_addresses.length ? "ok" : "unknown"), value: data.source.ip_addresses.length ? data.source.ip_addresses.join(", ") : t("operations.source.not_collected"), caption: t("operations.source.current_contract") },
    {
      key: "disks", label: t("operations.source.fact_disks"), tone: stateTone(data.source.disk_state),
      value: data.source.disks.length ? `${data.source.disks.length}` : t("operations.source.not_collected"),
      caption: diskStateLabel(data.source.disk_state, data.source.disks.length),
    },
  ] : [];

  return <section className="sli-ds-report">
    <PageHeader title={data?.source.hostname ?? (hostname || t("operations.source.title_default"))}
      subtitle={t("operations.source.subtitle")}
      meta={<><Badge tone="accent">{t("operations.source.badge_source")}</Badge> <span>{t("operations.source.badge_readonly")}</span></>}
      actions={<Link className="sli-ds-button" to="/operations">{t("operations.source.back")}</Link>}/>
    {query.isLoading ? <StateView state="loading"/> : null}
    {query.error ? <StateView state="unavailable" detail={query.error.message} onRetry={() => void query.refetch()}/> : null}
    {data ? <>
      <MetricStrip label={t("operations.source.source_details")} items={metrics}/>
      {data.source.disks.length ? <>
        <h2 className="sli-ds-section-title">{t("operations.source.disks_title")}</h2>
        <p className="sli-ds-header__subtitle">{t("operations.source.disks_subtitle")}</p>
        <DataTable columns={diskColumns} rows={data.source.disks} rowKey={(disk) => disk.name ?? "disk"} caption={t("operations.source.disks_caption")}/>
      </> : null}
      <div className="sli-ds-widget__head">
        <h2 className="sli-ds-section-title">{t("operations.source.channels_title")}</h2>
        <Badge tone={freshnessTone}>{freshness?.label ? fixedText(freshness.label, "operations.source.fixed.") : t("operations.source.state_unknown")}</Badge>
      </div>
      <p className="sli-ds-header__subtitle">{t("operations.source.channels_subtitle")}</p>
      {data.channels.length
        ? <DataTable columns={channelColumns} rows={data.channels} rowKey={(channel) => `${channel.server}-${channel.channel}`} caption={t("operations.source.channels_caption")}/>
        : <StateView state="empty" detail={t("operations.source.no_channels")}/>}
      <Note title={t("operations.source.limitations")}><ul>{data.limitations.map((item) => <li key={item}>{fixedText(item, "operations.source.fixed.")}</li>)}</ul></Note>
    </> : null}
  </section>;
}
