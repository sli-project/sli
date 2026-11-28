import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t } from "../../i18n";
import { formatDateTime } from "../../design-system";
import { formatDateTime as formatZonedDateTime } from "../../shared/date-time";
import { useTimeZone } from "../../shared/time-zone";

type Row = Record<string, unknown>;
const object = (value: unknown): Row => value && typeof value === "object" ? value as Row : {};
const text = (value: unknown) => typeof value === "string" && value.trim() ? value : null;

export function dnsColumnLabel(rows: Row[], timeZone?: string) {
  const dates = [...new Set(rows.map((row) => text(object(row.dns_ip).observed_at_utc)).filter((at): at is string => Boolean(at)).map((at) => formatDateTime(at, false, timeZone)))];
  return dates.length === 1 ? t("reports.ad.additions.dns_on", { date: dates[0] }) : t("reports.ad.additions.dns_label");
}

export function formatAgentStatus(row: Row, timeZone: string): string {
  const agent = object(row.sli_agent);
  const state = agent.state;
  if (state === "absent") return t("reports.ad.additions.agent.absent");
  if (state !== "installed" && state !== "silent") return t("table.noValue");
  const stamp = text(agent.last_seen_utc);
  const label = stamp
    ? t(state === "silent" ? "reports.computers.agent_silent" : "reports.computers.agent_connected", { time: formatZonedDateTime(stamp, timeZone, { withYear: false }) })
    : t(state === "silent" ? "reports.ad.additions.agent.silent" : "reports.computers.registered");
  return [text(agent.version), label].filter(Boolean).join(" · ");
}

export function AgentStatus({ row }: { row: Row }) {
  const { timeZone } = useTimeZone();
  return formatAgentStatus(row, timeZone);
}

export function DnsIp({ row }: { row: Row }) {
  const { formatDateTime } = useDateFormatters();
  const dns = object(row.dns_ip);
  const at = text(dns.observed_at_utc);
  const addresses = Array.isArray(dns.addresses) ? dns.addresses.filter((value): value is string => typeof value === "string") : [];
  return <span>{addresses.length && at ? addresses.join(", ") : t("table.noValue")}
    {at ? <small className="sli-ds-muted" style={{ display: "block" }}>{t("reports.ad.additions.dns_at", { date: formatDateTime(at) })}</small> : null}</span>;
}

export function LastWorkplace({ row, compact = false }: { row: Row; compact?: boolean }) {
  const { formatDateTime } = useDateFormatters();
  const workplace = object(row.last_workplace);
  const computer = text(workplace.computer);
  const at = text(workplace.at_utc);
  const params = new URLSearchParams();
  if (row.sam) params.set("user", String(row.sam));
  if (row.domain_id != null) params.set("domain_id", String(row.domain_id));
  const missing = t("table.noValue");
  const kind = workplace.kind === "rdp" ? t("reports.ad.additions.rdp") : workplace.kind === "local" ? t("reports.ad.additions.local_logon") : missing;
  const timeAndKind = at ? `${formatDateTime(at)} · ${kind}` : null;
  const logons = row.sam ? t("reports.ad.additions.all_user_logons") : null;
  const title = [computer && timeAndKind ? `${computer} · ${timeAndKind}` : missing, logons].filter(Boolean).join(" · ");
  return <span className={compact ? "sli-ds-table__cell-line" : undefined} title={compact ? title : undefined}>
    <span>{computer && timeAndKind ? <>{typeof workplace.computer_id === "number" && workplace.computer_id > 0
      ? <a href={`/app/entities/${workplace.computer_id}`} onClick={(event) => event.stopPropagation()}>{computer}</a> : computer} · {timeAndKind}</> : missing}</span>
    {logons ? <a style={compact ? undefined : { display: "block" }} href={`/app/report/ad.computer-logons?${params}`} onClick={(event) => event.stopPropagation()}>{logons}</a> : null}
  </span>;
}
