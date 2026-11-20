import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t } from "../../i18n";
import { formatDateTime } from "../../design-system";

type Row = Record<string, unknown>;
const object = (value: unknown): Row => value && typeof value === "object" ? value as Row : {};
const text = (value: unknown) => typeof value === "string" && value.trim() ? value : null;

export function dnsColumnLabel(rows: Row[], timeZone?: string) {
  const dates = [...new Set(rows.map((row) => text(object(row.dns_ip).observed_at_utc)).filter((at): at is string => Boolean(at)).map((at) => formatDateTime(at, false, timeZone)))];
  return dates.length === 1 ? t("reports.ad.additions.dns_on", { date: dates[0] }) : t("reports.ad.additions.dns_label");
}

export function AgentStatus({ row, compact = false }: { row: Row; compact?: boolean }) {
  const agent = object(row.sli_agent);
  const state = agent.state;
  const missing = t("reports.metrics.no_data");
  if (compact) return state === "absent" || state === "silent"
    ? <span role="img" aria-label={t(`reports.ad.additions.agent.${state}`)} title={t(`reports.ad.additions.agent.${state}`)}> ⚠</span> : null;
  if (state === "absent") return <>{t("reports.ad.additions.agent.absent")}</>;
  if (state !== "installed" && state !== "silent") return <span title={t("reports.ad.additions.agent.unknown_reason")}>{missing}</span>;
  const age = typeof agent.age_seconds === "number" ? agent.age_seconds : null;
  return <span>{state === "silent"
    ? t("reports.ad.additions.agent.silent_days", { count: age === null ? missing : Math.floor(age / 86400) })
    : t("reports.ad.additions.agent.installed")}
    {" · "}{text(agent.version) ?? missing}
    {state === "installed" ? <> · {age === null ? missing : t("reports.ad.additions.agent.signal_minutes", { count: Math.floor(age / 60) })}</> : null}</span>;
}

export function DnsIp({ row }: { row: Row }) {
  const { formatDateTime } = useDateFormatters();
  const dns = object(row.dns_ip);
  const at = text(dns.observed_at_utc);
  const addresses = Array.isArray(dns.addresses) ? dns.addresses.filter((value): value is string => typeof value === "string") : [];
  return <span>{addresses.length && at ? addresses.join(", ") : t("reports.metrics.no_data")}
    {at ? <small className="sli-ds-muted" style={{ display: "block" }}>{t("reports.ad.additions.dns_at", { date: formatDateTime(at) })}</small> : null}</span>;
}

export function LastWorkplace({ row }: { row: Row }) {
  const { formatDateTime } = useDateFormatters();
  const workplace = object(row.last_workplace);
  const computer = text(workplace.computer);
  const at = text(workplace.at_utc);
  const params = new URLSearchParams();
  if (row.sam) params.set("user", String(row.sam));
  if (row.domain_id != null) params.set("domain_id", String(row.domain_id));
  return <span>{computer && at ? <>{typeof workplace.computer_id === "number" && workplace.computer_id > 0
    ? <a href={`/app/entities/${workplace.computer_id}`} onClick={(event) => event.stopPropagation()}>{computer}</a> : computer} · {formatDateTime(at)} · {workplace.kind === "rdp" ? t("reports.ad.additions.rdp") : workplace.kind === "local" ? t("reports.ad.additions.local_logon") : t("reports.metrics.no_data")}</> : t("reports.metrics.no_data")}
    {row.sam ? <a style={{ display: "block" }} href={`/app/report/ad.computer-logons?${params}`} onClick={(event) => event.stopPropagation()}>{t("reports.ad.additions.all_user_logons")}</a> : null}</span>;
}
