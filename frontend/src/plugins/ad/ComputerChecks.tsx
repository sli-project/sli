import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { ReportState } from "../../app/report-v2/ReportState";
import { formatNumber } from "../../shared/format";
import { useTimeZone } from "../../shared/time-zone";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { Button, DataTable, type TableColumn } from "../../design-system";
import { ReviewList, type ReviewItem } from "../../design-system/ReviewList";
import type { ReportResultDto } from "../../api/report-v2-types";
import { t } from "../../i18n";
import { DnsIp, dnsColumnLabel, formatAgentStatus } from "./ReportAdditions";
import { ComputerGpoPlan } from "./GpoPlan";

type Row = Record<string, unknown>;
type ComputerPreview = Row & { name: string | null; domain_name: string | null; computer_type: string | null };
type Check = {
  key: string; title: string; severity: string; status: string | null;
  total: number | null; newCount: number | null; remaining: number;
  why: string | null; action: string | null; observed: string | null; actor: string | null;
  objects: ComputerPreview[];
};
const text = (value: unknown) => typeof value === "string" && value.trim() ? value : null;
const count = (value: unknown) => typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;

export function computerRole(value: unknown) {
  return value === "domain_controller" ? t("reports.v2.ad.computers.v6.columns.computer_type.labels.domain_controller")
    : value === "server" ? t("reports.v2.ad.computers.v6.columns.computer_type.labels.server")
    : value === "workstation" ? t("reports.v2.ad.computers.v6.columns.computer_type.labels.workstation")
    : t("table.noValue");
}

/** Only saved agent facts enter this view model; null counts are never zero. */
function checkModel(row: Row): Check {
  const change = row.change && typeof row.change === "object" ? row.change as Row : {};
  return {
    key: text(row.key) ?? String(row.id), title: text(row.title) ?? t("table.noValue"),
    severity: text(row.severity) ?? "unknown",
    status: row.status === "no_comparison" || row.status === "not_evaluated" || row.status_text === t("reports.ad.checks.status.not_evaluated")
      ? null : text(row.status_text),
    total: count(row.total), newCount: count(row.new_count),
    remaining: count(row.remaining_objects) ?? 0,
    why: text(row.why), action: text(row.action), observed: text(row.last_seen_utc), actor: text(change.actor),
    objects: (Array.isArray(row.objects) ? row.objects : []).filter((obj): obj is Row => Boolean(obj) && typeof obj === "object")
      .map(computerPreview),
  };
}

function computerPreview(row: Row): ComputerPreview {
  return { ...row, name: text(row.name), domain_name: text(row.domain_name), computer_type: text(row.computer_type) };
}

function CheckObjects({ check, onSelect, params }: { check: Check; onSelect: (row: Row) => void; params: string }) {
  const [full, setFull] = useState(false);
  const { timeZone } = useTimeZone();
  const matches = useInfiniteQuery({
    queryKey: ["report-v2", "computer-check-matches", check.key, params],
    enabled: full,
    queryFn: ({ pageParam }) => {
      const request = new URLSearchParams(params);
      request.set("tab", "checks");
      request.set("check", check.key);
      request.set("limit", "50");
      request.delete("sort");
      request.delete("direction");
      if (pageParam) request.set("cursor", pageParam);
      return api.reportV2Data("ad.computers.v6", request);
    },
    initialPageParam: null as string | null,
    getNextPageParam: (page) => page.has_more ? page.next_cursor : null,
    retry: false,
  });
  const page = matches.data?.pages[0];
  const rows = full && page ? matches.data!.pages.flatMap((item) => item.items.map(computerPreview)) : check.objects;
  const columns: TableColumn<ComputerPreview>[] = [
      { key: "name", label: t("reports.v2.ad.computers.v6.columns.display_name.label"), render: (obj) => <>
        <button type="button" className="sli-ds-button" data-variant="ghost" onClick={() => onSelect({ ...obj, display_name: obj.name,
          account_state: obj.enabled === true ? "enabled" : obj.enabled === false ? "disabled" : "unknown",
          reasons: [{ label: check.title }] })}>{obj.name ?? t("table.noValue")}</button>
        <div className="sli-ds-muted">{obj.domain_name ?? t("table.noValue")}</div>
      </> },
      { key: "computer_type", label: t("reports.ad.computers.role"), render: (obj) => computerRole(obj.computer_type) },
      { key: "dns_ip", label: dnsColumnLabel(rows, timeZone), render: (obj) =>
        (obj.dns_ip as { addresses?: unknown[] } | undefined)?.addresses?.length ? <DnsIp row={obj}/> : t("table.noValue"), mobile: false },
      { key: "sli_agent", label: t("reports.ad.additions.agent_label"), render: (obj) => formatAgentStatus(obj, timeZone), mobile: false },
      { key: "observed_at_utc", label: t("reports.ad.computers.last_seen"), kind: "datetime", mobile: false },
    ];
  if (full && matches.isLoading) return <ReportState state="loading"/>;
  if (page?.state === "denied") return <ReportState state="denied"/>;
  if (matches.isError || page?.state === "error")
    return <ReportState state="error" subject={check.title} onRetry={() => void matches.refetch()}/>;
  return <>
    {rows.length ? <DataTable caption={check.title} columns={columns} rows={rows}
      rowKey={(obj) => String(obj.entity_id ?? `${obj.domain_id}:${obj.name}`)} stickyHeader={false}
      showFooter={full && Boolean(matches.hasNextPage)} hasMore={matches.hasNextPage}
      loadingMore={matches.isFetchingNextPage} onLoadMore={() => void matches.fetchNextPage()}/> : null}
    {!full && check.remaining > 0 && check.total !== null ?
      <Button onClick={() => setFull(true)}>{t("reports.ad.computers.show_matches", { count: formatNumber(check.total) })}</Button> : null}
  </>;
}

export function ComputerChecks({ result, onSelect, params }: {
  result?: ReportResultDto; onSelect: (row: Row) => void; params: string;
}) {
  const { formatDateTime } = useDateFormatters();
  const checks = (result?.items ?? []).filter((row) => row.section !== "not_evaluated").map(checkModel)
    .filter((check) => check.status !== null || check.total !== null || check.newCount !== null);
  const item = (check: Check): ReviewItem => ({
    key: check.key, title: check.title, severity: check.severity,
    status: check.status ?? formatDateTime(check.observed ?? text(result?.coverage.observed_at_utc)),
    total: check.total, newCount: check.newCount,
    detail: <>
      {check.why ? <p>{check.why}</p> : null}
      {check.action ? <p>{check.action}</p> : null}
      {check.key === "no_sli_agent" ? <ComputerGpoPlan rows={check.objects}/> : null}
      {check.actor ? <p className="sli-ds-muted">{t("reports.ad.computers.actor")}: {check.actor}</p> : null}
      <CheckObjects check={check} onSelect={onSelect} params={params}/>
    </>,
  });
  const hygiene = checks.filter((check) => check.severity === "low");
  return <>
    <ReviewList compact items={checks.filter((check) => check.severity !== "low").map(item)}/>
    {hygiene.length ? <details><summary>{t("reports.ad.checks.hygiene")} · {t("reports.ad.computers.more_checks", { count: hygiene.length })}</summary><ReviewList compact items={hygiene.map(item)}/></details> : null}
  </>;
}
