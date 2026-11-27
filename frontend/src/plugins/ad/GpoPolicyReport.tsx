import { useLayoutEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { DataTable, FilterChip, ReportLayout, type TableColumn } from "../../design-system";
import { Icon } from "../../design-system/Icon";
import "../../design-system/split-report.css";
import { t } from "../../i18n";
import { withReturnTo } from "../../app/report-v2/legacy";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { FirstAdSource, isEmptyFirstAdReportResult, useFirstAdSource } from "../../app/first-ad-source";
import { GpoPolicyCard, hasMismatch, versionPair, type PolicyRow, type PolicyTab } from "./GpoPolicyCard";

const caption = () => t("reports.gpo.title");
const reportPath = "/app/report/ad.gpo.v2";
const pageSizes = [25, 50, 100, 200];
const inventoryParams = (domain: string) => new URLSearchParams({ tab: "gpos", view: "all", ...(domain ? { domain } : {}) });
const reportAddress = (params: URLSearchParams) => params.size ? reportPath + "?" + params.toString() : reportPath;

function backAddress(params: URLSearchParams, domain: string) {
  const saved = params.get("return_to");
  if (saved?.startsWith(reportPath + "?")) {
    const address = new URL(saved, window.location.origin);
    if (address.pathname === reportPath && !["policy", "policy_id", "snapshot"].some((key) => address.searchParams.has(key))) return saved;
  }
  return reportAddress(domain ? new URLSearchParams({ domain }) : new URLSearchParams());
}

export function GpoPolicyReport({ definition, search }: { definition: ReportDefinitionDto; search?: string }) {
  const params = new URLSearchParams(search ?? window.location.search);
  const domain = params.get("domain") ?? params.get("domain_id") ?? "";
  const denied = definition.access?.allowed === false || definition.views.find((view) => view.key === "gpos")?.access?.allowed === false;
  if (denied) return <ReportDenied reportKey={definition.key} page/>;
  if (params.has("policy") || params.has("policy_id") || params.has("snapshot")) return <GpoPolicyCard
    key={[domain, params.get("policy") ?? params.get("policy_id"), params.get("snapshot")].join(":")} definition={definition} domain={domain}
    initial={params} backHref={backAddress(params, domain)}/>;
  return <PolicyInventory key={domain} definition={definition} domain={domain} initial={params}/>;
}

function PolicyInventory({ definition, domain, initial }: { definition: ReportDefinitionDto; domain: string; initial: URLSearchParams }) {
  const [search, setSearch] = useState(initial.get("q") ?? "");
  const [mismatch, setMismatch] = useState(["version_mismatch", "unlinked_version_mismatch"].includes(initial.get("view") ?? ""));
  const [unlinked, setUnlinked] = useState(["unlinked", "unlinked_version_mismatch"].includes(initial.get("view") ?? ""));
  const [direction, setDirection] = useState<"asc" | "desc">(initial.get("direction") === "asc" ? "asc" : "desc");
  const initialSize = Number(initial.get("page_size"));
  const [pageSize, setPageSize] = useState(pageSizes.includes(initialSize) ? initialSize : 50);
  const [page, setPage] = useState(() => /^\d{1,6}$/.test(initial.get("page") ?? "") ? Math.max(1, Number(initial.get("page"))) : 1);
  const focusId = initial.get("focus");
  const restoreLink = useRef<HTMLAnchorElement>(null);
  const restored = useRef(false);
  const list = useRef<HTMLDivElement>(null);
  const data = useQuery({
    queryKey: ["report-v2", "gpo-inventory", domain],
    queryFn: () => api.reportV2Data(definition.key, inventoryParams(domain)),
    staleTime: 60_000, retry: false, refetchOnWindowFocus: false,
  });
  const policies = (data.data?.items ?? []) as PolicyRow[];
  const snapshotDomain = data.data?.coverage.domain_id;
  const effectiveDomain = domain || (typeof snapshotDomain === "number" ? String(snapshotDomain) : "");
  const snapshot = data.data?.coverage.snapshot_id;
  const text = search.trim().toLocaleLowerCase();
  const visible = useMemo(() => policies.filter((row) => [row.display_name, row.guid].some((value) => value?.toLocaleLowerCase().includes(text))), [policies, text]);
  const rows = visible.filter((row) => (!mismatch || hasMismatch(row)) && (!unlinked || row.unlinked)).sort((left, right) => {
    const leftTime = Date.parse(left.modification_time ?? "");
    const rightTime = Date.parse(right.modification_time ?? "");
    if (Number.isNaN(leftTime)) return Number.isNaN(rightTime) ? 0 : 1;
    if (Number.isNaN(rightTime)) return -1;
    return direction === "desc" ? rightTime - leftTime : leftTime - rightTime;
  });
  const currentPage = Math.min(page, Math.max(1, Math.ceil(rows.length / pageSize)));
  const start = (currentPage - 1) * pageSize;
  const scrollBox = () => list.current?.querySelector<HTMLElement>(".sli-ds-table__scroll");
  useLayoutEffect(() => {
    if (restored.current || !data.isSuccess || !focusId) return;
    restored.current = true;
    restoreLink.current?.focus({ preventScroll: true });
    const box = scrollBox();
    if (box) box.scrollTop = Number(initial.get("table_scroll")) || 0;
    if (initial.has("scroll")) window.scrollTo(0, Number(initial.get("scroll")) || 0);
  }, [data.isSuccess, focusId, initial]);

  const view = mismatch ? unlinked ? "unlinked_version_mismatch" : "version_mismatch" : unlinked ? "unlinked" : "all";
  const detailHref = (row: PolicyRow, tab: PolicyTab, captureScroll = false) => {
    const back = new URLSearchParams({ view, direction, page: String(currentPage), page_size: String(pageSize), focus: row.guid! });
    if (effectiveDomain) back.set("domain", effectiveDomain);
    if (search.trim()) back.set("q", search);
    if (captureScroll) {
      back.set("scroll", String(window.scrollY));
      back.set("table_scroll", String(scrollBox()?.scrollTop ?? 0));
    }
    return withReturnTo(reportAddress(new URLSearchParams({
      domain: effectiveDomain, policy: row.guid!, detail_tab: tab,
    })), reportAddress(back));
  };
  const canOpen = (row: PolicyRow) => Boolean(effectiveDomain && row.guid);
  const capturedLink = (row: PolicyRow, tab: PolicyTab, element: HTMLAnchorElement) => {
    element.setAttribute("href", detailHref(row, tab, true));
  };
  const jump = (row: PolicyRow, target: PolicyTab, count?: number | null) => count == null ? "—" : count === 0 ? count :
    !canOpen(row) ? count : <a className="sli-ds-text-button" href={detailHref(row, target)}
      aria-label={t(target === "settings" ? "reports.gpo.open_settings" : "reports.gpo.open_links", { name: row.display_name, count })}
      onClick={(event) => capturedLink(row, target, event.currentTarget)}>{count}</a>;
  const columns: TableColumn<PolicyRow>[] = [
    { key: "display_name", label: t("reports.gpo.policy"), render: (row) => <span className="sli-ds-cell-with-icon"><Icon name="report"/>
      {canOpen(row) ? <a ref={row.guid === focusId || row.id === focusId ? restoreLink : undefined} href={detailHref(row, "settings")}
        onClick={(event) => capturedLink(row, "settings", event.currentTarget)}>{row.display_name ?? "—"}</a> : row.display_name ?? "—"}
    </span> },
    { key: "setting_count", label: t("reports.gpo.setting_count"), kind: "number", width: "8rem", render: (row) => jump(row, "settings", row.setting_count) },
    { key: "side_count", label: t("reports.gpo.side_count"), wideOnly: true, width: "14rem",
      render: (row) => row.computer_setting_count == null && row.user_setting_count == null ? "—" : `${row.computer_setting_count ?? "—"} / ${row.user_setting_count ?? "—"}` },
    { key: "link_count", label: t("reports.gpo.links"), kind: "number", width: "6rem", render: (row) => jump(row, "links", row.link_count) },
    { key: "versions", label: t("reports.gpo.version_pair"), width: "13rem", render: (row) => versionPair(row, hasMismatch(row, "user") && !hasMismatch(row, "computer") ? "user" : "computer", effectiveDomain) },
    { key: "owner", label: t("reports.gpo.owner"), width: "15rem" },
    { key: "modification_time", label: t("reports.gpo.modified"), kind: "datetime", width: "13rem", sortable: true },
  ];
  const firstAdSource = useFirstAdSource(initial, initial.size === 0 && !effectiveDomain && !snapshot
    && !text && !mismatch && !unlinked && data.isSuccess && !data.isFetching && isEmptyFirstAdReportResult(data.data));
  const denied = data.data?.state === "denied" || data.error instanceof ApiResponseError && [401, 403].includes(data.error.status);
  if (denied) return <ReportDenied reportKey={definition.key} page/>;
  const failed = data.isError || data.data?.state === "error";
  const exportParams = inventoryParams(effectiveDomain);
  exportParams.set("view", view);
  exportParams.set("sort", "modified");
  exportParams.set("direction", direction);
  if (search.trim()) exportParams.set("q", search.trim());
  const observed = data.data?.coverage.observed_at_utc;
  const refresh = () => { void data.refetch(); };

  return <ReportLayout title={caption()} domain={effectiveDomain || undefined} state={failed ? "error" : data.isPending ? "loading" : "ok"}
    controls={{ updatedAt: typeof observed === "string" ? observed : undefined, onRefresh: refresh, refreshing: data.isFetching }}
    stateView={<div role="alert">{t("reports.gpo.load_failed")} <button className="sli-ds-button" type="button" onClick={refresh}>{t("state.retry")}</button></div>}
    actions={definition.export && data.data && !failed ? <a className="sli-ds-button" download
      href={`/api/v2/reports/${encodeURIComponent(definition.key)}/export.csv?${exportParams}`}><Icon name="download"/>{t("reports.renderer.export_csv")}</a> : undefined}>
    <div ref={list}>
        <div className="sli-ds-split-report__toolbar">
          <label className="sli-ds-field" data-search=""><Icon name="search"/><input type="search" aria-label={t("reports.gpo.search_policy")} placeholder={t("reports.gpo.search_policy")} maxLength={256}
            value={search} onChange={(event) => { setSearch(event.target.value); setPage(1); }}/></label>
          <FilterChip aria-pressed={mismatch} count={visible.filter((item) => hasMismatch(item)).length}
            onClick={() => { setMismatch(!mismatch); setPage(1); }}>{t("reports.gpo.mismatch")}</FilterChip>
          <FilterChip aria-pressed={unlinked} count={visible.filter((item) => item.unlinked).length}
            onClick={() => { setUnlinked(!unlinked); setPage(1); }}>{t("reports.gpo.unlinked")}</FilterChip>
        </div>
        <DataTable columns={columns} rows={rows.slice(start, start + pageSize)} columnSample={rows} rowKey={(row) => row.id} caption={caption()}
          selectedKey={rows.find((row) => row.guid === focusId)?.id ?? focusId} emptyContent={firstAdSource ? <FirstAdSource/> : "—"} sort={{ field: "modification_time", direction }}
          onSort={() => { setDirection(direction === "desc" ? "asc" : "desc"); setPage(1); }}
          total={rows.length} pageSize={{ value: pageSize, options: pageSizes, onChange: (size) => { setPageSize(size); setPage(1); } }}
          pagination={{ start: start + 1, onPrevious: currentPage > 1 ? () => setPage(currentPage - 1) : undefined,
            onNext: start + pageSize < rows.length ? () => setPage(currentPage + 1) : undefined }}/>
    </div>
  </ReportLayout>;
}
