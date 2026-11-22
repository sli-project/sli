import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { DataTable, ReportLayout, type TableColumn } from "../../design-system";
import { Icon } from "../../design-system/Icon";
import { SplitReport } from "../../design-system/SplitReport";
import { t } from "../../i18n";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { GpoPolicyCard, hasMismatch, versionPair, type PolicyRow, type PolicyTab } from "./GpoPolicyCard";

const caption = () => t("reports.gpo.title");
const inventoryParams = (domain: string) => new URLSearchParams({ tab: "gpos", view: "all", ...(domain ? { domain } : {}) });

export function GpoPolicyReport({ definition, search }: { definition: ReportDefinitionDto; search?: string }) {
  const params = new URLSearchParams(search ?? window.location.search);
  const domain = params.get("domain") ?? params.get("domain_id") ?? "";
  const denied = definition.access?.allowed === false || definition.views.find((view) => view.key === "gpos")?.access?.allowed === false;
  if (denied) return <ReportDenied reportKey={definition.key} page/>;
  return <PolicyInventory key={domain} definition={definition} domain={domain} initial={params}/>;
}

function PolicyInventory({ definition, domain, initial }: { definition: ReportDefinitionDto; domain: string; initial: URLSearchParams }) {
  const [search, setSearch] = useState(initial.get("q") ?? "");
  const [mismatch, setMismatch] = useState(["version_mismatch", "unlinked_version_mismatch"].includes(initial.get("view") ?? ""));
  const [unlinked, setUnlinked] = useState(["unlinked", "unlinked_version_mismatch"].includes(initial.get("view") ?? ""));
  const [selected, setSelected] = useState<string | null>();
  const [tab, setTab] = useState<PolicyTab>(initial.get("tab") === "changes" ? "changes" : initial.get("tab") === "linked_scopes" ? "links" : "settings");
  const [direction, setDirection] = useState<"asc" | "desc">("desc");
  const data = useQuery({
    queryKey: ["report-v2", "gpo-inventory", domain],
    queryFn: () => api.reportV2Data(definition.key, inventoryParams(domain)),
    staleTime: 60_000, retry: false, refetchOnWindowFocus: false,
  });
  const policies = (data.data?.items ?? []) as PolicyRow[];
  const snapshotDomain = data.data?.coverage.domain_id;
  const effectiveDomain = domain || (typeof snapshotDomain === "number" ? String(snapshotDomain) : "");
  const text = search.trim().toLocaleLowerCase();
  const visible = useMemo(() => policies.filter((row) => row.display_name?.toLocaleLowerCase().includes(text)), [policies, text]);
  const rows = visible.filter((row) => (!mismatch || hasMismatch(row)) && (!unlinked || row.unlinked)).sort((left, right) => {
    const leftTime = Date.parse(left.modification_time ?? "");
    const rightTime = Date.parse(right.modification_time ?? "");
    if (Number.isNaN(leftTime)) return Number.isNaN(rightTime) ? 0 : 1;
    if (Number.isNaN(rightTime)) return -1;
    return direction === "desc" ? rightTime - leftTime : leftTime - rightTime;
  });
  const defaultId = rows[0]?.id;
  useEffect(() => {
    if (defaultId !== undefined) setSelected((current) => current === undefined ? defaultId : current);
  }, [defaultId]);
  const policy = selected === undefined ? rows[0] : policies.find((row) => row.id === selected);
  const select = (next: PolicyRow, nextTab?: PolicyTab) => {
    if (policy?.id !== next.id || nextTab !== undefined) setTab(nextTab ?? "settings");
    setSelected(next.id);
  };
  const jump = (row: PolicyRow, target: PolicyTab, count?: number | null) => count == null ? "—" : count === 0 ? count :
    <button type="button" className="sli-ds-text-button"
      aria-label={t(target === "settings" ? "reports.gpo.open_settings" : "reports.gpo.open_links", { name: row.display_name, count })}
      onClick={(event) => { event.stopPropagation(); select(row, target); }}>{count}</button>;
  const columns: TableColumn<PolicyRow>[] = [
    { key: "display_name", label: t("reports.gpo.policy"), render: (row) => <span className="sli-ds-cell-with-icon"><Icon name="report"/>{row.display_name ?? "—"}</span> },
    { key: "setting_count", label: t("reports.gpo.setting_count"), kind: "number", width: "8rem", render: (row) => jump(row, "settings", row.setting_count) },
    { key: "side_count", label: t("reports.gpo.side_count"), wideOnly: true, width: "14rem",
      render: (row) => row.computer_setting_count == null && row.user_setting_count == null ? "—" : `${row.computer_setting_count ?? "—"} / ${row.user_setting_count ?? "—"}` },
    { key: "link_count", label: t("reports.gpo.links"), kind: "number", width: "6rem", render: (row) => jump(row, "links", row.link_count) },
    { key: "versions", label: t("reports.gpo.version_pair"), width: "13rem", render: (row) => versionPair(row, hasMismatch(row, "user") && !hasMismatch(row, "computer") ? "user" : "computer", effectiveDomain) },
    { key: "owner", label: t("reports.gpo.owner"), width: "15rem" },
    { key: "modification_time", label: t("reports.gpo.modified"), kind: "datetime", width: "13rem", sortable: true },
  ];
  const denied = data.data?.state === "denied" || data.error instanceof ApiResponseError && [401, 403].includes(data.error.status);
  if (denied) return <ReportDenied reportKey={definition.key} page/>;
  const failed = data.isError || data.data?.state === "error";
  const exportParams = inventoryParams(effectiveDomain);
  exportParams.set("view", mismatch ? unlinked ? "unlinked_version_mismatch" : "version_mismatch" : unlinked ? "unlinked" : "all");
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
    <SplitReport title={policy?.display_name} onClose={() => setSelected(null)}
      resizeLabel={t("reports.gpo.resize")} expandLabel={t("reports.gpo.full")} restoreLabel={t("reports.gpo.restore")} closeLabel={t("reports.gpo.close")}
      list={<>
        <div className="sli-ds-split-report__toolbar">
          <label className="sli-ds-field" data-search=""><Icon name="search"/><input type="search" aria-label={t("reports.gpo.search_policy")} placeholder={t("reports.gpo.search_policy")} maxLength={256}
            value={search} onChange={(event) => setSearch(event.target.value)}/></label>
          <button className="sli-ds-chip" type="button" aria-pressed={mismatch} onClick={() => setMismatch(!mismatch)}>
            {t("reports.gpo.mismatch")} <b>{visible.filter((item) => hasMismatch(item)).length}</b>
          </button>
          <button className="sli-ds-chip" type="button" aria-pressed={unlinked} onClick={() => setUnlinked(!unlinked)}>
            {t("reports.gpo.unlinked")} <b>{visible.filter((item) => item.unlinked).length}</b>
          </button>
        </div>
        <DataTable columns={columns} rows={rows} rowKey={(row) => row.id} caption={caption()} onRowClick={select}
          selectedKey={policy?.id} showFooter={false} emptyContent="—" sort={{ field: "modification_time", direction }}
          onSort={() => setDirection(direction === "desc" ? "asc" : "desc")}/>
      </>}>
      {policy ? <GpoPolicyCard key={policy.id} definition={definition} domain={effectiveDomain} policy={policy} tab={tab} setTab={setTab} revision={data.dataUpdatedAt}/> : null}
    </SplitReport>
  </ReportLayout>;
}
