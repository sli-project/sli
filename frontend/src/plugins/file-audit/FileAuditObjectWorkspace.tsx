import { Select } from "../../design-system/Select";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import { FactList, ReportLayout, StateView, Tabs, TabList, type ResultState } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t, type MessageKey } from "../../i18n";
import { useEffectiveAccess } from "../../app/App";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { withDomain } from "../../app/domain-navigation";
import { FileAuditAclTable } from "./FileAuditAclTable";
import { FileAuditComparison } from "./FileAuditComparison";
import type { FileAuditDetailResult } from "./acl";
import { fileAuditHref, tabTitle, type FileAuditTab } from "./report";

const objectTabs = ["permissions", "permission-changes", "actions", "audit-state"] as const;
const knownReasons = new Set(["snapshot_unavailable", "object_unavailable", "policy_incompatible", "source_generation_mismatch", "object_replaced", "object_type_mismatch", "path_mismatch", "same_snapshot", "acl_unavailable"]);
// A browser handoff also carries navigation/domain context, which the detail API rejects.
const detailQueryKeys = new Set(["period", "from", "to", "source_kind", "path", "include_nested", "employee", "share",
  "operation", "show_service", "source_instance_id", "device_id", "tz", "limit"]);

export function FileAuditObjectWorkspace({ snapshotId: initialSnapshot, objectPath: initialPath, params: initialParams, backHref,
  session, pageSize, onBack }: { snapshotId: string; objectPath: string; params: string; backHref: string;
  session: string; pageSize: number; onBack?: () => void }) {
  const access = useEffectiveAccess();
  const { formatCell } = useDateFormatters();
  const initial = new URLSearchParams(window.location.search);
  const [snapshotId, setSnapshotId] = useState(initialSnapshot);
  const [path, setPath] = useState(initialPath);
  const [tab, setTab] = useState<FileAuditTab>(initial.get("object_tab") === "audit-state" ? "audit-state"
    : initial.get("object_tab") === "comparison" ? "permission-changes" : "permissions");
  const [compareId, setCompareId] = useState(initial.get("compare_snapshot_id") ?? "");
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const params = new URLSearchParams([...new URLSearchParams(initialParams)].filter(([key]) => detailQueryKeys.has(key)));
  params.set("path", path); params.set("include_nested", "false");
  if (compareId && tab === "permission-changes") params.set("compare_snapshot_id", compareId);
  else params.delete("compare_snapshot_id");
  const canView = access?.reports?.some(report => report.report_key === "file-audit.permissions" && report.allowed) ?? false;
  const query = useQuery({ queryKey: ["report-v2", "file-audit", session, "acl", snapshotId, params.toString()],
    queryFn: async () => await api.reportV2Detail("file-audit.permissions", snapshotId, params) as FileAuditDetailResult,
    enabled: canView && Boolean(snapshotId && path && params.getAll("share").length === 1), retry: false, refetchOnWindowFocus: false });
  const denied = !canView || query.data?.access?.allowed === false || query.data?.state === "denied"
    || query.error instanceof ApiResponseError && [401, 403].includes(query.error.status);
  const failed = Boolean(query.error) || query.data?.state === "error";
  const result = !denied && !failed && !query.isFetching ? query.data : undefined;
  const detail = result?.detail;
  const object = detail?.object;
  const snapshots = result?.collections?.snapshots ?? [];
  const objects = result?.collections?.objects ?? [];
  const idOf = (row: Record<string, unknown>) => String(row.id ?? row.snapshot_id ?? "");
  const options = snapshots.filter(row => idOf(row) !== snapshotId);
  const updateAddress = (changes: Record<string, string | null>) => {
    const url = new URL(window.location.href);
    for (const [key, value] of Object.entries(changes)) value ? url.searchParams.set(key, value) : url.searchParams.delete(key);
    window.history.replaceState(window.history.state, "", url);
  };
  const selectObject = (nextPath: string) => { setPath(nextPath); setCopied("idle"); updateAddress({ object_path: nextPath }); };
  const openComparison = () => {
    setTab("permission-changes");
    const previous = compareId || (options[0] ? idOf(options[0]) : "");
    setCompareId(previous); updateAddress({ object_tab: "comparison", compare_snapshot_id: previous });
  };
  const scopedHref = (next: FileAuditTab) => {
    const context = new URLSearchParams(params);
    const comparison = detail?.comparison;
    if (tab === "permission-changes" && comparison?.state === "available" && comparison.before && comparison.after) {
      const observed = [comparison.before.snapshot.observed_at, comparison.after.snapshot.observed_at].sort((a, b) => Date.parse(a) - Date.parse(b));
      if (observed[0] !== observed[1] && observed.every(value => Number.isFinite(Date.parse(value)))) {
        context.set("period", "custom"); context.set("from", observed[0]); context.set("to", observed[1]);
      }
    }
    return withDomain(fileAuditHref(next, context, undefined,
      { path, include_nested: "false", return_to: `${window.location.pathname}${window.location.search}` }), window.location.search);
  };
  const selectTab = (next: string) => {
    if (next === "actions" || next === "permission-changes") { window.location.assign(scopedHref(next)); return; }
    setTab(next as FileAuditTab); updateAddress({ object_tab: next === "permissions" ? null : next });
  };
  const state: ResultState = denied ? "denied" : failed ? "error" : query.isFetching || query.isPending ? "loading"
    : !detail ? "not_collected" : "ok";
  const stateView = denied ? <ReportDenied reportKey="file-audit.permissions"/> : failed
    ? <StateView state="error" onRetry={() => void query.refetch()}/> : <StateView state="not_collected" detail={t("file-audit.workspace.snapshot_missing")}/>;
  const title = denied ? t("file-audit.title") : path.split(/[\\/]/).filter(Boolean).at(-1) || path;
  const comparison = detail?.comparison;
  const unavailable = comparison?.reason && knownReasons.has(comparison.reason)
    ? t(`file-audit.compare.reason.${comparison.reason}` as MessageKey) : t("file-audit.compare.missing");
  const copy = async () => {
    try { await navigator.clipboard.writeText(path); setCopied("copied"); } catch { setCopied("failed"); }
  };
  return <div className="sli-file-audit sli-file-audit--object"><Tabs items={objectTabs.map(key => ({ key, label: tabTitle(key) }))} active={tab} onChange={selectTab}>
    <ReportLayout title={title} subtitle={denied ? undefined : <span className="sli-file-audit__path">{path}</span>} tabbed state={state} stateView={stateView}
      crumbs={[{ label: t("file-audit.title"), href: backHref }, ...(detail?.share.name ? [{ label: detail.share.name }] : [])]}
      meta={detail && object ? <>{detail.snapshot.observed_at ? <span>{t("file-audit.workspace.snapshot")}: {formatCell(detail.snapshot.observed_at, "datetime")}</span> : null}
        <span>{params.get("tz")}</span><span>{t("file-audit.workspace.owner")}: {object.owner_sid ?? "—"}</span></> : null}
      actions={<><a className="sli-ds-button" href={backHref} onClick={onBack ? event => { event.preventDefault(); onBack(); } : undefined}>{t("file-audit.workspace.back")}</a>
        {!denied && detail ? <button type="button" className="sli-ds-button" onClick={openComparison}>{t("file-audit.compare.title")}</button> : null}
        {!denied && object && navigator.clipboard ? <button type="button" className="sli-ds-button" onClick={() => void copy()}>{t(copied === "copied" ? "file-audit.workspace.copied" : "file-audit.workspace.copy_path")}</button> : null}</>}
      tabs={<TabList label={title} variant="underline"/>}>
      {copied === "failed" ? <p role="alert">{t("file-audit.workspace.copy_error")}</p> : null}
      {detail && tab === "permissions" ? <div className="sli-file-audit__object-grid">
        {objects.length ? <details className="sli-file-audit__object-tree" open><summary>{t("file-audit.workspace.retained_objects")}</summary>
          <nav aria-label={t("file-audit.workspace.retained_objects")}>{objects.map((row, index) => <button type="button"
            key={String(row.id ?? row.path ?? index)} className="sli-ds-table__link" aria-current={row.path === path ? "page" : undefined}
            onClick={() => selectObject(String(row.path))} title={String(row.path)}>{String(row.path)}</button>)}</nav>
        </details> : null}
        <div className="sli-file-audit__acl-content" key={`${snapshotId}:${path}`}>
          <FileAuditAclTable acl={detail.share.dacl} title={`${t("file-audit.acl.smb")} · ${detail.share.name}`} initialPageSize={pageSize}/>
          {object ? <FileAuditAclTable acl={object.dacl} title={t("file-audit.acl.ntfs")} initialPageSize={pageSize}/>
            : <p className="sli-file-audit__local-state">{t("file-audit.workspace.snapshot_missing")}</p>}
        </div>
      </div> : null}
      {detail && object && tab === "audit-state" ? <>
        <FactList facts={[
          { label: t("file-audit.detail.completeness"), value: detail.snapshot.completeness },
          { label: t("file-audit.workspace.scan_gaps"), value: String(detail.snapshot.unread_objects) },
          { label: t("file-audit.receipt.policy_revision"), value: String(detail.snapshot.policy_revision) },
          { label: t("file-audit.acl.protected"), value: object.sacl_protected == null ? "—" : String(object.sacl_protected) },
        ]}/><FileAuditAclTable key={`${snapshotId}:${path}:sacl`} acl={object.sacl} title={t("file-audit.acl.sacl")} initialPageSize={pageSize}/>
      </> : null}
      {detail && object && tab === "permission-changes" ? <>
        <div className="sli-file-audit__compare-controls">
          <div className="sli-ds-control-field">{t("file-audit.compare.before")}<Select label={t("file-audit.compare.before")} value={compareId} disabled={!options.length} onChange={(selectedValue) => { setCompareId(selectedValue); updateAddress({ compare_snapshot_id: selectedValue }); }}
            options={[{ value: "", label: "—" }, ...(options.map(row => ({ value: idOf(row), label: String(formatCell(row.observed_at, "datetime")) + String(" · ") + String(idOf(row)) })) ?? [])]}/></div>
          <div className="sli-ds-control-field">{t("file-audit.compare.after")}<Select label={t("file-audit.compare.after")} value={snapshotId} onChange={(selectedValue) => { setSnapshotId(selectedValue); setCompareId(""); updateAddress({ snapshot_id: selectedValue, compare_snapshot_id: null }); }}
            options={[...(!snapshots.some(row => idOf(row) === snapshotId) ? [{ value: snapshotId, label: formatCell(detail.snapshot.observed_at, "datetime") }] : []), ...(snapshots.map(row => ({ value: idOf(row), label: String(formatCell(row.observed_at, "datetime")) + String(" · ") + String(idOf(row)) })) ?? [])]}/></div>
          <a className="sli-ds-button" href={scopedHref("permission-changes")}>{t("file-audit.compare.events")}</a>
        </div>
        {comparison?.state === "available" ? <FileAuditComparison key={`${snapshotId}:${compareId}:${path}`} comparison={comparison} pageSize={pageSize}/>
          : <p className="sli-file-audit__local-state">{unavailable}</p>}
      </> : null}
      {result?.limitations.filter(item => !item.code.endsWith("coverage_unverified")).length ? <ul className="sli-file-audit__limitations">{result.limitations.filter(item => !item.code.endsWith("coverage_unverified")).map(item => <li key={item.code}>{item.text}</li>)}</ul> : null}
    </ReportLayout>
  </Tabs></div>;
}
