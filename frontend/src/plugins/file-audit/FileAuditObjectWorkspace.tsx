import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import { Button, FilterBar, ReportLayout, StateView, type ResultState } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t, type MessageKey } from "../../i18n";
import { useEffectiveAccess } from "../../app/App";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { FileAuditAclTable } from "./FileAuditAclTable";
import { FileAuditComparison } from "./FileAuditComparison";
import type { FileAuditDetailResult } from "./acl";

const knownReasons = new Set(["snapshot_unavailable", "object_unavailable", "policy_incompatible", "source_generation_mismatch", "object_replaced", "object_type_mismatch", "path_mismatch", "same_snapshot", "acl_unavailable"]);
// A browser handoff also carries navigation/domain context, which the detail API rejects.
const detailQueryKeys = new Set(["file_server_domain", "period", "from", "to", "source_kind", "path", "include_nested", "employee", "share",
  "operation", "show_service", "source_instance_id", "device_id", "tz", "limit"]);

export function FileAuditObjectWorkspace({ snapshotId: initialSnapshot, objectPath: initialPath, params: initialParams, backHref,
  session, pageSize, onBack }: { snapshotId: string; objectPath: string; params: string; backHref: string;
  session: string; pageSize: number; onBack?: () => void }) {
  const access = useEffectiveAccess();
  const { formatCell } = useDateFormatters();
  const initial = new URLSearchParams(window.location.search);
  const [snapshotId, setSnapshotId] = useState(initialSnapshot);
  const [path, setPath] = useState(initialPath);
  const [comparing, setComparing] = useState(initial.get("object_tab") === "comparison");
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  const [compareId, setCompareId] = useState(initial.get("compare_snapshot_id") ?? "");
  const [copied, setCopied] = useState<"idle" | "path" | "unc" | "failed">("idle");
  const params = new URLSearchParams([...new URLSearchParams(initialParams)].filter(([key]) => detailQueryKeys.has(key)));
  params.set("path", path); params.set("include_nested", "false");
  if (compareId && comparing) params.set("compare_snapshot_id", compareId);
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
    if (comparing) { setComparing(false); updateAddress({ object_tab: null, compare_snapshot_id: null }); return; }
    setComparing(true);
    const previous = compareId || (options[0] ? idOf(options[0]) : "");
    setCompareId(previous); updateAddress({ object_tab: "comparison", compare_snapshot_id: previous });
  };
  const state: ResultState = denied ? "denied" : failed ? "error" : query.isFetching || query.isPending ? "loading"
    : !detail ? "not_collected" : "ok";
  const stateView = denied ? <ReportDenied reportKey="file-audit.permissions"/> : failed
    ? <StateView state="error" detail={t("file-audit.screen.load_error", { subject: t("file-audit.workspace.snapshot") })} onRetry={() => void query.refetch()}/> : <StateView state="not_collected" detail={t("file-audit.workspace.snapshot_missing")}/>;
  const title = denied ? t("file-audit.title") : path.split(/[\\/]/).filter(Boolean).at(-1) || path;
  const comparison = detail?.comparison;
  const unavailable = comparison?.reason && knownReasons.has(comparison.reason)
    ? t(`file-audit.compare.reason.${comparison.reason}` as MessageKey) : t("file-audit.compare.missing");
  const server = detail?.resource?.source_name?.slice(0, 256);
  const share = detail?.share.name?.slice(0, 256);
  const copy = async (kind: "path" | "unc") => {
    try {
      await navigator.clipboard.writeText(kind === "unc" ? `\\\\${server}\\${share}` : path);
      setCopied(kind);
    } catch { setCopied("failed"); }
  };
  const folders = [...new Set(objects.filter(row => row.object_type === "directory" && typeof row.path === "string").map(row => String(row.path)))];
  const byParent = new Map<string | undefined, string[]>();
  for (const folder of folders) {
    const lower = folder.toLowerCase();
    let parent: string | undefined;
    for (const candidate of folders) {
      if (candidate !== folder && lower.startsWith(candidate.replace(/\\+$/, "").toLowerCase() + "\\")
          && (!parent || candidate.length > parent.length)) parent = candidate;
    }
    byParent.set(parent, [...(byParent.get(parent) ?? []), folder]);
  }
  const folderList = (parent?: string) => <ul>{byParent.get(parent)?.map(folder => {
    const children = byParent.has(folder);
    const expanded = !collapsed.has(folder);
    return <li key={folder}>
      {children ? <Button icon={expanded ? "chevron-down" : "chevron-right"} variant="ghost"
        aria-label={t(expanded ? "file-audit.screen.collapse_folder" : "file-audit.screen.expand_folder", { path: folder })}
        aria-expanded={expanded} onClick={() => setCollapsed(current => {
          const next = new Set(current);
          if (expanded) next.add(folder); else next.delete(folder);
          return next;
        })}/> : null}
      <Button variant="ghost" aria-current={folder === path ? "page" : undefined} title={folder}
        onClick={() => selectObject(folder)}>{folder.split(/[\\/]/).filter(Boolean).at(-1) ?? folder}</Button>
      {children && expanded ? folderList(folder) : null}
    </li>;
  })}</ul>;
  return <div className="sli-file-audit sli-file-audit--object">
    <ReportLayout title={title.slice(0, 256)} subtitle={denied ? undefined : <span className="sli-file-audit__path">{path.slice(0, 4096)}</span>}
      state={state} stateView={stateView} controls={{ showBreadcrumbs: true }}
      crumbs={[{ label: t("file-audit.title"), href: backHref }, ...[server, share].flatMap(label => label ? [{ label }] : [])]}
      meta={detail && object ? <>{detail.snapshot.observed_at ? <span>{t("file-audit.workspace.snapshot")} · {formatCell(detail.snapshot.observed_at, "datetime")}</span> : null}
        <span>{params.get("tz")}</span><span>{t("file-audit.workspace.owner")} · {object.owner_sid ?? "—"}</span></> : null}
      actions={<><a className="sli-ds-button" href={backHref} onClick={onBack ? event => { event.preventDefault(); onBack(); } : undefined}>{t("file-audit.workspace.back")}</a>
        {!denied && detail ? <Button aria-pressed={comparing} onClick={openComparison}>{t("file-audit.compare.title")}</Button> : null}
        {!denied && object && navigator.clipboard ? <Button onClick={() => void copy("path")}>{t(copied === "path" ? "file-audit.workspace.copied" : "file-audit.workspace.copy_path")}</Button> : null}
        {!denied && server && share && navigator.clipboard ? <Button onClick={() => void copy("unc")}>{t(copied === "unc" ? "file-audit.workspace.copied" : "file-audit.overview.copy_unc")}</Button> : null}</>}>
      {copied === "failed" ? <p role="alert">{t("file-audit.workspace.copy_error")}</p> : null}
      {detail && !comparing ? <div className="sli-file-audit__object-grid">
        {folders.length ? <nav className="sli-file-audit__object-tree" aria-label={t("file-audit.workspace.retained_objects")}>
          {folderList()}
        </nav> : null}
        <div className="sli-file-audit__acl-content" key={`${snapshotId}:${path}`}>
          <FileAuditAclTable acl={detail.share.dacl} title={`${t("file-audit.acl.smb")} · ${detail.share.name}`} initialPageSize={pageSize} shareLevel/>
          {object ? <FileAuditAclTable acl={object.dacl} title={t("file-audit.acl.ntfs")} initialPageSize={pageSize}/>
            : <p className="sli-file-audit__local-state">{t("file-audit.workspace.snapshot_missing")}</p>}
        </div>
      </div> : null}
      {detail && comparing ? <>
        <FilterBar layout="inline" applyInline compact primaryKeys={["before", "after"]}
          fields={[
            { key: "before", kind: "select", label: t("file-audit.compare.before"), options: options.map(row =>
              ({ value: idOf(row), label: formatCell(row.observed_at, "datetime") })) },
            { key: "after", kind: "select", label: t("file-audit.compare.after"), options: [
              ...(!snapshots.some(row => idOf(row) === snapshotId) ? [{ value: snapshotId, label: formatCell(detail.snapshot.observed_at, "datetime") }] : []),
              ...snapshots.map(row => ({ value: idOf(row), label: formatCell(row.observed_at, "datetime") })),
            ] },
          ]}
          values={{ before: compareId, after: snapshotId }}
          onApply={next => {
            if (typeof next.after === "string" && next.after !== snapshotId) {
              setSnapshotId(next.after); setCompareId(""); updateAddress({ snapshot_id: next.after, compare_snapshot_id: null });
            } else {
              const before = typeof next.before === "string" ? next.before : "";
              setCompareId(before); updateAddress({ compare_snapshot_id: before });
            }
          }}/>
        {comparison?.state === "available" ? <FileAuditComparison key={`${snapshotId}:${compareId}:${path}`} comparison={comparison} pageSize={pageSize}/>
          : <p className="sli-file-audit__local-state">{unavailable}</p>}
      </> : null}
    </ReportLayout>
  </div>;
}
