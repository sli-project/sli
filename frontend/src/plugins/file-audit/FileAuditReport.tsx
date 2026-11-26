import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { Button, DataTable, FactList, FilterBar, ReportLayout, Select, StateView, Tabs, TabList,
  type FilterValues, type PeriodValue, type ResultState } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t } from "../../i18n";
import { useEffectiveAccess, useTimeZone } from "../../app/App";
import { columnValue, defaultValues, searchFromValues, valuesFromSearch } from "../../app/report-v2/state";
import { cellKind } from "../../app/report-v2/DetailSection";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { selectedDomain, withDomain } from "../../app/domain-navigation";
import { ACTION_FILTERS, FILE_SERVER_VIEWS, appliedFileAuditValues, fileAuditFields, fileAuditFilterValues, fileAuditHref,
  fileAuditPageSize, fileAuditPageSizes, fileAuditParams, fileAuditReturnHref, fileAuditShare,
  type ActionFilter, type FileServerView, type FileAuditTab, type FileAuditRow as Row } from "./report";
import { evidenceRecordNumbers, fileAuditOperation, fileServerColumns, FileAuditInterval } from "./FileAuditCells";
import { FileAuditObjectWorkspace } from "./FileAuditObjectWorkspace";
import "./file-audit.css";

const minute = () => new Date(Math.floor(Date.now() / 60_000) * 60_000);
const viewOf = (key: string): FileServerView => key === "overview" || key === "audit-state" ? "overview" : key === "permissions" ? key : "actions";
const filterOf = (key: string, search: URLSearchParams): ActionFilter =>
  ACTION_FILTERS.find(filter => filter === search.get("action_filter"))
  ?? ACTION_FILTERS.find(filter => filter === key)
  ?? (search.get("operation") === "delete" ? "delete" : search.get("operation") === "write" ? "changes" : "all");
const actionSource = (filter: ActionFilter): FileAuditTab =>
  filter === "permission-changes" || filter === "access-denials" || filter === "out-of-hours" ? filter : "actions";

export function FileAuditReport({ definition: initial }: { definition: ReportDefinitionDto }) {
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const { formatCell } = useDateFormatters();
  const [entrySearch] = useState(() => new URLSearchParams(window.location.search));
  const requested = entrySearch.get("tab") ?? initial.key.slice("file-audit.".length);
  const [view, setView] = useState<FileServerView>(() => viewOf(requested));
  const [filter, setFilter] = useState(() => filterOf(requested, entrySearch));
  const [values, setValues] = useState<FilterValues>(() => ({
    period: { preset: "24h" }, include_nested: "true", ...defaultValues(initial), ...valuesFromSearch(initial, entrySearch),
    source_kind: "server", file_server_domain: selectedDomain(window.location.search) ?? undefined,
    ...Object.fromEntries(["source_instance_id", "device_id", "snapshot_id", "path_search", "account_search"].flatMap(key =>
      entrySearch.get(key) ? [[key, entrySearch.get(key)!]] : [])),
  }));
  const [pages, setPages] = useState<Array<string | null>>([entrySearch.get("cursor")]);
  const [firstPage, setFirstPage] = useState(Math.max(0, Number(entrySearch.get("page_index")) || 0));
  const [selectedId, setSelectedId] = useState<string | null>(entrySearch.get("detail_row"));
  const [anchor, setAnchor] = useState(() => {
    const parsed = Date.parse(entrySearch.get("fa_anchor") ?? "");
    return Number.isFinite(parsed) ? new Date(parsed) : minute();
  });
  const [workspace, setWorkspace] = useState<{ snapshot: string; path: string; params: string; back: string } | null>(null);
  const list = useRef<HTMLDivElement>(null);
  const previousScope = useRef<string>(undefined);
  const listScroll = useRef(0);
  const preference = 'sli.file-audit.page-size:' + (access?.subject.type ?? "unknown") + ':' + (access?.subject.id ?? "unknown");
  const [requestedSize, setRequestedSize] = useState(() => {
    try { return fileAuditPageSize(entrySearch.get("limit") ?? localStorage.getItem(preference)); }
    catch { return 50; }
  });
  const tab = view === "actions" ? actionSource(filter) : view;
  const reportKey = 'file-audit.' + tab;
  const session = JSON.stringify([access?.subject.type, access?.subject.id, access?.evaluated_at_utc]);
  const definitionQuery = useQuery({ queryKey: ["report-v2", "file-audit", session, "definition", reportKey],
    queryFn: () => api.reportV2Definition(reportKey), initialData: reportKey === initial.key ? initial : undefined, staleTime: 5 * 60_000, retry: false });
  const definition = definitionQuery.data;
  const pageSize = fileAuditPageSize(requestedSize, definition?.limits.max ?? initial.limits.max);
  const requestValues: FilterValues = { ...values, view: undefined,
    path_search: view === "actions" ? values.path_search : undefined, account_search: view === "actions" ? values.account_search : undefined,
    operation: filter === "delete" && view === "actions" ? "delete" : values.operation,
    activity: filter === "changes" && view === "actions" ? "changes" : undefined };
  const baseParams = definition ? fileAuditParams(definition, requestValues, timeZone, null, anchor, pageSize) : null;
  const params = definition ? fileAuditParams(definition, requestValues, timeZone, pages.at(-1), anchor, pageSize) : null;
  const data = useQuery({ queryKey: ["report-v2", "file-audit", session, "data", reportKey, params?.toString()],
    queryFn: () => api.reportV2Data(reportKey, params!), enabled: Boolean(params && definition?.access?.allowed !== false && !definitionQuery.error),
    retry: false, refetchOnWindowFocus: false });
  const result = data.data;
  const error = definitionQuery.error ?? data.error;
  const denied = definition?.access?.allowed === false || result?.access?.allowed === false || result?.state === "denied"
    || error instanceof ApiResponseError && [401, 403].includes(error.status);
  const failed = Boolean(error) || result?.state === "error";
  const rows = !denied && !failed ? result?.items ?? [] : [];
  const reset = () => { setPages([null]); setFirstPage(0); setSelectedId(null); };
  const pageIndex = firstPage + pages.length - 1;
  const currentKeys = new Set(access?.reports?.filter(report => report.allowed).map(report => report.report_key));
  const canPermissions = currentKeys.has("file-audit.permissions");
  const switchView = (next: string) => {
    reset(); setView(next as FileServerView); setFilter("all");
    setValues(current => ({ ...current, operation: undefined, record_unit: undefined, path_search: undefined, account_search: undefined }));
  };
  const selectFilter = (next: ActionFilter) => {
    reset(); setFilter(next);
    setValues(current => ({ ...current, operation: undefined, record_unit: undefined }));
  };
  const makeListSearch = () => {
    const search = searchFromValues(definition ?? initial, requestValues);
    search.delete("file_server_domain");
    search.set("tab", view);
    if (view === "actions") search.set("action_filter", filter);
    search.set("limit", String(pageSize)); search.set("fa_anchor", anchor.toISOString());
    for (const key of ["source_instance_id", "device_id", "snapshot_id", "path_search", "account_search", "record_unit"])
      if (typeof requestValues[key] === "string" && requestValues[key])
        search.set(key, String(requestValues[key]));
    if (pages.at(-1)) { search.set("cursor", pages.at(-1)!); search.set("page_index", String(pageIndex)); }
    for (const key of ["object_path", "object_tab", "compare_snapshot_id", "return_to"]) {
      const value = entrySearch.get(key);
      if (value) search.set(key, value);
    }
    return search;
  };
  const listHref = withDomain('/app/report/' + reportKey + '?' + makeListSearch(), window.location.search);
  useEffect(() => {
    if (workspace) return;
    const url = new URL(listHref, window.location.origin);
    if (selectedId) url.searchParams.set("detail_row", selectedId);
    window.history.replaceState(window.history.state, "", url.pathname + url.search + window.location.hash);
  }, [listHref, selectedId, workspace]);
  useEffect(() => {
    const scope = session + timeZone;
    if (previousScope.current !== undefined && previousScope.current !== scope) reset();
    previousScope.current = scope;
  }, [session, timeZone]);
  useEffect(() => {
    const scroll = list.current?.querySelector<HTMLElement>(".sli-ds-table__scroll");
    if (!workspace && scroll) scroll.scrollTop = listScroll.current;
  }, [workspace]);
  const hrefFor = (next: FileAuditTab, row: Row, extra: Record<string, string | null> = {}) =>
    withDomain(fileAuditHref(next, baseParams ?? new URLSearchParams(), row, { return_to: listHref,
      ...(view === "overview" && next === "permission-changes" ? { record_unit: "saved_event_group",
        ...(baseParams?.get("path") ? { path: baseParams.get("path")! } : {}) } : {}), ...extra }), window.location.search);
  const open = (row: Row) => {
    if (!definition) return;
    if (view === "actions") {
      const id = String(row[definition.row_key]);
      setSelectedId(current => current === id ? null : id);
    } else if (canPermissions && typeof row.snapshot_id === "string" && typeof row.path === "string" && fileAuditShare(row)) {
      listScroll.current = list.current?.querySelector<HTMLElement>(".sli-ds-table__scroll")?.scrollTop ?? 0;
      const href = hrefFor("permissions", row, { object_path: row.path });
      setWorkspace({ snapshot: row.snapshot_id, path: row.path, params: new URL(href, window.location.origin).searchParams.toString(), back: listHref });
      window.history.replaceState(window.history.state, "", href);
    }
  };
  const directObject = view === "permissions" && entrySearch.get("object_path") && entrySearch.get("snapshot_id") && baseParams?.getAll("share").length === 1
    ? { snapshot: entrySearch.get("snapshot_id")!, path: entrySearch.get("object_path")!, params: baseParams.toString(),
      back: fileAuditReturnHref(entrySearch.get("return_to")) ?? fileAuditHref("permissions", baseParams, undefined, { object_path: null }) } : null;
  const object = workspace ?? directObject;
  if (object && !denied && !failed) return <FileAuditObjectWorkspace key={session + ':' + object.snapshot + ':' + object.path}
    snapshotId={object.snapshot} objectPath={object.path} params={object.params} backHref={object.back}
    session={session} pageSize={pageSize} onBack={workspace ? () => setWorkspace(null) : undefined}/>;

  const reportAccess = access?.reports?.find(report => report.report_key === reportKey);
  const canExport = access?.capabilities.includes("file-audit.export") && reportAccess?.allowed && reportAccess.allowed_actions.includes("export");
  const exportHref = canExport && definition?.export && baseParams && result && result.state !== "not_collected" && !denied && !failed
    ? '/api/v2/reports/' + encodeURIComponent(reportKey) + '/export.csv?' + new URLSearchParams([...baseParams].filter(([key]) => key !== "limit")) : null;
  const state: ResultState = denied ? "denied" : failed || definition && !params ? "error" : result ? "ok" : "loading";
  const retry = () => void (definitionQuery.error ? definitionQuery.refetch() : data.refetch());
  const period = fileAuditFilterValues(values, timeZone).period as PeriodValue;
  const serverOptions = result?.filter_options?.source_instance_id ?? [];
  const previousOptions = definition?.filter_options?.source_instance_id ?? [];
  const servers = [{ value: "", label: t("file-audit.screen.all_servers") }, ...(serverOptions.length ? serverOptions : previousOptions)];
  const viewTitle = (key: FileServerView) => t('file-audit.screen.' + key as "file-audit.screen.actions" | "file-audit.screen.overview" | "file-audit.screen.permissions");
  const refresh = () => {
    reset();
    const next = minute();
    if (anchor.getTime() === next.getTime() && !pages.at(-1)) retry();
    setAnchor(next);
  };
  const title = viewTitle(view);
  const tabItems = FILE_SERVER_VIEWS.map(key => ({ key, label: viewTitle(key) }));
  return <div className="sli-file-audit">
    <Tabs items={tabItems} active={view} onChange={switchView}>
      <ReportLayout title={t("file-audit.title")} tabbed state={state} busy={data.isFetching && !data.isLoading}
        controls={{
          scope: <Select label={t("file-audit.workspace.server")} options={servers}
            value={String(values.source_instance_id ?? "")} onChange={source => {
              reset(); setValues({ ...values, source_instance_id: source || undefined, share: undefined, path: undefined, device_id: undefined, snapshot_id: undefined });
            }}/>,
          period: { value: period, presets: ["24h", "7d", "30d", "custom"], precision: "datetime-local", showBounds: true, strictRange: true,
            bounds: baseParams ? { from: baseParams.get("from")!, to: baseParams.get("to")! } : undefined,
            onChange: next => { reset(); setAnchor(minute()); setValues(appliedFileAuditValues({ ...values, period: next }, values, timeZone)); } },
          onRefresh: refresh, refreshing: data.isFetching,
        }}
        actions={<>
          {exportHref ? <a className="sli-ds-button" href={exportHref} download>{t("reports.renderer.export_csv")}</a> : null}
          {fileAuditReturnHref(entrySearch.get("return_to")) ? <a className="sli-ds-button" href={fileAuditReturnHref(entrySearch.get("return_to"))!}>{t("file-audit.workspace.back")}</a> : null}
        </>}
        tabs={<TabList label={t("file-audit.title")} variant="underline"/>}
        stateView={denied ? <ReportDenied reportKey={reportKey}/> : <StateView state="error"
          message={definition && !params ? t("file-audit.invalid_period") : t("file-audit.screen.load_error", { subject: title })}
          onRetry={definition && !params ? undefined : retry}/>}>
        {definition && result ? <div ref={list}>
          <DataTable caption={title} compact density="compact" columns={fileServerColumns(view, definition.columns, rows, baseParams, canPermissions, open, hrefFor)}
            rows={rows} rowKey={row => String(row[definition.row_key])} selectedKey={selectedId}
            onRowClick={view === "actions" ? open : undefined}
            renderExpandedRow={view === "actions" ? row => <FactList facts={[
              { label: t("file-audit.workspace.interval"), value: <FileAuditInterval row={row}/> },
              ...definition.columns.filter(column => ["path", "operation", "outcome", "access_mask", "denial_layer"].includes(column.key))
                .map(column => ({ label: column.label, value: formatCell(column.key === "operation" ? fileAuditOperation(row, column) : columnValue(column, row), cellKind(column)).slice(0, 4096) })),
              ...["source_name", "old_path", "client_ip"].flatMap(key => typeof row[key] === "string" && row[key] ? [{
                label: t(key === "source_name" ? "file-audit.workspace.server" : key === "client_ip" ? "file-audit.screen.from" : "file-audit.screen.previous_path"),
                value: String(row[key]).slice(0, 4096),
              }] : []),
              { label: t("file-audit.employee"), value: String(row.subject_sid ?? "—").slice(0, 256) },
              ...evidenceRecordNumbers(row),
            ]}/> : undefined}
            toolbar={view === "actions" ? <FilterBar layout="inline" applyInline compact
              primaryKeys={["path_search", "account_search"]} fields={fileAuditFields(view)}
              values={values} onApply={next => { reset(); setValues(next); }}
              leadingControls={<div className="sli-file-audit__segments" role="group" aria-label={title}>
                {ACTION_FILTERS.filter(key => !access || currentKeys.has('file-audit.' + actionSource(key))).map(key =>
                  <Button key={key} aria-pressed={filter === key} onClick={() => selectFilter(key)}>{t('file-audit.filters.' + key as 'file-audit.filters.all')}</Button>)}
              </div>}/> : undefined}
            total={result.filtered_count}
            pageSize={{ value: pageSize, options: fileAuditPageSizes(definition.limits.max), onChange: size => {
              reset(); setRequestedSize(size); try { localStorage.setItem(preference, String(size)); } catch { /* optional preference */ }
            } }}
            pagination={{ start: pageIndex * pageSize + 1, busy: data.isFetching,
              onPrevious: pages.length > 1 ? () => { setSelectedId(null); setPages(current => current.slice(0, -1)); } : undefined,
              onNext: result.has_more && result.next_cursor ? () => { setSelectedId(null); setPages(current => [...current, result.next_cursor]); } : undefined }}/>
        </div> : null}
      </ReportLayout>
    </Tabs>
  </div>;
}
