import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { Button, DataTable, FilterBar, ReportLayout, Select, StateView, Tabs, TabList,
  type FilterValues, type PeriodValue, type ResultState } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t } from "../../i18n";
import { useEffectiveAccess, useTimeZone } from "../../app/App";
import { defaultValues, searchFromValues, valuesFromSearch } from "../../app/report-v2/state";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { selectedDomain, withDomain } from "../../app/domain-navigation";
import { FILE_ACTIVITY_VIEWS, FILE_SERVER_VIEWS, appliedFileAuditValues, fileAuditFields, fileAuditFilterValues, fileAuditHref,
  fileAuditPageSize, fileAuditPageSizes, fileAuditParams, fileAuditReturnHref, fileAuditShare, isFileActivityView, tabTitle,
  type FileServerView, type FileAuditTab, type FileAuditRow as Row } from "./report";
import { fileServerColumns } from "./FileAuditCells";
import { FileAuditActivityDetails, fileActivityColumns } from "./FileAuditActivity";
import { FileAuditObjectWorkspace } from "./FileAuditObjectWorkspace";
import { useResourceAuditControls } from "./ResourceAuditControls";
import { formatNumber } from "../../shared/format";
import "./file-audit.css";

const minute = () => new Date(Math.floor(Date.now() / 60_000) * 60_000);
const viewOf = (key: string, search: URLSearchParams): FileServerView => {
  const requested = key === "actions" ? search.get("action_filter") : key;
  return FILE_ACTIVITY_VIEWS.find(view => view === requested)
    ?? (key === "overview" || key === "audit-state" ? "overview" : key === "permissions" ? key : "actions");
};

export function FileAuditReport({ definition: initial }: { definition: ReportDefinitionDto }) {
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const { formatCell } = useDateFormatters();
  const [entrySearch] = useState(() => new URLSearchParams(window.location.search));
  const requested = entrySearch.get("tab") ?? initial.key.slice("file-audit.".length);
  const [view, setView] = useState<FileServerView>(() => viewOf(requested, entrySearch));
  const activity = isFileActivityView(view);
  const [values, setValues] = useState<FilterValues>(() => ({
    period: { preset: "24h" }, include_nested: "true", ...defaultValues(initial), ...valuesFromSearch(initial, entrySearch),
    source_kind: "server", file_server_domain: selectedDomain(window.location.search) ?? undefined,
    ...Object.fromEntries(["source_instance_id", "device_id", "snapshot_id", "path_search", "account_search", "record_unit", "operation"].flatMap(key =>
      entrySearch.get(key) ? [[key, entrySearch.get(key)!]] : [])),
    ...(entrySearch.get("action_filter") === "delete" ? { operation: "delete" }
      : entrySearch.get("action_filter") === "changes" ? { activity: "changes" } : {}),
  }));
  const selectedShares = Array.isArray(values.share) ? values.share : [];
  const selectedShare = selectedShares.length > 1 ? "selected-resources" : selectedShares[0];
  const filterValues = useMemo(() => ({ ...values, share: selectedShare, path_search: values.path_search ?? values.path }), [values, selectedShare]);
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
  const reportKey = 'file-audit.' + view;
  const session = JSON.stringify([access?.subject.type, access?.subject.id, access?.evaluated_at_utc]);
  const definitionQuery = useQuery({ queryKey: ["report-v2", "file-audit", session, "definition", reportKey],
    queryFn: () => api.reportV2Definition(reportKey), initialData: reportKey === initial.key ? initial : undefined, staleTime: 5 * 60_000, retry: false });
  const definition = definitionQuery.data;
  const pageSize = fileAuditPageSize(requestedSize, definition?.limits.max ?? initial.limits.max);
  const requestValues: FilterValues = { ...values, view: undefined,
    path_search: activity ? values.path_search : undefined, account_search: activity ? values.account_search : undefined };
  const baseParams = definition ? fileAuditParams(definition, requestValues, timeZone, null, anchor, pageSize) : null;
  const params = definition ? fileAuditParams(definition, requestValues, timeZone, pages.at(-1), anchor, pageSize) : null;
  const data = useQuery({ queryKey: ["report-v2", "file-audit", session, "data", reportKey, params?.toString()],
    queryFn: () => api.reportV2Data(reportKey, params!), enabled: Boolean(params && definition?.access?.allowed !== false && !definitionQuery.error),
    retry: false, refetchOnWindowFocus: false,
    refetchInterval: view === "overview" ? 5_000 : false });
  const result = data.data;
  const optionKey = JSON.stringify([session, reportKey, values.file_server_domain, values.source_instance_id]);
  const [lastOptions, setLastOptions] = useState<{ key: string; options: NonNullable<typeof result>["filter_options"] }>();
  useEffect(() => {
    if (result?.filter_options && result.state !== "denied" && result.state !== "error")
      setLastOptions({ key: optionKey, options: result.filter_options });
  }, [result, optionKey]);
  const domain = useQuery({ queryKey: ["domains", access], queryFn: () => api.domains(),
    enabled: activity && Boolean(values.file_server_domain && api.domains), retry: false, staleTime: 30_000 });
  const error = definitionQuery.error ?? data.error;
  const denied = definition?.access?.allowed === false || result?.access?.allowed === false || result?.state === "denied"
    || error instanceof ApiResponseError && [401, 403].includes(error.status);
  const failed = Boolean(error) || result?.state === "error";
  const rows = !denied && !failed ? result?.items ?? [] : [];
  const resources = useResourceAuditControls(view === "overview" ? rows : [], session + ":" + baseParams + ":" + pages.at(-1),
    () => void data.refetch());
  const reset = () => { setPages([null]); setFirstPage(0); setSelectedId(null); };
  const pageIndex = firstPage + pages.length - 1;
  const currentKeys = new Set(access?.reports?.filter(report => report.allowed).map(report => report.report_key));
  const canPermissions = currentKeys.has("file-audit.permissions");
  const canRefreshCatalog = access?.platform_owner || access?.capabilities.includes("access.manage");
  useEffect(() => {
    if (view === "overview" && canRefreshCatalog && !denied)
      void api.refreshFileAuditCatalogs().catch(() => { /* Agents also refresh the catalog on check-in. */ });
  }, [view, session, canRefreshCatalog, denied]);
  const switchView = (next: string) => {
    reset(); setView(next as FileServerView);
    setValues(current => ({ ...current, operation: undefined, activity: undefined, record_unit: undefined }));
  };
  const makeListSearch = () => {
    const search = searchFromValues(definition ?? initial, requestValues);
    search.delete("file_server_domain");
    search.set("tab", view);
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
    if (activity) {
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
  const filterOptions = result?.filter_options ?? (lastOptions?.key === optionKey ? lastOptions.options : undefined);
  const serverOptions = filterOptions?.source_instance_id ?? [];
  const previousOptions = definition?.filter_options?.source_instance_id ?? [];
  const servers = [{ value: "", label: t("file-audit.screen.all_servers") }, ...(serverOptions.length ? serverOptions : previousOptions)];
  const shares = [
    { value: "", label: t("file-audit.activity.all_resources") },
    ...(selectedShares.length > 1 ? [{ value: "selected-resources", label: t("file-audit.activity.selected_resources", {
      count: formatNumber(selectedShares.length),
    }) }] : []),
    ...(filterOptions?.share ?? []),
  ];
  const viewTitle = (key: FileServerView) => key === "actions" || key === "overview" || key === "permissions"
    ? t(`file-audit.screen.${key}`) : tabTitle(key);
  const refresh = () => {
    reset();
    const next = minute();
    if (anchor.getTime() === next.getTime() && !pages.at(-1)) retry();
    setAnchor(next);
  };
  const title = viewTitle(view);
  const reason = result?.coverage.reason;
  const unmeasured = result?.state === "not_collected" || reason === "schedule_not_configured" || reason === "full_activity_not_collected";
  const emptyMessage = result?.state === "not_collected" ? "file-audit.screen.empty_setup"
    : view === "permissions" ? "file-audit.screen.empty_permissions"
    : view === "overview" ? "file-audit.screen.empty_resources"
    : reason === "schedule_not_configured" ? "file-audit.activity.no_schedule"
    : reason === "full_activity_not_collected" ? "file-audit.screen.empty_activity_not_collected"
    : pageIndex > 0 ? "file-audit.screen.empty_page"
    : view === "mass-operations" ? "file-audit.activity.no_mass_operations"
    : view === "access-denials" ? "file-audit.activity.no_denials"
    : view === "out-of-hours" ? "file-audit.activity.no_out_of_hours"
    : "file-audit.screen.empty_actions";
  const tabItems = [...FILE_SERVER_VIEWS, ...(view === "permission-changes" ? [view] : [])]
    .filter(key => key === view || !access?.reports || currentKeys.has("file-audit." + key))
    .map(key => ({ key, label: viewTitle(key) }));
  const activityFields = activity ? fileAuditFields(view, servers, shares) : [];
  const selectServer = (source?: string) => {
    reset();
    setValues(current => ({ ...current, source_instance_id: source, share: undefined, path: undefined,
      device_id: undefined, snapshot_id: undefined }));
  };
  const from = baseParams?.get("from"), to = baseParams?.get("to");
  const displayZone = timeZone === "browser" ? Intl.DateTimeFormat().resolvedOptions().timeZone : timeZone;
  const scopeLine = [
    values.file_server_domain ? domain.data?.items.find(item => String(item.id) === values.file_server_domain)?.display_name : t("shell.domain.all"),
    servers.find(option => option.value === String(values.source_instance_id ?? ""))?.label,
    shares.find(option => option.value === (selectedShare ?? ""))?.label,
    from && to ? `${formatCell(from, "datetime")} – ${formatCell(to, "datetime")}` : null,
    displayZone,
  ].filter(Boolean).join(" · ");
  const exportControl = exportHref && (!activity || !unmeasured) ? <a className="sli-ds-button" href={exportHref} download>
    {(result?.filtered_count ?? 0) > 10_000 && activity
      ? t("file-audit.activity.export_limit", { count: formatNumber(10_000) }) : t("reports.renderer.export_csv")}
  </a> : null;
  return <div className="sli-file-audit">
    <Tabs items={tabItems} active={view} onChange={switchView}>
      <ReportLayout title={t("file-audit.title")} meta={activity && !denied ? scopeLine : undefined}
        tabbed state={state} busy={data.isFetching && !data.isLoading}
        controls={{
          scope: activity ? undefined : <Select label={t("file-audit.workspace.server")} options={servers}
            value={String(values.source_instance_id ?? "")} onChange={source => selectServer(source || undefined)}/>,
          period: { value: period, presets: ["24h", "7d", "30d", "custom"], precision: "datetime-local", showBounds: !activity, showPrevious: false, strictRange: true,
            bounds: baseParams ? { from: baseParams.get("from")!, to: baseParams.get("to")! } : undefined,
            onChange: next => { reset(); setAnchor(minute()); setValues(appliedFileAuditValues({ ...values, period: next }, values, timeZone)); } },
          onRefresh: activity ? undefined : refresh, refreshing: data.isFetching,
        }}
        actions={<>
          {activity ? null : exportControl}
          {fileAuditReturnHref(entrySearch.get("return_to")) ? <a className="sli-ds-button" href={fileAuditReturnHref(entrySearch.get("return_to"))!}>{t("file-audit.workspace.back")}</a> : null}
        </>}
        tabs={<>
          <TabList label={t("file-audit.title")} variant="underline"/>
          {activity && !denied ? <div className="sli-ds-table__toolbar" data-align="start">
            <FilterBar layout="inline" applyInline compact primaryKeys={activityFields.map(field => field.key)}
              fields={activityFields} values={filterValues}
              onApply={next => {
                if (next.source_instance_id !== values.source_instance_id) {
                  selectServer(String(next.source_instance_id ?? "") || undefined);
                  return;
                }
                reset();
                const samePath = next.path_search === filterValues.path_search;
                setValues({ ...next, share: next.share === selectedShare ? values.share : next.share ? [String(next.share)] : undefined,
                  path: samePath ? values.path : undefined, path_search: samePath ? values.path_search : next.path_search,
                  activity: next.operation === values.operation ? values.activity : undefined });
              }}/>
            <div className="sli-file-audit__segments">
              <Button variant="primary" onClick={refresh} disabled={data.isFetching}>{t("shell.header.refresh")}</Button>
              {exportControl}
            </div>
          </div> : null}
        </>}
        stateView={denied ? <ReportDenied reportKey={reportKey}/> : <StateView state="error"
          message={definition && !params ? t("file-audit.invalid_period") : t("file-audit.screen.load_error", { subject: title })}
          onRetry={definition && !params ? undefined : retry}/>}>
        {definition && result ? <div ref={list}>
          {view === "overview" ? resources.errors.map(error => <p key={error} role="alert">{error}</p>) : null}
          <DataTable caption={title} compact density="compact" columns={[
            ...(view === "overview" && resources.column ? [resources.column] : []),
            ...(activity ? fileActivityColumns(view, definition.columns, selectedId, definition.row_key, open)
              : fileServerColumns(view, definition.columns, baseParams, canPermissions, open, hrefFor, () => void data.refetch())),
          ]}
            rows={view === "overview" ? resources.displayRows : rows} rowKey={row => String(row[definition.row_key])} selectedKey={selectedId}
            emptyContent={<p role="status">{t(emptyMessage)}</p>}
            onRowClick={activity ? open : undefined}
            renderExpandedRow={activity ? row => <FileAuditActivityDetails view={view} row={row} declared={definition.columns}
              params={baseParams} session={session} canPermissions={canPermissions}
              back={listHref + "&detail_row=" + encodeURIComponent(String(row[definition.row_key]))}/> : undefined}
            toolbar={view === "overview" ? resources.toolbar : undefined}
            total={result.filtered_count}
            showFooter={!activity || rows.length > 0 || !unmeasured}
            pageSize={{ value: pageSize, options: fileAuditPageSizes(definition.limits.max), onChange: size => {
              reset(); setRequestedSize(size); try { localStorage.setItem(preference, String(size)); } catch { /* optional preference */ }
            } }}
            pagination={{ start: pageIndex * pageSize + 1, busy: data.isFetching,
              pageLabel: activity ? rows.length ? t("file-audit.activity.range", {
                from: formatNumber(pageIndex * pageSize + 1), to: formatNumber(pageIndex * pageSize + rows.length),
              }) : t("file-audit.activity.no_records") : undefined,
              onPrevious: pages.length > 1 ? () => { setSelectedId(null); setPages(current => current.slice(0, -1)); } : undefined,
              onNext: result.has_more && result.next_cursor ? () => { setSelectedId(null); setPages(current => [...current, result.next_cursor]); } : undefined }}/>
        </div> : null}
      </ReportLayout>
    </Tabs>
  </div>;
}
