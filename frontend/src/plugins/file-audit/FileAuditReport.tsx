import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { DataTable, FactList, FilterBar, ReportLayout, StateView, Tabs, TabList, type FilterValues, type ResultState } from "../../design-system";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { t, type MessageKey } from "../../i18n";
import { useEffectiveAccess, useTimeZone } from "../../app/App";
import { columnValue, defaultValues, fillTemplate, searchFromValues, valuesFromSearch } from "../../app/report-v2/state";
import { cellKind, DetailSection, ResultWindowContext } from "../../app/report-v2/DetailSection";
import { CollectionView } from "../../app/report-v2/views";
import { ReportState } from "../../app/report-v2/ReportState";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { accessErrorReason } from "../../app/report-v2/access";
import { FILE_AUDIT_TABS, fileAuditFields, fileAuditParams, fileAuditPageSize, fileAuditPageSizes, fileAuditHref, fileAuditShare,
  fileAuditReturnHref, fileAuditFilterValues, appliedFileAuditValues, tabTitle, type FileAuditTab, type FileAuditRow as Row } from "./report";
import { FileRansomDetails } from "./FileRansomDetails";
import { fileAuditColumns, FileAuditCount, FileAuditInterval } from "./FileAuditCells";
import { FileAuditObjectWorkspace } from "./FileAuditObjectWorkspace";
import { auditAgentHref } from "./agent-navigation";
import { withDomain } from "../../app/domain-navigation";
import "./file-audit.css";

function initialAnchor(search: URLSearchParams) {
  const previous = search.get("fa_anchor");
  const instant = previous ? new Date(previous) : null;
  return instant && !Number.isNaN(instant.getTime()) ? instant : new Date(Math.floor(Date.now() / 60_000) * 60_000);
}

/** File-audit retains the shared report authorization and native row units. */
export function FileAuditReport({ definition: initial }: { definition: ReportDefinitionDto }) {
  const { formatCell } = useDateFormatters();
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const [entrySearch] = useState(() => new URLSearchParams(window.location.search));
  const defaultFilters: FilterValues = { period: { preset: "24h" }, include_nested: "true", source_kind: "server", ...defaultValues(initial) };
  const requested = entrySearch.get("tab") ?? entrySearch.get("nav_view") ?? initial.key.slice("file-audit.".length);
  const [tab, setTab] = useState<FileAuditTab>(FILE_AUDIT_TABS.find(item => item === requested) ?? "overview");
  const [values, setValues] = useState<FilterValues>(() => ({ ...defaultFilters, ...valuesFromSearch(initial, entrySearch),
    ...Object.fromEntries(["source_instance_id", "device_id", "snapshot_id"].flatMap(key => entrySearch.get(key) ? [[key, entrySearch.get(key)!]] : [])) }));
  const [pages, setPages] = useState<Array<string | null>>([entrySearch.get("cursor")]);
  const [initialPage, setInitialPage] = useState(Math.max(0, Number(entrySearch.get("page_index")) || 0));
  const [selectedId, setSelectedId] = useState<string | null>(entrySearch.get("detail_row"));
  const [highlight, setHighlight] = useState<string | null>(entrySearch.get("selected_row"));
  const [anchor, setAnchor] = useState(() => initialAnchor(entrySearch));
  const [workspace, setWorkspace] = useState<{ snapshot: string; path: string; params: string; back: string } | null>(null);
  const list = useRef<HTMLDivElement>(null);
  const listScroll = useRef(0);
  const preference = `sli.file-audit.page-size:${access?.subject.type ?? "unknown"}:${access?.subject.id ?? "unknown"}`;
  const [requestedSize, setRequestedSize] = useState(() => {
    try { return fileAuditPageSize(entrySearch.get("limit") ?? localStorage.getItem(preference), initial.limits.max); }
    catch { return 50; }
  });
  const reportKey = `file-audit.${tab}`;
  const session = JSON.stringify([access?.subject.type, access?.subject.id, access?.evaluated_at_utc]);
  const declaration = useQuery({ queryKey: ["report-v2", "file-audit", session, "definition", reportKey],
    queryFn: () => api.reportV2Definition(reportKey), initialData: reportKey === initial.key ? initial : undefined, retry: false });
  const definition = declaration.data;
  const pageSize = fileAuditPageSize(requestedSize, definition?.limits.max ?? initial.limits.max);
  const requestValues = tab === "permissions" && definition?.params.some(param => param.key === "view") ? { ...values, view: "objects" } : values;
  const params = definition ? fileAuditParams(definition, requestValues, timeZone, pages.at(-1), anchor, pageSize) : null;
  const baseParams = definition ? fileAuditParams(definition, requestValues, timeZone, null, anchor, pageSize) : null;
  const data = useQuery({ queryKey: ["report-v2", "file-audit", session, "data", reportKey, params?.toString()],
    queryFn: () => api.reportV2Data(reportKey, params!), enabled: Boolean(definition && params && definition.access?.allowed !== false && !declaration.error),
    retry: false, refetchOnWindowFocus: false });
  const result = data.data;
  const rows = result?.items ?? [];
  const reset = () => { setPages([null]); setInitialPage(0); setSelectedId(null); setWorkspace(null); };
  const filterValues = useMemo(() => fileAuditFilterValues(values, timeZone), [values, timeZone]);
  const apply = (draft: FilterValues) => {
    const next = appliedFileAuditValues(draft, values, timeZone);
    reset(); const instant = new Date(Math.floor(Date.now() / 60_000) * 60_000);
    if (instant.getTime() === anchor.getTime() && JSON.stringify(next) === JSON.stringify(values)) void data.refetch();
    setAnchor(instant); setValues(next);
  };
  const selectTab = (key: string) => { reset(); setTab(key as FileAuditTab); };
  const pageIndex = initialPage + pages.length - 1;
  const makeListSearch = () => {
    const next = searchFromValues(definition ?? initial, requestValues); next.set("tab", tab);
    next.set("limit", String(pageSize)); next.set("fa_anchor", anchor.toISOString());
    for (const key of ["source_instance_id", "device_id", "snapshot_id"]) if (typeof values[key] === "string" && values[key]) next.set(key, values[key]);
    if (pages.at(-1)) { next.set("cursor", pages.at(-1)!); next.set("page_index", String(pageIndex)); }
    if (highlight) next.set("selected_row", highlight);
    const returnTo = fileAuditReturnHref(entrySearch.get("return_to"));
    if (returnTo) next.set("return_to", returnTo);
    return next;
  };
  useEffect(() => {
    if (workspace) return;
    const next = makeListSearch();
    if (selectedId) next.set("detail_row", selectedId);
    if (entrySearch.get("object_path") && !workspace) {
      next.set("object_path", entrySearch.get("object_path")!);
      for (const key of ["object_tab", "compare_snapshot_id"]) if (entrySearch.get(key)) next.set(key, entrySearch.get(key)!);
    }
    window.history.replaceState(window.history.state, "", withDomain(`/app/report/${reportKey}?${next}${window.location.hash}`, window.location.search));
  }, [initial, definition, values, tab, pageSize, pageIndex, selectedId, anchor, workspace]);
  const previousScope = useRef(`${session}:${timeZone}`);
  useEffect(() => {
    const next = `${session}:${timeZone}`;
    if (previousScope.current !== next) { previousScope.current = next; reset(); }
  }, [session, timeZone]);
  useEffect(() => {
    if (!selectedId && !workspace && list.current) {
      const scroll = list.current.querySelector<HTMLElement>(".sli-ds-table__scroll");
      if (scroll) scroll.scrollTop = listScroll.current;
    }
  }, [selectedId, workspace, data.dataUpdatedAt]);

  const error = declaration.error ?? data.error;
  let state: ResultState = "loading";
  let detail: string | undefined;
  if (error) {
    state = error instanceof ApiResponseError && [401, 403].includes(error.status) ? "denied" : "error";
    if (state === "denied" && error instanceof ApiResponseError) detail = accessErrorReason(error);
  } else if (definition?.access?.allowed === false) state = "denied";
  else if (definition && !params) { state = "empty"; detail = t("file-audit.invalid_period"); }
  else if (result) state = result.access?.allowed === false ? "denied" : result.state;
  if (!error && result?.coverage.reason === "full_activity_not_collected") detail = t("file-audit.workspace.full_activity_not_collected");
  const reportAccess = access?.reports?.find(report => report.report_key === reportKey);
  const canConfigure = access && !access.preview && (access.platform_owner === true
    || (access.subject.coarse_role === "admin"
      && ["access.manage", "operations.view", "file-audit.audit.manage"].every(key => access.capabilities.includes(key))
      && reportAccess?.allowed && reportAccess.scopes?.some(scope => scope.kind === "all" || scope.mode === "all")));
  const explicitScope = ["domain", "domain_id", "scope", "agent_id", "source_kind", "source_instance_id", "device_id", "collection_scope_id", "share"]
    .some(key => entrySearch.has(key));
  const plugin = result?.plugin ?? definition?.plugin;
  const checkSource = Boolean(canConfigure && !explicitScope && !plugin?.read_only && plugin?.state !== "disabled"
    && tab === "overview" && pages.length === 1 && state === "not_collected" && data.isSuccess && !data.isFetching
    && !rows.length && searchFromValues(initial, values).toString() === searchFromValues(initial, defaultFilters).toString());
  const agents = useQuery({ queryKey: ["admin-agents"], queryFn: () => api.agents(), enabled: checkSource, retry: false });
  const offerSetup = checkSource && agents.isSuccess && !agents.isFetching && !agents.data.items.some(agent =>
    agent.assigned_modules.some(module => (typeof module === "string" ? module : module.module_id) === "sli.file-audit"));
  const visibleSelection = !error && !data.isFetching && state !== "denied" && selectedId && definition
    ? rows.find(row => String(row[definition.row_key]) === selectedId) ?? null : null;
  const agentHref = visibleSelection ? auditAgentHref(access?.platform_owner === true, tab, visibleSelection.agent_id, window.location.search) : null;
  const canExport = access?.capabilities.includes("file-audit.export") && reportAccess?.allowed && reportAccess.allowed_actions.includes("export");
  const exportHref = canExport && definition?.export && baseParams && !error && result?.access?.allowed !== false && state !== "denied"
    ? `/api/v2/reports/${encodeURIComponent(reportKey)}/export.csv?${new URLSearchParams([...baseParams].filter(([key]) => key !== "limit"))}` : null;
  const exportLimit = Number((result?.window as Record<string, unknown> | undefined)?.export_row_limit) || null;
  const canPermissions = access?.reports?.some(report => report.report_key === "file-audit.permissions" && report.allowed);
  const listHref = withDomain(`/app/report/${reportKey}?${makeListSearch()}`, window.location.search);
  const hrefFor = (next: FileAuditTab, row: Row, extra: Record<string, string | null> = {}) => withDomain(fileAuditHref(next, baseParams ?? new URLSearchParams(), row,
    { return_to: listHref, ...(tab === "overview" && next === "permission-changes" ? { record_unit: "saved_event_group", ...(baseParams?.get("path") ? { path: baseParams.get("path")! } : {}) } : {}), ...extra }), window.location.search);
  const open = (row: Row) => {
    if (!definition) return;
    listScroll.current = list.current?.querySelector<HTMLElement>(".sli-ds-table__scroll")?.scrollTop ?? 0;
    setHighlight(String(row[definition.row_key]));
    if ((tab === "overview" || tab === "permissions") && canPermissions && typeof row.snapshot_id === "string" && typeof row.path === "string" && fileAuditShare(row)) {
      const href = hrefFor("permissions", row, { object_path: row.path });
      setWorkspace({ snapshot: row.snapshot_id, path: row.path, params: new URL(href, window.location.origin).searchParams.toString(), back: listHref });
      window.history.replaceState(window.history.state, "", href);
    } else setSelectedId(String(row[definition.row_key]));
  };
  const close = () => { setSelectedId(null); setWorkspace(null); };
  const directObject = tab === "permissions" && entrySearch.get("object_path") && entrySearch.get("snapshot_id") && baseParams
    ? { snapshot: entrySearch.get("snapshot_id")!, path: entrySearch.get("object_path")!, params: baseParams.toString(),
      back: fileAuditReturnHref(entrySearch.get("return_to")) ?? fileAuditHref("permissions", baseParams, undefined, { object_path: null }) } : null;
  const objectWorkspace = workspace ?? directObject;
  const columns = fileAuditColumns(definition?.columns ?? [], timeZone, tab, rows, baseParams, open, hrefFor);
  const collections = definition && result && !error && requestValues.view !== "objects" ? definition.views
    .filter(view => view.kind === "table" && view.source && view.source !== "items" && view.access?.allowed !== false).map(view =>
      <CollectionView key={view.key} view={view} rows={result.collections?.[view.source!] ?? []}
        columns={view.source === "groups" ? fileAuditColumns(view.columns ?? [], timeZone, tab, result.collections?.[view.source!] ?? [], baseParams, open, hrefFor) : undefined}
        reportTitle={tabTitle(tab)} state={result.state} stateDetails={result.state_details}/>) : null;
  if (objectWorkspace && state !== "denied" && !error) return <FileAuditObjectWorkspace key={`${session}:${objectWorkspace.snapshot}:${objectWorkspace.path}`}
    snapshotId={objectWorkspace.snapshot} objectPath={objectWorkspace.path} params={objectWorkspace.params} backHref={objectWorkspace.back}
    session={session} pageSize={pageSize} onBack={workspace ? close : undefined}/>;

  return <div className="sli-file-audit"><ResultWindowContext.Provider value={result?.window}>
    <Tabs items={FILE_AUDIT_TABS.map(key => ({ key, label: tabTitle(key) }))} active={tab} onChange={selectTab}>
      <ReportLayout title={values.source_kind === "workstation" ? t("file-audit.workspace.workstations") : t("file-audit.title")}
        tabbed state={state} busy={data.isFetching && !data.isLoading}
        meta={baseParams ? <><span>{t("file-audit.workspace.scope")}</span><span>{formatCell(baseParams.get("from"), "datetime")} — {formatCell(baseParams.get("to"), "datetime")}</span><span>{timeZone}</span>
          {values.show_service === "false" ? <span>{t("file-audit.workspace.service_hidden")}</span> : null}
          {values.record_unit === "saved_event_group" ? <span>{t("file-audit.workspace.saved_4670_groups")}</span> : null}</> : null}
        actions={<>{visibleSelection ? <button type="button" className="sli-ds-button" onClick={close}>{t("file-audit.workspace.back")}</button>
          : <button type="button" className="sli-ds-button" disabled={data.isFetching} onClick={() => { reset(); const next = new Date(Math.floor(Date.now() / 60_000) * 60_000); setAnchor(next); if (next.getTime() === anchor.getTime()) void data.refetch(); }}>{t("file-audit.workspace.refresh")}</button>}
          {exportHref && !visibleSelection ? <a className="sli-ds-button" href={exportHref} download title={exportLimit ? t("file-audit.workspace.export_limit", { count: exportLimit }) : undefined}>{t("reports.renderer.export_csv")}</a> : null}
          {!visibleSelection && fileAuditReturnHref(entrySearch.get("return_to")) ? <a className="sli-ds-button" href={fileAuditReturnHref(entrySearch.get("return_to"))!}>{t("file-audit.workspace.back")}</a> : null}</>}
        filters={definition && !visibleSelection ? <FilterBar align="start" layout="grid" fields={fileAuditFields(definition, result?.filter_options)}
          primaryKeys={tab === "overview" ? ["period", "source_instance_id", "share", "path"] : ["period", "source_instance_id", "share", "path", "employee", "operation", "record_unit"]}
          values={filterValues} defaults={defaultFilters} onApply={apply}/> : null}
        tabs={<TabList label={t("file-audit.title")} variant="underline"/>}
        stateView={offerSetup ? <StateView state="empty" titleMessage={{ code: "pluginPage.noSources", params: {} }} detail={
          <a className="sli-ds-button" href="/app/admin/plugins/sli.file-audit">{t("pluginPage.configure")}</a>}/>
          : state === "denied" ? <ReportDenied reportKey={reportKey} reason={detail}/>
          : state === "partial" ? <></> : <ReportState state={state} detail={detail} details={result?.state_details} message={result?.state_message}
            onRetry={() => void (declaration.error ? declaration.refetch() : data.refetch())} compact={state === "stale" || state === "processing"}/>}>
        {definition && result && !error ? visibleSelection ? <section aria-label={t("file-audit.workspace.evidence")} className="sli-file-audit__evidence">
          <h2>{String(visibleSelection.path ?? tabTitle(tab))}</h2>
          {visibleSelection.aggregate ? <div className="sli-file-audit__observation">
            <FileAuditInterval row={visibleSelection}/><strong><FileAuditCount row={visibleSelection}/></strong>
            <p>{t("file-audit.workspace.aggregate")}</p>
            {(visibleSelection.aggregate as { boundary?: string }).boundary === "overlap" ? <p>{t("file-audit.workspace.boundary")}</p> : null}
          </div> : null}
          <FactList facts={definition.columns.map(column => ({ label: column.label, value: formatCell(columnValue(column, visibleSelection), cellKind(column)) }))}/>
          <FactList facts={["subject_sid", "correlation_state", "snapshot_id", "snapshot_sha256", "completeness"].filter(key => visibleSelection[key] != null).map(key => ({ label: t(`file-audit.detail.${key}` as MessageKey), value: String(visibleSelection[key]) }))}/>
          <div className="sli-ds-header__actions">
            {canPermissions && fileAuditShare(visibleSelection) ? <a className="sli-ds-button" href={hrefFor("permissions", visibleSelection,
              typeof visibleSelection.snapshot_id === "string" ? { object_path: String(visibleSelection.path) } : {})}>{t("file-audit.workspace.open_permissions")}</a> : null}
            {agentHref ? <a href={agentHref} target="_blank" rel="noopener noreferrer" className="sli-ds-button">{t("file-audit.open_agent_new_tab")}</a> : null}
            {definition.row_links.map(link => { const href = fillTemplate(link.href, visibleSelection); return href ? <a key={link.label} href={withDomain(href, window.location.search)} className="sli-ds-button">{link.label}</a> : null; })}
          </div>
          {tab === "mass-operations" ? <FileRansomDetails row={visibleSelection}/> : null}
          {visibleSelection.audit_receipt && typeof visibleSelection.audit_receipt === "object" ? <FactList facts={Object.entries(visibleSelection.audit_receipt)
            .filter(([key]) => ["command_id", "policy_revision", "action", "state", "observed_at", "reason_code", "result_sha256", "required_masks", "actual_masks"].includes(key))
            .map(([key, value]) => ({ label: t(`file-audit.receipt.${key}` as MessageKey), value: value && typeof value === "object" ? JSON.stringify(value) : formatCell(value, key === "observed_at" ? "datetime" : "text") }))}/> : null}
          {typeof definition.detail === "object" && baseParams ? <DetailSection definition={definition} detail={definition.detail} row={visibleSelection} baseParams={baseParams.toString()}/> : null}
        </section> : <>
          <div ref={list}><DataTable caption={tabTitle(tab)} columns={columns} rows={rows} rowKey={row => String(row[definition.row_key])}
            compact density="compact" selectedKey={highlight} onRowClick={definition.detail !== "none" ? open : undefined}
            total={result.filtered_count} pageSize={{ value: pageSize, options: fileAuditPageSizes(definition.limits.max), onChange: size => { reset(); setRequestedSize(size); try { localStorage.setItem(preference, String(size)); } catch { /* preferences are optional */ } } }}
            pagination={{ start: pageIndex * pageSize + 1, busy: data.isFetching,
              onPrevious: pages.length > 1 ? () => { setSelectedId(null); setPages(current => current.slice(0, -1)); } : undefined,
              onNext: result.has_more && result.next_cursor ? () => { setSelectedId(null); setPages(current => [...current, result.next_cursor]); } : undefined }}/></div>
          {collections}
          {result.coverage.reason === "full_activity_not_collected" ? <p className="sli-file-audit__local-state">{t("file-audit.workspace.full_activity_not_collected")}</p> : null}
          {tab === "audit-state" ? <p className="sli-file-audit__local-state">{t("file-audit.audit_scope_note")}</p> : null}
          {exportHref && exportLimit ? <p className="sli-file-audit__local-state">{t("file-audit.workspace.export_limit", { count: exportLimit })}</p> : null}
          {result.limitations.filter(item => !item.code.endsWith("coverage_unverified")).length ? <ul className="sli-file-audit__limitations">{result.limitations.filter(item => !item.code.endsWith("coverage_unverified")).map(item => <li key={item.code}>{item.text}</li>)}</ul> : null}
        </> : null}
      </ReportLayout>
    </Tabs>
  </ResultWindowContext.Provider></div>;
}
