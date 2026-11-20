import { useDateFormatters } from "../../design-system/useDateFormatters";
import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { ReportColumnDto, ReportDefinitionDto } from "../../api/report-v2-types";
import { DataTable, DetailDrawer, FactList, FilterBar, MetricStrip, Panel, ReportLayout, Tabs, TabList, type FilterValues, type ResultState } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { useEffectiveAccess, useTimeZone } from "../../app/App";
import { columnValue, readPath, fillTemplate, searchFromValues, valuesFromSearch } from "../../app/report-v2/state";
import { cellKind, DetailSection, ResultWindowContext, tableColumns } from "../../app/report-v2/DetailSection";
import { CollectionView } from "../../app/report-v2/views";
import { ReportState } from "../../app/report-v2/ReportState";
import { ReportDenied } from "../../app/report-v2/ReportDenied";
import { accessErrorReason } from "../../app/report-v2/access";
import { FILE_AUDIT_TABS, fileAuditFields, fileAuditParams, tabTitle, type FileAuditTab } from "./report";
import { FileRansomDetails } from "./FileRansomDetails";
import { fileMaskLabel, type FileMaskLabels } from "./permissionMasks";
import { auditAgentHref } from "./agent-navigation";
import { withDomain } from "../../app/domain-navigation";

type Row = Record<string, unknown>;

/** Display labels only: raw rows, drawer evidence and server CSV stay intact. */
function fileAuditColumns(columns: ReportColumnDto[], timeZone: string) {
  const labels: FileMaskLabels = {
    none: t("file-audit.permissions.none"), read: t("file-audit.permissions.read"),
    write: t("file-audit.permissions.write"), readWrite: t("file-audit.permissions.read_write"),
    readExecute: t("file-audit.permissions.read_execute"), modify: t("file-audit.permissions.modify"),
    full: t("file-audit.permissions.full"), custom: t("file-audit.permissions.custom"),
  };
  return tableColumns(columns, timeZone).map((column, index) => {
    if (!["share_mask", "smb_mask", "ntfs_mask"].includes(column.key)) return column;
    const declared = columns[index];
    return { ...column, value: (row: Row) => {
      const raw = readPath(row, declared.path);
      return fileMaskLabel(raw, labels) ?? columnValue(declared, row);
    } };
  });
}

/** File-audit body inside the shared renderer; all data and scope come from v2 reports. */
export function FileAuditReport({ definition: initial }: { definition: ReportDefinitionDto }) {
  const { formatCell } = useDateFormatters();
  const access = useEffectiveAccess();
  const { timeZone } = useTimeZone();
  const search = new URLSearchParams(window.location.search);
  const requested = search.get("tab") ?? search.get("nav_view") ?? initial.key.slice("file-audit.".length);
  const [tab, setTab] = useState<FileAuditTab>(FILE_AUDIT_TABS.find((item) => item === requested) ?? "overview");
  const [values, setValues] = useState<FilterValues>(() => ({ period: { preset: "24h" }, include_nested: "true", ...valuesFromSearch(initial, search) }));
  const [pages, setPages] = useState<Array<string | null>>([null]);
  const [selected, setSelected] = useState<Row | null>(null);
  const [anchor, setAnchor] = useState(() => new Date());
  const reportKey = `file-audit.${tab}`;
  // Identity and evaluation revision fence cached data when grants change.
  const session = JSON.stringify([access?.subject.type, access?.subject.id, access?.evaluated_at_utc]);
  const declaration = useQuery({ queryKey: ["report-v2", "file-audit", session, "definition", reportKey],
    queryFn: () => api.reportV2Definition(reportKey), initialData: reportKey === initial.key ? initial : undefined, retry: false });
  const definition = declaration.data;
  const params = definition ? fileAuditParams(definition, values, timeZone, pages.at(-1), anchor) : null;
  const baseParams = definition ? fileAuditParams(definition, values, timeZone, null, anchor) : null;
  const data = useQuery({ queryKey: ["report-v2", "file-audit", session, "data", reportKey, params?.toString()],
    queryFn: () => api.reportV2Data(reportKey, params!), enabled: Boolean(definition && params && definition.access?.allowed !== false && !declaration.error), retry: false });
  const result = data.data;
  const rows = result?.items ?? [];
  const columns = useMemo(() => fileAuditColumns(definition?.columns ?? [], timeZone), [definition, timeZone]);
  const reset = () => { setPages([null]); setSelected(null); };
  const apply = (next: FilterValues) => { reset(); setAnchor(new Date()); setValues(next); };
  const selectTab = (key: string) => { reset(); setTab(key as FileAuditTab); };
  useEffect(() => {
    const next = searchFromValues(initial, values); next.set("tab", tab);
    const path = window.location.pathname.replace(/file-audit\.[a-z-]+$/, `file-audit.${tab}`);
    window.history.replaceState(window.history.state, "", withDomain(`${path}?${next.toString()}${window.location.hash}`, window.location.search));
  }, [initial, values, tab]);
  useEffect(() => { setSelected(null); setPages([null]); }, [session, timeZone]);

  const error = declaration.error ?? data.error;
  let state: ResultState = "loading";
  let detail: string | undefined;
  if (error) {
    state = error instanceof ApiResponseError && [401, 403].includes(error.status) ? "denied" : "error";
    if (state === "denied" && error instanceof ApiResponseError) detail = accessErrorReason(error);
  } else if (definition?.access?.allowed === false) state = "denied";
  else if (definition && !params) { state = "empty"; detail = t("file-audit.invalid_period"); }
  else if (result) state = result.access?.allowed === false ? "denied" : result.state;
  // A revoked result must not leave a previously opened row visible.
  const visibleSelection = !error && !data.isFetching && state !== "denied" && selected && rows.includes(selected) ? selected : null;
  const agentHref = visibleSelection ? auditAgentHref(access?.platform_owner === true, tab, visibleSelection.agent_id, window.location.search) : null;
  const canExport = access?.capabilities.includes("file-audit.export") && access.reports?.some((report) => report.report_key === reportKey && report.allowed && report.allowed_actions.includes("export"));
  const exportHref = canExport && definition?.export && baseParams && !error && result?.access?.allowed !== false && state !== "denied"
    ? `/api/v2/reports/${encodeURIComponent(reportKey)}/export.csv?${new URLSearchParams([...baseParams].filter(([key]) => key !== "limit"))}` : null;
  const denied = <ReportDenied reportKey={reportKey} reason={detail}/>;
  const collections = definition && result && !error ? definition.views
    .filter((view) => view.source && view.source !== "items" && view.access?.allowed !== false).map((view) =>
      <CollectionView key={view.key} view={view}
        columns={view.source === "groups" && view.kind === "table" ? fileAuditColumns(view.columns ?? [], timeZone) : undefined} rows={result.collections?.[view.source!] ?? []} reportTitle={tabTitle(tab)} state={result.state} stateDetails={result.state_details}/>) : null;

  return <ResultWindowContext.Provider value={result?.window}><Tabs items={FILE_AUDIT_TABS.map((key) => ({ key, label: tabTitle(key) }))} active={tab} onChange={selectTab}>
    <ReportLayout title={t("file-audit.title")} tabbed state={state} busy={data.isFetching && !data.isLoading}
      meta={result?.window.timezone ? <span>{result.window.timezone}</span> : null}
      actions={exportHref ? <a className="sli-ds-button" href={exportHref} download>{t("reports.renderer.export_csv")}</a> : null}
      metrics={!error && result && state !== "denied" ? <MetricStrip compact items={result.metrics.map((metric) => ({ ...metric, value: metric.quality === "unknown" ? null : metric.value,
        onSelect: metric.quality === "unknown" ? undefined : () => { setValues({ ...values, ...metric.filter }); selectTab(metric.key === "denials" ? "access-denials" : "actions"); } }))}/> : null}
      filters={definition ? <FilterBar align="start" layout="grid" fields={fileAuditFields(definition, result?.filter_options)} primaryKeys={["period", "path", "employee", "share", "operation"]}
        values={values} defaults={{ period: { preset: "24h" }, include_nested: "true" }} onApply={apply}/> : null}
      tabs={<TabList label={t("file-audit.title")}/>}
      stateView={state === "denied" ? denied : <ReportState state={state} detail={detail} details={result?.state_details}
        message={result?.state_message} onRetry={() => void (declaration.error ? declaration.refetch() : data.refetch())} compact={state === "partial" || state === "stale" || state === "processing"}/>}
      drawer={<DetailDrawer open={visibleSelection !== null} title={tabTitle(tab)} onClose={() => setSelected(null)}
        footer={visibleSelection && definition ? <>{agentHref ? <a href={agentHref} target="_blank" rel="noopener noreferrer" className="sli-ds-button">{t("file-audit.open_agent_new_tab")}</a> : null}{definition.row_links.map((link) => {
          const href = fillTemplate(link.href, visibleSelection);
          return href ? <a key={link.label} href={href} className="sli-ds-button">{link.label}</a> : null;
        })}</> : null}>
        {visibleSelection && definition ? <>
          <FactList facts={definition.columns.map((column) => ({ label: column.label, value: formatCell(columnValue(column, visibleSelection), cellKind(column)) }))}/>
          <FactList facts={["subject_sid", "correlation_state", "snapshot_id", "snapshot_sha256", "completeness"].filter((key) => visibleSelection[key] != null).map((key) => ({
            label: t(`file-audit.detail.${key}` as MessageKey), value: String(visibleSelection[key]),
          }))}/>
          {tab === "mass-operations" ? <FileRansomDetails row={visibleSelection}/> : null}
          {visibleSelection.audit_receipt && typeof visibleSelection.audit_receipt === "object" ? <FactList facts={
            Object.entries(visibleSelection.audit_receipt).filter(([key]) => ["command_id", "policy_revision", "action", "state", "observed_at", "reason_code", "result_sha256", "required_masks", "actual_masks"].includes(key))
              .map(([key, value]) => ({ label: t(`file-audit.receipt.${key}` as MessageKey), value: value && typeof value === "object" ? JSON.stringify(value) : formatCell(value, key === "observed_at" ? "datetime" : "text") }))
          }/> : null}
          {typeof definition.detail === "object" && baseParams ? <DetailSection definition={definition} detail={definition.detail} row={visibleSelection} baseParams={baseParams.toString()}/> : null}
        </> : null}
      </DetailDrawer>}>
      {definition && result && !error ? <>
        {tab !== "permissions" ? collections : null}
        <Panel title={t(`file-audit.headings.${tab}` as MessageKey)}><DataTable caption={tabTitle(tab)} columns={columns} rows={rows} rowKey={(row) => String(row[definition.row_key])}
          onRowClick={definition.detail !== "none" ? setSelected : undefined} total={result.filtered_count}
          pagination={{ start: (pages.length - 1) * 50 + 1, busy: data.isFetching,
            onPrevious: pages.length > 1 ? () => { setSelected(null); setPages((current) => current.slice(0, -1)); } : undefined,
            onNext: result.has_more && result.next_cursor ? () => { setSelected(null); setPages((current) => [...current, result.next_cursor]); } : undefined }}/></Panel>
        {tab === "permissions" ? collections : null}
        {tab === "audit-state" ? <Panel title={t("file-audit.retention")}><p className="sli-ds-state__text">{t("file-audit.audit_scope_note")}</p><FactList facts={[
          { label: t("file-audit.retention.payload"), value: t("file-audit.retention.payload_value") },
          { label: t("file-audit.retention.facts"), value: t("file-audit.retention.facts_value") },
          { label: t("file-audit.retention.acl"), value: t("file-audit.retention.acl_value") },
        ]}/></Panel> : null}
        {result.limitations.length ? <ul className="sli-ds-state__text">{result.limitations.map((item) => <li key={item.code}>{item.text}</li>)}</ul> : null}
      </> : null}
    </ReportLayout>
  </Tabs></ResultWindowContext.Provider>;
}
