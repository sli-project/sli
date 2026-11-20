import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, type V4ReportDefinition } from "../../api/client";
import { Badge, Button, Callout, DataTable, EmptyState, MetricStrip, PageHeader, StateView, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { useEffectiveAccess } from "../App";
import { CapabilityGate } from "./gate";
import "./report-studio.css";
import { DefinitionTab, PreviewTab, type PreviewState } from "./report-studio-editor";
import { AccessTab, CodeInfoTab, PublicationTab } from "./report-studio-publication";
import {
  buildRows, partitionRows, definitionBody, emptyForm, executableDatasets, formFromVersion, grantCount, previewSignature, statusLabel, statusTone, studioCapabilities,
  visibilityLabel, visibilityOf, metaComplete, type DefinitionForm, type PreviewResult, type StudioCapabilities, type StudioRow,
} from "./report-studio-model";

import { useReportTitles } from "../report-titles";
import { buildNavigation } from "../navigation";
import { reportTargetPath } from "../report-labels";

type Tab = "definition" | "preview" | "publication" | "access";
type Selection = { kind: "new" } | { kind: "row"; key: string; tab?: Tab };
type StatusFilter = "all" | "published" | "draft";

/** Для пользователя только с `reports.assign` реестр определений закрыт: показываем каталог без счётчиков. */
function rowsFromCatalog(items: Awaited<ReturnType<typeof api.v4Reports>>["items"]): StudioRow[] {
  return items.map((item) => ({
    key: item.report_key, name: item.name, version: item.version, date: null, status: item.status, datasetKey: item.dataset_key, datasetVersion: item.dataset_version,
    owner: item.owner, purpose: item.purpose, sensitivity: item.sensitivity, discoverable: Boolean(item.discoverable), requestable: Boolean(item.requestable),
    assignmentCount: null, packageCount: null, codeDefined: false, pendingDraft: null, published: item.status === "published",
  }));
}

function DetailBody({ row, detail, datasets, caps, userId, initialTab, onSaved }: {
  row: StudioRow | null;
  detail: Awaited<ReturnType<typeof api.v4ReportDefinitionDetail>> | null;
  datasets: ReturnType<typeof executableDatasets>;
  caps: StudioCapabilities;
  userId: number | null;
  initialTab: Tab;
  onSaved: (key: string, status: string) => void;
}) {
  const latest = detail?.versions.reduce((best, item) => (item.version > best.version ? item : best), detail.versions[0]);
  const [form, setFormState] = useState<DefinitionForm>(() => (latest ? formFromVersion(latest) : emptyForm()));
  const [tab, setTab] = useState<Tab>(initialTab);
  const [preview, setPreview] = useState<PreviewResult | null>(null);
  const dataset = useMemo(() => datasets.filter((item) => item.dataset_key === form.datasetKey).sort((a, b) => b.version - a.version)[0], [datasets, form.datasetKey]);
  const body = definitionBody(form, dataset);
  const signature = previewSignature(body);
  const fingerprint = JSON.stringify([signature, form.name, form.owner, form.purpose, form.sensitivity]);
  const [savedFingerprint] = useState(fingerprint);
  const run = useMutation({
    mutationFn: (withRows: boolean) => api.v4BuilderPreview({ ...body, ...(withRows ? { with_rows: true } : {}) }),
    onSuccess: (data, withRows) => setPreview({ signature, withRows, data }),
  });
  // Любая правка определения обесценивает проверку и сбрасывает ошибку: публиковать можно только проверенное.
  const setForm = (next: DefinitionForm) => { setFormState(next); run.reset(); };
  const current = preview && preview.signature === signature ? preview : null;
  const state: PreviewState = { current, pending: run.isPending, error: run.error };
  const codeDefined = Boolean(detail?.code_defined ?? row?.codeDefined);
  const limited = !caps.design && !caps.publish;
  const tabs: Array<{ key: Tab; label: string }> = limited ? [{ key: "access", label: t("studio.tab.access") }]
    : codeDefined ? [{ key: "definition", label: t("studio.tab.info") }, { key: "access", label: t("studio.tab.access") }]
    : [
      { key: "definition", label: t("studio.tab.definition") }, { key: "preview", label: t("studio.tab.preview") },
      { key: "publication", label: t("studio.tab.publication") }, ...(row ? [{ key: "access" as const, label: t("studio.tab.access") }] : []),
    ];
  const active = tabs.some((item) => item.key === tab) ? tab : tabs[0].key;
  const canPreview = caps.design && Boolean(body);
  // Сохранённую и нетронутую версию повторно проверять не нужно: сервер всё равно проверит её при выпуске.
  const previewOk = Boolean((current && !run.error) || (row && fingerprint === savedFingerprint));
  return <>
    <div className="sli-ds-tabs" role="tablist" aria-label={t("studio.tabs.aria")}>
      {tabs.map((item) => <button key={item.key} type="button" role="tab" aria-selected={active === item.key} onClick={() => setTab(item.key)}>{item.label}</button>)}
    </div>
    {active === "definition" && !codeDefined ? <DefinitionTab form={form} setForm={setForm} datasets={datasets} editable={caps.design} isNew={!row} preview={state}
      canValidate={canPreview} onValidate={() => run.mutate(false)}/> : null}
    {active === "definition" && codeDefined && row ? <CodeInfoTab row={row}/> : null}
    {active === "preview" ? <PreviewTab signature={signature} preview={state} canRun={canPreview} onRun={() => run.mutate(true)}
      reason={!caps.design ? t("studio.preview.need.design") : !body ? t("studio.preview.need.fields") : null}/> : null}
    {active === "publication" ? <PublicationTab row={row} detail={detail} form={form} body={body} previewOk={previewOk && metaComplete(form)} caps={caps} untouchedDraft={row && latest?.status === "draft" && fingerprint === savedFingerprint ? latest.version : null} onSaved={onSaved}/> : null}
    {active === "access" && row ? <AccessTab row={row} caps={caps} userId={userId}/> : null}
  </>;
}

function StudioDetail({ selection, rows, caps, userId, fetching, onSaved, onClose }: {
  selection: Selection; rows: StudioRow[]; caps: StudioCapabilities; userId: number | null; fetching: boolean;
  onSaved: (key: string, status: string) => void; onClose: () => void;
}) {
  const row = selection.kind === "row" ? rows.find((item) => item.key === selection.key) ?? null : null;
  const full = caps.design || caps.publish;
  const detail = useQuery({
    queryKey: ["v4", "studio", "detail", row?.key], retry: false, enabled: Boolean(row) && full,
    queryFn: () => api.v4ReportDefinitionDetail(row!.key),
  });
  const datasets = useQuery({ queryKey: ["v4", "studio", "datasets"], retry: false, enabled: full, queryFn: api.v4Datasets });
  const awaitingRow = selection.kind === "row" && !row;
  const loading = awaitingRow ? fetching : (row && full && detail.isLoading) || (full && datasets.isLoading);
  const failure = detail.error ?? datasets.error;
  const title = row ? row.name : t("studio.new.title");
  const initialTab: Tab = limitedTab(caps) ?? (selection.kind === "row" && selection.tab ? selection.tab : row?.codeDefined ? "definition" : row ? "publication" : "definition");
  return <aside className="sli-studio__detail" aria-label={title}>
    <header className="sli-studio__detail-head">
      <div><h2>{title}</h2><p className="sli-ds-header__subtitle">{row ? row.key : t("studio.new.subtitle")}</p></div>
      <Button onClick={onClose} aria-label={t("studio.close")}>✕</Button>
    </header>
    {loading ? <StateView state="loading"/> : awaitingRow ? <StateView state="unavailable" detail={t("studio.notfound")}/> : failure ? <StateView state="unavailable" detail={failure.message}/>
      : <DetailBody key={`${row?.key ?? "new"}:${initialTab}`} row={row} detail={detail.data ?? null} datasets={executableDatasets(datasets.data?.items ?? [])}
          caps={caps} userId={userId} initialTab={initialTab} onSaved={onSaved}/>}
  </aside>;
}

const limitedTab = (caps: StudioCapabilities): Tab | null => (!caps.design && !caps.publish ? "access" : null);

function RowDetails({ row }: { row: StudioRow }) {
  const total = grantCount(row);
  return <details className="sli-ds-admin__details" onClick={(event) => event.stopPropagation()}>
    <summary>{t("studio.row.details")}</summary>
    <dl>
      <dt>{t("studio.col.version")}</dt><dd>v{row.version}</dd>
      <dt>{t("studio.col.visibility")}</dt><dd>{row.published ? visibilityLabel(visibilityOf(row)) : t("table.noValue")}</dd>
      <dt>{t("studio.col.assignments")}</dt><dd>{total === null ? t("table.noValue") : total}</dd>
      <dt>{t("studio.col.source")}</dt><dd>{row.codeDefined ? t("studio.source.code") : t("studio.source.builder")}</dd>
    </dl>
  </details>;
}

function StudioContent() {
  const reportTitle = useReportTitles();
  const access = useEffectiveAccess();
  const catalog = useQuery({ queryKey: ["report-v2", "catalog"], queryFn: api.reportsV2Catalog, staleTime: 60_000, retry: false });
  const menuPaths = new Set(buildNavigation({
    reports: new Set(access?.reports.filter((report) => report.allowed).map((report) => report.report_key)),
    capabilities: new Set(access?.capabilities),
  }, catalog.data?.navigation).flatMap((section) => section.groups.flatMap((group) => group.items.map((item) => item.path))));
  const caps = studioCapabilities(access?.capabilities ?? []);
  const full = caps.design || caps.publish;
  const registry = useQuery({
    queryKey: ["v4", "studio", "definitions", full], retry: false,
    queryFn: async (): Promise<StudioRow[]> => (full ? buildRows((await api.v4ReportDefinitions()).items as V4ReportDefinition[]) : rowsFromCatalog((await api.v4Reports()).items)),
  });
  const [selection, setSelection] = useState<Selection | null>(null);
  const [filter, setFilter] = useState<StatusFilter>("all");
  const [showArchived, setShowArchived] = useState(false);
  const rows = (registry.data ?? []).map((row) => ({ ...row, name: reportTitle(row.key, row.name) }));
  const { current, archived } = partitionRows(rows);
  const visible = current.filter((row) => filter === "all" || row.status === filter);
  const count = (status: StatusFilter) => (status === "all" ? current.length : current.filter((row) => row.status === status).length);
  const unassigned = current.filter((row) => row.published && !row.codeDefined && grantCount(row) === 0).length;
  const detailsColumn: TableColumn<StudioRow> = { key: "details", label: t("studio.row.details"), render: (row) => <RowDetails row={row}/> };
  const columns: TableColumn<StudioRow>[] = [
    { key: "name", label: t("studio.col.name"), render: (row) => <strong>{row.name}</strong> },
    { key: "status", label: t("studio.col.status"), render: (row) => <><Badge tone={statusTone(row.status)}>{statusLabel(row.status)}</Badge>{row.pendingDraft ? <> <Badge tone="warning">{t("studio.row.pendingDraft", { version: row.pendingDraft })}</Badge></> : null}</> },
    { key: "owner", label: t("studio.def.owner"), mobile: false },
    { key: "date", label: t("studio.col.date"), kind: "datetime", mobile: false },
    { key: "menu", label: t("studio.col.menu"), render: (row) => catalog.data?.navigation
      ? t(row.published && menuPaths.has(reportTargetPath({ report_key: row.key, target_path: `/reports/${row.key}` })) ? "studio.menu.yes" : "studio.menu.no")
      : t("table.noValue") },
    detailsColumn,
  ];
  // Рядом с карточкой оставляем название, статус и раскрываемые сведения.
  const compact: TableColumn<StudioRow>[] = [
    { key: "name", label: t("studio.col.name"), render: (row) => <strong>{row.name}</strong> },
    { key: "status", label: t("studio.col.status"), render: (row) => <span className="sli-studio__nowrap"><Badge tone={statusTone(row.status)}>{statusLabel(row.status)}</Badge> v{row.version}</span> },
    detailsColumn,
  ];
  const selectedKey = selection?.kind === "row" ? selection.key : null;
  return <section className="sli-ds-report">
    <PageHeader title={t("studio.title")} subtitle={t("studio.subtitle")}
      actions={caps.design ? <Button variant="primary" icon="plus" onClick={() => setSelection({ kind: "new" })}>{t("studio.create")}</Button> : null}/>
    {!full ? <Callout tone="neutral" icon="key" title={t("studio.limited.title")}>{t("studio.limited.text")}</Callout> : null}
    {caps.design && !caps.publish ? <Callout tone="neutral" icon="lock" title={t("studio.nopublish.title")}>{t("studio.nopublish.text")}</Callout> : null}
    {caps.publish && !caps.design ? <Callout tone="neutral" icon="lock" title={t("studio.nodesign.title")}>{t("studio.nodesign.text")}</Callout> : null}
    {registry.isLoading ? <StateView state="loading"/> : registry.error ? <StateView state="unavailable" detail={registry.error.message} onRetry={() => void registry.refetch()}/> : null}
    {registry.data ? <MetricStrip label={t("studio.metrics.aria")} items={[
      { key: "total", label: t("studio.metrics.total"), value: current.length, caption: t("studio.metrics.total.caption") },
      { key: "published", label: t("studio.metrics.published"), value: current.filter((row) => row.published).length, caption: t("studio.metrics.published.caption"), tone: "success" as const },
      { key: "drafts", label: t("studio.metrics.drafts"), value: current.filter((row) => row.status === "draft" || row.pendingDraft).length, caption: t("studio.metrics.drafts.caption") },
      { key: "unassigned", label: t("studio.metrics.unassigned"), value: full ? unassigned : null, caption: t("studio.metrics.unassigned.caption"), tone: "warning" as const },
    ].filter((item) => item.value !== 0)}/> : null}
    <div className="sli-studio" data-detail={selection ? "open" : "closed"}>
      <div className="sli-studio__registry">
        {registry.data ? <>
          <div className="sli-ds-header__meta" role="group" aria-label={t("studio.filter.aria")}>
            {(["all", "published", "draft"] as const).map((status) => <button key={status} type="button" className="sli-ds-chip" aria-pressed={filter === status} onClick={() => setFilter(status)}>
              {status === "all" ? t("studio.filter.all") : statusLabel(status)} · {count(status)}
            </button>)}
          </div>
          {visible.length ? <DataTable caption={t("studio.registry.caption")} columns={selection ? compact : columns} rows={visible} rowKey={(row) => row.key} selectedKey={selectedKey}
            onRowClick={(row) => setSelection({ kind: "row", key: row.key })} stickyHeader={false}/>
            : <EmptyState title={t("studio.registry.empty.title")} copy={t("studio.registry.empty.text")}
                action={caps.design ? <Button variant="primary" onClick={() => setSelection({ kind: "new" })}>{t("studio.create")}</Button> : undefined}/>}
          {archived.length ? <>
            <Button aria-expanded={showArchived} aria-controls="studio-archived" onClick={() => setShowArchived(!showArchived)}>
              {t(showArchived ? "studio.archive.hide" : "studio.archive.show")}
            </Button>
            {showArchived ? <div id="studio-archived">
              <DataTable caption={t("studio.archive.caption")} columns={selection ? compact : columns} rows={archived} rowKey={(row) => row.key} selectedKey={selectedKey}
                onRowClick={(row) => setSelection({ kind: "row", key: row.key })} stickyHeader={false}/>
            </div> : null}
          </> : null}
        </> : null}
      </div>
      {selection ? <StudioDetail key={selection.kind === "new" ? "new" : selection.key} selection={selection} rows={rows} caps={caps} userId={access?.subject.id ?? null} fetching={registry.isFetching}
        onSaved={(key, status) => setSelection({ kind: "row", key, tab: status === "published" ? "access" : "publication" })} onClose={() => setSelection(null)}/> : null}
    </div>
  </section>;
}

export function ReportStudioPage() {
  return <CapabilityGate title={t("studio.title")} anyOf={["reports.design", "report.design", "reports.publish", "report.publish", "reports.assign"]} label={t("studio.gate.label")}>
    <StudioContent/>
  </CapabilityGate>;
}

