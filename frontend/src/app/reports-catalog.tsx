import { useMemo, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api, type V4Report } from "../api/client";
import { DataTable, DetailDrawer, PageHeader, StateView, type TableColumn } from "../design-system";
import { useOverlays } from "../design-system";
import { t } from "../i18n";
import { reportSupportsPreference, reportTargetPath, scopeKindLabel } from "./report-labels";

const otherSection = () => t("reports.catalog.other_section");

export type CatalogRow = {
  key: string;
  title: string;
  description: string;
  section: string;
  path: string;
  /** Опубликованный отчёт v4: доступ, закрепление и заявка идут через него. */
  report: V4Report | null;
};

const ACCESS_LABELS: Record<string, string> = {
  get available() { return t("reports.catalog.access.available"); },
  get available_until() { return t("reports.catalog.access.available_until"); },
  get requestable() { return t("reports.catalog.access.requestable"); },
  get request_pending() { return t("reports.catalog.access.request_pending"); },
  get request_rejected() { return t("reports.catalog.access.request_rejected"); },
  get request_unavailable() { return t("reports.catalog.access.request_unavailable"); },
};

function accessStateOf(report: V4Report): string {
  return report.access_state ?? (report.allowed ? "available" : report.requestable ? "requestable" : "request_unavailable");
}

/** Ключ v2-отчёта, на страницу которого ведёт опубликованный отчёт v4. */
function v2KeyOf(report: V4Report): string {
  const match = /^\/report\/([^/?#]+)/.exec(reportTargetPath(report));
  return match ? decodeURIComponent(match[1]) : report.report_key;
}

/** Строки единого каталога: v2-отчёты по разделам и опубликованные v4-отчёты, которых нет среди v2. */
export function buildCatalogRows(
  v2Items: Array<{ key: string; title: string; description: string; section_title: string }>,
  v4Items: V4Report[],
): CatalogRow[] {
  const v2Keys = new Set(v2Items.map((item) => item.key));
  const byV2Key = new Map<string, V4Report>();
  for (const report of v4Items) {
    const key = v2KeyOf(report);
    if (v2Keys.has(key) && !byV2Key.has(key)) byV2Key.set(key, report);
  }
  const rows: CatalogRow[] = v2Items.map((item) => ({
    key: item.key, title: item.title, description: item.description, section: item.section_title,
    path: `/report/${item.key}`, report: byV2Key.get(item.key) ?? null,
  }));
  for (const report of v4Items) {
    if (v2Keys.has(v2KeyOf(report))) continue;
    const target = reportTargetPath(report);
    rows.push({
      key: `v4:${report.report_key}`, title: report.name, description: report.purpose, section: otherSection(),
      path: target === "/reports" ? `/reports/${encodeURIComponent(report.report_key)}` : target, report,
    });
  }
  return rows;
}

export function ReportAccessRequestDrawer({ report, onClose }: { report: V4Report; onClose: () => void }) {
  const client = useQueryClient();
  const { toast } = useOverlays();
  const scopeKinds = report.request_profile?.scope_kinds?.length ? report.request_profile.scope_kinds : ["all"];
  const [scopeKind, setScopeKind] = useState(scopeKinds[0]);
  const [scopeValues, setScopeValues] = useState("");
  const [reason, setReason] = useState("");
  const [validUntil, setValidUntil] = useState(() => new Date(Date.now() + 30 * 86_400_000).toISOString().slice(0, 16));
  const send = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.v4CreateReportAccessRequest({ report_key: report.report_key, ...body }),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ["v4", "reports"] }),
        client.invalidateQueries({ queryKey: ["v4", "access"] }),
        client.invalidateQueries({ queryKey: ["v4", "report-access-requests"] }),
      ]);
      onClose();
      toast(t("reports.catalog.toast.request_sent"), t("reports.catalog.toast.request_sent_detail", { name: report.name }));
    },
    onError: (error: Error) => toast(t("reports.catalog.toast.request_failed"), error.message),
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (reason.trim().length < 10 || !validUntil) return;
    const values = scopeValues.split(",").map((item) => item.trim()).filter(Boolean);
    const scope = scopeKind === "all" ? { kind: "all" } : { kind: scopeKind, [scopeKind === "channel" ? "values" : "ids"]: values };
    send.mutate({ scope, business_reason: reason.trim(), valid_until: new Date(validUntil).toISOString() });
  };
  const formId = "report-request-form";
  return <DetailDrawer open title={t("reports.catalog.drawer.title")} subtitle={report.name} onClose={onClose}
    footer={<>
      <button type="button" className="sli-ds-button" onClick={onClose}>{t("reports.catalog.drawer.cancel")}</button>
      <button type="submit" form={formId} className="sli-ds-button" data-variant="primary" disabled={send.isPending}>{send.isPending ? t("reports.catalog.drawer.sending") : t("reports.catalog.drawer.send")}</button>
    </>}>
    <form id={formId} className="sli-ds-report__views" onSubmit={submit}>
      <p className="sli-ds-header__subtitle">{report.purpose}</p>
      <div className="sli-ds-field"><label htmlFor="request-scope">{t("reports.catalog.drawer.scope")}</label>
        <select id="request-scope" value={scopeKind} onChange={(event) => setScopeKind(event.target.value)}>
          {scopeKinds.map((kind) => <option key={kind} value={kind}>{scopeKindLabel(kind)}</option>)}
        </select></div>
      {scopeKind !== "all" ? <div className="sli-ds-field"><label htmlFor="request-scope-values">{t("reports.catalog.drawer.scope_values")}</label>
        <input id="request-scope-values" value={scopeValues} onChange={(event) => setScopeValues(event.target.value)} placeholder={t("reports.catalog.drawer.scope_placeholder")}/></div> : null}
      <div className="sli-ds-field"><label htmlFor="request-reason">{t("reports.catalog.drawer.reason")}</label>
        <textarea id="request-reason" required minLength={10} value={reason} onChange={(event) => setReason(event.target.value)} placeholder={t("reports.catalog.drawer.reason_placeholder")}/></div>
      <div className="sli-ds-field"><label htmlFor="request-valid-until">{t("reports.catalog.drawer.valid_until")}</label>
        <input id="request-valid-until" type="datetime-local" required value={validUntil} onChange={(event) => setValidUntil(event.target.value)}/></div>
    </form>
  </DetailDrawer>;
}

function CatalogSection({ title, rows, onRequest, onPin, pinningKey }: {
  title: string; rows: CatalogRow[]; onRequest: (report: V4Report) => void; onPin: (report: V4Report) => void; pinningKey: string | null;
}) {
  const columns: TableColumn<CatalogRow>[] = [
    { key: "title", label: t("reports.catalog.table.report"), render: (row) => !row.report || row.report.allowed ? <Link to={row.path}>{row.title}</Link> : row.title },
    { key: "description", label: t("reports.catalog.table.purpose") },
    { key: "access", label: t("reports.catalog.table.access"), render: (row) => (row.report ? ACCESS_LABELS[accessStateOf(row.report)] : t("reports.catalog.access.available")) },
    { key: "actions", label: t("reports.catalog.table.actions"), render: (row) => {
      const report = row.report;
      if (!report) return null;
      if (report.allowed) {
        if (!reportSupportsPreference(report)) return null;
        const pending = pinningKey === report.report_key;
        return <button type="button" className="sli-ds-button" disabled={pending} aria-label={report.pinned ? t("reports.catalog.action.unpin_aria", { name: report.name }) : t("reports.catalog.action.pin_aria", { name: report.name })} onClick={() => onPin(report)}>
          {pending ? t("reports.catalog.action.saving") : report.pinned ? t("reports.catalog.action.unpin") : t("reports.catalog.action.pin")}</button>;
      }
      const state = accessStateOf(report);
      if (report.requestable && state !== "request_pending") {
        return <button type="button" className="sli-ds-button" aria-label={t("reports.catalog.action.request_aria", { name: report.name })} onClick={() => onRequest(report)}>{state === "request_rejected" ? t("reports.catalog.action.request_retry") : t("reports.catalog.action.request")}</button>;
      }
      return <span>{state === "request_pending" ? t("reports.catalog.action.pending") : t("reports.catalog.action.unavailable")}</span>;
    } },
  ];
  return <section className="sli-ds-home-section" aria-label={title}>
    <h2 className="sli-ds-home-section__title">{title}</h2>
    <DataTable caption={title} columns={columns} rows={rows} rowKey={(row) => row.key}/>
  </section>;
}

/** Каталог отчётов: v2-отчёты по разделам и опубликованные v4-отчёты без v2-представления. */
export function ReportsCatalogPage() {
  const client = useQueryClient();
  const { toast } = useOverlays();
  const v2 = useQuery({ queryKey: ["report-v2", "catalog"], queryFn: api.reportsV2Catalog, staleTime: 60_000, retry: false });
  const v4 = useQuery({ queryKey: ["v4", "reports"], queryFn: api.v4Reports, staleTime: 30_000, retry: false });
  const [search, setSearch] = useState("");
  const [requesting, setRequesting] = useState<V4Report | null>(null);
  const preference = useMutation({
    mutationFn: ({ reportKey, pinned }: { reportKey: string; pinned: boolean }) => api.v4UpdateReportPreference(reportKey, pinned),
    onSuccess: async (_result, variables) => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ["v4", "reports"] }),
        client.invalidateQueries({ queryKey: ["v4", "workspace"] }),
        client.invalidateQueries({ queryKey: ["v4", "access"] }),
      ]);
      toast(variables.pinned ? t("reports.toast.pinned") : t("reports.toast.unpinned"), t("reports.toast.home_updated"));
    },
    onError: (error: Error) => toast(t("reports.toast.pin_failed"), error.message),
  });

  const rows = useMemo(() => buildCatalogRows(v2.data?.items ?? [], v4.data?.items ?? []), [v2.data, v4.data]);
  const needle = search.trim().toLowerCase();
  const visible = useMemo(() => rows.filter((row) => !needle || `${row.title} ${row.description} ${row.section}`.toLowerCase().includes(needle)), [rows, needle]);
  const sections = useMemo(() => {
    const groups = new Map<string, CatalogRow[]>();
    for (const row of visible) groups.set(row.section, [...(groups.get(row.section) ?? []), row]);
    return [...groups.entries()];
  }, [visible]);

  const loading = v2.isLoading || v4.isLoading;
  const failed = v2.isError && v4.isError;
  const state = loading ? "loading" : failed ? "unavailable" : visible.length ? "ok" : "empty";
  const partial = !loading && !failed && (v2.isError || v4.isError);
  const detail = failed ? (v2.error?.message ?? v4.error?.message)
    : rows.length ? t("reports.catalog.empty.search") : t("reports.catalog.empty.catalog");

  return <section className="sli-ds-report">
    <PageHeader title={t("reports.catalog.page.title")} subtitle={t("reports.catalog.page.subtitle")}/>
    <div className="sli-ds-filters">
      <div className="sli-ds-field"><label htmlFor="report-search">{t("reports.catalog.search.label")}</label>
        <input id="report-search" type="search" value={search} onChange={(event) => setSearch(event.target.value)} placeholder={t("reports.catalog.search.placeholder")}/></div>
      {search ? <div><button type="button" className="sli-ds-button" onClick={() => setSearch("")}>{t("reports.catalog.search.clear")}</button></div> : null}
    </div>
    {partial ? <StateView state="partial" compact detail={v2.isError ? t("reports.catalog.partial.v2") : t("reports.catalog.partial.v4")}/> : null}
    {state !== "ok" ? <StateView state={state} detail={state === "loading" ? undefined : detail} onRetry={() => { void v2.refetch(); void v4.refetch(); }}/> : null}
    {sections.map(([title, group]) => <CatalogSection key={title} title={title} rows={group} onRequest={setRequesting}
      onPin={(report) => preference.mutate({ reportKey: report.report_key, pinned: !report.pinned })}
      pinningKey={preference.isPending ? preference.variables?.reportKey ?? null : null}/>)}
    {requesting ? <ReportAccessRequestDrawer report={requesting} onClose={() => setRequesting(null)}/> : null}
  </section>;
}
