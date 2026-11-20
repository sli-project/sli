import { useDateFormatters } from "../../design-system/useDateFormatters";
import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api, ApiResponseError, type V4ReportDefinitionDetail, type V4ReportDefinitionVersion } from "../../api/client";
import { Badge, Button, Callout, DataTable, EmptyState, FactList, StateView, useOverlays, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { accessActionLabel } from "../report-labels";
import { saveReportVersionWithVerification } from "../v4-mutation-workflows";
import { AssignDrawer } from "./report-assign-drawer";
import {
  canMutate, errorCode, errorMessage, metaComplete, statusLabel, statusTone, visibilityLabel, visibilityOf,
  type DefinitionForm, type StudioCapabilities, type StudioRow,
} from "./report-studio-model";

const SENSITIVITY_KEYS = { internal: "studio.sensitivity.low", restricted: "studio.sensitivity.restricted", confidential: "studio.sensitivity.confidential" } as const;

/** Подтверждение необратимого или заметного для других шага: общий модальный диалог дизайн-системы. */
function useConfirm() {
  const { openModal, closeModal } = useOverlays();
  return (title: string, body: ReactNode, confirmLabel: string, onConfirm: () => void) => openModal({
    title, body,
    footer: <>
      <Button onClick={closeModal}>{t("studio.confirm.cancel")}</Button>
      <Button variant="primary" onClick={() => { closeModal(); onConfirm(); }}>{confirmLabel}</Button>
    </>,
  });
}

const MutationError = ({ error }: { error: unknown }) => {
  if (!error) return null;
  if (errorCode(error) === "report_security_reapproval_required") {
    return <Callout tone="danger" role="alert" title={t("studio.reapproval.title")}>{t("studio.reapproval.text")}</Callout>;
  }
  return <p className="sli-ds-field__error" role="alert">{errorMessage(error)}</p>;
};

/** Вкладка «Публикация»: версии, сохранение, выпуск, снятие и видимость. */
export function PublicationTab({ row, detail, form, body, previewOk, caps, untouchedDraft, onSaved }: {
  row: StudioRow | null;
  detail: V4ReportDefinitionDetail | null;
  form: DefinitionForm;
  body: Record<string, unknown> | null;
  previewOk: boolean;
  /** Номер сохранённого и нетронутого черновика: «Опубликовать» выпускает его, а не плодит копию. */
  untouchedDraft: number | null;
  caps: StudioCapabilities;
  onSaved: (key: string, status: string) => void;
}) {
  const { formatDateTime } = useDateFormatters();
  const client = useQueryClient();
  const { toast } = useOverlays();
  const confirm = useConfirm();
  const mayMutate = canMutate(caps);
  const refresh = () => void client.invalidateQueries({ queryKey: ["v4"] });
  const save = useMutation({
    mutationFn: (status: "draft" | "published") => saveReportVersionWithVerification({
      report_key: form.reportKey.trim(), name: form.name.trim(), purpose: form.purpose.trim(), owner: form.owner.trim(), sensitivity: form.sensitivity, status, ...body,
    }),
    onSuccess: (result) => {
      toast(result.status === "published" ? t("studio.toast.published") : t("studio.toast.draftSaved"), t("studio.toast.versionVerified", { version: result.version }));
      refresh();
      onSaved(result.reportKey, result.status);
    },
  });
  const promote = useMutation({
    mutationFn: (version: number) => api.v4PromoteReportVersion(form.reportKey, version),
    onSuccess: () => { toast(t("studio.toast.promoted"), t("studio.toast.promoted.text")); refresh(); },
  });
  const retire = useMutation({
    mutationFn: () => api.v4RetireReport(form.reportKey),
    onSuccess: () => { toast(t("studio.toast.retired"), t("studio.toast.retired.text")); refresh(); },
  });
  const publishedVersion = detail?.versions.find((item) => item.status === "published") ?? null;
  const [discoverable, setDiscoverable] = useState(publishedVersion?.discoverable ?? false);
  const [requestable, setRequestable] = useState(publishedVersion?.requestable ?? false);
  const visibility = useMutation({
    mutationFn: () => api.v4SetReportVisibility(form.reportKey, { discoverable, requestable: discoverable && requestable }),
    onSuccess: () => { toast(t("studio.toast.visibility"), t("studio.toast.visibility.text")); refresh(); },
  });
  const visibilityChanged = Boolean(publishedVersion) && (discoverable !== publishedVersion?.discoverable || (discoverable && requestable) !== publishedVersion?.requestable);

  const saveBlock = !mayMutate ? t("studio.pub.need.both", { missing: [!caps.design ? t("studio.cap.reports.design") : "", !caps.publish ? t("studio.cap.reports.publish") : ""].filter(Boolean).join(", ") })
    : !metaComplete(form) ? t("studio.pub.need.meta")
    : !previewOk ? t("studio.pub.need.preview") : null;
  const mutating = save.isPending || promote.isPending || retire.isPending || visibility.isPending;

  const columns: TableColumn<V4ReportDefinitionVersion>[] = [
    { key: "version", label: t("studio.versions.version"), render: (item) => `v${item.version}` },
    { key: "status", label: t("studio.versions.status"), render: (item) => <Badge tone={statusTone(item.status)}>{statusLabel(item.status)}</Badge> },
    { key: "published_at", label: t("studio.versions.published"), render: (item) => (item.published_at ? formatDateTime(item.published_at) : t("table.noValue")) },
    { key: "owner_name", label: t("studio.versions.owner") },
    { key: "actions", label: t("studio.versions.actions"), render: (item) => item.status === "draft"
      ? <Button disabled={!mayMutate || mutating} onClick={() => confirm(t("studio.confirm.promote.title", { version: item.version }), t("studio.confirm.promote.text"), t("studio.pub.promote"), () => promote.mutate(item.version))}>{t("studio.pub.promote")}</Button>
      : item.status === "published"
        ? <Button disabled={!mayMutate || mutating} onClick={() => confirm(t("studio.confirm.retire.title"), t("studio.confirm.retire.text"), t("studio.pub.retire"), () => retire.mutate())}>{t("studio.pub.retire")}</Button>
        : null },
  ];

  return <div className="sli-studio__tab">
    <section aria-label={t("studio.pub.save")}>
      <h3 className="sli-ds-section-title">{t("studio.pub.save")}</h3>
      <p className="sli-ds-header__subtitle">{t("studio.pub.save.text")}</p>
      <div className="sli-ds-filters__actions">
        <Button disabled={Boolean(saveBlock) || mutating} onClick={() => save.mutate("draft")}>{t("studio.pub.draft")}</Button>
        <Button variant="primary" disabled={Boolean(saveBlock) || mutating}
          onClick={() => confirm(t("studio.confirm.publish.title"), <>{t("studio.confirm.publish.text")}</>, t("studio.pub.publish"), () => (untouchedDraft ? promote.mutate(untouchedDraft) : save.mutate("published")))}>{save.isPending ? t("studio.pub.saving") : t("studio.pub.publish")}</Button>
      </div>
      {saveBlock ? <p role="note" className="sli-ds-header__subtitle">{saveBlock}</p> : null}
      <MutationError error={save.error ?? promote.error ?? retire.error}/>
    </section>

    {row ? <section aria-label={t("studio.versions.title")}>
      <h3 className="sli-ds-section-title">{t("studio.versions.title")}</h3>
      {detail?.versions.length ? <DataTable caption={t("studio.versions.title")} columns={columns} rows={detail.versions} rowKey={(item) => String(item.version)} stickyHeader={false}/> : <StateView state="empty" compact/>}
    </section> : null}

    {row && publishedVersion ? <section aria-label={t("studio.visibility.title")}>
      <h3 className="sli-ds-section-title">{t("studio.visibility.title")}</h3>
      <p className="sli-ds-header__subtitle">{t("studio.visibility.explain")}</p>
      <fieldset className="sli-ds-choices" disabled={!mayMutate}>
        <legend className="sli-ds-sr-only">{t("studio.visibility.title")}</legend>
        <label><input type="checkbox" checked={discoverable} onChange={(event) => { setDiscoverable(event.target.checked); if (!event.target.checked) setRequestable(false); }}/>{t("studio.visibility.catalog")}</label>
        <label><input type="checkbox" checked={discoverable && requestable} disabled={!discoverable} onChange={(event) => setRequestable(event.target.checked)}/>{t("studio.visibility.requestable")}</label>
      </fieldset>
      <p className="sli-ds-header__subtitle">{t("studio.visibility.help")}</p>
      <div><Button disabled={!mayMutate || !visibilityChanged || mutating} onClick={() => visibility.mutate()}>{t("studio.visibility.apply")}</Button></div>
      {!mayMutate ? <p role="note" className="sli-ds-header__subtitle">{t("studio.pub.need.both", { missing: [!caps.design ? t("studio.cap.reports.design") : "", !caps.publish ? t("studio.cap.reports.publish") : ""].filter(Boolean).join(", ") })}</p> : null}
      <MutationError error={visibility.error}/>
    </section> : null}
  </div>;
}

const subjectLabel = (item: Record<string, unknown>) =>
  String(item.subject_name ?? item.username ?? item.subject_label ?? item.name ?? `${item.subject_type ?? "?"} #${item.subject_id ?? "?"}`);

/** Вкладка «Доступ»: кто уже имеет отчёт, пакеты, заявки и назначение. */
export function AccessTab({ row, caps, userId }: { row: StudioRow; caps: StudioCapabilities; userId: number | null }) {
  const { formatDateTime } = useDateFormatters();
  const [assign, setAssign] = useState<{ preset: number | null } | null>(null);
  const summary = useQuery({
    queryKey: ["v4", "studio", "access-summary", row.key], retry: false,
    queryFn: () => api.v4ReportAccessSummary(row.key),
  });
  const unsupported = summary.error instanceof ApiResponseError && (summary.error.status === 404 || summary.error.status === 405);
  const data = summary.data;
  const pending = Array.isArray(data?.pending_requests) ? data.pending_requests.length : Number(data?.pending_requests ?? 0);
  const assignBlock = !caps.assign ? t("studio.access.need.assign") : !row.published ? t("studio.access.need.published") : null;

  return <div className="sli-studio__tab">
    <FactList facts={[
      { label: t("studio.access.direct"), value: row.assignmentCount },
      { label: t("studio.access.packages"), value: row.packageCount },
      { label: t("studio.access.visibility"), value: visibilityLabel(visibilityOf(row)) },
    ]}/>
    <div className="sli-ds-filters__actions">
      <Button variant="primary" disabled={Boolean(assignBlock)} onClick={() => setAssign({ preset: null })}>{t("studio.access.assign")}</Button>
      <Button disabled={Boolean(assignBlock) || userId === null} onClick={() => setAssign({ preset: userId })}>{t("studio.access.assignMe")}</Button>
      {row.published ? (row.codeDefined ? <Link className="sli-ds-button" to="/report/$reportKey" params={{ reportKey: row.key }}>{t("studio.access.open")}</Link> : <Link className="sli-ds-button" to="/reports/$reportKey" params={{ reportKey: row.key }}>{t("studio.access.open")}</Link>) : null}
    </div>
    {assignBlock ? <p role="note" className="sli-ds-header__subtitle">{assignBlock}</p> : null}
    {summary.isLoading ? <StateView state="loading" compact/> : null}
    {unsupported ? <p className="sli-ds-header__subtitle">{t("studio.access.summary.unsupported")}</p> : null}
    {summary.error && !unsupported ? <StateView state="unavailable" compact detail={errorMessage(summary.error)} onRetry={() => void summary.refetch()}/> : null}
    {data ? <>
      <section aria-label={t("studio.access.who")}>
        <h3 className="sli-ds-section-title">{t("studio.access.who")}</h3>
        {data.assignments?.length ? <ul className="sli-studio__caps">{data.assignments.map((item, index) => <li key={String(item.id ?? index)}>
          <span>{subjectLabel(item)}{Array.isArray(item.allowed_actions) ? ` · ${(item.allowed_actions as string[]).map(accessActionLabel).join(", ")}` : ""}</span>
          {item.valid_until ? <Badge tone="warning">{t("studio.access.until", { date: formatDateTime(String(item.valid_until), false) })}</Badge> : null}
        </li>)}</ul> : <EmptyState title={t("studio.access.none.title")} copy={t("studio.access.none.text")}/>}
      </section>
      <section aria-label={t("studio.access.packages")}>
        <h3 className="sli-ds-section-title">{t("studio.access.packages")}</h3>
        {data.packages?.length ? <ul className="sli-studio__caps">{data.packages.map((item, index) => <li key={String(item.package_key ?? item.key ?? index)}><span>{String(item.name ?? item.package_name ?? item.package_key ?? item.key)}</span></li>)}</ul>
          : <p className="sli-ds-header__subtitle">{t("studio.access.packages.none")}</p>}
      </section>
      <p>{t("studio.access.pending", { count: pending })}</p>
    </> : null}
    {assign ? <AssignDrawer key={`${row.key}:${assign.preset}`} report={{ report_key: row.key, name: row.name }} presetUserId={assign.preset} onClose={() => setAssign(null)}/> : null}
  </div>;
}

/** Вкладка «Сведения» для отчётов, определённых в коде: только чтение. */
export function CodeInfoTab({ row }: { row: StudioRow }) {
  return <div className="sli-studio__tab">
    <Callout tone="neutral" icon="lock" title={t("studio.code.title")}>{t("studio.code.text")}</Callout>
    <FactList facts={[
      { label: t("studio.def.name"), value: row.name },
      { label: t("studio.def.key"), value: row.key },
      { label: t("studio.def.dataset"), value: row.datasetKey },
      { label: t("studio.def.owner"), value: row.owner },
      { label: t("studio.def.purpose"), value: row.purpose },
      { label: t("studio.def.sensitivity"), value: t(SENSITIVITY_KEYS[row.sensitivity as keyof typeof SENSITIVITY_KEYS] ?? "studio.sensitivity.restricted") },
      { label: t("studio.col.version"), value: `v${row.version}` },
      { label: t("studio.col.status"), value: statusLabel(row.status) },
    ]}/>
    <div><Link className="sli-ds-button" to="/report/$reportKey" params={{ reportKey: row.key }}>{t("studio.access.open")}</Link></div>
  </div>;
}
