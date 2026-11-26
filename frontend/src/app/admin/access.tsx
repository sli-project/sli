import { DateInput } from "../../design-system/PeriodPicker";
import { Select } from "../../design-system/Select";
import { Checkbox } from "../../design-system/Checkbox";
import { EMPTY_VALUE } from "../../shared/format";
import { AccessRequestStateView, useAccessRequest } from "../access-request-state";
import { uniqueApprovalInstant } from "./approval-time";
import { getLocale, t, type MessageKey } from "../../i18n";
import { codedText } from "../../i18n/event-metadata";
import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api, type V4Access, type V4AccessAuditItem, type V4PackageAssignment, type V4Report, type V4ReportAccessRequest, type V4ReportAssignment } from "../../api/client";
import { DataTable, DetailDrawer, FactList, PageHeader, StateView, type TableColumn } from "../../design-system";
import { formatDateTime, utcToLocalDateTimeInput } from "../../shared/date-time";
import { useOverlays } from "../../design-system";
import { useEffectiveAccess, useTimeZone } from "../App";
import { useReportAccessTraceDrawer } from "../report-access-trace";
import { accessActionLabel, auditActionLabel, auditReasonLabel, fieldCategoryLabel, reportSensitivityLabel, roleLabel, scopeKindLabel } from "../report-labels";
import { TechnicalKey } from "../technical-key";
import { bootstrapEffectiveRole } from "../access-control";
import { createAssignmentWithVerification, createPackageAssignmentWithVerification } from "../v4-mutation-workflows";

import { ReportTitle, useReportTitles } from "../report-titles";
import { AccountFilterField, filterAccounts, type AccountFilter } from "./account-filter";
import { AccessUsersContent } from "./access-users";

const REQUEST_STATUS_LABELS: Record<V4ReportAccessRequest["status"], MessageKey> = {
  submitted: "access.center.status.submitted",
  reviewing: "access.center.status.reviewing",
  approved: "access.center.status.approved",
  approved_limited: "access.center.status.approved_limited",
  rejected: "access.center.status.rejected",
  expired: "access.center.status.expired",
  system_cancelled: "access.center.status.system_cancelled",
};

const accessSourceTypeLabel = (value: string) => ({ direct: t("access.trace.source.direct"), temporary: t("access.trace.source.temporary"), package: t("access.trace.source.package"), group: t("access.trace.source.group") } as Record<string, string>)[value] ?? (value || t("access.audit.noSource"));
function accessExplanationLabel(value: string) {
  if (getLocale() === "en") return value;
  return value.replace("Access allowed by assignment and capability policy", t("access.center.explanation.allowed")).replace("capability policy", t("access.center.explanation.policy"));
}

const ACCESS_KEY = ["v4", "access"] as const;

const Badge = ({ tone, children }: { tone?: "accent" | "success" | "warning" | "danger"; children: ReactNode }) => <span className="sli-ds-badge" data-tone={tone}>{children}</span>;
const Note = ({ title, children }: { title: string; children: ReactNode }) => <div className="sli-ds-state sli-ds-state--banner" data-tone="warning" role="note"><div className="sli-ds-state__title">{title}</div><div className="sli-ds-state__text">{children}</div></div>;
const FieldError = ({ error }: { error?: Error | null }) => (error ? <p className="sli-ds-field__error" role="alert">{error.message}</p> : null);

/** Страницы администрирования доступа требуют access.manage; сервер повторяет проверку. */
function ManageGate({ title, capability, children }: { title: string; capability: string; children: ReactNode }) {
  const access = useEffectiveAccess();
  const accessRequest = useAccessRequest();
  if (!access || accessRequest?.error) return <section className="sli-ds-report"><PageHeader title={title}/><AccessRequestStateView/></section>;
  if (!access.capabilities.includes("access.manage")) {
    return <section className="sli-ds-report"><PageHeader title={title}/>
      <StateView state="denied" detail={<>{t("access.center.gate.missing", { capability })} <Link to="/access-user">{t("access.center.gate.openMine")}</Link></>}/></section>;
  }
  return <>{children}</>;
}

function ChoiceGroup({ legend, options, selected, onToggle }: { legend: string; options: Array<{ key: string; label: string }>; selected: string[]; onToggle: (key: string) => void }) {
  return <fieldset className="sli-ds-choices"><legend>{legend}</legend>
    {options.map((option) => <Checkbox key={option.key} checked={selected.includes(option.key)} onChange={() => onToggle(option.key)}>{option.label}</Checkbox>)}
  </fieldset>;
}

type HistoryRow = { reportKey?: string; key: string; kind: string; target: string; effect: string; sourceType: string; scope: string; reason: string; validUntil?: string | null };

/** Kept for beta-2; the users route does not mount assignment controls. */
export function AccessCenterContent() {
  const bootstrap = useQuery({ queryKey: ["bootstrap"], queryFn: api.bootstrap, staleTime: 60_000 });
  const canManageAccounts = !bootstrap.isError && bootstrapEffectiveRole(bootstrap.data) === "admin";
  const reportTitle = useReportTitles();
  const client = useQueryClient();
  const { toast } = useOverlays();
  const { timeZone } = useTimeZone();
  const [selectedUser, setSelectedUser] = useState<number | undefined>();
  const [accountFilter, setAccountFilter] = useState<AccountFilter>("people");
  const [reportKey, setReportKey] = useState("");
  const [reason, setReason] = useState("");
  const [effect, setEffect] = useState("allow");
  const [sourceType, setSourceType] = useState("direct");
  const [expires, setExpires] = useState("");
  const [scopeKind, setScopeKind] = useState("all");
  const [scopeValues, setScopeValues] = useState("");
  const [allowedActions, setAllowedActions] = useState<string[]>([]);
  const [fieldCategories, setFieldCategories] = useState<string[]>([]);
  const [packageKey, setPackageKey] = useState("");
  const [packageEffect, setPackageEffect] = useState("allow");
  const [packageSourceType, setPackageSourceType] = useState("direct");
  const [packageExpires, setPackageExpires] = useState("");
  const [packageReason, setPackageReason] = useState("");
  const subjects = useQuery({ queryKey: ["v4", "subjects", accountFilter], queryFn: () => api.v4AccessSubjectsForAccountType(accountFilter) });
  const grantOptions = useQuery({ queryKey: ["v4", "grant-options"], queryFn: api.v4AccessGrantOptions });
  const audit = useQuery({ queryKey: ["v4", "access-audit"], queryFn: api.v4AccessAudit });
  const access = useQuery({ queryKey: [...ACCESS_KEY, selectedUser], queryFn: () => api.v4Access(selectedUser) });
  const selectedGrant = grantOptions.data?.items.find((item) => item.report_key === reportKey);
  const selectedPackage = subjects.data?.packages.find((item) => item.package_key === packageKey);
  const missingForSubject = selectedGrant?.required_capabilities.filter((capability) => !access.data?.capabilities.includes(capability)) ?? [];

  const assign = useMutation({
    mutationFn: (body: Record<string, unknown>) => createAssignmentWithVerification(body),
    onSuccess: (result) => {
      setReason("");
      const denied = result.item.effect === "deny";
      toast(
        denied ? t("access.center.toast.denyConfirmed") : result.effectiveAccess?.allowed ? t("access.assign.toast.confirmed") : t("access.assign.toast.saved"),
        denied ? t("access.center.toast.denyText")
          : result.effectiveAccess?.allowed ? t("access.assign.toast.confirmed.text")
            : t("access.center.toast.assignmentText", { explanation: result.effectiveAccess?.explanation ?? t("access.center.toast.noConditions") }),
      );
      void client.invalidateQueries({ queryKey: ["v4"] });
    },
    onError: (error) => toast(t("access.assign.toast.error"), error.message),
  });
  const assignPackage = useMutation({
    mutationFn: (body: Record<string, unknown>) => createPackageAssignmentWithVerification(body),
    onSuccess: (result) => {
      setPackageReason("");
      const denied = result.item.effect === "deny";
      toast(denied ? t("access.center.toast.packageDenyConfirmed") : t("access.center.toast.packageConfirmed"), denied ? t("access.center.toast.packageDenyText") : t("access.center.toast.packageText"));
      void client.invalidateQueries({ queryKey: ["v4"] });
    },
    onError: (error) => toast(t("access.center.toast.packageError"), error.message),
  });

  const chooseReport = (key: string) => {
    setReportKey(key);
    const option = grantOptions.data?.items.find((item) => item.report_key === key);
    setAllowedActions(option?.allowed_actions.includes("view") ? ["view"] : []);
    setFieldCategories(option?.field_categories.map((item) => item.key) ?? []);
    setScopeKind("all");
    setScopeValues("");
  };
  const toggleChoice = (values: string[], value: string, setter: (next: string[]) => void) => setter(values.includes(value) ? values.filter((item) => item !== value) : [...values, value]);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedUser || !reportKey || !reason.trim() || !selectedGrant) return;
    const values = scopeValues.split(",").map((item) => item.trim()).filter(Boolean);
    const scope = scopeKind === "all" ? { kind: "all" } : scopeKind === "channel" ? { kind: scopeKind, values } : { kind: scopeKind, ids: values.map(Number).filter(Number.isFinite) };
    assign.mutate({
      subject_type: "user", subject_id: selectedUser, report_key: reportKey, effect, source_type: sourceType, scope,
      business_reason: reason.trim(),
      field_categories: effect === "allow" ? fieldCategories : [],
      allowed_actions: effect === "allow" ? allowedActions : [],
      valid_until: expires ? new Date(expires).toISOString() : null,
    });
  };
  const submitPackage = (event: FormEvent) => {
    event.preventDefault();
    if (!selectedUser || !packageKey || !packageReason.trim()) return;
    assignPackage.mutate({
      subject_type: "user", subject_id: selectedUser, package_key: packageKey, effect: packageEffect, source_type: packageSourceType,
      business_reason: packageReason.trim(), valid_until: packageExpires ? new Date(packageExpires).toISOString() : null,
    });
  };

  const until = (value?: string | null) => (value ? formatDateTime(value, timeZone) : EMPTY_VALUE);
  const reportColumns: TableColumn<V4Report>[] = [
    { key: "name", label: t("access.center.audit.report"), render: (row) => <ReportTitle reportKey={row.report_key} name={row.name} targetPath={row.target_path}/> },
    { key: "allowed", label: t("access.center.audit.decision"), render: (row) => <Badge tone={row.allowed ? "success" : "danger"}>{row.allowed ? t("access.center.audit.allowed") : t("access.center.audit.closed")}</Badge> },
    { key: "explanation", label: t("access.center.audit.basis"), render: (row) => row.explanation_code ? codedText(`access.explanation.${row.explanation_code}`, row.explanation, { capabilities: row.missing_capabilities.join(", ") }) : accessExplanationLabel(row.explanation) },
  ];
  const history: HistoryRow[] = [
    ...(subjects.data?.package_assignments ?? []).slice(0, 10).map((item: V4PackageAssignment): HistoryRow => ({
      key: `package:${item.id}`, kind: t("access.center.kind.package"), target: item.package_name, effect: item.effect, sourceType: item.source_type, scope: t("access.audit.packageScope"), reason: item.business_reason, validUntil: item.valid_until,
    })),
    ...(subjects.data?.assignments ?? []).slice(0, 20).map((item: V4ReportAssignment): HistoryRow => ({
      reportKey: item.report_key, key: `report:${item.id}`, kind: t("access.center.kind.report"), target: item.report_key, effect: item.effect, sourceType: item.source_type, scope: item.scope_json.kind ? scopeKindLabel(String(item.scope_json.kind)) : t("access.audit.noScope"), reason: item.business_reason, validUntil: item.valid_until,
    })),
  ];
  const historyColumns: TableColumn<HistoryRow>[] = [
    { key: "kind", label: t("access.center.col.object") },
    { key: "target", label: t("access.center.col.assignment"), render: (row) => row.reportKey ? <ReportTitle reportKey={row.reportKey} name={row.target}/> : row.target },
    { key: "effect", label: t("access.center.col.effect"), render: (row) => <Badge tone={row.effect === "allow" ? "success" : "danger"}>{row.effect === "allow" ? t("access.center.effect.allowed") : t("access.center.effect.denied")}</Badge> },
    { key: "sourceType", label: t("access.center.col.source"), render: (row) => accessSourceTypeLabel(row.sourceType) },
    { key: "scope", label: t("access.assign.field.scope") },
    { key: "reason", label: t("access.center.audit.basis") },
    { key: "validUntil", label: t("access.assign.field.validUntil"), render: (row) => until(row.validUntil) },
  ];
  const auditColumns: TableColumn<V4AccessAuditItem>[] = [
    { key: "action", label: t("access.audit.action"), render: (row) => <>{auditActionLabel(row.action)}<TechnicalKey value={row.action} label={t("access.audit.actionCode")}/></> },
    { key: "outcome", label: t("access.center.col.outcome"), render: (row) => (row.outcome === "ok" ? t("access.center.outcome.ok") : row.outcome) },
    { key: "target_key", label: t("access.audit.target"), render: (row) => row.target_key ? <>{subjects.data?.packages.find((item) => item.package_key === row.target_key)?.name ?? reportTitle(row.target_key, t("access.audit.targetDetails"))}<TechnicalKey value={row.target_key} label={t("access.audit.targetKey")}/></> : t("access.audit.noTarget") },
    { key: "reason", label: t("access.center.audit.basis"), render: (row) => auditReasonLabel(row.reason) },
    { key: "created_at", label: t("access.center.col.time"), render: (row) => until(row.created_at) },
  ];

  const summary = access.data;
  const auditItems = audit.data?.items.slice(0, 20) ?? [];
  return <section className="sli-ds-report">
    <PageHeader title={t("access.center.user_access")}
      actions={canManageAccounts ? <a className="sli-ds-button" href="/app/admin">{t("access.admin.title")}</a> : undefined}
      subtitle={t("access.center.packages_groups_direct_and_temporary_assignments_combine_exp")}/>
    <div className="sli-ds-filters">
      <div className="sli-ds-filters__fields">
        <AccountFilterField value={accountFilter} onChange={(value) => { setAccountFilter(value); setSelectedUser(undefined); }}/>
        <div className="sli-ds-field"><label htmlFor="access-subject">{t("access.center.audit.subject")}</label>
          <Select label={t("access.center.audit.subject")} id="access-subject" value={selectedUser ?? ""} onChange={(selectedValue) => setSelectedUser(selectedValue ? Number(selectedValue) : undefined)}
            options={[{ value: "", label: t("access.center.audit.effective") }, ...(filterAccounts(subjects.data?.users ?? [], accountFilter).map((user) => ({ value: user.id, label: String(user.username) + String(" · ") + String(roleLabel(user.role)) + String(user.is_active ? "" : t("access.center.audit.loginDisabled")), disabled: !user.is_active })) ?? [])]}/></div>
      </div>
      {subjects.isLoading ? <StateView state="loading" compact/> : subjects.error ? <StateView state="unavailable" compact detail={subjects.error.message}/> : null}
    </div>

    {access.isLoading ? <StateView state="loading"/> : access.error ? <StateView state="unavailable" detail={access.error.message} onRetry={() => void access.refetch()}/> : null}
    {summary ? <>
      <FactList facts={[
        { label: t("access.center.audit.packages"), value: summary.packages.length },
        { label: t("access.center.audit.groups"), value: summary.groups.length },
        { label: t("access.center.audit.reports"), value: summary.allowed_report_count },
        { label: t("access.center.audit.denies"), value: summary.explicit_denies.reports.length },
      ]}/>
      {summary.reports.length
        ? <DataTable columns={reportColumns} rows={summary.reports} rowKey={(row) => row.report_key} caption={t("access.center.audit.caption")}/>
        : <StateView state="empty" detail={t("access.center.audit.noReports")}/>}
    </> : null}

    {selectedUser ? <form className="sli-ds-filters" aria-label={t("access.center.package.title")} onSubmit={submitPackage}>
      <h2 className="sli-ds-section-title">{t("access.center.package.title")}</h2>
      <div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor="package-key">{t("access.center.kind.package")}</label>
          <Select label={t("access.center.kind.package")} id="package-key" required value={packageKey} onChange={(selectedValue) => setPackageKey(selectedValue)}
            options={[{ value: "", label: t("access.center.package.field.package.placeholder") }, ...(subjects.data?.packages.map((item) => ({ value: item.package_key, label: item.name })) ?? [])]}/></div>
        <div className="sli-ds-field"><label htmlFor="package-effect">{t("access.center.col.effect")}</label>
          <Select label={t("access.center.col.effect")} id="package-effect" value={packageEffect} onChange={(selectedValue) => setPackageEffect(selectedValue)}
            options={[{ value: "allow", label: t("access.center.package.effect.allow") }, { value: "deny", label: t("access.center.package.effect.deny") }]}/></div>
        <div className="sli-ds-field"><label htmlFor="package-source">{t("access.center.package.field.source")}</label>
          <Select label={t("access.center.package.field.source")} id="package-source" value={packageSourceType} onChange={(selectedValue) => setPackageSourceType(selectedValue)}
            options={[{ value: "direct", label: t("access.center.source.direct") }, { value: "temporary", label: t("access.center.source.temporary") }]}/></div>
        <div className="sli-ds-field"><label htmlFor="package-expires">{t("access.center.package.field.expires")}</label>
          <DateInput id="package-expires" label={t("access.center.package.field.expires")} required={packageSourceType === "temporary"} value={packageExpires} onChange={setPackageExpires}/></div>
        <div className="sli-ds-field"><label htmlFor="package-reason">{t("access.center.audit.basis")}</label>
          <input id="package-reason" required value={packageReason} onChange={(event) => setPackageReason(event.target.value)} placeholder={t("access.center.package.field.reason.placeholder")}/></div>
      </div>
      {selectedPackage ? <>
        <p className="sli-ds-header__subtitle">{selectedPackage.description || t("access.center.package.defaultDesc")}</p>
        <Note title={t("access.center.package.note.title")}>{t("access.center.package.note.text", { caps: (selectedPackage.capabilities ?? []).join(", ") || t("access.center.none"), reports: (selectedPackage.reports ?? []).join(", ") || t("access.center.none") })}</Note>
      </> : null}
      <FieldError error={assignPackage.error}/>
      <div className="sli-ds-filters__actions">
        <button type="submit" className="sli-ds-button" data-variant="primary" disabled={assignPackage.isPending || !selectedPackage}>{assignPackage.isPending ? t("access.assign.drawer.assigning") : packageEffect === "allow" ? t("access.center.button.assignPackage") : t("access.center.button.setDeny")}</button>
      </div>
    </form> : null}

    {selectedUser ? <form className="sli-ds-filters" aria-label={t("access.center.report.title")} onSubmit={submit}>
      <h2 className="sli-ds-section-title">{t("access.center.report.title")}</h2>
      {grantOptions.isLoading ? <StateView state="loading" compact/> : grantOptions.error ? <StateView state="unavailable" compact detail={grantOptions.error.message}/> : null}
      <div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor="grant-report">{t("access.center.audit.report")}</label>
          <Select label={t("access.center.audit.report")} id="grant-report" required value={reportKey} onChange={(selectedValue) => chooseReport(selectedValue)}
            options={[{ value: "", label: t("access.center.report.field.report.placeholder") }, ...(grantOptions.data?.items.map((report) => ({ value: report.report_key, label: String(reportTitle(report.report_key, report.name)) + String(" · ") + String(reportSensitivityLabel(report.sensitivity)) })) ?? [])]}/></div>
        <div className="sli-ds-field"><label htmlFor="grant-effect">{t("access.center.col.effect")}</label>
          <Select label={t("access.center.col.effect")} id="grant-effect" value={effect} onChange={(selectedValue) => setEffect(selectedValue)}
            options={[{ value: "allow", label: t("access.center.report.effect.allow") }, { value: "deny", label: t("access.center.report.effect.deny") }]}/></div>
        <div className="sli-ds-field"><label htmlFor="grant-source">{t("access.center.package.field.source")}</label>
          <Select label={t("access.center.package.field.source")} id="grant-source" value={sourceType} onChange={(selectedValue) => setSourceType(selectedValue)}
            options={[{ value: "direct", label: t("access.center.source.direct") }, { value: "temporary", label: t("access.center.source.temporary") }]}/></div>
        {selectedGrant ? <div className="sli-ds-field"><label htmlFor="grant-scope-kind">{t("access.assign.field.scope")}</label>
          <Select label={t("access.assign.field.scope")} id="grant-scope-kind" value={scopeKind} onChange={(selectedValue) => setScopeKind(selectedValue)}
            options={selectedGrant.scope_kinds.map((kind) => ({ value: kind, label: scopeKindLabel(kind) }))}/></div> : null}
        {scopeKind !== "all" ? <div className="sli-ds-field"><label htmlFor="grant-scope-values">{t("access.center.report.field.scopeValues")}</label>
          <input id="grant-scope-values" required value={scopeValues} onChange={(event) => setScopeValues(event.target.value)} placeholder={scopeKind === "channel" ? "Security, System" : t("access.assign.field.scopeValues.placeholder")}/></div> : null}
        <div className="sli-ds-field"><label htmlFor="grant-expires">{t("access.assign.field.validUntil")}</label>
          <DateInput id="grant-expires" label={t("access.assign.field.validUntil")} required={sourceType === "temporary"} value={expires} onChange={setExpires}/></div>
        <div className="sli-ds-field"><label htmlFor="grant-reason">{t("access.center.audit.basis")}</label>
          <input id="grant-reason" required value={reason} onChange={(event) => setReason(event.target.value)} placeholder={t("access.center.report.field.reason.placeholder")}/></div>
      </div>
      {selectedGrant ? <p className="sli-ds-header__subtitle">{selectedGrant.purpose} · {t("access.center.report.dataset", { dataset: selectedGrant.dataset_key })}</p> : null}
      {scopeKind === "all" ? <p className="sli-ds-header__subtitle">{t("access.center.report.scopeAll")}</p> : null}
      {selectedGrant && effect === "allow" && missingForSubject.length
        ? <Note title={t("access.center.report.note.title")}>{t("access.center.report.note.text", { caps: missingForSubject.join(", ") })}</Note> : null}
      {selectedGrant && effect === "allow" ? <>
        <ChoiceGroup legend={t("access.assign.field.actions")} options={selectedGrant.allowed_actions.map((action) => ({ key: action, label: accessActionLabel(action) }))} selected={allowedActions} onToggle={(key) => toggleChoice(allowedActions, key, setAllowedActions)}/>
        <ChoiceGroup legend={t("access.center.report.categories")} options={selectedGrant.field_categories.map((category) => ({ key: category.key, label: fieldCategoryLabel(category.label) }))} selected={fieldCategories} onToggle={(key) => toggleChoice(fieldCategories, key, setFieldCategories)}/>
      </> : effect === "deny" ? <p className="sli-ds-header__subtitle">{t("access.center.report.denyText")}</p> : null}
      <FieldError error={assign.error}/>
      <div className="sli-ds-filters__actions">
        <button type="submit" className="sli-ds-button" data-variant="primary" disabled={assign.isPending || !selectedGrant || (effect === "allow" && !allowedActions.includes("view"))}>{assign.isPending ? t("access.assign.drawer.assigning") : effect === "allow" ? t("access.assign.drawer.submit") : t("access.center.button.setDeny")}</button>
      </div>
    </form> : null}

    <h2 className="sli-ds-section-title">{t("access.center.recent_assignments")}</h2>
    {subjects.data ? (history.length ? <DataTable columns={historyColumns} rows={history} rowKey={(row) => row.key} caption={t("access.center.recent_assignments")}/> : <StateView state="empty" detail={t("access.center.no_assignments_yet")}/>) : null}
    <h2 className="sli-ds-section-title">{t("access.center.access_action_log")}</h2>
    {audit.isLoading ? <StateView state="loading"/> : audit.error ? <StateView state="unavailable" detail={audit.error.message} onRetry={() => void audit.refetch()}/>
      : auditItems.length ? <DataTable columns={auditColumns} rows={auditItems} rowKey={(row) => String(row.id)} caption={t("access.center.access_action_log")}/> : <StateView state="empty" detail={t("access.center.no_access_actions_recorded_yet")}/>}
  </section>;
}

export function AccessCenterPage() {
  return <ManageGate title={t("access.people.title")} capability={t("access.center.capability.manage")}><AccessUsersContent/></ManageGate>;
}

/** Эффективный доступ текущего пользователя; открыт всем, сервер решает по субъекту. */
export function AccessUserPage() {
  const query = useQuery({ queryKey: [...ACCESS_KEY, "self"], queryFn: () => api.v4Access() });
  const { timeZone } = useTimeZone();
  const reportTrace = useReportAccessTraceDrawer();
  const data: V4Access | undefined = query.data;

  const columns: TableColumn<V4Report>[] = [
    { key: "name", label: t("access.center.audit.report"), render: (row) => <ReportTitle reportKey={row.report_key} name={row.name} targetPath={row.target_path}/> },
    { key: "allowed", label: t("access.center.audit.decision"), render: (row) => <Badge tone={row.allowed ? "success" : "danger"}>{row.allowed ? t("access.user.allowed") : t("access.user.denied")}</Badge> },
    { key: "explanation", label: t("access.center.audit.basis"), render: (row) => row.explanation_code ? codedText(`access.explanation.${row.explanation_code}`, row.explanation, { capabilities: row.missing_capabilities.join(", ") }) : accessExplanationLabel(row.explanation) },
    { key: "dataset_key", label: t("access.user.col.dataset") },
    { key: "allowed_actions", label: t("access.user.col.actions"), render: (row) => row.allowed_actions.map(accessActionLabel).join(", ") || t("access.user.noActions") },
    { key: "sources", label: t("access.user.col.sources"), render: (row) => row.sources?.map((source) => `${accessSourceTypeLabel(source.source_type)}: ${source.source}`).join(" · ") || t("access.user.noSources") },
    { key: "trace", label: t("access.user.col.trace"), render: (row) => <button type="button" className="sli-ds-button" data-access-trace={row.report_key} onClick={() => reportTrace.openTrace(row.report_key)}>{t("access.user.col.trace")}</button> },
  ];

  return <section className="sli-ds-report">
    <PageHeader title={t("access.user.title")}
      subtitle={t("access.user.subtitle")}/>
    {query.isLoading ? <StateView state="loading"/> : query.error ? <StateView state="unavailable" detail={query.error.message} onRetry={() => void query.refetch()}/> : null}
    {data ? <>
      <FactList facts={[
        { label: t("access.user.fact.user"), value: data.subject.username },
        { label: t("access.user.fact.role"), value: roleLabel(data.subject.coarse_role) },
        { label: t("access.user.fact.evaluatedAt"), value: formatDateTime(data.evaluated_at_utc, timeZone) },
        { label: t("access.user.fact.reports"), value: data.allowed_report_count },
        { label: t("access.user.fact.packages"), value: data.packages.length ? data.packages.map((item) => <Badge key={item.key} tone="accent">{item.name}</Badge>) : t("access.center.none") },
        { label: t("access.user.fact.groups"), value: data.groups.length ? data.groups.map((item) => <Badge key={item.key}>{item.name}</Badge>) : t("access.center.none") },
      ]}/>
      <h2 className="sli-ds-section-title">{t("access.user.reports.title")}</h2>
      {data.reports.length
        ? <DataTable columns={columns} rows={data.reports} rowKey={(row) => row.report_key} caption={t("access.user.reports.title")}/>
        : <StateView state="empty" detail={t("access.user.reports.empty")}/>}
      <h2 className="sli-ds-section-title">{t("access.user.caps.title")}</h2>
      {data.capabilities.length
        ? <div className="sli-ds-choices">{[...data.capabilities].sort().map((capability) => <Badge key={capability} tone={capability.includes("manage") || capability.includes("publish") ? "warning" : capability.includes("view") ? "accent" : undefined}>{capability}</Badge>)}</div>
        : <StateView state="empty" detail={t("access.user.caps.empty")}/>}
      <h2 className="sli-ds-section-title">{t("access.user.denies.title")}</h2>
      <FactList facts={[
        { label: t("access.user.fact.packages"), value: data.explicit_denies.packages.length },
        { label: t("access.user.caps.title"), value: data.explicit_denies.capabilities.length },
        { label: t("access.user.fact.reportDenies"), value: data.explicit_denies.reports.length },
      ]}/>
      <Note title={t("access.user.note.title")}>{t("access.user.note.text")}</Note>
    </> : null}
  </section>;
}

type DecisionMode = "approve" | "reject";

function AccessRequestsContent() {
  const queryClient = useQueryClient();
  const { timeZone } = useTimeZone();
  const { toast } = useOverlays();
  const [decisionFor, setDecisionFor] = useState<{ item: V4ReportAccessRequest; mode: DecisionMode } | null>(null);
  const query = useQuery({ queryKey: ["v4", "report-access-requests", "all"], queryFn: () => api.v4ReportAccessRequests(true), staleTime: 15_000 });
  const decision = useMutation({
    mutationFn: ({ requestId, body }: { requestId: number; body: Record<string, unknown> }) => api.v4DecideReportAccessRequest(requestId, body),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["v4", "report-access-requests"] }),
        queryClient.invalidateQueries({ queryKey: ["v4", "reports"] }),
        queryClient.invalidateQueries({ queryKey: ACCESS_KEY }),
      ]);
      setDecisionFor(null);
      toast(t("access.requests.toast.saved"), t("access.requests.toast.saved.text"));
    },
    onError: (error: Error) => toast(t("access.requests.toast.error"), error.message),
  });

  const items = query.data?.items ?? [];
  const state = query.isLoading ? "loading" : query.error ? "unavailable" : !items.length ? "empty" : "ok";
  const statusTone = (status: V4ReportAccessRequest["status"]) => (status === "submitted" ? "warning" : status.startsWith("approved") ? "success" : status === "rejected" ? "danger" : undefined);
  const columns: TableColumn<V4ReportAccessRequest>[] = [
    { key: "id", label: t("access.requests.col.id"), render: (row) => `#${row.id} · ${row.username}` },
    { key: "report_name", label: t("access.center.audit.report"), render: (row) => <><ReportTitle reportKey={row.report_key} name={row.report_name}/><br/><span className="sli-ds-header__subtitle">{row.business_reason}</span></> },
    { key: "status", label: t("access.requests.col.status"), render: (row) => <Badge tone={statusTone(row.status)}>{Object.hasOwn(REQUEST_STATUS_LABELS, row.status) ? t(REQUEST_STATUS_LABELS[row.status]) : row.status}</Badge> },
    { key: "versions", label: t("access.requests.col.versions"), render: (row) => t("access.requests.versions", { version: row.report_version, dataset: row.dataset_version }) },
    { key: "requested_scope_json", label: t("access.assign.field.scope"), render: (row) => scopeKindLabel(String(row.requested_scope_json.kind ?? "all")) },
    { key: "requested_valid_until", label: t("access.requests.col.validUntil"), render: (row) => formatDateTime(row.requested_valid_until, timeZone) },
    { key: "fields", label: t("access.requests.col.fields"), render: (row) => `${row.requested_field_categories.map(fieldCategoryLabel).join(", ")} · ${row.requested_actions.map(accessActionLabel).join(", ")}` },
    { key: "decision", label: t("access.center.audit.decision"), render: (row) => row.status === "submitted"
      ? <span className="sli-ds-filters__actions">
          <button type="button" className="sli-ds-button" data-variant="primary" onClick={() => setDecisionFor({ item: row, mode: "approve" })}>{t("access.requests.button.review")}</button>
          <button type="button" className="sli-ds-button" onClick={() => setDecisionFor({ item: row, mode: "reject" })}>{t("access.requests.button.reject")}</button>
        </span>
      : row.decision_reason ?? EMPTY_VALUE },
  ];

  return <section className="sli-ds-report">
    <PageHeader title={t("access.center.access_requests")}
      subtitle={t("access.center.requests_for_individual_published_reports_packages_and_admin")}/>
    {state === "empty" ? <StateView state="empty" detail={t("access.center.no_access_requests_yet")}/>
      : state !== "ok" ? <StateView state={state} detail={query.error?.message} onRetry={() => void query.refetch()}/>
        : <DataTable columns={columns} rows={items} rowKey={(row) => String(row.id)} caption={t("access.center.access_requests")}/>}
    {decisionFor ? <DecisionDrawer key={decisionFor.item.id + decisionFor.mode} item={decisionFor.item} mode={decisionFor.mode} pending={decision.isPending}
      onClose={() => setDecisionFor(null)} onSubmit={(body) => decision.mutate({ requestId: decisionFor.item.id, body })}/> : null}
  </section>;
}

function DecisionDrawer({ item, mode, pending, onClose, onSubmit }: { item: V4ReportAccessRequest; mode: DecisionMode; pending: boolean; onClose: () => void; onSubmit: (body: Record<string, unknown>) => void }) {
  const { timeZone } = useTimeZone();
  const [editTimeZone] = useState(timeZone);
  const [deadlineError, setDeadlineError] = useState(false);
  const initialValidUntil = utcToLocalDateTimeInput(item.requested_valid_until, editTimeZone);
  const requestedKind = String(item.requested_scope_json.kind || "all");
  const requestedValues = (item.requested_scope_json[requestedKind === "channel" ? "values" : "ids"] as string[] | undefined) ?? [];
  const formId = "access-request-decision-form";
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const body: Record<string, unknown> = { decision: mode, decision_reason: String(form.get("decision_reason") || "") };
    if (mode === "approve") {
      const kind = String(form.get("scope_kind") || requestedKind);
      const values = String(form.get("scope_values") || "").split(",").map((value) => value.trim()).filter(Boolean);
      body.scope = kind === "all" ? { kind: "all" } : { kind, [kind === "channel" ? "values" : "ids"]: values };
      const enteredValidUntil = String(form.get("valid_until") || "");
      // An untouched minute-resolution input must preserve the exact requested instant.
      const validUntil = enteredValidUntil === initialValidUntil
        ? item.requested_valid_until : uniqueApprovalInstant(enteredValidUntil, editTimeZone);
      if (!validUntil) { setDeadlineError(true); return; }
      setDeadlineError(false);
      body.valid_until = validUntil;
      body.field_categories = item.requested_field_categories.filter((field) => form.has(`field:${field}`));
      body.allowed_actions = item.requested_actions.filter((action) => action === "view" || form.has(`action:${action}`));
    }
    onSubmit(body);
  };
  return <DetailDrawer open title={mode === "approve" ? t("access.requests.drawer.approveTitle") : t("access.requests.drawer.rejectTitle")} subtitle={<>{item.username} · <ReportTitle reportKey={item.report_key} name={item.report_name}/></>} onClose={onClose}
    footer={<>
      <button type="button" className="sli-ds-button" onClick={onClose}>{t("access.assign.drawer.cancel")}</button>
      <button type="submit" form={formId} className="sli-ds-button" data-variant="primary" disabled={pending}>{pending ? t("access.requests.drawer.saving") : mode === "approve" ? t("access.requests.drawer.approve") : t("access.requests.button.reject")}</button>
    </>}>
    <form id={formId} className="sli-ds-report__views" onSubmit={submit}>
      <FactList facts={[
        { label: t("access.requests.drawer.reason"), value: item.business_reason },
        { label: t("access.requests.col.versions"), value: t("access.requests.drawer.versions", { report: item.report_version, dataset: item.dataset_version }) },
        { label: t("access.requests.drawer.requestedUntil"), value: formatDateTime(item.requested_valid_until, timeZone) },
      ]}/>
      {mode === "approve" ? <>
        <div className="sli-ds-field"><label htmlFor="decision-scope-kind">{t("access.requests.drawer.grantedScope")}</label>
          <Select label={t("access.requests.drawer.grantedScope")} id="decision-scope-kind" name="scope_kind" defaultValue={requestedKind}
            options={[{ value: requestedKind, label: scopeKindLabel(requestedKind) }, ...(requestedKind === "all" ? [{ value: "server", label: t("access.requests.drawer.scope.servers") }, { value: "domain", label: t("access.requests.drawer.scope.domains") }, { value: "channel", label: t("access.requests.drawer.scope.channels") }] : [])]}/></div>
        <div className="sli-ds-field"><label htmlFor="decision-scope-values">{t("access.center.report.field.scopeValues")}</label>
          <input id="decision-scope-values" name="scope_values" defaultValue={requestedValues.join(", ")} placeholder={requestedKind === "all" ? t("access.requests.drawer.scope.placeholder.all") : t("access.requests.drawer.scope.placeholder.values")}/></div>
        <div className="sli-ds-field"><label htmlFor="decision-valid-until">{t("access.requests.drawer.validUntilLimit")}</label>
          <DateInput id="decision-valid-until" label={t("access.requests.drawer.validUntilLimit")} name="valid_until" required defaultValue={initialValidUntil} aria-describedby="decision-time-zone" aria-invalid={deadlineError || undefined} onChange={() => setDeadlineError(false)}/>
          <small id="decision-time-zone">{t("access.approval.editZone", { zone: editTimeZone })}</small>
          {deadlineError ? <p role="alert">{t("access.approval.invalidWallTime")}</p> : null}</div>
        <fieldset className="sli-ds-choices"><legend>{t("access.center.report.categories")}</legend>
          {item.requested_field_categories.map((field) => <Checkbox key={field} name={`field:${field}`} defaultChecked>{fieldCategoryLabel(field)}</Checkbox>)}</fieldset>
        <fieldset className="sli-ds-choices"><legend>{t("access.user.col.actions")}</legend>
          {item.requested_actions.map((action) => <Checkbox key={action} name={`action:${action}`} defaultChecked disabled={action === "view"}>{accessActionLabel(action)}</Checkbox>)}</fieldset>
      </> : null}
      <div className="sli-ds-field"><label htmlFor="decision-reason">{mode === "approve" ? t("access.requests.drawer.decisionReason") : t("access.requests.drawer.rejectReason")}</label>
        <textarea id="decision-reason" name="decision_reason" required minLength={5} rows={3}/></div>
    </form>
  </DetailDrawer>;
}

export function AccessRequestsPage() {
  return <ManageGate title={t("access.center.access_requests")} capability={t("access.center.capability.review")}><AccessRequestsContent/></ManageGate>;
}
