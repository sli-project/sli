import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client";
import { DetailDrawer, StateView } from "../../design-system";
import { useOverlays } from "../../design-system";
import { accessActionLabel, fieldCategoryLabel, roleLabel, scopeKindLabel } from "../report-labels";
import { createAssignmentWithVerification } from "../v4-mutation-workflows";
import { ChoiceGroup, FieldError, toggleValue } from "./gate";
import { t } from "../../i18n";

const scopeFrom = (kind: string, rawValues: string) => {
  const values = rawValues.split(",").map((item) => item.trim()).filter(Boolean);
  return kind === "all" ? { kind: "all" } : kind === "channel" ? { kind, values } : { kind, ids: values.map(Number).filter(Number.isFinite) };
};

/** Назначение прав на отчёт пользователю; `presetUserId` подставляет пользователя заранее («Назначить мне»). */
export function AssignDrawer({ report, presetUserId, onClose }: { report: { report_key: string; name: string }; presetUserId?: number | null; onClose: () => void }) {
  const client = useQueryClient();
  const { toast } = useOverlays();
  const subjects = useQuery({ queryKey: ["v4", "subjects", "management"], queryFn: api.v4AccessSubjects, retry: false });
  const grantOptions = useQuery({ queryKey: ["v4", "grant-options", "management"], queryFn: api.v4AccessGrantOptions, retry: false });
  const option = grantOptions.data?.items.find((item) => item.report_key === report.report_key);
  const [subjectId, setSubjectId] = useState(presetUserId ? String(presetUserId) : "");
  const [scopeKind, setScopeKind] = useState("all");
  const [scopeValues, setScopeValues] = useState("");
  const [validUntil, setValidUntil] = useState("");
  const [reason, setReason] = useState("");
  const [actions, setActions] = useState<string[]>(["view"]);
  const [categories, setCategories] = useState<string[] | null>(null);
  const selectedCategories = categories ?? option?.field_categories.map((item) => item.key) ?? [];
  const assign = useMutation({
    mutationFn: (body: Record<string, unknown>) => createAssignmentWithVerification(body),
    onSuccess: (result) => {
      onClose();
      toast(
        result.effectiveAccess?.allowed ? t("access.assign.toast.confirmed") : t("access.assign.toast.saved"),
        result.effectiveAccess?.allowed ? t("access.assign.toast.confirmed.text")
          : t("access.assign.toast.saved.text", { explanation: result.effectiveAccess?.explanation ?? t("access.assign.toast.saved.noConditions") }),
      );
      void client.invalidateQueries({ queryKey: ["v4"] });
    },
    onError: (error) => toast(t("access.assign.toast.error"), error.message),
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!option || !subjectId || !reason.trim()) return;
    assign.mutate({
      subject_type: "user", subject_id: Number(subjectId), report_key: report.report_key, effect: "allow",
      source_type: validUntil ? "temporary" : "direct", scope: scopeFrom(scopeKind, scopeValues), business_reason: reason.trim(),
      allowed_actions: actions, field_categories: selectedCategories, valid_until: validUntil ? new Date(validUntil).toISOString() : null,
    });
  };
  const formId = "report-assign-form";
  return <DetailDrawer open title={t("access.assign.drawer.title")} subtitle={report.name} onClose={onClose}
    footer={<>
      <button type="button" className="sli-ds-button" onClick={onClose}>{t("access.assign.drawer.cancel")}</button>
      <button type="submit" form={formId} className="sli-ds-button" data-variant="primary" disabled={assign.isPending || !option || !subjectId}>{assign.isPending ? t("access.assign.drawer.assigning") : t("access.assign.drawer.submit")}</button>
    </>}>
    <form id={formId} className="sli-ds-report__views" onSubmit={submit}>
      {subjects.isLoading || grantOptions.isLoading ? <StateView state="loading" compact/> : null}
      {subjects.error ? <StateView state="unavailable" compact detail={subjects.error.message}/> : null}
      {grantOptions.error ? <StateView state="unavailable" compact detail={grantOptions.error.message}/> : null}
      {grantOptions.data && !option ? <StateView state="unavailable" compact detail={t("access.assign.error.noOptions")}/> : null}
      <div className="sli-ds-field"><label htmlFor="assign-subject">{t("access.assign.field.subject")}</label>
        <select id="assign-subject" required value={subjectId} onChange={(event) => setSubjectId(event.target.value)}>
          <option value="">{t("access.assign.field.subject.placeholder")}</option>
          {subjects.data?.users.filter((user) => user.is_active).map((user) => <option key={user.id} value={user.id}>{user.username} · {roleLabel(user.role)}</option>)}
        </select></div>
      <div className="sli-ds-field"><label htmlFor="assign-scope">{t("access.assign.field.scope")}</label>
        <select id="assign-scope" value={scopeKind} onChange={(event) => setScopeKind(event.target.value)}>
          {(option?.scope_kinds ?? ["all"]).map((kind) => <option key={kind} value={kind}>{scopeKindLabel(kind)}</option>)}
        </select></div>
      {scopeKind !== "all" ? <div className="sli-ds-field"><label htmlFor="assign-scope-values">{t("access.assign.field.scopeValues")}</label>
        <input id="assign-scope-values" required value={scopeValues} onChange={(event) => setScopeValues(event.target.value)} placeholder={scopeKind === "channel" ? "Security, System" : t("access.assign.field.scopeValues.placeholder")}/></div> : null}
      <div className="sli-ds-field"><label htmlFor="assign-valid-until">{t("access.assign.field.validUntil")}</label>
        <input id="assign-valid-until" type="datetime-local" value={validUntil} onChange={(event) => setValidUntil(event.target.value)}/></div>
      {option ? <>
        <ChoiceGroup legend={t("access.assign.field.actions")} options={option.allowed_actions.map((action) => ({ key: action, label: accessActionLabel(action) }))} selected={actions} onToggle={(key) => setActions(toggleValue(actions, key))}/>
        <ChoiceGroup legend={t("access.assign.field.categories")} options={option.field_categories.map((category) => ({ key: category.key, label: fieldCategoryLabel(category.label) }))} selected={selectedCategories} onToggle={(key) => setCategories(toggleValue(selectedCategories, key))}/>
      </> : null}
      <div className="sli-ds-field"><label htmlFor="assign-reason">{t("access.assign.field.reason")}</label>
        <textarea id="assign-reason" required rows={3} value={reason} onChange={(event) => setReason(event.target.value)} placeholder={t("access.assign.field.reason.placeholder")}/></div>
      <FieldError error={assign.error}/>
    </form>
  </DetailDrawer>;
}
