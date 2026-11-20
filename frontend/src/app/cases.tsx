import { EMPTY_VALUE, formatNumber } from "../shared/format";
import { AccessRequestStateView, useAccessRequest } from "./access-request-state";
import { caseNumber } from "./case-number";
import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { api, type InvestigationCaseSummary } from "../api/client";
import { DataTable, PageHeader, StateView, type TableColumn } from "../design-system";
import { formatDateTime } from "../shared/date-time";
import { useOverlays } from "../design-system";
import { useEffectiveAccess, useTimeZone } from "./App";
import { createInvestigationWithVerification } from "./v4-mutation-workflows";
import { caseStatusLabel as statusLabel } from "./case-status";
import { hasAllowedReport } from "./report-access";
import { plural, t } from "../i18n";

const CASES_KEY = ["v4", "cases"] as const;

/** Список дел: единственная точка входа раздела «Расследования» без точного контекста. */
export function CaseListPage() {
  const access = useEffectiveAccess();
  const accessRequest = useAccessRequest();
  const client = useQueryClient();
  const navigate = useNavigate();
  const { toast } = useOverlays();
  const { timeZone } = useTimeZone();
  const [creating, setCreating] = useState(false);
  const allowed = hasAllowedReport(access, ["cases.workspace", "investigations.workspace"]);
  const canCreate = Boolean(access?.capabilities.includes("investigations.manage"));
  const query = useQuery({ queryKey: CASES_KEY, queryFn: api.investigationCases, enabled: access !== undefined && allowed && !accessRequest?.error, retry: false });
  const createCase = useMutation({
    mutationFn: (body: { title: string; owner?: string | null }) => createInvestigationWithVerification(body),
    onSuccess: (result) => {
      setCreating(false);
      toast(t("investigations.cases.toastCreated"), t("investigations.cases.toastCreatedDetail", { id: caseNumber(result.item) }));
      void client.invalidateQueries({ queryKey: CASES_KEY });
    },
    onError: (error) => toast(t("investigations.cases.toastCreateFailed"), error.message),
  });
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const title = String(form.get("title") ?? "").trim();
    if (!title) return;
    createCase.mutate({ title, owner: String(form.get("owner") ?? "").trim() || null });
  };

  if (!access || accessRequest?.error) return <section className="sli-ds-report"><PageHeader title={t("investigations.cases.title")}/><AccessRequestStateView/></section>;

  if (!allowed) return <section className="sli-ds-report"><PageHeader title={t("investigations.cases.title")}/><StateView state="denied" detail={t("investigations.cases.deniedDetail")}/></section>;

  const columns: TableColumn<InvestigationCaseSummary>[] = [
    { key: "public_id", label: t("investigations.cases.colNumber"), render: (row) => <Link to="/investigations/$investigationId" params={{ investigationId: String(row.id) }}>{caseNumber(row)}</Link> },
    { key: "title", label: t("investigations.cases.colTitle") },
    { key: "status", label: t("investigations.cases.colStatus"), render: (row) => statusLabel(row.status, row.status_message) },
    { key: "owner", label: t("investigations.cases.colOwner"), render: (row) => row.owner ?? t("investigations.cases.ownerUnassigned") },
    { key: "evidence_count", label: t("investigations.cases.colEvidence"), render: (row) => (row.evidence_count === null || row.evidence_count === undefined ? t("investigations.cases.evidenceInCard") : `${formatNumber(row.evidence_count)} ${plural(row.evidence_count, { one: t("investigations.cases.evidence.one"), few: t("investigations.cases.evidence.few"), many: t("investigations.cases.evidence.many"), other: t("investigations.cases.evidence.many") })}`) },
    { key: "updated_at", label: t("investigations.cases.colUpdated"), render: (row) => (row.updated_at ? formatDateTime(row.updated_at, timeZone) : EMPTY_VALUE) },
  ];
  const items = query.data?.items ?? [];
  const state = query.isLoading ? "loading" : query.error ? "unavailable" : query.data && !items.length ? "empty" : "ok";

  return <section className="sli-ds-report">
    <PageHeader
      title={t("investigations.cases.title")}
      subtitle={t("investigations.cases.subtitle")}
      actions={canCreate ? <button type="button" className="sli-ds-button" data-variant="primary" aria-expanded={creating} onClick={() => setCreating((value) => !value)}>{t("investigations.cases.createCase")}</button> : null}/>
    {canCreate && creating ? <form className="sli-ds-filters" aria-label={t("investigations.cases.formAriaLabel")} onSubmit={submit}>
      <div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor="case-title">{t("investigations.cases.labelTitle")}</label><input id="case-title" name="title" required maxLength={300} placeholder={t("investigations.cases.placeholderTitle")}/></div>
        <div className="sli-ds-field"><label htmlFor="case-owner">{t("investigations.cases.labelOwner")}</label><input id="case-owner" name="owner" maxLength={200} placeholder={t("investigations.cases.placeholderOwner")}/></div>
      </div>
      <p className="sli-ds-header__subtitle">{t("investigations.cases.evidenceHint")}</p>
      <div className="sli-ds-filters__actions">
        <button type="button" className="sli-ds-button" onClick={() => setCreating(false)}>{t("investigations.cases.cancel")}</button>
        <button type="submit" className="sli-ds-button" data-variant="primary" disabled={createCase.isPending}>{createCase.isPending ? t("investigations.cases.creating") : t("investigations.cases.submit")}</button>
      </div>
    </form> : null}
    {state === "empty" ? <StateView state="empty" detail={t("investigations.cases.emptyDetail")}/>
      : state !== "ok" ? <StateView state={state} skeleton="table" detail={query.error?.message} onRetry={() => void query.refetch()}/>
        : <DataTable columns={columns} rows={items} rowKey={(row) => String(row.id)} caption={t("investigations.cases.tableCaption")}
          onRowClick={(row) => void navigate({ to: "/investigations/$investigationId", params: { investigationId: String(row.id) } })}/>}
  </section>;
}
