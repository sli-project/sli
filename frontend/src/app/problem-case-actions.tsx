import { caseNumber } from "./case-number";
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";

import { api, ApiResponseError, type InvestigationCase, type InvestigationCaseSummary } from "../api/client";
import { useOverlays } from "../design-system";
import { t, type MessageKey } from "../i18n";
import { useEffectiveAccess } from "./App";

type Row = Record<string, unknown>;
type LinkedCase = { id: number; public_id?: string | null; status?: string | null };

const CASES_KEY = ["v4", "cases"] as const;

/** Readable ru/en text for a refused case action (never the raw server string). */
export function caseActionErrorMessage(error: unknown): string {
  if (error instanceof ApiResponseError) {
    const code = error.code ?? "";
    if (code === "finding_already_linked") return t("problem.case.err.finding_already_linked", { number: error.payload?.investigation_id ? caseNumber({ id: Number(error.payload.investigation_id) }) : "?" });
    if (code === "insufficient_capability" || code === "report_not_assigned" || error.status === 403) return t("problem.case.err.forbidden");
    const key = `problem.case.err.${code}` as MessageKey;
    const text = t(key);
    if (text !== key) return text;
  }
  return t("problem.case.err.generic");
}

/** Open cases matching the query by title, number (id) or public id. */
export function filterOpenCases(items: InvestigationCaseSummary[], query: string): InvestigationCaseSummary[] {
  const needle = query.trim().toLowerCase().replace(/^№\s*/, "");
  return items.filter((item) => item.status !== "closed").filter((item) => !needle
    || item.title.toLowerCase().includes(needle)
    || String(item.id) === needle
    || caseNumber(item).toLowerCase().includes(needle));
}

/** «Открыть расследование» / «Привязать к делу» / «Открыть дело №…» for one problem. */
export function ProblemCaseActions({ row, onOpen }: { row: Row; onOpen?: () => void }) {
  const access = useEffectiveAccess();
  const client = useQueryClient();
  const navigate = useNavigate();
  const { toast } = useOverlays();
  const [picking, setPicking] = useState(false);
  const [search, setSearch] = useState("");
  const [attachedTo, setAttachedTo] = useState<number | null>(null);
  const findingId = Number(row.id);
  const linked = ((row.linked_case ?? (attachedTo === null ? null : { id: attachedTo })) ?? null) as LinkedCase | null;
  const canManage = Boolean(access?.capabilities.includes("investigations.manage"));

  const cases = useQuery({ queryKey: CASES_KEY, queryFn: api.investigationCases, enabled: picking && canManage, retry: false });
  const refresh = () => Promise.all([
    client.invalidateQueries({ queryKey: ["report-v2", "data"] }),
    client.invalidateQueries({ queryKey: CASES_KEY }),
  ]);
  const goTo = (id: number) => {
    onOpen?.();
    return navigate({ to: "/investigations/$investigationId", params: { investigationId: String(id) } });
  };

  const create = useMutation({
    mutationFn: () => api.createInvestigationFromFinding(findingId),
    onSuccess: async (created: InvestigationCase) => {
      toast(t("problem.case.created"), t("problem.case.createdCopy", { number: caseNumber(created) }));
      await refresh();
      await goTo(created.id);
    },
    onError: (error) => toast(t("problem.case.failed"), caseActionErrorMessage(error)),
  });
  const attach = useMutation({
    mutationFn: (caseId: number) => api.linkFindingToInvestigation(caseId, findingId),
    onSuccess: async (updated: InvestigationCase) => {
      setPicking(false);
      setAttachedTo(updated.id);
      toast(t("problem.case.attached"), t("problem.case.attachedCopy", { number: caseNumber(updated) }));
      await refresh();
    },
    onError: (error) => toast(t("problem.case.failed"), caseActionErrorMessage(error)),
  });

  if (linked) {
    return <section aria-label={t("problem.case.heading")} className="sli-ds-report__views">
      <h3 style={{ margin: 0 }}>{t("problem.case.heading")}</h3>
      <Link className="sli-ds-button" to="/investigations/$investigationId" params={{ investigationId: String(linked.id) }} onClick={onOpen}>{t("problem.case.linked", { number: caseNumber(linked) })}</Link>
    </section>;
  }
  if (!canManage) return null;

  const open = filterOpenCases(cases.data?.items ?? [], search);
  return <section aria-label={t("problem.case.heading")} className="sli-ds-report__views">
    <h3 style={{ margin: 0 }}>{t("problem.case.heading")}</h3>
    <div className="sli-ds-filters__actions">
      <button type="button" className="sli-ds-button" data-variant="primary" disabled={create.isPending || attach.isPending} onClick={() => create.mutate()}>
        {create.isPending ? t("problem.case.opening") : t("problem.case.open")}
      </button>
      <button type="button" className="sli-ds-button" aria-expanded={picking} disabled={create.isPending || attach.isPending} onClick={() => setPicking((value) => !value)}>
        {t("problem.case.attach")}
      </button>
    </div>
    {picking ? <div role="group" aria-label={t("problem.case.pickerTitle")}>
      <div className="sli-ds-field">
        <label htmlFor={`problem-case-search-${findingId}`}>{t("problem.case.search")}</label>
        <input id={`problem-case-search-${findingId}`} value={search} onChange={(event) => setSearch(event.target.value)} autoComplete="off"/>
      </div>
      {cases.isLoading ? <p className="sli-ds-header__subtitle">{t("problem.case.loading")}</p>
        : cases.error ? <p className="sli-ds-header__subtitle" role="alert">{t("problem.case.loadFailed")}</p>
          : open.length === 0 ? <p className="sli-ds-header__subtitle">{t("problem.case.noOpen")}</p>
            : <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 4 }}>
              {open.map((item) => <li key={item.id}>
                <button type="button" className="sli-ds-button" disabled={attach.isPending} onClick={() => attach.mutate(item.id)}>
                  {caseNumber(item)} · {item.title}
                </button>
              </li>)}
            </ul>}
      <div className="sli-ds-filters__actions">
        <button type="button" className="sli-ds-button" onClick={() => { setPicking(false); setSearch(""); }}>{t("problem.case.cancel")}</button>
      </div>
    </div> : null}
  </section>;
}
