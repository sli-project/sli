import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { ReportLayout, StateView } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { reportTargetPath } from "../report-labels";
import { ReportAccessRequestDrawer } from "../reports-catalog";

const DENIAL_REASONS: Record<string, MessageKey> = {
  explicit_deny: "reports.access.reason_explicit_deny",
  missing_capabilities: "reports.access.reason_missing_capabilities",
  version_review: "reports.access.reason_version_review",
  not_assigned: "reports.access.reason_not_assigned",
};

/** Only the user's server-filtered catalogue may disclose report metadata. */
export function ReportDenied({ reportKey, title, reason, page = false }: {
  reportKey: string; title?: string; reason?: string; page?: boolean;
}) {
  const catalog = useQuery({ queryKey: ["v4", "reports"], queryFn: api.v4Reports, staleTime: 30_000, retry: false });
  const report = catalog.data?.items?.find((item) => item.report_key === reportKey || reportTargetPath(item) === `/report/${reportKey}`);
  const [requesting, setRequesting] = useState(false);
  const canRequest = report?.requestable && !report.allowed && report.access_state !== "request_pending";
  const explanation = !report?.allowed && report?.explanation_code ? DENIAL_REASONS[report.explanation_code] : undefined;
  const denialReason = reason && reason !== t("reports.access.denied_part") ? reason
    : explanation ? t(explanation) : reason ?? t("reports.access.denied_part");
  const state = <>
    <StateView state="denied" message={denialReason} actions={<>
      <a className="sli-ds-button" href="/app/access-user">{t("reports.access.own_rights")}</a>
      <a className="sli-ds-button" href="/app/reports">{t("reports.catalog.page.title")}</a>
      {canRequest ? <button type="button" className="sli-ds-button" onClick={() => setRequesting(true)}>{t("reports.catalog.action.request")}</button> : null}
    </>}/>
    {requesting && canRequest && report ? <ReportAccessRequestDrawer report={report} onClose={() => setRequesting(false)}/> : null}
  </>;
  return page ? <ReportLayout title={report?.name ?? title ?? t("reports.renderer.default_title")} state="denied" stateView={state}/> : state;
}
