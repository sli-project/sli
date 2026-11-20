import { useMutation } from "@tanstack/react-query";
import { api, type V4ReportAccessTrace } from "../api/client";
import { formatDateTime } from "../shared/date-time";
import { Callout, useOverlays } from "../design-system";
import { useTimeZone } from "./App";
import { t } from "../i18n";

const sourceTypeLabels = (): Record<string, string> => ({
  platform_owner: t("access.trace.source.owner"),
  package: t("access.trace.source.package"),
  direct: t("access.trace.source.direct"),
  temporary: t("access.trace.source.temporary"),
  group: t("access.trace.source.group"),
  assignment: t("access.trace.source.assignment"),
});
const scopeKindLabels = (): Record<string, string> => ({ all: t("access.trace.scope.all"), server: t("access.trace.scope.server"), domain: t("access.trace.scope.domain"), channel: t("access.trace.scope.channel") });
const fieldLabels = (): Record<string, string> => ({ identity_basic: t("access.trace.field.identity_basic"), security: t("access.trace.field.security"), hr: t("access.trace.field.hr"), contact: t("access.trace.field.contact"), technical: t("access.trace.field.technical") });
const actionLabels = (): Record<string, string> => ({ view: t("access.trace.action.view"), export: t("access.trace.action.export"), create_task: t("access.trace.action.create_task"), configure_channel: t("access.labels.configure_channel") });

export function reportTraceScopeLabel(scope: Record<string, unknown>): string {
  const scopeKind = String(scope.kind ?? "");
  const details = Object.entries(scope).filter(([key]) => key !== "kind").map(([, value]) => Array.isArray(value) ? value.join(", ") : String(value)).join(" · ");
  const label = scopeKindLabels()[scopeKind] ?? (scopeKind || t("access.trace.scope.unspecified"));
  return `${label}${details ? `: ${details}` : ""}`;
}

export function reportTraceGrantLabel(grant: V4ReportAccessTrace["grants"][number]): { title: string; fields: string; actions: string } {
  return {
    title: sourceTypeLabels()[grant.source_type] ?? t("access.trace.grant.assignment"),
    fields: grant.field_categories.map((item) => fieldLabels()[item] ?? item).join(", ") || t("access.trace.grant.none"),
    actions: grant.allowed_actions.map((item) => actionLabels()[item] ?? item).join(", ") || t("access.trace.grant.none"),
  };
}

export function useReportAccessTraceDrawer() {
  const { openDrawer } = useOverlays();
  const { timeZone } = useTimeZone();
  const traceMutation = useMutation({
    mutationFn: ({ reportKey }: { reportKey: string; returnFocus: HTMLElement | null }) => api.v4ReportAccessTrace(reportKey),
    onSuccess: (trace, { returnFocus }) => {
      const grantSteps = trace.grants.map((grant, index) => {
        const labels = reportTraceGrantLabel(grant);
        return <div className="sli-ds-trace__step" key={`${grant.source_type}:${grant.source}:${index}`}><div className="sli-ds-trace__index">{index + 3}</div><div><div className="sli-ds-trace__title">{labels.title}</div><div className="sli-ds-trace__copy">{t("access.trace.grant.details", { source: grant.source, scope: reportTraceScopeLabel(grant.scope), fields: labels.fields, actions: labels.actions })}{grant.valid_until ? t("access.trace.grant.validUntil", { date: formatDateTime(grant.valid_until, timeZone) }) : "."}</div></div></div>;
      });
      const body = <div className="sli-ds-trace"><div className="sli-ds-trace__step"><div className="sli-ds-trace__index">1</div><div><div className="sli-ds-trace__title">{t("access.trace.subject")}</div><div className="sli-ds-trace__copy">{trace.subject.username} · {trace.subject.coarse_role}</div></div></div><div className="sli-ds-trace__step"><div className="sli-ds-trace__index">2</div><div><div className="sli-ds-trace__title">{t("access.trace.decision.title")}</div><div className="sli-ds-trace__copy">{t("access.trace.decision.copy", { status: trace.decision === "allowed" ? t("access.trace.decision.allowed") : t("access.trace.decision.denied"), explanation: trace.explanation, date: formatDateTime(trace.evaluated_at_utc, timeZone) })}</div></div></div>{grantSteps.length ? grantSteps : <div className="sli-ds-trace__step"><div className="sli-ds-trace__index">3</div><div><div className="sli-ds-trace__title">{t("access.trace.noBranch.title")}</div><div className="sli-ds-trace__copy">{t("access.trace.noBranch.copy")}</div></div></div>}</div>;
      openDrawer({ title: trace.report.name, body }, returnFocus);
    },
    onError: (error, { returnFocus }) => openDrawer({ title: t("access.trace.error.title"), body: <Callout tone="danger" icon="warning" title={t("access.trace.error.calloutTitle")}>{t("access.trace.error.calloutBody", { error: error.message })}</Callout> }, returnFocus),
  });
  return {
    openTrace: (reportKey: string, returnFocus?: HTMLElement | null) => traceMutation.mutate({
      reportKey,
      returnFocus: returnFocus ?? (document.activeElement instanceof HTMLElement ? document.activeElement : null),
    }),
    isPending: traceMutation.isPending,
    pendingReportKey: traceMutation.variables?.reportKey,
  };
}
