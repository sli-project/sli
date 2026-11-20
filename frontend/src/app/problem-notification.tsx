import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { t } from "../i18n";
import { useEffectiveAccess } from "./App";

/** Never infer dispatch from the finding itself or from an empty failed read. */
export function ProblemNotification({ findingId }: { findingId: number }) {
  const access = useEffectiveAccess();
  const allowed = Boolean(access?.capabilities.includes("access.manage") &&
    ["notifications.channels", "notifications.deliveries"].every((key) => access.reports?.some((report) => report.report_key === key && report.allowed)));
  const query = useQuery({ queryKey: ["notifications", "finding", findingId],
    queryFn: () => api.notificationWorkspace(new URLSearchParams({ days: "30", finding_id: String(findingId) })),
    enabled: allowed && Number.isSafeInteger(findingId) && findingId > 0, retry: false,
  });
  const counts = !query.isError && allowed ? query.data?.counts : undefined;
  const state = counts && counts.total !== null && counts.total > 0
    ? ["accepted", "errors", "waiting", "other"].filter((key) => (counts[key as keyof typeof counts] ?? 0) > 0)
      .map((key) => `${t(`notify.${key}` as "notify.accepted")} ${counts[key as keyof typeof counts]}`).join(" · ")
    : t("notify.noData");
  return <p className="sli-ds-header__subtitle"><span>{t("notify.notificationLine", { status: state })}</span>{allowed ? <> · <a href={`/app/notifications?tab=journal&finding_id=${findingId}`}>{t("notify.viewJournal")}</a></> : null}</p>;
}
