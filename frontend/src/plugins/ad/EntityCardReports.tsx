import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import { useEffectiveAccess } from "../../app/App";
import { withReturnTo } from "../../app/report-v2/legacy";
import { t } from "../../i18n";
import { formatNumber } from "../../shared/format";

type EntityScope = { entity_id: string; domain: string };
type Bounds = { from: string; to: string };

export function useEntityReportAccess(key: string) {
  const access = useEffectiveAccess();
  return !access || access.reports.some((report) => report.allowed
    && (report.report_key === key || report.target_path === `/app/report/${key}`));
}

export function useEntityOpenProblems(scope: EntityScope | null, allowed: boolean, limit = 1) {
  const filter = { ...scope, population: "open" };
  const query = useQuery({
    queryKey: ["report-v2", "entity-open-problems", scope, limit],
    enabled: allowed && scope !== null,
    queryFn: ({ signal }) => api.reportV2Data("security.problems", new URLSearchParams({ ...filter, queue_view: "all", limit: String(limit) }), signal),
    retry: false,
  });
  const counts = query.data?.coverage.open_by_severity;
  return {
    query,
    count: counts && !query.isError ? Object.values(counts).reduce((sum, count) => sum + count, 0) : null,
    params: new URLSearchParams(filter),
  };
}

export function EntityChangesLink({ scope, bounds, timeZone, returnTo }: {
  scope: EntityScope; bounds: Bounds; timeZone: string; returnTo: string;
}) {
  const params = new URLSearchParams({ ...scope, ...bounds, period: "custom", changes_view: "all", repeat_mode: "collapsed", tz: timeZone });
  const query = useQuery({
    queryKey: ["report-v2", "entity-changes", params.toString()],
    queryFn: ({ signal }) => api.reportV2Data("security.events.chains",
      new URLSearchParams({ ...Object.fromEntries(params), limit: "1" }), signal),
    retry: false,
  });
  const count = query.isError || query.data?.state === "error" ? null : query.data?.filtered_count;
  return <a href={withReturnTo(`/app/report/security.events.chains?${params}`, returnTo)}>
    {count == null ? t("reports.ad.users.card.object_changes") : t("entities.card.changesCount", { count: formatNumber(count) })} →
  </a>;
}
