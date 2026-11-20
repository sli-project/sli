import type { ReportResultDto } from "../../api/report-v2-types";
import { t } from "../../i18n";
import { formatDateTime } from "../../shared/date-time";
import { knownTime } from "./FreshnessTimes";

/** The archive date describes this report's observations, never another source's clock. */
export function ArchiveDomainNotice({ domains, coverage, timeZone, detail = false }: {
  domains?: ReportResultDto["domains"]; coverage?: ReportResultDto["coverage"]; timeZone: string; detail?: boolean;
}) {
  const rows = Array.isArray(coverage?.domains) ? coverage.domains : [];
  return <>{domains?.filter((domain) => domain.is_archived).map((domain) => {
    const observations = rows.flatMap((value) => {
      if (!value || typeof value !== "object") return [];
      const row = value as Record<string, unknown>;
      if (row.domain_id !== domain.id) return [];
      const observed = "observed_at_utc" in row ? row.observed_at_utc : row.latest_observed_at_utc;
      return knownTime(observed) ? [observed] : [];
    }).sort((a, b) => Date.parse(a) - Date.parse(b));
    const date = observations[0] ? t("domain.archive.asOf", { date: formatDateTime(observations[0], timeZone) }) : null;
    return <span role={detail ? undefined : "status"} key={domain.id}>{domain.display_name} · {t("domain.archive.label")}
      {date ? <> · {date}</> : detail ? <> · {t("domain.archive.unknownDate")}</> : null}
      {detail ? <>. {t("domain.archive.coverage")}</> : null}</span>;
  })}</>;
}
