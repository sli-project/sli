import type { ReportViewDto } from "../../api/report-v2-types";
import { t } from "../../i18n";

/** Explain which evidence belongs here without treating missing rows as proof. */
export function reportEmptyText(view: ReportViewDto, report: string, adInfrastructure = false): string {
  const params = { view: view.title || report, report };
  const source = view.source ?? view.key;
  if (source === "semantic") return t("reports.empty.findings", params);
  if (source === "changes") return adInfrastructure ? t("reports.ad.infrastructure.no_changes") : t("reports.empty.changes", params);
  if (source === "quality") return t("reports.empty.quality", params);
  if (view.kind === "chart") return t("reports.empty.chart", params);
  return t("reports.empty.table", params);
}
