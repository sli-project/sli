import { useDateFormatters } from "../../design-system/useDateFormatters";
import type { ReportResultDto } from "../../api/report-v2-types";
import { t } from "../../i18n";
import { knownTime } from "../../app/report-v2/FreshnessTimes";

/** Window bounds describe retained observations, not continuous collection. */
export function PairsWindowState({ result, onShowLatest, onChangeBaseline }: {
  result?: ReportResultDto;
  onShowLatest?: () => void;
  onChangeBaseline: () => void;
}) {
  const { formatDateTime } = useDateFormatters();
  if (result?.report_key !== "ad.new-logon-pairs" || !["partial", "empty"].includes(result.state)) return null;
  const coverage = result.coverage;
  const windowStatus = (truncated: unknown, covered: unknown): "truncated" | "missing" | "available" | "unknown" => truncated === true ? "truncated" : covered === false ? "missing" : covered === true ? "available" : "unknown";
  const baseline = windowStatus(coverage.baseline_truncated, coverage.baseline_history_covered);
  const period = windowStatus(coverage.period_truncated, coverage.period_history_covered ?? coverage.period_covered);
  const range = (from: unknown, to: unknown) => knownTime(from) && knownTime(to)
    ? `${formatDateTime(String(from))} — ${formatDateTime(String(to))}` : t("reports.pairs.range_unknown");
  return <div role="status">
    <p>{t("reports.pairs.baseline_window", { range: range(coverage.baseline_from_utc, coverage.baseline_to_utc_exclusive), status: t(`reports.pairs.window.${baseline}`) })}</p>
    <p>{t("reports.pairs.current_window", { range: range(result.window.from_utc, result.window.to_utc_exclusive), status: t(`reports.pairs.window.${period}`) })}</p>
    <p>{t("reports.pairs.retained_window", { range: range(coverage.history_from_utc, coverage.history_to_utc) })}</p>
    <p>{t("reports.pairs.recovery_note")}</p>
    {onShowLatest ? <button type="button" className="sli-ds-button" onClick={onShowLatest}>{t("reports.pairs.show_latest")}</button> : null}
    <button type="button" className="sli-ds-button" onClick={onChangeBaseline}>{t("reports.pairs.change_baseline")}</button>
  </div>;
}
