import { EMPTY_VALUE } from "../../shared/format";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { FactList } from "../../design-system";
import { t } from "../../i18n";

type Row = Record<string, unknown>;
const states = ["not_evaluated", "not_applicable", "admitted", "diagnostic", "excluded", "details_unavailable", "denied"] as const;

export function FileRansomDetails({ row }: { row: Row }) {
  const { formatDateTime } = useDateFormatters();
  const ransom = (row.ransom ?? {}) as Row;
  const details = (row.details ?? {}) as Row;
  const exclusion = ransom.exclusion as Row | undefined;
  const state = states.find((value) => value === ransom.state) ?? "not_evaluated";
  const instant = (value: unknown) => typeof value === "string" ? formatDateTime(value) : EMPTY_VALUE;
  const text = (value: unknown) => typeof value === "string" || typeof value === "number" ? String(value) : EMPTY_VALUE;
  return <section aria-label={t("file-audit.ransom.title")}>
    <h3>{t("file-audit.ransom.title")}</h3>
    <p>{t(`file-audit.ransom.state.${state}`)}</p>
    <p>{t("file-audit.ransom.explanation")}</p>
    <FactList facts={[
      { label: t("file-audit.ransom.threshold"), value: text(details.threshold) },
      { label: t("file-audit.ransom.window"), value: text(details.window_seconds) },
      { label: t("file-audit.ransom.files"), value: text(details.distinct_files) },
      { label: t("file-audit.ransom.episode"), value: text(ransom.episode_key) },
      { label: t("file-audit.ransom.start"), value: instant(ransom.first_seen) },
      { label: t("file-audit.ransom.end"), value: instant(ransom.last_seen) },
      { label: t("file-audit.ransom.generation"), value: text(ransom.source_generation) },
      ...(exclusion ? [
        { label: t("file-audit.ransom.reason"), value: text(exclusion.reason) },
        { label: t("file-audit.ransom.approved_by"), value: text(exclusion.approved_by) },
        { label: t("file-audit.ransom.active_from"), value: instant(exclusion.active_from) },
        { label: t("file-audit.ransom.active_to"), value: instant(exclusion.active_to) },
      ] : []),
    ]}/>
    {ransom.incomplete === true ? <p role="status">{t("file-audit.ransom.incomplete")}</p> : null}
  </section>;
}
