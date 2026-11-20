import type { ReactNode } from "react";
import { useTimeZone } from "../../shared/time-zone";
import type { ReportIntentDto, ReportResultDto } from "../../api/report-v2-types";
import { Badge, type ResultState } from "../../design-system";
import { t } from "../../i18n";
import { FreshnessTimes, freshnessSummary } from "./FreshnessTimes";

/**
 * The status line says how fresh the data is and nothing else (docs/UI_STANDARD.md, rule 2).
 * A silent or failed source is reported by ReportState, by name and time.
 */
export function ReportPassportMeta({ intent, coverage, state, timeZone, description, children }: {
  intent: ReportIntentDto;
  coverage?: ReportResultDto["coverage"];
  state: ResultState;
  timeZone?: string;
  description?: string;
  children?: ReactNode;
}) {
  const selected = useTimeZone();
  timeZone ??= selected.timeZone;
  const clocks = { event: coverage?.event_at_utc, snapshot: coverage?.snapshot_at_utc,
    published: coverage?.published_at_utc, observed: coverage?.observed_at_utc, timeZone };
  const summary = freshnessSummary(clocks);
  return <>
    {summary ? <span>{summary}</span> : null}
    <details><summary>{t("reports.passport.more")}</summary>
      {description ? <p>{description}</p> : null}
      {children}
      <FreshnessTimes {...clocks}/>
      {state === "stale" || coverage?.state === "stale" ? <Badge tone="warning">{t("reports.passport.stale")}</Badge> : null}
      {intent.freshness_expectation.trim() ? <p>{t("reports.passport.expectation", { value: intent.freshness_expectation })}</p> : null}
    </details>
  </>;
}
