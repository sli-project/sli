import { EMPTY_VALUE } from "../shared/format";
import { t, plural } from "../i18n";
import { useState } from "react";
import { DetailDrawer, FactList } from "../design-system";
import { formatDate, formatDateTime } from "../shared/date-time";
import { useTimeZone } from "./App";
import { VpnConnectionSessionEvidence } from "./vpn-session-evidence";

type Row = Record<string, unknown>;
export type DaySession = {
  session_row_id?: string; started_at_utc?: string | null; stopped_at_utc?: string | null; last_observed_at_utc?: string | null;
  lifecycle_state?: string | null; overlap_violation?: boolean | null; duration_seconds?: number | null;
  confirmed_seconds_in_period?: number | null; observation_count?: number | null;
};

/** «2 ч 05 мин»; an unknown duration is said, not shown as zero. */
export function vpnDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return t("vpn.duration.notCalculated");
  const minutes = Math.round(seconds / 60);
  const hours = Math.floor(minutes / 60);
  return hours ? t("vpn.duration.hm", { hours, minutes: String(minutes % 60).padStart(2, "0") }) : t("vpn.duration.m", { minutes });
}

const stateText = (session: DaySession) => session.overlap_violation ? t("vpn.state.overlap") : session.lifecycle_state === "closed" && session.stopped_at_utc ? t("vpn.state.closed") : t("vpn.state.noEnd");

/** Sessions of one employee on one day; a chosen session shows its facts and Accounting evidence. */
export function VpnDayDrawer({ row, date, sessions, sourceDomainId, dayTimeZone, onClose }: {
  row: Row; date: string; sessions: DaySession[]; sourceDomainId: number | null; dayTimeZone?: string | null; onClose: () => void;
}) {
  const { timeZone } = useTimeZone();
  const format = (value?: string | null) => (value ? formatDateTime(value, timeZone) : EMPTY_VALUE);
  const [chosenId, setChosenId] = useState<string | null>(null);
  const chosen = sessions.find((session) => session.session_row_id === chosenId) ?? null;
  const name = String(row.display_name ?? t("vpn.drawer.employeeFallback"));
  const dayTitle = formatDate(date);
  return <DetailDrawer open title={chosen ? t("vpn.drawer.title.session", { name }) : t("vpn.drawer.title.day", { name, dayTitle })}
    subtitle={chosen ? `${String(row.account_name ?? "")} · ${String(row.department ?? "")}` : plural(sessions.length, {
      one: t("vpn.drawer.daySessions.one", { count: sessions.length }),
      few: t("vpn.drawer.daySessions.few", { count: sessions.length }),
      many: t("vpn.drawer.daySessions.many", { count: sessions.length }),
      other: t("vpn.drawer.daySessions.other", { count: sessions.length }),
    }) + (dayTimeZone ? t("vpn.drawer.dayTimeZone", { timeZone: dayTimeZone }) : "")}
    onClose={onClose}
    footer={<>
      {chosen ? <button type="button" className="sli-ds-button" onClick={() => setChosenId(null)}>{t("vpn.drawer.backToDay")}</button> : null}
      {row.entity_id ? <a className="sli-ds-button" data-variant="primary" href={`/app/entities/${encodeURIComponent(String(row.entity_id))}`}>{t("vpn.drawer.employeeCard")}</a> : null}
    </>}>
    {chosen ? <>
      <FactList facts={[
        { label: t("vpn.drawer.fact.state"), value: stateText(chosen) },
        { label: t("vpn.drawer.fact.start"), value: format(chosen.started_at_utc) },
        { label: t("vpn.drawer.fact.lastObserved"), value: format(chosen.last_observed_at_utc) },
        { label: t("vpn.drawer.fact.end"), value: chosen.stopped_at_utc ? format(chosen.stopped_at_utc) : t("vpn.drawer.fact.endUnconfirmed") },
        { label: t("vpn.drawer.fact.duration"), value: vpnDuration(chosen.duration_seconds) },
        { label: t("vpn.drawer.fact.inPeriod"), value: vpnDuration(chosen.confirmed_seconds_in_period) },
        { label: t("vpn.drawer.fact.observations"), value: chosen.observation_count ?? EMPTY_VALUE },
      ]}/>
      {sourceDomainId && chosen.session_row_id
        ? <VpnConnectionSessionEvidence key={chosen.session_row_id} sourceDomainId={sourceDomainId} sessionRowId={chosen.session_row_id} formatTime={format}/>
        : <p className="sli-ds-header__subtitle">{t("vpn.drawer.noEvidenceId")}</p>}
    </> : <ul className="sli-ds-list">
      {sessions.map((session) => <li key={session.session_row_id ?? session.started_at_utc ?? ""} className="sli-ds-list__item">
        <button type="button" className="sli-ds-button" data-variant="ghost" onClick={() => setChosenId(session.session_row_id ?? null)}>
          {format(session.started_at_utc)} → {session.stopped_at_utc ? format(session.stopped_at_utc) : t("vpn.drawer.fact.endUnconfirmed")} · {vpnDuration(session.duration_seconds)} · {stateText(session)}
        </button>
      </li>)}
      {row.session_details_has_more ? <li className="sli-ds-header__subtitle">{t("vpn.drawer.hasMoreNote")}</li> : null}
    </ul>}
  </DetailDrawer>;
}
