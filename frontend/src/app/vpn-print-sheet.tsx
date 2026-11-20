import { EMPTY_VALUE } from "../shared/format";
import { plural, t } from "../i18n";
import { useMemo, useState } from "react";
import { createPortal } from "react-dom";
import type { ReportResultDto } from "../api/report-v2-types";
import { DetailDrawer } from "../design-system";
import { formatDate, formatDateTime } from "../shared/date-time";
import { useTimeZone } from "./App";
import { vpnDuration } from "./vpn-day-drawer";

type Row = Record<string, unknown>;

const num = (value: unknown) => (typeof value === "number" ? value : Number(value ?? 0) || 0);
const employeeForm = (count: number) => plural(count, {
  one: t("vpn.print.employee.one"), few: t("vpn.print.employee.few"),
  many: t("vpn.print.employee.many"), other: t("vpn.print.employee.other"),
});

/** Confirmed time of one employee; only open sessions means "unknown", not zero. */
export function confirmedTime(row: Row): string {
  if (!num(row.closed_session_count) && num(row.open_session_count)) return t("vpn.print.unconfirmedTime");
  return vpnDuration(row.confirmed_minutes === null || row.confirmed_minutes === undefined ? null : num(row.confirmed_minutes) * 60);
}

/**
 * «Печатный лист» (page action `vpn.print-sheet`): the user picks employees
 * among the loaded rows and prints a one-page summary for the period.
 */
export function VpnPrintSheet({ rows, result }: { rows: Row[]; result?: ReportResultDto }) {
  const { timeZone } = useTimeZone();
  const [open, setOpen] = useState(false);
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const keyOf = (row: Row) => String(row.entity_id ?? row.account_name ?? row.display_name);
  const selected = useMemo(() => rows.filter((row) => chosen.has(keyOf(row))), [rows, chosen]);
  const allChosen = rows.length > 0 && rows.every((row) => chosen.has(keyOf(row)));
  const selectionParams = { count: rows.length, more: result?.has_more ? t("vpn.print.selection.more") : "" };
  const selectionText = plural(rows.length, {
    one: t("vpn.print.selection.one", selectionParams), few: t("vpn.print.selection.few", selectionParams),
    many: t("vpn.print.selection.many", selectionParams), other: t("vpn.print.selection.other", selectionParams),
  });
  const window_ = result?.window;
  const period = `${(window_?.local_from_date ? formatDate(window_.local_from_date) : null) ?? (window_?.from_utc ? formatDateTime(window_.from_utc, timeZone) : EMPTY_VALUE)} — ${(window_?.local_to_date ? formatDate(window_.local_to_date) : null) ?? (window_?.to_utc_exclusive ? formatDateTime(window_.to_utc_exclusive, timeZone) : EMPTY_VALUE)}`;
  const toggle = (key: string) => setChosen((current) => {
    const next = new Set(current);
    if (next.has(key)) next.delete(key); else next.add(key);
    return next;
  });

  return <>
    <button type="button" className="sli-ds-button" onClick={() => setOpen(true)} disabled={!rows.length}>{t("vpn.print.button")}</button>
    <DetailDrawer open={open} title={t("vpn.print.button")} subtitle={selectionText}
      onClose={() => setOpen(false)}
      footer={<>
        <button type="button" className="sli-ds-button" onClick={() => setChosen(allChosen ? new Set() : new Set(rows.map(keyOf)))}>{allChosen ? t("vpn.print.unselectAll") : t("vpn.print.selectAll")}</button>
        <button type="button" className="sli-ds-button" data-variant="primary" disabled={!selected.length} onClick={() => window.print()}>{t("vpn.print.action")} · {selected.length} {employeeForm(selected.length)}</button>
      </>}>
      <ul className="sli-ds-list">
        {rows.map((row) => {
          const key = keyOf(row);
          return <li key={key} className="sli-ds-list__item">
            <label><input type="checkbox" checked={chosen.has(key)} onChange={() => toggle(key)}/> {String(row.display_name ?? key)} <span className="sli-ds-header__subtitle">· {String(row.department ?? "")} · {confirmedTime(row)}</span></label>
          </li>;
        })}
      </ul>
    </DetailDrawer>
    {selected.length ? createPortal(<section className="sli-ds-print-sheet" aria-hidden="true">
      <h1>{t("vpn.print.header")}</h1>
      <p>{t("vpn.print.period", { period, timezone: window_?.timezone ? ` · ${window_.timezone}` : "" })}</p>
      <p>{t("vpn.print.meta", { date: formatDateTime(new Date().toISOString(), timeZone), count: selected.length, status: selected.some((row) => num(row.open_session_count) > 0) ? t("vpn.print.meta.withOpen") : t("vpn.print.meta.allClosed") })}</p>
      <table>
        <thead><tr><th>{t("vpn.print.col.name")}</th><th>{t("vpn.print.col.account")}</th><th>{t("vpn.print.col.department")}</th><th>{t("vpn.print.col.sessions")}</th><th>{t("vpn.print.col.confirmedTime")}</th><th>{t("vpn.print.col.openSessions")}</th><th>{t("vpn.print.col.overlaps")}</th></tr></thead>
        <tbody>{selected.map((row) => <tr key={keyOf(row)}>
          <td>{String(row.display_name ?? "")}</td><td>{String(row.account_name ?? "")}</td><td>{String(row.department ?? "")}</td>
          <td>{num(row.session_count)}</td><td>{confirmedTime(row)}</td><td>{num(row.open_session_count)}</td><td>{num(row.overlap_count) ? t("vpn.print.yes") : t("vpn.print.no")}</td>
        </tr>)}</tbody>
      </table>
      <p>{t("vpn.print.disclaimer")}</p>
    </section>, document.body) : null}
  </>;
}
