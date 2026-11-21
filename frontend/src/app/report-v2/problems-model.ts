import { getLocale, t } from "../../i18n";
import { formatDateTime, utcToLocalDateTimeInput } from "../../shared/date-time";
import { EMPTY_VALUE, formatNumber } from "../../shared/format";

const actionable = ["success", "brute", "spray", "disabled", "member", "cleared", "audit", "agent"] as const;
export type ProblemKind = typeof actionable[number] | "other";
export type Severity = "critical" | "high" | "medium" | "low";
export type Breakdown = { object?: string | null; source?: string | null; accounts: number; attempts: number; at: string };
export type Problem = {
  id: number; title: string; next?: string; kind: ProblemKind; severity?: Severity; status: string;
  object?: string | null; account?: string | null; computer?: string | null; actor?: string | null;
  source?: string | null; group?: string | null; category?: string | null;
  log?: string | null; event_type?: number | null;
  first_seen_utc?: string | null; last_seen_utc?: string | null; closed_at?: string | null;
  first_attempt?: string | null; success_at?: string | null;
  attempts?: number | null; accounts?: number | null; address_count?: number | null;
  addresses?: string[]; breakdown?: Breakdown[]; has_journal?: boolean;
};

export function isClosed(problem: Problem) {
  return problem.status === "closed" || problem.status === "false_positive";
}

export function problemTime(value: string | null | undefined, zone: string, now = new Date(), timeOnly = false) {
  if (!value || Number.isNaN(Date.parse(value))) return EMPTY_VALUE;
  const localDay = (instant: string) => utcToLocalDateTimeInput(instant, zone).slice(0, 10);
  if (!timeOnly && localDay(value) !== localDay(now.toISOString())) return formatDateTime(value, zone, { withYear: false });
  return new Intl.DateTimeFormat(getLocale() === "ru" ? "ru-RU" : "en-GB", {
    timeZone: zone === "browser" ? undefined : zone, hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).format(new Date(value));
}

export function problemObject(problem: Problem) {
  return problem.object || (problem.accounts ? t("problems.accounts_value", { count: formatNumber(problem.accounts) }) : EMPTY_VALUE);
}

export function problemSource(problem: Problem) {
  if (problem.kind === "brute" && (problem.address_count ?? 0) > 1)
    return t("problems.addresses_value", { count: formatNumber(problem.address_count!) });
  if (problem.kind === "success" && problem.computer && problem.source && problem.computer.toLowerCase() !== problem.source.toLowerCase())
    return `${problem.computer} · ${problem.source}`;
  return [problem.actor, problem.source].find((value) => value && value.toLowerCase() !== problem.object?.toLowerCase()) || EMPTY_VALUE;
}

export function recorded(problem: Problem) {
  const { kind, attempts } = problem;
  return typeof attempts === "number" && (kind === "success" || kind === "brute" || kind === "spray")
    ? t(`problems.event.${kind}`, { count: formatNumber(attempts) })
    : problem.title || EMPTY_VALUE;
}

export function problemStatement(problem: Problem, zone: string, now: Date) {
  const event = recorded(problem).replace(/[.]+$/, "");
  const time = problemTime(problem.success_at ?? problem.last_seen_utc, zone, now);
  if (time === EMPTY_VALUE) return event;
  if (problem.kind === "success" && problem.account && typeof problem.attempts === "number") {
    return t("problems.statement.success", { time, account: problem.account, count: formatNumber(problem.attempts) });
  }
  return event === EMPTY_VALUE ? time : t("problems.at", { time, event });
}

export function problemSteps(problem: Problem) {
  return problem.kind === "other" ? problem.next ? [problem.next] : [] : ([1, 2, 3] as const).map((step) => t(`problems.step.${problem.kind as Exclude<ProblemKind, "other">}.${step}`));
}

export function problemFacts(problem: Problem, zone: string) {
  const time = (value?: string | null) => value ? problemTime(value, zone) : null;
  const number = (value?: number | null) => value == null ? null : formatNumber(value);
  const sameTime = (a?: string | null, b?: string | null) => Boolean(a && b && Date.parse(a) === Date.parse(b));
  const candidates = [
    { label: t("problems.account"), value: problem.account },
    { label: t("problems.computer"), value: problem.computer },
    { label: t("problems.group"), value: problem.group },
    { label: t("problems.initiator"), value: problem.actor },
    { label: t("problems.address"), value: problem.source && problem.addresses?.includes(problem.source) ? problem.source : null },
    { label: t("problems.category"), value: problem.category },
    { label: t("problems.attempts"), value: number(problem.attempts) },
    { label: t("problems.first_attempt"), value: time(problem.first_attempt) },
    { label: t("problems.success_time"), value: time(problem.success_at) },
    { label: t("problems.accounts"), value: number(problem.accounts) },
    { label: t("problems.addresses"), value: number(problem.address_count) },
    { label: t("problems.log"), value: problem.log },
    { label: t("problems.event_type"), value: problem.event_type?.toString() },
    { label: t("problems.first_seen"), value: !sameTime(problem.first_seen_utc, problem.first_attempt) && !sameTime(problem.first_seen_utc, problem.last_seen_utc) ? time(problem.first_seen_utc) : null },
    { label: t("problems.last_seen"), value: !sameTime(problem.last_seen_utc, problem.success_at) ? time(problem.last_seen_utc) : null },
  ];
  return candidates.filter((fact) => fact.value && fact.value !== EMPTY_VALUE).slice(0, 6);
}

export function problemJournalHref(problem: Problem, zone: string) {
  const last = Date.parse(problem.last_seen_utc || "");
  const first = Date.parse(problem.first_attempt || problem.first_seen_utc || "");
  if (!problem.has_journal || !Number.isFinite(last)) return null;
  const from = new Date(Math.min(Number.isFinite(first) ? first : last, last) - 60_000).toISOString();
  const to = new Date(last + 60_000).toISOString();
  return `/app/report/events.journal?${new URLSearchParams({ problem_id: String(problem.id), period: "custom", from, to, tz: zone })}`;
}
