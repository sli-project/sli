// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { PlatformReadiness, SemanticQueueOverview } from "../api/client";
import { localeRuntime, setLocale } from "../i18n";
import { operationsReadinessView } from "./admin/readiness-view";
import { вердиктКонтура } from "./semantic-observability";
import { VpnDayDrawer } from "./vpn-day-drawer";

vi.mock("./App", () => ({ useTimeZone: () => ({ timeZone: "UTC" }) }));
vi.mock("./vpn-session-evidence", () => ({ VpnConnectionSessionEvidence: () => null }));
vi.spyOn(localeRuntime, "reload").mockImplementation(() => {});
afterEach(() => { cleanup(); setLocale("ru"); });

const cases = [
  [0, "предупреждений", "заданий", "сессий"],
  [1, "предупреждение", "задание", "сессия"],
  [2, "предупреждения", "задания", "сессии"],
  [5, "предупреждений", "заданий", "сессий"],
  [11, "предупреждений", "заданий", "сессий"],
  [21, "предупреждение", "задание", "сессия"],
  [22, "предупреждения", "задания", "сессии"],
  [25, "предупреждений", "заданий", "сессий"],
] as const;

for (const locale of ["en", "ru"] as const) {
  it.each(cases)(`${locale}: localizes readiness warnings and queue verdicts at %i`, (count, warning, task) => {
    setLocale(locale);
    const view = operationsReadinessView({ postgres: { warnings: Array(count).fill("synthetic") }, storage: {} } as PlatformReadiness);
    expect(view.metrics[0].caption).toContain(count === 0 ? (locale === "en" ? "no warnings" : "без предупреждений")
      : `${count} ${locale === "en" ? count === 1 ? "warning" : "warnings" : warning}`);
    for (const status of ["queued", "quarantined"]) {
      const queue = { status: "ok", items: [{ queue_name: "processing", queue_status: status, depth: count, expired_leases: 0, retries: 0 }] } as SemanticQueueOverview;
      const verdict = вердиктКонтура(queue, false, null);
      if (count > 0) expect(verdict.строка).toContain(`${count} ${locale === "en" ? count === 1 ? "task" : "tasks" : task}`);
      if (locale === "en") expect(verdict.строка).not.toMatch(/[а-яё]/i);
    }
  });

  it.each(cases)(`${locale}: localizes the VPN day subtitle at %i`, (count, _warning, _task, session) => {
    setLocale(locale);
    render(<VpnDayDrawer row={{}} date="2026-10-22" sessions={Array.from({ length: count }, (_, i) => ({ session_row_id: String(i) }))}
      sourceDomainId={null} dayTimeZone="Asia/Novosibirsk" onClose={() => {}}/>);
    const label = locale === "en"
      ? `${count} ${count === 1 ? "session" : "sessions"} for the day · day in time zone Asia/Novosibirsk`
      : `${count} ${session} за день · день по часовому поясу Asia/Novosibirsk`;
    expect(screen.getByText(label)).toBeTruthy();
  });
}
