// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { localeRuntime, setLocale } from "../../i18n";
import { ArchiveDomainNotice } from "./ADSourceNotice";

const old = { domain_id: 11, domain_name: "old.example.test", observed_at_utc: "2026-09-15T12:00:00Z" };
const fresh = { domain_id: 22, domain_name: "new.example.test", observed_at_utc: "2026-10-16T11:00:00Z" };

beforeEach(() => {
  vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined);
  vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-16T12:00:00Z"));
  setLocale("ru");
});
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("dates an archive from rendered report coverage, not a different domain or publication (%s)", (locale) => {
  setLocale(locale);
  render(<ArchiveDomainNotice timeZone="UTC" domains={[{ id: 11, display_name: "old.example.test", is_archived: true,
    freshness: { observed_at_utc: "2026-10-16T11:00:00Z" } }]} coverage={{ domains: [old, fresh] }}/>);
  expect(screen.getByRole("status").textContent).toContain(locale === "ru" ? "15.09.2026" : "Sep 15, 2026");
  expect(screen.getByRole("status").textContent).not.toContain("16.10.2026");
});
