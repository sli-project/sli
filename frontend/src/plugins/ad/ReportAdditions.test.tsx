// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale } from "../../i18n";
import { AgentStatus, DnsIp, LastWorkplace, dnsColumnLabel } from "./ReportAdditions";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });

it("shows agent versions with their contact state and leaves an unresolved match blank", () => {
  const stamp = "2026-10-17T03:00:00Z";
  render(<><div><AgentStatus row={{ sli_agent: { state: "installed", version: "1.2.3", last_seen_utc: stamp } }}/></div>
    <div><AgentStatus row={{ sli_agent: { state: "silent", version: "2.3.4", last_seen_utc: stamp } }}/></div>
    <div><AgentStatus row={{ sli_agent: { state: "absent" } }}/></div>
    <div><AgentStatus row={{ sli_agent: { state: "unknown" } }}/></div></>);
  expect(screen.getByText(/1\.2\.3 · На связи/)).toBeTruthy();
  expect(screen.getByText(/2\.3\.4 · Нет связи с/)).toBeTruthy();
  expect(screen.getByText("Нет агента")).toBeTruthy();
  expect(screen.getByText("—")).toBeTruthy();
});

it("labels DNS with its observation date and uses a dash for missing addresses", () => {
  setLocale("ru");
  const { rerender } = render(<DnsIp row={{ dns_ip: { addresses: ["192.0.2.1"], observed_at_utc: "2026-10-17T03:00:00Z" } }}/>);
  expect(screen.getByText("192.0.2.1")).toBeTruthy();
  expect(screen.getByText(/DNS на/)).toBeTruthy();
  expect(dnsColumnLabel([{ dns_ip: { observed_at_utc: "2026-10-17T03:00:00Z" } }])).toContain("17.10.2026");
  rerender(<DnsIp row={{}}/>);
  expect(dnsColumnLabel([])).toBe("IP по DNS");
  expect(screen.getByText("—")).toBeTruthy();
});

it("shows the workplace and URL-encodes the exact account and domain filter", () => {
  setLocale("ru");
  render(<LastWorkplace row={{ sam: "synthetic\\account+1", domain_id: 2, last_workplace: {
    computer: "synthetic-host", computer_id: 5, at_utc: "2026-10-17T03:00:00Z", kind: "rdp",
  } }}/>);
  expect(screen.getByRole("link", { name: "synthetic-host" }).getAttribute("href")).toBe("/app/entities/5");
  expect(screen.getByText(/RDP/)).toBeTruthy();
  const link = screen.getByRole("link", { name: "Все входы пользователя" });
  const url = new URL(link.getAttribute("href")!, "https://synthetic.invalid");
  expect(url.pathname).toBe("/app/report/ad.computer-logons");
  expect(url.searchParams.get("user")).toBe("synthetic\\account+1");
  expect(url.searchParams.get("domain_id")).toBe("2");
});

it("shows a dash and keeps logon navigation available when the workplace is absent", () => {
  setLocale("en");
  render(<LastWorkplace compact row={{ sam: "synthetic-account" }}/>);
  expect(screen.getByText("—")).toBeTruthy();
  expect(screen.getByRole("link", { name: "All user logons" })).toBeTruthy();
});

it.each([
  ["ru", "локально"],
  ["en", "local"],
] as const)("translates local workplace logons in %s", (locale, label) => {
  setLocale(locale);
  render(<LastWorkplace row={{ last_workplace: {
    computer: "synthetic-host", at_utc: "2026-10-17T03:00:00Z", kind: "local",
  } }}/>);
  expect(screen.getByText(new RegExp(` · ${label}$`))).toBeTruthy();
});
