// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { t } from "../../i18n";
import { en } from "../../i18n/en";
import { ru } from "../../i18n/ru";
import { FileRansomDetails } from "./FileRansomDetails";

afterEach(cleanup);

describe("file ransomware details", () => {
  it("shows policy limits, episode boundaries and unproven continuity", () => {
    render(<FileRansomDetails row={{ details: { threshold: 100, window_seconds: 300, distinct_files: 110 },
      ransom: { state: "admitted", episode_key: "synthetic-episode", incomplete: true,
        first_seen: "2026-10-18T00:00:00Z", last_seen: "2026-10-18T00:04:00Z" } }}/>);
    expect(screen.getByText(t("file-audit.ransom.state.admitted"))).toBeTruthy();
    expect(screen.getByText("100")).toBeTruthy();
    expect(screen.getByText("300")).toBeTruthy();
    expect(screen.getByText("110")).toBeTruthy();
    expect(screen.getByText("synthetic-episode")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toBe(t("file-audit.ransom.incomplete"));
    expect(screen.getByText(t("file-audit.ransom.start"))).toBeTruthy();
    expect(screen.getByText(t("file-audit.ransom.end"))).toBeTruthy();
  });

  it("shows the retained approval reason, author and exclusive expiry", () => {
    render(<FileRansomDetails row={{ ransom: { state: "excluded", exclusion: {
      reason: "Synthetic backup", approved_by: "synthetic-admin", active_from: "2026-10-18T00:00:00Z",
      active_to: "2026-10-18T01:00:00Z" } } }}/>);
    expect(screen.getByText(t("file-audit.ransom.state.excluded"))).toBeTruthy();
    expect(screen.getByText("Synthetic backup")).toBeTruthy();
    expect(screen.getByText("synthetic-admin")).toBeTruthy();
    expect(screen.getByText(t("file-audit.ransom.active_to"))).toBeTruthy();
  });

  it.each(["diagnostic", "not_evaluated", "not_applicable", "details_unavailable", "denied"] as const)("keeps %s distinct from publication", (state) => {
    render(<FileRansomDetails row={{ ransom: { state } }}/>);
    expect(screen.getByText(t(`file-audit.ransom.state.${state}`))).toBeTruthy();
    expect(screen.queryByText(t("file-audit.ransom.state.admitted"))).toBeNull();
  });

  it("has the same nonempty RANSOM keys in both languages", () => {
    const keys = (dictionary: Record<string, string>) => Object.keys(dictionary).filter((key) => key.startsWith("file-audit.ransom.")).sort();
    expect(keys(ru)).toEqual(keys(en));
    expect(keys(ru).every((key) => ru[key as keyof typeof ru] && en[key as keyof typeof en])).toBe(true);
  });
});
