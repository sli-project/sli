// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale, t } from "../i18n";
import { DecoyVersionLink } from "./decoy-version-link";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { cleanup(); setLocale("ru"); vi.restoreAllMocks(); });
const id = "00000000-0000-4000-8000-000000000003";

it.each(["ru", "en"] as const)("links the event-time label version in %s", (locale) => {
  setLocale(locale);
  render(<DecoyVersionLink row={{ decoy_id: id, decoy_revision: 7 }}/>);
  expect(screen.getByRole("link", { name: t("decoys.event_version", { revision: 7 }) }).getAttribute("href"))
    .toBe(`/app/platform-settings?decoy_id=${id}&decoy_revision=7#decoys`);
});

it.each([{}, { decoy_id: id }, { decoy_id: "invalid", decoy_revision: 1 },
  { decoy_id: id, decoy_revision: 0 }, { decoy_id: id, decoy_revision: 1.5 }])("omits incomplete or hidden references: %s", (row) => {
  render(<DecoyVersionLink row={row}/>);
  expect(screen.queryByRole("link")).toBeNull();
});
