// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale, t } from "./index";
import { localizeReportRow } from "./report-metadata";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it.each(["ru", "en"] as const)("preserves observed names, source facts and unknown identifiers in %s", (locale) => {
  setLocale(locale);
  const sid = "S-1-5-21-100-200-300-1101";
  const raw = { actor: sid, actor_text: "fallback", assigned_to: null,
    entities: [{ display_name: sid, entity_role: "target_entity" }],
    entity_messages: ["Synthetic retained name"],
    presentation_messages: {
      actor_text: { code: "security.problems.identity.name", params: { name: "EXAMPLE\\synthetic-admin" }, text: "fallback" },
      assigned_to_text: { code: "security.problems.assignee.unassigned", params: {}, text: "fallback" },
      identity_sources_text: { code: "security.problems.identity.sources", params: { details: "Synthetic retained name · AD · 2026-08-01" }, text: "fallback" },
    } };
  const view = localizeReportRow("security.problems", raw);
  expect(view.actor_text).toBe("EXAMPLE\\synthetic-admin");
  expect(view.entity_text).toBe("Synthetic retained name");
  expect(view.actor).toBe(sid);
  expect(view.entities).toEqual(raw.entities);
  expect(view.assigned_to).toBeNull();
  expect(view.assigned_to_text).toBe(t("security.problems.assignee.unassigned"));
  expect(view.identity_sources_text).toBe(t("security.problems.identity.sources", { details: "Synthetic retained name · AD · 2026-08-01" }));
  expect(raw.actor_text).toBe("fallback");
  const unknown = localizeReportRow("security.problems", { ...raw, entity_messages: [sid] });
  expect(unknown.entity_text).toBe(sid);
});
