import { expect, it } from "vitest";
import { stateTone } from "./state-tone";

it.each(["critical", "high", " HIGH ", "высокий", "критическое", "error", "failed", "stale", "timeout", "blocked"])("renders %s in red", (state) => {
  expect(stateTone(state)).toBe("danger");
});

it.each([undefined, null, "", "unknown", "future_state", "not_ok", "inactive", "incomplete", "not_enabled", "not_high", "не получена", "constructor", "__proto__"])("keeps %s neutral without substring matching", (state) => {
  expect(stateTone(state)).toBe("neutral");
});

it.each(["ok", "normal", "healthy", "current", "complete", "low", "в норме"])("renders confirmed %s in green", (state) => {
  expect(stateTone(state)).toBe("success");
});

it.each(["warning", "medium", "partial", "lagging"])("keeps %s as a warning", (state) => {
  expect(stateTone(state)).toBe("warning");
});
