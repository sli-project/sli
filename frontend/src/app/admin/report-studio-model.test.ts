// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { localeRuntime, setLocale } from "../../i18n";
import { buildRows, formFromVersion } from "./report-studio-model";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

it("localizes builtin list presentation while retaining original values in the editing form", () => {
  setLocale("en");
  const definition = { report_key: "access.center", version: 1, name: "Доступы пользователей и групп", owner_name: "Исходный владелец",
    purpose: "Пакеты, grants, scopes, сроки и explain", sensitivity: "confidential", status: "published", dataset_key: "access.subjects",
    dataset_version: 1, created_at: "2026-01-01T00:00:00Z", discoverable: true, requestable: false, definition_json: null,
    presentation_messages: { name: { code: "access.builtin.report.access.center.name", params: {}, text: "User and group access" },
      purpose: { code: "access.builtin.report.access.center.purpose", params: {}, text: "Packages, grants, scopes, expiry and access explanations" } } };
  const row = buildRows([definition])[0];
  expect(row.name).toBe("User and group access");
  expect(row.purpose).toBe("Packages, grants, scopes, expiry and access explanations");
  const form = formFromVersion(definition);
  expect(form.name).toBe("Доступы пользователей и групп");
  expect(form.purpose).toBe("Пакеты, grants, scopes, сроки и explain");
  expect(form.owner).toBe("Исходный владелец");
});

it("preserves custom names and purposes without presentation messages", () => {
  const definition = { report_key: "custom", version: 2, name: "Отчёт владельца", owner_name: "Владелец", purpose: "Описание владельца",
    sensitivity: "confidential", status: "published", dataset_key: "fixture", dataset_version: 1, created_at: "2026-01-01T00:00:00Z" };
  expect(buildRows([definition])[0]).toMatchObject({ name: "Отчёт владельца", purpose: "Описание владельца", owner: "Владелец" });
});
