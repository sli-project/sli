import { afterEach, expect, it, vi } from "vitest";
import { api } from "./client";

afterEach(() => vi.unstubAllGlobals());

it("preserves the legacy unfiltered method and sends explicit class filters separately", async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ users: [] }) });
  vi.stubGlobal("fetch", fetch);
  await api.v4AccessSubjects();
  await api.v4AccessSubjectsForAccountType("people");
  await api.v4AccessSubjectsForAccountType("service");
  expect(fetch.mock.calls.map(([url]) => url)).toEqual([
    "/api/v1/access/subjects",
    "/api/v1/access/subjects?account_type=people",
    "/api/v1/access/subjects?account_type=service",
  ]);
});
