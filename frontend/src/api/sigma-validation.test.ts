// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { api } from "./client";

afterEach(() => vi.unstubAllGlobals());

it("discovers Sigma scopes and reads exact scoped rules without a manual catalog hash", async () => {
  const payload = { state: "available", sources: [], rules: [] };
  const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => payload });
  vi.stubGlobal("fetch", fetchMock);
  expect(await api.sigmaRules()).toEqual(payload);
  expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/semantic/sigma-rules");
  const scope = { installation_id: "00000000-0000-0000-0000-000000000001", plugin_id: "sli.windows.ad-dc",
    source_instance_id: "fixture/source+one", source_generation: "generation-1", collection_scope_id: "" };
  await api.sigmaRules(scope);
  const [path, options] = fetchMock.mock.calls[1];
  expect(Object.fromEntries(new URL(path, "https://example.invalid").searchParams)).toEqual(scope);
  expect(options.method).toBeUndefined(); expect(options.body).toBeUndefined();
});

it("reads the authorized projection with encoded exact scope and version pins", async () => {
  const payload = { state: "unavailable", reason: "catalog_unavailable", rules: [] };
  const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => payload });
  vi.stubGlobal("fetch", fetchMock);
  const params = { installation_id: "00000000-0000-0000-0000-000000000001", plugin_id: "sli.ad",
    source_instance_id: "fixture/source+one", source_generation: "fixture-generation", collection_scope_id: "fixture-scope",
    catalog_sha256: "a".repeat(64), since: "2026-01-01T00:00:00Z", until: "2026-01-02T00:00:00Z" };
  expect(await api.sigmaValidation(params)).toEqual(payload);
  const [path, options] = fetchMock.mock.calls[0];
  const url = new URL(path, "https://fixture.invalid");
  expect(url.pathname).toBe("/api/v1/semantic/attack-coverage");
  expect(Object.fromEntries(url.searchParams)).toEqual(params);
  expect(options.credentials).toBe("same-origin");
  expect(options.method).toBeUndefined();
  expect(options.body).toBeUndefined();
});
