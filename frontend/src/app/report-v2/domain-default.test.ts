import { describe, expect, it } from "vitest";
import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { apiParams, valuesFromSearch, searchFromValues } from "./state";

const definition = { key: "ad.computers.v6", default_domain_id: 2, params: [
  { key: "domain", kind: "domain", hidden: true }, { key: "domain_id", kind: "domain", hidden: true },
], limits: { default: 50 } } as unknown as ReportDefinitionDto;

it.each([["", "2"], ["domain=7", "7"], ["domain_id=8", "8"], ["scope=all", undefined]] as const)("keeps the header domain on the domain events report (%s)", (search, domain) => {
  const events = { ...definition, key: "security.events.chains", params: definition.params.slice(0, 1) };
  const values = valuesFromSearch(events, new URLSearchParams(search));
  expect(values.domain).toBe(domain);
  expect(apiParams(events, values, { timeZone: "UTC", view: "events" }).get("domain")).toBe(domain ?? null);
});

describe("AD initial domain without overriding explicit choice", () => {
  it("uses server-authorized default on initial arrival", () => {
    expect(valuesFromSearch(definition, new URLSearchParams()).domain).toBe("2");
  });
  it.each(["domain=7", "domain_id=7"])("retains explicit archive or active selection %s", (search) => {
    const values = valuesFromSearch(definition, new URLSearchParams(search));
    expect(searchFromValues(definition, values).toString()).toBe(search);
  });
  it("roundtrips explicit All without changing the legacy API meaning", () => {
    const values = valuesFromSearch(definition, new URLSearchParams("scope=all"));
    expect(searchFromValues(definition, values).toString()).toBe("scope=all");
    const params = apiParams(definition, values, { timeZone: "UTC" });
    expect(params.has("domain")).toBe(false);
    expect(params.has("domain_id")).toBe(false);
    expect(params.has("scope")).toBe(false);
  });
  it("does not invent a domain without evidence or affect unrelated reports", () => {
    expect(valuesFromSearch({ ...definition, default_domain_id: null }, new URLSearchParams()).domain).toBeUndefined();
    expect(valuesFromSearch({ ...definition, key: "other" }, new URLSearchParams()).domain).toBeUndefined();
  });
});

it("preserves explicit All from AD through another report and back", () => {
  const first = valuesFromSearch(definition, new URLSearchParams("scope=all"));
  const otherDefinition = { ...definition, key: "security.problems" };
  const other = valuesFromSearch(otherDefinition, searchFromValues(definition, first));
  const back = valuesFromSearch(definition, searchFromValues(otherDefinition, other));
  expect(searchFromValues(definition, back).toString()).toBe("scope=all");
  expect(apiParams(otherDefinition, other, { timeZone: "UTC" }).has("scope")).toBe(false);
});

describe("VPN initial domain and period", () => {
  const vpn = { ...definition, key: "vpn.connections", default_domain_state: "available", params: [
    { key: "domain", label: "Domain", kind: "domain", required: true },
    { key: "period", label: "Period", kind: "period", default: "7d" },
  ], filter_options: { domain: [{ value: "1", label: "Archive" }, { value: "2", label: "Live" }] } } as ReportDefinitionDto;

  it("uses the authorized live recommendation rather than the first archive option", () => {
    const values = valuesFromSearch(vpn, new URLSearchParams());
    expect(values.domain).toBe("2");
    expect(values.period).toEqual({ preset: "7d" });
  });
  it.each(["unknown", "unavailable", "denied"] as const)("does not invent a domain when %s", (state) => {
    const values = valuesFromSearch({ ...vpn, default_domain_id: null, default_domain_state: state }, new URLSearchParams());
    expect(values.domain).toBeUndefined();
  });
  it.each(["domain=1", "domain_id=1"])("keeps the explicit archive choice %s and custom period", (selection) => {
    const values = valuesFromSearch(vpn, new URLSearchParams(`${selection}&period=custom&from=2026-01-01&to=2026-01-07`));
    expect(values.domain).toBe("1");
    expect(values.period).toEqual({ preset: "custom", from: "2026-01-01", to: "2026-01-07" });
    expect(apiParams(vpn, values, { timeZone: "UTC" }).get("domain")).toBe("1");
  });
  it("requires a choice for explicit All because VPN is a single-domain report", () => {
    const values = valuesFromSearch(vpn, new URLSearchParams("scope=all"));
    expect(values.domain).toBeUndefined();
    expect(searchFromValues(vpn, values).get("scope")).toBe("all");
    expect(apiParams(vpn, values, { timeZone: "UTC" }).get("scope")).toBe("all");
  });
});
