import { describe, expect, it } from "vitest";
import { defaultEntityWindow, entityBoundDay, entityTypeLacksTab, entityWindowDays, recentEntityWindow } from "./entity-window";

describe("entity card period", () => {
  it("defaults to 30 days ending at the last observation", () => {
    expect(defaultEntityWindow("2026-10-02T12:00:00Z")).toEqual({ from: "2026-09-03", to: "2026-10-02" });
    expect(entityWindowDays(defaultEntityWindow("2026-10-02T12:00:00Z"))).toBe(30);
  });

  it("falls back to today when the entity was never observed", () => {
    expect(defaultEntityWindow(null, new Date("2026-10-03T08:00:00Z"))).toEqual({ from: "2026-09-04", to: "2026-10-03" });
  });

  it("counts recent windows inclusively and rejects reversed ones", () => {
    expect(recentEntityWindow(7, new Date("2026-10-03T08:00:00Z"))).toEqual({ from: "2026-09-27", to: "2026-10-03" });
    expect(entityWindowDays({ from: "2026-10-03", to: "2026-10-01" })).toBeNull();
    expect(entityWindowDays({ from: "2026-09-01", to: "2026-10-01" })).toBe(31);
  });

  it("takes the date part of a time bound", () => {
    expect(entityBoundDay("2026-09-10T00:00:00Z")).toBe("2026-09-10");
    expect(entityBoundDay(null)).toBe("");
  });

  it("hides tabs that can never hold data for a type", () => {
    expect(entityTypeLacksTab("gpo", "groups")).toBe(true);
    expect(entityTypeLacksTab("ad_group", "vpn")).toBe(true);
    expect(entityTypeLacksTab("ad_group", "groups")).toBe(false);
    expect(entityTypeLacksTab("ad_user", "vpn")).toBe(false);
    expect(entityTypeLacksTab("ad_user", "events")).toBe(false);
  });
});
