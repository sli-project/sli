import { describe, expect, it } from "vitest";
import { entityVpnApiParameters, entityVpnCompletenessLabel, entityVpnLifecycleLabel } from "./entity-vpn";

describe("entity VPN presentation", () => {
  it("preserves exact Accounting window and declines an unbounded read", () => {
    expect(entityVpnApiParameters("?timezone=UTC")).toBeNull();
    expect(entityVpnApiParameters("?time_from=2026-09-10T10%3A00%3A00.123456Z&time_to=2026-09-10T11%3A00%3A00.654321Z&timezone=Asia%2FBangkok")?.toString())
      .toBe("limit=50&time_from=2026-09-10T10%3A00%3A00.123456Z&time_to=2026-09-10T11%3A00%3A00.654321Z&timezone=Asia%2FBangkok");
  });

  it("never calls an observed open session active or completed", () => {
    expect(entityVpnLifecycleLabel("open_observed")).toBe("Наблюдается Start, Stop отсутствует");
    expect(entityVpnLifecycleLabel("closed")).toBe("Наблюдаются Start и Stop");
    expect(entityVpnCompletenessLabel("partial")).toBe("Неполные наблюдения");
  });
});
