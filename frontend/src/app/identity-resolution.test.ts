import { describe, expect, it } from "vitest";
import { представлениеОпознания, состояниеОпознания } from "./identity-resolution";

describe("представление identity resolution", () => {
  it("показывает provisional как временное обозначение", () => {
    const view = представлениеОпознания({ identity_resolution: "partial" });
    expect(view.подпись).toBe("Временное обозначение");
    expect(view.тон).toBe("warn");
    expect(view.пояснение).toContain("пересчёту");
  });

  it("не выводит exact из отсутствующего или неизвестного значения", () => {
    expect(состояниеОпознания(undefined)).toBe("unknown");
    expect(состояниеОпознания({ identity_resolution: "invented" })).toBe("unknown");
    expect(представлениеОпознания(undefined).подпись).toBe("Опознание не проверено");
  });

  it("различает exact, unresolved и partial", () => {
    const labels = ["exact", "unresolved", "partial"].map((identity_resolution) =>
      представлениеОпознания({ identity_resolution }).подпись,
    );
    expect(new Set(labels).size).toBe(3);
    expect(представлениеОпознания({ identity_resolution: "exact" }).тон).toBe("good");
    expect(представлениеОпознания({ identity_resolution: "unresolved" }).тон).toBe("bad");
  });
});
