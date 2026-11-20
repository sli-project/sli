import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { InvestigationMutationGate, INVESTIGATION_MUTATION_ROLE_MATRIX, bootstrapEffectiveRole, canPerformInvestigationMutation } from "./access-control";

const actions = Object.keys(INVESTIGATION_MUTATION_ROLE_MATRIX) as Array<keyof typeof INVESTIGATION_MUTATION_ROLE_MATRIX>;

describe("investigation mutation role matrix", () => {
  it.each(actions)("renders %s for viewers because ИБ owns investigations", (action) => {
    const html = renderToStaticMarkup(<InvestigationMutationGate role="viewer" action={action}><button type="button">Изменить</button></InvestigationMutationGate>);
    expect(html).toContain("Изменить");
    expect(canPerformInvestigationMutation("viewer", action)).toBe(true);
  });

  it.each(["operator", "admin"] as const)("renders every mutation action for %s", (role) => {
    for (const action of actions) {
      const html = renderToStaticMarkup(<InvestigationMutationGate role={role} action={action}><button type="button">Изменить</button></InvestigationMutationGate>);
      expect(html).toContain("Изменить");
      expect(canPerformInvestigationMutation(role, action)).toBe(true);
    }
  });

  it("fails closed for a missing or unknown role", () => {
    expect(canPerformInvestigationMutation(undefined, "create_case")).toBe(false);
    expect(canPerformInvestigationMutation("unexpected", "add_case_note")).toBe(false);
  });

  it("uses the server effective role when local auth is disabled", () => {
    expect(bootstrapEffectiveRole({
      api_version: "v1", principal: null,
      effective_role: "operator", navigation: [], api_time_contract: "UTC",
    })).toBe("operator");
    expect(canPerformInvestigationMutation("operator", "create_case")).toBe(true);
  });

  it.each(["viewer", "operator", "admin"] as const)("preserves authenticated %s role", (role) => {
    expect(bootstrapEffectiveRole({
      api_version: "v1", principal: { username: "user", role },
      effective_role: role, navigation: [], api_time_contract: "UTC",
    })).toBe(role);
  });
});
