import { describe, expect, it } from "vitest";
import { confidenceTone, operationalTone, riskTone } from "./Badges";

describe("semantic indicator tones", () => {
  it("never maps high or medium security risk to the low-risk family", () => {
    expect(riskTone("high")).toBe("high");
    expect(riskTone("medium")).toBe("medium");
    expect(riskTone("critical")).toBe("critical");
    expect(riskTone("low")).toBe("low");
  });

  it("keeps confidence independent from risk", () => {
    expect(confidenceTone("high")).toBe("high");
    expect(confidenceTone("medium")).toBe("medium");
    expect(confidenceTone("low")).toBe("low");
  });

  it("distinguishes a running service from a failed one", () => {
    expect(operationalTone("running")).toBe("running");
    expect(operationalTone("warning")).toBe("warning");
    expect(operationalTone("failed")).toBe("failed");
  });
});
