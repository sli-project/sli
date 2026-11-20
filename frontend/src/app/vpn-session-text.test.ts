import { describe, expect, it } from "vitest";
import { vpnSessionDurationText, vpnSessionLifecycleText } from "./vpn-session-text";

describe("VPN session text", () => {
  it("does not call an unclosed VPN session active", () => {
    expect(vpnSessionLifecycleText("closed")).toBe("Завершена");
    expect(vpnSessionLifecycleText("open_observed"))
      .toBe("Старт наблюдался; завершение не зафиксировано");
    expect(vpnSessionDurationText(3660)).toBe("1 ч 1 мин");
    expect(vpnSessionDurationText(null)).toBe("не определена");
  });
});
