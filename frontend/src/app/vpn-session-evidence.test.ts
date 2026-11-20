import { describe, expect, it } from "vitest";
import { vpnSessionEvidencePresentation, vpnSessionEvidenceRequest } from "./vpn-session-evidence";

describe("VPN session evidence", () => {
  it("запрашивает proof только для выбранной exact session и её source domain", () => {
    const sessionRowId = "radius-session-row:f0f2a2ebf55900c086ad22013daaddc5291749c07edc8be6b8d2769d05024b59";

    expect(vpnSessionEvidenceRequest(7, sessionRowId)).toEqual({ sourceDomainId: 7, sessionRowId });
    expect(vpnSessionEvidenceRequest(7, "")).toBeNull();
    expect(vpnSessionEvidenceRequest(0, sessionRowId)).toBeNull();
  });

  it("не подменяет отказ или ошибку old unavailable состоянием", () => {
    const request = vpnSessionEvidenceRequest(
      7,
      "radius-session-row:f0f2a2ebf55900c086ad22013daaddc5291749c07edc8be6b8d2769d05024b59",
    );
    expect(request).not.toBeNull();

    expect(vpnSessionEvidencePresentation({ request, requested: true, pending: false, failed: false, responseState: "not_authorized" })).toBe("not_authorized");
    expect(vpnSessionEvidencePresentation({ request, requested: true, pending: false, failed: true, responseState: undefined })).toBe("error");
    expect(vpnSessionEvidencePresentation({ request: null, requested: false, pending: false, failed: false, responseState: undefined })).toBe("missing_exact_id");
  });

});
