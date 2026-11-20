import { t } from "../i18n";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { Button } from "../design-system";
import { VpnSessionEvidenceView } from "./vpn-evidence-view";

/*
  Exact RADIUS Accounting evidence for one VPN session. Loaded on demand
  and only when the server published an exact session identifier.
*/

const VPN_SESSION_ROW_ID = /^radius-session-row:[0-9a-f]{64}$/;

export type VpnSessionEvidenceRequest = {
  sourceDomainId: number;
  sessionRowId: string;
};

/** A proof request has no fallback to another session, person, or time window. */

export function vpnSessionEvidenceRequest(
  sourceDomainId: number,
  sessionRowId: string | null | undefined,
): VpnSessionEvidenceRequest | null {
  const exactSessionRowId = String(sessionRowId ?? "").trim();
  if (!Number.isSafeInteger(sourceDomainId) || sourceDomainId <= 0 || !VPN_SESSION_ROW_ID.test(exactSessionRowId)) return null;
  return { sourceDomainId, sessionRowId: exactSessionRowId };
}

type VpnSessionEvidencePresentationInput = {
  request: VpnSessionEvidenceRequest | null;
  requested: boolean;
  pending: boolean;
  failed: boolean;
  responseState: string | undefined;
};

export function vpnSessionEvidencePresentation({ request, requested, pending, failed, responseState }: VpnSessionEvidencePresentationInput): "missing_exact_id" | "not_requested" | "loading" | "not_authorized" | "error" | "available" {
  if (!request) return "missing_exact_id";
  if (!requested) return "not_requested";
  if (pending) return "loading";
  if (failed) return "error";
  if (responseState === "not_authorized") return "not_authorized";
  return responseState === "available" ? "available" : "error";
}

function VpnConnectionSessionEvidenceBody({ request, formatTime }: {
  request: VpnSessionEvidenceRequest;
  formatTime: (value?: string | null) => string;
}) {
  const query = useQuery({
    queryKey: ["vpn-connections", "session-evidence", request.sourceDomainId, request.sessionRowId],
    queryFn: () => api.vpnSessionEvidence(request.sourceDomainId, request.sessionRowId),
    retry: false,
  });
  const presentation = vpnSessionEvidencePresentation({
    request,
    requested: true,
    pending: query.isPending,
    failed: query.isError,
    responseState: query.data?.state,
  });

  if (presentation === "loading") return <p className="sli-ds-note">{t("vpn.evidence.req.loading")}</p>;
  if (presentation === "error") return <p className="sli-ds-note sli-ds-error" role="alert">{t("vpn.evidence.req.error")}</p>;
  if (!query.data) return null;
  return <VpnSessionEvidenceView evidence={query.data} formatTime={formatTime}/>;
}

export function VpnConnectionSessionEvidence({ sourceDomainId, sessionRowId, formatTime }: {
  sourceDomainId: number;
  sessionRowId: string;
  formatTime: (value?: string | null) => string;
}) {
  const request = vpnSessionEvidenceRequest(sourceDomainId, sessionRowId);
  const [requested, setRequested] = useState(false);
  if (!request) {
    return <p className="sli-ds-note">{t("vpn.evidence.req.noId")}</p>;
  }
  if (!requested) {
    return <Button icon="info" onClick={() => setRequested(true)}>{t("vpn.evidence.req.button")}</Button>;
  }
  return <VpnConnectionSessionEvidenceBody request={request} formatTime={formatTime}/>;
}
