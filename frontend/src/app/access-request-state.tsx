import { createContext, useContext } from "react";
import { ApiResponseError } from "../api/client";
import { StateView } from "../design-system";
import { t } from "../i18n";

type AccessRequestState = { error: unknown; isFetching: boolean; retry: () => void };

// Keep transport failure and recovery separate from the effective grants.
export const AccessRequestContext = createContext<AccessRequestState | null>(null);
export const useAccessRequest = () => useContext(AccessRequestContext);

/** Render only while grants are missing or their latest refresh failed. */
export function AccessRequestStateView() {
  const request = useAccessRequest();
  if (!request?.error || request.isFetching) return <StateView state="loading"/>;
  const denied = request.error instanceof ApiResponseError && [401, 403].includes(request.error.status);
  return <StateView state={denied ? "denied" : "unavailable"}
    actions={denied ? <button type="button" className="sli-ds-button" onClick={request.retry}>{t("state.retry")}</button> : undefined}
    onRetry={request.retry}/>;
}
