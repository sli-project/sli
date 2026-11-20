import { entityWorkspaceApiParameters } from "./investigation-context";
import { t } from "../i18n";

/** VPN Accounting is requested only for an explicit, complete entity window. */
export function entityVpnApiParameters(search: string, limit = 50): URLSearchParams | null {
  const parameters = entityWorkspaceApiParameters(search, limit);
  if (!parameters.has("time_from") || !parameters.has("time_to")) return null;
  return parameters;
}

export function entityVpnLifecycleLabel(value: string): string {
  if (value === "closed") return t("entities.vpn.lifecycle.closed");
  if (value === "open_observed") return t("entities.vpn.lifecycle.openObserved");
  if (value === "partial_open") return t("entities.vpn.lifecycle.partialOpen");
  if (value === "partial_closed") return t("entities.vpn.lifecycle.partialClosed");
  return t("entities.vpn.lifecycle.unknown");
}

export function entityVpnCompletenessLabel(value: string): string {
  return value === "complete" ? t("entities.vpn.completeness.complete") : t("entities.vpn.completeness.partial");
}
