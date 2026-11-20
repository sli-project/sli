import { t } from "../i18n";

export function vpnSessionLifecycleText(state: string | undefined): string {
  if (state === "closed") return t("vpn.session.state.closed");
  if (state === "open_observed") return t("vpn.session.state.openObserved");
  return t("vpn.session.state.incomplete");
}

export function vpnSessionDurationText(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || seconds < 0) return t("vpn.session.duration.unknown");
  if (seconds < 60) return t("vpn.session.duration.seconds", { seconds: Math.round(seconds) });
  if (seconds < 3600) return t("vpn.session.duration.minutes", { minutes: Math.round(seconds / 60) });
  return t("vpn.session.duration.hoursMinutes", { hours: Math.floor(seconds / 3600), minutes: Math.round((seconds % 3600) / 60) });
}
