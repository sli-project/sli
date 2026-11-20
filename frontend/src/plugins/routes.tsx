import { useCallback } from "react";
import { useNavigate } from "@tanstack/react-router";
import { StateView } from "../design-system/StateView";
import { useAccessStatus, useEffectiveAccess } from "../app/App";
import { ReportRenderer } from "../app/report-v2/ReportRenderer";
import { PluginHost } from "./PluginHost";
import { AD_PLUGIN_ID, adReportPage, adReportPageForRoute } from "./ad/AdPages";

export const VPN_PLUGIN_ID = "sli.remote-access";
export const VPN_PLUGIN_ROUTE = `/extensions/${VPN_PLUGIN_ID}/accounts`;

// The pilot gets one approved component, not the renderer or arbitrary report
// keys. Report authorization and report-specific UX stay in the shared renderer.
function VpnAccountsPage() { return <ReportRenderer reportKey="vpn.accounts"/>; }

export function InstalledPluginPage({ pluginId, route }: { pluginId: string; route: string }) {
  const access = useEffectiveAccess();
  const status = useAccessStatus();
  const navigate = useNavigate();
  const go = useCallback((href: string) => { void navigate({ href }); }, [navigate]);
  const AdPage = pluginId === AD_PLUGIN_ID ? adReportPageForRoute(route) : undefined;
  if (AdPage) return <AdPage/>;
  if (status === "отказ") return <StateView state="unavailable"/>;
  if (!access) return <StateView state="loading"/>;
  // Includes evaluation revision so refreshed grants/expiry revoke old caches
  // even if the coarse capabilities are unchanged. No identity text in keys.
  const sessionKey = JSON.stringify([access.subject.type, access.subject.id, access.evaluated_at_utc]);
  return <PluginHost pluginId={pluginId} route={route} sessionKey={sessionKey} capabilities={access.capabilities}
    navigate={go} Page={pluginId === VPN_PLUGIN_ID && route === VPN_PLUGIN_ROUTE ? VpnAccountsPage : undefined}/>;
}

export function PluginReportPage({ reportKey, pilotEnabled = import.meta.env.VITE_SLI_PLUGIN_UI_PILOT === "1" }: {
  reportKey: string; pilotEnabled?: boolean;
}) {
  const AdPage = adReportPage(reportKey);
  if (AdPage) return <AdPage/>;
  if (pilotEnabled && reportKey === "vpn.accounts") return <InstalledPluginPage pluginId={VPN_PLUGIN_ID} route={VPN_PLUGIN_ROUTE}/>;
  return <ReportRenderer reportKey={reportKey}/>;
}
