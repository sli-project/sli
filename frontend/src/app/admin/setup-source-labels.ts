import { t, type MessageKey } from "../../i18n";

const SOURCE_NAMES: Record<string, MessageKey> = {
  "sli.windows.ad-context": "setup.source.name.adContext",
  "sli.windows.ad-dc": "setup.source.name.domainController",
  "sli.windows.file-audit": "setup.source.name.fileAudit",
  "sli.windows.vpn-radius": "setup.source.name.vpnRadius",
  "sli.windows.workstations": "setup.source.name.workstations",
};

/** Only registered product names are translated; external source names are evidence. */
export function setupSourceName(pack: { pack_id: string; display_name: string }): string {
  return Object.hasOwn(SOURCE_NAMES, pack.pack_id) ? t(SOURCE_NAMES[pack.pack_id]) : pack.display_name;
}
