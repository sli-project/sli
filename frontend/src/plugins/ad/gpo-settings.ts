import { getLocale, t, type MessageKey } from "../../i18n";
import { auditMode, auditPath, auditSubcategory } from "./gpo-audit-setting";

export type Setting = { id: string; side: "computer" | "user"; setting_name?: string; category?: string;
  extension?: string; path?: string; value_display?: string };

type DisplayFormat = "flag" | "inverted" | "seconds" | "minute" | "day" | "characters" | "attempts" | "passwords";
type KnownSetting = [MessageKey, DisplayFormat, MessageKey?];

const registryPolicies: Record<string, KnownSetting> = {
  "system\\currentcontrolset\\control\\lsa\\nolmhash": ["reports.gpo.registry.no_lm_hash", "flag"],
  "system\\currentcontrolset\\control\\lsa\\scenoapplylegacyauditpolicy": ["reports.gpo.registry.use_audit_subcategories", "flag"],
  "software\\microsoft\\windows\\currentversion\\policies\\system\\inactivitytimeoutsecs": ["reports.gpo.registry.inactivity_timeout", "seconds", "reports.gpo.registry.inactivity_timeout_description"],
  "software\\policies\\microsoft\\windowsfirewall\\domainprofile\\enablefirewall": ["reports.gpo.registry.domain_firewall", "flag"],
  "software\\policies\\microsoft\\windows nt\\terminal services\\fdenytsconnections": ["reports.gpo.registry.remote_desktop", "inverted"],
  "software\\policies\\microsoft\\windows\\personalization\\nolockscreencamera": ["reports.gpo.registry.lock_screen_camera", "flag"],
  "software\\policies\\microsoft\\windows\\windowsupdate\\au\\noautorebootwithloggedonusers": ["reports.gpo.registry.suppress_restart", "flag"],
  "software\\policies\\microsoft\\windows\\powershell\\scriptblocklogging\\enablescriptblocklogging": ["reports.gpo.registry.script_block_logging", "flag", "reports.gpo.registry.script_block_logging_description"],
};

const accountPolicies: Record<string, KnownSetting> = {
  MinimumPasswordLength: ["reports.gpo.account.minimum_password_length", "characters"],
  MinimumPasswordAge: ["reports.gpo.account.minimum_password_age", "day"],
  MaximumPasswordAge: ["reports.gpo.account.maximum_password_age", "day"],
  PasswordHistorySize: ["reports.gpo.account.password_history", "passwords"],
  PasswordComplexity: ["reports.gpo.account.password_complexity", "flag"],
  LockoutBadCount: ["reports.gpo.account.account_lockout_threshold", "attempts"],
  LockoutDuration: ["reports.gpo.account.account_lockout_duration", "minute"],
  ResetLockoutCount: ["reports.gpo.account.reset_lockout_counter", "minute"],
};

const userRights: Record<string, MessageKey> = {
  SeServiceLogonRight: "reports.gpo.right.service_logon",
  SeDenyServiceLogonRight: "reports.gpo.right.deny_service_logon",
  SeInteractiveLogonRight: "reports.gpo.right.local_logon",
  SeDenyInteractiveLogonRight: "reports.gpo.right.deny_local_logon",
  SeRemoteInteractiveLogonRight: "reports.gpo.right.remote_logon",
  SeDenyRemoteInteractiveLogonRight: "reports.gpo.right.deny_remote_logon",
  SeNetworkLogonRight: "reports.gpo.right.network_logon",
  SeDenyNetworkLogonRight: "reports.gpo.right.deny_network_logon",
  SeBatchLogonRight: "reports.gpo.right.batch_logon",
  SeDenyBatchLogonRight: "reports.gpo.right.deny_batch_logon",
  SeBackupPrivilege: "reports.gpo.right.backup",
  SeRestorePrivilege: "reports.gpo.right.restore",
  SeDebugPrivilege: "reports.gpo.right.debug",
  Members: "reports.gpo.right.members",
};

export const maskedValue = "значение скрыто";
export const gpoSettingLabel = (value?: string) => value?.replace(/([a-z\d])([A-Z])/g, "$1 $2");
export const gpoSettingMetadata = (name?: string) => ["blocked", "admsetting", "extension"].includes(name?.toLowerCase() ?? "");

function formatValue(value?: string, format?: DisplayFormat): string | undefined {
  if (value === maskedValue) return t("reports.gpo.value_hidden");
  if (!value) return undefined;
  const flag = value.toLowerCase();
  if ((format === "flag" || format === "inverted") && /^(true|false|0|1)$/.test(flag)) {
    const enabled = (flag === "true" || flag === "1") !== (format === "inverted");
    return t(enabled ? "reports.gpo.configured_enabled" : "reports.gpo.configured_disabled");
  }
  if (!format || format === "flag" || format === "inverted" || !/^\d+$/.test(value)) return value;
  const quantity = Number(value);
  if (!Number.isSafeInteger(quantity)) return value;
  const units = (value: number, unit: "day" | "minute" | "second") =>
    new Intl.NumberFormat(getLocale(), { style: "unit", unit, unitDisplay: "short" }).format(value);
  if (format === "seconds") {
    const minutes = Math.floor(quantity / 60);
    const seconds = quantity % 60;
    return minutes ? [units(minutes, "minute"), ...(seconds ? [units(seconds, "second")] : [])].join(" ") : units(seconds, "second");
  }
  if (format === "day" || format === "minute") return units(quantity, format);
  const form = new Intl.PluralRules(getLocale()).select(quantity);
  return t(`reports.gpo.unit.${format}.${form === "one" || form === "few" ? form : "other"}`, { value });
}

export function displaySetting(row: Setting) {
  const name = row.setting_name === maskedValue ? undefined : row.setting_name;
  let path = row.path === maskedValue ? undefined : row.path;
  const masked = row.value_display === maskedValue;
  if (row.category === "AuditSetting") return {
    ...row, category: t("reports.gpo.audit.category"), path: auditPath(row.side),
    setting_name: auditSubcategory(name), value_display: masked ? formatValue(row.value_display) : auditMode(row.value_display) ?? row.value_display,
    masked, description: undefined,
  };

  let category = gpoSettingLabel(row.category) || t("reports.gpo.settings");
  let settingName = gpoSettingLabel(name);
  let known: KnownSetting | undefined;
  if (row.category === "Registry") {
    const key = path?.toLowerCase().replace(/^(?:hklm|hkey_local_machine|hkcu|hkey_current_user)\\/, "");
    known = key && Object.hasOwn(registryPolicies, key) ? registryPolicies[key] : undefined;
    category = t("reports.gpo.registry");
    settingName = name || path?.split("\\").at(-1) || t("reports.gpo.registry_setting");
  } else if (row.category === "Account Policy") {
    known = name && Object.hasOwn(accountPolicies, name) ? accountPolicies[name] : undefined;
    category = t("reports.gpo.account_policy");
  } else if (row.category === "User Rights Assignment") {
    category = t("reports.gpo.user_rights");
    settingName = name && Object.hasOwn(userRights, name) ? t(userRights[name]) : settingName;
    path = t("reports.gpo.right.path", {
      side: t(row.side === "computer" ? "reports.gpo.audit.computer_configuration" : "reports.gpo.audit.user_configuration"),
    });
  } else if (!name || /^(name|value|boolean|string|number|sid)$/i.test(name)) {
    settingName = path?.split("/").filter(Boolean).map(gpoSettingLabel).join(" / ") || category;
  }
  const format = known?.[1] ?? (name?.toLowerCase() === "boolean" ? "flag" : undefined);
  return { ...row, category, setting_name: known ? t(known[0]) : settingName || category, path,
    value_display: formatValue(row.value_display, format), masked, description: known?.[2] ? t(known[2]) : undefined };
}

export const displaySettings = (settings: Setting[]) => settings.map(displaySetting);
