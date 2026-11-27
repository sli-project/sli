import { t, type MessageKey } from "../../i18n";
import { auditMode, auditPath, auditSubcategory } from "./gpo-audit-setting";

export type Setting = { id: string; side: "computer" | "user"; setting_name?: string; category?: string;
  extension?: string; path?: string; value_display?: string; audit_mode?: string; registry_path?: string };

const registryPolicies: Record<string, [MessageKey, "flag" | "inverted" | "seconds"]> = {
  "system\\currentcontrolset\\control\\lsa\\nolmhash": ["reports.gpo.registry.no_lm_hash", "flag"],
  "system\\currentcontrolset\\control\\lsa\\scenoapplylegacyauditpolicy": ["reports.gpo.registry.use_audit_subcategories", "flag"],
  "software\\microsoft\\windows\\currentversion\\policies\\system\\inactivitytimeoutsecs": ["reports.gpo.registry.inactivity_timeout", "seconds"],
  "software\\policies\\microsoft\\windowsfirewall\\domainprofile\\enablefirewall": ["reports.gpo.registry.domain_firewall", "flag"],
  "software\\policies\\microsoft\\windows nt\\terminal services\\fdenytsconnections": ["reports.gpo.registry.remote_desktop", "inverted"],
  "software\\policies\\microsoft\\windows\\personalization\\nolockscreencamera": ["reports.gpo.registry.lock_screen_camera", "flag"],
  "software\\policies\\microsoft\\windows\\windowsupdate\\au\\noautorebootwithloggedonusers": ["reports.gpo.registry.suppress_restart", "flag"],
};

const accountPolicies: Record<string, MessageKey> = {
  MinimumPasswordLength: "reports.gpo.account.minimum_password_length", MinimumPasswordAge: "reports.gpo.account.minimum_password_age",
  MaximumPasswordAge: "reports.gpo.account.maximum_password_age", PasswordHistorySize: "reports.gpo.account.password_history",
  PasswordComplexity: "reports.gpo.account.password_complexity", LockoutBadCount: "reports.gpo.account.account_lockout_threshold",
  LockoutDuration: "reports.gpo.account.account_lockout_duration", ResetLockoutCount: "reports.gpo.account.reset_lockout_counter",
};

const leaf = (row: Setting) => row.setting_name?.toLowerCase();
const audit = (row: Setting) => ["subcategoryguid", "subcategoryname"].includes(leaf(row) ?? "")
  || /(?:^|\/)AuditSetting(?:\/|$)/i.test(row.path ?? "") || row.category === "AuditSetting";
const legacyRegistry = (row: Setting) => /(?:^|\/)RegistrySetting(?:\/|$)/i.test(row.path ?? "") || row.category === "RegistrySetting";
const registry = (row: Setting) => row.category === "Registry" || legacyRegistry(row);
export const gpoSettingLabel = (value?: string) => value?.replace(/([a-z\d])([A-Z])/g, "$1 $2");
export const gpoSettingMetadata = (name?: string) => ["blocked", "admsetting", "extension"].includes(name?.toLowerCase() ?? "");
const account = (row: Setting) => row.category === "Account Policy" || row.category === "Account" || /(?:^|\/)Account\//i.test(row.path ?? "");

function accountRow(row: Setting, name?: string, value?: string): Setting {
  const key = name && Object.hasOwn(accountPolicies, name) ? accountPolicies[name] : undefined;
  const boolean = value?.toLowerCase();
  return { ...row, category: t("reports.gpo.account_policy"), setting_name: key ? t(key) : gpoSettingLabel(name), path: undefined,
    value_display: boolean === "true" ? t("reports.gpo.configured_enabled") : boolean === "false" ? t("reports.gpo.configured_disabled") : value };
}

function registryRow(row: Setting, path: string, value: string | undefined, name?: string): Setting {
  const key = path.toLowerCase().replace(/^(?:hklm|hkey_local_machine|hkcu|hkey_current_user)\\/, "");
  const known = Object.hasOwn(registryPolicies, key) ? registryPolicies[key] : undefined;
  const [message, kind] = known ?? [];
  if (value != null && kind === "seconds" && /^\d+$/.test(value)) value = t("reports.gpo.seconds", { value });
  if ((kind === "flag" || kind === "inverted") && /^(0|1)$/.test(value ?? "")) {
    value = t((value === "1") !== (kind === "inverted") ? "reports.gpo.configured_enabled" : "reports.gpo.configured_disabled");
  }
  return { ...row, category: t("reports.gpo.registry"), setting_name: message ? t(message) : name || t("reports.gpo.registry_setting"),
    path, value_display: value, registry_path: message || name ? undefined : path };
}

export function displaySettings(settings: Setting[]): Setting[] {
  const result: Setting[] = [];
  for (const side of ["computer", "user"] as const) {
    const records = settings.filter((row) => row.side === side);
    const audits = records.filter(audit);
    const guids = audits.filter((row) => leaf(row) === "subcategoryguid");
    const names = audits.filter((row) => leaf(row) === "subcategoryname");
    const modes = audits.filter((row) => leaf(row) === "settingvalue");
    const named = new Set(guids.map((row) => auditSubcategory(row.value_display)));
    const subcategories = [...guids, ...names.filter((row) => !named.has(auditSubcategory(row.value_display)))];
    for (const row of subcategories) {
      const value = row.audit_mode ?? (subcategories.length === 1 && modes.length === 1 ? modes[0].value_display : undefined);
      result.push({ ...row, category: t("reports.gpo.audit.category"), path: auditPath(side),
        setting_name: auditSubcategory(row.value_display), value_display: value == null ? undefined : auditMode(value) });
    }

    const oldRegistry = records.filter(legacyRegistry);
    const keys = oldRegistry.filter((row) => leaf(row) === "keypath" || leaf(row) === "key");
    const valueNames = oldRegistry.filter((row) => leaf(row) === "valuename" || leaf(row) === "name" && /\/Value\/Name$/i.test(row.path ?? ""));
    const values = oldRegistry.filter((row) => ["value", "number", "string", "data"].includes(leaf(row) ?? ""));
    const policyNames = oldRegistry.filter((row) => leaf(row) === "name" && !/\/Value\/Name$/i.test(row.path ?? ""));
    for (const row of keys) {
      const single = keys.length === 1;
      const path = [row.value_display, single && valueNames.length === 1 ? valueNames[0].value_display : undefined].filter(Boolean).join("\\");
      result.push(registryRow(row, path, single && values.length === 1 ? values[0].value_display : undefined,
        single && policyNames.length === 1 ? policyNames[0].value_display : undefined));
    }
    const oldAccounts = records.filter((row) => account(row) && row.category !== "Account Policy");
    const accountNames = oldAccounts.filter((row) => leaf(row) === "name");
    const accountValues = oldAccounts.filter((row) => ["settingnumber", "settingboolean", "settingstring"].includes(leaf(row) ?? ""));
    for (const row of accountNames) {
      result.push(accountRow(row, row.value_display, accountNames.length === 1 && accountValues.length === 1 ? accountValues[0].value_display : undefined));
    }
    for (const row of records) {
      if (audit(row) || legacyRegistry(row) || gpoSettingMetadata(row.setting_name)) continue;
      if (account(row)) {
        if (row.category === "Account Policy") result.push(accountRow(row, row.setting_name, row.value_display));
        continue;
      }
      result.push(registry(row) ? registryRow(row, row.path ?? "", row.value_display, row.setting_name) : {
        ...row, setting_name: gpoSettingLabel(row.setting_name),
        category: gpoSettingMetadata(row.category) ? t("reports.gpo.settings") : gpoSettingLabel(row.category),
        path: row.path?.split("/").filter((part) => !gpoSettingMetadata(part)).map(gpoSettingLabel).join("/"),
      });
    }
  }
  return result;
}
