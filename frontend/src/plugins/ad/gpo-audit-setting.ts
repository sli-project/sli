import { t, type MessageKey } from "../../i18n";
import { en } from "../../i18n/en";

const subcategories = {
  "9210": "security_state_change",
  "9211": "security_system_extension",
  "9212": "system_integrity",
  "9215": "logon",
  "9216": "logoff",
  "9217": "account_lockout",
  "921b": "special_logon",
  "921c": "other_logon",
  "9224": "file_share",
  "9227": "other_object_access",
  "922b": "process_creation",
  "922c": "process_termination",
  "922f": "audit_policy_change",
  "9230": "authentication_policy_change",
  "9231": "authorization_policy_change",
  "9232": "firewall_policy_change",
  "9234": "other_policy_change",
  "9235": "user_account_management",
  "9236": "computer_account_management",
  "9237": "security_group_management",
  "923a": "other_account_management",
  "923b": "directory_service_access",
  "923c": "directory_service_changes",
  "923d": "directory_service_replication",
  "923f": "credential_validation",
  "9240": "kerberos_service_ticket_operations",
  "9242": "kerberos_authentication_service",
  "9245": "removable_storage",
  "9248": "pnp_activity",
  "9213": "ipsec_driver",
  "9214": "other_system_events",
  "9218": "ipsec_main_mode",
  "9219": "ipsec_quick_mode",
  "921a": "ipsec_extended_mode",
  "921d": "file_system",
  "921e": "registry",
  "921f": "kernel_object",
  "9220": "sam",
  "9221": "certification_services",
  "9222": "application_generated",
  "9223": "handle_manipulation",
  "9225": "filtering_platform_packet_drop",
  "9226": "filtering_platform_connection",
  "9228": "sensitive_privilege_use",
  "9229": "non_sensitive_privilege_use",
  "922a": "other_privilege_use",
  "922d": "dpapi_activity",
  "922e": "rpc_events",
  "9233": "filtering_platform_policy_change",
  "9238": "distribution_group_management",
  "9239": "application_group_management",
  "923e": "detailed_directory_service_replication",
  "9241": "other_account_logon_events",
  "9243": "network_policy_server",
  "9244": "detailed_file_share",
  "9246": "central_policy_staging",
  "9247": "user_device_claims",
  "9249": "group_membership",
  "924a": "token_right_adjusted",
  "924b": "access_rights",
} as const satisfies Record<string, string>;

type AuditLeaf = "subcategoryguid" | "subcategoryname" | "settingvalue" | "auditsetting" | "policytarget";
const namedSubcategories = new Map(Object.values(subcategories).map((name) => [en[`agents.auditSubcategory.${name}`].toLowerCase(), name]));

export function auditLeaf(name?: string, path?: string, category?: string, extension?: string): AuditLeaf | undefined {
  const leaf = name?.toLowerCase();
  if (leaf === "subcategoryguid" || leaf === "subcategoryname" || leaf === "auditsetting" || leaf === "policytarget") return leaf;
  if (leaf === "settingvalue" && [path, category, extension].some((part) => /audit/i.test(part ?? ""))) return leaf;
  return undefined;
}

export function auditSubcategory(value?: string): string {
  const guid = value?.trim().replace(/^\{|\}$/g, "").toLowerCase();
  const id = guid?.match(/^0cce([0-9a-f]{4})-69ae-11d9-bed3-505054503030$/)?.[1];
  const name = id && Object.hasOwn(subcategories, id) ? subcategories[id as keyof typeof subcategories]
    : namedSubcategories.get(guid?.replace(/^audit /, "") ?? "");
  return name === "logon" ? t("reports.gpo.audit.logon") : name ? t(`agents.auditSubcategory.${name}`) : t("reports.gpo.audit.unknown_subcategory");
}

export function auditMode(value?: string): string {
  const mode = value?.trim().toLowerCase();
  if (!mode) return t("reports.gpo.setting_unavailable");
  const modes: Record<string, MessageKey> = {
    "0": "reports.gpo.audit.none", "no auditing": "reports.gpo.audit.none", none: "reports.gpo.audit.none",
    "1": "reports.gpo.audit.success", success: "reports.gpo.audit.success",
    "2": "reports.gpo.audit.failure", failure: "reports.gpo.audit.failure",
    "3": "reports.gpo.audit.both", "success and failure": "reports.gpo.audit.both",
    "success, failure": "reports.gpo.audit.both", successandfailure: "reports.gpo.audit.both",
    "4": "reports.gpo.audit.none",
  };
  return t(Object.hasOwn(modes, mode) ? modes[mode] : "reports.gpo.audit.unknown_mode");
}

export function auditLeafValue(leaf: AuditLeaf | undefined, value: unknown, side?: "computer" | "user") {
  if (!leaf || typeof value !== "string") return value;
  if (leaf === "subcategoryguid" || leaf === "subcategoryname") return auditSubcategory(value);
  if (leaf === "policytarget") return side ? auditPath(side) : t("reports.gpo.audit.category");
  return auditMode(value);
}

export function auditLeafLabel(leaf: AuditLeaf, value?: string) {
  if (leaf === "subcategoryguid" || leaf === "subcategoryname") return auditSubcategory(value);
  return t(leaf === "policytarget" ? "reports.gpo.path" : "reports.gpo.audit.mode");
}

export function auditPath(side: "computer" | "user"): string {
  return t("reports.gpo.audit.path", { side: t(side === "computer" ? "reports.gpo.audit.computer_configuration" : "reports.gpo.audit.user_configuration") });
}
