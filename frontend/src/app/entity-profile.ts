import { t } from "../i18n";

type Field = { value: unknown; observation: Record<string, unknown>; observedAt: string };
type ProfileField = Field & { key: string; label: string; note?: string };

/** Select a short profile explicitly; aliases and duplicate contacts stay out of it. */
export function shortEntityProfile(type: string, fields: Map<string, Field>, name: string) {
  const selected: ProfileField[] = [];
  const used = new Set<string>();
  const add = (key: string, aliases: string[] = [key], fallback?: unknown) => {
    const source = aliases.find((alias) => fields.has(alias) && fields.get(alias)!.value != null && fields.get(alias)!.value !== "");
    if (source) {
      used.add(source);
      for (const alias of aliases) {
        if (fields.get(alias)?.value === fields.get(source)!.value) used.add(alias);
      }
    }
    const field = source ? fields.get(source)! : { value: fallback, observation: {}, observedAt: "" };
    if (field.value === undefined) return;
    const entry: ProfileField = { ...field, key, label: t(`entities.profile.${key}` as Parameters<typeof t>[0]) };
    selected.push(entry);
    return entry;
  };
  add("display_name", ["display_name", "name"], name);
  if (["ad_user", "account", "user", "security_principal"].includes(type)) {
    add("sam_account_name", ["sam_account_name", "login", "user_principal_name"]);
    add("enabled");
    add("locked", ["locked_out", "locked"]);
    add("department");
    add("title");
    const successful = fields.get("exact_last_logon_successful_dc_count")?.value;
    const discovered = fields.get("exact_last_logon_discovered_dc_count")?.value;
    const hasCoverage = typeof successful === "number" && Number.isInteger(successful) && successful >= 0
      && typeof discovered === "number" && Number.isInteger(discovered) && discovered > 0 && successful <= discovered;
    const partial = fields.get("exact_last_logon_status")?.value === "partial" || (hasCoverage && successful < discovered);
    let logonAliases = ["exact_last_logon_utc", "last_logon_utc", "last_logon_timestamp_utc"];
    if (partial) {
      // Match the users report: a partial DC maximum must not hide a newer replicated timestamp.
      logonAliases = logonAliases.filter((alias) => typeof fields.get(alias)?.value === "string" && Number.isFinite(Date.parse(String(fields.get(alias)!.value))))
        .sort((left, right) => Date.parse(String(fields.get(right)!.value)) - Date.parse(String(fields.get(left)!.value)));
    }
    const logon = add("last_logon", logonAliases, partial ? null : undefined);
    if (logon && partial) logon.note = hasCoverage
      ? t("entities.profile.lastLogonDcCoverage", { successful, discovered })
      : t("entities.profile.lastLogonPartial");
    add("password_last_set", ["password_last_set_utc"]);
    add("groups_count", ["groups_count", "group_count", "member_of"], null);
  } else if (["ad_computer", "computer", "server"].includes(type)) {
    add("operating_system");
    add("enabled");
    add("last_logon", ["exact_last_logon_utc", "last_logon_utc", "last_logon_timestamp_utc", "last_activity_utc"]);
    const dn = fields.get("distinguished_name");
    const ou = typeof dn?.value === "string" ? /(?:^|,)(OU=.*)$/i.exec(dn.value)?.[1] : undefined;
    add("ou", ["ou", "ou_dn", "organizational_unit"], ou);
  } else if (["ad_group", "group"].includes(type)) {
    add("group_category", ["group_category", "group_type"]);
    add("group_scope");
    add("members_count", ["members_count", "member_count", "members"], null);
  }
  const technical: ProfileField[] = [];
  for (const [key, field] of fields) {
    if (used.has(key)) continue;
    // AD can return both mail and email for the same contact.
    if (key === "email" && fields.get("mail")?.value === field.value) continue;
    technical.push({ ...field, key, label: key });
  }
  return { selected, technical };
}

export function entityProfileValue(key: string, value: unknown, format: (value: string) => string): string {
  if (value === null || value === undefined || value === "") return t("table.noValue");
  if (key === "enabled" && typeof value === "boolean") return t(value ? "entities.profile.stateEnabled" : "entities.profile.stateDisabled");
  if (typeof value === "boolean") return t(value ? "entities.profile.yes" : "entities.profile.no");
  if (key === "last_logon" || key === "password_last_set" || key.endsWith("_utc")) return format(String(value));
  if ((key === "groups_count" || key === "members_count") && Array.isArray(value)) return String(new Set(value.map((item) => JSON.stringify(item))).size);
  if (key === "ou" && typeof value === "string") {
    const units = [...value.matchAll(/(?:^|,)\s*OU=((?:\\.|[^,\\])+)/gi)].map((match) => match[1].replace(/\\(.)/g, "$1"));
    if (units.length) return units.reverse().join(" / ");
  }
  const groupLabels = {
    security: "entities.profile.groupSecurity", distribution: "entities.profile.groupDistribution",
    global: "entities.profile.scopeGlobal", universal: "entities.profile.scopeUniversal", domainlocal: "entities.profile.scopeDomainLocal",
  } as const;
  if (key === "group_category" || key === "group_scope") {
    const normalized = String(value).toLowerCase().replaceAll("_", "");
    if (Object.hasOwn(groupLabels, normalized)) return t(groupLabels[normalized as keyof typeof groupLabels]);
  }
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}
