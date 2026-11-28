import type { SettingsSchema } from "../../api/plugin-settings-types";

export const workstationLogonPolicyKey = "workstations.logon_policy";

export function workstationLogonPolicy(value: unknown) {
  if (!value || typeof value !== "object") return null;
  const policy = value as { version: number; enabled?: boolean; policies: unknown[] };
  return Number.isInteger(policy.version) && Array.isArray(policy.policies) ? policy : null;
}

export const schemaTypes = (node: SettingsSchema) => Array.isArray(node.type) ? node.type : [node.type];

/** Validate recursively before any PUT; the server remains authoritative. */
export function validSetting(value: unknown, node: SettingsSchema): boolean {
  const types = schemaTypes(node);
  const kind = value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
  if (!types.includes(kind) && !(kind === "number" && types.includes("integer") && Number.isSafeInteger(value))) return false;
  if (node.enum && !node.enum.some((entry) => JSON.stringify(entry) === JSON.stringify(value))) return false;
  if (node.oneOf && node.oneOf.filter((branch) => validSetting(value, branch)).length !== 1) return false;
  if (typeof value === "number" && (!Number.isFinite(value) || (node.minimum !== undefined && value < node.minimum) || (node.maximum !== undefined && value > node.maximum))) return false;
  if (typeof value === "string") {
    const length = Array.from(value).length;
    if ((node.minLength !== undefined && length < node.minLength) || (node.maxLength !== undefined && length > node.maxLength)) return false;
    try { if (node.pattern && !new RegExp(node.pattern, "u").test(value)) return false; } catch { return false; }
  }
  if (Array.isArray(value)) {
    if ((node.minItems !== undefined && value.length < node.minItems) || (node.maxItems !== undefined && value.length > node.maxItems)) return false;
    if (node.uniqueItems && new Set(value.map((entry) => JSON.stringify(entry))).size !== value.length) return false;
    if (node.items && !value.every((entry) => validSetting(entry, node.items!))) return false;
  } else if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    if (node.required?.some((key) => !Object.hasOwn(record, key))) return false;
    if (node.additionalProperties === false && Object.keys(record).some((key) => !Object.hasOwn(node.properties ?? {}, key))) return false;
    if (Object.entries(node.properties ?? {}).some(([key, child]) => Object.hasOwn(record, key) && !validSetting(record[key], child))) return false;
  }
  return true;
}

export function initialSetting(node: SettingsSchema): unknown {
  if (node.default !== undefined) return node.default;
  if (node.enum) return node.enum[0];
  if (node.oneOf) return initialSetting(node.oneOf[0]);
  const types = schemaTypes(node);
  if (types.includes("object")) return Object.fromEntries(Object.entries(node.properties ?? {})
    .filter(([key]) => node.required?.includes(key)).map(([key, child]) => [key, initialSetting(child)]));
  if (types.includes("array")) return [];
  if (types.includes("boolean")) return false;
  if (types.includes("integer") || types.includes("number")) return node.minimum ?? 0;
  return "";
}
