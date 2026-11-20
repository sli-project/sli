import { EMPTY_VALUE } from "../../shared/format";
import { t } from "../../i18n";

export type GroupMembershipRowView = { relation: string; groupName: string; membershipType: string; source: string; status: string; observedAt: string };
export type PrivilegePathRowView = { classification: string; groupName: string; path: string; targetObjectId: string; evidenceId: string; observedAt: string };

const text = (value: unknown, fallback = EMPTY_VALUE) => value === null || value === undefined || value === "" ? fallback : String(value);
const record = (value: unknown): Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {};

function membershipTypeLabel(value: unknown): string {
  const normalized = text(value, "unknown").toLocaleLowerCase("ru-RU");
  if (normalized === "direct") return t("entities.adRelations.membershipDirect");
  if (normalized === "nested" || normalized === "indirect") return t("entities.adRelations.membershipNested");
  return t("entities.adRelations.membershipUnknown");
}

/**
 * The AD-context contract carries only `member_of` relations; the section comes
 * as `source_section` (technical readers) or the derived `relation_class`.
 * A relation that explicitly names another kind is not a group membership.
 */
function isMembershipRelation(item: Record<string, unknown>): boolean {
  if (item.context_kind !== "relation") return false;
  const kind = record(item.attributes).relation_kind ?? item.relation_kind;
  return kind === undefined || kind === null || String(kind).toLocaleLowerCase("ru-RU") === "member_of";
}

function isPrivilegedRelation(item: Record<string, unknown>): boolean {
  return isMembershipRelation(item) && (item.relation_class === "privileged" || /privileged/i.test(text(item.source_section, "")));
}

function relationSourceLabel(item: Record<string, unknown>): string {
  if (isPrivilegedRelation(item)) return t("entities.adRelations.sourcePrivileged");
  if (item.relation_class === "vpn" || /vpn/i.test(text(item.source_section, ""))) return t("entities.adRelations.sourceVpn");
  return t("entities.adRelations.sourceAdContext");
}

function membershipTypeOf(item: Record<string, unknown>): unknown {
  const attributes = record(item.attributes);
  return attributes.membership_type ?? record(attributes.attributes).membership_type;
}

function groupNameOf(item: Record<string, unknown>): string {
  const name = typeof item.related_display_name === "string" ? item.related_display_name.trim() : "";
  if (name) return name;
  return item.related_entity_id ? t("entities.adRelations.groupById", { id: String(item.related_entity_id) }) : t("entities.adRelations.groupUnnamed");
}

/** Common name of a group from its distinguished name; the full DN is never shown. */
function groupNameFromDn(value: string): string {
  const match = /^CN=((?:\\.|[^,\\])+)/i.exec(value.trim());
  return (match ? match[1] : value).replace(/\\(.)/g, "$1").trim();
}

/** Direct `memberOf` values of the account's own AD attributes (exposed to readers allowed to see privilege fields). */
function memberOfAttributeRows(items: Array<Record<string, unknown>>, formatTime: (value: string) => string): GroupMembershipRowView[] {
  return items.filter((item) => item.context_kind === "entity").flatMap((item) => {
    const attributes = record(item.attributes);
    const raw = attributes.member_of ?? record(attributes.attributes).member_of;
    const values = (Array.isArray(raw) ? raw : raw ? [raw] : []).map((value) => groupNameFromDn(String(value))).filter(Boolean);
    return values.map((groupName) => ({
      relation: t("entities.adRelations.relationGroupMembership"),
      groupName,
      membershipType: t("entities.adRelations.membershipDirect"),
      source: t("entities.adRelations.sourceMemberOf"),
      status: item.current === false ? t("entities.adRelations.stateHistorical") : t("entities.adRelations.stateCurrent"),
      observedAt: item.observed_at_utc ? formatTime(String(item.observed_at_utc)) : EMPTY_VALUE,
    }));
  });
}

export function groupMembershipRowsView(items: Array<Record<string, unknown>>, formatTime: (value: string) => string): GroupMembershipRowView[] {
  const relationRows = items.filter(isMembershipRelation).map((item) => ({
    relation: t("entities.adRelations.relationGroupMembership"),
    groupName: groupNameOf(item),
    membershipType: membershipTypeLabel(membershipTypeOf(item)),
    source: relationSourceLabel(item),
    status: item.current === false ? t("entities.adRelations.stateHistorical") : t("entities.adRelations.stateCurrent"),
    observedAt: item.observed_at_utc ? formatTime(String(item.observed_at_utc)) : EMPTY_VALUE,
  }));
  const known = new Set(relationRows.map((row) => row.groupName.toLocaleLowerCase("ru-RU")));
  const attributeRows = memberOfAttributeRows(items, formatTime).filter((row) => !known.has(row.groupName.toLocaleLowerCase("ru-RU")));
  return [...relationRows, ...attributeRows];
}

export function privilegePathRowsView(items: Array<Record<string, unknown>>, formatTime: (value: string) => string): PrivilegePathRowView[] {
  return items.filter(isPrivilegedRelation).map((item) => {
    const groupName = groupNameOf(item);
    return {
      classification: t("entities.adRelations.classificationPrivileged"),
      groupName,
      path: t("entities.adRelations.pathFormat", { type: membershipTypeLabel(membershipTypeOf(item)), name: groupName }),
      targetObjectId: text(item.related_entity_id),
      evidenceId: text(item.context_evidence_id),
      observedAt: item.observed_at_utc ? formatTime(String(item.observed_at_utc)) : EMPTY_VALUE,
    };
  });
}
