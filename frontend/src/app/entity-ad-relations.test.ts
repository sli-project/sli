import { describe, expect, it } from "vitest";
import { groupMembershipRowsView, privilegePathRowsView } from "./entity-ad-relations";

const format = () => "19.07.2026 · 18:43";

describe("AD relations of an entity", () => {
  it("uses separate view models for group membership and privilege paths", () => {
    const context = [{
      context_kind: "relation",
      source_section: "privileged_membership",
      related_entity_id: 534478,
      related_display_name: "Admins",
      context_evidence_id: 21,
      current: true,
      observed_at_utc: "2026-07-19T18:43:23+07:00",
      attributes: { membership_type: "direct" },
    }];
    expect(groupMembershipRowsView(context, format)[0]).toEqual({
      relation: "Членство в группе", groupName: "Admins", membershipType: "Прямое",
      source: "Контекст AD · привилегированные группы", status: "Текущая", observedAt: "19.07.2026 · 18:43",
    });
    expect(privilegePathRowsView(context, format)[0]).toEqual({
      classification: "Привилегированное членство", groupName: "Admins", path: "Прямое членство → Admins",
      targetObjectId: "534478", evidenceId: "21", observedAt: "19.07.2026 · 18:43",
    });
  });

  it("lists relations exactly as the server sends them: flat attributes and no relation_kind", () => {
    const rows = groupMembershipRowsView([
      { context_kind: "relation", source_section: "vpn_membership", related_entity_id: 375, related_display_name: "VPN Users", current: true, attributes: { membership_type: "direct", record_key: "k" } },
      { context_kind: "entity", source_section: "directory_accounts", attributes: { display_name: "Demo" } },
    ], format);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ groupName: "VPN Users", source: "Контекст AD · VPN-группы", membershipType: "Прямое" });
  });

  it("classifies by relation_class when the technical section is hidden and marks historical rows", () => {
    const items = [
      { context_kind: "relation", relation_class: "privileged", related_entity_id: 9, current: false, attributes: {} },
      { context_kind: "relation", relation_class: "group", related_display_name: "Plain", current: true, attributes: {} },
    ];
    expect(privilegePathRowsView(items, format).map((row) => row.groupName)).toEqual(["Группа (объект 9)"]);
    expect(groupMembershipRowsView(items, format).map((row) => row.status)).toEqual(["Историческая", "Текущая"]);
  });

  it("ignores a relation that names another kind and adds memberOf values without duplicating relations", () => {
    const rows = groupMembershipRowsView([
      { context_kind: "relation", relation_kind: "manager_of", related_display_name: "Nope", attributes: {} },
      { context_kind: "relation", related_display_name: "Admins", attributes: {} },
      { context_kind: "entity", current: true, attributes: { member_of: ["CN=Admins,OU=Groups,DC=example,DC=test", "CN=Staff,OU=Groups,DC=example,DC=test"] } },
    ], format);
    expect(rows.map((row) => `${row.groupName}|${row.source}`)).toEqual(["Admins|Контекст AD", "Staff|Атрибут memberOf учётной записи"]);
  });
});
