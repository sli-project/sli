import { describe, expect, it } from "vitest";
import { entityAdContextPresentation } from "./entity-ad-context";

describe("entity AD context presentation", () => {
  it("names the exact related VPN group and labels it as current context", () => {
    expect(entityAdContextPresentation({
      context_evidence_id: 9,
      evidence_type: "relation_observation",
      source_pack_id: "sli.windows.ad-context",
      integrity_sha256: "a".repeat(64),
      context_kind: "relation",
      current: true,
      source_section: "vpn_membership",
      subject_entity_id: 42,
      subject_display_name: "evidence-reader",
      related_entity_id: 77,
      related_display_name: "VPNl2tp",
      attributes: { membership_type: "direct" },
      supplemental_context_only: true,
      changes_entity_state: false,
    })).toEqual({
      title: "VPN-группа VPNl2tp",
      summary: "Прямое членство",
      context: "Текущий контекст AD — не историческое состояние",
    });
  });

  it("uses a subject name from the observed attributes without exposing the record key", () => {
    expect(entityAdContextPresentation({
      context_evidence_id: 10,
      evidence_type: "entity_observation",
      source_pack_id: "sli.windows.ad-context",
      integrity_sha256: "b".repeat(64),
      context_kind: "entity",
      current: false,
      source_section: "directory_accounts",
      attributes: { attributes: { display_name: "Иван Суворов", enabled: true, locked_out: false } },
      supplemental_context_only: true,
      changes_entity_state: false,
    })).toEqual({
      title: "Иван Суворов",
      summary: "Учётная запись включена; блокировка не наблюдается",
      context: "Историческая версия наблюдения AD",
    });
  });
});
