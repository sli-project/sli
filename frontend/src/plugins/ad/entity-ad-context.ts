import type { EntityWorkspaceDetail } from "../../api/client";
import { t } from "../../i18n";

type AdContextItem = EntityWorkspaceDetail["ad_context"]["items"][number];

function text(value: unknown): string | null {
  const result = typeof value === "string" ? value.trim() : "";
  return result || null;
}

export function entityAdContextPresentation(item: AdContextItem): { title: string; summary: string; context: string } {
  const nested = item.attributes?.attributes ?? {};
  const context = item.current
    ? t("entities.adContext.currentContext")
    : t("entities.adContext.historicalContext");
  if (item.context_kind === "relation") {
    const related = text(item.related_display_name) ?? (item.related_entity_id ? t("entities.adContext.relatedEntityById", { id: String(item.related_entity_id) }) : t("entities.adContext.relatedEntityFallback"));
    const title = item.source_section === "vpn_membership"
      ? t("entities.adContext.vpnGroupTitle", { name: related })
      : t("entities.adContext.groupMembershipTitle", { name: related });
    const membership = text(item.attributes?.membership_type);
    return { title, summary: membership === "direct" ? t("entities.adContext.directMembership") : t("entities.adContext.observedMembership"), context };
  }
  const title = text(nested.display_name)
    ?? text(nested.sam_account_name)
    ?? text(nested.dns_host_name)
    ?? text(item.subject_display_name)
    ?? t("entities.adContext.objectObservation");
  const facts: string[] = [];
  if (nested.enabled === true) facts.push(t("entities.adContext.accountEnabled"));
  if (nested.enabled === false) facts.push(t("entities.adContext.accountDisabled"));
  if (nested.locked_out === true) facts.push(t("entities.adContext.lockedObserved"));
  if (nested.locked_out === false) facts.push(t("entities.adContext.lockedNotObserved"));
  return { title, summary: facts.join("; ") || t("entities.adContext.attributesSummary"), context };
}
