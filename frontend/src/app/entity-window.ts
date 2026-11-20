/** Period handling and per-type tab availability of the entity card. */

export type EntityWindow = { from: string; to: string };

/** The VPN reader refuses wider windows (server MAX_PERIOD_DAYS), so the card never asks for more. */
export const ENTITY_WINDOW_MAX_DAYS = 31;
const DEFAULT_WINDOW_DAYS = 30;
const DAY_MS = 86_400_000;

const isoDay = (date: Date) => date.toISOString().slice(0, 10);

function shiftDay(day: string, days: number): string {
  const date = new Date(`${day}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + days);
  return isoDay(date);
}

/**
 * Security actions and VPN sessions are read only for an explicit period. When the
 * card is opened without one, it shows the 30 UTC days that end at the entity's
 * last observation (or today when it was never observed) instead of asking for a
 * period the page offers no way to choose.
 */
export function defaultEntityWindow(lastSeenUtc: string | null | undefined, now = new Date()): EntityWindow {
  const seen = lastSeenUtc ? new Date(lastSeenUtc) : null;
  const to = isoDay(seen && !Number.isNaN(seen.getTime()) ? seen : now);
  return { from: shiftDay(to, -(DEFAULT_WINDOW_DAYS - 1)), to };
}

/** "Last N days" counted back from today (UTC calendar days, inclusive). */
export function recentEntityWindow(days: number, now = new Date()): EntityWindow {
  const to = isoDay(now);
  return { from: shiftDay(to, -(days - 1)), to };
}

/** Inclusive number of calendar days; null for a malformed or reversed window. */
export function entityWindowDays(window: EntityWindow): number | null {
  const from = Date.parse(`${window.from}T00:00:00Z`);
  const to = Date.parse(`${window.to}T00:00:00Z`);
  if (Number.isNaN(from) || Number.isNaN(to) || from > to) return null;
  return Math.round((to - from) / DAY_MS) + 1;
}

/** Date part of an API time bound (date, local or absolute form), or "" when it is not a date. */
export function entityBoundDay(value: string | null | undefined): string {
  const match = /^(\d{4}-\d{2}-\d{2})/.exec(value ?? "");
  return match ? match[1] : "";
}

/** Tabs that can never hold data for an entity type are not offered for it. */
const NO_MEMBERSHIP_TYPES = new Set(["gpo", "domain", "domain_trust", "password_policy", "replication_link"]);
const NO_VPN_TYPES = new Set(["ad_group", "ad_computer", "gpo", "domain", "domain_trust", "domain_controller", "password_policy", "replication_link"]);

export function entityTypeLacksTab(entityType: string | null | undefined, tab: string): boolean {
  const type = (entityType ?? "").toLowerCase();
  if (tab === "groups" || tab === "privileges") return NO_MEMBERSHIP_TYPES.has(type);
  if (tab === "vpn") return NO_VPN_TYPES.has(type);
  return false;
}
