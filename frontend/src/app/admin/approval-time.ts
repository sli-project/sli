import { zonedParts } from "../../shared/date-time";

/** Resolve a minute-resolution approval edit only when it names one instant.
 * Gaps and folds are rejected; authorization deadlines must never guess an offset.
 * This is intentionally separate from the general report-period conversion helper.
 */
export function uniqueApprovalInstant(value: string, timeZone: string): string | null {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return null;
  const wall = new Date(`${value}:00Z`);
  if (!Number.isFinite(wall.getTime()) || wall.toISOString().slice(0, 16) !== value) return null;
  try {
    let match: string | null = null;
    // Search all minute offsets within a full day, including half/quarter-hour
    // zones. Require seconds=00 too, rather than guessing historical offsets.
    for (let offset = -24 * 60; offset <= 24 * 60; offset += 1) {
      const instant = new Date(wall.getTime() - offset * 60_000);
      const parts = zonedParts(instant, timeZone);
      if (`${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}` !== value || parts.second !== "00") continue;
      if (match !== null) return null;
      match = instant.toISOString();
    }
    return match;
  } catch { return null; }
}
