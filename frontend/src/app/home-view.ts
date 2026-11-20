import type { HomeDecisionGroup } from "../api/client";
import { EMPTY_VALUE } from "../shared/format";
import { t, plural } from "../i18n";
import { browserTimeZone, formatDate, formatDateTime } from "../shared/date-time";

export function homeTime(value: string | null | undefined, timeZone: string): string {
  if (!value || !Number.isFinite(Date.parse(value))) return EMPTY_VALUE;
  return formatDateTime(value, timeZone);
}

export function homeDay(value: string | null | undefined): string {
  if (!value || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return EMPTY_VALUE;
  // The server has already selected this calendar day in the report timezone.
  // UTC is only a stable formatting carrier, never a second zone conversion.
  const date = new Date(`${value}T00:00:00Z`);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 10) !== value) return EMPTY_VALUE;
  return formatDate(date, "UTC");
}

type HomeObject = HomeDecisionGroup["objects"][number];

function homeObjectName(object: HomeObject): string {
  // Unresolved names and raw identifiers have no display label on the home screen.
  switch (object.name_state) {
    case "no_match":
    case "ambiguous":
    case "unverified":
    case "unavailable": return EMPTY_VALUE;
    default: return /^(?:sid:[^:]+:)?S-1-\d+(?:-\d+)+$/i.test(object.name.trim()) ? EMPTY_VALUE : object.name || EMPTY_VALUE;
  }
}

export function homeObjects(group: HomeDecisionGroup): string {
  if (!group.objects.length) return t("home.queue.no_data");
  const visible = group.objects.slice(0, 3);
  const text = visible.map((object) => {
    const name = homeObjectName(object);
    return name !== EMPTY_VALUE && object.domain ? `${name} (${object.domain})` : name;
  }).join(", ");
  const remaining = group.object_count === null ? 0 : Math.max(0, group.object_count - visible.length);
  return remaining ? `${text} ${t("home.queue.more_objects", { count: remaining })}` : text;
}

export function homeParams(search: string, displayZone: string) {
  const source = new URLSearchParams(search);
  const params = new URLSearchParams();
  for (const key of ["scope", "domain", "domain_id", "period", "from", "to", "tz"]) {
    const value = source.get(key);
    if (value !== null) params.set(key, value);
  }
  if (params.has("domain") && !params.has("domain_id")) params.set("scope", "domain");
  if (!params.has("tz")) params.set("tz", displayZone === "browser" ? browserTimeZone() : displayZone);
  return params;
}


export function homeAssignee(group: HomeDecisionGroup): string {
  if (group.assignee_state === "unassigned") return t("security.problems.assignee.unassigned");
  if (group.assignee_state === "mixed") {
    return t("home.queue.assignee.mixed", { name: group.assigned_to || "", count: group.unassigned_count ?? 0 });
  }
  return group.assigned_to || t("home.queue.no_data");
}

export function homeOccurrences(count: number): string {
  return plural(count, {
    one: t("home.queue.occurrences.one", { count }),
    few: t("home.queue.occurrences.few", { count }),
    many: t("home.queue.occurrences.many", { count }),
    other: t("home.queue.occurrences.other", { count }),
  });
}

