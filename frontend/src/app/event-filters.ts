export type EventViewTab = "attention" | "authentication" | "accounts" | "tasks" | "all";

export function normalizeCalendarBound(previous: string, next: string, boundary: "start" | "end") {
  const nextDate = next.slice(0, 10);
  if (!nextDate || nextDate === previous.slice(0, 10)) return next;
  return `${nextDate}T${boundary === "start" ? "00:00" : "23:59:59"}`;
}
