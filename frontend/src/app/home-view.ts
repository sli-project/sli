import { t, plural } from "../i18n";

export function homeOccurrences(count: number): string {
  return plural(count, {
    one: t("home.queue.occurrences.one", { count }),
    few: t("home.queue.occurrences.few", { count }),
    many: t("home.queue.occurrences.many", { count }),
    other: t("home.queue.occurrences.other", { count }),
  });
}
