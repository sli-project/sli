import { formatNumber } from "../../shared/format";
import type { PlatformReadiness } from "../../api/client";
import { postgresOperationalState } from "../operations-actions";
import { plural, t } from "../../i18n";

export type ReadinessCheckView = {
  key: string;
  name: string;
  state: string;
  meaning: string;
  nextStep: string;
  href?: string;
  retry?: boolean;
};

export function operationsReadinessView(data: PlatformReadiness): ReadinessCheckView[] {
  const postgresState = postgresOperationalState(data.postgres);
  const count = data.postgres.warnings?.length ?? 0;
  const checks: ReadinessCheckView[] = [];
  if (data.archive && data.archive.status !== "ok") {
    const invalidRoot = data.archive.status === "invalid_root";
    checks.push({
      key: "archive", name: t("operations.readiness.archive.name"),
      state: t("operations.readiness.archive.unavailable"),
      meaning: t(invalidRoot ? "operations.readiness.archive.invalidRoot" : "operations.readiness.archive.checkFailed"),
      nextStep: t(invalidRoot ? "operations.readiness.archive.correctRoot" : "state.retry"),
      retry: !invalidRoot,
    });
  }
  if (postgresState !== "ready" || count > 0) {
    const params = { count: formatNumber(count) };
    const blocked = postgresState === "blocked";
    checks.push({
      key: "postgres", name: t("operations.readiness_view.check_postgres_name"),
      state: t(blocked ? "operations.readiness_view.status_error" : "operations.readiness_view.status_warn"),
      meaning: blocked ? t("operations.readiness_view.check_postgres_meaning_blocked")
        : count > 0 ? plural(count, {
          one: t("operations.readiness_view.warningCount.one", params),
          few: t("operations.readiness_view.warningCount.few", params),
          many: t("operations.readiness_view.warningCount.many", params),
          other: t("operations.readiness_view.warningCount.other", params),
        }) : t("operations.readiness.postgresMetrics"),
      nextStep: t(blocked ? "operations.readiness.postgresService" : "operations.readiness.postgresExport"),
      href: blocked ? undefined : "/app/admin/status",
    });
  }
  return checks;
}
