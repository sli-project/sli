/** Presentation boundary for Stage 8 I2. */
import { t } from "../i18n";

export type СостояниеОпознания = "exact" | "partial" | "unresolved" | "unknown";

export type ПредставлениеОпознания = {
  состояние: СостояниеОпознания;
  подпись: string;
  пояснение: string;
  тон: "good" | "warn" | "bad";
};

export function состояниеОпознания(
  factors: Record<string, unknown> | null | undefined,
): СостояниеОпознания {
  const raw = String(factors?.identity_resolution ?? "unknown").toLowerCase();
  return raw === "exact" || raw === "partial" || raw === "unresolved" ? raw : "unknown";
}

export function представлениеОпознания(
  factors: Record<string, unknown> | null | undefined,
): ПредставлениеОпознания {
  const состояние = состояниеОпознания(factors);
  if (состояние === "exact") return {
    состояние, подпись: t("entities.resolution.exact.label"),
    пояснение: t("entities.resolution.exact.detail"), тон: "good",
  };
  if (состояние === "partial") return {
    состояние, подпись: t("entities.resolution.partial.label"),
    пояснение: t("entities.resolution.partial.detail"), тон: "warn",
  };
  if (состояние === "unresolved") return {
    состояние, подпись: t("entities.resolution.unresolved.label"),
    пояснение: t("entities.resolution.unresolved.detail"), тон: "bad",
  };
  return {
    состояние, подпись: t("entities.resolution.unknown.label"),
    пояснение: t("entities.resolution.unknown.detail"), тон: "warn",
  };
}
