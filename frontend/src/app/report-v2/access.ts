import { ApiResponseError } from "../../api/client";
import type { ReportAccessDto } from "../../api/report-v2-types";
import { t } from "../../i18n";

export function categoryNames(categories: string[] = []): string {
  const labels: Record<string, string> = {
    identity_basic: t("reports.access.category_identity"), technical: t("reports.access.category_technical"),
    security: t("reports.access.category_security"), privilege: t("reports.access.category_privilege"),
    hr: t("reports.access.category_hr"), contact: t("reports.access.category_contact"),
  };
  return [...new Set(categories.map((key) => labels[key] ?? t("reports.access.category_other")))].join(", ");
}

/** Render known reason codes, never arbitrary server messages or grant data. */
export function accessReason(access?: ReportAccessDto): string {
  if (access?.reason === "report_field_categories_not_allowed") {
    return access.hidden_categories?.length
      ? t("reports.access.denied_categories", { categories: categoryNames(access.hidden_categories) })
      : t("reports.access.denied_fields");
  }
  if (access?.reason === "report_scope_not_executable") return t("reports.access.denied_scope");
  return t("reports.access.denied_part");
}

export function accessErrorReason(error: ApiResponseError): string {
  const access = error.payload?.access as ReportAccessDto | undefined;
  return accessReason({ ...access, allowed: false, reason: error.code });
}
