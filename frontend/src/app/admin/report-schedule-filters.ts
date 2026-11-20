import type { NotificationScheduleInput } from "../../api/notification-types";
import type { ReportDefinitionDto, ReportParamDto } from "../../api/report-v2-types";

// Presentation subset of the existing schedule API. Enum values/labels come
// only from its authorized report declaration; the server remains authoritative.
const filterKeys = {
  "security.problems": ["severity", "status", "population"],
  "file-audit.mass-operations": ["operation", "source_kind"],
} satisfies Record<NotificationScheduleInput["report_key"], string[]>;

export function scheduleFilterParams(report: NotificationScheduleInput["report_key"], definition?: Pick<ReportDefinitionDto, "key" | "params">): ReportParamDto[] | null {
  if (!definition || definition.key !== report || !Array.isArray(definition.params)) return null;
  const params = definition.params.filter((param) => filterKeys[report].includes(param.key) && !param.hidden);
  if (new Set(params.map((param) => param.key)).size !== params.length || params.some((param) =>
    param.kind !== "choice" || typeof param.label !== "string" || !Array.isArray(param.options)
    || param.options.some((option) => typeof option.value !== "string" || typeof option.label !== "string"))) return null;
  return params;
}

export function scheduleFilterValues(params: ReportParamDto[], selected: Record<string, string>): Record<string, string> | null {
  const filters: Record<string, string> = {};
  for (const [key, value] of Object.entries(selected)) {
    if (value === "") continue;
    if (!params.some((param) => param.key === key && param.options?.some((option) => option.value === value))) return null;
    filters[key] = value;
  }
  return filters;
}
