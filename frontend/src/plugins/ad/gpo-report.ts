import type { ReportDefinitionDto } from "../../api/report-v2-types";
import { t, type MessageKey } from "../../i18n";

/** Beta list presentation; keep the server's field paths and access rules. */
export function gpoReportDefinition(definition: ReportDefinitionDto): ReportDefinitionDto {
  const visibleColumns = ["name", "status", "reasons", "links", "modified", "owner"];
  const tabs = ["gpos", "changes", "linked_scopes"];
  return { ...definition,
    params: [...definition.params.map((param) => param.key === "view" ? { ...param, default: "all", hidden: true } : param),
      ...(!definition.params.some((param) => param.kind === "domain")
        ? [{ key: "domain", label: "", kind: "domain" as const, hidden: true }] : [])],
    columns: [...visibleColumns.flatMap((key) => definition.columns.filter((column) => column.key === key)),
      ...definition.columns.filter((column) => !visibleColumns.includes(column.key))].map((column) => ({ ...column,
        label: visibleColumns.includes(column.key) ? t(`reports.v2.ad.gpo.v2.columns.${column.key}.label` as MessageKey) : column.label,
        hidden_by_default: !visibleColumns.includes(column.key),
      })),
    views: tabs.flatMap((key) => definition.views.filter((view) => view.key === key)).map((view) => ({ ...view,
      title: t(`reports.v2.ad.gpo.v2.views.${view.key}.title` as MessageKey), note: undefined,
      columns: view.columns?.map((column, index) => ({
        ...column,
        hidden_by_default: column.hidden_by_default || index >= 7,
        labels: view.key === "linked_scopes" && column.key === "outcome" ? { ...column.labels, unknown: t("reports.v2.ad.gpo.v2.views.linked_scopes.columns.outcome.labels.unknown") }
          : view.key === "linked_scopes" && column.key === "wmi_state" ? { ...column.labels, partial: t("reports.v2.ad.gpo.v2.views.linked_scopes.columns.wmi_state.labels.partial") } : column.labels,
      })),
    })),
    presets: ["all", "attention", "unlinked"].map((view) => ({
      label: t(`reports.v2.ad.gpo.v2.params.view.options.${view}` as MessageKey), params: { view },
    })),
    row_links: definition.row_links.filter((link) => !new URL(link.href, "http://localhost").searchParams.has("tab")
      || tabs.includes(new URL(link.href, "http://localhost").searchParams.get("tab")!)),
  };
}
