import { ApiResponseError, type V4BuilderPreview, type V4Dataset, type V4ReportDefinition, type V4ReportDefinitionVersion } from "../../api/client";
import { t, type MessageKey } from "../../i18n";
import { ru } from "../../i18n/ru";
import { resolveMessage } from "../../i18n/messages";

/** Одна строка реестра: отчёт целиком, а не отдельная версия. */
export type StudioRow = {
  key: string;
  name: string;
  /** Версия, которую видит реестр: опубликованная, а при её отсутствии — самая новая. */
  version: number;
  date: string | null;
  status: string;
  datasetKey: string;
  datasetVersion: number;
  owner: string;
  purpose: string;
  sensitivity: string;
  discoverable: boolean;
  requestable: boolean;
  assignmentCount: number | null;
  packageCount: number | null;
  codeDefined: boolean;
  /** Номер черновика, который новее опубликованной версии. */
  pendingDraft: number | null;
  published: boolean;
};

export type StudioCapabilities = { design: boolean; publish: boolean; assign: boolean };

export const studioCapabilities = (capabilities: readonly string[]): StudioCapabilities => ({
  design: capabilities.includes("reports.design") || capabilities.includes("report.design"),
  publish: capabilities.includes("reports.publish") || capabilities.includes("report.publish"),
  assign: capabilities.includes("reports.assign"),
});

/** Сервер требует обе возможности для любого изменения версии, видимости и публикации. */
export const canMutate = (caps: StudioCapabilities) => caps.design && caps.publish;

export function buildRows(items: V4ReportDefinition[]): StudioRow[] {
  const groups = new Map<string, V4ReportDefinition[]>();
  for (const item of items) groups.set(item.report_key, [...(groups.get(item.report_key) ?? []), item]);
  const rows: StudioRow[] = [];
  for (const [key, versions] of groups) {
    const sorted = [...versions].sort((a, b) => b.version - a.version);
    const published = sorted.find((item) => item.status === "published");
    const shown = published ?? sorted[0];
    const draft = sorted.find((item) => item.status === "draft" && (!published || item.version > published.version));
    rows.push({
      key, name: resolveMessage(shown.presentation_messages?.name, shown.name), version: shown.version, date: shown.published_at ?? shown.created_at, status: shown.status, datasetKey: shown.dataset_key, datasetVersion: shown.dataset_version,
      owner: shown.owner_name, purpose: resolveMessage(shown.presentation_messages?.purpose, shown.purpose), sensitivity: shown.sensitivity,
      discoverable: Boolean(shown.discoverable), requestable: Boolean(shown.requestable),
      assignmentCount: shown.assignment_count ?? null, packageCount: shown.package_count ?? null,
      codeDefined: Boolean(shown.code_defined), pendingDraft: draft && draft !== shown ? draft.version : null,
      published: Boolean(published),
    });
  }
  return rows;
}

/** Вызывать после подстановки названий каталога: разные ключи могут обозначать один отчёт. */
export function partitionRows(rows: StudioRow[]): { current: StudioRow[]; archived: StudioRow[] } {
  const chosen = new Map<string, StudioRow>();
  const nameOf = (row: StudioRow) => row.name.trim().replace(/\s+/g, " ").toLowerCase();
  const timestamp = (row: StudioRow) => Date.parse(row.date ?? "") || 0;
  for (const row of rows) {
    if (row.status === "retired") continue;
    const name = nameOf(row);
    const previous = chosen.get(name);
    // Опубликованная версия предпочтительнее черновика; затем берём самую новую.
    const priority = previous ? Number(row.published) - Number(previous.published)
      || timestamp(row) - timestamp(previous) || row.version - previous.version
      || previous.key.localeCompare(row.key) : 1;
    if (priority > 0) chosen.set(name, row);
  }
  const current = rows.filter((row) => chosen.get(nameOf(row)) === row);
  const archived = rows.filter((row) => chosen.get(nameOf(row)) !== row);
  return { current, archived };
}

export type VisibilityKind = "hidden" | "catalog" | "requestable";
export const visibilityOf = (row: Pick<StudioRow, "discoverable" | "requestable">): VisibilityKind =>
  row.discoverable && row.requestable ? "requestable" : row.discoverable ? "catalog" : "hidden";

export const visibilityLabel = (kind: VisibilityKind) =>
  kind === "requestable" ? t("studio.visibility.requestable") : kind === "catalog" ? t("studio.visibility.catalog") : t("studio.visibility.hidden");

export const statusLabel = (status: string) =>
  status === "published" ? t("studio.status.published") : status === "draft" ? t("studio.status.draft") : status === "retired" ? t("studio.status.retired") : status;

export const statusTone = (status: string) => (status === "published" ? "success" : status === "draft" ? "warning" : "neutral") as "success" | "warning" | "neutral";

/** Сколько назначений у отчёта (прямые + пакеты). `null`, если сервер счётчик не отдал. */
export const grantCount = (row: Pick<StudioRow, "assignmentCount" | "packageCount">) =>
  row.assignmentCount === null && row.packageCount === null ? null : (row.assignmentCount ?? 0) + (row.packageCount ?? 0);

/** --- Форма определения ------------------------------------------------- */

export type FilterRow = { id: number; field: string; op: string; value: string };
export type SortRow = { id: number; field: string; direction: "asc" | "desc" };
export type DefinitionForm = {
  datasetKey: string; fields: string[]; filters: FilterRow[]; sort: SortRow[]; actions: string[];
  reportKey: string; name: string; owner: string; purpose: string; sensitivity: string;
};

export const emptyForm = (): DefinitionForm => ({
  datasetKey: "", fields: [], filters: [], sort: [], actions: ["view"], reportKey: "", name: "", owner: "", purpose: "", sensitivity: "restricted",
});

let rowSerial = 0;
export const nextRowId = () => ++rowSerial;

export function formFromVersion(version: V4ReportDefinitionVersion): DefinitionForm {
  const definition = version.definition_json ?? {};
  return {
    datasetKey: version.dataset_key,
    fields: [...(definition.columns ?? [])],
    filters: (definition.filters ?? []).map((item) => ({ id: nextRowId(), field: item.field, op: item.op, value: Array.isArray(item.value) ? item.value.join(", ") : String(item.value ?? "") })),
    sort: (definition.sort ?? []).map((item) => ({ id: nextRowId(), field: item.field, direction: item.direction === "desc" ? "desc" : "asc" })),
    actions: [...(definition.actions ?? ["view"])],
    reportKey: version.report_key, name: version.name, owner: version.owner_name, purpose: version.purpose, sensitivity: version.sensitivity,
  };
}

/** Тело предпросмотра/сохранения; `null`, пока набор данных или поля не выбраны. */
export function definitionBody(form: DefinitionForm, dataset: V4Dataset | undefined): Record<string, unknown> | null {
  if (!dataset || !form.fields.length) return null;
  return {
    dataset_key: dataset.dataset_key, dataset_version: dataset.version, fields: form.fields,
    filters: form.filters.filter((item) => item.field && item.op).map((item) => ({
      field: item.field, op: item.op, value: item.op === "in" ? item.value.split(",").map((part) => part.trim()).filter(Boolean) : item.value,
    })),
    sort: form.sort.filter((item) => item.field).map((item) => ({ field: item.field, direction: item.direction })),
    actions: form.actions,
  };
}

export const REPORT_KEY_PATTERN = "[a-z0-9][a-z0-9_.\\-]{2,79}";
export const isValidReportKey = (key: string) => new RegExp(`^${REPORT_KEY_PATTERN}$`).test(key.trim());

export const metaComplete = (form: DefinitionForm) => isValidReportKey(form.reportKey) && Boolean(form.name.trim() && form.owner.trim() && form.purpose.trim());

/** Выполняемые наборы данных: остальные в реестре есть, но отчёт на них не откроется. */
export const executableDatasets = (items: V4Dataset[]) => items.filter((item) => item.executable !== false);

/** --- Человекочитаемые сообщения об ошибках ------------------------------- */

export function errorCode(error: unknown): string {
  if (error instanceof ApiResponseError) return error.code ?? error.message;
  return error instanceof Error ? error.message : String(error);
}

/** Код серверного отказа -> понятная фраза; незнакомый код показываем как есть. */
export function errorMessage(error: unknown): string {
  const code = errorCode(error);
  const key = `studio.err.${code}`;
  return key in ru ? t(key as MessageKey) : code;
}

export const capabilityLabel = (capability: string) => {
  const key = `studio.cap.${capability}`;
  return key in ru ? t(key as MessageKey) : capability;
};

export type PreviewResult = { signature: string; withRows: boolean; data: V4BuilderPreview };
export const previewSignature = (body: Record<string, unknown> | null) => JSON.stringify(body);
