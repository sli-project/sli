import { useEffect } from "react";
import { Badge, Button, Callout, DataTable, EmptyState, StateView, type TableColumn } from "../../design-system";
import type { V4Dataset } from "../../api/client";
import { t } from "../../i18n";
import { accessActionLabel, fieldCategoryLabel } from "../report-labels";
import { ChoiceGroup, toggleValue } from "./gate";
import {
  REPORT_KEY_PATTERN, capabilityLabel, errorMessage, nextRowId,
  type DefinitionForm, type PreviewResult,
} from "./report-studio-model";

export type PreviewState = { current: PreviewResult | null; pending: boolean; error: unknown };

/** Таблица «требуемые возможности — есть ли они у вас». */
function CapabilityList({ required, missing }: { required: string[]; missing: string[] }) {
  if (!required.length) return null;
  return <section aria-label={t("studio.caps.title")}>
    <h3 className="sli-ds-section-title">{t("studio.caps.title")}</h3>
    <ul className="sli-studio__caps">
      {required.map((capability) => {
        const has = !missing.includes(capability);
        return <li key={capability}><span>{capabilityLabel(capability)}</span><Badge tone={has ? "success" : "danger"}>{has ? t("studio.caps.have") : t("studio.caps.lack")}</Badge></li>;
      })}
    </ul>
  </section>;
}

/** Вкладка «Определение»: редактор набора данных, полей, фильтров, сортировки и сведений об отчёте. */
export function DefinitionTab({ form, setForm, datasets, editable, isNew, preview, onValidate, canValidate }: {
  form: DefinitionForm;
  setForm: (next: DefinitionForm) => void;
  datasets: V4Dataset[];
  editable: boolean;
  isNew: boolean;
  preview: PreviewState;
  onValidate: () => void;
  canValidate: boolean;
}) {
  const dataset = datasets.find((item) => item.dataset_key === form.datasetKey);
  const filterKeys = (dataset?.executable_filter_keys ?? dataset?.filters_json.map((item) => item.key) ?? []).filter((key) => dataset?.filters_json.some((item) => item.key === key));
  const sortKeys = dataset?.executable_sort_keys ?? dataset?.fields_json.map((item) => item.key) ?? [];
  const fieldLabel = (key: string) => dataset?.fields_json.find((item) => item.key === key)?.label ?? key;
  const patch = (next: Partial<DefinitionForm>) => setForm({ ...form, ...next });
  const chooseDataset = (key: string) => {
    const item = datasets.find((candidate) => candidate.dataset_key === key);
    patch({ datasetKey: key, fields: item?.fields_json.slice(0, 4).map((field) => field.key) ?? [], filters: [], sort: [], actions: item?.actions_json.includes("view") ? ["view"] : [] });
  };
  const opsFor = (field: string) => dataset?.filters_json.find((item) => item.key === field)?.ops ?? [];
  const result = preview.current?.data;

  return <div className="sli-studio__tab">
    {!editable ? <Callout tone="warning" icon="lock" title={t("studio.def.readonly.title")}>{t("studio.def.readonly.text")}</Callout> : null}
    <fieldset className="sli-studio__form" disabled={!editable}>
      <legend className="sli-ds-section-title">{t("studio.def.about")}</legend>
      <div className="sli-ds-filters__fields">
        <div className="sli-ds-field"><label htmlFor="studio-key">{t("studio.def.key")}</label>
          <input id="studio-key" required disabled={!isNew} pattern={REPORT_KEY_PATTERN} value={form.reportKey} onChange={(event) => patch({ reportKey: event.target.value })} placeholder="team.report_name"/></div>
        <div className="sli-ds-field"><label htmlFor="studio-name">{t("studio.def.name")}</label>
          <input id="studio-name" required value={form.name} onChange={(event) => patch({ name: event.target.value })}/></div>
        <div className="sli-ds-field"><label htmlFor="studio-owner">{t("studio.def.owner")}</label>
          <input id="studio-owner" required value={form.owner} onChange={(event) => patch({ owner: event.target.value })}/></div>
        <div className="sli-ds-field"><label htmlFor="studio-sensitivity">{t("studio.def.sensitivity")}</label>
          <select id="studio-sensitivity" value={form.sensitivity} onChange={(event) => patch({ sensitivity: event.target.value })}>
            <option value="internal">{t("studio.sensitivity.low")}</option>
            <option value="restricted">{t("studio.sensitivity.restricted")}</option>
            <option value="confidential">{t("studio.sensitivity.confidential")}</option>
          </select></div>
      </div>
      <div className="sli-ds-field" style={{ maxWidth: "none" }}><label htmlFor="studio-purpose">{t("studio.def.purpose")}</label>
        <textarea id="studio-purpose" required rows={2} value={form.purpose} onChange={(event) => patch({ purpose: event.target.value })}/></div>

      <h3 className="sli-ds-section-title">{t("studio.def.source")}</h3>
      <div className="sli-ds-field"><label htmlFor="studio-dataset">{t("studio.def.dataset")}</label>
        <select id="studio-dataset" value={form.datasetKey} onChange={(event) => chooseDataset(event.target.value)}>
          <option value="">{t("studio.def.dataset.choose")}</option>
          {datasets.map((item) => <option key={item.dataset_key} value={item.dataset_key}>{item.name} · v{item.version}</option>)}
        </select></div>
      {!datasets.length ? <EmptyState title={t("studio.def.dataset.none.title")} copy={t("studio.def.dataset.none.text")}/> : null}
      {form.datasetKey && !dataset ? <Callout tone="danger" role="alert" title={t("studio.def.dataset.gone.title")}>{t("studio.def.dataset.gone.text")}</Callout> : null}

      {dataset ? <>
        <ChoiceGroup legend={t("studio.def.fields")} options={dataset.fields_json.map((field) => ({ key: field.key, label: `${field.label} (${fieldCategoryLabel(field.category)})` }))}
          selected={form.fields} onToggle={(key) => patch({ fields: toggleValue(form.fields, key) })}/>

        <h3 className="sli-ds-section-title">{t("studio.def.filters")}</h3>
        {!filterKeys.length ? <p className="sli-ds-header__subtitle">{t("studio.def.filters.none")}</p> : null}
        {form.filters.map((row, index) => <div className="sli-studio__row" key={row.id} role="group" aria-label={t("studio.def.filter.n", { n: index + 1 })}>
          <div className="sli-ds-field"><label htmlFor={`studio-filter-field-${row.id}`}>{t("studio.def.filter.field")}</label>
            <select id={`studio-filter-field-${row.id}`} value={row.field} onChange={(event) => patch({ filters: form.filters.map((item) => (item.id === row.id ? { ...item, field: event.target.value, op: opsFor(event.target.value)[0] ?? "" } : item)) })}>
              <option value="">{t("studio.def.pick")}</option>
              {filterKeys.map((key) => <option key={key} value={key}>{fieldLabel(key)}</option>)}
            </select></div>
          <div className="sli-ds-field"><label htmlFor={`studio-filter-op-${row.id}`}>{t("studio.def.filter.op")}</label>
            <select id={`studio-filter-op-${row.id}`} value={row.op} disabled={!row.field} onChange={(event) => patch({ filters: form.filters.map((item) => (item.id === row.id ? { ...item, op: event.target.value } : item)) })}>
              {opsFor(row.field).map((op) => <option key={op} value={op}>{op}</option>)}
            </select></div>
          <div className="sli-ds-field"><label htmlFor={`studio-filter-value-${row.id}`}>{t("studio.def.filter.value")}</label>
            <input id={`studio-filter-value-${row.id}`} value={row.value} disabled={!row.field} placeholder={row.op === "in" ? t("studio.def.filter.value.many") : ""} onChange={(event) => patch({ filters: form.filters.map((item) => (item.id === row.id ? { ...item, value: event.target.value } : item)) })}/></div>
          <Button onClick={() => patch({ filters: form.filters.filter((item) => item.id !== row.id) })}>{t("studio.def.remove")}</Button>
        </div>)}
        <div><Button disabled={!filterKeys.length} onClick={() => patch({ filters: [...form.filters, { id: nextRowId(), field: "", op: "", value: "" }] })}>{t("studio.def.filter.add")}</Button></div>

        <h3 className="sli-ds-section-title">{t("studio.def.sort")}</h3>
        {!sortKeys.length ? <p className="sli-ds-header__subtitle">{t("studio.def.sort.none")}</p> : null}
        {form.sort.map((row, index) => <div className="sli-studio__row" key={row.id} role="group" aria-label={t("studio.def.sort.n", { n: index + 1 })}>
          <div className="sli-ds-field"><label htmlFor={`studio-sort-field-${row.id}`}>{t("studio.def.sort.field")}</label>
            <select id={`studio-sort-field-${row.id}`} value={row.field} onChange={(event) => patch({ sort: form.sort.map((item) => (item.id === row.id ? { ...item, field: event.target.value } : item)) })}>
              <option value="">{t("studio.def.pick")}</option>
              {sortKeys.map((key) => <option key={key} value={key}>{fieldLabel(key)}</option>)}
            </select></div>
          <div className="sli-ds-field"><label htmlFor={`studio-sort-dir-${row.id}`}>{t("studio.def.sort.direction")}</label>
            <select id={`studio-sort-dir-${row.id}`} value={row.direction} onChange={(event) => patch({ sort: form.sort.map((item) => (item.id === row.id ? { ...item, direction: event.target.value === "desc" ? "desc" : "asc" } : item)) })}>
              <option value="asc">{t("table.sortAsc")}</option><option value="desc">{t("table.sortDesc")}</option>
            </select></div>
          <Button onClick={() => patch({ sort: form.sort.filter((item) => item.id !== row.id) })}>{t("studio.def.remove")}</Button>
        </div>)}
        <div><Button disabled={!sortKeys.length} onClick={() => patch({ sort: [...form.sort, { id: nextRowId(), field: "", direction: "asc" }] })}>{t("studio.def.sort.add")}</Button></div>

        <ChoiceGroup legend={t("studio.def.actions")} options={dataset.actions_json.map((action) => ({ key: action, label: accessActionLabel(action) }))}
          selected={form.actions} onToggle={(key) => patch({ actions: toggleValue(form.actions, key) })}/>
      </> : null}
    </fieldset>

    {dataset ? <section aria-label={t("studio.validation.title")} className="sli-studio__validation">
      <h3 className="sli-ds-section-title">{t("studio.validation.title")}</h3>
      <div><Button variant="primary" disabled={!canValidate || preview.pending || !editable} onClick={onValidate}>{preview.pending ? t("studio.validation.running") : t("studio.validation.run")}</Button></div>
      {preview.error ? <Callout tone="danger" role="alert" title={t("studio.validation.failed")}>{errorMessage(preview.error)}</Callout> : null}
      {!preview.error && result ? <>
        <Callout tone={result.status === "accepted" ? "success" : "warning"} role="status" title={result.status === "accepted" ? t("studio.validation.accepted") : t("studio.validation.gated")}>
          {result.status === "accepted" ? t("studio.validation.accepted.text") : t("studio.validation.gated.text")}
        </Callout>
        <CapabilityList required={result.required_capabilities} missing={result.missing_capabilities}/>
      </> : null}
      {!preview.error && !result && !preview.pending ? <p className="sli-ds-header__subtitle">{t("studio.validation.hint")}</p> : null}
    </section> : null}
  </div>;
}

/** Вкладка «Предпросмотр»: строки образца или честное сообщение о том, почему их нет. */
export function PreviewTab({ signature, preview, onRun, canRun, reason }: {
  signature: string;
  preview: PreviewState;
  onRun: () => void;
  canRun: boolean;
  reason: string | null;
}) {
  const current = preview.current;
  const haveRows = Boolean(current?.withRows);
  // Открытие вкладки сразу запрашивает строки; повторять запрос при том же определении не нужно.
  useEffect(() => { if (canRun && !haveRows && !preview.pending && !preview.error) onRun(); }, [signature, canRun, haveRows]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!canRun) return <div className="sli-studio__tab"><EmptyState title={t("studio.preview.blocked")} copy={reason ?? t("studio.preview.blocked.text")}/></div>;
  if (preview.pending && !haveRows) return <div className="sli-studio__tab"><StateView state="loading"/></div>;
  if (preview.error) return <div className="sli-studio__tab"><Callout tone="danger" role="alert" title={t("studio.validation.failed")}>{errorMessage(preview.error)}</Callout><div><Button onClick={onRun}>{t("state.retry")}</Button></div></div>;
  const data = current?.data;
  const rows = data?.sample_rows ?? [];
  const columns: TableColumn<Record<string, unknown>>[] = (data?.sample_columns?.length ? data.sample_columns : Object.keys(rows[0] ?? {}).map((key) => ({ key, label: key })))
    .map((column) => ({ key: column.key, label: column.label }));
  return <div className="sli-studio__tab">
    <div><Button onClick={onRun} disabled={preview.pending}>{t("studio.preview.refresh")}</Button></div>
    {data?.sample_state === "rows" && rows.length
      ? <DataTable caption={t("studio.preview.caption")} columns={columns} rows={rows} rowKey={(row) => JSON.stringify(row)} stickyHeader={false}/>
      : data?.sample_state === "empty" ? <StateView state="empty" detail={t("studio.preview.empty")}/>
      : data?.sample_state === "gated" || (data?.status === "gated" && data.sample_state !== "rows")
        ? <Callout tone="warning" role="status" title={t("studio.preview.gated.title")}>
            {t("studio.preview.gated.text")}
            <ul className="sli-studio__caps">{(data?.missing_capabilities ?? []).map((capability) => <li key={capability}><span>{capabilityLabel(capability)}</span><Badge tone="danger">{t("studio.caps.lack")}</Badge></li>)}</ul>
          </Callout>
        : <EmptyState title={t("studio.preview.norows.title")} copy={t("studio.preview.norows.text")}/>}
    {data ? <CapabilityList required={data.required_capabilities} missing={data.missing_capabilities}/> : null}
  </div>;
}
