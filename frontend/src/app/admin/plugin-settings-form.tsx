import { Checkbox } from "../../design-system/Checkbox";
import { Select } from "../../design-system/Select";
import { useId, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, ApiResponseError } from "../../api/client";
import type { PluginSettings, SettingsSchema } from "../../api/plugin-settings-types";
import { Button } from "../../design-system";
import { t, type MessageKey } from "../../i18n";
import { initialSetting, schemaTypes, validSetting } from "./plugin-settings-model";

const text = (key: string | undefined, fallback: string) => key ? t(key as MessageKey) : fallback;
const serialized = (value: unknown) => JSON.stringify(value);

/** Forms for nested schema values, without making users edit JSON. */
function ValueEditor({ node, value, onChange, label, id, describedBy }: {
  node: SettingsSchema; value: unknown; onChange: (value: unknown) => void; label: string; id: string; describedBy?: string;
}) {
  const types = schemaTypes(node);
  if (node.oneOf) {
    const record = (value ?? {}) as Record<string, unknown>;
    const branch = node.oneOf.find((item) => Object.entries(item.properties ?? {}).every(([key, child]) => !child.enum || child.enum.includes(record[key]))) ?? node.oneOf[0];
    return <>
      <label htmlFor={`${id}-kind`}>{t("pluginPage.scope")}</label>
      <Select label={t("pluginPage.scope")} id={`${id}-kind`} value={node.oneOf.indexOf(branch)} onChange={(selectedValue) => onChange(initialSetting(node.oneOf![Number(selectedValue)]))}
        options={node.oneOf.map((item, index) => ({ value: index, label: text(`pluginPage.field.${String(item.properties?.kind?.enum?.[0])}`, String(index + 1)) }))}/>
      <ValueEditor node={{ ...branch, properties: Object.fromEntries(Object.entries(branch.properties ?? {}).filter(([key]) => key !== "kind")) }} value={value}
        onChange={onChange} label={label} id={id}/>
    </>;
  }
  if (types.includes("object")) {
    const record = (value ?? {}) as Record<string, unknown>;
    return <fieldset><legend>{label}</legend>
      {value === null ? <Button onClick={() => onChange(initialSetting({ ...node, default: undefined }))}>{t("pluginPage.configure")}</Button> : <>
        {Object.entries(node.properties ?? {}).map(([key, child]) => <div className="sli-ds-field" key={key}>
          <ValueEditor node={child} value={record[key] ?? initialSetting(child)} id={`${id}-${key}`} label={text(child["x-label"], text(`pluginPage.field.${key}`, key))}
            onChange={(next) => onChange({ ...record, [key]: next })}/>
        </div>)}
        {types.includes("null") ? <Button onClick={() => onChange(null)}>{t("pluginPage.clear")}</Button> : null}
      </>}
    </fieldset>;
  }
  if (types.includes("array")) {
    const entries = Array.isArray(value) ? value : [];
    // AD exceptions can carry server attribution. Preserve it unless this field is edited.
    if (node.items && schemaTypes(node.items).includes("string")) {
      const lines = entries.map((entry: unknown) => typeof entry === "object" && entry !== null ? (entry as { sid?: string }).sid ?? "" : String(entry)).join("\n");
      return <><label htmlFor={id}>{label}</label><textarea id={id} value={lines} aria-describedby={describedBy} rows={4}
        onChange={(event) => onChange(event.target.value.split(/\r?\n/).filter(Boolean))}/></>;
    }
    return <fieldset><legend>{label}</legend>{entries.map((entry, index) => <div className="sli-ds-field" key={index}>
      <ValueEditor node={node.items!} value={entry} label={`${label} ${index + 1}`} id={`${id}-${index}`} onChange={(next) => onChange(entries.map((item, position) => position === index ? next : item))}/>
      <Button onClick={() => onChange(entries.filter((_, position) => position !== index))}>{t("pluginPage.removeItem", { index: index + 1 })}</Button>
    </div>)}<Button disabled={!node.items || entries.length >= (node.maxItems ?? 1000)} onClick={() => onChange([...entries, initialSetting(node.items!)])}>{t("pluginPage.addItem")}</Button></fieldset>;
  }
  if (node.enum) return <><label htmlFor={id}>{label}</label><Select label={label} id={id} value={serialized(value)} aria-describedby={describedBy} onChange={(selectedValue) => onChange(JSON.parse(selectedValue))}
    options={node.enum.map((entry) => ({ value: serialized(entry), label: String(entry) }))}/></>;
  if (types.includes("boolean")) return <Checkbox id={id} checked={value === true} onChange={(event) => onChange(event.target.checked)}>{label}</Checkbox>;
  const numeric = types.includes("integer") || types.includes("number");
  return <><label htmlFor={id}>{label}</label><input id={id} type={node["x-secret"] ? "password" : numeric ? "number" : "text"}
    autoComplete={node["x-secret"] ? "new-password" : "off"} aria-describedby={describedBy} aria-invalid={!validSetting(value, node)}
    value={value == null ? "" : String(value)} min={node.minimum} max={node.maximum} step={types.includes("integer") ? 1 : "any"}
    onChange={(event) => onChange(numeric ? event.target.value === "" ? "" : Number(event.target.value) : event.target.value === "" && types.includes("null") && !node["x-secret"] ? null : event.target.value)}/></>;
}

export function PluginSettingsForm({ data, canEdit, emptyAction }: { data: PluginSettings; canEdit: boolean; emptyAction: ReactNode }) {
  const client = useQueryClient();
  const prefix = useId();
  const properties = Object.entries(data.schema.properties ?? {});
  // Never copy current secret values or defaults into form state or the DOM.
  const [values, setValues] = useState<Record<string, unknown>>(() => Object.fromEntries(properties.map(([key, node]) => [key, node["x-secret"] ? "" : data.values[key] ?? node.default ?? null])));
  const [baseline, setBaseline] = useState(values);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const changed = properties.filter(([key, node]) => node["x-secret"] ? values[key] !== "" : serialized(values[key]) !== serialized(baseline[key]));
  const edit = (key: string, value: unknown) => { setValues((current) => ({ ...current, [key]: value })); setError(""); setMessage(""); };
  const fields = (advanced: boolean) => properties.filter(([, node]) => (node["x-group"] === "advanced") === advanced).map(([key, node], index) => {
    const label = text(node["x-label"], key);
    const id = `${prefix}-${advanced}-${index}`;
    return <div className="sli-ds-field" key={key}>
      <ValueEditor node={node} id={id} label={label} describedBy={`${id}-help`} value={values[key]} onChange={(value) => edit(key, value)}/>
      <p id={`${id}-help`} className="sli-ds-muted">{text(node["x-help"], "")}</p>
      {node["x-secret"] ? <p>{t("pluginPage.secretReplacement")}</p> : <>
        <p>{t("pluginPage.default", { value: node.default == null ? t("pluginPage.notSet") : typeof node.default === "object" ? Array.isArray(node.default) && !node.default.length ? t("pluginPage.emptyList") : t("pluginPage.structuredDefault") : String(node.default) })}</p>
        {Object.hasOwn(node, "default") ? <Button onClick={() => edit(key, node.default)}>{t("pluginPage.reset")}</Button> : null}
      </>}
    </div>;
  });
  return <form noValidate onSubmit={async (event) => {
    event.preventDefault();
    if (!canEdit || busy || !changed.length) return;
    const invalid = changed.find(([key, node]) => !validSetting(values[key], node));
    if (invalid) { setError(t("pluginPage.invalid", { label: text(invalid[1]["x-label"], invalid[0]) })); return; }
    setBusy(true); setError(""); setMessage("");
    let saved = 0;
    let currentKey = "";
    try {
      // The API writes one key at a time. Retain confirmed writes if a later key fails.
      for (const [key, node] of changed) {
        currentKey = text(node["x-label"], key);
        const result = await api.savePluginSetting(data.plugin_id, key, values[key]);
        const confirmed = node["x-secret"] ? "" : result.value;
        setValues((current) => ({ ...current, [key]: confirmed }));
        setBaseline((current) => ({ ...current, [key]: confirmed }));
        client.setQueryData<PluginSettings>(["plugin-settings", data.plugin_id], (current) => current ? { ...current, values: { ...current.values, [key]: node["x-secret"] ? null : confirmed } } : current);
        saved++;
      }
      setMessage(t("pluginPage.saved"));
    } catch (failure) {
      const reason = failure instanceof ApiResponseError && failure.status === 403 ? t("pluginPage.readOnly")
        : failure instanceof ApiResponseError && failure.code === "invalid_plugin_setting_value" ? t("pluginPage.invalid", { label: currentKey }) : t("pluginPage.saveFailed", { label: currentKey });
      setError(reason);
      if (saved) setMessage(t("pluginPage.partialSave", { count: saved }));
    } finally { setBusy(false); }
  }}>
    {!properties.length ? <p>{t("pluginPage.noSettings")} {data.schema["x-core-settings"]?.length
      ? <a href="/app/platform-settings">{t("pluginPage.coreSettings")}</a> : emptyAction}</p> : <fieldset disabled={!canEdit || busy}>
      <legend>{t(data.plugin_id === "sli.ad" ? "pluginPage.sharedDomains" : "pluginPage.basic")}</legend>
      {fields(false)}
      {properties.some(([, node]) => node["x-group"] === "advanced") ? <details className="sli-ds-filters__additional"><summary>{t("pluginPage.advanced")}</summary>{fields(true)}</details> : null}
      <Button type="submit" disabled={!changed.length}>{t(busy ? "plugins.saving" : "platformSettings.save")}</Button>
    </fieldset>}
    {data.plugin_id === "sli.ad" ? <p>{t("pluginPage.noOverrides")}</p> : null}
    {properties.length > 0 && data.schema["x-core-settings"]?.length ? <a href="/app/platform-settings">{t("pluginPage.coreSettings")}</a> : null}
    {error ? <p role="alert">{error}</p> : null}{message ? <p role="status">{message}</p> : null}
  </form>;
}
