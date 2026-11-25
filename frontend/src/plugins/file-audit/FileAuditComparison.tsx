import { useMemo, useState } from "react";
import { DataTable, FactList, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { useDateFormatters } from "../../design-system/useDateFormatters";
import { aclDifferences, type AclDifference, type FileAuditComparison as Comparison, type FileAuditObservation } from "./acl";
import { aceAppliesTo, aceKind, aceRights, FileAuditAceDetails } from "./FileAuditAclTable";
import { FILE_AUDIT_PAGE_SIZES } from "./report";

type Layer = "ntfs" | "smb" | "owner" | "sacl";
const aclAt = (item: FileAuditObservation | undefined, layer: Layer) => layer === "smb" ? item?.share.dacl
  : layer === "sacl" ? item?.object?.sacl : item?.object?.dacl;

export function FileAuditComparison({ comparison, pageSize: initialSize }: { comparison: Comparison; pageSize: number }) {
  const { formatCell } = useDateFormatters();
  const [layer, setLayer] = useState<Layer>("ntfs");
  const [search, setSearch] = useState("");
  const [onlyChanges, setOnlyChanges] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(initialSize);
  const before = comparison.before, after = comparison.after;
  const beforeFlags = aclAt(before, layer)?.flags_raw, afterFlags = aclAt(after, layer)?.flags_raw;
  const flagsChanged = layer !== "owner" && beforeFlags !== undefined && afterFlags !== undefined && beforeFlags !== afterFlags;
  const changes = useMemo(() => aclDifferences(aclAt(before, layer), aclAt(after, layer)), [before, after, layer]);
  const rows = useMemo(() => changes?.filter(row => (!onlyChanges || row.change !== "unchanged")
    && (!search || [row.before?.sid, row.after?.sid, row.before?.raw, row.after?.raw]
      .some(value => value?.toLocaleLowerCase().includes(search.toLocaleLowerCase())))) ?? [], [changes, onlyChanges, search]);
  const reset = () => { setPage(0); setSelected(null); };
  const labels = { ntfs: t("file-audit.acl.ntfs"), smb: t("file-audit.acl.smb"), owner: t("file-audit.workspace.owner"), sacl: t("file-audit.acl.sacl") };
  const columns: TableColumn<AclDifference>[] = [
    { key: "change", label: t("file-audit.compare.change"), render: row => <span className="sli-file-audit__change" data-change={row.change}>
      <span aria-hidden="true">{row.change === "added" ? "+" : row.change === "removed" ? "−" : row.change === "changed" ? "↔" : "="}</span>{t(`file-audit.compare.${row.change}`)}</span> },
    { key: "sid", label: t("file-audit.acl.subject"), wrap: true, value: row => row.after?.name || row.after?.sid || row.before?.name || row.before?.sid },
    { key: "before", label: t("file-audit.compare.before"), wrap: true, value: row => row.before ? `${aceKind(row.before)}: ${aceRights(row.before)}` : t("file-audit.compare.not_present") },
    { key: "after", label: t("file-audit.compare.after"), wrap: true, value: row => row.after ? `${aceKind(row.after)}: ${aceRights(row.after)}` : t("file-audit.compare.not_present") },
    { key: "applies_to", label: t("file-audit.acl.applies_to"), wrap: true, value: row => aceAppliesTo((row.after ?? row.before)!) },
    { key: "ordinal", label: t("file-audit.acl.position"), value: row => `${row.before?.ordinal ?? "—"} → ${row.after?.ordinal ?? "—"}` },
  ];
  return <section className="sli-file-audit__comparison" aria-label={t("file-audit.compare.title")}>
    <p className="sli-file-audit__local-state">{t("file-audit.compare.observations")}: {formatCell(before?.snapshot.observed_at, "datetime")} → {formatCell(after?.snapshot.observed_at, "datetime")}</p>
    {comparison.identity_basis === "path" ? <p className="sli-file-audit__local-state">{t("file-audit.compare.identity_path")}</p> : null}
    <div className="sli-file-audit__segments" role="group" aria-label={t("file-audit.compare.layer")}>
      {(Object.keys(labels) as Layer[]).map(key => <button className="sli-ds-button" type="button" key={key} aria-pressed={key === layer} onClick={() => { reset(); setLayer(key); }}>{labels[key]}</button>)}
    </div>
    {flagsChanged ? <div className="sli-file-audit__comparison-sides" aria-label={t("file-audit.compare.acl_flags")}>
      <section><h3>{t("file-audit.compare.before")}</h3><FactList facts={[{ label: t("file-audit.compare.acl_flags"), value: beforeFlags || "—" }]}/></section>
      <section><h3>{t("file-audit.compare.after")}</h3><FactList facts={[{ label: t("file-audit.compare.acl_flags"), value: afterFlags || "—" }]}/></section>
    </div> : null}
    {layer === "owner" ? <div className="sli-file-audit__comparison-sides">
      <section><h3>{t("file-audit.compare.before")}</h3><FactList facts={[{ label: labels.owner, value: before?.object?.owner_sid ?? t("file-audit.acl.not_read") }]}/></section>
      <section><h3>{t("file-audit.compare.after")}</h3><FactList facts={[{ label: labels.owner, value: after?.object?.owner_sid ?? t("file-audit.acl.not_read") }]}/></section>
    </div> : changes === null ? <p className="sli-file-audit__local-state">{t("file-audit.compare.incomplete")}</p> : <DataTable
      caption={labels[layer]} columns={columns} rows={rows.slice(page * pageSize, (page + 1) * pageSize)} rowKey={row => row.id}
      compact density="compact" wrapCells selectedKey={selected} onRowClick={row => setSelected(current => current === row.id ? null : row.id)}
      toolbar={<div className="sli-file-audit__acl-filters"><label><input type="checkbox" checked={onlyChanges} onChange={event => { reset(); setOnlyChanges(event.target.checked); }}/>{t("file-audit.compare.only_changes")}</label>
        <input type="search" aria-label={t("file-audit.acl.search")} placeholder={t("file-audit.acl.search")} value={search} onChange={event => { reset(); setSearch(event.target.value); }}/></div>}
      total={rows.length} emptyContent={t("file-audit.compare.no_change")}
      pageSize={{ value: pageSize, options: FILE_AUDIT_PAGE_SIZES, onChange: size => { reset(); setPageSize(size); } }}
      pagination={{ start: page * pageSize + 1, onPrevious: page > 0 ? () => { setSelected(null); setPage(page - 1); } : undefined,
        onNext: (page + 1) * pageSize < rows.length ? () => { setSelected(null); setPage(page + 1); } : undefined }}
      renderExpandedRow={row => <div className="sli-file-audit__comparison-sides">
        <section><h3>{t("file-audit.compare.before")}</h3>{row.before ? <FileAuditAceDetails ace={row.before}/> : <p>{t("file-audit.compare.not_present")}</p>}</section>
        <section><h3>{t("file-audit.compare.after")}</h3>{row.after ? <FileAuditAceDetails ace={row.after}/> : <p>{t("file-audit.compare.not_present")}</p>}</section>
      </div>}/>}
    {layer !== "owner" ? <details className="sli-file-audit__raw"><summary>{t("file-audit.acl.descriptor")}</summary><div className="sli-file-audit__comparison-sides">
      <section><h3>{t("file-audit.compare.before")}</h3><pre>{aclAt(before, layer)?.raw ?? t("file-audit.acl.not_read")}</pre></section>
      <section><h3>{t("file-audit.compare.after")}</h3><pre>{aclAt(after, layer)?.raw ?? t("file-audit.acl.not_read")}</pre></section>
    </div></details> : null}
    <p className="sli-file-audit__local-state">{t("file-audit.compare.no_actor")}</p>
  </section>;
}
