import { useId, useMemo, useState } from "react";
import { DataTable, FactList, type TableColumn } from "../../design-system";
import { t } from "../../i18n";
import { fileMaskLabel } from "./permissionMasks";
import { fileMaskLabels } from "./FileAuditCells";
import { FILE_AUDIT_PAGE_SIZES } from "./report";
import { filterAces, type AceFilter, type FileAuditAce, type FileAuditAcl } from "./acl";

export const aceKind = (ace: FileAuditAce) => ace.type === "allow" ? t("file-audit.acl.allow")
  : ace.type === "deny" ? t("file-audit.acl.deny") : ace.type === "audit" ? t("file-audit.acl.audit")
  : t("file-audit.acl.unsupported", { type: ace.ace_type });
export const aceRights = (ace: FileAuditAce) => fileMaskLabel(ace.mask, fileMaskLabels()) ?? ace.mask_raw ?? "—";
export const aceAppliesTo = (ace: FileAuditAce) => [
  !ace.inherit_only ? t("file-audit.acl.this_object") : null,
  ace.flags.includes("CI") ? t("file-audit.acl.children") : null,
  ace.flags.includes("OI") ? t("file-audit.acl.files") : null,
  ace.inherit_only ? t("file-audit.acl.inherit_only") : null,
  ace.flags.includes("NP") ? t("file-audit.acl.no_propagate") : null,
].filter(Boolean).join(", ");

export function FileAuditAceDetails({ ace }: { ace: FileAuditAce }) {
  return <div className="sli-file-audit__ace-details"><FactList facts={[
    { label: t("file-audit.acl.position"), value: String(ace.ordinal) },
    { label: t("file-audit.acl.subject"), value: ace.sid },
    { label: t("file-audit.acl.kind"), value: `${aceKind(ace)} (${ace.ace_type})` },
    { label: t("file-audit.acl.mask"), value: ace.mask_raw },
    { label: t("file-audit.acl.flags"), value: ace.flags_raw || "—" },
    { label: t("file-audit.acl.applies_to"), value: aceAppliesTo(ace) },
  ]}/><details><summary>{t("file-audit.acl.raw")}</summary><pre>{ace.raw}</pre></details></div>;
}

export function FileAuditAclTable({ acl, title, initialPageSize = 50, onPageSize }: {
  acl?: FileAuditAcl; title: string; initialPageSize?: number; onPageSize?: (size: number) => void;
}) {
  const id = useId();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<AceFilter>("all");
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [selected, setSelected] = useState<string | null>(null);
  const entries = useMemo(() => filterAces(acl?.aces ?? [], search, filter), [acl, search, filter]);
  const columns: TableColumn<FileAuditAce>[] = [
    { key: "sid", label: t("file-audit.acl.subject"), width: "30%", wrap: true, render: ace => <span className="sli-file-audit__resource">{ace.name || ace.sid}{ace.name ? <small>{ace.sid}</small> : null}</span> },
    { key: "type", label: t("file-audit.acl.kind"), value: aceKind },
    { key: "rights", label: t("file-audit.acl.rights"), value: aceRights },
    { key: "applies_to", label: t("file-audit.acl.applies_to"), wrap: true, value: aceAppliesTo },
    { key: "inheritance", label: t("file-audit.acl.inheritance"), value: ace => t(ace.inherited ? "file-audit.acl.inherited" : "file-audit.acl.explicit") },
    { key: "ordinal", label: t("file-audit.acl.position"), kind: "number", hiddenByDefault: true },
  ];
  const reset = () => { setPage(0); setSelected(null); };
  return <section className="sli-file-audit__acl" aria-label={title}>
    <h2>{title}</h2>
    {!acl || acl.state === "missing" ? <p className="sli-file-audit__local-state">{t("file-audit.acl.not_read")}</p> : <>
      {acl.state !== "complete" ? <p className="sli-file-audit__local-state">{t(acl.state === "partial" ? "file-audit.compare.incomplete" : "file-audit.acl.unsupported_descriptor")}</p> : null}
      <DataTable caption={title} columns={columns} rows={entries.slice(page * pageSize, (page + 1) * pageSize)}
        rowKey={ace => String(ace.ordinal)} compact density="compact" wrapCells selectedKey={selected}
        onRowClick={ace => setSelected(current => current === String(ace.ordinal) ? null : String(ace.ordinal))}
        renderExpandedRow={ace => <FileAuditAceDetails ace={ace}/>}
        toolbar={<div className="sli-file-audit__acl-filters">
          <label htmlFor={`${id}-search`} className="sli-ds-sr-only">{t("file-audit.acl.search")}</label>
          <input id={`${id}-search`} type="search" placeholder={t("file-audit.acl.search")} value={search} onChange={event => { reset(); setSearch(event.target.value); }}/>
          <label htmlFor={`${id}-filter`} className="sli-ds-sr-only">{t("file-audit.acl.filter")}</label>
          <select id={`${id}-filter`} value={filter} onChange={event => { reset(); setFilter(event.target.value as AceFilter); }}>
            {(["all", "explicit", "inherited", "deny"] as const).map(value => <option key={value} value={value}>{t(`file-audit.acl.${value}`)}</option>)}
          </select>
        </div>}
        emptyContent={t(acl.aces.length === 0 && acl.state === "complete" ? "file-audit.acl.empty" : "file-audit.acl.no_matches")} total={entries.length}
        pageSize={{ value: pageSize, options: FILE_AUDIT_PAGE_SIZES, onChange: size => { reset(); setPageSize(size); onPageSize?.(size); } }}
        pagination={{ start: page * pageSize + 1, onPrevious: page > 0 ? () => { setSelected(null); setPage(page - 1); } : undefined,
          onNext: (page + 1) * pageSize < entries.length ? () => { setSelected(null); setPage(page + 1); } : undefined }}/>
    </>}
    {acl?.raw != null ? <details className="sli-file-audit__raw"><summary>{t("file-audit.acl.descriptor")}</summary><pre>{acl.raw}</pre></details> : null}
  </section>;
}
