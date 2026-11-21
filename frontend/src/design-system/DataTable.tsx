import { formatNumber } from "../shared/format";
import { useMemo, useState, type ReactNode } from "react";
import { flexRender, getCoreRowModel, useReactTable, type ColumnDef, type VisibilityState } from "@tanstack/react-table";
import { t } from "../i18n";
import { type CellKind } from "./format";
import { useDateFormatters } from "./useDateFormatters";

export type SortState = { field: string; direction: "asc" | "desc" };

export type TableColumn<Row> = {
  key: string;
  label: string;
  renderHeader?: () => ReactNode;
  kind?: CellKind;
  /** Server-side sortable (ADR 0010: sorting is done by the report query). */
  sortable?: boolean;
  /** Hidden until the user enables it in the column menu. */
  hiddenByDefault?: boolean;
  /** Omit secondary columns on narrow screens while keeping row details available. */
  mobile?: boolean;
  width?: string;
  minWidth?: string;
  align?: "start" | "end";
  value?: (row: Row) => unknown;
  render?: (row: Row) => ReactNode;
};

export function DataTable<Row>({
  columns, rows, rowKey, sort, onSort, onRowClick, selectedKey, caption,
  hasMore = false, loadingMore = false, onLoadMore, total, stickyHeader = true, pagination, showFooter = true, compact, isSubRow,
}: {
  columns: TableColumn<Row>[];
  rows: Row[];
  rowKey: (row: Row) => string;
  sort?: SortState | null;
  onSort?: (field: string) => void;
  onRowClick?: (row: Row) => void;
  selectedKey?: string | null;
  caption: string;
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
  total?: number | null;
  pagination?: { start: number; end?: number; onPrevious?: () => void; onNext?: () => void; busy?: boolean };
  /** Embedded previews may provide their own count and open-all action. */
  showFooter?: boolean;
  /** The table scrolls inside a bounded box so the header stays visible; pass false for small embedded tables. */
  stickyHeader?: boolean;
  compact?: boolean;
  isSubRow?: (row: Row) => boolean;
}) {
  const { formatCell } = useDateFormatters();
  const [visibility, setVisibility] = useState<VisibilityState>({});
  const defaultVisibility = Object.fromEntries(columns.map((column) => [column.key, !column.hiddenByDefault]));
  const defs = useMemo<ColumnDef<Row>[]>(() => columns.map((column) => ({
    id: column.key,
    header: column.label,
    accessorFn: (row: Row) => (column.value ? column.value(row) : (row as Record<string, unknown>)[column.key]),
    meta: column,
  })), [columns]);
  const table = useReactTable({
    data: rows, columns: defs, getCoreRowModel: getCoreRowModel(), getRowId: (row) => rowKey(row),
    state: { columnVisibility: { ...defaultVisibility, ...visibility } }, onColumnVisibilityChange: setVisibility, manualSorting: true,
  });
  const toggleable = columns.filter((column) => column.hiddenByDefault !== undefined);

  return <div className="sli-ds-table" data-compact={compact || undefined}>
    {toggleable.length ? <details className="sli-ds-table__columns">
      <summary>{t("table.columns")}</summary>
      <div role="group" aria-label={t("table.columns")}>
        {table.getAllLeafColumns().filter((column) => toggleable.some((item) => item.key === column.id)).map((column) => <label key={column.id}>
          <input type="checkbox" checked={column.getIsVisible()} onChange={column.getToggleVisibilityHandler()}/>
          {String(column.columnDef.header)}
        </label>)}
      </div>
    </details> : null}
    <div className="sli-ds-table__scroll" data-sticky={stickyHeader || undefined}>
      <table data-responsive={columns.some((column) => column.mobile === false) || undefined}>
        <caption className="sli-ds-sr-only">{caption}</caption>
        <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => {
          const column = header.column.columnDef.meta as TableColumn<Row>;
          const active = sort?.field === column.key;
          const ariaSort = active ? (sort?.direction === "asc" ? "ascending" : "descending") : column.sortable && onSort ? "none" : undefined;
          return <th key={header.id} scope="col" data-mobile={column.mobile} style={{ width: column.width, minWidth: column.minWidth }} data-align={column.align ?? (column.kind === "number" ? "end" : "start")} aria-sort={ariaSort}>
            {column.sortable && onSort
              ? <button type="button" className="sli-ds-table__sort" onClick={() => onSort(column.key)}>
                  {flexRender(header.column.columnDef.header, header.getContext())}
                  <span aria-hidden="true" className="sli-ds-table__sort-mark" data-active={active || undefined}>{active ? (sort?.direction === "asc" ? "↑" : "↓") : "↕"}</span>
                  {active ? <span className="sli-ds-sr-only">, {sort?.direction === "asc" ? t("table.sortAsc") : t("table.sortDesc")}</span> : null}
                </button>
              : column.renderHeader ? column.renderHeader() : flexRender(header.column.columnDef.header, header.getContext())}
          </th>;
        })}</tr>)}</thead>
        <tbody>{table.getRowModel().rows.map((row) => {
          const selected = selectedKey === row.id;
          const subRow = isSubRow?.(row.original);
          const open = subRow ? undefined : onRowClick;
          return <tr key={row.id} data-selected={selected || undefined} data-subrow={subRow || undefined} data-clickable={open ? true : undefined}
            tabIndex={open ? 0 : undefined}
            onClick={open ? () => open(row.original) : undefined}
            onKeyDown={open ? (event) => { if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); open(row.original); } } : undefined}
            aria-selected={open ? selected : undefined}>
            {row.getVisibleCells().map((cell) => {
              const column = cell.column.columnDef.meta as TableColumn<Row>;
              return <td key={cell.id} data-mobile={column.mobile} style={{ minWidth: column.minWidth }} data-kind={column.kind} data-align={column.align ?? (column.kind === "number" ? "end" : "start")}>
                {column.render ? column.render(row.original) : formatCell(cell.getValue(), column.kind)}
              </td>;
            })}
          </tr>;
        })}</tbody>
      </table>
    </div>
    {showFooter ? <div className="sli-ds-table__footer" aria-live="polite">
      {pagination ? <>
        <span>{t("table.range", { from: rows.length ? pagination.start : 0, to: rows.length ? pagination.end ?? pagination.start + rows.length - 1 : 0,
          total: typeof total === "number" ? formatNumber(total) : t("table.noValue") })}</span>
        <div className="sli-ds-header__actions">
          <button type="button" className="sli-ds-button" disabled={pagination.busy || !pagination.onPrevious} onClick={pagination.onPrevious}>{t("table.previous")}</button>
          <button type="button" className="sli-ds-button" disabled={pagination.busy || !pagination.onNext} onClick={pagination.onNext}>{t("table.next")}</button>
        </div>
      </> : <>
        <span>{t("table.shown", { count: rows.length })}{typeof total === "number" ? ` ${t("table.of", { total: formatNumber(total) })}` : ""}</span>
        {hasMore && onLoadMore ? <button type="button" className="sli-ds-button" disabled={loadingMore} onClick={onLoadMore}>{loadingMore ? t("table.loadingMore") : t("table.loadMore")}</button> : null}
      </>}
    </div> : null}
  </div>;
}
