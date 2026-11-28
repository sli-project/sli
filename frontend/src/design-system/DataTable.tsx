import { formatNumber } from "../shared/format";
import { Fragment, isValidElement, useMemo, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { flexRender, getCoreRowModel, useReactTable, type ColumnDef, type VisibilityState } from "@tanstack/react-table";
import { t } from "../i18n";
import { type CellKind } from "./format";
import { Checkbox } from "./Checkbox";
import { Pager, type PageSize } from "./Pager";
import { useDateFormatters } from "./useDateFormatters";

export type SortState = { field: string; direction: "asc" | "desc" };
type TablePagination = {
  start: number;
  end?: number;
  label?: ReactNode;
  pageLabel?: string;
  onPrevious?: () => void;
  onNext?: () => void;
  busy?: boolean;
};
const LOCAL_PAGE_SIZES = [25, 50, 100, 200];

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
  wideOnly?: boolean;
  wrap?: boolean;
  width?: string;
  minWidth?: string;
  align?: "start" | "end";
  value?: (row: Row) => unknown;
  render?: (row: Row) => ReactNode;
};

export function DataTable<Row>({
  columns, rows: resultRows, rowKey, sort, onSort, onRowClick, canActivateRow, selectedKey, caption, labelledBy,
  hasMore = false, loadingMore = false, onLoadMore, total: serverTotal, stickyHeader = true, pageScroll = false, pagination: serverPaging, showFooter = true,
  compact, density, expanded, afterRow, renderExpanded, toolbar, toolbarEnd, footerControls, wrapCells = false,
  pageSize: serverPageSize, localPagination, columnSample = resultRows, columnsControlTarget, rowGroup, rowDetail, expandedContent, emptyContent, renderExpandedRow,
}: {
  columns: TableColumn<Row>[];
  rows: Row[];
  rowKey: (row: Row) => string;
  sort?: SortState | null;
  onSort?: (field: string) => void;
  onRowClick?: (row: Row) => void;
  canActivateRow?: (row: Row) => boolean;
  selectedKey?: string | null;
  expandedContent?: (row: Row) => ReactNode;
  rowGroup?: (row: Row) => { key: string; heading: ReactNode; collapsed: boolean };
  rowDetail?: (row: Row) => ReactNode;
  emptyContent?: ReactNode;
  hasMore?: boolean;
  loadingMore?: boolean;
  onLoadMore?: () => void;
  total?: number | null;
  pagination?: TablePagination;
  /** Embedded previews may provide their own count and open-all action. */
  showFooter?: boolean;
  renderExpandedRow?: (row: Row) => ReactNode;
  /** The table scrolls inside a bounded box so the header stays visible; pass false for small embedded tables. */
  stickyHeader?: boolean;
  pageScroll?: boolean;
  renderExpanded?: (row: Row, visibleCells: number) => ReactNode;
  toolbar?: ReactNode;
  toolbarEnd?: ReactNode;
  footerControls?: ReactNode;
  wrapCells?: boolean | "all";
  compact?: boolean;
  density?: "compact" | "comfortable" | "standard";
  expanded?: (row: Row) => ReactNode;
  afterRow?: (row: Row) => ReactNode;
  pageSize?: PageSize;
  /** Use when the caller has loaded the complete filtered result. */
  localPagination?: boolean;
  /** Complete result when the caller handles paging locally. */
  columnSample?: Row[];
  columnsControlTarget?: HTMLElement | null;
} & ({ caption: string; labelledBy?: never } | { caption?: never; labelledBy: string })) {
  const { formatCell } = useDateFormatters();
  const [visibility, setVisibility] = useState<VisibilityState>({});
  const [localSize, setLocalSize] = useState(50);
  const [localPage, setLocalPage] = useState(0);
  const page = Math.min(localPage, Math.max(0, Math.ceil(resultRows.length / localSize) - 1));
  const start = page * localSize;
  const rows = useMemo(() => localPagination ? resultRows.slice(start, start + localSize) : resultRows,
    [localPagination, resultRows, start, localSize]);
  const total = localPagination ? resultRows.length : serverTotal;
  const pageSize = localPagination ? { value: localSize, options: LOCAL_PAGE_SIZES, onChange: (size: number) => {
    setLocalSize(size);
    setLocalPage(0);
  } } : serverPageSize;
  const pagination: TablePagination | undefined = localPagination ? {
    start: start + 1,
    onPrevious: page ? () => setLocalPage(page - 1) : undefined,
    onNext: start + localSize < resultRows.length ? () => setLocalPage(page + 1) : undefined,
  } : serverPaging;
  const dash = t("table.noValue");
  const { content, displayed } = useMemo(() => {
    const isEmpty = (value: unknown) => value == null || typeof value === "boolean" ||
      typeof value === "string" && (value.trim() === "" || value.trim() === dash);
    const content = new Map<Row, Map<string, ReactNode>>();
    const emptyColumns = new Set(columns.map((column) => column.key));
    const renderCell = (column: TableColumn<Row>, row: Row) => column.render ? column.render(row) : formatCell(
      column.value ? column.value(row) : (row as Record<string, unknown>)[column.key], column.kind);
    for (const row of rows) {
      const cells = new Map<string, ReactNode>();
      for (const column of columns) {
        const cell = renderCell(column, row);
        cells.set(column.key, cell);
        if (!isEmpty(cell)) emptyColumns.delete(column.key);
      }
      content.set(row, cells);
    }
    if (columnSample !== rows) {
      for (const column of columns) {
        if (emptyColumns.has(column.key) && columnSample.some((row) => !isEmpty(content.get(row)?.get(column.key) ?? renderCell(column, row)))) {
          emptyColumns.delete(column.key);
        }
      }
    }
    const populated = columnSample.length ? columns.filter((column) => !emptyColumns.has(column.key)) : columns;
    return { content, displayed: populated.length ? populated : columns.slice(0, 1) };
  }, [columns, rows, columnSample, formatCell, dash]);
  const columnVisibility = Object.fromEntries(displayed.map((column) => [column.key, visibility[column.key] ?? !column.hiddenByDefault]));
  const defs = useMemo<ColumnDef<Row>[]>(() => displayed.map((column) => ({
    id: column.key,
    header: column.renderHeader ?? column.label,
    meta: column,
  })), [displayed]);
  const table = useReactTable({
    data: rows, columns: defs, getCoreRowModel: getCoreRowModel(), getRowId: (row) => rowKey(row),
    state: { columnVisibility }, manualSorting: true,
  });
  const toggleable = columns.filter((column) => column.hiddenByDefault !== undefined);
  const visibleRows = table.getRowModel().rows;
  const columnCount = table.getVisibleLeafColumns().length;

  const columnsControl = toggleable.length ? <details className="sli-ds-table__columns">
      <summary className="sli-ds-button">{t("table.columns")}</summary>
      <div role="group" aria-label={t("table.columns")}>
        {toggleable.map((column) => <Checkbox key={column.key} checked={columnVisibility[column.key] ?? false}
          disabled={!displayed.some((item) => item.key === column.key)} onChange={(event) => setVisibility({ ...visibility, [column.key]: event.target.checked })}>{column.label}</Checkbox>)}
      </div>
    </details> : null;
  const columnsMenu = columnsControl && columnsControlTarget ? createPortal(columnsControl, columnsControlTarget) : columnsControl;

  return <div className="sli-ds-table" data-wrap={wrapCells || undefined} data-compact={compact || undefined} data-density={density}>
    {toolbar || toolbarEnd ? <div className="sli-ds-table__toolbar">{toolbar}{columnsMenu}{toolbarEnd}</div> : columnsMenu}
    <div className="sli-ds-table__scroll" data-sticky={stickyHeader && !pageScroll || undefined} data-page-scroll={pageScroll || undefined}>
      <table aria-labelledby={labelledBy} data-responsive={columns.some((column) => column.mobile === false) || undefined}>
        {caption ? <caption className="sli-ds-sr-only">{caption}</caption> : null}
        <thead>{table.getHeaderGroups().map((group) => <tr key={group.id}>{group.headers.map((header) => {
          const column = header.column.columnDef.meta as TableColumn<Row>;
          const active = sort?.field === column.key;
          const ariaSort = active ? (sort?.direction === "asc" ? "ascending" : "descending") : column.sortable && onSort ? "none" : undefined;
          return <th key={header.id} scope="col" data-mobile={column.mobile} data-wide-only={column.wideOnly || undefined} style={{ width: column.width, minWidth: column.minWidth }} data-align={column.align ?? (column.kind === "number" ? "end" : "start")} aria-sort={ariaSort}>
            {column.sortable && onSort
              ? <button type="button" className="sli-ds-table__sort" onClick={() => onSort(column.key)}>
                  {flexRender(header.column.columnDef.header, header.getContext())}
                  <span aria-hidden="true" className="sli-ds-table__sort-mark" data-active={active || undefined}>{active ? (sort?.direction === "asc" ? "↑" : "↓") : "↕"}</span>
                  {active ? <span className="sli-ds-sr-only">, {sort?.direction === "asc" ? t("table.sortAsc") : t("table.sortDesc")}</span> : null}
                </button>
              : flexRender(header.column.columnDef.header, header.getContext())}
          </th>;
        })}</tr>)}</thead>
        <tbody>{visibleRows.map((row, index) => {
          const group = rowGroup?.(row.original);
          const groupStart = group && (index === 0 || rowGroup?.(visibleRows[index - 1].original).key !== group.key);
          const detail = group?.collapsed ? null : rowDetail?.(row.original);
          const inlineContent = group?.collapsed ? null : expandedContent?.(row.original);
          const selected = selectedKey === row.id;
          const visibleCells = row.getVisibleCells();
          const expansion = group?.collapsed ? null : expanded?.(row.original);
          const extra = group?.collapsed ? null : afterRow?.(row.original);
          const activate = canActivateRow?.(row.original) === false ? undefined : onRowClick;
          return <Fragment key={row.id}>
            {groupStart ? <tr data-group><td colSpan={columnCount}>{group.heading}</td></tr> : null}
            {group?.collapsed ? null : <tr data-selected={selected || Boolean(detail) || undefined} data-clickable={activate ? true : undefined}
            tabIndex={activate ? 0 : undefined}
            onClick={activate ? () => activate(row.original) : undefined}
            onKeyDown={activate ? (event) => { if (event.target === event.currentTarget && (event.key === "Enter" || event.key === " ")) { event.preventDefault(); activate(row.original); } } : undefined}
            aria-expanded={renderExpandedRow ? selected : undefined}
            aria-selected={activate && !renderExpandedRow ? selected : undefined}>
            {visibleCells.map((cell) => {
              const column = cell.column.columnDef.meta as TableColumn<Row>;
              const value = content.get(row.original)?.get(column.key);
              const text = isValidElement<{ children?: ReactNode }>(value) && value.type === "a" ? value.props.children : value;
              const title = typeof text === "string" || typeof text === "number" ? String(text) : undefined;
              return <td key={cell.id} data-mobile={column.mobile} data-wide-only={column.wideOnly || undefined}
                data-wrap={column.wrap || undefined} style={{ minWidth: column.minWidth }} title={wrapCells === "all" ? undefined : title}
                data-kind={column.kind} data-empty={value === dash || undefined} data-align={column.align ?? (column.kind === "number" ? "end" : "start")}>{value}</td>;
            })}
          </tr>}
            {expansion ? <tr><td colSpan={columnCount} className="sli-ds-table__expanded">{expansion}</td></tr> : null}
            {extra ? <tr><td colSpan={columnCount}>{extra}</td></tr> : null}
            {detail ? <tr data-detail><td colSpan={columnCount}>{detail}</td></tr> : null}
            {!group?.collapsed && selected && renderExpandedRow ? <tr><td data-wrap colSpan={columnCount}>{renderExpandedRow(row.original)}</td></tr> : null}
            {!group?.collapsed ? renderExpanded?.(row.original, visibleCells.length) : null}
            {inlineContent != null ? <tr className="sli-ds-table__expanded"><td colSpan={columnCount}>{inlineContent}</td></tr> : null}
          </Fragment>;
        })}{!visibleRows.length && emptyContent != null ? <tr><td colSpan={columnCount}>{emptyContent}</td></tr> : null}</tbody>
      </table>
    </div>
    {showFooter ? <Pager pageSize={pageSize} busy={pagination?.busy} onPrevious={pagination?.onPrevious} onNext={pagination?.onNext}
      label={pagination && (pagination.pageLabel ?? (pageSize ? t("table.page", {
        page: Math.floor((pagination.start - 1) / pageSize.value) + 1,
        total: typeof total === "number" ? Math.max(1, Math.ceil(total / pageSize.value)) : dash,
      }) : pagination.label) ?? t("table.range", { from: rows.length ? pagination.start : 0,
        to: rows.length ? pagination.end ?? pagination.start + rows.length - 1 : 0, total: typeof total === "number" ? formatNumber(total) : dash }))}>
      {footerControls}
      {!pagination ? <>
        <span aria-live="polite">{t("table.shown", { count: rows.length })}{typeof total === "number" ? ` ${t("table.of", { total: formatNumber(total) })}` : ""}</span>
        {hasMore && onLoadMore ? <button type="button" className="sli-ds-button" disabled={loadingMore} onClick={onLoadMore}>{loadingMore ? t("table.loadingMore") : t("table.loadMore")}</button> : null}
      </> : null}
    </Pager> : null}
  </div>;
}
