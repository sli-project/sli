import type { TableColumn } from "../../design-system";

type Row = Record<string, unknown>;
const present = (value: unknown) => value != null && !["", "-", "—"].includes(String(value).trim());

export function journalColumns(columns: TableColumn<Row>[], rows: Row[]): TableColumn<Row>[] {
  return columns.map((column) => ["participant", "on_behalf"].includes(column.key)
    ? { ...column, hiddenByDefault: !rows.some((row) => present(column.value?.(row) ?? row[column.key])) }
    : column);
}
