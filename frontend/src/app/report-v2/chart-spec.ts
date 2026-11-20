import type { ChartSpec } from "../../design-system";
import type { ReportViewDto } from "../../api/report-v2-types";
import { readPath } from "./state";

type Row = Record<string, unknown>;

function label(value: unknown): string {
  return value === null || value === undefined ? "" : String(value);
}

/** Heatmap cells from rows: labels keep the server's row order (it sends the full grid in order). */
function heatmapSpec(view: ReportViewDto, rows: Row[]): ChartSpec {
  const valuePath = view.series?.[0]?.path ?? "value";
  const xLabels: string[] = [];
  const yLabels: string[] = [];
  const cells: Array<{ x: number; y: number; value: number }> = [];
  for (const row of rows) {
    const x = label(readPath(row, view.x ?? "x"));
    const y = label(readPath(row, view.y ?? "y"));
    if (!xLabels.includes(x)) xLabels.push(x);
    if (!yLabels.includes(y)) yLabels.push(y);
    const value = Number(readPath(row, valuePath));
    if (Number.isFinite(value) && value > 0) cells.push({ x: xLabels.indexOf(x), y: yLabels.indexOf(y), value });
  }
  return { kind: "heatmap", data: { xLabels, yLabels, cells } };
}

/** Builds a chart spec from a collection and the view's x/series paths. */
export function chartSpecFor(view: ReportViewDto, rows: Row[]): ChartSpec {
  if (view.chart === "heatmap") return heatmapSpec(view, rows);
  const series = (view.series ?? []).map((item) => ({
    name: item.label,
    points: rows.map((row) => {
      const value = readPath(row, item.path);
      return { x: String(readPath(row, view.x ?? "x") ?? ""), y: typeof value === "number" ? value : value === null || value === undefined || value === "" ? null : Number(value) };
    }),
  }));
  if (view.chart === "bar") return { kind: "bar", series };
  return { kind: "timeseries", series, stacked: view.stacked };
}
