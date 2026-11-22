import { useEffect, useMemo, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, HeatmapChart, LineChart, ScatterChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent, VisualMapComponent } from "echarts/components";
import { SVGRenderer } from "echarts/renderers";
import type { EChartsCoreOption } from "echarts/core";
import { t } from "../i18n";
import { useTimeZone } from "../shared/time-zone";
import { formatDateTime } from "./format";
import { formatDateTime as sharedDateTime } from "../shared/date-time";

echarts.use([LineChart, BarChart, HeatmapChart, ScatterChart, GridComponent, TooltipComponent, LegendComponent, VisualMapComponent, SVGRenderer]);

/** One named series of points; `x` is an ISO time (timeseries) or a category. */
export type ChartSeries = { name: string; points: Array<{ x: string; y: number | null }>; style?: "bar" | "line" | "dashed" };
type ChartMarker = { at: string; label: string; severity: "critical" | "high" | "medium" | "low" };
const markerSymbols = { critical: "rect", high: "diamond", medium: "triangle", low: "circle" };
export type HeatmapData = { xLabels: string[]; yLabels: string[]; cells: Array<{ x: number; y: number; value: number }> };

export type ChartSpec =
  | { kind: "timeseries"; series: ChartSeries[]; stacked?: boolean; bars?: boolean; markers?: ChartMarker[]; range?: [string, string] }
  | { kind: "bar"; series: ChartSeries[]; horizontal?: boolean }
  | { kind: "heatmap"; data: HeatmapData };

function token(name: string, fallback: string): string {
  if (typeof document === "undefined") return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  if (!value.startsWith("light-dark(")) return value || fallback;
  const sample = document.createElement("span");
  sample.style.color = value;
  document.body.append(sample);
  const resolved = getComputedStyle(sample).color;
  sample.remove();
  return resolved || fallback;
}

export function chartIsEmpty(spec: ChartSpec): boolean {
  if (spec.kind === "heatmap") return spec.data.cells.length === 0;
  if (spec.kind === "timeseries" && spec.markers?.length) return false;
  return spec.series.every((series) => series.points.every((point) => point.y === null));
}

/** Builds the ECharts option from a spec; pure so it can be unit-tested. */
export function buildChartOption(spec: ChartSpec, colors: { text: string; muted: string; grid: string; palette: string[]; accent: string; surface: string; danger?: string; warning?: string }, timeZone?: string): EChartsCoreOption {
  const base = {
    color: colors.palette,
    textStyle: { color: colors.text, fontFamily: "inherit" },
    tooltip: { trigger: spec.kind === "heatmap" ? "item" : "axis", confine: true, renderMode: "richText" },
    grid: { left: 8, right: 16, top: 32, bottom: 8, containLabel: true },
    animation: false,
  };
  // Multi-series legend: one scrollable row at the top with its own band in the
  // grid, so it never overlaps bars or axis labels (ECharts 6 lays out legends differently).
  const multiSeries = spec.kind !== "heatmap" && spec.series.length > 1;
  const legend = multiSeries
    ? { type: "scroll", top: 0, left: 0, right: 0, itemGap: 20, textStyle: { color: colors.muted }, pageTextStyle: { color: colors.muted } }
    : undefined;
  const legendGrid = multiSeries ? { ...base.grid, top: 40 } : base.grid;
  const axisStyle = { axisLine: { lineStyle: { color: colors.grid } }, axisLabel: { color: colors.muted }, splitLine: { lineStyle: { color: colors.grid } } };
  if (spec.kind === "heatmap") {
    const max = Math.max(1, ...spec.data.cells.map((cell) => cell.value));
    return {
      ...base,
      grid: { ...base.grid, bottom: 48 },
      xAxis: { type: "category", data: spec.data.xLabels, ...axisStyle, splitArea: { show: false } },
      yAxis: { type: "category", data: spec.data.yLabels, inverse: true, ...axisStyle },
      visualMap: { min: 0, max, calculable: false, orient: "horizontal", left: "center", bottom: 0, inRange: { color: [colors.surface, colors.accent] }, textStyle: { color: colors.muted } },
      series: [{ type: "heatmap", data: spec.data.cells.map((cell) => [cell.x, cell.y, cell.value]) }],
    };
  }
  if (spec.kind === "bar") {
    const categories = spec.series[0]?.points.map((point) => point.x) ?? [];
    const category = { type: "category", data: categories, ...axisStyle };
    const value = { type: "value", ...axisStyle };
    return {
      ...base,
      legend,
      grid: legendGrid,
      xAxis: spec.horizontal ? value : category,
      yAxis: spec.horizontal ? category : value,
      series: spec.series.map((series) => ({ type: "bar", name: series.name, data: series.points.map((point) => point.y) })),
    };
  }
  // Calendar days (no time part): one bar per day, labelled by locale; a second
  // series with another magnitude gets its own right-hand axis.
  const days = spec.series[0]?.points.map((point) => point.x) ?? [];
  if (days.length && days.every((x) => /^\d{4}-\d{2}-\d{2}$/.test(x))) {
    const dual = spec.series.length === 2 && !spec.stacked && !spec.series.some((series) => series.style);
    return {
      ...base,
      legend,
      grid: legendGrid,
      xAxis: { type: "category", data: days.map((day) => sharedDateTime(day, "UTC", { withTime: false, withYear: false })), ...axisStyle },
      yAxis: dual ? [{ type: "value", ...axisStyle }, { type: "value", ...axisStyle, splitLine: { show: false } }] : { type: "value", ...axisStyle },
      series: spec.series.map((series, index) => ({
        type: series.style ? series.style === "bar" ? "bar" : "line" : dual && index === 1 ? "line" : "bar",
        lineStyle: series.style === "dashed" ? { type: "dashed" } : undefined, name: series.name, yAxisIndex: dual ? index : 0,
        stack: spec.stacked ? "total" : undefined, showSymbol: false,
        data: series.points.map((point) => point.y),
      })),
    };
  }
  return {
    ...base,
    legend,
    grid: legendGrid,
    xAxis: { type: "time", ...axisStyle, min: spec.range?.[0], max: spec.range?.[1], axisPointer: { label: { formatter: ({ value }: { value: string | number }) => formatDateTime(new Date(value), true, timeZone) } }, axisLabel: { color: colors.muted, formatter: (value: number) => formatDateTime(new Date(value), true, timeZone) } },
    yAxis: { type: "value", ...axisStyle, min: spec.range ? 0 : undefined, minInterval: spec.range ? 1 : undefined },
    series: [...spec.series.map((series) => ({
      type: series.style === "bar" || (!series.style && spec.bars) ? "bar" : "line", name: series.name, showSymbol: false, stack: spec.stacked ? "total" : undefined,
      areaStyle: spec.stacked && !spec.bars ? { opacity: 0.2 } : undefined,
      itemStyle: series.style === "bar" ? { color: colors.muted, opacity: 0.55 }
        : series.style ? { color: series.style === "line" ? colors.text : colors.muted } : undefined,
      lineStyle: series.style === "dashed" ? { type: "dashed", color: colors.muted, width: 2 }
        : series.style === "line" ? { color: colors.text, width: 2 } : undefined,
      data: series.points.map((point) => [point.x, point.y]),
    })), ...(spec.markers?.length ? [{
      type: "scatter", z: 5, symbolSize: 10, symbolOffset: [0, -7], tooltip: { trigger: "item", formatter: "{b}" },
      data: spec.markers.map((marker) => ({ name: marker.label, value: [marker.at, 0], symbol: markerSymbols[marker.severity],
        itemStyle: { color: marker.severity === "critical" || marker.severity === "high" ? colors.danger : marker.severity === "medium" ? colors.warning : colors.muted } })),
    }] : [])],
  };
}

function currentColors() {
  return {
    text: token("--sli-text", "#10213d"),
    muted: token("--sli-text-muted", "#5d6d84"),
    grid: token("--sli-chart-grid", "#e3e9f2"),
    accent: token("--sli-accent", "#0868e8"),
    surface: token("--sli-surface-2", "#f7f9fc"),
    danger: token("--sli-danger", "#b42318"),
    warning: token("--sli-warning", "#9a5b00"),
    palette: [1, 2, 3, 4, 5, 6, 7, 8].map((index) => token(`--sli-chart-${index}`, "#0868e8")),
  };
}

/** The only chart entry point for reports (ADR 0013). */
export function Chart({ title, spec, height = 280, emptyValue }: { title: string; spec: ChartSpec; height?: number | string; emptyValue?: string }) {
  const { timeZone } = useTimeZone();
  const host = useRef<HTMLDivElement | null>(null);
  const empty = useMemo(() => chartIsEmpty(spec), [spec]);

  useEffect(() => {
    if (empty || !host.current) return;
    const instance = echarts.init(host.current, undefined, { renderer: "svg" });
    const render = () => instance.setOption(buildChartOption(spec, currentColors(), timeZone), true);
    render();
    const fit = () => instance.resize();
    const resize = new ResizeObserver(fit);
    resize.observe(host.current);
    window.addEventListener("resize", fit);
    const scheme = window.matchMedia?.("(prefers-color-scheme: dark)");
    scheme?.addEventListener?.("change", render);
    const themeObserver = new MutationObserver(render);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => { window.removeEventListener("resize", fit); resize.disconnect(); themeObserver.disconnect(); scheme?.removeEventListener?.("change", render); instance.dispose(); };
  }, [spec, empty, timeZone]);

  return <figure className="sli-ds-chart">
    <figcaption>{title}</figcaption>
    {empty
      ? <div className="sli-ds-chart__empty" role="status">{emptyValue ?? t("chart.empty")}</div>
      : <div ref={host} className="sli-ds-chart__canvas" style={{ height }} role="img" aria-label={t("chart.label", { title })}/>}
  </figure>;
}
