import { expect, it } from "vitest";
import { buildChartOption } from "./Chart";
const stamp = "2026-10-08T23:05:00Z";

import * as echarts from "echarts/core";
// ECharts exposes this runtime helper through lib; it is the TooltipView header path.
// @ts-expect-error ECharts internal lib entrypoint has no adjacent declaration.
import { getValueLabel } from "echarts/lib/component/axisPointer/viewHelper.js";
it("formats the actual ECharts tooltip axis value label in the selected zone", () => {
  const colors = { text: "", muted: "", grid: "", palette: [], accent: "", surface: "" };
  const chart = echarts.init(null!, undefined, { renderer: "svg", ssr: true, width: 400, height: 200 });
  try {
    chart.setOption(buildChartOption({ kind: "timeseries", series: [{ name: "n", points: [{ x: stamp, y: 1 }] }] }, colors, "Asia/Novosibirsk"));
    // TooltipView calls getValueLabel with the actual axis and its valueLabelOpt.
    const model = (chart as unknown as { getModel(): { getComponent(type: string): { axis: unknown; getModel(path: string): { get(path: string[]): unknown } } } }).getModel();
    const axis = model.getComponent("xAxis");
    const formatter = axis.getModel("axisPointer").get(["label", "formatter"]);
    expect(getValueLabel(Date.parse(stamp), axis.axis, model, [], { formatter })).toBe("09.10.2026, 06:05");
  } finally { chart.dispose(); }
});

it("shows the chart's empty value for a missing hourly measurement and keeps observed zero", () => {
  const colors = { text: "", muted: "", grid: "", palette: [], accent: "", surface: "" };
  const option = buildChartOption({ kind: "timeseries", series: [{ name: "Failed logons", points: [
    { x: stamp, y: null }, { x: "2026-10-09T00:05:00Z", y: 0 },
  ] }] }, colors, "UTC", "—");
  const [series] = option.series as Array<{
    data: Array<[string, number | null]>;
    tooltip: { valueFormatter: (value: number | null) => string };
  }>;
  expect(series.data.map(([, value]) => series.tooltip.valueFormatter(value))).toEqual(["—", "0"]);
});
