// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  buildChartOption, Chart, chartIsEmpty, DataTable, DetailDrawer, FactList, FilterBar, MetricStrip,
  periodBounds, ReportLayout, StateView, type FilterField, type TableColumn,
} from ".";

afterEach(cleanup);

type Row = { id: string; name: string; count: number; last: string | null };
const rows: Row[] = [
  { id: "1", name: "dc01", count: 1200, last: "2026-09-01T10:00:00Z" },
  { id: "2", name: "ws-17", count: 3, last: null },
];
const columns: TableColumn<Row>[] = [
  { key: "name", label: "Имя", sortable: true },
  { key: "count", label: "События", kind: "number", sortable: true },
  { key: "last", label: "Последний вход", kind: "datetime", hiddenByDefault: false },
];

describe("StateView", () => {
  it("renders nothing for ok and an alert for denied", () => {
    const { container } = render(<StateView state="ok"/>);
    expect(container.innerHTML).toBe("");
    render(<StateView state="denied"/>);
    expect((screen.getByRole("alert")).textContent).toContain("Нет доступа");
  });

  it("offers retry only for unavailable", async () => {
    const retry = vi.fn();
    render(<StateView state="unavailable" onRetry={retry}/>);
    await userEvent.click(screen.getByRole("button", { name: "Повторить" }));
    expect(retry).toHaveBeenCalledOnce();
  });

  it("never renders partial data as empty", () => {
    render(<StateView state="partial" detail="DC2 не ответил"/>);
    const status = screen.getByRole("status");
    expect((status).textContent).toContain("Доступна часть данных");
    expect(status.getAttribute("data-state")).toBe("partial");
    expect(status.classList.contains("sli-ds-state--banner")).toBe(false);
    expect((status).textContent).toContain("DC2 не ответил");
    expect((status).textContent).not.toContain("Ничего не найдено");
  });
});

describe("MetricStrip", () => {
  it("shows an unknown value as a dash, not zero, and toggles a filter tile", async () => {
    const select = vi.fn();
    render(<MetricStrip items={[
      { key: "a", label: "Всего", value: 1200 },
      { key: "b", label: "Неизвестно", value: null },
      { key: "c", label: "Отключены", value: 5, onSelect: select, active: true },
    ]}/>);
    expect(screen.getByText("1 200")).toBeTruthy();
    expect(screen.getByText("—")).toBeTruthy();
    const tile = screen.getByRole("button", { name: /Отключены/ });
    expect(tile.getAttribute("aria-pressed")).toBe("true");
    await userEvent.click(tile);
    expect(select).toHaveBeenCalledOnce();
  });
});

describe("DataTable", () => {
  it("applies an optional minimum width to both the header and body cells", () => {
    render(<DataTable caption="t" columns={[
      { key: "name", label: "Имя", width: "40%", minWidth: "var(--sli-field-max-width)" },
      { key: "count", label: "События" },
    ]} rows={rows} rowKey={(row) => row.id}/>);
    const header = screen.getByRole("columnheader", { name: "Имя" });
    expect(header.style.width).toBe("40%");
    expect(header.style.minWidth).toBe("var(--sli-field-max-width)");
    for (const row of rows) {
      expect(screen.getByText(row.name).closest("td")!.style.minWidth).toBe(header.style.minWidth);
    }
    expect(screen.getByRole("columnheader", { name: "События" }).style.minWidth).toBe("");
    expect(screen.getByText("1200").closest("td")!.style.minWidth).toBe("");
  });

  it("renders formatted cells and explicit dashes for missing values", () => {
    render(<DataTable caption="Компьютеры" columns={columns} rows={rows} rowKey={(row) => row.id}/>);
    const table = screen.getByRole("table", { name: "Компьютеры" });
    expect(within(table).getByText("1 200")).toBeTruthy();
    expect(within(table).getAllByText("—").length).toBeGreaterThan(0);
    expect(screen.getByText(/Показано: 2/)).toBeTruthy();
  });

  it("delegates sorting to the server and exposes aria-sort", async () => {
    const onSort = vi.fn();
    render(<DataTable caption="t" columns={columns} rows={rows} rowKey={(row) => row.id} sort={{ field: "count", direction: "desc" }} onSort={onSort}/>);
    const header = screen.getByRole("columnheader", { name: /События/ });
    expect(header.getAttribute("aria-sort")).toBe("descending");
    await userEvent.click(within(header).getByRole("button"));
    expect(onSort).toHaveBeenCalledWith("count");
    expect(within(header).getByRole("button").textContent).toContain("↓");
    const other = screen.getByRole("columnheader", { name: /Имя/ });
    expect(other.getAttribute("aria-sort")).toBe("none");
    expect(within(other).getByRole("button").textContent).toContain("↕");
  });

  it("shows the ascending arrow and keeps the scroll box sticky by default", () => {
    const { container, rerender } = render(<DataTable caption="t" columns={columns} rows={rows} rowKey={(row) => row.id} sort={{ field: "name", direction: "asc" }} onSort={() => undefined}/>);
    const header = screen.getByRole("columnheader", { name: /Имя/ });
    expect(header.getAttribute("aria-sort")).toBe("ascending");
    expect(within(header).getByRole("button").textContent).toContain("↑");
    expect(container.querySelector(".sli-ds-table__scroll")!.getAttribute("data-sticky")).toBe("true");
    rerender(<DataTable caption="t" columns={columns} rows={rows} rowKey={(row) => row.id} stickyHeader={false}/>);
    expect(container.querySelector(".sli-ds-table__scroll")!.hasAttribute("data-sticky")).toBe(false);
  });

  it("opens a row by click and by keyboard", async () => {
    const open = vi.fn();
    render(<DataTable caption="t" columns={columns} rows={rows} rowKey={(row) => row.id} onRowClick={open}/>);
    const row = screen.getByText("ws-17").closest("tr")!;
    await userEvent.click(row);
    row.focus();
    await userEvent.keyboard("{Enter}");
    expect(open).toHaveBeenCalledTimes(2);
    expect(open).toHaveBeenLastCalledWith(rows[1]);
  });

  it("lets the user hide an optional column", async () => {
    render(<DataTable caption="t" columns={columns} rows={rows} rowKey={(row) => row.id}/>);
    expect(screen.getByRole("columnheader", { name: "Последний вход" })).toBeTruthy();
    await userEvent.click(screen.getByLabelText("Последний вход"));
    expect(screen.queryByRole("columnheader", { name: "Последний вход" })).toBeNull();
  });

  it("loads more only while the server says there is more", async () => {
    const more = vi.fn();
    const { rerender } = render(<DataTable caption="t" columns={columns} rows={rows} rowKey={(row) => row.id} hasMore onLoadMore={more} total={40}/>);
    expect(screen.getByText(/из 40/)).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Показать ещё" }));
    expect(more).toHaveBeenCalledOnce();
    rerender(<DataTable caption="t" columns={columns} rows={rows} rowKey={(row) => row.id} hasMore={false} onLoadMore={more}/>);
    expect(screen.queryByRole("button", { name: "Показать ещё" })).toBeNull();
  });
});

describe("FilterBar", () => {
  const fields: FilterField[] = [
    { key: "q", label: "Поиск по имени", kind: "text" },
    { key: "os", label: "ОС", kind: "select", options: [{ value: "win11", label: "Windows 11", count: 12 }] },
    { key: "period", label: "Период", kind: "period" },
  ];

  it("keeps edits in a draft until applied", async () => {
    const apply = vi.fn();
    render(<FilterBar fields={fields} values={{ period: { preset: "30d" } }} onApply={apply}/>);
    await userEvent.type(screen.getByLabelText("Поиск по имени"), "dc");
    await userEvent.selectOptions(screen.getByLabelText("ОС"), "win11");
    await userEvent.click(screen.getByRole("radio", { name: "7 дней" }));
    expect(apply).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Применить" }));
    expect(apply).toHaveBeenCalledWith({ q: "dc", os: "win11", period: { preset: "7d" } });
  });

  it("counts active filters and resets to defaults", async () => {
    const apply = vi.fn();
    render(<FilterBar fields={fields} values={{ q: "dc", os: "win11" }} defaults={{ period: { preset: "30d" } }} onApply={apply}/>);
    expect(screen.getByText("Активно: 2")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Сбросить" }));
    expect(apply).toHaveBeenCalledWith({ period: { preset: "30d" } });
  });
});

describe("periodBounds", () => {
  it("resolves presets relative to now and rejects inverted custom ranges", () => {
    const now = new Date("2026-09-29T12:00:00Z");
    expect(periodBounds({ preset: "24h" }, now)).toEqual({ from: "2026-09-28T12:00:00.000Z", to: "2026-09-29T12:00:00.000Z" });
    expect(periodBounds({ preset: "custom", from: "2026-09-10", to: "2026-09-01" }, now)).toBeNull();
    expect(periodBounds({ preset: "custom", from: "2026-09-01" }, now)).toBeNull();
  });
});

describe("DetailDrawer", () => {
  it("is a labelled modal dialog that closes on Escape", async () => {
    const close = vi.fn();
    render(<DetailDrawer open title="dc01" onClose={close}><FactList facts={[{ label: "ОС", value: "Windows Server 2022" }, { label: "IP", value: null }]}/></DetailDrawer>);
    const dialog = screen.getByRole("dialog", { name: "dc01" });
    expect(within(dialog).getByText("Windows Server 2022")).toBeTruthy();
    expect(within(dialog).getByText("—")).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(close).toHaveBeenCalledOnce();
  });

  it("renders nothing when closed", () => {
    render(<DetailDrawer open={false} title="x" onClose={() => {}}>body</DetailDrawer>);
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("ReportLayout", () => {
  it("hides metrics and filters for a denied report", () => {
    render(<ReportLayout title="Компьютеры" state="denied" metrics={<div>metrics</div>} filters={<div>filters</div>}>rows</ReportLayout>);
    expect(screen.queryByText("metrics")).toBeNull();
    expect(screen.queryByText("filters")).toBeNull();
    expect(screen.queryByText("rows")).toBeNull();
    expect((screen.getByRole("alert")).textContent).toContain("Нет доступа");
  });

  it("shows a partial banner above the data instead of replacing it", () => {
    render(<ReportLayout title="Компьютеры" state="partial" stateDetail="1 из 2 доменов">rows</ReportLayout>);
    expect(screen.getByText("rows")).toBeTruthy();
    expect((screen.getByRole("status")).textContent).toContain("1 из 2 доменов");
    expect((screen.getByRole("heading", { level: 1 })).textContent).toContain("Компьютеры");
  });
});

describe("Chart", () => {
  const colors = { text: "#000", muted: "#555", grid: "#eee", accent: "#00f", surface: "#fff", palette: ["#111", "#222"] };

  it("builds a timeseries option with one line per series", () => {
    const option = buildChartOption({ kind: "timeseries", series: [
      { name: "Входы", points: [{ x: "2026-09-01T00:00:00Z", y: 3 }] },
      { name: "Отказы", points: [{ x: "2026-09-01T00:00:00Z", y: 1 }] },
    ] }, colors) as { series: Array<{ type: string; name: string }> };
    expect(option.series.map((series) => [series.type, series.name])).toEqual([["line", "Входы"], ["line", "Отказы"]]);
  });

  it("scales the heatmap to the observed maximum", () => {
    const option = buildChartOption({ kind: "heatmap", data: { xLabels: ["0", "1"], yLabels: ["Пн"], cells: [{ x: 0, y: 0, value: 7 }, { x: 1, y: 0, value: 2 }] } }, colors) as { visualMap: { max: number } };
    expect(option.visualMap.max).toBe(7);
  });

  it("treats all-null series as empty and shows a message instead of a canvas", () => {
    const spec = { kind: "timeseries" as const, series: [{ name: "x", points: [{ x: "2026-09-01", y: null }] }] };
    expect(chartIsEmpty(spec)).toBe(true);
    render(<Chart title="Активность" spec={spec}/>);
    expect((screen.getByRole("status")).textContent).toContain("Нет данных для графика");
    expect(screen.queryByRole("img")).toBeNull();
  });
});
