// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { CardSkeleton, MetricStripSkeleton, ReportLayout, StateView, TableSkeleton } from ".";

afterEach(cleanup);

describe("Skeleton", () => {
  it("StateView loading renders a busy status with the accessible text and a hidden skeleton", () => {
    const { container } = render(<StateView state="loading"/>);
    const status = screen.getByRole("status");
    expect(status.getAttribute("aria-busy")).toBe("true");
    expect(status.textContent).toContain("Загружаем данные");
    expect(container.querySelector(".sli-ds-visually-hidden")?.textContent).toContain("Загружаем данные");
    expect(container.querySelectorAll(".sli-ds-skeleton").length).toBeGreaterThan(0);
    container.querySelectorAll(".sli-ds-skeleton").forEach((node) => expect(node.getAttribute("aria-hidden")).toBe("true"));
  });

  it("StateView picks the placeholder shape", () => {
    const table = render(<StateView state="loading" skeleton="table" compact/>);
    expect(table.container.querySelectorAll("tbody tr").length).toBe(3);
    cleanup();
    const metrics = render(<StateView state="loading" skeleton="metrics"/>);
    expect(metrics.container.querySelectorAll(".sli-ds-metric").length).toBe(4);
  });

  it("TableSkeleton matches the requested geometry and is hidden from assistive tech", () => {
    const { container } = render(<TableSkeleton columns={3} rows={5}/>);
    expect(container.querySelectorAll("thead th").length).toBe(3);
    expect(container.querySelectorAll("tbody tr").length).toBe(5);
    expect(container.firstElementChild?.getAttribute("aria-hidden")).toBe("true");
  });

  it("MetricStripSkeleton and CardSkeleton render the requested number of placeholders", () => {
    const metrics = render(<MetricStripSkeleton count={2}/>);
    expect(metrics.container.querySelectorAll(".sli-ds-metric").length).toBe(2);
    const card = render(<CardSkeleton lines={3}/>);
    expect(card.container.querySelectorAll(".sli-ds-skeleton").length).toBe(4);
  });

  it("ReportLayout shows metric and table skeletons while loading, keeping header and filters", () => {
    const { container } = render(<ReportLayout title="Отчёт" state="loading" filters={<div>фильтры</div>}/>);
    expect(screen.getByText("Отчёт")).toBeTruthy();
    expect(screen.getByText("фильтры")).toBeTruthy();
    expect(screen.getByRole("status").textContent).toContain("Загружаем данные");
    expect(container.querySelectorAll(".sli-ds-metric").length).toBeGreaterThan(0);
    expect(container.querySelectorAll("tbody tr").length).toBeGreaterThan(0);
  });

  it("ReportLayout keeps data visible and marks busy on refetch", () => {
    const { container } = render(<ReportLayout title="Отчёт" busy><p>данные</p></ReportLayout>);
    expect(screen.getByText("данные")).toBeTruthy();
    expect(container.querySelector("section")?.getAttribute("aria-busy")).toBe("true");
    expect(screen.getByRole("progressbar")).toBeTruthy();
    expect(container.querySelector(".sli-ds-skeleton")).toBeNull();
  });
});
