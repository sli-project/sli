/** @vitest-environment jsdom */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { MetricStrip } from "./MetricStrip";

afterEach(cleanup);

it("links confirmed counts including zero to their population without linking unknowns", () => {
  render(<MetricStrip items={[
    { key: "known", label: "Synthetic count", value: 3, valueHref: "/app/report/synthetic?population=counted" },
    { key: "zero", label: "Synthetic zero", value: 0, valueHref: "/app/report/synthetic?population=empty" },
    { key: "unknown", label: "Synthetic unknown", value: null, valueHref: "/app/report/synthetic" },
  ]}/>);
  expect(screen.getByRole("link", { name: "Synthetic count: 3" }).getAttribute("href")).toBe("/app/report/synthetic?population=counted");
  expect(screen.getByRole("link", { name: "Synthetic zero: 0" }).getAttribute("href")).toBe("/app/report/synthetic?population=empty");
  expect(screen.getAllByRole("link")).toHaveLength(2);
  expect(screen.getByText("Synthetic unknown").closest(".sli-ds-metric")?.querySelector("[data-unknown]")).toBeTruthy();
});

it("preserves filter-toggle behaviour without nesting a population link inside a button", () => {
  const select = vi.fn();
  render(<MetricStrip items={[{ key: "filter", label: "Synthetic filter", value: 3, valueHref: "/app/report/synthetic", onSelect: select }]}/>);
  fireEvent.click(screen.getByRole("button"));
  expect(select).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole("link")).toBeNull();
});
