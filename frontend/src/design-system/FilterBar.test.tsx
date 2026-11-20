// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { FilterBar, type FilterField } from "./FilterBar";

afterEach(cleanup);
it("renders the declared all-domains option once and allows clearing a selected domain", async () => {
  const apply = vi.fn();
  render(<FilterBar fields={[{ key: "domain", label: "Domain", kind: "select", options: [
    { value: "", label: "All accessible domains" }, { value: "7", label: "Synthetic domain" },
  ] }]} values={{ domain: "7" }} onApply={apply}/>);
  const select = screen.getByLabelText("Domain");
  expect(within(select).getAllByRole("option")).toHaveLength(2);
  fireEvent.change(select, { target: { value: "" } });
  await userEvent.click(screen.getByRole("button", { name: "Применить" }));
  expect(apply).toHaveBeenCalledWith({ domain: undefined });
});

it("opts into the shared grid for a wide object field without changing other forms", () => {
  const gridFields: FilterField[] = [
    { key: "period", label: "Period", kind: "period", presets: ["24h", "7d", "30d", "custom"], precision: "datetime-local" },
    { key: "path", label: "Object", kind: "text", wide: true, nested: { key: "nested", label: "Descendants" } },
  ];
  const { rerender } = render(<FilterBar fields={gridFields} layout="grid" primaryKeys={["period", "path"]}
    values={{ nested: "true" }} onApply={vi.fn()}/>);
  const field = screen.getByLabelText("Object").closest(".sli-ds-field")!;
  expect(field.getAttribute("data-wide")).toBe("true");
  expect(field.parentElement?.getAttribute("data-layout")).toBe("grid");
  expect(screen.getByLabelText("Descendants").closest(".sli-ds-field")).toBe(field);
  expect(screen.queryByText("Ещё фильтры")).toBeNull();
  rerender(<FilterBar fields={gridFields} values={{}} onApply={vi.fn()}/>);
  expect(screen.getByLabelText("Object").closest(".sli-ds-filters__fields")?.hasAttribute("data-layout")).toBe(false);
});

it("applies a path and its descendant setting together and resets both", async () => {
  const apply = vi.fn();
  render(<FilterBar fields={[{ key: "path", label: "Object", kind: "text", nested: { key: "nested", label: "Descendants" } }]}
    values={{ nested: "true" }} defaults={{ nested: "true" }} onApply={apply}/>);
  fireEvent.change(screen.getByLabelText("Object"), { target: { value: "C:\\Synthetic\\Folder" } });
  await userEvent.click(screen.getByLabelText("Descendants"));
  expect(apply).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Применить" }));
  expect(apply).toHaveBeenCalledWith({ path: "C:\\Synthetic\\Folder", nested: "false" });
  await userEvent.click(screen.getByRole("button", { name: "Сбросить" }));
  expect(apply).toHaveBeenLastCalledWith({ nested: "true" });
});
const fields: FilterField[] = [
  { key: "q", label: "Search", kind: "text" },
  { key: "os", label: "OS", kind: "text" },
  { key: "type", label: "Type", kind: "select", options: [{ value: "server", label: "Server" }] },
];

it("folds additional filters while retaining one draft and one apply action", async () => {
  const apply = vi.fn();
  render(<FilterBar fields={fields} primaryKeys={["q"]} values={{}} onApply={apply}/>);
  const more = screen.getByText("Ещё фильтры").closest("details")!;
  expect(more.open).toBe(false);
  expect(within(more).getByLabelText("OS")).toBeTruthy();
  expect(more.contains(screen.getByLabelText("Search"))).toBe(false);
  await userEvent.click(screen.getByText("Ещё фильтры"));
  await userEvent.type(screen.getByLabelText("Search"), "sample");
  await userEvent.type(screen.getByLabelText("OS"), "sample-os");
  await userEvent.click(screen.getByRole("button", { name: "Применить" }));
  expect(apply).toHaveBeenCalledWith({ q: "sample", os: "sample-os" });
});

it("opens active additional filters from the URL, presets and draft edits", () => {
  const { rerender } = render(<FilterBar fields={fields} primaryKeys={["q"]} values={{ type: "server" }} onApply={vi.fn()}/>);
  const more = screen.getByText(/Ещё фильтры/).closest("details")!;
  expect(more.open).toBe(true);
  rerender(<FilterBar fields={fields} primaryKeys={["q"]} values={{}} onApply={vi.fn()}/>);
  fireEvent.change(screen.getByLabelText("OS"), { target: { value: "sample-os" } });
  expect(more.open).toBe(true);
});

it("does not expand for declared defaults and preserves the form without grouping", () => {
  const { rerender } = render(<FilterBar fields={fields} primaryKeys={["q"]} values={{ os: "default-os" }} defaults={{ os: "default-os" }} onApply={vi.fn()}/>);
  expect(screen.getByText("Ещё фильтры").closest("details")!.open).toBe(false);
  rerender(<FilterBar fields={fields} values={{}} onApply={vi.fn()}/>);
  expect(screen.queryByText("Ещё фильтры")).toBeNull();
  expect(screen.getByLabelText("OS")).toBeTruthy();
});

it("keeps the additional block reachable when it holds only additionalContent", () => {
  render(<FilterBar fields={fields.filter((field) => field.key === "q")} primaryKeys={["q"]} additionalContent={<span>extra-content</span>} values={{}} onApply={vi.fn()}/>);
  const more = screen.getByText("Ещё фильтры").closest("details")!;
  expect(more.open).toBe(false);
  expect(within(more).getByText("extra-content")).toBeTruthy();
});

it("renders quickFilters above the additional block and does not open it by itself", async () => {
  render(<FilterBar fields={fields} primaryKeys={["q"]} quickFilters={<button type="button">quick-one</button>} values={{ os: "sample-os" }} onApply={vi.fn()}/>);
  const quick = screen.getByText("quick-one");
  const more = screen.getByText(/Ещё фильтры/).closest("details")!;
  expect(quick.compareDocumentPosition(more) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(more.contains(quick)).toBe(false);
  expect(more.open).toBe(false);
  await userEvent.click(quick);
  expect(more.open).toBe(false);
});

it("keeps inline search outside additional filters and applies their draft together", async () => {
  const apply = vi.fn();
  render(<FilterBar fields={fields} layout="inline" primaryKeys={["q"]} values={{}} onApply={apply}/>);
  const search = screen.getByRole("searchbox", { name: "Search" });
  const additional = screen.getByText("Ещё фильтры").closest("details")!;
  expect(additional.open).toBe(false);
  expect(screen.getByRole("button", { name: "Применить", hidden: true }).closest("details")).toBe(additional);
  expect(additional.contains(search)).toBe(false);
  await userEvent.click(screen.getByText("Ещё фильтры"));
  fireEvent.change(search, { target: { value: "synthetic" } });
  fireEvent.change(screen.getByLabelText("Type"), { target: { value: "server" } });
  expect(apply).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Применить" }));
  expect(apply).toHaveBeenCalledWith({ q: "synthetic", type: "server" });
});
