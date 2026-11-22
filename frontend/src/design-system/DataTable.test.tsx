// @vitest-environment jsdom
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { DataTable } from "./DataTable";

afterEach(cleanup);
const rows = [{ id: "one" }, { id: "two" }];
it("renders a page range with previous and next controls and disables navigation while fetching", async () => {
  const previous = vi.fn(), next = vi.fn();
  const props = { columns: [{ key: "id", label: "ID" }], rows, rowKey: (row: { id: string }) => row.id, caption: "Rows", total: 102 };
  const { rerender } = render(<DataTable {...props} pagination={{ start: 51, onPrevious: previous, onNext: next }}/>);
  expect(screen.getByText("51–52 из 102")).toBeTruthy();
  expect(screen.queryByText(/Показано/)).toBeNull();
  await userEvent.click(screen.getByRole("button", { name: "Назад" }));
  await userEvent.click(screen.getByRole("button", { name: "Вперёд" }));
  expect(previous).toHaveBeenCalledOnce(); expect(next).toHaveBeenCalledOnce();
  rerender(<DataTable {...props} pagination={{ start: 51, onPrevious: previous, onNext: next, busy: true }}/>);
  expect((screen.getByRole("button", { name: "Назад" }) as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole("button", { name: "Вперёд" }) as HTMLButtonElement).disabled).toBe(true);
});

it("shows unknown totals explicitly and preserves the existing load-more footer by default", () => {
  const props = { columns: [{ key: "id", label: "ID" }], rows, rowKey: (row: { id: string }) => row.id, caption: "Rows", total: null };
  const { rerender } = render(<DataTable {...props} pagination={{ start: 1 }}/>);
  expect(screen.getByText("1–2 из —")).toBeTruthy();
  rerender(<DataTable {...props} hasMore onLoadMore={vi.fn()}/>);
  expect(screen.queryByText("1–2 из —")).toBeNull();
  expect(screen.getByRole("button", { name: "Показать ещё" })).toBeTruthy();
});

it("updates column defaults when a new page arrives and preserves explicit choices", async () => {
  const props = { rows, rowKey: (row: { id: string }) => row.id, caption: "Rows" };
  const columns = (hiddenByDefault: boolean) => [{ key: "id", label: "ID", hiddenByDefault }];
  const { rerender } = render(<DataTable {...props} columns={columns(false)}/>);
  expect(screen.getByRole("columnheader", { name: "ID" })).toBeTruthy();
  rerender(<DataTable {...props} columns={columns(true)}/>);
  expect(screen.queryByRole("columnheader", { name: "ID" })).toBeNull();
  await userEvent.click(screen.getByText("Колонки"));
  await userEvent.click(screen.getByRole("checkbox", { name: "ID" }));
  expect(screen.getByRole("columnheader", { name: "ID" })).toBeTruthy();
  rerender(<DataTable {...props} columns={columns(true)}/>);
  expect(screen.getByRole("columnheader", { name: "ID" })).toBeTruthy();
});

it("lets an embedded preview supply its own single count and open-all footer", () => {
  const { container } = render(<DataTable columns={[{ key: "id", label: "ID" }]} rows={rows} rowKey={(row) => row.id} caption="Preview" showFooter={false}/>);
  expect(screen.getByRole("table", { name: "Preview" })).toBeTruthy();
  expect(container.querySelector(".sli-ds-table__footer")).toBeNull();
});

it("keeps full names available on text cells and linked cells", () => {
  const name = "A directory account with a name too long to display in a narrow column";
  render(<DataTable columns={[
    { key: "name", label: "Name" },
    { key: "id", label: "Account", render: (row) => <a href="#account">{row.name}</a> },
  ]} rows={[{ id: "sample", name }]} rowKey={(row) => row.id} caption="Accounts"/>);
  expect(screen.getAllByTitle(name)).toHaveLength(2);
  expect(screen.getByRole("link", { name }).closest("td")?.title).toBe(name);
});

it("hides row details and expanded content when their group is collapsed", () => {
  const props = { columns: [{ key: "id", label: "ID" }], rows, rowKey: (row: { id: string }) => row.id, caption: "Grouped rows",
    selectedKey: "one", rowDetail: (row: { id: string }) => row.id === "one" ? "Parameter history" : null,
    renderExpandedRow: () => "Problem observations" };
  const group = (collapsed: boolean) => () => ({ key: "group", heading: "Controllers", collapsed });
  const { rerender } = render(<DataTable {...props} rowGroup={group(false)}/>);
  expect(screen.getByText("one").closest("tr")?.getAttribute("aria-expanded")).toBe("true");
  expect(screen.getByText("Parameter history")).toBeTruthy();
  expect(screen.getByText("Problem observations")).toBeTruthy();
  rerender(<DataTable {...props} rowGroup={group(true)}/>);
  expect(screen.getByText("Controllers")).toBeTruthy();
  expect(screen.queryByText("one")).toBeNull();
  expect(screen.queryByText("Parameter history")).toBeNull();
  expect(screen.queryByText("Problem observations")).toBeNull();
});

it("activates a focused row without intercepting nested link or button keyboard actions", async () => {
  const openRow = vi.fn(), openLink = vi.fn(), pressButton = vi.fn();
  render(<DataTable columns={[{ key: "id", label: "Actions", render: () => <>
    <a href="#evidence" onClick={(event) => { event.preventDefault(); event.stopPropagation(); openLink(); }}>Evidence</a>
    <button onClick={(event) => { event.stopPropagation(); pressButton(); }}>Action</button>
  </> }]} rows={[rows[0]]} rowKey={(row) => row.id} caption="Keyboard rows" onRowClick={openRow}/>);
  const row = screen.getAllByRole("row")[1];
  row.focus();
  await userEvent.keyboard("{Enter} ");
  expect(openRow).toHaveBeenCalledTimes(2);
  openRow.mockClear();
  screen.getByRole("link", { name: "Evidence" }).focus();
  await userEvent.keyboard("{Enter}");
  expect(openLink).toHaveBeenCalledOnce();
  screen.getByRole("button", { name: "Action" }).focus();
  await userEvent.keyboard("{Enter} ");
  expect(pressButton).toHaveBeenCalledTimes(2);
  expect(openRow).not.toHaveBeenCalled();
});
