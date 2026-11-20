// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { useState } from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SearchMultiSelect, type SearchOption } from "./SearchMultiSelect";

beforeEach(() => {
  // React Aria uses browser APIs that jsdom 25 does not provide.
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("CSS", { ...globalThis.CSS, escape: (value: string) =>
    Array.from(String(value), (character) => `\\${(character.codePointAt(0) || 0xfffd).toString(16)} `).join("") });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
const options: SearchOption[] = Array.from({ length: 1000 }, (_, index) => ({
  value: `share-${index}`, label: `Synthetic server · Share ${String(index).padStart(4, "0")}`, important: index === 900,
}));
function Control() {
  const [values, setValues] = useState<string[]>([]);
  return <SearchMultiSelect label="Shares" options={options} values={values} onChange={setValues}/>;
}

it("searches one thousand shares through one control and shows important shares first", async () => {
  render(<Control/>);
  const user = userEvent.setup();
  const input = screen.getByRole("combobox", { name: "Shares" });
  await user.click(input);
  const suggestions = await screen.findAllByRole("option");
  expect(suggestions).toHaveLength(50);
  expect(suggestions[0].textContent).toContain("Share 0900");
  await user.type(input, "0999");
  await waitFor(() => expect(screen.getAllByRole("option")).toHaveLength(1));
  await user.click(screen.getByRole("option", { name: /Share 0999/ }));
  expect(await screen.findByRole("button", { name: "Убрать Synthetic server · Share 0999" })).toBeTruthy();
  expect(screen.getAllByRole("combobox")).toHaveLength(1);
  await user.click(screen.getByRole("button", { name: "Убрать Synthetic server · Share 0999" }));
  expect(screen.queryByRole("button", { name: /Убрать/ })).toBeNull();
  await user.click(input);
  const afterRemoval = await screen.findAllByRole("option");
  expect(afterRemoval[0].textContent).toContain("Share 0900");
  expect(afterRemoval[1].textContent).toContain("Share 0999");
});

it("supports keyboard selection and never adds the same share twice", async () => {
  const change = vi.fn();
  render(<SearchMultiSelect label="Shares" options={options} values={["share-900"]} onChange={change}/>);
  const user = userEvent.setup();
  await user.click(screen.getByRole("combobox", { name: "Shares" }));
  await user.keyboard("{ArrowDown}{Enter}");
  expect(change).toHaveBeenCalledWith(["share-900", "share-0"]);
  expect(screen.queryByRole("option", { name: /Share 0900/ })).toBeNull();
});

it("keeps the first selection while adding another share", async () => {
  render(<Control/>);
  const user = userEvent.setup();
  const input = screen.getByRole("combobox", { name: "Shares" });
  await user.click(input);
  await user.click(await screen.findByRole("option", { name: /Share 0900/ }));
  expect(await screen.findByRole("button", { name: "Убрать Synthetic server · Share 0900" })).toBeTruthy();
  await user.type(input, "0999");
  await user.click(await screen.findByRole("option", { name: /Share 0999/ }));
  expect(await screen.findByRole("button", { name: "Убрать Synthetic server · Share 0999" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "Убрать Synthetic server · Share 0900" })).toBeTruthy();
});

it("can select the last chosen share again after removing its chip", async () => {
  render(<Control/>);
  const user = userEvent.setup();
  const input = screen.getByRole("combobox", { name: "Shares" });
  await user.click(input);
  await user.click(await screen.findByRole("option", { name: /Share 0900/ }));
  await user.click(await screen.findByRole("button", { name: "Убрать Synthetic server · Share 0900" }));
  await user.click(input);
  await user.click(await screen.findByRole("option", { name: /Share 0900/ }));
  expect(await screen.findByRole("button", { name: "Убрать Synthetic server · Share 0900" })).toBeTruthy();
  expect(screen.getAllByRole("button", { name: /Убрать/ })).toHaveLength(1);
});
