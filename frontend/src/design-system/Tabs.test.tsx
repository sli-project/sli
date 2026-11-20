// @vitest-environment jsdom
import { useState } from "react";
import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Tabs, TabList, TabPanel } from "./Tabs";

afterEach(cleanup);

function Example() {
  const [active, setActive] = useState("one");
  return <Tabs items={[{ key: "one", label: "One" }, { key: "two", label: "Two" }, { key: "three", label: "Three" }]} active={active} onChange={setActive}>
    <TabList label="Views"/><TabPanel>{active}</TabPanel>
  </Tabs>;
}

it("links each tab to the panel and gives only the selected tab a tab stop", () => {
  render(<Example/>);
  const tabs = screen.getAllByRole("tab");
  const panel = screen.getByRole("tabpanel");
  expect(panel.getAttribute("aria-labelledby")).toBe(tabs[0].id);
  for (const [index, tab] of tabs.entries()) {
    expect(tab.getAttribute("aria-controls")).toBe(panel.id);
    expect(tab.tabIndex).toBe(index === 0 ? 0 : -1);
  }
});

it("activates and focuses tabs with arrows, Home and End, wrapping at the ends", async () => {
  render(<Example/>);
  const tabs = screen.getAllByRole("tab");
  tabs[0].focus();
  for (const [key, index] of [["{ArrowLeft}", 2], ["{ArrowRight}", 0], ["{End}", 2], ["{Home}", 0], ["{ArrowRight}", 1]] as const) {
    await userEvent.keyboard(key);
    expect(document.activeElement).toBe(tabs[index]);
    expect(tabs[index].getAttribute("aria-selected")).toBe("true");
    expect(tabs[index].tabIndex).toBe(0);
    expect(screen.getByRole("tabpanel").getAttribute("aria-labelledby")).toBe(tabs[index].id);
  }
});

it("keeps IDs unique when two cards are on the same page", () => {
  render(<><Example/><Example/></>);
  const panels = screen.getAllByRole("tabpanel");
  expect(panels[0].id).not.toBe(panels[1].id);
  const ids = screen.getAllByRole("tab").map((tab) => tab.id);
  expect(new Set(ids).size).toBe(ids.length);
});
