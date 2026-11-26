// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { Select } from "./Select";

afterEach(cleanup);

it("chooses an enabled option with the keyboard and submits its original value", async () => {
  const submit = vi.fn();
  render(<form onSubmit={(event) => {
    event.preventDefault();
    submit(new FormData(event.currentTarget).get("scope"));
  }}>
    <Select label="Scope" name="scope" defaultValue="" required options={[
      { value: "", label: "Choose", disabled: true },
      { value: 7, label: "example.test" },
    ]}/>
    <button type="submit">Save</button>
  </form>);
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(submit).not.toHaveBeenCalled();
  const trigger = screen.getByRole("button", { name: /Scope/ });
  trigger.focus();
  await user.keyboard("{ArrowDown}");
  await screen.findByRole("option", { name: "example.test" });
  await user.keyboard("{Enter}");
  expect(trigger.textContent).toBe("example.test");
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(submit).toHaveBeenCalledWith("7");
});
