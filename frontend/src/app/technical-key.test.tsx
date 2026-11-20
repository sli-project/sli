// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { TechnicalKey } from "./technical-key";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("keeps the exact identifier in closed details and copies it on demand", async () => {
  const user = userEvent.setup();
  const write = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
  render(<TechnicalKey value="ad:fixture:sid" label="Идентификатор"/>);
  const code = screen.getByText("ad:fixture:sid");
  expect(code.closest("details")?.open).toBe(false);
  expect(write).not.toHaveBeenCalled();
  await user.click(screen.getByText("Идентификатор"));
  await user.click(screen.getByRole("button", { name: "Копировать" }));
  expect(write).toHaveBeenCalledWith("ad:fixture:sid");
  expect(await screen.findByRole("button", { name: "Скопировано" })).toBeTruthy();
});

it("reports clipboard denial and leaves the code available for manual copying", async () => {
  const user = userEvent.setup();
  vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("denied"));
  render(<TechnicalKey value="fixture-key" label="Идентификатор"/>);
  await user.click(screen.getByText("Идентификатор"));
  await user.click(screen.getByRole("button", { name: "Копировать" }));
  expect((await screen.findByRole("status")).textContent).toContain("Не удалось скопировать");
  expect(screen.getByText("fixture-key")).toBeTruthy();
});
