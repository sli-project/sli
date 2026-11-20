// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { OverlayProvider, useOverlays } from ".";

function Harness() {
  const { toast, openDrawer, openModal } = useOverlays();
  return <div>
    <div data-sli-shell>
      <button type="button" onClick={() => toast("Сохранено", "Изменения применены")}>toast</button>
      <button type="button" onClick={(event) => openDrawer({ title: "Основание доступа", eyebrow: "Проверка", body: <p>Тело панели</p> }, event.currentTarget)}>drawer</button>
      <button type="button" onClick={() => openModal({ title: "Подтверждение", body: <input aria-label="Причина"/>, footer: <button type="submit">Готово</button> })}>modal</button>
    </div>
  </div>;
}

const renderHarness = () => render(<OverlayProvider><Harness/></OverlayProvider>);

beforeEach(() => { vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "requestAnimationFrame", "cancelAnimationFrame"] }); });
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("useOverlays", () => {
  it("shows a toast and removes it after its lifetime", () => {
    renderHarness();
    fireEvent.click(screen.getByRole("button", { name: "toast" }));
    expect(screen.getByText("Сохранено")).toBeTruthy();
    act(() => { vi.advanceTimersByTime(4600); });
    expect(screen.queryByText("Сохранено")).toBeNull();
  });

  it("opens a drawer, makes the shell inert and returns focus to the trigger on close", () => {
    renderHarness();
    const trigger = screen.getByRole("button", { name: "drawer" });
    trigger.focus();
    fireEvent.click(trigger);
    expect(screen.getByRole("dialog", { name: "Основание доступа" })).toBeTruthy();
    expect(screen.getByText("Тело панели")).toBeTruthy();
    expect((document.querySelector("[data-sli-shell]") as HTMLElement).inert).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Закрыть" }));
    act(() => { vi.advanceTimersByTime(50); });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect((document.querySelector("[data-sli-shell]") as HTMLElement).inert).toBe(false);
    expect(document.activeElement).toBe(trigger);
  });

  it("closes the drawer on Escape", () => {
    renderHarness();
    fireEvent.click(screen.getByRole("button", { name: "drawer" }));
    expect(screen.getByRole("dialog")).toBeTruthy();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("closes a modal on Escape and returns focus to the trigger", () => {
    renderHarness();
    const trigger = screen.getByRole("button", { name: "modal" });
    trigger.focus();
    fireEvent.click(trigger);
    expect(screen.getByRole("dialog", { name: "Подтверждение" })).toBeTruthy();
    act(() => { vi.advanceTimersByTime(50); });
    expect(document.activeElement).toBe(screen.getByLabelText("Причина"));
    fireEvent.keyDown(document, { key: "Escape" });
    act(() => { vi.advanceTimersByTime(50); });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});
