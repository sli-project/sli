// @vitest-environment jsdom
import css from "./ds.css?raw";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { Badge, Button } from "./Primitives";
import { Badge as AdminBadge } from "../app/admin/gate";
import { DetailDrawer } from "./DetailDrawer";

afterEach(cleanup);

it("uses the same badge in administrative controls", () => {
  expect(AdminBadge).toBe(Badge);
  render(<AdminBadge tone="danger">Синтетическое предупреждение</AdminBadge>);
  expect(screen.getByText("Синтетическое предупреждение").getAttribute("data-tone")).toBe("danger");
});

it("preserves a long button label, submit semantics and the callback", async () => {
  const click = vi.fn();
  const label = "Применить выбранные параметры с дополнительными ограничениями источников";
  render(<Button type="submit" variant="primary" onClick={click}>{label}</Button>);
  const button = screen.getByRole("button", { name: label });
  expect(button.getAttribute("type")).toBe("submit");
  expect(button.getAttribute("data-variant")).toBe("primary");
  await userEvent.click(button);
  expect(click).toHaveBeenCalledOnce();
});

it.each([false, true])("keeps initial %s-direction Tab inside the drawer and ignores hidden controls", async (reverse) => {
  const view = render(<><button>Внешнее действие</button><DetailDrawer open title="Синтетическая карточка" onClose={() => undefined}>
    <div hidden><button>Скрытое действие</button></div><Button>Последнее действие</Button>
  </DetailDrawer></>);
  const dialog = screen.getByRole("dialog");
  expect(document.activeElement).toBe(dialog);
  await userEvent.tab({ shift: reverse });
  expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: reverse ? "Последнее действие" : "Закрыть" }));
  await userEvent.tab({ shift: !reverse });
  expect(document.activeElement).toBe(within(dialog).getByRole("button", { name: reverse ? "Закрыть" : "Последнее действие" }));
  view.unmount();
});

it("restores focus to the connected drawer trigger", () => {
  const trigger = document.createElement("button");
  document.body.append(trigger);
  trigger.focus();
  const view = render(<DetailDrawer open title="Синтетическая карточка" onClose={() => undefined}>Сведения</DetailDrawer>);
  view.rerender(<DetailDrawer open={false} title="Синтетическая карточка" onClose={() => undefined}>Сведения</DetailDrawer>);
  expect(document.activeElement).toBe(trigger);
  trigger.remove();
});

it("keeps wrapping and focus rules in shared scoped CSS", () => {
  // CSS contract only. Actual geometry belongs to the manual browser gate.
  expect(css, "Vite raw import must preserve the shared CSS source").not.toBe("");
  expect(css).toMatch(/\.sli-ds-button, \.sli-ds-chip \{[^}]*max-width: 100%;[^}]*white-space: normal;[^}]*overflow-wrap: anywhere/);
  expect(css).toMatch(/\.sli-ds-drawer__body \{[^}]*min-height: 0;[^}]*min-width: 0;[^}]*overflow-y: auto/);
  expect(css).toMatch(/:where\(#root\) :focus-visible \{ outline: var\(--sli-focus-width\)/);
  expect(css).toMatch(/\.sli-ds-field__error[^}]*overflow-wrap: anywhere/);
  expect(css).toMatch(/grid-template-rows: minmax\(var\(--sli-topbar-height\), auto\)/);
  expect(css).toMatch(/@media \(max-width: 480px\)[\s\S]*?\.sli-ds-shell__search \{ order: 1; flex-basis: 100%; max-width: none/);
});
