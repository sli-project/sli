import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { EventCardCompletenessBadge, EventClassificationBadge, RiskBadge } from "./Badges";

it("keeps global finding risk separate from event classification and role completeness", () => {
  const html = renderToStaticMarkup(<>
    <RiskBadge value="high" />
    <EventClassificationBadge value="low" origin="catalog_base" />
    <EventCardCompletenessBadge completeness="complete" />
    <EventCardCompletenessBadge completeness="partial" />
    <EventCardCompletenessBadge completeness="not_applicable" />
  </>);

  expect(html).toContain("Риск ИБ: Высокая");
  expect(html).toContain("Класс каталога: низкий");
  expect(html).toContain("Полнота карточки: полная");
  expect(html).toContain("Полнота карточки: частичная");
  expect(html).not.toContain("not_applicable");
});
