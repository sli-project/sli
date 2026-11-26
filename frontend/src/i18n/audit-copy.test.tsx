// @vitest-environment jsdom
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StateView } from "../design-system/StateView";
import { CollectionView } from "../app/report-v2/views";
import { reportEmptyText } from "../app/report-v2/empty-copy";
import { objectTypeLabel, roleLabel } from "../app/report-labels";
import { setupStepPresentation } from "../app/admin/setup-presentation";
import type { ReportDefinitionDto, ReportResultDto } from "../api/report-v2-types";
import type { SetupStatus } from "../api/client";
import { localizeByteSize } from "../shared/byte-size";
import { localeRuntime, setLocale, t } from "./index";
import { fixedText } from "./fixed-text";
import { localizeReportCatalog, localizeReportDefinition, localizeReportResult, reportText } from "./report-metadata";

beforeEach(() => { vi.spyOn(localeRuntime, "reload").mockImplementation(() => undefined); });
afterEach(() => { setLocale("ru"); vi.restoreAllMocks(); });

describe("audit empty states", () => {
  it("uses section detail instead of generic filter advice, retaining the fallback and nonempty state copy", () => {
    const detail = t("entities.section.events.empty");
    const html = renderToStaticMarkup(<StateView state="empty" detail={detail}/>);
    expect(html).toContain(detail);
    expect(html).not.toContain(t("state.empty.text"));
    expect(renderToStaticMarkup(<StateView state="empty"/>)).toContain(t("state.empty.text"));
    expect(renderToStaticMarkup(<StateView state="partial" detail="Synthetic detail"/>)).toContain(t("state.partial.text"));
  });

  it("explains findings, changes, quality and empty charts separately in both languages", () => {
    for (const locale of ["ru", "en"] as const) {
      setLocale(locale);
      const texts = ["semantic", "changes", "quality", "table"].map((source) => reportEmptyText({ kind: "table", key: source, source, title: "View" }, "Report"));
      texts.push(reportEmptyText({ kind: "chart", key: "daily", title: "Daily" }, "Report"));
      expect(new Set(texts).size).toBe(5);
      const html = renderToStaticMarkup(<CollectionView view={{ kind: "chart", key: "daily", title: "Daily", chart: "timeseries" }} reportTitle="Report" rows={[]}/>);
      expect(html).toContain(locale === "en" ? "no observations" : "нет наблюдений");
      expect(html).not.toContain("sli-ds-chart");
    }
  });
});

describe("audited English presentation", () => {
  it("translates all audited report titles and UI metadata while preserving data and query values", () => {
    setLocale("en");
    const titles = ["Состояние Active Directory", "Входы на компьютеры", "Компьютеры", "Журнал событий", "Групповые политики", "Изменения в домене", "Очередь проблем", "Пользователи", "VPN-доступ и актуальность владельцев", "VPN-подключения"];
    for (const title of titles) expect(reportText(title)).not.toMatch(/[А-Яа-яЁё]/);
    const raw: ReportDefinitionDto = {
      key: "security.events.chains", title: "Изменения в домене", description: "События безопасности контроллеров домена: блокировки, изменения учётных записей и групп, пароли, аудит.", section: "investigation", archetype: "investigation-evidence",
      params: [{ key: "domain", kind: "domain", label: "Домен", options: [{ value: "1", label: "Политика" }] }, { key: "category", kind: "choice", label: "Показывать", options: [{ value: "authentication", label: "Все события" }] }],
      columns: [{ key: "outcome", label: "Состояние", kind: "state", path: "state", labels: { success: "Включена" } }],
      views: [{ key: "semantic", kind: "table", title: "Связанные находки", note: "Пустой результат не доказывает, что источник собран полностью." }],
      detail: { kind: "inline", key: "id", title: "Исходное событие", columns: [], row_links: [] }, row_key: "id", export: false, limits: { default: 10, max: 10 },
      presets: [{ label: "Блокировки учётных записей", params: { family: "lockout" } }], row_links: [{ label: "Карточка события", href: "/app/events/{id}" }],
      filter_options: { domain: [{ value: "1", label: "Политика" }] },
    };
    const localized = localizeReportDefinition(raw);
    expect(localized.title).toBe("Domain changes");
    expect(localized.params[1].options?.[0]).toEqual({ value: "authentication", label: "Authentication" });
    expect(localized.columns[0].labels?.success).toBe("Success");
    expect(localized.params[0].options).toBe(raw.params[0].options);
    expect(localized.filter_options).toBe(raw.filter_options);
    expect(localized.presets[0].params).toBe(raw.presets[0].params);
    expect(localized.row_links[0].href).toBe(raw.row_links[0].href);
    expect(raw.title).toBe("Изменения в домене");
    const result = { report_key: "ad.computers.v6", metrics: [{ key: "all", label: "Всего в AD", value: 3 }], limitations: [{ code: "source", text: "Пустой результат не доказывает, что источник собран полностью." }], items: [{ name: "Политика", description: "Описание" }], collections: { objects: [{ title: "Изменения" }] }, filter_options: raw.filter_options } as unknown as ReportResultDto;
    const translatedResult = localizeReportResult(result);
    expect(translatedResult.metrics[0].label).toBe("Total in AD");
    expect(translatedResult.limitations[0].text).not.toMatch(/[А-Яа-яЁё]/);
    expect(translatedResult.items).toBe(result.items);
    expect(translatedResult.collections).toBe(result.collections);
    expect(translatedResult.filter_options).toBe(result.filter_options);
    const catalog = localizeReportCatalog({ contract_id: "sli.report-catalog.v2", items: [{ key: "security.events.chains", title: raw.title, description: raw.description, section: "reports/identity", section_title: "Учётные записи и AD", executable: false }] });
    expect(catalog.items[0].section_title).toBe("Accounts and AD");
    expect(catalog.items[0].executable).toBe(false);
  });

  it("translates roles and known explanations, leaving unknown server text intact", () => {
    setLocale("en");
    expect(objectTypeLabel("ad_computer")).toBe("AD computer");
    expect(roleLabel("admin")).toBe("administrator");
    expect(fixedText("Данные сильно устарели", "operations.source.fixed.")).toBe("Data is severely outdated");
    expect(fixedText("Снимок и событие являются разными типами факта", "entities.fixed.")).not.toMatch(/[А-Яа-яЁё]/);
    expect(fixedText("Синтетическое описание", "entities.fixed.")).toBe("Синтетическое описание");
    expect(t("security.scenarios.completeness.incomplete")).toBe("incomplete");
    expect(t("security.scenarios.semantic_layer")).toBe("Semantic layer");
  });

  it("localizes byte units without changing the values", () => {
    setLocale("en");
    expect(localizeByteSize("44.5 ГБ")).toBe("44.5 GB");
    expect(localizeByteSize("331.2 МБ")).toBe("331.2 MB");
    expect(localizeByteSize("2 Б")).toBe("2 B");
    expect(localizeByteSize(undefined)).toBeUndefined();
    expect(localizeByteSize("Описание ГБ")).toBe("Описание ГБ");
  });

  it("localizes known setup steps using structured state and preserves identifiers and values", () => {
    setLocale("en");
    const status = { report_domain: { source: "database", value: "synthetic.invalid" }, domains: [{}], domain_controllers: [{ enabled: true }, { enabled: false }], sources: [{}], collection: null } as SetupStatus;
    for (const id of ["report-domain", "domains", "domain-controllers", "sources", "first-collection"]) {
      const original = { id, title: "Синтетический заголовок", state: "done" as const, summary: "Синтетическое описание", link: "/setup" };
      const step = setupStepPresentation(original, status);
      expect(step.title).not.toMatch(/[А-Яа-яЁё]/);
      expect(step.summary).not.toMatch(/[А-Яа-яЁё]/);
      expect(step.link).toBe("/setup");
      if (id === "domain-controllers") expect(step.summary).toContain("1");
      if (id === "report-domain") expect(step.summary).toContain("synthetic.invalid");
      expect(original.title).toBe("Синтетический заголовок");
      expect(setupStepPresentation({ ...original, state: "unavailable" }, status).summary).toContain("unavailable");
    }
  });
});
