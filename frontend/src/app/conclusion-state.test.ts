import { describe, expect, it } from "vitest";
import type { CompletenessSnapshot } from "../api/client";
import { отсутствующиеКаналы, подписьВывода, причинаНеполноты, разборПолноты, чегоНеХватило } from "./conclusion-state";

const полный: CompletenessSnapshot = {
  captured_at_utc: "2026-07-30T01:00:00+00:00",
  catalog_completeness: { entry_count: 76, fully_classified: 76, classification_ratio: 1, schema_v2_ready: 76 },
  collection_freshness: { max_age_seconds: 120, budget_seconds: 900, complete: true },
  channel_availability: { required: ["Security", "System"], available: ["Security", "System"], required_count: 2, available_count: 2, complete: true },
  window_closure: { window_end_utc: "2026-07-30T00:00:00+00:00", descriptor_close_timeout_seconds: 3600, allowed_lateness_seconds: 300, close_deadline_utc: "2026-07-30T01:05:00+00:00", closed: true },
  supports_negative_conclusion: true,
};

describe("подпись вывода", () => {
  it("три состояния различаются заголовком и тоном", () => {
    expect(подписьВывода("observed").заголовок).toBe("Наблюдалось");
    expect(подписьВывода("not_found").заголовок).toBe("Проверено, не найдено");
    expect(подписьВывода("not_checked").заголовок).toBe("Не проверено");
    const тона = new Set(["observed", "not_found", "not_checked"].map((с) => подписьВывода(с as never).тон));
    expect(тона.size).toBe(3);
  });

  // Отсутствие поля не должно читаться как успешная проверка: сервер мог не
  // прислать состояние, и молчание нельзя толковать в пользу полноты.
  it("отсутствие состояния трактуется как «не проверено»", () => {
    expect(подписьВывода(undefined).заголовок).toBe(подписьВывода("not_checked").заголовок);
  });

  it("«не найдено» и «не проверено» не совпадают ни заголовком, ни пояснением", () => {
    expect(подписьВывода("not_found").заголовок).not.toBe(подписьВывода("not_checked").заголовок);
    expect(подписьВывода("not_found").пояснение).not.toBe(подписьВывода("not_checked").пояснение);
  });
});

describe("разбор полноты", () => {
  it("четыре измерения в порядке серверной проверки", () => {
    expect(разборПолноты(полный).map((и) => и.ключ)).toEqual(["catalog", "freshness", "channels", "window"]);
  });

  it("полный снимок не оставляет нехватки", () => {
    expect(чегоНеХватило(полный)).toEqual([]);
    expect(причинаНеполноты(полный)).toBe("Все четыре измерения полны.");
  });

  // Главное отличие от Coverage: неизмеренное - это не «плохо», это «неизвестно».
  it("не измеренное не выдаётся за неполное", () => {
    const без: CompletenessSnapshot = { ...полный, collection_freshness: { budget_seconds: 900 } };
    const свежесть = разборПолноты(без).find((и) => и.ключ === "freshness");
    expect(свежесть?.состояние).toBe("не измерено");
    expect(свежесть?.подробность).toContain("не измерен");
  });

  it("называет, какого именно измерения не хватило", () => {
    const частичный: CompletenessSnapshot = {
      ...полный,
      channel_availability: { required: ["Security", "System"], available: ["Security"], required_count: 2, available_count: 1, complete: false },
    };
    expect(чегоНеХватило(частичный)).toEqual(["Каналы"]);
    expect(причинаНеполноты(частичный)).toContain("каналы");
    expect(разборПолноты(частичный).find((и) => и.ключ === "channels")?.подробность).toContain("System");
  });

  it("неописанные записи каталога делают измерение неполным", () => {
    const частичный: CompletenessSnapshot = {
      ...полный,
      catalog_completeness: { entry_count: 76, fully_classified: 74, classification_ratio: 0.97, schema_v2_ready: 76 },
    };
    expect(разборПолноты(частичный).find((и) => и.ключ === "catalog")?.состояние).toBe("неполно");
    expect(разборПолноты(частичный).find((и) => и.ключ === "catalog")?.подробность).toContain("74 из 76");
  });

  // Пустой снимок - частый случай: сервер не прислал ничего. Ни одно измерение
  // при этом не должно выглядеть пройденным.
  it("пустой снимок не даёт ни одного полного измерения", () => {
    expect(разборПолноты(undefined).every((и) => и.состояние !== "полно")).toBe(true);
    expect(причинаНеполноты(undefined)).toBe("Снимок полноты не прислан сервером.");
  });
});

describe("отсутствующие каналы", () => {
  it("возвращает требуемые, но недоступные", () => {
    expect(отсутствующиеКаналы({ required: ["A", "B", "C"], available: ["B"] })).toEqual(["A", "C"]);
    expect(отсутствующиеКаналы({ required: ["A"], available: ["A"] })).toEqual([]);
    expect(отсутствующиеКаналы(undefined)).toEqual([]);
  });
});
