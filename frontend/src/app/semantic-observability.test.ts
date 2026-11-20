import { describe, expect, it } from "vitest";
import type { CatalogCompleteness, SemanticQueueOverview } from "../api/client";
import {
  вердиктКонтура, короткоОКаталоге,
  возрастСловами, недообъявленныеПоля, сводкаКаталога, сводкаОчередей, строкаТревожная, строкиПоВажности,
} from "./semantic-observability";

const пустаяОпрошенная: SemanticQueueOverview = { status: "ok", contains_event_payload: false, items: [] };
const неопрошенная: SemanticQueueOverview = { status: "unavailable", error_type: "OperationalError", items: [] };

const рабочая: SemanticQueueOverview = {
  status: "ok",
  items: [
    { queue_name: "processing", queue_status: "queued", depth: 12, retries: 3, expired_leases: 0, oldest_ready_age_seconds: 420 },
    { queue_name: "risk", queue_status: "queued", depth: 4, retries: 0, expired_leases: 0, oldest_ready_age_seconds: 60 },
  ],
};

/**
 * Ровно то, что вернул рабочий стенд 30.07.2026: обе очереди завершены,
 * ожидающих нет. Первая версия складывала `depth` по всем строкам и показывала
 * «560 в очереди» рядом с «ожидающих нет».
 */
const завершённая: SemanticQueueOverview = {
  status: "ok",
  items: [
    { queue_name: "risk", queue_status: "completed", depth: 420, retries: 32, expired_leases: 0, oldest_ready_age_seconds: 0 },
    { queue_name: "processing", queue_status: "completed", depth: 140, retries: 0, expired_leases: 0, oldest_ready_age_seconds: 0 },
  ],
};

describe("сводка очередей", () => {
  it("задания с удалённым источником закрыты без принятия событий", () => {
    const обзор: SemanticQueueOverview = { status: "ok", items: [
      { queue_name: "processing", queue_status: "closed", depth: 15, retries: 0, expired_leases: 0, oldest_ready_age_seconds: 0 },
    ] };
    const сводка = сводкаОчередей(обзор);
    expect(сводка.глубина).toBe(0);
    expect(сводка.вКарантине).toBe(0);
    expect(сводка.завершено).toBe(0);
    expect(сводка.состояние).toBe("пусто");
    expect(сводка.пояснение).toBe("Закрыто заданий: 15. Источник удалён.");
  });
  it("восстановленные задания сохраняются в истории и не считаются застрявшими", () => {
    const обзор: SemanticQueueOverview = {
      status: "ok",
      items: [...(завершённая.items ?? []),
        { queue_name: "processing", queue_status: "repaired", depth: 260, retries: 1040, expired_leases: 0, oldest_ready_age_seconds: 0 }],
    };
    const сводка = сводкаОчередей(обзор);
    expect(сводка.глубина).toBe(0);
    expect(сводка.вКарантине).toBe(0);
    expect(сводка.завершено).toBe(560);
    expect(сводка.восстановлено).toBe(260);
    expect(сводка.состояние).toBe("пусто");
    expect(строкиПоВажности(обзор)).toHaveLength(3);
    обзор.items?.push({ queue_name: "processing", queue_status: "quarantined", depth: 1, retries: 4, expired_leases: 0, oldest_ready_age_seconds: 0 });
    expect(сводкаОчередей(обзор).вКарантине).toBe(1);
    expect(сводкаОчередей(обзор).состояние).toBe("тревога");
  });

  it("завершённые задания не считаются ожидающими", () => {
    const сводка = сводкаОчередей(завершённая);
    expect(сводка.глубина).toBe(0);
    expect(сводка.завершено).toBe(560);
    expect(сводка.состояние).toBe("пусто");
    expect(сводка.пояснение).toContain("560");
  });

  it("неизвестный статус считается ожидающим, а не прячется", () => {
    const сводка = сводкаОчередей({
      status: "ok",
      items: [{ queue_name: "risk", queue_status: "нечто", depth: 7, retries: 0, expired_leases: 0, oldest_ready_age_seconds: 0 }],
    });
    expect(сводка.глубина).toBe(7);
    expect(сводка.завершено).toBe(0);
  });

  // Ради этого различения пункт H4 и существует: без него оператор не отличит
  // «работать не над чем» от «система не знает, что происходит».
  it("пустая и неопрошенная очередь — разные состояния", () => {
    const пусто = сводкаОчередей(пустаяОпрошенная);
    const молчание = сводкаОчередей(неопрошенная);
    expect(пусто.состояние).toBe("пусто");
    expect(молчание.состояние).toBe("не опрошено");
    expect(пусто.заголовок).not.toBe(молчание.заголовок);
  });

  it("неопрошенная очередь даёт null, а не ноль", () => {
    expect(сводкаОчередей(неопрошенная).глубина).toBeNull();
    expect(сводкаОчередей(пустаяОпрошенная).глубина).toBe(0);
    expect(сводкаОчередей(undefined).глубина).toBeNull();
  });

  it("причина недоступности попадает в пояснение", () => {
    expect(сводкаОчередей(неопрошенная).пояснение).toContain("OperationalError");
  });

  it("суммирует глубину, повторы и берёт максимум возраста", () => {
    const сводка = сводкаОчередей(рабочая);
    expect(сводка.состояние).toBe("ok");
    expect(сводка.глубина).toBe(16);
    expect(сводка.повторы).toBe(3);
    expect(сводка.старейшее).toBe(420);
  });

  it("карантин и просроченные аренды поднимают тревогу", () => {
    const сКарантином: SemanticQueueOverview = {
      status: "ok",
      items: [...(рабочая.items ?? []), { queue_name: "dispatch", queue_status: "quarantined", depth: 2, retries: 7, expired_leases: 0, oldest_ready_age_seconds: 90_000 }],
    };
    const сводка = сводкаОчередей(сКарантином);
    expect(сводка.состояние).toBe("тревога");
    expect(сводка.вКарантине).toBe(2);

    const сАрендами: SemanticQueueOverview = {
      status: "ok",
      items: [{ queue_name: "risk", queue_status: "leased", depth: 5, retries: 0, expired_leases: 3, oldest_ready_age_seconds: 10 }],
    };
    expect(сводкаОчередей(сАрендами).состояние).toBe("тревога");
    expect(сводкаОчередей(сАрендами).просроченныеАренды).toBe(3);
  });
});

describe("порядок строк", () => {
  it("тревожные вперёд, затем по убыванию глубины", () => {
    const обзор: SemanticQueueOverview = {
      status: "ok",
      items: [
        { queue_name: "a", queue_status: "queued", depth: 100, retries: 0, expired_leases: 0, oldest_ready_age_seconds: 0 },
        { queue_name: "b", queue_status: "failed", depth: 1, retries: 9, expired_leases: 0, oldest_ready_age_seconds: 0 },
        { queue_name: "c", queue_status: "queued", depth: 50, retries: 0, expired_leases: 0, oldest_ready_age_seconds: 0 },
      ],
    };
    expect(строкиПоВажности(обзор).map((с) => с.queue_name)).toEqual(["b", "a", "c"]);
  });

  it("просроченная аренда делает строку тревожной независимо от статуса", () => {
    expect(строкаТревожная({ queue_name: "x", queue_status: "leased", depth: 1, retries: 0, expired_leases: 1, oldest_ready_age_seconds: 0 })).toBe(true);
    expect(строкаТревожная({ queue_name: "x", queue_status: "leased", depth: 1, retries: 0, expired_leases: 0, oldest_ready_age_seconds: 0 })).toBe(false);
  });
});

describe("возраст словами", () => {
  it("различает «не измерен» и «нет ожидающих»", () => {
    expect(возрастСловами(null)).toBe("не измерен");
    expect(возрастСловами(undefined)).toBe("не измерен");
    expect(возрастСловами(0)).toBe("нет ожидающих");
  });

  it("укрупняет единицы", () => {
    expect(возрастСловами(45)).toBe("45 с");
    expect(возрастСловами(600)).toBe("10 мин");
    expect(возрастСловами(7200)).toBe("2 ч");
    expect(возрастСловами(172_800)).toBe("2 сут");
  });
});

describe("сводка каталога", () => {
  const полный: CatalogCompleteness = {
    status: "ok", basis: "distinct_catalog_entries", entry_count: 76,
    fully_classified: 76, classification_ratio: 1, schema_v2_ready: 76,
  };

  it("полный каталог назван полным", () => {
    expect(сводкаКаталога(полный).состояние).toBe("полон");
    expect(сводкаКаталога(полный).заголовок).toContain("76 из 76");
  });

  // Самая опасная возможная неправда этого экрана: выдать 76/76 за покрытие
  // корпуса. Неописанный тип может давать миллион строк, описанный - одну.
  it("оговорка про основание расчёта не исчезает и при полном каталоге", () => {
    expect(сводкаКаталога(полный).оговорка).toContain("не доля событий корпуса");
  });

  it("нечитаемый каталог отличается от неполного", () => {
    const отказ: CatalogCompleteness = { status: "unavailable", basis: "distinct_catalog_entries", error_type: "FileNotFoundError" };
    expect(сводкаКаталога(отказ).состояние).toBe("не прочитан");
    expect(сводкаКаталога(отказ).основание).toContain("FileNotFoundError");
    expect(сводкаКаталога(undefined).состояние).toBe("не прочитан");
  });

  it("неполная форма v2 делает каталог неполным даже при полной классификации", () => {
    expect(сводкаКаталога({ ...полный, schema_v2_ready: 70 }).состояние).toBe("неполон");
  });
});

describe("недообъявленные поля", () => {
  it("возвращает поля, объявленные не у всех записей, от худшего", () => {
    const полнота: CatalogCompleteness = {
      status: "ok", entry_count: 76,
      declared_per_field: { noise_class: 76, correlation: 2, required_fields: 40 },
    };
    expect(недообъявленныеПоля(полнота)).toEqual([["correlation", 2], ["required_fields", 40]]);
  });

  it("без записей ничего не утверждает", () => {
    expect(недообъявленныеПоля({ status: "ok", entry_count: 0, declared_per_field: { a: 0 } })).toEqual([]);
    expect(недообъявленныеПоля(undefined)).toEqual([]);
  });
});

describe("вердикт контура — один ответ вместо трёх рассуждений", () => {
  const очередь = (глубина: number, аренды = 0): SemanticQueueOverview => ({
    status: "ok",
    items: [{ queue_name: "d", queue_status: аренды || глубина ? "queued" : "queued", depth: глубина, retries: 0, expired_leases: аренды, oldest_ready_age_seconds: глубина ? 420 : 0 }],
  });

  it("выключенный процесс важнее состояния очереди", () => {
    const в = вердиктКонтура(пустаяОпрошенная, true, "manual_poll_complete");
    expect(в.подпись).toBe("Выключен");
    expect(в.строка).toBe("События сейчас не анализируются.");
    // Оговорка L2 не исчезла - она переехала в подсказку, а не на экран.
    expect(в.уточнение).toContain("не означает, что проверка выполнена");
  });

  it("неопрошенная очередь называется неизвестностью, а не нулём", () => {
    const в = вердиктКонтура(неопрошенная, false, null);
    expect(в.подпись).toBe("Состояние неизвестно");
    expect(в.тон).toBe("warn");
  });

  it("пустая и неопрошенная дают разные подписи", () => {
    expect(вердиктКонтура(пустаяОпрошенная, false, null).подпись).toBe("В норме");
    expect(вердиктКонтура(неопрошенная, false, null).подпись).not.toBe("В норме");
  });

  it("застрявшее важнее непустой очереди", () => {
    expect(вердиктКонтура(очередь(5, 2), false, null).подпись).toBe("Требует внимания");
    expect(вердиктКонтура(очередь(5), false, null).подпись).toBe("В работе");
  });

  it("числительные склоняются", () => {
    expect(вердиктКонтура(очередь(0, 1), false, null).строка).toContain("1 задание");
    expect(вердиктКонтура(очередь(0, 3), false, null).строка).toContain("3 задания");
    expect(вердиктКонтура(очередь(0, 11), false, null).строка).toContain("11 заданий");
  });
});

describe("коротко о каталоге", () => {
  it("значение короткое, оговорка в подсказке", () => {
    const к = короткоОКаталоге({ status: "ok", basis: "distinct_catalog_entries", entry_count: 76, fully_classified: 76, schema_v2_ready: 76 });
    expect(к.значение).toBe("76 из 76");
    expect(к.значение).not.toContain("корпус");
    expect(к.уточнение).toContain("не доля событий корпуса");
  });

  it("нечитаемый каталог не выдаётся за полный", () => {
    expect(короткоОКаталоге(undefined).значение).toBe("не прочитан");
    expect(короткоОКаталоге(undefined).тон).toBe("warn");
  });
});
