import { describe, expect, it } from "vitest";
import { entityEvidenceHref, entityInvestigationHref, eventEvidenceHref, eventMachineRisk, eventParticipantFacts, humanAge, объёмРаздела, отказЗапроса } from "./event-presentation";

describe("отказ запроса различает причины", () => {
  it("не найдено, нет прав и отказ сервера — разные сообщения", () => {
    const нет = отказЗапроса({ status: 404 });
    const прав = отказЗапроса({ status: 403 });
    const сервер = отказЗапроса({ status: 500 });
    expect(new Set([нет.title, прав.title, сервер.title]).size).toBe(3);
  });

  it("повторять предлагается только там, где это имеет смысл", () => {
    // Записи нет и прав нет — повтор ничего не изменит.
    expect(отказЗапроса({ status: 404 }).retry).toBe(false);
    expect(отказЗапроса({ status: 403 }).retry).toBe(false);
    expect(отказЗапроса({ status: 401 }).retry).toBe(false);
    // Отказ сервера, таймаут и обрыв связи — повтор уместен.
    expect(отказЗапроса({ status: 500 }).retry).toBe(true);
    expect(отказЗапроса({ status: 504 }).retry).toBe(true);
    expect(отказЗапроса(null).retry).toBe(true);
  });

  it("отсутствие статуса не выдаётся за отсутствие записи", () => {
    // Обрыв связи легко спутать с «не найдено», и это самая дорогая путаница:
    // она заставляет искать несуществующую причину вместо проверки сервера.
    const обрыв = отказЗапроса(undefined);
    const нетЗаписи = отказЗапроса({ status: 404 });
    expect(обрыв.title).not.toBe(нетЗаписи.title);
    expect(обрыв.detail).not.toBe(нетЗаписи.detail);
    expect(обрыв.retry).toBe(true);
  });

  it("название сущности не ломает согласование", () => {
    // Подстановка в заголовок давала «Такой отчёта нет». Название уходит в
    // пояснение, а заголовок остаётся без рода.
    for (const сущность of ["записи", "сущности", "отчёта", "дела"]) {
      const отказ = отказЗапроса({ status: 404 }, сущность);
      expect(отказ.title).toBe("Ничего не найдено по этой ссылке");
      expect(отказ.detail).toContain(сущность);
    }
  });
});

describe("возраст в человеческих единицах", () => {
  it("переходит от минут к часам и суткам", () => {
    expect(humanAge(0)).toBe("только что");
    expect(humanAge(42)).toBe("42 мин. назад");
    expect(humanAge(90)).toBe("2 ч. назад");
    // Тот самый случай с экрана «Эксплуатация»: было «2 302 мин. назад».
    expect(humanAge(2302)).toBe("38 ч. назад");
    expect(humanAge(60 * 24 * 3)).toBe("3 сут. назад");
    expect(humanAge(60 * 24 * 45)).toBe("2 мес. назад");
    expect(humanAge(60 * 24 * 400)).toBe("более года назад");
  });

  it("отсутствие возраста не выдаёт за ноль", () => {
    expect(humanAge(null)).toBe("");
    expect(humanAge(undefined)).toBe("");
    expect(humanAge(Number.NaN)).toBe("");
  });
});

describe("участники события на карточке", () => {
  it("берёт вошедшую учётную запись из target, а не из subject", () => {
    // В событии 4624 subject — это система, а человек лежит в target.
    // Обратный порядок дважды приводил к ошибкам при разборе корпуса.
    const facts = eventParticipantFacts({ subject: "DC1$", target: "EXAMPLE\\ivanov", server: "DC2" });
    expect(facts).toContainEqual(["Кто", "EXAMPLE\\ivanov"]);
    expect(facts).toContainEqual(["Откуда", "DC2"]);
    expect(facts).toContainEqual(["От чьего имени", "DC1$"]);
  });

  it("не повторяет участника, если subject и target совпадают", () => {
    const facts = eventParticipantFacts({ subject: "ivanov", target: "ivanov", server: "DC2" });
    expect(facts.filter(([label]) => label === "От чьего имени")).toHaveLength(0);
  });

  it("падает на subject, когда target пуст", () => {
    expect(eventParticipantFacts({ subject: "ivanov", target: "", server: "" })).toEqual([["Кто", "ivanov"]]);
  });

  it("ничего не добавляет, когда каталог уже назвал участника", () => {
    const declared: Array<[string, string]> = [["Кто", "ivanov"], ["Сервер", "DC2"]];
    expect(eventParticipantFacts({ subject: "DC1$", target: "ivanov", server: "DC2" }, declared))
      .toEqual([["От чьего имени", "DC1$"]]);
  });

  it("не показывает пустые значения", () => {
    expect(eventParticipantFacts({ subject: null, target: null, server: null })).toEqual([]);
  });
});

describe("machine event presentation", () => {
  it("uses final_risk and never the localized display risk", () => {
    expect(eventMachineRisk({ severity: "medium", semantics: { final_risk: "HIGH" } })).toBe("high");
    expect(eventMachineRisk({ severity: "high", final_risk: "medium" })).toBe("medium");
    expect(eventMachineRisk({ severity: "critical" })).toBe("critical");
    expect(eventMachineRisk(undefined)).toBe("unknown");
  });


  it("uses exact entity identity and retains time without a name query or old event anchor", () => {
    const url = new URL(entityInvestigationHref(42, "?event_db_id=7&q=alice&scope=important&time_from=2026-09-10&timezone=UTC"), "http://localhost");
    expect(url.pathname).toBe("/app/investigations");
    expect(Object.fromEntries(url.searchParams)).toEqual({ entity_id: "42", scope: "important", time_from: "2026-09-10", timezone: "UTC" });
    expect(() => entityInvestigationHref(0)).toThrow();
  });

  it("carries only validated exact IDs and typed bounds across evidence links", () => {
    const search = "?entity_id=5632&scope=all&time_from=2026-09-10T12%3A00%3A00.123001Z&time_to=2026-09-10T12%3A00%3A00.123999Z&timezone=Asia%2FNovosibirsk";
    expect(new URL(eventEvidenceHref(517550, search)!, "http://localhost")).toMatchObject({ pathname: "/app/events/517550" });
    expect(Object.fromEntries(new URL(eventEvidenceHref(517550, search)!, "http://localhost").searchParams)).toEqual({ event_db_id: "517550", entity_id: "5632", scope: "all", time_from: "2026-09-10T12:00:00.123001Z", time_to: "2026-09-10T12:00:00.123999Z", timezone: "Asia/Novosibirsk" });
    expect(new URL(entityEvidenceHref(5632, search)!, "http://localhost").pathname).toBe("/app/entities/5632");
    expect(eventEvidenceHref(0, search)).toBeNull();
    expect(entityEvidenceHref("\"5632\"", search)).toBeNull();
  });
});

describe("подпись объёма раздела", () => {
  it("различает пусто, есть и число полей", () => {
    expect(объёмРаздела(0)).toBe("пусто");
    expect(объёмРаздела(null)).toBe("есть");
    expect(объёмРаздела(6)).toBe("6 полей");
  });

  it("склоняет по русским правилам, включая 11-14", () => {
    expect(объёмРаздела(1)).toBe("1 поле");
    expect(объёмРаздела(3)).toBe("3 поля");
    expect(объёмРаздела(11)).toBe("11 полей");
    expect(объёмРаздела(14)).toBe("14 полей");
    expect(объёмРаздела(21)).toBe("21 поле");
    expect(объёмРаздела(22)).toBe("22 поля");
    expect(объёмРаздела(25)).toBe("25 полей");
    expect(объёмРаздела(111)).toBe("111 полей");
  });

  // Пустое и отсутствующее не должны выглядеть одинаково: у сообщения Windows
  // полей нет вовсе, а у EventData их может быть ноль — это разные случаи.
  it("не путает отсутствие полей с их нулевым числом", () => {
    expect(объёмРаздела(null)).not.toBe(объёмРаздела(0));
  });
});
