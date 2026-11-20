import { describe, expect, it } from "vitest";
import {
  переходДоТекст,
  переходПослеТекст,
} from "./ad-account-change-history";

/*
  Смысловые границы истории учётных записей: 4738 не придумывает изменённые
  поля, 4781 показывает старое/новое имя только если backend их дал, unknown
  и partial не превращаются в подтверждённое значение. Проверяются чистые
  функции представления — там, где такая подмена молчит.
*/



describe("переходДоТекст / переходПослеТекст: честные состояния", () => {
  it("unknown не превращается в подтверждённое значение", () => {
    const до = переходДоТекст({ state: "unknown", reason: "prior_account_state_not_observed" });
    expect(до.текст).toBe("не подтверждено");
    expect(до.уточнение).toBe("предыдущее состояние не наблюдалось");
  });

  it("partial называет источник как «по последнему наблюдению», не как это событие", () => {
    const до = переходДоТекст({
      state: "partial",
      last_observed: { value: "disabled", event_db_id: 1, time_created_utc: "2026-08-23T10:10:00Z" },
      reason: "intervening_account_state_not_proven",
    });
    expect(до.текст).toBe("отключена");
    expect(до.уточнение).toContain("по последнему наблюдению");
  });

  it("observed после наблюдения выводит состояние словом по коду сервера", () => {
    expect(переходПослеТекст({ state: "observed", value: "enabled" }).текст).toBe("включена");
    expect(переходПослеТекст({ state: "observed", value: "locked" }).текст).toBe("заблокирована");
  });

  it("незнакомый код состояния не прячется — выводится как есть", () => {
    expect(переходПослеТекст({ state: "observed", value: "new_server_state" }).текст).toBe("new_server_state");
  });
});




