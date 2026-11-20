import { formatNumber } from "../shared/format";
import type { CatalogCompleteness, SemanticQueueOverview, SemanticQueueRow } from "../api/client";
import { t, plural } from "../i18n";

/**
 * Наблюдаемость семантического контура на экране «Эксплуатация» —
 * пункты `H4`, `K3` и `L3` этапа 8.
 *
 * Экран показывал процессы, PostgreSQL и хранилище, но не показывал очередь.
 * Из-за этого **пустая очередь и неопрошенная очередь выглядели одинаково**:
 * оператор видел отсутствие строк и в том, и в другом случае. Разница
 * решающая — в первом случае работать не над чем, во втором система не знает,
 * что происходит.
 *
 * Поэтому здесь всюду различаются три исхода, а не два: `ok`, `пусто` и
 * `не опрошено`. Ни одна функция не имеет права свести последние два к одному.
 */

export type СостояниеОчередей = "ok" | "пусто" | "не опрошено" | "тревога";

export type СводкаОчередей = {
  состояние: СостояниеОчередей;
  заголовок: string;
  пояснение: string;
  глубина: number | null;
  завершено: number;
  восстановлено: number;
  повторы: number;
  просроченныеАренды: number;
  вКарантине: number;
  старейшее: number | null;
};

/** Статусы, которые означают «задание не движется» — их и надо показывать первыми. */
const ТРЕВОЖНЫЕ_СТАТУСЫ = new Set(["failed", "quarantined", "dead", "poisoned"]);

/**
 * Статусы завершённых заданий.
 *
 * `get_semantic_queue_overview()` группирует задания `group by status`, поэтому
 * строка со статусом `completed` и `depth = 420` означает **420 завершённых
 * заданий**, а не 420 ожидающих. Первая версия складывала `depth` по всем
 * строкам и подписывала сумму «в очереди»: на рабочем стенде это дало
 * «560 в очереди» рядом с «ожидающих нет», то есть экран утверждал работу,
 * которой нет.
 *
 * Неизвестный статус в глубину **входит**: спрятать незнакомое опаснее, чем
 * показать лишнее.
 */
const ЗАВЕРШЁННЫЕ_СТАТУСЫ = new Set(["completed", "done", "succeeded", "published"]);

export function строкаЗавершена(строка: SemanticQueueRow): boolean {
  return ЗАВЕРШЁННЫЕ_СТАТУСЫ.has(строка.queue_status.toLowerCase());
}

export function возрастСловами(секунды: number | null | undefined): string {
  if (секунды === null || секунды === undefined) return t("operations.semantic_observability.age_not_measured");
  if (секунды <= 0) return t("operations.semantic_observability.age_no_pending");
  if (секунды < 60) return t("operations.semantic_observability.age_seconds", { value: Math.round(секунды) });
  if (секунды < 3600) return t("operations.semantic_observability.age_minutes", { value: Math.round(секунды / 60) });
  if (секунды < 86_400) return t("operations.semantic_observability.age_hours", { value: Math.round(секунды / 3600) });
  return t("operations.semantic_observability.age_days", { value: Math.round(секунды / 86_400) });
}

export function строкаТревожная(строка: SemanticQueueRow): boolean {
  return (
    ТРЕВОЖНЫЕ_СТАТУСЫ.has(строка.queue_status.toLowerCase())
    || строка.expired_leases > 0
  );
}

/**
 * Сводка по всем очередям.
 *
 * `глубина: null` означает «не опрошено». Ноль здесь был бы ложью: он
 * утверждал бы, что очередь пуста, тогда как её не смотрели.
 */
export function сводкаОчередей(обзор: SemanticQueueOverview | undefined): СводкаОчередей {
  const опрошено = обзор?.status === "ok";
  const строки = обзор?.items ?? [];

  if (!обзор || !опрошено) {
    return {
      состояние: "не опрошено",
      заголовок: t("operations.semantic_observability.queue_not_polled_title"),
      пояснение: обзор?.error_type
        ? t("operations.semantic_observability.queue_not_polled_error", { error: обзор.error_type })
        : t("operations.semantic_observability.queue_not_polled_text"),
      глубина: null,
      завершено: 0,
      восстановлено: 0,
      повторы: 0,
      просроченныеАренды: 0,
      вКарантине: 0,
      старейшее: null,
    };
  }

  const глубина = строки
    .filter((строка) => !строкаЗавершена(строка) && !["repaired", "closed"].includes(строка.queue_status))
    .reduce((сумма, строка) => сумма + строка.depth, 0);
  const завершено = строки
    .filter(строкаЗавершена)
    .reduce((сумма, строка) => сумма + строка.depth, 0);
  const восстановлено = строки
    .filter((строка) => строка.queue_status === "repaired")
    .reduce((сумма, строка) => сумма + строка.depth, 0);
  const повторы = строки.reduce((сумма, строка) => сумма + строка.retries, 0);
  const аренды = строки.reduce((сумма, строка) => сумма + строка.expired_leases, 0);
  const карантин = строки
    .filter((строка) => ТРЕВОЖНЫЕ_СТАТУСЫ.has(строка.queue_status.toLowerCase()))
    .reduce((сумма, строка) => сумма + строка.depth, 0);
  const старейшее = строки.length
    ? строки.reduce((макс, строка) => Math.max(макс, строка.oldest_ready_age_seconds), 0)
    : 0;

  if (карантин > 0 || аренды > 0) {
    return {
      состояние: "тревога",
      заголовок: карантин > 0 ? t("operations.semantic_observability.stuck_tasks_title") : t("operations.semantic_observability.expired_leases_title"),
      пояснение: t("operations.semantic_observability.stuck_tasks_text", { quarantine: карантин, leases: аренды }),
      глубина, завершено, восстановлено, повторы, просроченныеАренды: аренды, вКарантине: карантин, старейшее,
    };
  }

  if (!глубина) {
    const закрыто = строки.filter((строка) => строка.queue_status === "closed").reduce((сумма, строка) => сумма + строка.depth, 0);
    return {
      состояние: "пусто",
      заголовок: t("operations.semantic_observability.queue_empty_title"),
      пояснение: закрыто ? t("operations.semantic_observability.source_deleted", { count: закрыто }) : завершено
        ? t("operations.semantic_observability.queue_empty_completed", { completed: завершено })
        : t("operations.semantic_observability.queue_empty_text"),
      глубина: 0, завершено, восстановлено, повторы, просроченныеАренды: 0, вКарантине: 0, старейшее: 0,
    };
  }

  return {
    состояние: "ok",
    заголовок: t("operations.semantic_observability.queue_depth_title", { depth: глубина }),
    пояснение: t("operations.semantic_observability.queue_depth_text", { age: возрастСловами(старейшее) }),
    глубина, завершено, восстановлено, повторы, просроченныеАренды: аренды, вКарантине: карантин, старейшее,
  };
}

/** Тревожные строки вперёд, дальше по убыванию глубины. Показывать надо то, что мешает. */
export function строкиПоВажности(обзор: SemanticQueueOverview | undefined): SemanticQueueRow[] {
  return [...(обзор?.items ?? [])].sort((левая, правая) => {
    const весЛевой = строкаТревожная(левая) ? 1 : 0;
    const весПравой = строкаТревожная(правая) ? 1 : 0;
    if (весЛевой !== весПравой) return весПравой - весЛевой;
    if (правая.depth !== левая.depth) return правая.depth - левая.depth;
    return левая.queue_name.localeCompare(правая.queue_name, "ru");
  });
}

export type СводкаКаталога = {
  состояние: "полон" | "неполон" | "не прочитан";
  заголовок: string;
  основание: string;
  оговорка: string;
};

/**
 * Полнота каталога для администратора, `K3`.
 *
 * Оговорка обязательна и не убирается. `basis=distinct_catalog_entries`
 * значит, что `76/76` — это доля **описанных типов**, а не доля событий
 * корпуса, которые каталог понимает. Событийное покрытие сервер сейчас не
 * присылает, и выдавать одно за другое нельзя: неописанный тип может давать
 * миллион строк, а описанный — одну.
 */
export function сводкаКаталога(полнота: CatalogCompleteness | undefined): СводкаКаталога {
  const оговорка = полнота?.basis === "distinct_catalog_entries"
    ? t("operations.semantic_observability.catalog_completeness_disclaimer_distinct")
    : t("operations.semantic_observability.catalog_completeness_disclaimer_basis", { basis: полнота?.basis ?? t("operations.semantic_observability.basis_not_specified") });

  if (!полнота || полнота.status !== "ok" || полнота.entry_count === undefined) {
    return {
      состояние: "не прочитан",
      заголовок: t("operations.semantic_observability.catalog_not_read_title"),
      основание: полнота?.error_type ? t("operations.semantic_observability.catalog_not_read_error", { error: полнота.error_type }) : t("operations.semantic_observability.catalog_not_read_text"),
      оговорка,
    };
  }

  const всего = полнота.entry_count;
  const описано = полнота.fully_classified ?? 0;
  const поФорме = полнота.schema_v2_ready ?? 0;
  const полон = всего > 0 && описано === всего && поФорме === всего;

  return {
    состояние: полон ? "полон" : "неполон",
    заголовок: полон ? t("operations.semantic_observability.catalog_full_title", { classified: описано, total: всего }) : t("operations.semantic_observability.catalog_partial_title", { classified: описано, total: всего }),
    основание: t("operations.semantic_observability.catalog_v2_ready", { ready: поФорме, total: всего }),
    оговорка,
  };
}

/** Поля, объявленные не у всех записей. Именно они и мешают полноте. */
export function недообъявленныеПоля(полнота: CatalogCompleteness | undefined): Array<[string, number]> {
  const всего = полнота?.entry_count ?? 0;
  const поля = полнота?.declared_per_field ?? {};
  if (!всего) return [];
  return Object.entries(поля)
    .filter(([, число]) => число < всего)
    .sort((левое, правое) => левое[1] - правое[1]);
}


/**
 * Один ответ вместо трёх абзацев рассуждений.
 *
 * Первая редакция выводила на экран три пояснительные фразы: «Это не то же
 * самое, что «очередь не опрошена»», «Выключенный процесс не означает, что
 * проверка выполнена», «Считаются различные записи каталога, а не доля
 * событий корпуса». Владелец сказал прямо: текст жесть, и непонятно, зачем он
 * админу в таком виде.
 *
 * Он был прав. Различать пустую и неопрошенную очередь необходимо — но
 * различать их надо **разными словами в самом состоянии**, а не объяснением,
 * почему слова разные. Оговорки переехали в подсказки и раскрытия; на экране
 * остался ответ.
 *
 * Админ спрашивает три вещи: работает ли анализ, застряло ли что-то, всё ли
 * описано. Здесь первые две.
 */
export type ВердиктКонтура = {
  подпись: string;
  тон: "good" | "bad" | "warn" | "";
  строка: string;
  /** Подсказка при наведении. Здесь живут оговорки, а не в основном тексте. */
  уточнение: string;
};

/** «3 задания», а не «3 заданий»: на экране числа меняются каждую минуту. */
function заданий(число: number): string {
  const count = formatNumber(число);
  return plural(число, {
    one: t("operations.semantic_observability.taskCount.one", { count }),
    few: t("operations.semantic_observability.taskCount.few", { count }),
    many: t("operations.semantic_observability.taskCount.many", { count }),
    other: t("operations.semantic_observability.taskCount.other", { count }),
  });
}

export function вердиктКонтура(
  обзор: SemanticQueueOverview | undefined,
  процессВыключен: boolean,
  фаза: string | null | undefined,
): ВердиктКонтура {
  const очередь = сводкаОчередей(обзор);

  if (процессВыключен) {
    return {
      подпись: t("operations.semantic_observability.verdict_disabled_title"),
      тон: "",
      строка: t("operations.semantic_observability.verdict_disabled_text"),
      уточнение: t("operations.semantic_observability.verdict_disabled_hint", { phase: фаза || t("operations.semantic_observability.phase_not_reported") }),
    };
  }
  if (очередь.состояние === "не опрошено") {
    return {
      подпись: t("operations.semantic_observability.verdict_unknown_title"),
      тон: "warn",
      строка: t("operations.semantic_observability.verdict_unknown_text"),
      уточнение: очередь.пояснение,
    };
  }
  if (очередь.вКарантине || очередь.просроченныеАренды) {
    const застряло = очередь.вКарантине + очередь.просроченныеАренды;
    return {
      подпись: t("operations.semantic_observability.verdict_attention_title"),
      тон: "bad",
      строка: t("operations.semantic_observability.verdict_attention_text", { tasks: заданий(застряло) }),
      уточнение: t("operations.semantic_observability.verdict_attention_hint", { quarantine: очередь.вКарантине, leases: очередь.просроченныеАренды }),
    };
  }
  if (очередь.глубина) {
    return {
      подпись: t("operations.semantic_observability.verdict_working_title"),
      тон: "good",
      строка: t("operations.semantic_observability.verdict_working_text", { tasks: заданий(очередь.глубина), age: возрастСловами(очередь.старейшее) }),
      уточнение: t("operations.semantic_observability.verdict_working_hint"),
    };
  }
  return {
    подпись: t("operations.semantic_observability.verdict_ok_title"),
    тон: "good",
    строка: t("operations.semantic_observability.verdict_ok_text"),
    уточнение: t("operations.semantic_observability.verdict_ok_hint"),
  };
}

export function короткоОКаталоге(полнота: CatalogCompleteness | undefined): {
  значение: string;
  тон: "good" | "warn" | "";
  уточнение: string;
} {
  const сводка = сводкаКаталога(полнота);
  if (сводка.состояние === "не прочитан") {
    return { значение: t("operations.semantic_observability.catalog_not_read_value"), тон: "warn", уточнение: `${сводка.основание} ${сводка.оговорка}` };
  }
  const всего = полнота?.entry_count ?? 0;
  const описано = полнота?.fully_classified ?? 0;
  return {
    значение: t("operations.semantic_observability.catalog_stats", { classified: описано, total: всего }),
    тон: сводка.состояние === "полон" ? "good" : "warn",
    уточнение: `${сводка.основание} ${сводка.оговорка}`,
  };
}
