import type { CompletenessSnapshot } from "../api/client";
import { t } from "../i18n";

/**
 * Различение «не найдено» и «не проверено» — пункт `K2` этапа 8.
 *
 * Экран показывал риск, уверенность и покрытие, но не показывал, **был ли
 * вывод возможен**. Незавершённая проверка выглядела как доказанное
 * отсутствие: человек читал пустой результат как «ничего не происходило»,
 * тогда как на деле система не смогла посмотреть.
 *
 * Разница не косметическая. «Не найдено» закрывает вопрос, «не проверено»
 * требует действия: доклассифицировать каталог, дождаться сбора, подключить
 * канал, дождаться закрытия окна. Действия разные, а вид был один.
 *
 * Сервер уже понижает `not_found` до `not_checked`, когда полнота не доказана
 * по всем четырём измерениям сразу (`resolve_conclusion_state()` и
 * `CompletenessSnapshot.supports_negative_conclusion` в
 * `server/app/semantic_risk.py`). Интерфейс это понижение обязан показывать, а
 * не сглаживать.
 */

export type СостояниеВывода = "observed" | "not_found" | "not_checked";

export type ИзмерениеПолноты = {
  ключ: "catalog" | "freshness" | "channels" | "window";
  название: string;
  состояние: "полно" | "неполно" | "не измерено";
  подробность: string;
};

/** Заголовок, тон и пояснение для значка вывода. */
export function подписьВывода(состояние: СостояниеВывода | undefined): {
  заголовок: string;
  тон: "good" | "bad" | "warn";
  пояснение: string;
} {
  if (состояние === "observed") {
    return {
      заголовок: t("investigations.conclusionState.observedTitle"),
      тон: "bad",
      пояснение: t("investigations.conclusionState.observedExplanation"),
    };
  }
  if (состояние === "not_found") {
    return {
      заголовок: t("investigations.conclusionState.notFoundTitle"),
      тон: "good",
      пояснение: t("investigations.conclusionState.notFoundExplanation"),
    };
  }
  // Умолчание намеренно пессимистично. Отсутствие поля означает, что сервер
  // состояния не прислал, а не что проверка прошла.
  return {
    заголовок: t("investigations.conclusionState.notCheckedTitle"),
    тон: "warn",
    пояснение: t("investigations.conclusionState.notCheckedExplanation"),
  };
}

function _измерение(
  ключ: ИзмерениеПолноты["ключ"],
  название: string,
  полно: boolean | undefined,
  подробность: string,
): ИзмерениеПолноты {
  return {
    ключ,
    название,
    // `undefined` - не «неполно». Сервер хранит неизмеренное как `null`, и
    // выдавать отсутствие измерения за отрицательный результат нельзя.
    состояние: полно === undefined ? "не измерено" : полно ? "полно" : "неполно",
    подробность,
  };
}

function _секунды(значение: number | null | undefined): string {
  if (значение === null || значение === undefined) return t("investigations.conclusionState.notMeasured");
  if (значение < 60) return t("investigations.conclusionState.seconds", { count: значение });
  if (значение < 3600) return t("investigations.conclusionState.minutes", { count: Math.round(значение / 60) });
  if (значение < 86_400) return t("investigations.conclusionState.hours", { count: Math.round(значение / 3600) });
  return t("investigations.conclusionState.days", { count: Math.round(значение / 86_400) });
}

/**
 * Четыре измерения полноты, каждое со своей подробностью.
 *
 * Порядок не произволен: он повторяет порядок проверок в
 * `supports_negative_conclusion`, чтобы человек, читающий экран, и человек,
 * читающий сервер, видели одно и то же в одной последовательности.
 */
export function разборПолноты(снимок: CompletenessSnapshot | undefined): ИзмерениеПолноты[] {
  const каталог = снимок?.catalog_completeness;
  const свежесть = снимок?.collection_freshness;
  const каналы = снимок?.channel_availability;
  const окно = снимок?.window_closure;

  const всего = каталог?.entry_count;
  const описано = каталог?.fully_classified;
  const поФорме = каталог?.schema_v2_ready;
  const каталогПолон =
    всего === undefined || описано === undefined || поФорме === undefined
      ? undefined
      : описано === всего && поФорме === всего;

  const missingChannels = отсутствующиеКаналы(каналы);
  const channelsDetail = каналы?.required_count === undefined
    ? t("investigations.conclusionState.channelListMissing")
    : missingChannels.length
      ? t("investigations.conclusionState.channelsDetailWithMissing", {
          available: каналы.available_count ?? 0,
          required: каналы.required_count,
          missing: missingChannels.join(", "),
        })
      : t("investigations.conclusionState.channelsDetail", {
          available: каналы.available_count ?? 0,
          required: каналы.required_count,
        });

  return [
    _измерение(
      "catalog",
      t("investigations.conclusionState.dimensionCatalog"),
      каталогПолон,
      всего === undefined
        ? t("investigations.conclusionState.catalogSnapshotMissing")
        : t("investigations.conclusionState.catalogDetail", {
            described: описано ?? "?",
            total: всего,
            schemaReady: поФорме ?? "?",
          }),
    ),
    _измерение(
      "freshness",
      t("investigations.conclusionState.dimensionFreshness"),
      свежесть?.complete,
      свежесть?.max_age_seconds === null || свежесть?.max_age_seconds === undefined
        ? t("investigations.conclusionState.dataAgeNotMeasured")
        : t("investigations.conclusionState.freshnessDetail", {
            lag: _секунды(свежесть.max_age_seconds),
            budget: _секунды(свежесть.budget_seconds),
          }),
    ),
    _измерение(
      "channels",
      t("investigations.conclusionState.dimensionChannels"),
      каналы?.complete,
      channelsDetail,
    ),
    _измерение(
      "window",
      t("investigations.conclusionState.dimensionWindow"),
      окно?.closed,
      окно?.close_deadline_utc
        ? t("investigations.conclusionState.windowDeadline", { deadline: окно.close_deadline_utc })
        : окно?.descriptor_close_timeout_seconds === null || окно?.descriptor_close_timeout_seconds === undefined
          ? t("investigations.conclusionState.windowTimeoutNotSet")
          : t("investigations.conclusionState.windowDetail", {
              timeout: _секунды(окно.descriptor_close_timeout_seconds),
              lateness: _секунды(окно.allowed_lateness_seconds),
            }),
    ),
  ];
}

/** Каналы, которые требуются, но недоступны. Именно они и мешают выводу. */
export function отсутствующиеКаналы(
  каналы: CompletenessSnapshot["channel_availability"] | undefined,
): string[] {
  const требуются = каналы?.required ?? [];
  const есть = new Set(каналы?.available ?? []);
  return требуются.filter((имя) => !есть.has(имя));
}

/**
 * Чего именно не хватило для вывода. Пустой список означает «всё полно».
 *
 * Ради этой строки всё и делается: сказать «не проверено» без причины —
 * значит переложить поиск причины на человека, у которого нет доступа к
 * снимку.
 */
export function чегоНеХватило(снимок: CompletenessSnapshot | undefined): string[] {
  return разборПолноты(снимок)
    .filter((измерение) => измерение.состояние !== "полно")
    .map((измерение) => измерение.название);
}

/** Одной фразой: почему вывод не состоялся. */
export function причинаНеполноты(снимок: CompletenessSnapshot | undefined): string {
  const нехватка = чегоНеХватило(снимок);
  if (!снимок) return t("investigations.conclusionState.snapshotMissing");
  if (!нехватка.length) return t("investigations.conclusionState.allComplete");
  return t("investigations.conclusionState.missingDimensions", { dimensions: нехватка.join(", ").toLowerCase() });
}
