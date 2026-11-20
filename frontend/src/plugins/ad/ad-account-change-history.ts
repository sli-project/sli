import type {
  AdAccountChangeTransitionAfter,
  AdAccountChangeTransitionBefore,
} from "../../api/client";
import { t } from "../../i18n";

/**
 * История изменений учётных записей (`GET /api/v1/reports/ad.state/account-changes`).
 *
 * Отчёт — bounded построчный журнал наблюдений 4720/4722/4723/4724/4725/4726/
 * 4738/4740/4767/4781 на контроллерах домена, а не восстановленное текущее состояние
 * каталога. Разбор смысловых границ: до/после известны ровно настолько,
 * насколько это доказывает конкретное событие — не восстанавливаются и не
 * достраиваются на клиенте.
 */

function состояниеСловом(код: string): string {
  type StateKey =
    | "entities.adChange.state.present"
    | "entities.adChange.state.enabled"
    | "entities.adChange.state.disabled"
    | "entities.adChange.state.deleted"
    | "entities.adChange.state.locked"
    | "entities.adChange.state.unlocked";
  const map: Record<string, StateKey> = {
    present: "entities.adChange.state.present",
    enabled: "entities.adChange.state.enabled",
    disabled: "entities.adChange.state.disabled",
    deleted: "entities.adChange.state.deleted",
    locked: "entities.adChange.state.locked",
    unlocked: "entities.adChange.state.unlocked",
  };
  return map[код] ? t(map[код]) : код;
}

/** Причина `unknown`/`partial` состояния — то же самое слово везде, где встречается код. */
function причинаСловом(код: string): string {
  type ReasonKey =
    | "entities.adChange.reason.prior_account_state_not_observed"
    | "entities.adChange.reason.event_does_not_prove_account_state"
    | "entities.adChange.reason.intervening_account_state_not_proven"
    | "entities.adChange.reason.source_native_rename_names_not_observed"
    | "entities.adChange.reason.changed_attribute_fields_not_in_warm_contract";
  const map: Record<string, ReasonKey> = {
    prior_account_state_not_observed: "entities.adChange.reason.prior_account_state_not_observed",
    event_does_not_prove_account_state: "entities.adChange.reason.event_does_not_prove_account_state",
    intervening_account_state_not_proven: "entities.adChange.reason.intervening_account_state_not_proven",
    source_native_rename_names_not_observed: "entities.adChange.reason.source_native_rename_names_not_observed",
    changed_attribute_fields_not_in_warm_contract: "entities.adChange.reason.changed_attribute_fields_not_in_warm_contract",
  };
  return map[код] ? t(map[код]) : код;
}

export type ПереходТекст = { текст: string; уточнение?: string };

export function переходДоТекст(before: AdAccountChangeTransitionBefore): ПереходТекст {
  if (before.state === "observed") return { текст: before.value };
  if (before.state === "partial") {
    return {
      текст: состояниеСловом(before.last_observed.value),
      уточнение: t("entities.adChange.partialNote", { reason: причинаСловом(before.reason) }),
    };
  }
  return { текст: t("entities.adChange.unconfirmed"), уточнение: причинаСловом(before.reason) };
}

export function переходПослеТекст(after: AdAccountChangeTransitionAfter): ПереходТекст {
  if (after.state === "observed") return { текст: состояниеСловом(after.value) };
  return { текст: t("entities.adChange.unconfirmed"), уточнение: причинаСловом(after.reason) };
}
