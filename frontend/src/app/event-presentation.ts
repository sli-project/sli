import { t } from "../i18n";
import { investigationContext, investigationSearch, safeInvestigationReturnTo } from "./investigation-context";

type MachineRiskCarrier = {
  final_risk?: string | null;
  severity?: string | null;
  semantics?: { final_risk?: string | null } | null;
};

/** Machine risk is the only value accepted by filters and risk badges. */
export function eventMachineRisk(event: MachineRiskCarrier | null | undefined): string {
  return String(event?.semantics?.final_risk ?? event?.final_risk ?? event?.severity ?? "unknown").trim().toLowerCase() || "unknown";
}

type ОшибкаЗапроса = { status?: number; code?: string } | null | undefined;

/**
 * Разные причины отказа — разные сообщения и разные действия.
 *
 * Карточка события на любую ошибку отвечала «Точная запись недоступна или была
 * удалена». Под этой фразой сходились три разных случая: записи нет, прав нет,
 * сервер не ответил. Действия у них противоположные — искать другую запись,
 * просить доступ, повторить позже, — а подсказка была одна.
 *
 * Тот же изъян, что с четырьмя нулями на «Очереди проблем»: незнание подано
 * как знание.
 */
export function отказЗапроса(ошибка: ОшибкаЗапроса, сущность = t("events.presentation.entityRecord")): { title: string; detail: string; retry: boolean } {
  const status = Number(ошибка?.status ?? 0);
  if (status === 404) {
    // Заголовок намеренно без рода: подстановка вида «Такой ${сущность} нет»
    // даёт «Такой отчёта нет». Название сущности уходит в пояснение, где
    // склонение задаёт вызывающая сторона.
    return { title: t("events.presentation.errorNotFoundTitle"), detail: t("events.presentation.errorNotFoundDetail", { entity: сущность }), retry: false };
  }
  if (status === 403) {
    return { title: t("events.presentation.errorDeniedTitle"), detail: t("events.presentation.errorDeniedDetail"), retry: false };
  }
  if (status === 401) {
    return { title: t("events.presentation.errorSessionTitle"), detail: t("events.presentation.errorSessionDetail"), retry: false };
  }
  if (status === 408 || status === 504) {
    return { title: t("events.presentation.errorTimeoutTitle"), detail: t("events.presentation.errorTimeoutDetail"), retry: true };
  }
  if (status >= 500) {
    return { title: t("events.presentation.errorServerTitle"), detail: t("events.presentation.errorServerDetail"), retry: true };
  }
  if (status === 0) {
    return { title: t("events.presentation.errorNetworkTitle"), detail: t("events.presentation.errorNetworkDetail"), retry: true };
  }
  return { title: t("events.presentation.errorDefaultTitle"), detail: t("events.presentation.errorDefaultDetail", { status: String(status) }), retry: true };
}

/**
 * Возраст в единицах, в которых его читают.
 *
 * Экран «Эксплуатация» показывал «2 302 мин. назад». Тридцать восемь часов —
 * это «позавчера», а не две тысячи триста минут: чтобы понять величину, её
 * приходилось делить в уме. Минуты остаются там, где они и осмысленны — в
 * пределах часа.
 */
export function humanAge(minutes: number | null | undefined): string {
  if (minutes === null || minutes === undefined || !Number.isFinite(minutes)) return "";
  const value = Math.max(0, Math.round(minutes));
  if (value < 1) return t("events.presentation.ageJustNow");
  if (value < 60) return t("events.presentation.ageMinutes", { value: String(value) });
  const hours = Math.round(value / 60);
  if (hours < 48) return t("events.presentation.ageHours", { value: String(hours) });
  const days = Math.round(hours / 24);
  if (days < 30) return t("events.presentation.ageDays", { value: String(days) });
  const months = Math.round(days / 30);
  return months < 12 ? t("events.presentation.ageMonths", { value: String(months) }) : t("events.presentation.ageOverYear");
}

type EventParticipants = {
  subject?: string | null;
  target?: string | null;
  server?: string | null;
};

/**
 * Кто и откуда — первые вопросы о событии, и до сих пор их на карточке не было.
 *
 * Карточка показывала только «Событие» и «Сервер». Учётная запись лежала ниже,
 * среди плиток связанных сущностей, вперемешку с каналом, поставщиком и
 * IP-адресом: чтобы узнать, кто вошёл, приходилось прочитать шесть плиток и
 * сообразить, что нужная — та, у которой роль `target`.
 *
 * Порядок `target` перед `subject` не случаен и не косметичен. В событии входа
 * вошедшая учётная запись лежит в `target_*`, а `subject_*` содержит того, от
 * чьего имени выполнено действие, то есть чаще всего систему. Та же особенность
 * дважды приводила к ошибкам при разборе корпуса, и та же причина стоит за
 * выбором роли `target` умолчанием в лестнице опознания на сервере.
 */
export function eventParticipantFacts(item: EventParticipants, existing: ReadonlyArray<readonly [string, string]> = []): Array<[string, string]> {
  const declared = new Set(existing.map(([label]) => label.trim().toLowerCase()));
  const extra: Array<[string, string]> = [];
  const who = (item.target ?? "").trim() || (item.subject ?? "").trim();
  const from = (item.server ?? "").trim();
  // Второго участника показываем, только если он есть и отличается от первого:
  // одинаковые значения в двух строках сообщают не больше, чем одна строка.
  const onBehalf = (item.subject ?? "").trim();
  if (who && !declared.has(t("events.presentation.factWho").toLowerCase())) extra.push([t("events.presentation.factWho"), who]);
  if (from && !declared.has(t("events.presentation.factFrom").toLowerCase()) && !declared.has(t("events.presentation.factServer").toLowerCase())) extra.push([t("events.presentation.factFrom"), from]);
  if (onBehalf && onBehalf !== who && !declared.has(t("events.presentation.factOnBehalf").toLowerCase())) extra.push([t("events.presentation.factOnBehalf"), onBehalf]);
  return extra;
}

/** Absolute SPA URL for links rendered outside TanStack Router's Link API. */
export function entityInvestigationHref(entityId: number, search = ""): string {
  const parameters = new URLSearchParams(search);
  const inherited = investigationContext(parameters);
  const context = investigationSearch(search, {
    entity_id: String(entityId), event_db_id: undefined, q: undefined, scope: inherited.scope ?? "all",
  });
  const target = withPresentationReturnTo(new URLSearchParams(context), parameters);
  return `/app/investigations?${target.toString()}`;
}

function withPresentationReturnTo(target: URLSearchParams, source: URLSearchParams): URLSearchParams {
  const returnValues = source.getAll("return_to");
  if (returnValues.length === 1) {
    const returnTo = safeInvestigationReturnTo(returnValues[0], "");
    if (returnTo) target.set("return_to", returnTo);
  }
  return target;
}

/** A rendered evidence link is shown only for an ID admitted by the shared navigation contract. */
export function exactNavigationId(value: unknown, key: "event_db_id" | "entity_id"): string | null {
  try {
    return investigationContext(new URLSearchParams({ [key]: value === null || value === undefined ? "" : String(value) }))[key] ?? null;
  } catch {
    return null;
  }
}

export function eventEvidenceHref(eventDbId: unknown, search = ""): string | null {
  const event_db_id = exactNavigationId(eventDbId, "event_db_id");
  if (!event_db_id) return null;
  const context = investigationSearch(search, { event_db_id });
  const parameters = withPresentationReturnTo(
    new URLSearchParams(context), new URLSearchParams(search),
  );
  return `/app/events/${event_db_id}?${parameters.toString()}`;
}

export function entityEvidenceHref(entityId: unknown, search = "", anchorEventDbId?: unknown): string | null {
  const entity_id = exactNavigationId(entityId, "entity_id");
  if (!entity_id) return null;
  const event_db_id = anchorEventDbId === undefined ? undefined : exactNavigationId(anchorEventDbId, "event_db_id");
  if (event_db_id === null) return null;
  const context = investigationSearch(search, { entity_id, event_db_id });
  const parameters = withPresentationReturnTo(
    new URLSearchParams(context), new URLSearchParams(search),
  );
  return `/app/entities/${entity_id}?${parameters.toString()}`;
}

/**
 * Подпись объёма свёрнутого раздела карточки события.
 *
 * Пять закрытых полос — нормализованные поля, сообщение Windows, EventData,
 * исходный XML, технические сведения — выглядели одинаково, и открывать их
 * приходилось наугад. Разница между «здесь двадцать три поля» и «здесь пусто»
 * должна быть видна до раскрытия, иначе человек тратит пять нажатий, чтобы
 * узнать то, что можно было напечатать в заголовке.
 *
 * `null` означает «содержимое есть, но полями не считается» — так помечено
 * сообщение Windows: у него нет полей, есть текст.
 */
export function объёмРаздела(количество: number | null): string {
  if (количество === null) return t("events.presentation.fieldsPresent");
  if (количество <= 0) return t("events.presentation.fieldsEmpty");
  const сотня = количество % 100;
  const единица = количество % 10;
  const слово = сотня >= 11 && сотня <= 14 ? t("events.presentation.fieldsMany") : единица === 1 ? t("events.presentation.fieldsOne") : единица >= 2 && единица <= 4 ? t("events.presentation.fieldsFew") : t("events.presentation.fieldsMany");
  return `${количество} ${слово}`;
}
