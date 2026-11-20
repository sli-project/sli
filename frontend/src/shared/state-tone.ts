import type { Tone } from "../design-system";

const STATE_TONES: Readonly<Partial<Record<string, Tone>>> = {
  critical: "danger", high: "danger", high_risk: "danger",
  failed: "danger", error: "danger", blocked: "danger", unavailable: "danger",
  stale: "danger", breach: "danger", timeout: "danger",
  medium: "warning", moderate: "warning", warn: "warning", warning: "warning",
  lagging: "warning", partial: "warning", degraded: "warning",
  ok: "success", good: "success", normal: "success", healthy: "success",
  current: "success", completed: "success", complete: "success", ready: "success",
  success: "success", enabled: "success", active: "success", met: "success",
  pass: "success", passed: "success", low: "success",
  "критический": "danger", "критичная": "danger", "критическое": "danger",
  "высокий": "danger", "высокая": "danger", "высокое": "danger",
  "ошибка": "danger", "заблокирован": "danger", "устарело": "danger",
  "средний": "warning", "средняя": "warning", "предупреждение": "warning",
  "неполно": "warning", "низкий": "success", "нормальное": "success",
  "в норме": "success", "активен": "success", "включён": "success", "полно": "success",
};

/** Only exact, known states carry a colour; unrecognised values stay neutral. */
export function stateTone(value: unknown): Tone {
  const state = typeof value === "string" ? value.trim().toLowerCase() : "";
  return Object.hasOwn(STATE_TONES, state) ? STATE_TONES[state]! : "neutral";
}
