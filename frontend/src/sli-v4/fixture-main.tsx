import "./reference.css";
import "./product-parity.css";
import { installFixtureApi } from "./fixture-api";

globalThis.__SLI_V4_FIXTURE_PRESENTATION__ = {
  defaultObjectSearch: "ivanov",
  defaultEventFilter: "CORP\\ivanov",
  workspaceProblems: [
    { id: "direct-membership", tone: "bad", title: "Проверить включение CORP\\ivanov в Backup Operators", copy: "Прямое изменение подтверждено событием DB 12854801; заявка владельца не связана.", meta: ["P1", "22 минуты назад", "Объект: CORP\\ivanov"], href: "/app/objects/ad_user/ivanov?tab=overview", icon: "entity", action: "Открыть объект" },
    { id: "dcsync-owners", tone: "warn", title: "Сверить владельцев 8 записей DCSync", copy: "Часть прав может быть штатной; требуется сравнение с разрешённым перечнем.", meta: ["P1", "AD-аудит 17.07.2026"], href: "/app/ad-report", icon: "report", action: "Открыть AD-отчёт" },
  ],
  objects: {
    ivanov: { initials: "ИИ", tags: [["Включён", "good"], ["2 находки", "warn"]] },
    "svc-backup": { initials: "SB", tags: [["Заблокирована", "bad"], ["P1", "bad"]] },
    "app-srv-03": { initials: "AS", kind: "computer", tags: [["Активен", "good"], ["1 связь", "accent"]] },
    "backup-operators": { initials: "BO", kind: "group", tags: [["Привилегированная", "bad"]] },
    "workstation-baseline": { initials: "GP", kind: "gpo", tags: [["P2", "warn"], ["Нужна проверка", "neutral"]], route: "/app/gpo-report" },
    dc2: { initials: "D2", kind: "computer", tags: [["Работает", "good"], ["Security внутри SLO", "good"]], route: "/app/ad-report" },
    "adm-kuznetsov": { initials: "АК", tags: [["Привилегированный", "bad"]] },
    vpnl2tp: { initials: "VH", kind: "group", tags: [["Доступ VPN", "purple"]], route: "/app/vpn-report" },
  },
};

installFixtureApi();
void import("../product-main");
