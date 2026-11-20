from __future__ import annotations

from server.sli.reporting.ui_labels import UI_TEXT


def report_controls() -> str:
    return """<div class=\"report-controls\" aria-label=\"Навигация отчёта\">
  <a href=\"/\" data-i18n=\"home\">На главную</a>
</div>"""


def report_bootstrap_script() -> str:
    return """<script>
(function () {
  const root = document.documentElement;
  const themeKey = 'sli.theme';
  const langKey = 'sli.lang';
  const dictionary = {
    ru: {
      themeLight: 'Тема: светлая', themeDark: 'Тема: темная', lang: 'Язык: RU', home: 'На главную',
      close: 'Закрыть', order: 'Сменить порядок', noData: 'Нет данных',
      openEvents: 'Открыть события', technicalDetails: 'Технические детали', accountChain: 'Цепочка учетной записи',
      sameUser: 'Тот же пользователь', sameIp: 'Тот же IP', sameLogonId: 'Тот же LogonId', nearbyEvents: 'Соседние события ±15 минут'
    },
    en: {
      themeLight: 'Theme: light', themeDark: 'Theme: dark', lang: 'Language: EN', home: 'Home',
      close: 'Close', order: 'Reverse order', noData: 'No data',
      openEvents: 'Open events', technicalDetails: 'Technical details', accountChain: 'Account chain',
      sameUser: 'Same user', sameIp: 'Same IP', sameLogonId: 'Same LogonId', nearbyEvents: 'Nearby events ±15 minutes'
    }
  };
  function getTheme() { return localStorage.getItem(themeKey) || 'light'; }
  function getLang() { return localStorage.getItem(langKey) || 'ru'; }
  function applyTheme(theme) {
    root.dataset.theme = theme === 'dark' ? 'dark' : 'light';
    localStorage.setItem(themeKey, root.dataset.theme);
  }
  function applyLang(lang) {
    const clean = lang === 'en' ? 'en' : 'ru';
    root.lang = clean;
    root.dataset.lang = clean;
    localStorage.setItem(langKey, clean);
    document.querySelectorAll('[data-i18n]').forEach((node) => {
      const key = node.getAttribute('data-i18n');
      const value = dictionary[clean][key];
      if (value) node.textContent = value;
    });
    document.querySelectorAll('[data-i18n-placeholder]').forEach((node) => {
      const key = node.getAttribute('data-i18n-placeholder');
      const value = dictionary[clean][key];
      if (value) node.setAttribute('placeholder', value);
    });
    document.querySelectorAll('[data-ai-draft-label-ru]').forEach((node) => {
      node.textContent = node.getAttribute('data-ai-draft-label-' + clean);
    });
    updateControls();
  }
  function updateControls() {
    const lang = getLang();
    const labels = dictionary[lang] || dictionary.ru;
    const theme = getTheme();
    document.querySelectorAll('[data-theme-toggle]').forEach((node) => {
      node.textContent = theme === 'dark' ? labels.themeDark : labels.themeLight;
    });
    document.querySelectorAll('[data-lang-toggle]').forEach((node) => { node.textContent = labels.lang; });
  }
  document.addEventListener('click', (event) => {
    const themeButton = event.target.closest('[data-theme-toggle]');
    if (themeButton) {
      applyTheme(getTheme() === 'dark' ? 'light' : 'dark');
      updateControls();
    }
    const langButton = event.target.closest('[data-lang-toggle]');
    if (langButton) {
      applyLang(getLang() === 'ru' ? 'en' : 'ru');
    }
  });
  applyTheme(getTheme());
  applyLang(getLang());
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => applyLang(getLang()), { once: true });
  }
})();
</script>"""



def inline_i18n_catalog() -> str:
    """Small HTML-safe label catalog for generated reports.

    Full server-side translations live in server.sli.reporting.ui_labels; this helper is
    intentionally small and only supports client-side control labels.
    """
    return str({lang: values for lang, values in UI_TEXT.items()})


def report_style(score_width: int | None = None, extra_css: str = "") -> str:
    score_css = ""
    if score_width is not None:
        safe_width = max(0, min(int(score_width), 100))
        score_css = f".bar i,.score-bar i{{width:{safe_width}%;}}"
    return f"""<style>
:root,
:root[data-theme=\"light\"] {{
  --bg:#eef3f7; --panel:#ffffff; --panel-2:#f8fafc; --text:#1f2937; --muted:#667085;
  --line:#d8e0e8; --blue:#2563eb; --green:#18875f; --amber:#b7791f; --red:#c2410c;
  --purple:#6d5bd0; --shadow-soft:0 14px 40px rgba(31,41,55,.10); --shadow-strong:0 18px 55px rgba(31,41,55,.14);
}}
:root[data-theme=\"dark\"] {{
  --bg:#111827; --panel:#1f2937; --panel-2:#111827; --text:#e5e7eb; --muted:#a8b3c2;
  --line:#334155; --blue:#7fb3ff; --green:#86efac; --amber:#fcd34d; --red:#fca5a5;
  --purple:#c4b5fd; --shadow-soft:0 14px 40px rgba(0,0,0,.24); --shadow-strong:0 20px 60px rgba(0,0,0,.35);
}}
*{{box-sizing:border-box;}}
html{{scroll-behavior:smooth;}}
body{{margin:0;background:linear-gradient(160deg,var(--bg) 0%,var(--panel-2) 58%,var(--bg) 100%);color:var(--text);font-family:"Segoe UI",Arial,sans-serif;line-height:1.45;}}
a{{color:var(--blue);text-decoration:none;}}a:hover{{text-decoration:underline;}}
.wrap{{max-width:1500px;margin:0 auto;padding:24px;}}
.report-controls{{position:sticky;top:0;z-index:50;display:flex;justify-content:flex-end;gap:8px;padding:10px 24px;background:color-mix(in srgb,var(--panel) 88%,transparent);border-bottom:1px solid var(--line);backdrop-filter:blur(10px);}}
.report-controls button,.report-controls a,button,.button,.detail-link{{border:1px solid #bfd1e2;border-color:var(--line);border-radius:12px;background:var(--panel-2);color:var(--text);padding:8px 11px;font-size:13px;font-weight:700;cursor:pointer;display:inline-flex;align-items:center;gap:6px;}}
.report-controls a:hover,button:hover,.button:hover,.detail-link:hover{{background:color-mix(in srgb,var(--blue) 10%,var(--panel));text-decoration:none;}}
.hero,header,section,.card,.source-card,.report-card,.job-item,.priority-card{{border:1px solid var(--line);border-radius:22px;background:color-mix(in srgb,var(--panel) 94%,transparent);box-shadow:var(--shadow-soft);}}
.hero,header{{padding:22px;}}section{{margin-top:18px;padding:22px;}}
.hero-grid{{display:grid;grid-template-columns:1.35fr .65fr;gap:22px;align-items:stretch;}}
.eyebrow{{color:#47647c;color:var(--blue);font-size:12px;font-weight:800;letter-spacing:.12em;text-transform:uppercase;}}
h1,h2,h3,p{{margin-top:0;}}h1{{font-size:32px;line-height:1.1;margin-bottom:10px;}}h2{{font-size:22px;margin-bottom:8px;}}h3{{font-size:17px;margin-bottom:10px;}}
.subtitle,.muted,.footer,.confidence{{color:var(--muted);}}
.pillrow,.navrow,.meta-row,.toolbar,.top-toolbar,.evidence-actions,.investigation-links{{display:flex;gap:8px;flex-wrap:wrap;}}
.pill{{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;background:var(--panel-2);color:var(--muted);padding:6px 10px;font-size:12px;white-space:nowrap;}}
.pill strong{{color:var(--text);}}.pill.ok,.ok{{border-color:color-mix(in srgb,var(--green) 40%,var(--line));}}.pill.warn,.warn{{border-color:color-mix(in srgb,var(--amber) 48%,var(--line));}}.pill.bad,.danger,.bad{{border-color:color-mix(in srgb,var(--red) 48%,var(--line));}}
.score,.score-card{{border:1px solid color-mix(in srgb,var(--amber) 45%,var(--line));border-radius:22px;background:var(--panel);padding:18px;}}
.score .num,.score-value{{font-size:48px;font-weight:800;color:#17436f;color:var(--blue);}}.score .num span{{font-size:24px;color:var(--muted);}}
.bar,.score-bar,.timeline{{height:10px;border-radius:999px;background:var(--panel-2);overflow:hidden;margin:12px 0;}}.bar i,.score-bar i{{display:block;height:100%;background:linear-gradient(90deg,var(--amber),var(--blue),var(--green));}}
nav{{position:sticky;top:0;z-index:10;background:color-mix(in srgb,var(--panel) 88%,transparent);backdrop-filter:blur(12px);border-bottom:1px solid var(--line);}}
.navrow{{padding:10px 24px;overflow:auto;}}nav a,.navrow a{{white-space:nowrap;padding:7px 10px;border-radius:999px;background:var(--panel);border:1px solid var(--line);font-size:12px;color:var(--text);}}
.grid{{display:grid;gap:14px;}}.grid.kpi{{grid-template-columns:repeat(4,minmax(0,1fr));}}.grid.two{{grid-template-columns:1fr 1fr;}}.grid.three{{grid-template-columns:repeat(3,1fr);}}.mt{{margin-top:14px;}}
.card,.kpi-card{{padding:16px;}}.kpi-card .value{{font-size:26px;font-weight:800;color:var(--text);}}.kpi-card .name,.kpi-card .hint{{font-size:12px;color:var(--muted);}}
table{{width:100%;border-collapse:separate;border-spacing:0;border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--panel);}}
th,td{{padding:10px 11px;border-bottom:1px solid var(--line);vertical-align:top;font-size:12px;}}th{{position:sticky;top:0;background:var(--panel-2);color:var(--muted);text-align:left;z-index:1;}}tr:last-child td{{border-bottom:0;}}tr:hover td{{background:color-mix(in srgb,var(--blue) 5%,var(--panel));}}
input,select,textarea{{border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--text);padding:10px 12px;}}
.filters,.search-form,.search-box{{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0;}}.search-box input,.search-form input{{min-width:300px;flex:1;}}
.matrix{{display:grid;grid-template-columns:240px 1fr 1fr;gap:1px;background:var(--line);border:1px solid var(--line);border-radius:16px;overflow:hidden;}}.matrix>div{{background:var(--panel);padding:12px;}}.matrix .head{{background:var(--panel-2);font-weight:700;}}
.risk-badge,.badge,.role{{font-size:11px;letter-spacing:.03em;border-radius:999px;padding:5px 9px;font-weight:800;white-space:nowrap;background:var(--panel-2);color:var(--text);}}
.risk-critical,.risk-high,.badge.high{{background:#fee2e2;color:#991b1b;}}.risk-medium,.badge.warn{{background:#fffbeb;color:#92400e;}}.risk-low,.badge.ok{{background:#ecfdf5;color:#166534;}}.risk-info{{background:#eff6ff;color:#1d4ed8;}}
:root[data-theme=\"dark\"] .risk-critical,:root[data-theme=\"dark\"] .risk-high,:root[data-theme=\"dark\"] .badge.high{{background:#7f1d1d;color:#fecaca;}}
:root[data-theme=\"dark\"] .risk-medium,:root[data-theme=\"dark\"] .badge.warn{{background:#78350f;color:#fde68a;}}
:root[data-theme=\"dark\"] .risk-low,:root[data-theme=\"dark\"] .badge.ok{{background:#064e3b;color:#a7f3d0;}}
:root[data-theme=\"dark\"] .risk-info{{background:#1e3a8a;color:#bfdbfe;}}
.mono{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;}}.summary{{max-width:540px;color:var(--text);}}
details{{margin-top:8px;border:1px solid var(--line);border-radius:12px;background:var(--panel-2);overflow:hidden;}}summary{{cursor:pointer;padding:9px 11px;color:var(--blue);}}pre{{max-width:720px;max-height:320px;overflow:auto;margin:0;padding:10px;color:var(--text);white-space:pre-wrap;word-break:break-word;}}
.callout{{border-left:4px solid var(--blue);background:color-mix(in srgb,var(--blue) 8%,var(--panel));padding:12px 14px;border-radius:12px;}}.badcallout{{border-left:4px solid var(--red);background:color-mix(in srgb,var(--red) 8%,var(--panel));padding:12px 14px;border-radius:12px;}}
.evidence-box{{margin:12px 0;border:1px solid color-mix(in srgb,var(--blue) 25%,var(--line));border-radius:14px;background:color-mix(in srgb,var(--blue) 6%,var(--panel));padding:10px;}}.evidence-title{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--blue);font-weight:800;margin-bottom:8px;}}
.entity-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;}}.entity-grid div,.mini-stat{{border:1px solid var(--line);border-radius:12px;background:var(--panel-2);padding:10px;}}.entity-grid span{{display:block;font-size:12px;color:var(--muted);}}.entity-grid strong{{display:block;margin-top:4px;word-break:break-word;}}
.timeline{{height:auto;background:transparent;border:0;border-radius:0;display:grid;gap:12px;overflow:visible;}}.timeline-item{{display:grid;grid-template-columns:34px 1fr;gap:10px;}}.timeline-marker{{width:14px;height:14px;border-radius:999px;background:var(--blue);margin:17px auto 0;box-shadow:0 0 0 6px color-mix(in srgb,var(--blue) 10%,transparent);}}.timeline-card{{border:1px solid var(--line);border-radius:16px;background:var(--panel);padding:14px;}}.timeline-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;}}.timeline-meta{{display:flex;flex-wrap:wrap;gap:8px 14px;color:var(--muted);font-size:12px;margin:10px 0;}}
.empty{{border:1px dashed var(--line);border-radius:16px;color:var(--muted);padding:16px;}}
{score_css}
{extra_css}
@media(max-width:1050px){{.hero-grid,.grid.two,.grid.three,.entity-grid{{grid-template-columns:1fr;}}.grid.kpi{{grid-template-columns:repeat(2,minmax(0,1fr));}}.matrix{{grid-template-columns:1fr;}}}}
@media(max-width:720px){{.wrap{{padding:14px;}}table{{display:block;overflow:auto;}}.section-title,.timeline-head{{display:grid;}}.report-controls{{justify-content:flex-start;overflow:auto;}}}}
@media print{{body{{background:#fff;color:#111827;}}.wrap{{max-width:none;padding:12px;}}nav,.filters,.report-controls,.toolbar{{display:none;}}section,header,.card{{box-shadow:none;background:#fff;color:#111827;border-color:#d1d5db;}}.muted,.footer{{color:#4b5563;}}table,th,td{{border-color:#d1d5db;}}th{{background:#f3f4f6;color:#111827;}}.pill{{background:#f3f4f6;color:#111827;}}}}
</style>{report_bootstrap_script()}"""
