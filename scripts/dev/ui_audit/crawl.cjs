#!/usr/bin/env node
/**
 * SLI UI auditor, step 1: crawl the SPA like a user and collect evidence.
 *
 * Usage:
 *   SLI_AUDIT_USER=... SLI_AUDIT_PASSWORD=... \
 *     node crawl.cjs <baseUrl> <outDir> <ru|en> [maxPages=120] [--rows=3] [--max-actions=800] [--per-route=8] [--seed=/app/path ...] [--headed]
 *
 * Credentials come ONLY from the environment and are never printed or stored.
 * Run it against a throwaway demo install, never against a working install:
 * the evidence (page text, screenshots) may later be given to an external LLM.
 *
 * What is walked: the /app entry page, every same-origin /app link, tabs
 * (role=tab), the first N explicitly clickable rows of each table
 * (row link or row click -> drawer/overlay/new route) and the pages those reach.
 * Only actions in policy.cjs are admitted. A passing dataset passport and an
 * isolated sli-audit-* stand are required before loading a browser.
 *
 * Output: <outDir>/evidence.jsonl (one JSON object per visited state) and
 * <outDir>/shots/*.png. Feed evidence.jsonl to rules.py.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");
const { createHash } = require("crypto");
const { ACTION_SELECTORS, allowAction, allowRequest, completionStatus, allowAccess } = require("./policy.cjs");
const { runScenario, observationMetadata } = require("./scenario_runner.cjs");
const { runModelScenario, operatorModel } = require("./model_walker.cjs");

function loadPlaywright() {
  const tried = [];
  const candidates = [process.env.SLI_AUDIT_PLAYWRIGHT, "@playwright/test", "playwright"].filter(Boolean);
  // Walk up from here so a worktree without node_modules finds the main checkout.
  let dir = __dirname;
  for (let i = 0; i < 8; i += 1) {
    candidates.push(path.join(dir, "node_modules", "@playwright", "test"));
    candidates.push(path.join(dir, "frontend", "node_modules", "@playwright", "test"));
    dir = path.dirname(dir);
  }
  for (const c of candidates) {
    try { return require(c); } catch (e) { tried.push(c); }
  }
  throw new Error("Playwright not found; set SLI_AUDIT_PLAYWRIGHT to its module path. Tried: " + tried.slice(0, 4).join(", "));
}
const SKIP_HREF = /(\/logout|\/api\/|^mailto:|^tel:|\/login)/i;

function parseArgs(argv) {
  const pos = [];
  const opt = { rows: 3, maxActions: 800, perRoute: 8, headed: false, settleMs: 20000 };
  for (const a of argv) {
    let m;
    if ((m = /^--rows=(\d+)$/.exec(a))) opt.rows = +m[1];
    else if ((m = /^--max-actions=(\d+)$/.exec(a))) opt.maxActions = +m[1];
    else if ((m = /^--per-route=(\d+)$/.exec(a))) opt.perRoute = +m[1];
    else if ((m = /^--settle-ms=(\d+)$/.exec(a))) opt.settleMs = +m[1];
    else if (a === "--headed") opt.headed = true;
    else if (a === "--model") opt.model = true;
    else if ((m = /^--scenario=([a-z0-9_]+)$/.exec(a))) opt.scenario = m[1];
    else if ((m = /^--seed=(\/app.*)$/.exec(a))) (opt.seeds = opt.seeds || []).push(m[1]);
    else pos.push(a);
  }
  if (pos.length < 3) {
    console.error("usage: node crawl.cjs <baseUrl> <outDir> <ru|en> [maxPages] [--rows=N] [--max-actions=N] [--per-route=N]");
    process.exit(2);
  }
  const parsed = { base: pos[0].replace(/\/+$/, ""), out: pos[1], locale: pos[2], maxPages: +(pos[3] || 120), ...opt };
  if ((parsed.model && !parsed.scenario) || !["ru", "en"].includes(parsed.locale) ||
      [parsed.maxPages, parsed.maxActions, parsed.perRoute, parsed.settleMs].some((value) => !Number.isInteger(value) || value < 1)) {
    throw new Error("invalid_crawl_arguments");
  }
  return parsed;
}

const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9а-яё]+/gi, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "x";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** /app/entities/<uuid> -> /app/entities/:id ; used to cap how many sibling detail pages are visited. */
function routeTemplate(u) {
  const p = u.pathname.split("/").map((seg) => (/^[0-9a-f-]{16,}$/i.test(seg) || /^\d+$/.test(seg) || seg.length > 28 || /[%@:]/.test(seg) ? ":id" : seg)).join("/");
  return p;
}
function normalizeUrl(href, base) {
  let u;
  try { u = new URL(href, base + "/"); } catch { return null; }
  if (u.origin !== new URL(base).origin) return null;
  if (!(u.pathname === "/app" || u.pathname.startsWith("/app/"))) return null;
  if (SKIP_HREF.test(u.pathname)) return null;
  const params = [...u.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
  const q = new URLSearchParams(params).toString();
  return { key: u.pathname.replace(/\/+$/, "") + (q ? "?" + q : ""), href: u.pathname + (q ? "?" + q : ""), template: routeTemplate(u) };
}

/** Count rows in a JSON API payload: arrays named items/rows/data/... or top-level arrays. */
function summarizeJson(body) {
  const preferred = ["items", "rows", "data", "results", "entries", "events", "records"];
  const arrays = {};
  let total = null;
  const visit = (obj, prefix, depth) => {
    if (!obj || typeof obj !== "object") return;
    if (Array.isArray(obj)) { arrays[prefix || "$"] = obj.length; return; }
    for (const [k, v] of Object.entries(obj)) {
      if (Array.isArray(v)) arrays[prefix ? prefix + "." + k : k] = v.length;
      else if (v && typeof v === "object" && depth < 2) visit(v, prefix ? prefix + "." + k : k, depth + 1);
      else if (typeof v === "number" && /^(total|total_count|count|total_rows|rows_total|matched|total_matches)$/i.test(k)) total = total === null ? v : total;
    }
  };
  visit(body, "", 0);
  let rows = null;
  const names = Object.keys(arrays);
  const pick = names.find((n) => n === "$") || names.find((n) => preferred.includes(n.split(".").pop()));
  if (pick) rows = arrays[pick];
  else if (names.length) rows = Math.max(...names.map((n) => arrays[n]));
  const metrics = Array.isArray(body?.metrics) ? body.metrics.map((m) => ({ key: m.key, value: m.value, filter: m.filter })) : [];
  const relationCollections = [];
  if (body?.object?.object_id && Array.isArray(body?.directory_context?.items)) {
    const items = body.directory_context.items;
    // The AD-context contract describes outbound member_of, not group members.
    const memberships = items.filter((item) => item.context_kind === "relation" &&
      [undefined, null, "member_of"].includes(item.attributes?.relation_kind ?? item.relation_kind) &&
      [undefined, null, "outbound"].includes(item.attributes?.direction ?? item.direction));
    const knownNames = new Set(memberships.map((item) => String(item.related_display_name || "").trim().toLowerCase()));
    const directNames = new Set();
    for (const item of items.filter((i) => i.context_kind === "entity")) {
      const raw = item.attributes?.member_of ?? item.attributes?.attributes?.member_of;
      for (const value of (Array.isArray(raw) ? raw : raw ? [raw] : [])) {
        const dn = String(value).trim();
        const match = /^CN=((?:\\.|[^,\\])+)/i.exec(dn);
        const name = (match ? match[1] : dn).replace(/\\(.)/g, "$1").trim().toLowerCase();
        if (name && !knownNames.has(name)) directNames.add(name);
      }
    }
    for (const tab of ["groups", "privileges"]) {
      const allowed = ["available", "ok", "partial", "stale"].includes(body.state) &&
        (body.tabs || []).some((t) => t.id === tab && t.available === true);
      const selected = tab === "groups" ? memberships : memberships.filter((item) => item.relation_class === "privileged" || /privileged/i.test(item.source_section || ""));
      relationCollections.push({ tab, collection: "directory_context.items", entity_id: String(body.object.object_id),
        relation_kind: tab === "groups" ? "member_of" : "privileged_member_of", direction: "outbound", authorized: allowed,
        rows: selected.length + (tab === "groups" ? directNames.size : 0) });
    }
  }
  const views = Array.isArray(body?.views) ? body.views.map((v) => ({ key: v.key, source: v.source || "items" })) : [];
  return { rows, total, arrays, metrics, views, relation_collections: relationCollections };
}

/** Free-form source fields; presentation states/titles/reasons are deliberately absent. */
function dataStrings(body, url = "") {
  // v2 definitions/catalog contain fixed presentation metadata, not user content.
  if (/^\/api\/v2\/reports(?:\/[^/?]+)?(?:\?|$)/.test(url)) return [];
  const fields = new Set(["display_name", "related_display_name", "name", "natural_key", "description", "sam_account_name",
    "distinguished_name", "dns_host_name", "department", "mail", "email", "source_host", "ou_path"]);
  const found = [];
  const visit = (value, prefix, depth) => {
    if (!value || typeof value !== "object" || depth > 8) return;
    for (const [key, child] of Object.entries(value)) {
      const fieldPath = prefix ? `${prefix}.${key}` : key;
      // A report definition's description is UI metadata; object/row descriptions are data.
      const dataContext = /(^|\.)(items|object|attributes|report|reports|entities)(\.|$)/.test(prefix);
      const personalTitle = key === "title" && (/\/(?:objects|entities)\//.test(url) || /\/reports\/vpn.accounts\/data/.test(url)) &&
        !/(^|\.)(semantic|metrics|limitations)(\.|$)/.test(prefix);
      const timestamp = /(?:_utc|_at|timestamp|datetime)$/.test(key);
      if (dataContext && (fields.has(key) || personalTitle || timestamp) && typeof child === "string" && /[А-Яа-яЁё]/.test(child)) {
        found.push({ text: child.replace(/\s+/g, " ").trim(), path: fieldPath });
      } else if (child && typeof child === "object") visit(child, fieldPath, depth + 1);
    }
  };
  visit(body, "", 0);
  return found;
}

/** Attach identities from the matching API source without guessing from UI words. */
function enrichSnapshot(snap, pathname, search, navCalls) {
  const report = /^\/app\/report\/([^/]+)$/.exec(pathname);
  const dataPath = report ? `/api/v2/reports/${report[1]}/data` : null;
  const dataCall = [...navCalls].reverse().find((c) => c.status === 200 && c.url.split("?")[0] === dataPath);
  const definition = [...navCalls].reverse().find((c) => c.status === 200 && c.views?.length &&
    dataCall?.url.startsWith(c.url.split("?")[0] + "/data"));
  const tab = new URLSearchParams(search).get("tab");
  const view = definition?.views.find((v) => v.key === tab) || definition?.views[0];
  const collection = view ? (view.source === "items" ? "items" : `collections.${view.source}`) : undefined;
  const mainTables = snap.tables?.filter((t) => !t.in_dialog) || [];
  if (dataCall && collection && mainTables.length === 1) {
    mainTables[0].source_url = dataCall.url; mainTables[0].collection = collection;
  }
  if (dataCall?.metrics?.length && dataCall.metrics.length === snap.metrics?.filter((m) => !m.in_dialog).length) {
    let index = 0;
    for (const metric of snap.metrics) {
      if (metric.in_dialog) continue;
      const source = dataCall.metrics[index++];
      if (String(source.value).replace(/\s/g, "") === metric.value.replace(/\s/g, "")) {
        metric.key = source.key; metric.filter = source.filter; metric.source_url = dataCall.url;
      }
    }
  }
  snap.relation_evidence = navCalls.filter((c) => c.status === 200).flatMap((c) => (c.relation_collections || []).map((r) => ({ ...r, url: c.url.split("?")[0] })));
  snap.tab_source = [...snap.relation_evidence].reverse().find((r) => r.tab === snap.active_tab_id);
  snap.active_collection = collection;
  return snap;
}

/** Runs in the page: everything the rules need to know about what is currently shown. */
function pageSnapshot({ locale, data = [] }) {
  const vis = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== "hidden" && cs.display !== "none" && cs.opacity !== "0";
  };
  const txt = (el) => (el.innerText || el.textContent || "").replace(/\s+/g, " ").trim();
  const dialogs = [...document.querySelectorAll('[role=dialog],[role=alertdialog],aside[aria-label],.sli-ds-drawer')].filter(vis);
  const inDialog = (el) => !!el.closest('[role=dialog],[role=alertdialog],.sli-ds-drawer');
  const headings = [...document.querySelectorAll("h1,h2,h3,h4,[role=heading]")].filter(vis).map((h) => txt(h)).filter(Boolean).slice(0, 40);
  const tabs = [...document.querySelectorAll('[role=tab]')].filter(vis).map((t) => ({ label: txt(t), selected: t.getAttribute("aria-selected") === "true" || t.getAttribute("aria-pressed") === "true" }));
  const placeholders = [];
  for (const el of document.querySelectorAll(".sli-ds-state")) {
    if (!vis(el)) continue;
    const r = el.getBoundingClientRect();
    placeholders.push({
      kind: "state", state: el.getAttribute("data-state") || "", tone: el.getAttribute("data-tone") || "",
      title: txt(el.querySelector(".sli-ds-state__title") || el).slice(0, 160),
      text: txt(el.querySelector(".sli-ds-state__text") || { innerText: "" }),
      detail: txt(el.querySelector(".sli-ds-state__detail") || { innerText: "" }),
      w: Math.round(r.width), h: Math.round(r.height), in_dialog: inDialog(el),
      in_tabpanel: !!el.closest('[role=tabpanel]'), role: el.getAttribute("role") || "",
    });
  }
  const stubRe = /(нет данных|данных нет|пока нет|не найден|недоступн|будет доступн|в разработке|не подключ|нет записей|нет строк|no data|nothing found|not available|coming soon|no records|no rows|not connected|under development)/i;
  const stubs = [];
  for (const el of document.querySelectorAll("p,div,span,li,td")) {
    if (el.children.length > 2 || !vis(el)) continue;
    const s = txt(el);
    if (s.length > 4 && s.length < 220 && stubRe.test(s) && !el.closest(".sli-ds-state")) stubs.push({ text: s, in_dialog: inDialog(el), tag: el.tagName.toLowerCase() });
    if (stubs.length >= 15) break;
  }
  const tables = [...document.querySelectorAll("table")].filter(vis).map((tb) => {
    const wrap = tb.closest(".sli-ds-table");
    const footer = wrap ? txt(wrap.querySelector(".sli-ds-table__footer") || { innerText: "" }) : "";
    const m = /(\d[\d\s .,]*)\s*(?:из|of)\s*(\d[\d\s .,]*)/i.exec(footer);
    const num = (s) => (s ? Number(String(s).replace(/[^\d]/g, "")) : null);
    return {
      caption: txt(tb.querySelector("caption") || { innerText: "" }).slice(0, 120),
      headers: [...tb.querySelectorAll("thead th")].map((h) => txt(h)).slice(0, 20),
      rows: tb.querySelectorAll("tbody tr").length, footer: footer.slice(0, 160), total: m ? num(m[2]) : null,
      in_dialog: inDialog(tb), clickable_rows: tb.querySelectorAll("tbody tr[data-clickable]").length,
      first_row: txt(tb.querySelector("tbody tr") || { innerText: "" }).slice(0, 200),
    };
  });
  const metrics = [...document.querySelectorAll(".sli-ds-metric")].filter(vis).map((m) => ({
    label: txt(m.querySelector(".sli-ds-metric__label") || { innerText: "" }), value: txt(m.querySelector(".sli-ds-metric__value") || { innerText: "" }),
    caption: txt(m.querySelector(".sli-ds-metric__caption") || { innerText: "" }).slice(0, 120), in_dialog: inDialog(m),
  }));
  let cyrillic = [];
  if (locale === "en") {
    const provenance = (s, el, attr) => {
      const fixed = !attr && el.closest('th,label,[role=tab],.sli-ds-metric__label,.sli-ds-state');
      if (fixed) return { origin: "ui" };
      const exact = data.find((d) => d.text === s);
      if (exact) return { origin: "data", source_path: exact.path };
      if (attr) {
        let template = s;
        const paths = [];
        for (const d of [...data].sort((a, b) => b.text.length - a.text.length)) {
          if (!d.text) continue;
          const escaped = d.text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
          const pattern = new RegExp(`(^|[^\\p{L}\\p{N}_])${escaped}(?=$|[^\\p{L}\\p{N}_])`, "gu");
          const replaced = template.replace(pattern, (_, prefix) => prefix + "{data}");
          if (replaced !== template) { template = replaced; paths.push(d.path); }
        }
        if (paths.length) return { origin: "ui", template, source_paths: paths };
      }
      return { origin: "ui" };
    };
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const seen = new Set();
    while (walker.nextNode()) {
      const n = walker.currentNode; const s = (n.nodeValue || "").replace(/\s+/g, " ").trim();
      if (!s || !/[А-Яа-яЁё]/.test(s)) continue;
      const el = n.parentElement;
      if (!el || ["SCRIPT", "STYLE", "NOSCRIPT"].includes(el.tagName) || !vis(el)) continue;
      const origin = provenance(s, el, null);
      const signature = JSON.stringify([s, origin]);
      if (seen.has(signature)) continue;
      seen.add(signature);
      cyrillic.push({ text: s, ...origin, tag: el.tagName.toLowerCase(), in_table: !!el.closest("td,th"), in_dialog: inDialog(el), cls: String(el.className || "").slice(0, 60) });
      if (cyrillic.length >= 80) break;
    }
    for (const el of document.querySelectorAll("[aria-label],[title],[placeholder]")) {
      for (const a of ["aria-label", "title", "placeholder"]) {
        const v = el.getAttribute(a);
        if (!vis(el) || !v || !/[А-Яа-яЁё]/.test(v) || cyrillic.length >= 100) continue;
        const origin = provenance(v, el, a);
        const signature = JSON.stringify([v, origin]);
        if (!seen.has(signature)) { seen.add(signature); cyrillic.push({ text: v, ...origin, tag: el.tagName.toLowerCase(), attr: a, in_table: !!el.closest("td,th"), in_dialog: inDialog(el), cls: "" }); }
      }
    }
  }
  const busy = !!document.querySelector('.sli-ds-loading,[aria-busy="true"],.sli-ds-skeleton,[data-loading="true"]');
  const body = (document.body.innerText || "").replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
  // Keep factual context together for the private evaluator. Never manufacture
  // an answer from API data or from the hidden expected answer.
  const answerBlocks = [
    ...body.split("\n").map((line) => line.trim()).filter(Boolean),
    ...[...document.querySelectorAll("table tbody tr,.sli-ds-metric,.sli-ds-home-rows li")].filter(vis).map(txt),
  ];
  return {
    title: document.title, h: headings, tabs, placeholders, stubs, tables, metrics, cyrillic, busy,
    active_tab_id: document.querySelector('[role=tab][aria-selected=true]')?.id?.replace(/^entity-tab-/, ""),
    dialog_open: dialogs.length > 0, dialog_text: dialogs.length ? txt(dialogs[0]).slice(0, 1500) : "",
    text: body.slice(0, 7000), text_len: body.length, lang: document.documentElement.lang || "",
    links: [...document.querySelectorAll("a[href]")].filter(vis).map((a) => a.getAttribute("href")).filter(Boolean),
    answer_blocks: answerBlocks,
  };
}

async function main() {
  const opt = parseArgs(process.argv.slice(2));
  // Admission is shared with the stand launcher. Never trust a saved "pass"
  // without rescanning the exact dataset and checking its current digest.
  const gate = spawnSync(process.env.SLI_AUDIT_PYTHON || "python", ["-m", "scripts.dev.ui_audit.stand", "check", "--base", opt.base, "--out", opt.out],
    { cwd: path.resolve(__dirname, "../../.."), encoding: "utf8" });
  if (gate.status !== 0) {
    const status = gate.status === 2 ? "blocked" : "infra_failure";
    console.error(`${status}: audit_admission_failed`);
    process.exitCode = gate.status === 2 ? 2 : 3;
    return;
  }
  const admission = JSON.parse(gate.stdout);
  let scenarioPlan;
  if (opt.scenario) {
    const planned = spawnSync(process.env.SLI_AUDIT_PYTHON || "python", ["-m", "scripts.dev.ui_audit.scenarios", "plan",
      "--scenario", opt.scenario, "--locale", opt.locale, "--base", opt.base, "--out", opt.out],
      { cwd: path.resolve(__dirname, "../../.."), encoding: "utf8" });
    if (planned.status !== 0) { console.error("blocked: scenario_plan_rejected"); process.exitCode = 2; return; }
    scenarioPlan = JSON.parse(planned.stdout);
  }
  let walkerModel;
  if (opt.model) {
    const configured = spawnSync(process.env.SLI_AUDIT_PYTHON || "python", ["-m", "scripts.dev.ui_audit.model_review", "configure",
      "--base", opt.base, "--out", opt.out], { cwd: path.resolve(__dirname, "../../.."), encoding: "utf8" });
    if (configured.status !== 0) { console.error("blocked: model_configuration_rejected"); process.exitCode = 2; return; }
    walkerModel = operatorModel();
  }
  const user = process.env.SLI_AUDIT_USER;
  const pass = process.env.SLI_AUDIT_PASSWORD;
  if (!user || !pass) { console.error("not_run: audit_credentials_required"); process.exitCode = 2; return; }
  fs.mkdirSync(path.join(opt.out, "shots"), { recursive: true });
  const run = { ...admission, status: "not_run", reason: "browser_not_started",
    ...(opt.model ? { mode: "model", model_status: "not_run" } : {}),
    coverage: { max_pages: opt.maxPages, max_actions: opt.maxActions, per_route: opt.perRoute, rows: opt.rows } };
  const saveRun = () => fs.writeFileSync(path.join(opt.out, "run.json"), JSON.stringify(run, null, 2));
  saveRun();
  const evPath = path.join(opt.out, "evidence.jsonl");
  fs.writeFileSync(evPath, "");
  let browser;
  let infraFailures = 0;
  let guardBlocked = false;
  let loginPhase = true;
  try {
  const { chromium } = loadPlaywright();
  browser = await chromium.launch({ channel: process.env.SLI_AUDIT_CHANNEL || "msedge", headless: !opt.headed });
  run.reason = "crawl_started";
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: opt.locale === "en" ? "en-US" : "ru-RU",
    ...(scenarioPlan ? { timezoneId: scenarioPlan.time_zone } : {}), serviceWorkers: "block" });
  const origin = new URL(opt.base).origin;
  await ctx.route("**/*", async (route) => {
    const request = route.request();
    const decision = allowRequest(request.url(), request.method(), origin, loginPhase, !!request.redirectedFrom());
    if (!decision.allowed) {
      guardBlocked = true;
      await route.abort("blockedbyclient");
      return;
    }
    try {
      // Browser routing intercepts only the first redirect hop. Do not follow
      // redirects in either the API fetch or the browser.
      const response = await route.fetch({ maxRedirects: 0 });
      const location = response.headers().location;
      if (response.status() >= 300 && response.status() < 400 && location) {
        guardBlocked = true;
        await route.abort("blockedbyclient");
        return;
      }
      await route.fulfill({ response });
    } catch {
      infraFailures += 1;
      await route.abort("failed").catch(() => {});
    }
  });
  if (typeof ctx.routeWebSocket !== "function") throw new Error("websocket_guard_unavailable");
  await ctx.routeWebSocket("**/*", (socket) => { guardBlocked = true; socket.close(); });
  await ctx.addInitScript((loc) => { try { window.localStorage.setItem("sli.locale", loc); } catch { /* ignore */ } }, opt.locale);
  if (scenarioPlan) {
    await ctx.addInitScript(({ fixed_time, time_zone }) => {
      localStorage.setItem("sli.timeZone", time_zone);
      const RealDate = Date;
      const fixed = RealDate.parse(fixed_time);
      // Freeze wall-clock queries, while preserving real timers for UI settling.
      class ScenarioDate extends RealDate {
        constructor(...args) { super(...(args.length ? args : [fixed])); }
        static now() { return fixed; }
      }
      window.Date = ScenarioDate;
    }, scenarioPlan);
  }
  const page = await ctx.newPage();

  // ---- network / console capture -------------------------------------------------
  let calls = []; let navCalls = []; let consoleErrors = []; let failed = []; let sourceData = [];
  let responseReads = 0;
  const pendingSet = new Set();
  page.on("request", (r) => { if (/\/api\//.test(r.url())) { pendingSet.add(r); } });
  page.on("requestfinished", (r) => pendingSet.delete(r));
  page.on("requestfailed", (r) => {
    pendingSet.delete(r);
    if (/\/api\//.test(r.url()) || r.resourceType() === "document") failed.push({ method: r.method(), url: new URL(r.url()).pathname, error: (r.failure() || {}).errorText || "failed" });
  });
  page.on("console", (m) => { if (m.type() === "error") {
    const location = m.location();
    let url = "";
    try { const u = new URL(location.url); url = u.pathname + u.search; } catch { /* no resource location */ }
    consoleErrors.push({ text: m.text().slice(0, 300), url });
  } });
  page.on("pageerror", (e) => consoleErrors.push("pageerror: " + String(e.message || e).slice(0, 300)));
  page.on("response", async (resp) => {
    const req = resp.request();
    let u;
    try { u = new URL(resp.url()); } catch { return; }
    if (!u.pathname.startsWith("/api/")) return;
    responseReads += 1;
    const rec = { method: req.method(), url: u.pathname + (u.search ? u.search.slice(0, 200) : ""), status: resp.status() };
    const startedAt = req.timing().startTime;
    try {
      const ct = resp.headers()["content-type"] || "";
      if (ct.includes("json")) {
        const buf = await resp.body();
        rec.bytes = buf.length;
        if (buf.length < 8e6) {
          const body = JSON.parse(buf.toString("utf8"));
          Object.assign(rec, summarizeJson(body));
          if (scenarioPlan) Object.assign(rec, observationMetadata(body, rec.url));
          if (rec.status === 200) sourceData.push(...dataStrings(body, rec.url));
        }
      }
    } catch { /* body not available (redirect/aborted) */ }
    if (startedAt > 0) rec.duration_ms = Math.round(Date.now() - startedAt);
    calls.push(rec); navCalls.push(rec);
    responseReads -= 1;
  });

  // ---- login -----------------------------------------------------------------------
  let loggedIn = false;
  for (let attempt = 1; attempt <= 3 && !loggedIn; attempt += 1) {
    await page.goto(opt.base + "/login", { waitUntil: "domcontentloaded" });
    await page.fill("input[autocomplete=username], input[name=username], input#username", user);
    await page.fill("input[type=password]", pass);
    await Promise.all([page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 20000 }).catch(() => {}), page.keyboard.press("Enter")]);
    loggedIn = !new URL(page.url()).pathname.startsWith("/login");
    if (!loggedIn) await sleep(4000 * attempt);
  }
  loginPhase = false;
  if (!loggedIn) {
    run.status = guardBlocked ? "blocked" : "infra_failure";
    run.reason = "login_failed";
    process.exitCode = 3;
    return;
  }
  const account = JSON.parse(fs.readFileSync(path.join(__dirname, "access_levels.json"), "utf8")).accounts[admission.access_level];
  const effective = await page.evaluate(async () => {
    const response = await fetch("/api/v1/access/effective");
    return response.ok ? response.json() : null;
  });
  if (!allowAccess(effective, account)) {
    guardBlocked = true;
    run.status = "blocked";
    run.reason = "read_only_access_level_mismatch";
    process.exitCode = 2;
    return;
  }

  // ---- crawl state ------------------------------------------------------------------
  let actions = 0; let seq = 0; let stateCount = 0;
  const visited = new Set(); const queued = new Set(); const perTemplate = new Map();
  const queue = [];
  const enqueue = (href, from) => {
    const n = normalizeUrl(href, opt.base);
    if (!n || visited.has(n.key) || queued.has(n.key)) return;
    const used = perTemplate.get(n.template) || 0;
    if (used >= opt.perRoute) return;
    perTemplate.set(n.template, used + 1);
    queued.add(n.key); queue.push({ href: n.href, key: n.key, from });
  };

  async function settle(startedAt) {
    let quiet = 0; let timedOut = false;
    for (;;) {
      await sleep(150);
      const busy = pendingSet.size > 0 || (scenarioPlan && responseReads > 0) || await page.evaluate(() => !!document.querySelector('.sli-ds-loading,[aria-busy="true"],.sli-ds-skeleton,[data-loading="true"]')).catch(() => false);
      quiet = busy ? 0 : quiet + 1;
      if (quiet >= 3) break;
      if (Date.now() - startedAt > opt.settleMs) { timedOut = true; infraFailures += 1; break; }
    }
    return { ms: Date.now() - startedAt, timedOut };
  }

  async function record(state, extra, observedSnapshot) {
    seq += 1;
    const snap = observedSnapshot || await page.evaluate(pageSnapshot, { locale: opt.locale, data: sourceData }).catch(() => {
      infraFailures += 1;
      return { error: "snapshot_failed", links: [], text: "" };
    });
    const location = new URL(page.url());
    enrichSnapshot(snap, location.pathname, location.search, navCalls);
    const id = String(seq).padStart(4, "0");
    const shot = path.join("shots", `${id}_${slug(new URL(page.url()).pathname.replace(/^\/app/, "") + "_" + state)}.png`);
    await page.screenshot({ path: path.join(opt.out, shot) }).catch(() => { infraFailures += 1; });
    const u = new URL(page.url());
    const rec = {
      id, locale: opt.locale, url: u.pathname + u.search, state, ...extra,
      title: snap.title, headings: snap.h, tabs: snap.tabs, text: snap.text, text_len: snap.text_len,
      dialog_open: snap.dialog_open, dialog_text: snap.dialog_text,
      placeholders: snap.placeholders, stubs: snap.stubs, tables: snap.tables, metrics: snap.metrics,
      cyrillic: snap.cyrillic, html_lang: snap.lang,
      tab_source: snap.tab_source, relation_evidence: snap.relation_evidence, active_collection: snap.active_collection,
      api_calls: calls, api_calls_since_nav: navCalls,
      console_errors: consoleErrors, failed_requests: failed,
      still_busy: !!snap.busy, screenshot: shot.replace(/\\/g, "/"), error: extra?.error || snap.error,
    };
    fs.appendFileSync(evPath, JSON.stringify(rec) + "\n");
    stateCount += 1;
    calls = []; consoleErrors = []; failed = [];
    return snap;
  }

  async function gotoUrl(href) {
    calls = []; navCalls = []; consoleErrors = []; failed = []; sourceData = [];
    const t0 = Date.now();
    let status = null;
    try {
      const resp = await page.goto(opt.base + href, { waitUntil: "domcontentloaded", timeout: 30000 });
      status = resp ? resp.status() : null;
    } catch { infraFailures += 1; failed.push({ method: "GET", url: href, error: "navigation_failed" }); }
    if (status === null || status >= 500) infraFailures += 1;
    const s = await settle(t0);
    actions += 1;
    return { status, ...s };
  }

  const clickables = (kind) => page.evaluate(({ kind, selector }) => {
    const vis = (el) => { const r = el.getBoundingClientRect(); return r.width > 2 && r.height > 2 && getComputedStyle(el).visibility !== "hidden"; };
    const inDialog = (el) => !!el.closest('[role=dialog],[role=alertdialog],.sli-ds-drawer');
    const label = (el) => ((el.getAttribute("aria-label") || "") + " " + (el.innerText || el.textContent || "")).replace(/\s+/g, " ").trim();
    const mark = (els) => els.map((el, i) => { el.setAttribute("data-audit-idx", kind + i); return { idx: kind + i, label: label(el).slice(0, 80), selected: el.getAttribute("aria-selected") === "true" || el.getAttribute("aria-pressed") === "true", in_dialog: inDialog(el) }; });
    return mark([...document.querySelectorAll(selector)].filter((e) => vis(e) && !e.disabled));
  }, { kind, selector: ACTION_SELECTORS[kind] });

  async function closeOverlay() {
    const open = await page.evaluate(() => !!document.querySelector('[role=dialog],[role=alertdialog],.sli-ds-drawer')).catch(() => false);
    if (allowAction("close", { dialogOpen: open })) { await page.keyboard.press("Escape").catch(() => { infraFailures += 1; }); await sleep(250); }
  }

  /** Click a marked element; returns {changedUrl, state info}. */
  async function clickMarked(idx) {
    const loc = page.locator(`[data-audit-idx="${idx}"]`).first();
    if (!(await loc.count())) return null;
    const descriptor = await loc.evaluate((el) => ({ role: el.getAttribute("role"), tag: el.tagName,
      disabled: !!el.disabled || el.getAttribute("aria-disabled") === "true", clickable: el.hasAttribute("data-clickable"), inTable: !!el.closest("table tbody") }));
    const kind = idx.startsWith("tab") ? "tab" : idx.startsWith("row") ? "row" : "unknown";
    if (!allowAction(kind, descriptor)) { guardBlocked = true; return null; }
    await loc.scrollIntoViewIfNeeded({ timeout: 3000 }).catch(() => {});
    calls = []; consoleErrors = []; failed = [];
    const before = page.url();
    const t0 = Date.now();
    await loc.click({ timeout: 4000 }).catch(() => { infraFailures += 1; });
    actions += 1;
    const s = await settle(t0);
    return { changedUrl: page.url() !== before, ...s };
  }

  if (scenarioPlan) {
    const screen = () => { const u = new URL(page.url()); return u.pathname + u.search; };
    const locator = (step) => page.locator(step.action === "link" ? step.selector : ACTION_SELECTORS[step.action]).nth(step.index);
    const driver = {
      currentScreen: screen,
      safeLink: (href) => !!normalizeUrl(href, opt.base),
      goto: async (target) => {
        const nav = await gotoUrl(target);
        if (nav.status === null || nav.status >= 400 || nav.timedOut || !normalizeUrl(page.url(), opt.base)) throw new Error("scenario_navigation_failed");
      },
      describe: async (step) => {
        const loc = locator(step);
        if (!(await loc.count()) || !(await loc.isVisible())) return null;
        return loc.evaluate((el) => ({ role: el.getAttribute("role"), tag: el.tagName,
          visible: true, disabled: !!el.disabled || el.getAttribute("aria-disabled") === "true",
          target: el.tagName === "A" ? el.getAttribute("href") : null,
          clickable: el.hasAttribute("data-clickable"), inTable: !!el.closest("table tbody") }));
      },
      offerActions: async () => page.evaluate((selectors) => {
        const actions = [];
        for (const [action, selector] of Object.entries({ link: "a[href]", row: selectors.row, tab: selectors.tab })) {
          [...document.querySelectorAll(selector)].forEach((el, index) => {
            const rect = el.getBoundingClientRect();
            if (rect.width > 2 && rect.height > 2 && getComputedStyle(el).visibility !== "hidden") {
              actions.push({ action, selector, index, label: (el.getAttribute("aria-label") || el.innerText || "").slice(0, 160) });
            }
          });
        }
        return actions;
      }, ACTION_SELECTORS),
      click: async (step) => {
        calls = []; navCalls = []; consoleErrors = []; failed = []; sourceData = [];
        await locator(step).click({ timeout: 4000 });
        actions += 1;
        const settled = await settle(Date.now());
        if (settled.timedOut || !normalizeUrl(page.url(), opt.base)) throw new Error("scenario_click_failed");
      },
      observe: async () => {
        if (guardBlocked || infraFailures) throw new Error("scenario_guard_failed");
        const snap = await page.evaluate(pageSnapshot, { locale: opt.locale, data: sourceData });
        return { snap, blocks: snap.answer_blocks,
          observed_scopes: [...new Set(calls.flatMap((c) => c.observed_scopes || []))],
          observed_tokens: [...new Set(calls.flatMap((c) => c.observed_tokens || []))],
          observed_problem_ids: [...new Set(calls.flatMap((c) => c.observed_problem_ids || []))],
          raw_evidence_observed: calls.some((c) => c.raw_evidence_observed) };
      },
      write: async (entry, observed) => { await record("scenario", entry, observed.snap); },
    };
    const result = opt.model ? await runModelScenario(scenarioPlan, driver, walkerModel) : await runScenario(scenarioPlan, driver);
    run.status = result.completed ? "completed" : "blocked";
    run.reason = result.completed ? "scenario_route_completed" : "scenario_route_blocked";
    Object.assign(run, { scenario_id: scenarioPlan.run_id, model_status: opt.model ? "walker_finished" : "not_run",
      ...(opt.model ? { mode: "model", duration_ms: result.duration_ms, walker_model_calls: result.model_calls } : {}), states: stateCount,
      actions: result.records.length, evidence_sha256: createHash("sha256").update(fs.readFileSync(evPath)).digest("hex") });
    saveRun();
    const scored = spawnSync(process.env.SLI_AUDIT_PYTHON || "python", ["-m", opt.model ? "scripts.dev.ui_audit.model_review" : "scripts.dev.ui_audit.scenarios", "score",
      "--scenario", opt.scenario, "--locale", opt.locale, "--base", opt.base, "--out", opt.out],
      { cwd: path.resolve(__dirname, "../../.."), encoding: "utf8" });
    if (opt.model) {
      // The evaluator owns final status; finally/saveRun must preserve its readback.
      Object.assign(run, JSON.parse(fs.readFileSync(path.join(opt.out, "run.json"), "utf8")));
      if (scored.status !== 0) run.accepted = false;
    } else run.metric_status = scored.status === 0 ? "passed" : "failed";
    if (scored.status !== 0 || !result.completed) process.exitCode = 1;
    return;
  }

  async function explorePage(item, nav) {
    const baseUrl = item.href;
    const pageState = await record("page", { from: item.from, nav_status: nav.status, settle_ms: nav.ms, settle_timeout: nav.timedOut, action: "goto" });
    for (const l of pageState.links || []) enqueue(l, baseUrl);
    if (pageState.error) return;

    // tabs ---------------------------------------------------------------
    let tabs = await clickables("tab");
    for (let i = 0; i < tabs.length && actions < opt.maxActions; i += 1) {
      const tab = tabs[i];
      if (tab.in_dialog || tab.selected) continue;
      const res = await clickMarked(tab.idx);
      if (!res) continue;
      const snap = await record("tab:" + tab.label, { from: baseUrl, parent_url: baseUrl, action: "tab", tab_label: tab.label, settle_ms: res.ms, settle_timeout: res.timedOut });
      for (const l of snap.links || []) enqueue(l, baseUrl);
      if (res.changedUrl) { enqueue(page.url().replace(opt.base, ""), baseUrl); }
      tabs = await clickables("tab"); // the DOM may have re-rendered
    }

    // rows -----------------------------------------------------------------
    const tables = pageState.tables || [];
    if (tables.some((t) => t.rows > 0 && !t.in_dialog) && opt.rows > 0) {
      let rows = await clickables("row");
      rows = rows.filter((r) => !r.in_dialog).slice(0, opt.rows);
      for (let i = 0; i < rows.length && actions < opt.maxActions; i += 1) {
        // Row link first: just remember it, the BFS visits it as a page.
        const href = await page.evaluate((idx) => { const a = document.querySelector(`[data-audit-idx="${idx}"] a[href]`); return a ? a.getAttribute("href") : null; }, rows[i].idx);
        if (href) { enqueue(href, baseUrl); continue; }
        const clickable = await page.evaluate((idx) => !!document.querySelector(`[data-audit-idx="${idx}"][data-clickable]`), rows[i].idx);
        if (!clickable) continue;
        const res = await clickMarked(rows[i].idx);
        if (!res) continue;
        const snap = await record("row:" + (i + 1), { from: baseUrl, parent_url: baseUrl, action: "row", row_label: rows[i].label, settle_ms: res.ms, settle_timeout: res.timedOut });
        for (const l of snap.links || []) enqueue(l, baseUrl);
        if (res.changedUrl) {
          enqueue(page.url().replace(opt.base, ""), baseUrl);
          await gotoUrl(baseUrl); // come back to the list and re-mark
        } else if (snap.dialog_open) {
          // tabs inside the drawer/overlay
          const dtabs = (await clickables("tab")).filter((t) => t.in_dialog && !t.selected).slice(0, 8);
          for (const dt of dtabs) {
            if (actions >= opt.maxActions) break;
            const r2 = await clickMarked(dt.idx);
            if (!r2) continue;
            await record(`row:${i + 1}/tab:${dt.label}`, { from: baseUrl, parent_url: baseUrl, action: "dialog-tab", tab_label: dt.label, settle_ms: r2.ms, settle_timeout: r2.timedOut });
          }
          await closeOverlay();
        }
        rows = (await clickables("row")).filter((r) => !r.in_dialog).slice(0, opt.rows);
      }
    }
  }

  // ---- seeds and BFS ------------------------------------------------------------------
  (opt.seeds || ["/app/", "/app/reports", "/app/scenarios", "/app/settings", "/app/objects", "/app/operations", "/app/project-readiness"]).forEach((s) => enqueue(s, "seed"));
  while (queue.length && stateCount < opt.maxPages * 6 && actions < opt.maxActions && visited.size < opt.maxPages) {
    const item = queue.shift();
    if (visited.has(item.key)) continue;
    visited.add(item.key);
    try {
      const nav = await gotoUrl(item.href);
      const finalPath = new URL(page.url()).pathname;
      if (finalPath.startsWith("/login")) { infraFailures += 1; break; }
      await explorePage(item, nav);
    } catch {
      infraFailures += 1;
      fs.appendFileSync(evPath, JSON.stringify({ id: "err", locale: opt.locale, url: item.href, state: "crawler-error", error: "crawler_step_failed" }) + "\n");
    }
    if (visited.size % 10 === 0) console.log(`[crawl ${opt.locale}] pages=${visited.size} states=${stateCount} actions=${actions} queue=${queue.length}`);
  }
  console.log(`[crawl ${opt.locale}] done: pages=${visited.size} states=${stateCount} actions=${actions} unvisited=${queue.length}`);
  run.status = completionStatus({ started: true, blocked: guardBlocked || stateCount === 0, failures: infraFailures, remaining: queue.length || (actions >= opt.maxActions ? 1 : 0) });
  run.reason = run.status === "completed" ? "queue_exhausted" : run.status === "blocked" ? "guard_or_budget" : "crawl_infrastructure_failed";
  Object.assign(run, { pages: visited.size, states: stateCount, actions,
    evidence_sha256: createHash("sha256").update(fs.readFileSync(evPath)).digest("hex") });
  fs.writeFileSync(path.join(opt.out, "crawl_summary.json"), JSON.stringify({ status: run.status, locale: opt.locale, pages: visited.size, states: stateCount, actions, unvisited: queue.map((q) => q.href) }, null, 1));
  if (run.status !== "completed") process.exitCode = 1;
  } catch {
    run.status = guardBlocked ? "blocked" : "infra_failure";
    run.reason = "crawler_infrastructure_failed";
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close().catch(() => {});
    saveRun();
  }
}

if (require.main === module) main().catch(() => { console.error("infra_failure: crawler_failed"); process.exitCode = 1; });
