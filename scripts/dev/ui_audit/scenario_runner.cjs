"use strict";

const { allowAction } = require("./policy.cjs");

function validatePlan(plan) {
  const allowed = new Set(["goto", "link", "row", "tab", "answer"]);
  const safeTarget = (target) => {
    if (typeof target !== "string" || !/^\/app(?:\/|$)/.test(target)) return false;
    const parsed = new URL(target, "http://127.0.0.1");
    return parsed.origin === "http://127.0.0.1" && /^\/app(?:\/|$)/.test(parsed.pathname) &&
      !/(?:\/logout|\/login|\/api\/)/i.test(parsed.pathname);
  };
  if (!plan || plan.persona !== "information_security_specialist" ||
      !["full", "limited-scope", "no-raw-evidence"].includes(plan.access_level) ||
      !["ru", "en"].includes(plan.locale) || !Number.isFinite(Date.parse(plan.fixed_time)) ||
      !Number.isInteger(plan.max_steps) || plan.max_steps < 1 ||
      !Number.isFinite(plan.max_seconds) || plan.max_seconds <= 0 ||
      !safeTarget(plan.start_page) || !Array.isArray(plan.route) || !plan.route.length ||
      !Array.isArray(plan.allowed_actions) || !plan.allowed_actions.includes("goto") || plan.allowed_actions.some((a) => !allowed.has(a)) ||
      plan.route.at(-1).action !== "answer" || plan.route.slice(0, -1).some((s) => s.action === "answer") ||
      plan.route.length + 1 > plan.max_steps || "expected_answer" in plan || "claims" in plan ||
      plan.route.some((s) => !allowed.has(s.action) || !plan.allowed_actions.includes(s.action) ||
        (s.action === "goto" && !safeTarget(s.target)) ||
        (["link", "row", "tab"].includes(s.action) && (!Number.isInteger(s.index) || s.index < 0)) ||
        (s.action === "link" && typeof s.selector !== "string"))) {
    throw new Error("invalid_scenario_plan");
  }
  new Intl.DateTimeFormat("en", { timeZone: plan.time_zone });
}

// Inspect structured responses, including identifiers in hidden/out-of-scope rows.
// Do not retain raw values in these metadata; the certified UI transcript is separate.
function observationMetadata(body, url = "") {
  const scopes = new Set();
  const tokens = new Set();
  let raw = false;
  function visit(value) {
    if (typeof value === "string") {
      for (const token of value.match(/\banon_(?:name|login|email|ip|dn|host|sid|domain|id)_\d+\b/g) || []) tokens.add(token);
      return;
    }
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (["scope_id", "domain_id"].includes(key) && Number.isInteger(child)) scopes.add(child);
      if (["collection_scope_id", "collection_scope_ids"].includes(key)) {
        for (const code of Array.isArray(child) ? child : [child]) {
          const match = /^ad-domain:(\d+)$/.exec(String(code));
          if (match) scopes.add(Number(match[1]));
        }
      }
      if ((key === "raw_evidence" || /(?:^|_)(?:xml|payload)$/.test(key)) &&
          child !== null && child !== undefined && child !== "" &&
          !(Array.isArray(child) && !child.length)) raw = true;
      visit(child);
    }
  }
  visit(body);
  const problemRows = /^\/api\/v2\/reports\/security\.problems\/data(?:\?|$)/.test(url) ? body?.items : body?.action_queue?.items;
  return { observed_scopes: [...scopes].sort((a, b) => a - b), raw_evidence_observed: raw,
    observed_tokens: [...tokens].sort(), observed_problem_ids: (problemRows || []).map((r) => r.id).filter(Number.isInteger) };
}

function observedAnswer(blocks) {
  const refusal = blocks.some((text) => /(?:нет доступа к сырым доказательствам|raw evidence access denied)/i.test(text))
    ? "raw_evidence_denied" : null;
  return { blocks, refusal };
}

/** The driver receives only the public plan, never the dataset or the oracle. */
async function runScenario(plan, driver, now = () => performance.now()) {
  validatePlan(plan);
  const started = now();
  const route = [{ action: "goto", target: plan.start_page }, ...plan.route];
  const answerBlocks = [];
  const records = [];
  for (const step of route) {
    const screen = driver.currentScreen();
    let blocked = false;
    let error;
    let observation = { blocks: [] };
    const remaining = plan.max_seconds * 1000 - (now() - started);
    if (remaining <= 0 || records.length >= plan.max_steps) {
      blocked = true;
      error = "scenario_budget_exceeded";
    } else {
      // Enforce wall time even if a driver action stalls. The outer crawler closes
      // its browser on return; no second scenario is started on that context.
      let timer;
      try {
        observation = await Promise.race([
          (async () => {
            if (step.action === "goto") {
              await driver.goto(step.target);
            } else if (["link", "row", "tab"].includes(step.action)) {
              const element = await driver.describe(step);
              if (!element || (step.action === "link" ? !element.visible || element.disabled ||
                  !element.target || !driver.safeLink(element.target) : !allowAction(step.action, element))) {
                throw new Error("scenario_action_blocked");
              }
              await driver.click(step);
            }
            return driver.observe();
          })(),
          new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("scenario_budget_exceeded")), remaining); }),
        ]);
      } catch {
        blocked = true;
        error = "scenario_step_blocked";
      } finally {
        clearTimeout(timer);
      }
    }
    answerBlocks.push(...(observation.blocks || []));
    const record = { scenario_id: plan.run_id, locale: plan.locale,
      fixed_time: plan.fixed_time, time_zone: plan.time_zone, data_snapshot_id: plan.data_snapshot_id,
      screen, action: step.action, target: step.target, next_screen: driver.currentScreen(),
      elapsed_ms: Math.max(0, Math.round(now() - started)), blocked,
      ...(error ? { error } : {}),
      answer: step.action === "answer" && !blocked ? observedAnswer([...new Set(answerBlocks)]) : null,
      observed_scopes: observation.observed_scopes || [], raw_evidence_observed: !!observation.raw_evidence_observed };
    record.observed_tokens = observation.observed_tokens || [];
    record.observed_problem_ids = observation.observed_problem_ids || [];
    records.push(record);
    await driver.write(record, observation);
    if (blocked) break;
  }
  return { records, completed: records.length === route.length && !records.some((r) => r.blocked) };
}

module.exports = { validatePlan, observationMetadata, observedAnswer, runScenario };
