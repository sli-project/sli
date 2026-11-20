"use strict";

// Labels and page data never grant permission to act.
const ACTION_SELECTORS = Object.freeze({
  tab: '[role="tab"]',
  row: 'table tbody tr[data-clickable]',
  close: '[role="dialog"],[role="alertdialog"],.sli-ds-drawer',
});

function allowAction(kind, element = {}) {
  if (element.disabled) return false;
  if (kind === "tab") return element.role === "tab";
  if (kind === "row") return element.tag === "TR" && element.clickable === true && element.inTable === true;
  if (kind === "close") return element.dialogOpen === true;
  return false;
}

function allowRequest(url, method, origin, loginPhase = false, redirected = false) {
  let target;
  try { target = new URL(url); } catch { return { allowed: false, reason: "invalid_url" }; }
  if (target.origin !== origin || !["http:", "https:"].includes(target.protocol) || target.username || target.password) {
    return { allowed: false, reason: "foreign_origin" };
  }
  if (redirected) return { allowed: false, reason: "redirect_forbidden" };
  if (["GET", "HEAD"].includes(method)) return { allowed: true };
  if (method === "POST" && loginPhase && target.pathname === "/api/auth/login" && !target.search) {
    return { allowed: true };
  }
  return { allowed: false, reason: "mutating_method" };
}

function completionStatus({ started = false, blocked = false, failures = 0, remaining = 0 } = {}) {
  if (blocked) return "blocked";
  if (!started) return "not_run";
  if (failures) return "infra_failure";
  return remaining ? "blocked" : "completed";
}

function allowAccess(access, account) {
  if (!access || !account || access.platform_owner || access.preview ||
      access.subject?.coarse_role !== "viewer" || access.subject?.username !== account.username) return false;
  const readCapabilities = new Set(["workspace.view", "reports.catalog", "objects.view", "objects.groups",
    "events.view", "investigations.view", "operations.view", "administrative.activity.view",
    "semantic.review", "vpn.session.evidence.read", "evidence.exact", ...account.field_classes.map((field) => `field.${field}`)]);
  const capabilities = [...(access.capabilities || []), ...(access.resource_bound_capabilities || [])];
  if (capabilities.some((capability) => !readCapabilities.has(capability))) return false;
  if (!account.field_classes.includes("raw_evidence") && capabilities.some((capability) =>
    ["field.raw_evidence", "evidence.exact", "vpn.session.evidence.read"].includes(capability))) return false;
  if (account.field_classes.includes("raw_evidence") &&
      !["field.raw_evidence", "evidence.exact"].every((capability) => capabilities.includes(capability))) return false;
  const reports = (access.reports || []).filter((report) => report.allowed);
  if (!reports.length) return false;
  const scopeAllowed = (scope) => {
    if (account.scope.mode === "all") return scope?.mode === "all" || scope?.kind === "all";
    if (scope?.mode !== "restricted" || !Array.isArray(scope.clauses) || !scope.clauses.length) return false;
    const domains = account.scope.clauses[0].collection_scope_ids;
    return scope.clauses.every((clause) => Array.isArray(clause.collection_scope_ids) && clause.collection_scope_ids.length &&
      clause.collection_scope_ids.every((id) => domains.includes(id)) &&
      Object.entries(clause).every(([key, value]) => key === "collection_scope_ids" || (Array.isArray(value) && value.length === 0)));
  };
  if (account.scope.mode === "restricted") {
    const globalMetadata = new Set(["workspace.view", "reports.catalog", ...account.field_classes.map((field) => `field.${field}`)]);
    if ((access.capabilities || []).some((capability) => !globalMetadata.has(capability))) return false;
    if ((access.capability_policies || []).some((policy) => policy.effect === "allow" &&
        !globalMetadata.has(policy.capability_key) && !scopeAllowed(policy.scope))) return false;
  }
  return reports.every((report) => {
    const grants = report.grants || [];
    return grants.length > 0 && grants.every((grant) =>
      Array.isArray(grant.allowed_actions) && grant.allowed_actions.length === 1 && grant.allowed_actions[0] === "view" &&
      Array.isArray(grant.field_categories) && grant.field_categories.every((field) => account.field_classes.includes(field)) &&
      scopeAllowed(grant.scope));
  });
}

module.exports = { ACTION_SELECTORS, allowAction, allowRequest, completionStatus, allowAccess };
