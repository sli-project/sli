import type { SearchMiddleware } from "@tanstack/react-router";

/** Keep the workspace scope across router links, including legacy domain URLs. */
export const domainSearchMiddleware: SearchMiddleware<Record<string, unknown>> = ({ search, next }) => {
  const result = next(search);
  if (Object.hasOwn(result, "domain") || Object.hasOwn(result, "domain_id") || Object.hasOwn(result, "scope")) return result;
  const domain = search.domain_id ?? search.domain;
  return domain === undefined ? (search.scope === "all" ? { ...result, scope: "all" } : result) : { ...result, domain };
};

export function selectedDomain(search: string): string | null {
  const params = new URLSearchParams(search);
  return params.get("domain_id") ?? params.get("domain");
}

/** Plain report links also carry scope when opened in a new tab. */
export function withDomain(href: string, search: string): string {
  const domain = selectedDomain(search);
  const all = new URLSearchParams(search).get("scope") === "all";
  if ((!domain && !all) || !href.startsWith("/app")) return href;
  const url = new URL(href, "http://localhost");
  if (!url.searchParams.has("domain") && !url.searchParams.has("domain_id") && !url.searchParams.has("scope")) {
    if (domain) url.searchParams.set("domain", domain);
    else if (all) url.searchParams.set("scope", "all");
  }
  return `${url.pathname}${url.search}${url.hash}`;
}
