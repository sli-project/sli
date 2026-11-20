/** Old «что где когда» links: q / user_q / with_logons=true → v2 parameters. */
export function legacyLogonsHref(search: string): string {
  const old = new URLSearchParams(search);
  const next = new URLSearchParams();
  const q = old.get("q");
  const user = old.get("user_q");
  if (q) next.set("q", q);
  if (user) next.set("user", user);
  if (old.get("with_logons") === "true") next.set("with_logons", "yes");
  const query = next.toString();
  return `/app/report/ad.computer-logons${query ? `?${query}` : ""}`;
}
