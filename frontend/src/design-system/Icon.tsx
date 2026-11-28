import type { ReactNode } from "react";

const symbols: Array<[string, ReactNode]> = [
  ["shield", <><path d="M12 3 5 6v5c0 4.8 2.8 8.2 7 10 4.2-1.8 7-5.2 7-10V6l-7-3Z"/><path d="m9.5 12 1.6 1.6 3.6-4"/></>],
  ["grid", <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>],
  ["search", <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>],
  ["report", <><path d="M5 3h14v18H5z"/><path d="M8 8h8M8 12h8M8 16h5"/></>],
  ["entity", <><circle cx="9" cy="8" r="3"/><path d="M3.5 19c.7-4 2.4-6 5.5-6s4.8 2 5.5 6"/><circle cx="17.5" cy="8.5" r="2.5"/><path d="M15.5 14c2.8.2 4.4 1.8 5 5"/></>],
  ["warning", <><path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5M12 17h.01"/></>],
  ["events", <><path d="M4 5h16v14H4z"/><path d="M8 9h8M8 13h5M8 17h7"/></>],
  ["case", <><path d="M8 6V4h8v2"/><rect x="3" y="6" width="18" height="14" rx="2"/><path d="M3 11h18M10 11v2h4v-2"/></>],
  ["users", <><circle cx="9" cy="8" r="3"/><path d="M3 20c.6-4.6 2.5-7 6-7s5.4 2.4 6 7"/><circle cx="17" cy="9" r="2.3"/><path d="M15.4 14.2c3 .2 4.8 2.1 5.3 5.8"/></>],
  ["lock", <><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></>],
  ["key", <><circle cx="8" cy="15" r="4"/><path d="m11 12 8-8M15 8l2 2M17 6l2 2"/></>],
  ["settings", <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.6v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/></>],
  ["menu", <path d="M4 7h16M4 12h16M4 17h16"/>], ["close", <path d="m5 5 14 14M19 5 5 19"/>],
  ["chevron", <path d="m9 18 6-6-6-6"/>], ["plus", <path d="M12 5v14M5 12h14"/>],
  ["code", <><path d="m8 9-3 3 3 3M16 9l3 3-3 3M14 5l-4 14"/></>],
  ["calendar", <><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 10h18"/></>],
  ["computer", <><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8m-4-4v4"/></>],
  ["laptop", <><rect x="5" y="4" width="14" height="12" rx="2"/><path d="M5 16 2 20h20l-3-4"/></>],
  ["bell", <path d="M18 8a6 6 0 0 0-12 0c0 6-3 6-3 8h18c0-2-3-2-3-8ZM10 20a2 2 0 0 0 4 0"/>],
  ["sliders", <><path d="M4 6h8m4 0h4M4 12h2m4 0h10M4 18h10m4 0h2"/><circle cx="14" cy="6" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="16" cy="18" r="2"/></>],
  ["refresh", <path d="M20 12a8 8 0 1 1-2.4-5.7L20 9m0-5v5h-5"/>],
  ["chevron-down", <path d="m6 9 6 6 6-6"/>],
  ["chevron-left", <path d="m15 6-6 6 6 6"/>],
  ["chevron-right", <path d="m9 6 6 6-6 6"/>],
  ["info", <><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></>], ["check", <path d="m5 12 4 4L19 6"/>],
  ["eye", <><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></>],
  ["link", <><path d="M10 13a5 5 0 0 0 7.1 0l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1"/><path d="M14 11a5 5 0 0 0-7.1 0l-2 2A5 5 0 0 0 12 20.1l1.1-1.1"/></>],
  ["branch", <><circle cx="6" cy="5" r="2"/><circle cx="18" cy="7" r="2"/><circle cx="18" cy="17" r="2"/><path d="M8 5h2a4 4 0 0 1 4 4v4a4 4 0 0 0 4 4M14 10a4 4 0 0 1 4-3"/></>],
  ["filter", <path d="M4 5h16l-6 7v6l-4 2v-8L4 5Z"/>],
  ["copy", <><rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></>],
  ["clock", <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>],
  ["database", <><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></>],
  ["download", <><path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 19h16"/></>],
  ["logout", <><path d="M10 5H5v14h5"/><path d="M13 8l4 4-4 4M8 12h9"/></>],
  ["edit", <><path d="m4 17-.8 3.8L7 20l11-11-3-3L4 17Z"/><path d="m13.5 7.5 3 3"/></>],
  ["mail", <><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m4 7 8 6 8-6"/></>],
  ["send", <path d="m3 10 18-7-7 18-3-8-8-3Zm8 3 10-10"/>],
  ["phone", <path d="M6.5 3h3l1.5 5-2.2 1.5c1.2 2.5 3.2 4.5 5.7 5.7L16 13l5 1.5v3c0 1.9-1.6 3.5-3.5 3.5C9.5 21 3 14.5 3 6.5 3 4.6 4.6 3 6.5 3Z"/>],
  ["building", <path d="M4 21V3h11v18M15 9h5v12M8 7h3M8 11h3M8 15h3M7 21v-3h5v3"/>],
  ["map", <><path d="M12 21s7-5.2 7-12a7 7 0 1 0-14 0c0 6.8 7 12 7 12Z"/><circle cx="12" cy="9" r="2.3"/></>],
  ["user", <><circle cx="12" cy="8" r="4"/><path d="M4 21c.8-5.2 3.5-7 8-7s7.2 1.8 8 7"/></>],
  ["layers", <><path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/></>],
  ["history", <><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/></>],
  ["save", <><path d="M5 3h12l2 2v16H5z"/><path d="M8 3v6h8V3M8 21v-7h8v7"/></>],
];



export function IconSprite() {
  return <svg aria-hidden="true" width="0" height="0" style={{ position: "absolute", overflow: "hidden" }}>
    {symbols.map(([id, node]) => <symbol id={`i-${id}`} viewBox="0 0 24 24" key={id}>{node}</symbol>)}
  </svg>;
}

/** Inline SVG symbol from the sprite rendered once by AppShell. */
export function Icon({ name }: { name: string }) {
  return <svg className="sli-ds-icon" aria-hidden="true"><use href={`#i-${name}`}/></svg>;
}
